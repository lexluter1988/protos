use std::ffi::OsString;
use std::future::pending;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use common::config::{OfficialMtProxyConfig, RelayConfig};
use common::mtproxy::{parse_mtproxy_secret, ParsedMtProxySecret};
use tokio::fs;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::telegram_fetch::{
    fetch_telegram_artifacts, summarize_telegram_proxy_config,
    validate_telegram_proxy_secret_bytes,
};

const OFFICIAL_MTPROXY_RESTART_BACKOFF: Duration = Duration::from_secs(2);

pub async fn run(config: RelayConfig) -> Result<()> {
    let mtproxy = config
        .mtproxy
        .as_ref()
        .ok_or_else(|| anyhow!("missing mtproxy config in official backend mode"))?
        .clone();
    let official = mtproxy
        .official
        .as_ref()
        .ok_or_else(|| anyhow!("missing mtproxy.official config in official backend mode"))?
        .clone();
    let parsed_secret = parse_mtproxy_secret(&mtproxy.secret)?;

    ensure_initial_artifacts(&official).await?;

    let mut shutdown = std::pin::pin!(tokio::signal::ctrl_c());

    loop {
        let command_spec = build_command_spec(&config, &official, &parsed_secret)?;
        let mut child = spawn_official_mtproxy(&command_spec)?;

        loop {
            let refresh = async {
                if official.auto_refresh {
                    sleep(Duration::from_secs(official.refresh_interval_secs)).await;
                } else {
                    pending::<()>().await;
                }
            };
            tokio::pin!(refresh);

            tokio::select! {
                _ = &mut shutdown => {
                    terminate_child(&mut child, "shutdown").await?;
                    return Ok(());
                }
                status = child.wait() => {
                    let status = status.context("failed waiting for official mtproto-proxy")?;
                    warn!(status = %status, "official mtproto-proxy exited");
                    sleep(OFFICIAL_MTPROXY_RESTART_BACKOFF).await;
                    break;
                }
                _ = &mut refresh => {
                    match refresh_artifacts(&official).await {
                        Ok(()) => {
                            info!("restarting official mtproto-proxy after Telegram artifact refresh");
                            terminate_child(&mut child, "artifact refresh").await?;
                            break;
                        }
                        Err(error) => {
                            warn!(error = %error, "failed to refresh Telegram artifacts; keeping current official mtproto-proxy process");
                        }
                    }
                }
            }
        }
    }
}

async fn ensure_initial_artifacts(official: &OfficialMtProxyConfig) -> Result<()> {
    if official.auto_refresh {
        match refresh_artifacts(official).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                warn!(error = %error, "failed to fetch Telegram artifacts at startup, falling back to local cache");
            }
        }
    }

    validate_cached_artifacts(official).await
}

async fn refresh_artifacts(official: &OfficialMtProxyConfig) -> Result<()> {
    let summary = fetch_telegram_artifacts(
        &official.config_url,
        &official.proxy_config_path,
        Some(&official.secret_url),
        Some(&official.proxy_secret_path),
    )
    .await?;

    info!(
        config_out = %official.proxy_config_path.display(),
        secret_out = %official.proxy_secret_path.display(),
        proxy_entries = summary.config_summary.proxy_entries,
        dc_clusters = summary.config_summary.dc_clusters,
        "refreshed Telegram official MTProxy artifacts"
    );

    Ok(())
}

async fn validate_cached_artifacts(official: &OfficialMtProxyConfig) -> Result<()> {
    let config = fs::read_to_string(&official.proxy_config_path)
        .await
        .with_context(|| {
            format!(
                "failed to read cached Telegram proxy config {}",
                official.proxy_config_path.display()
            )
        })?;
    summarize_telegram_proxy_config(&config).with_context(|| {
        format!(
            "cached Telegram proxy config {} was invalid",
            official.proxy_config_path.display()
        )
    })?;

    let secret = fs::read(&official.proxy_secret_path).await.with_context(|| {
        format!(
            "failed to read cached Telegram proxy secret {}",
            official.proxy_secret_path.display()
        )
    })?;
    validate_telegram_proxy_secret_bytes(&secret).with_context(|| {
        format!(
            "cached Telegram proxy secret {} was invalid",
            official.proxy_secret_path.display()
        )
    })?;

    Ok(())
}

async fn terminate_child(child: &mut Child, reason: &str) -> Result<()> {
    if child.id().is_some() {
        info!(reason, "stopping official mtproto-proxy child");
        child
            .start_kill()
            .context("failed to signal official mtproto-proxy child")?;
    }

    let _ = child.wait().await;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfficialMtProxyCommandSpec {
    program: OsString,
    args: Vec<OsString>,
}

impl OfficialMtProxyCommandSpec {
    fn display_args(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }
}

fn build_command_spec(
    relay: &RelayConfig,
    official: &OfficialMtProxyConfig,
    parsed_secret: &ParsedMtProxySecret,
) -> Result<OfficialMtProxyCommandSpec> {
    let listen_port = relay
        .listen_addr
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.port())
        .with_context(|| {
            format!(
                "failed to parse listen_addr {} for official mtproxy backend",
                relay.listen_addr
            )
        })?;

    let mut args = Vec::new();
    let run_as_user = official.run_as_user.as_deref().unwrap_or("mtproxy");
    args.push(OsString::from("-u"));
    args.push(OsString::from(run_as_user));
    args.push(OsString::from("-p"));
    args.push(OsString::from(official.stats_port.to_string()));
    args.push(OsString::from("-H"));
    args.push(OsString::from(listen_port.to_string()));
    args.push(OsString::from("-S"));
    args.push(OsString::from(hex::encode(parsed_secret.key())));
    if let Some(proxy_tag) = &official.proxy_tag {
        args.push(OsString::from("-P"));
        args.push(OsString::from(proxy_tag));
    }
    if let Some(domain) = parsed_secret.fake_tls_domain() {
        args.push(OsString::from("-D"));
        args.push(OsString::from(domain));
    }
    if official.workers > 0 {
        args.push(OsString::from("-M"));
        args.push(OsString::from(official.workers.to_string()));
    }
    args.push(OsString::from("--aes-pwd"));
    args.push(official.proxy_secret_path.clone().into_os_string());
    args.push(official.proxy_config_path.clone().into_os_string());

    Ok(OfficialMtProxyCommandSpec {
        program: official.binary_path.clone().into_os_string(),
        args,
    })
}

fn spawn_official_mtproxy(spec: &OfficialMtProxyCommandSpec) -> Result<Child> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    info!(
        binary = %spec.program.to_string_lossy(),
        args = ?redact_args(&spec.display_args()),
        "starting official mtproto-proxy child"
    );

    command.spawn().with_context(|| {
        format!(
            "failed to spawn official mtproto-proxy binary {}",
            spec.program.to_string_lossy()
        )
    })
}

fn redact_args(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut hide_next = false;
    for arg in args {
        if hide_next {
            redacted.push("<redacted>".to_string());
            hide_next = false;
            continue;
        }
        if arg == "-S" {
            redacted.push(arg.clone());
            hide_next = true;
            continue;
        }
        redacted.push(arg.clone());
    }
    redacted
}

#[cfg(test)]
mod tests {
    use common::config::{
        DestinationPolicyConfig, MtProxyBackendMode, MtProxyConfig, OfficialMtProxyConfig,
        RelayConfig, RelayMode,
    };

    use super::build_command_spec;

    #[test]
    fn builds_command_for_plain_or_dd_secret() {
        let relay = sample_relay_config("dd00112233445566778899aabbccddeeff");
        let mtproxy = relay.mtproxy.as_ref().expect("mtproxy");
        let official = mtproxy.official.as_ref().expect("official");
        let parsed = common::mtproxy::parse_mtproxy_secret(&mtproxy.secret).expect("secret");

        let spec = build_command_spec(&relay, official, &parsed).expect("command");
        assert_eq!(
            spec.display_args(),
            vec![
                "-u",
                "mtproxy",
                "-p",
                "8888",
                "-H",
                "443",
                "-S",
                "00112233445566778899aabbccddeeff",
                "--aes-pwd",
                "var/telegram/proxy-secret",
                "var/telegram/proxy-multi.conf",
            ]
        );
    }

    #[test]
    fn builds_command_for_fake_tls_secret_and_proxy_tag() {
        let mut relay = sample_relay_config(
            "ee00112233445566778899aabbccddeeff7777772e74656c656772616d2e6f7267",
        );
        {
            let mtproxy = relay.mtproxy.as_mut().expect("mtproxy");
            let official = mtproxy.official.as_mut().expect("official");
            official.proxy_tag = Some("fedcba98765432100123456789abcdef".to_string());
            official.run_as_user = Some("nobody".to_string());
            official.workers = 0;
        }

        let mtproxy = relay.mtproxy.as_ref().expect("mtproxy");
        let official = mtproxy.official.as_ref().expect("official");
        let parsed = common::mtproxy::parse_mtproxy_secret(&mtproxy.secret).expect("secret");
        let spec = build_command_spec(&relay, official, &parsed).expect("command");

        assert_eq!(
            spec.display_args(),
            vec![
                "-u",
                "nobody",
                "-p",
                "8888",
                "-H",
                "443",
                "-S",
                "00112233445566778899aabbccddeeff",
                "-P",
                "fedcba98765432100123456789abcdef",
                "-D",
                "www.telegram.org",
                "--aes-pwd",
                "var/telegram/proxy-secret",
                "var/telegram/proxy-multi.conf",
            ]
        );
    }

    fn sample_relay_config(secret: &str) -> RelayConfig {
        RelayConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            mode: RelayMode::MtProxy,
            tls_cert_path: None,
            tls_key_path: None,
            auth_token: None,
            socks_auth: None,
            mtproxy: Some(MtProxyConfig {
                secret: secret.to_string(),
                backend: MtProxyBackendMode::Official,
                dc_endpoints: Vec::new(),
                official: Some(OfficialMtProxyConfig {
                    binary_path: "/opt/MTProxy/objs/bin/mtproto-proxy".into(),
                    proxy_config_path: "var/telegram/proxy-multi.conf".into(),
                    proxy_secret_path: "var/telegram/proxy-secret".into(),
                    stats_port: 8888,
                    workers: 0,
                    run_as_user: None,
                    proxy_tag: None,
                    auto_refresh: true,
                    refresh_interval_secs: 86_400,
                    config_url: "https://core.telegram.org/getProxyConfig".to_string(),
                    secret_url: "https://core.telegram.org/getProxySecret".to_string(),
                }),
            }),
            destination_policy: DestinationPolicyConfig::default(),
            handshake_timeout_secs: 10,
            outbound_connect_timeout_secs: 10,
            idle_timeout_secs: 300,
            max_concurrent_streams: 1024,
            max_handshake_size: 2048,
            log_level: "info".to_string(),
        }
    }
}
