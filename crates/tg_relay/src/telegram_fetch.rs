use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use tokio::fs;
use tracing::info;

pub const DEFAULT_TELEGRAM_PROXY_CONFIG_URL: &str = "https://core.telegram.org/getProxyConfig";
pub const DEFAULT_TELEGRAM_PROXY_SECRET_URL: &str = "https://core.telegram.org/getProxySecret";
const MIN_PROXY_SECRET_LEN: usize = 32;
const MAX_PROXY_SECRET_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramProxyConfigSummary {
    pub proxy_entries: usize,
    pub dc_clusters: usize,
    pub default_dc: Option<i16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramArtifactFetchSummary {
    pub config_bytes: usize,
    pub config_summary: TelegramProxyConfigSummary,
    pub secret_bytes: Option<usize>,
}

pub async fn fetch_telegram_artifacts(
    config_url: &str,
    config_out: &Path,
    secret_url: Option<&str>,
    secret_out: Option<&Path>,
) -> Result<TelegramArtifactFetchSummary> {
    if secret_url.is_some() != secret_out.is_some() {
        bail!("secret_url and secret_out must either both be set or both be omitted");
    }

    let client = Client::builder()
        .user_agent("tg_relay/0.1 telegram-artifact-fetcher")
        .build()
        .context("failed to build HTTP client")?;

    let config_bytes = download_bytes(&client, config_url)
        .await
        .with_context(|| format!("failed to download Telegram proxy config from {config_url}"))?;
    let config_summary = summarize_telegram_proxy_config(
        std::str::from_utf8(&config_bytes).context("Telegram proxy config was not valid UTF-8")?,
    )?;
    write_atomic(config_out, &config_bytes).await?;

    let secret_bytes = match (secret_url, secret_out) {
        (Some(secret_url), Some(secret_out)) => {
            let secret = download_bytes(&client, secret_url).await.with_context(|| {
                format!("failed to download Telegram proxy secret from {secret_url}")
            })?;
            validate_telegram_proxy_secret_bytes(&secret)?;
            write_atomic(secret_out, &secret).await?;
            Some(secret.len())
        }
        _ => None,
    };

    info!(
        config_url = %config_url,
        config_out = %config_out.display(),
        proxy_entries = config_summary.proxy_entries,
        dc_clusters = config_summary.dc_clusters,
        default_dc = config_summary.default_dc.unwrap_or_default(),
        secret_out = secret_out.map(|path| path.display().to_string()).unwrap_or_default(),
        "downloaded Telegram MTProxy artifacts"
    );

    Ok(TelegramArtifactFetchSummary {
        config_bytes: config_bytes.len(),
        config_summary,
        secret_bytes,
    })
}

pub fn summarize_telegram_proxy_config(config: &str) -> Result<TelegramProxyConfigSummary> {
    let mut clusters = HashSet::new();
    let mut proxy_entries = 0;
    let mut default_dc = None;

    let normalized = strip_hash_comments(config);
    for statement in normalized.split(';') {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }

        let mut parts = statement.split_whitespace();
        let directive = parts
            .next()
            .ok_or_else(|| anyhow!("empty Telegram proxy config statement"))?;
        match directive {
            "proxy" => {
                let endpoint = parts
                    .next()
                    .ok_or_else(|| anyhow!("proxy directive is missing endpoint"))?;
                validate_endpoint(endpoint)?;
                ensure_no_extra_tokens(parts, "proxy")?;
                proxy_entries += 1;
                clusters.insert(0_i16);
            }
            "proxy_for" => {
                let dc = parse_dc(parts.next(), "proxy_for")?;
                let endpoint = parts
                    .next()
                    .ok_or_else(|| anyhow!("proxy_for directive is missing endpoint"))?;
                validate_endpoint(endpoint)?;
                ensure_no_extra_tokens(parts, "proxy_for")?;
                proxy_entries += 1;
                clusters.insert(dc);
            }
            "default" => {
                default_dc = Some(parse_dc(parts.next(), "default")?);
                ensure_no_extra_tokens(parts, "default")?;
            }
            "min_connections" | "max_connections" | "timeout" => {
                let value = parts
                    .next()
                    .ok_or_else(|| anyhow!("{directive} directive is missing numeric value"))?;
                value
                    .parse::<u32>()
                    .with_context(|| format!("{directive} value must be an unsigned integer"))?;
                ensure_no_extra_tokens(parts, directive)?;
            }
            other => bail!("unsupported Telegram proxy config directive `{other}`"),
        }
    }

    if proxy_entries == 0 {
        bail!("Telegram proxy config did not contain any proxy or proxy_for directives");
    }

    Ok(TelegramProxyConfigSummary {
        proxy_entries,
        dc_clusters: clusters.len(),
        default_dc,
    })
}

fn strip_hash_comments(config: &str) -> String {
    let mut stripped = String::with_capacity(config.len());
    for line in config.lines() {
        let line = line.split('#').next().unwrap_or_default();
        stripped.push_str(line);
        stripped.push('\n');
    }
    stripped
}

fn ensure_no_extra_tokens<'a>(
    mut parts: impl Iterator<Item = &'a str>,
    directive: &str,
) -> Result<()> {
    if let Some(extra) = parts.next() {
        bail!("unexpected trailing token `{extra}` in {directive} directive");
    }
    Ok(())
}

fn parse_dc(value: Option<&str>, directive: &str) -> Result<i16> {
    let value = value.ok_or_else(|| anyhow!("{directive} directive is missing datacenter id"))?;
    value
        .parse::<i16>()
        .with_context(|| format!("{directive} datacenter id must fit in i16"))
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let (host, port) = if endpoint.starts_with('[') {
        let closing = endpoint
            .find(']')
            .ok_or_else(|| anyhow!("invalid bracketed endpoint `{endpoint}`"))?;
        let host = &endpoint[1..closing];
        let port = endpoint
            .get(closing + 2..)
            .ok_or_else(|| anyhow!("invalid bracketed endpoint `{endpoint}`"))?;
        if endpoint.as_bytes().get(closing + 1) != Some(&b':') {
            bail!("invalid bracketed endpoint `{endpoint}`");
        }
        (host, port)
    } else {
        endpoint
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("endpoint `{endpoint}` must be host:port"))?
    };

    if host.trim().is_empty() {
        bail!("endpoint `{endpoint}` has an empty host");
    }
    let port = port
        .parse::<u16>()
        .with_context(|| format!("endpoint `{endpoint}` has invalid port"))?;
    if port == 0 {
        bail!("endpoint `{endpoint}` port must be non-zero");
    }
    Ok(())
}

pub fn validate_telegram_proxy_secret_bytes(secret: &[u8]) -> Result<()> {
    if !(MIN_PROXY_SECRET_LEN..=MAX_PROXY_SECRET_LEN).contains(&secret.len()) {
        bail!(
            "Telegram proxy secret length {} was outside the expected {}..={} byte range",
            secret.len(),
            MIN_PROXY_SECRET_LEN,
            MAX_PROXY_SECRET_LEN
        );
    }
    Ok(())
}

async fn download_bytes(client: &Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("request to {url} failed"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("request to {url} returned HTTP {status}");
    }
    Ok(response
        .bytes()
        .await
        .with_context(|| format!("failed to read response body from {url}"))?
        .to_vec())
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let temp_path = temp_path_for(path);
    fs::write(&temp_path, bytes)
        .await
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    if let Err(rename_error) = fs::rename(&temp_path, path).await {
        let _ = fs::remove_file(path).await;
        fs::rename(&temp_path, path)
            .await
            .map_err(|_| rename_error)
            .with_context(|| {
                format!("failed to rename {} to {}", temp_path.display(), path.display())
            })?;
    }
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("telegram-artifact");
    path.with_file_name(format!(".{file_name}.{nanos}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::{fetch_telegram_artifacts, summarize_telegram_proxy_config};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn summarizes_official_style_proxy_config() {
        let config = r#"
            proxy_for 1 149.154.175.50:443;
            proxy_for 2 [2001:67c:4e8:f002::a]:443;
            proxy 149.154.167.40:443;
            default 2;
            min_connections 4;
            max_connections 8;
            timeout 300;
        "#;

        let summary = summarize_telegram_proxy_config(config).expect("summary");
        assert_eq!(summary.proxy_entries, 3);
        assert_eq!(summary.dc_clusters, 3);
        assert_eq!(summary.default_dc, Some(2));
    }

    #[tokio::test]
    async fn fetches_and_writes_proxy_artifacts() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = match listener.accept().await {
                    Ok(value) => value,
                    Err(_) => return,
                };
                let mut buffer = [0_u8; 2048];
                let read = match socket.read(&mut buffer).await {
                    Ok(read) => read,
                    Err(_) => return,
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let body: &[u8] = match path {
                    "/getProxyConfig" => b"proxy_for 2 149.154.167.51:443; default 2;",
                    "/getProxySecret" => b"0123456789abcdef0123456789abcdef",
                    _ => b"not found",
                };
                let status = if path == "/getProxyConfig" || path == "/getProxySecret" {
                    "200 OK"
                } else {
                    "404 Not Found"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                let _ = socket.write_all(body).await;
            }
        });

        let tempdir = tempdir()?;
        let config_out = tempdir.path().join("proxy-multi.conf");
        let secret_out = tempdir.path().join("proxy-secret");
        let base = format!("http://{addr}");

        let summary = fetch_telegram_artifacts(
            &format!("{base}/getProxyConfig"),
            &config_out,
            Some(&format!("{base}/getProxySecret")),
            Some(&secret_out),
        )
        .await?;

        assert_eq!(summary.config_summary.proxy_entries, 1);
        assert_eq!(summary.config_summary.default_dc, Some(2));
        assert_eq!(
            tokio::fs::read_to_string(&config_out).await?,
            "proxy_for 2 149.154.167.51:443; default 2;"
        );
        assert_eq!(
            tokio::fs::read(&secret_out).await?,
            b"0123456789abcdef0123456789abcdef"
        );

        server.await?;
        Ok(())
    }
}
