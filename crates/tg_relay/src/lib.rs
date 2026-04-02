pub mod official_mtproxy;
pub mod telegram_fetch;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use common::config::{DestinationPolicyConfig, MtProxyBackendMode, RelayConfig, RelayMode};
use common::io::relay_bidirectional;
use common::mtproxy::{
    build_outbound_mtproto_obfuscated_connection, parse_mtproxy_secret, parse_obfuscated_secret,
    read_inbound_mtproxy_handshake, relay_fake_tls_mtproto_transforms, relay_mtproto_transforms,
    MtProxyClientFraming, ParsedMtProxySecret,
};
use common::protocol::{self, ConnectResponse, ConnectStatus, TargetAddr};
use common::socks::{
    self, SOCKS_REPLY_CONNECTION_NOT_ALLOWED, SOCKS_REPLY_CONNECTION_REFUSED,
    SOCKS_REPLY_HOST_UNREACHABLE,
};
use common::telemetry::RuntimeStats;
use common::tls::load_server_config;
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
enum RelayRuntimeMode {
    DirectSocks5,
    MtProxy {
        secret: Arc<ParsedMtProxySecret>,
        dc_endpoints: Arc<HashMap<i16, MtProxyDcEndpoint>>,
    },
    Tunnel {
        acceptor: TlsAcceptor,
    },
}

#[derive(Clone)]
struct MtProxyDcEndpoint {
    addr: String,
    obfuscated_secret: Option<[u8; 16]>,
}

#[derive(Clone)]
struct RelayState {
    config: Arc<RelayConfig>,
    runtime_mode: RelayRuntimeMode,
    semaphore: Arc<Semaphore>,
    stats: Arc<RuntimeStats>,
}

pub async fn run(config: RelayConfig) -> Result<()> {
    if config.is_official_mtproxy_mode() {
        return official_mtproxy::run(config).await;
    }

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind relay listener on {}", config.listen_addr))?;
    serve(listener, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn serve<F>(listener: TcpListener, config: RelayConfig, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    let runtime_mode = match config.mode {
        RelayMode::DirectSocks5 => RelayRuntimeMode::DirectSocks5,
        RelayMode::MtProxy => {
            let mtproxy = config
                .mtproxy
                .as_ref()
                .ok_or_else(|| anyhow!("missing mtproxy config in mtproxy mode"))?;
            if mtproxy.backend == MtProxyBackendMode::Official {
                return Err(anyhow!(
                    "official mtproxy backend must be started via tg_relay::run"
                ));
            }
            let secret = Arc::new(parse_mtproxy_secret(&mtproxy.secret)?);
            let mut dc_endpoints = HashMap::new();
            for endpoint in &mtproxy.dc_endpoints {
                dc_endpoints.insert(
                    endpoint.id,
                    MtProxyDcEndpoint {
                        addr: endpoint.addr.clone(),
                        obfuscated_secret: endpoint
                            .obfuscated_secret
                            .as_deref()
                            .map(parse_obfuscated_secret)
                            .transpose()?,
                    },
                );
            }
            RelayRuntimeMode::MtProxy {
                secret,
                dc_endpoints: Arc::new(dc_endpoints),
            }
        }
        RelayMode::Tunnel => {
            let server_config = load_server_config(
                config
                    .tls_cert_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing tls_cert_path in tunnel mode"))?,
                config
                    .tls_key_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing tls_key_path in tunnel mode"))?,
            )?;
            RelayRuntimeMode::Tunnel {
                acceptor: TlsAcceptor::from(Arc::new(server_config)),
            }
        }
    };

    let state = RelayState {
        semaphore: Arc::new(Semaphore::new(config.max_concurrent_streams)),
        config: Arc::new(config),
        runtime_mode,
        stats: Arc::new(RuntimeStats::default()),
    };

    let listen_addr = listener.local_addr()?;
    info!(
        listen_addr = %listen_addr,
        mode = %state.config.mode,
        "relay listener started"
    );

    let mut shutdown = std::pin::pin!(shutdown);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received for relay listener");
                break;
            }
            accepted = listener.accept() => {
                let (socket, peer_addr) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(error = %error, "failed to accept relay connection");
                        continue;
                    }
                };

                let permit = match state.semaphore.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(error) => {
                        warn!(error = %error, "relay semaphore closed");
                        break;
                    }
                };

                let snapshot = state.stats.on_accept();
                info!(
                    peer_addr = %peer_addr,
                    active = snapshot.active,
                    accepted = snapshot.accepted,
                    "accepted relay connection"
                );

                let task_state = state.clone();
                tasks.spawn(async move {
                    if let Err(error) = handle_connection(socket, peer_addr, task_state, permit).await {
                        warn!(peer_addr = %peer_addr, error = %error, "relay connection ended with error");
                    }
                });
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(error = %error, "relay task panicked");
        }
    }

    Ok(())
}

async fn handle_connection(
    socket: TcpStream,
    peer_addr: SocketAddr,
    state: RelayState,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let result = handle_connection_inner(socket, &state).await;
    let snapshot = state.stats.on_finish(result.is_ok());

    match &result {
        Ok(()) => info!(
            peer_addr = %peer_addr,
            active = snapshot.active,
            succeeded = snapshot.succeeded,
            failed = snapshot.failed,
            "relay connection completed"
        ),
        Err(error) => warn!(
            peer_addr = %peer_addr,
            error = %error,
            active = snapshot.active,
            succeeded = snapshot.succeeded,
            failed = snapshot.failed,
            "relay connection failed"
        ),
    }

    result
}

async fn handle_connection_inner(socket: TcpStream, state: &RelayState) -> Result<()> {
    match &state.runtime_mode {
        RelayRuntimeMode::DirectSocks5 => handle_direct_socks_connection(socket, state).await,
        RelayRuntimeMode::MtProxy {
            secret,
            dc_endpoints,
        } => handle_mtproxy_connection(socket, state, secret, dc_endpoints).await,
        RelayRuntimeMode::Tunnel { acceptor } => {
            handle_tunnel_connection(socket, acceptor.clone(), state).await
        }
    }
}

async fn handle_mtproxy_connection(
    mut socket: TcpStream,
    state: &RelayState,
    secret: &Arc<ParsedMtProxySecret>,
    dc_endpoints: &Arc<HashMap<i16, MtProxyDcEndpoint>>,
) -> Result<()> {
    let config = &state.config;
    let inbound =
        read_inbound_mtproxy_handshake(&mut socket, secret, config.handshake_timeout()).await?;

    let endpoint = find_mtproxy_endpoint(dc_endpoints, inbound.target_dc).ok_or_else(|| {
        anyhow!(
            "no MTProxy DC endpoint configured for {}",
            inbound.target_dc
        )
    })?;

    debug!(
        transport = %inbound.transport,
        target_dc = inbound.target_dc,
        endpoint = %endpoint.addr,
        "validated MTProxy client request"
    );

    let mut outbound = timeout(
        config.outbound_connect_timeout(),
        TcpStream::connect(&endpoint.addr),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "timed out connecting to MTProto DC endpoint {}",
            endpoint.addr
        )
    })?
    .with_context(|| format!("failed to connect to MTProto DC endpoint {}", endpoint.addr))?;

    let outbound_obfuscated = build_outbound_mtproto_obfuscated_connection(
        inbound.transport,
        endpoint.obfuscated_secret.as_ref(),
    )?;
    outbound
        .write_all(&outbound_obfuscated.init_payload)
        .await?;

    match inbound.client_framing {
        MtProxyClientFraming::Direct => {
            relay_mtproto_transforms(
                socket,
                outbound,
                inbound.codec,
                outbound_obfuscated.codec,
                config.idle_timeout(),
            )
            .await
            .context("MTProxy relay failed")?;
        }
        MtProxyClientFraming::FakeTls(fake_tls) => {
            relay_fake_tls_mtproto_transforms(
                socket,
                outbound,
                fake_tls,
                inbound.codec,
                outbound_obfuscated.codec,
                config.idle_timeout(),
            )
            .await
            .context("fake-TLS MTProxy relay failed")?;
        }
    }

    Ok(())
}

async fn handle_direct_socks_connection(mut socket: TcpStream, state: &RelayState) -> Result<()> {
    let config = &state.config;
    let socks_request = timeout(
        config.handshake_timeout(),
        socks::accept_request(&mut socket, config.socks_auth.as_ref()),
    )
    .await
    .map_err(|_| anyhow!("SOCKS5 handshake timed out"))??;

    debug!(
        target = %socks_request.target.as_log_value(),
        port = socks_request.port,
        "validated direct SOCKS5 request"
    );

    let outbound = match connect_target(
        &socks_request.target,
        socks_request.port,
        config.outbound_connect_timeout(),
        &config.destination_policy,
    )
    .await
    {
        Ok(stream) => stream,
        Err(TargetConnectError::Resolve(error)) => {
            let _ = socks::send_reply(&mut socket, SOCKS_REPLY_HOST_UNREACHABLE).await;
            return Err(error);
        }
        Err(TargetConnectError::Connect(error)) => {
            let _ = socks::send_reply(&mut socket, SOCKS_REPLY_CONNECTION_REFUSED).await;
            return Err(error);
        }
        Err(TargetConnectError::Policy(error)) => {
            let _ = socks::send_reply(&mut socket, SOCKS_REPLY_CONNECTION_NOT_ALLOWED).await;
            return Err(error);
        }
    };

    socks::send_success_reply(&mut socket).await?;

    let relay_stats = relay_bidirectional(socket, outbound, config.idle_timeout())
        .await
        .context("stream relay failed")?;
    debug!(
        inbound_to_outbound_bytes = relay_stats.left_to_right_bytes,
        outbound_to_inbound_bytes = relay_stats.right_to_left_bytes,
        "completed direct SOCKS5 relay session"
    );
    Ok(())
}

async fn handle_tunnel_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    state: &RelayState,
) -> Result<()> {
    let config = &state.config;
    let mut tunnel = timeout(config.handshake_timeout(), acceptor.accept(socket))
        .await
        .map_err(|_| anyhow!("TLS accept timed out"))?
        .context("TLS accept failed")?;

    let request = match timeout(
        config.handshake_timeout(),
        protocol::read_connect_request(&mut tunnel, config.max_handshake_size),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            let _ = protocol::write_connect_response(
                &mut tunnel,
                ConnectResponse {
                    status: ConnectStatus::BadRequest,
                },
            )
            .await;
            return Err(error.context("invalid tunnel request"));
        }
        Err(_) => {
            let _ = protocol::write_connect_response(
                &mut tunnel,
                ConnectResponse {
                    status: ConnectStatus::BadRequest,
                },
            )
            .await;
            return Err(anyhow!("tunnel request timed out"));
        }
    };

    if request.token != config.auth_token.as_deref().unwrap_or_default() {
        protocol::write_connect_response(
            &mut tunnel,
            ConnectResponse {
                status: ConnectStatus::AuthFailed,
            },
        )
        .await?;
        return Err(anyhow!("invalid auth token"));
    }

    debug!(
        target = %request.target.as_log_value(),
        port = request.port,
        dns_mode = %request.dns_mode,
        "validated relay tunnel request"
    );

    let outbound = match connect_target(
        &request.target,
        request.port,
        config.outbound_connect_timeout(),
        &config.destination_policy,
    )
    .await
    {
        Ok(stream) => stream,
        Err(TargetConnectError::Resolve(error)) => {
            protocol::write_connect_response(
                &mut tunnel,
                ConnectResponse {
                    status: ConnectStatus::ResolveFailed,
                },
            )
            .await?;
            return Err(error);
        }
        Err(TargetConnectError::Connect(error) | TargetConnectError::Policy(error)) => {
            protocol::write_connect_response(
                &mut tunnel,
                ConnectResponse {
                    status: ConnectStatus::ConnectFailed,
                },
            )
            .await?;
            return Err(error);
        }
    };

    protocol::write_connect_response(
        &mut tunnel,
        ConnectResponse {
            status: ConnectStatus::Ok,
        },
    )
    .await?;

    let relay_stats = relay_bidirectional(tunnel, outbound, config.idle_timeout())
        .await
        .context("stream relay failed")?;
    debug!(
        inbound_to_outbound_bytes = relay_stats.left_to_right_bytes,
        outbound_to_inbound_bytes = relay_stats.right_to_left_bytes,
        "completed relay tunnel session"
    );
    Ok(())
}

enum TargetConnectError {
    Resolve(anyhow::Error),
    Connect(anyhow::Error),
    Policy(anyhow::Error),
}

async fn connect_target(
    target: &TargetAddr,
    port: u16,
    connect_timeout: Duration,
    destination_policy: &DestinationPolicyConfig,
) -> std::result::Result<TcpStream, TargetConnectError> {
    match target {
        TargetAddr::Ip(ip) => {
            enforce_ip_policy(ip, destination_policy).map_err(TargetConnectError::Policy)?;
            let addr = SocketAddr::new(*ip, port);
            timeout(connect_timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| {
                    TargetConnectError::Connect(anyhow!("timed out connecting to {addr}"))
                })?
                .map_err(|error| {
                    TargetConnectError::Connect(anyhow!("failed to connect to {addr}: {error}"))
                })
        }
        TargetAddr::Domain(domain) => {
            enforce_domain_policy(domain, destination_policy)
                .map_err(TargetConnectError::Policy)?;
            let addrs = resolve_domain(domain, port, connect_timeout, destination_policy).await?;
            connect_any(domain, addrs, connect_timeout).await
        }
    }
}

async fn resolve_domain(
    domain: &str,
    port: u16,
    connect_timeout: Duration,
    destination_policy: &DestinationPolicyConfig,
) -> std::result::Result<Vec<SocketAddr>, TargetConnectError> {
    let resolved = timeout(connect_timeout, lookup_host((domain, port)))
        .await
        .map_err(|_| TargetConnectError::Resolve(anyhow!("timed out resolving {domain}:{port}")))?
        .with_context(|| format!("failed to resolve {domain}:{port}"))
        .map_err(TargetConnectError::Resolve)?;

    let addrs: Vec<_> = resolved
        .filter(|addr| ip_allowed(&addr.ip(), destination_policy))
        .collect();

    if addrs.is_empty() {
        return Err(TargetConnectError::Policy(anyhow!(
            "resolved addresses for {domain}:{port} were rejected by destination policy"
        )));
    }

    Ok(addrs)
}

async fn connect_any(
    domain: &str,
    addrs: Vec<SocketAddr>,
    connect_timeout: Duration,
) -> std::result::Result<TcpStream, TargetConnectError> {
    let started = Instant::now();
    let mut last_error = None;

    for addr in addrs {
        let elapsed = started.elapsed();
        if elapsed >= connect_timeout {
            break;
        }
        let remaining = connect_timeout - elapsed;
        match timeout(remaining, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                last_error = Some(anyhow!("failed to connect to {domain} via {addr}: {error}"))
            }
            Err(_) => {
                return Err(TargetConnectError::Connect(anyhow!(
                    "timed out connecting to {domain} via {addr}"
                )))
            }
        }
    }

    Err(TargetConnectError::Connect(last_error.unwrap_or_else(
        || anyhow!("timed out connecting to resolved addresses for {domain}"),
    )))
}

fn enforce_domain_policy(domain: &str, destination_policy: &DestinationPolicyConfig) -> Result<()> {
    if domain_allowed(domain, destination_policy) {
        Ok(())
    } else {
        Err(anyhow!(
            "domain {domain} is not permitted by the configured destination policy"
        ))
    }
}

fn enforce_ip_policy(ip: &IpAddr, destination_policy: &DestinationPolicyConfig) -> Result<()> {
    if ip_allowed(ip, destination_policy) {
        Ok(())
    } else {
        Err(anyhow!(
            "address {ip} is not permitted by the configured destination policy"
        ))
    }
}

fn domain_allowed(domain: &str, destination_policy: &DestinationPolicyConfig) -> bool {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();

    if destination_policy.allowed_domains.is_empty()
        && destination_policy.allowed_domain_suffixes.is_empty()
    {
        return true;
    }

    destination_policy
        .allowed_domains
        .iter()
        .map(|entry| entry.trim_end_matches('.').to_ascii_lowercase())
        .any(|entry| entry == normalized)
        || destination_policy
            .allowed_domain_suffixes
            .iter()
            .map(|entry| entry.trim_matches('.').to_ascii_lowercase())
            .any(|suffix| normalized == suffix || normalized.ends_with(&format!(".{suffix}")))
}

fn ip_allowed(ip: &IpAddr, destination_policy: &DestinationPolicyConfig) -> bool {
    let listed = destination_policy.allowed_ips.is_empty()
        || destination_policy
            .allowed_ips
            .iter()
            .any(|allowed| allowed == ip);
    listed && (destination_policy.allow_private_destinations || !is_private_destination(ip))
}

fn is_private_destination(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
    }
}

fn find_mtproxy_endpoint<'a>(
    dc_endpoints: &'a HashMap<i16, MtProxyDcEndpoint>,
    target_dc: i16,
) -> Option<&'a MtProxyDcEndpoint> {
    dc_endpoints
        .get(&target_dc)
        .or_else(|| dc_endpoints.get(&target_dc.abs()))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use common::config::DestinationPolicyConfig;

    use super::{domain_allowed, ip_allowed};

    #[test]
    fn domain_policy_matches_exact_and_suffix_entries() {
        let policy = DestinationPolicyConfig {
            allowed_domains: vec!["api.telegram.org".into()],
            allowed_domain_suffixes: vec!["telegram.org".into()],
            ..Default::default()
        };

        assert!(domain_allowed("api.telegram.org", &policy));
        assert!(domain_allowed("updates.telegram.org", &policy));
        assert!(!domain_allowed("example.org", &policy));
    }

    #[test]
    fn private_ips_are_blocked_by_default() {
        let policy = DestinationPolicyConfig::default();
        assert!(!ip_allowed(
            &IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            &policy
        ));
        assert!(ip_allowed(
            &IpAddr::V4(Ipv4Addr::new(149, 154, 167, 51)),
            &policy
        ));
    }
}
