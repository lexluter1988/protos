use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use common::config::LocalConfig;
use common::io::relay_bidirectional;
use common::protocol::{self, ConnectRequest, ConnectResponse, ConnectStatus, DnsMode, TargetAddr};
use common::socks::{
    self, SocksConnectRequest, SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_HOST_UNREACHABLE,
};
use common::telemetry::RuntimeStats;
use common::tls::load_client_config;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig},
    TlsConnector,
};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
struct LocalState {
    config: Arc<LocalConfig>,
    tls_config: Arc<ClientConfig>,
    stats: Arc<RuntimeStats>,
}

pub async fn run(config: LocalConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind local listener on {}", config.listen_addr))?;
    serve(listener, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn serve<F>(listener: TcpListener, config: LocalConfig, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    let tls_config = load_client_config(config.ca_cert_path.as_deref())?;
    let state = LocalState {
        config: Arc::new(config),
        tls_config: Arc::new(tls_config),
        stats: Arc::new(RuntimeStats::default()),
    };

    let listen_addr = listener.local_addr()?;
    info!(listen_addr = %listen_addr, "local SOCKS5 listener started");

    let mut shutdown = std::pin::pin!(shutdown);
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received for local listener");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(error = %error, "failed to accept local client");
                        continue;
                    }
                };

                let snapshot = state.stats.on_accept();
                info!(
                    peer_addr = %peer_addr,
                    active = snapshot.active,
                    accepted = snapshot.accepted,
                    "accepted local client"
                );

                let task_state = state.clone();
                tasks.spawn(async move {
                    if let Err(error) = handle_client(stream, peer_addr, task_state).await {
                        warn!(peer_addr = %peer_addr, error = %error, "local client ended with error");
                    }
                });
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(error = %error, "local client task panicked");
        }
    }

    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    state: LocalState,
) -> Result<()> {
    let result = handle_client_inner(&mut client, &state).await;
    let snapshot = state.stats.on_finish(result.is_ok());

    match &result {
        Ok(()) => info!(
            peer_addr = %peer_addr,
            active = snapshot.active,
            succeeded = snapshot.succeeded,
            failed = snapshot.failed,
            "local client completed"
        ),
        Err(error) => warn!(
            peer_addr = %peer_addr,
            error = %error,
            active = snapshot.active,
            succeeded = snapshot.succeeded,
            failed = snapshot.failed,
            "local client failed"
        ),
    }

    result
}

async fn handle_client_inner(client: &mut TcpStream, state: &LocalState) -> Result<()> {
    let config = &state.config;
    let socks_request = timeout(
        config.handshake_timeout(),
        socks::accept_request(client, config.socks_auth.as_ref()),
    )
    .await
    .map_err(|_| anyhow!("SOCKS5 handshake timed out"))??;

    let target =
        resolve_target_for_tunnel(&socks_request, config.dns_mode, config.connect_timeout())
            .await?;

    let relay_stream = timeout(
        config.connect_timeout(),
        TcpStream::connect(&config.relay_addr),
    )
    .await
    .map_err(|_| anyhow!("timed out connecting to relay {}", config.relay_addr))?
    .with_context(|| format!("failed to connect to relay {}", config.relay_addr))?;

    let connector = TlsConnector::from(state.tls_config.clone());
    let server_name = ServerName::try_from(config.relay_server_name.clone())
        .map_err(|_| anyhow!("invalid relay_server_name {}", config.relay_server_name))?;
    let mut tunnel = timeout(
        config.handshake_timeout(),
        connector.connect(server_name, relay_stream),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake with relay timed out"))?
    .context("TLS handshake with relay failed")?;

    let tunnel_request = ConnectRequest {
        token: config.auth_token.clone(),
        dns_mode: config.dns_mode,
        target,
        port: socks_request.port,
    };

    let response = timeout(config.handshake_timeout(), async {
        protocol::write_connect_request(&mut tunnel, &tunnel_request).await?;
        protocol::read_connect_response(&mut tunnel).await
    })
    .await
    .map_err(|_| anyhow!("relay handshake timed out"))??;

    if response.status != ConnectStatus::Ok {
        let reply = map_tunnel_status_to_socks_reply(response);
        let _ = socks::send_reply(client, reply).await;
        return Err(anyhow!(
            "relay rejected connect request with status {}",
            response.status
        ));
    }

    socks::send_success_reply(client).await?;

    let relay_stats = relay_bidirectional(client, tunnel, config.idle_timeout())
        .await
        .context("stream relay failed")?;

    debug!(
        client_to_relay_bytes = relay_stats.left_to_right_bytes,
        relay_to_client_bytes = relay_stats.right_to_left_bytes,
        "completed local relay session"
    );

    Ok(())
}

async fn resolve_target_for_tunnel(
    request: &SocksConnectRequest,
    dns_mode: DnsMode,
    connect_timeout: std::time::Duration,
) -> Result<TargetAddr> {
    match (&request.target, dns_mode) {
        (TargetAddr::Ip(ip), _) => Ok(TargetAddr::Ip(*ip)),
        (TargetAddr::Domain(domain), DnsMode::Remote) => Ok(TargetAddr::Domain(domain.clone())),
        (TargetAddr::Domain(domain), DnsMode::Local) => {
            let mut resolved = timeout(
                connect_timeout,
                lookup_host((domain.as_str(), request.port)),
            )
            .await
            .map_err(|_| anyhow!("local DNS resolution timed out for {}", domain))?
            .with_context(|| format!("local DNS resolution failed for {domain}"))?;

            let addr = resolved
                .find_map(|socket| match socket.ip() {
                    IpAddr::V4(ip) => Some(TargetAddr::Ip(IpAddr::V4(ip))),
                    IpAddr::V6(ip) => Some(TargetAddr::Ip(IpAddr::V6(ip))),
                })
                .ok_or_else(|| anyhow!("no IP addresses returned for {}", domain))?;

            Ok(addr)
        }
    }
}

fn map_tunnel_status_to_socks_reply(response: ConnectResponse) -> u8 {
    match response.status {
        ConnectStatus::Ok => socks::SOCKS_REPLY_SUCCEEDED,
        ConnectStatus::ResolveFailed => SOCKS_REPLY_HOST_UNREACHABLE,
        ConnectStatus::ConnectFailed => socks::SOCKS_REPLY_CONNECTION_REFUSED,
        ConnectStatus::AuthFailed
        | ConnectStatus::BadRequest
        | ConnectStatus::InternalError
        | ConnectStatus::ServerBusy
        | ConnectStatus::UnsupportedVersion => SOCKS_REPLY_GENERAL_FAILURE,
    }
}
