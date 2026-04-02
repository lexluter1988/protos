use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::config::{DestinationPolicyConfig, LocalConfig, RelayConfig, RelayMode};
use rcgen::generate_simple_self_signed;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn spawn_server<Fut>(future: Fut) -> tokio::task::JoinHandle<anyhow::Result<()>>
where
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(future)
}

#[tokio::test]
async fn socks5_round_trip_via_relay() -> anyhow::Result<()> {
    let certs = write_test_certificates()?;
    let echo_addr = spawn_echo_server().await?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let (relay_shutdown_tx, relay_shutdown_rx) = oneshot::channel();
    let relay_task = spawn_server(tg_relay::serve(
        relay_listener,
        relay_config(relay_addr, &certs),
        async move {
            let _ = relay_shutdown_rx.await;
        },
    ));

    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;
    let (local_shutdown_tx, local_shutdown_rx) = oneshot::channel();
    let local_task = spawn_server(tg_local::serve(
        local_listener,
        local_config(relay_addr, &certs),
        async move {
            let _ = local_shutdown_rx.await;
        },
    ));

    run_socks_connect(local_addr, echo_addr.ip(), echo_addr.port(), b"ping").await?;

    let _ = local_shutdown_tx.send(());
    let _ = relay_shutdown_tx.send(());
    local_task.await??;
    relay_task.await??;
    Ok(())
}

#[tokio::test]
async fn remote_dns_mode_resolves_domain_on_relay() -> anyhow::Result<()> {
    let certs = write_test_certificates()?;
    let echo_addr = spawn_echo_server().await?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let (relay_shutdown_tx, relay_shutdown_rx) = oneshot::channel();
    let relay_task = spawn_server(tg_relay::serve(
        relay_listener,
        relay_config(relay_addr, &certs),
        async move {
            let _ = relay_shutdown_rx.await;
        },
    ));

    let mut local = local_config(relay_addr, &certs);
    local.dns_mode = common::DnsMode::Remote;
    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;
    let (local_shutdown_tx, local_shutdown_rx) = oneshot::channel();
    let local_task = spawn_server(tg_local::serve(local_listener, local, async move {
        let _ = local_shutdown_rx.await;
    }));

    run_socks_connect_domain(local_addr, "localhost", echo_addr.port(), b"dns").await?;

    let _ = local_shutdown_tx.send(());
    let _ = relay_shutdown_tx.send(());
    local_task.await??;
    relay_task.await??;
    Ok(())
}

async fn run_socks_connect(
    proxy_addr: SocketAddr,
    ip: IpAddr,
    port: u16,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    let octets = match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(_) => anyhow::bail!("test only supports IPv4"),
    };

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&octets);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00);

    stream.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);
    Ok(())
}

async fn run_socks_connect_domain(
    proxy_addr: SocketAddr,
    domain: &str,
    port: u16,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    assert_eq!(header[1], 0x00);

    match header[3] {
        0x01 => {
            let mut buf = [0_u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0_u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        other => anyhow::bail!("unexpected address type in SOCKS reply: {other}"),
    }

    stream.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);
    Ok(())
}

async fn spawn_echo_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    Ok(addr)
}

fn local_config(relay_addr: SocketAddr, certs: &TestCertificates) -> LocalConfig {
    LocalConfig {
        listen_addr: "127.0.0.1:0".into(),
        relay_addr: relay_addr.to_string(),
        relay_server_name: "localhost".into(),
        auth_token: "integration-secret".into(),
        handshake_timeout_secs: 5,
        connect_timeout_secs: 5,
        idle_timeout_secs: 30,
        dns_mode: common::DnsMode::Local,
        log_level: "info".into(),
        socks_auth: None,
        ca_cert_path: Some(certs.ca_cert_path.clone()),
    }
}

fn relay_config(relay_addr: SocketAddr, certs: &TestCertificates) -> RelayConfig {
    RelayConfig {
        listen_addr: relay_addr.to_string(),
        mode: RelayMode::Tunnel,
        tls_cert_path: Some(certs.server_cert_path.clone()),
        tls_key_path: Some(certs.server_key_path.clone()),
        auth_token: Some("integration-secret".into()),
        socks_auth: None,
        mtproxy: None,
        destination_policy: DestinationPolicyConfig {
            allow_private_destinations: true,
            ..Default::default()
        },
        handshake_timeout_secs: 5,
        outbound_connect_timeout_secs: 5,
        idle_timeout_secs: 30,
        max_concurrent_streams: 64,
        max_handshake_size: 2048,
        log_level: "info".into(),
    }
}

struct TestCertificates {
    _dir: Arc<TempDir>,
    ca_cert_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
}

fn write_test_certificates() -> anyhow::Result<TestCertificates> {
    let dir = Arc::new(TempDir::new()?);
    let certified = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let certificate_pem = certified.cert.pem();
    let private_key_pem = certified.key_pair.serialize_pem();

    let ca_cert_path = write_file(dir.path(), "ca.pem", &certificate_pem)?;
    let server_cert_path = write_file(dir.path(), "server.pem", &certificate_pem)?;
    let server_key_path = write_file(dir.path(), "server-key.pem", &private_key_pem)?;

    Ok(TestCertificates {
        _dir: dir,
        ca_cert_path,
        server_cert_path,
        server_key_path,
    })
}

fn write_file(dir: &Path, name: &str, contents: &str) -> anyhow::Result<PathBuf> {
    let path = dir.join(name);
    std::fs::write(&path, contents)?;
    Ok(path)
}
