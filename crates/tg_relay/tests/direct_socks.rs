use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use common::config::{DestinationPolicyConfig, RelayConfig, RelayMode, SocksAuthConfig};
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
async fn direct_socks5_round_trip_with_auth() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let relay_task = spawn_server(tg_relay::serve(
        relay_listener,
        relay_config(relay_addr, true),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    run_socks_connect_with_auth(
        relay_addr,
        "telegram",
        "secret",
        echo_addr.ip(),
        echo_addr.port(),
        b"hello",
    )
    .await?;

    let _ = shutdown_tx.send(());
    relay_task.await??;
    Ok(())
}

#[tokio::test]
async fn direct_socks5_rejects_private_targets_by_default() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let relay_task = spawn_server(tg_relay::serve(
        relay_listener,
        relay_config(relay_addr, false),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut stream = TcpStream::connect(relay_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x02]).await?;
    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x02]);

    write_auth(&mut stream, "telegram", "secret").await?;
    let mut auth_reply = [0_u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    assert_eq!(auth_reply, [0x01, 0x00]);

    let octets = match echo_addr.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(_) => anyhow::bail!("test only supports IPv4"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&octets);
    request.extend_from_slice(&echo_addr.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x02);

    let _ = shutdown_tx.send(());
    relay_task.await??;
    Ok(())
}

async fn run_socks_connect_with_auth(
    proxy_addr: SocketAddr,
    username: &str,
    password: &str,
    ip: IpAddr,
    port: u16,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x02]).await?;

    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x02]);

    write_auth(&mut stream, username, password).await?;
    let mut auth_reply = [0_u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    assert_eq!(auth_reply, [0x01, 0x00]);

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

async fn write_auth(stream: &mut TcpStream, username: &str, password: &str) -> anyhow::Result<()> {
    let mut auth_request = vec![0x01, username.len() as u8];
    auth_request.extend_from_slice(username.as_bytes());
    auth_request.push(password.len() as u8);
    auth_request.extend_from_slice(password.as_bytes());
    stream.write_all(&auth_request).await?;
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

fn relay_config(relay_addr: SocketAddr, allow_private_destinations: bool) -> RelayConfig {
    RelayConfig {
        listen_addr: relay_addr.to_string(),
        mode: RelayMode::DirectSocks5,
        tls_cert_path: None,
        tls_key_path: None,
        auth_token: None,
        socks_auth: Some(SocksAuthConfig {
            username: "telegram".into(),
            password: "secret".into(),
        }),
        mtproxy: None,
        destination_policy: DestinationPolicyConfig {
            allow_private_destinations,
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
