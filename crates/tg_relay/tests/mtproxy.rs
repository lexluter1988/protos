use std::future::Future;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use common::config::{
    DestinationPolicyConfig, MtProxyBackendMode, MtProxyConfig, MtProxyDcEndpointConfig,
    RelayConfig, RelayMode,
};
use common::mtproxy::{
    build_outbound_mtproxy_client_connection, decode_inbound_obfuscated_handshake,
    parse_mtproxy_secret, MtProtoTransport, ParsedMtProxySecret,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

type HmacSha256 = Hmac<Sha256>;

const TLS_CHANGE_CIPHER_SPEC_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
const TLS_REQUEST_LENGTH: usize = 517;

fn spawn_server<Fut>(future: Fut) -> tokio::task::JoinHandle<anyhow::Result<()>>
where
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(future)
}

#[tokio::test]
async fn mtproxy_mode_relays_to_configured_dc() -> anyhow::Result<()> {
    let dc_secret = "00112233445566778899aabbccddeeff";
    let client_secret = "dd112233445566778899aabbccddeeff00";

    let dc_addr = spawn_fake_dc_server(dc_secret).await?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let relay_task = spawn_server(tg_relay::serve(
        relay_listener,
        relay_config(relay_addr, dc_addr, client_secret, dc_secret),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut client = TcpStream::connect(relay_addr).await?;
    let mut mtproxy = build_outbound_mtproxy_client_connection(
        MtProtoTransport::PaddedIntermediate,
        2,
        &common::mtproxy::parse_mtproxy_secret(client_secret)?,
    )?;

    client.write_all(&mtproxy.init_payload).await?;

    let mut payload = b"\xdd\xdd\xdd\xddtelegram-through-mtproxy".to_vec();
    mtproxy.codec.encrypt_bytes(&mut payload);
    client.write_all(&payload).await?;

    let mut echoed = vec![0_u8; payload.len()];
    client.read_exact(&mut echoed).await?;
    mtproxy.codec.decrypt_bytes(&mut echoed);
    assert_eq!(echoed, b"\xdd\xdd\xdd\xddtelegram-through-mtproxy");

    drop(client);
    let _ = shutdown_tx.send(());
    relay_task.await??;
    Ok(())
}

#[tokio::test]
async fn fake_tls_mtproxy_mode_relays_to_configured_dc() -> anyhow::Result<()> {
    let dc_secret = "00112233445566778899aabbccddeeff";
    let client_secret = "ee112233445566778899aabbccddeeff006578616d706c652e636f6d";

    let dc_addr = spawn_fake_dc_server(dc_secret).await?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let relay_task = spawn_server(tg_relay::serve(
        relay_listener,
        relay_config(relay_addr, dc_addr, client_secret, dc_secret),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let secret = parse_mtproxy_secret(client_secret)?;
    let mut client = TcpStream::connect(relay_addr).await?;
    let client_hello = build_fake_tls_client_hello(&secret)?;
    client.write_all(&client_hello).await?;

    consume_fake_tls_server_handshake(&mut client).await?;

    let mut mtproxy = build_outbound_mtproxy_client_connection(
        MtProtoTransport::PaddedIntermediate,
        2,
        &secret,
    )?;
    let plaintext = b"\xdd\xdd\xdd\xddtelegram-through-fake-tls".to_vec();
    let mut encrypted_payload = plaintext.clone();
    mtproxy.codec.encrypt_bytes(&mut encrypted_payload);

    client.write_all(&TLS_CHANGE_CIPHER_SPEC_RECORD).await?;
    write_tls_application_record(
        &mut client,
        &[&mtproxy.init_payload[..], &encrypted_payload[..]].concat(),
    )
    .await?;

    let mut echoed = read_tls_application_record_payload(&mut client).await?;
    mtproxy.codec.decrypt_bytes(&mut echoed);
    assert_eq!(echoed, plaintext);

    drop(client);
    let _ = shutdown_tx.send(());
    relay_task.await??;
    Ok(())
}

async fn spawn_fake_dc_server(secret_hex: &str) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let secret = Some(common::mtproxy::parse_obfuscated_secret(secret_hex)?);

    tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(value) => value,
            Err(_) => return,
        };

        let mut init = [0_u8; 64];
        if stream.read_exact(&mut init).await.is_err() {
            return;
        }

        let mut inbound =
            match decode_inbound_obfuscated_handshake(init, secret.as_ref()).map_err(|_| ()) {
                Ok(value) => value,
                Err(_) => return,
            };
        if inbound.transport != MtProtoTransport::PaddedIntermediate {
            return;
        }

        let mut buffer = [0_u8; 1024];
        let read = match stream.read(&mut buffer).await {
            Ok(read) => read,
            Err(_) => return,
        };
        if read == 0 {
            return;
        }

        inbound.codec.decrypt_bytes(&mut buffer[..read]);
        inbound.codec.encrypt_bytes(&mut buffer[..read]);
        let _ = stream.write_all(&buffer[..read]).await;
    });

    Ok(addr)
}

fn build_fake_tls_client_hello(secret: &ParsedMtProxySecret) -> anyhow::Result<Vec<u8>> {
    let domain = secret
        .fake_tls_domain()
        .ok_or_else(|| anyhow::anyhow!("expected ee fake-TLS secret"))?;

    let mut greases = [0_u8; 7];
    OsRng.fill_bytes(&mut greases);
    for grease in &mut greases {
        *grease = (*grease & 0xF0) + 0x0A;
    }
    for index in (1..greases.len()).step_by(2) {
        if greases[index] == greases[index - 1] {
            greases[index] ^= 0x10;
        }
    }

    let mut request = Vec::with_capacity(TLS_REQUEST_LENGTH);
    request.extend_from_slice(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03");
    let client_random_offset = request.len();
    request.extend_from_slice(&[0_u8; 32]);
    request.push(0x20);
    let mut session_id = [0_u8; 32];
    OsRng.fill_bytes(&mut session_id);
    request.extend_from_slice(&session_id);
    request.extend_from_slice(b"\x00\x22");
    request.extend_from_slice(&[greases[0], greases[0]]);
    request.extend_from_slice(
        b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\
          \xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91",
    );
    request.extend_from_slice(&[greases[2], greases[2]]);
    request.extend_from_slice(b"\x00\x00\x00\x00");
    push_u16(&mut request, domain.len() + 5);
    push_u16(&mut request, domain.len() + 3);
    request.push(0x00);
    push_u16(&mut request, domain.len());
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(
        b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08",
    );
    request.extend_from_slice(&[greases[4], greases[4]]);
    request.extend_from_slice(
        b"\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\
          \x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\
          \x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\
          \x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00\
          \x33\x00\x2b\x00\x29",
    );
    request.extend_from_slice(&[greases[4], greases[4]]);
    request.extend_from_slice(b"\x00\x01\x00\x00\x1d\x00\x20");
    let mut key_share = [0_u8; 32];
    OsRng.fill_bytes(&mut key_share);
    request.extend_from_slice(&key_share);
    request.extend_from_slice(b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a");
    request.extend_from_slice(&[greases[6], greases[6]]);
    request.extend_from_slice(b"\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02");
    request.extend_from_slice(&[greases[3], greases[3]]);
    request.extend_from_slice(b"\x00\x01\x00\x00\x15");

    let padding_length = TLS_REQUEST_LENGTH
        .checked_sub(2 + request.len())
        .ok_or_else(|| anyhow::anyhow!("fake-TLS request template exceeded expected size"))?;
    push_u16(&mut request, padding_length);
    request.resize(TLS_REQUEST_LENGTH, 0);

    let mut hmac_input = request.clone();
    hmac_input[client_random_offset..client_random_offset + 32].fill(0);
    let digest = hmac_sha256(secret.key(), &hmac_input);
    let timestamp = current_unix_time()? as u32;
    let digest_tail = u32::from_le_bytes(digest[28..32].try_into().unwrap());

    let mut client_random = [0_u8; 32];
    client_random[..28].copy_from_slice(&digest[..28]);
    client_random[28..32].copy_from_slice(&(digest_tail ^ timestamp).to_le_bytes());
    request[client_random_offset..client_random_offset + 32].copy_from_slice(&client_random);

    Ok(request)
}

async fn consume_fake_tls_server_handshake(stream: &mut TcpStream) -> anyhow::Result<()> {
    let server_hello = read_tls_record(stream).await?;
    anyhow::ensure!(server_hello[0] == 0x16, "expected TLS handshake record");

    let ccs = read_tls_record(stream).await?;
    anyhow::ensure!(
        ccs == TLS_CHANGE_CIPHER_SPEC_RECORD,
        "expected dummy TLS ChangeCipherSpec"
    );

    let app_data = read_tls_record(stream).await?;
    anyhow::ensure!(app_data[0] == 0x17, "expected TLS application data record");
    Ok(())
}

async fn write_tls_application_record(
    stream: &mut TcpStream,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&[
        0x17,
        0x03,
        0x03,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ]);
    record.extend_from_slice(payload);
    stream.write_all(&record).await?;
    Ok(())
}

async fn read_tls_application_record_payload(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let record = read_tls_record(stream).await?;
    anyhow::ensure!(record[0] == 0x17, "expected TLS application data record");
    Ok(record[5..].to_vec())
}

async fn read_tls_record(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = vec![0_u8; 5 + payload_len];
    record[..5].copy_from_slice(&header);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

fn push_u16(buffer: &mut Vec<u8>, value: usize) {
    buffer.extend_from_slice(&(value as u16).to_be_bytes());
}

fn hmac_sha256(secret: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts 16-byte MTProxy key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn current_unix_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn relay_config(
    relay_addr: SocketAddr,
    dc_addr: SocketAddr,
    client_secret: &str,
    dc_secret: &str,
) -> RelayConfig {
    RelayConfig {
        listen_addr: relay_addr.to_string(),
        mode: RelayMode::MtProxy,
        tls_cert_path: None,
        tls_key_path: None,
        auth_token: None,
        socks_auth: None,
        mtproxy: Some(MtProxyConfig {
            secret: client_secret.into(),
            backend: MtProxyBackendMode::StaticDc,
            dc_endpoints: vec![MtProxyDcEndpointConfig {
                id: 2,
                addr: dc_addr.to_string(),
                obfuscated_secret: Some(dc_secret.into()),
            }],
            official: None,
        }),
        destination_policy: DestinationPolicyConfig::default(),
        handshake_timeout_secs: 5,
        outbound_connect_timeout_secs: 5,
        idle_timeout_secs: 30,
        max_concurrent_streams: 64,
        max_handshake_size: 2048,
        log_level: "info".into(),
    }
}
