use std::fmt;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const INIT_LEN: usize = 64;
const PLAIN_SECRET_LEN: usize = 16;
const DD_PREFIX: u8 = 0xdd;
const EE_PREFIX: u8 = 0xee;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CHANGE_CIPHER_SPEC_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
const TLS_APPLICATION_RECORD_TYPE: u8 = 0x17;
const MAX_FAKE_TLS_CLIENT_HELLO_LEN: usize = 4096;
const MAX_FAKE_TLS_RECORD_PAYLOAD_LEN: usize = 16 * 1024;
const MAX_FAKE_TLS_WRITE_CHUNK: usize = 1425;
const FAKE_TLS_ENCRYPTED_SERVER_PAYLOAD_BASE_LEN: usize = 2500;
const FAKE_TLS_ENCRYPTED_SERVER_PAYLOAD_VARIATION: usize = 1120;
const MAX_FAKE_TLS_FUTURE_SKEW_SECS: i64 = 3;
const MAX_FAKE_TLS_PAST_SKEW_SECS: i64 = 10 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtProtoTransport {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl MtProtoTransport {
    pub fn tag(self) -> u32 {
        match self {
            Self::Abridged => 0xefefefef,
            Self::Intermediate => 0xeeeeeeee,
            Self::PaddedIntermediate => 0xdddddddd,
        }
    }

    fn from_tag(tag: u32) -> Result<Self> {
        match tag {
            0xefefefef => Ok(Self::Abridged),
            0xeeeeeeee => Ok(Self::Intermediate),
            0xdddddddd => Ok(Self::PaddedIntermediate),
            _ => Err(anyhow!("unsupported MTProto transport tag {tag:08x}")),
        }
    }
}

impl fmt::Display for MtProtoTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abridged => write!(f, "abridged"),
            Self::Intermediate => write!(f, "intermediate"),
            Self::PaddedIntermediate => write!(f, "padded_intermediate"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMtProxySecret {
    key: [u8; PLAIN_SECRET_LEN],
    required_transport: Option<MtProtoTransport>,
    fake_tls_domain: Option<String>,
}

impl ParsedMtProxySecret {
    pub fn key(&self) -> &[u8; PLAIN_SECRET_LEN] {
        &self.key
    }

    pub fn required_transport(&self) -> Option<MtProtoTransport> {
        self.required_transport
    }

    pub fn fake_tls_domain(&self) -> Option<&str> {
        self.fake_tls_domain.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtProxyClientFraming {
    Direct,
    FakeTls(FakeTlsFrameState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeTlsFrameState {
    pending_client_payload: Vec<u8>,
}

impl FakeTlsFrameState {
    pub fn pending_client_payload(&self) -> &[u8] {
        &self.pending_client_payload
    }

    pub fn into_pending_client_payload(self) -> Vec<u8> {
        self.pending_client_payload
    }
}

#[derive(Clone)]
pub struct MtProtoCodecState {
    decrypt: Aes256Ctr,
    encrypt: Aes256Ctr,
}

impl MtProtoCodecState {
    pub fn decrypt_bytes(&mut self, bytes: &mut [u8]) {
        self.decrypt.apply_keystream(bytes);
    }

    pub fn encrypt_bytes(&mut self, bytes: &mut [u8]) {
        self.encrypt.apply_keystream(bytes);
    }

    fn into_parts(self) -> (Aes256Ctr, Aes256Ctr) {
        (self.decrypt, self.encrypt)
    }
}

#[derive(Clone)]
pub struct InboundMtProxyHandshake {
    pub transport: MtProtoTransport,
    pub target_dc: i16,
    pub codec: MtProtoCodecState,
    pub client_framing: MtProxyClientFraming,
}

#[derive(Clone)]
pub struct InboundMtProtoObfuscatedHandshake {
    pub transport: MtProtoTransport,
    pub codec: MtProtoCodecState,
}

#[derive(Clone)]
pub struct OutboundMtProtoConnection {
    pub init_payload: [u8; INIT_LEN],
    pub codec: MtProtoCodecState,
}

pub fn parse_mtproxy_secret(secret_hex: &str) -> Result<ParsedMtProxySecret> {
    let bytes = hex::decode(secret_hex).context("invalid MTProxy secret hex")?;
    match bytes.len() {
        PLAIN_SECRET_LEN => {
            let mut key = [0_u8; PLAIN_SECRET_LEN];
            key.copy_from_slice(&bytes);
            Ok(ParsedMtProxySecret {
                key,
                required_transport: None,
                fake_tls_domain: None,
            })
        }
        len if len == PLAIN_SECRET_LEN + 1 && bytes[0] == DD_PREFIX => {
            let mut key = [0_u8; PLAIN_SECRET_LEN];
            key.copy_from_slice(&bytes[1..]);
            Ok(ParsedMtProxySecret {
                key,
                required_transport: Some(MtProtoTransport::PaddedIntermediate),
                fake_tls_domain: None,
            })
        }
        len if len > PLAIN_SECRET_LEN + 1 && bytes[0] == EE_PREFIX => {
            let mut key = [0_u8; PLAIN_SECRET_LEN];
            key.copy_from_slice(&bytes[1..=PLAIN_SECRET_LEN]);
            let domain = String::from_utf8(bytes[PLAIN_SECRET_LEN + 1..].to_vec())
                .context("ee fake-TLS MTProxy secret domain must be valid UTF-8")?;
            let domain = normalize_fake_tls_domain(&domain);
            validate_fake_tls_domain(&domain)?;
            Ok(ParsedMtProxySecret {
                key,
                required_transport: Some(MtProtoTransport::PaddedIntermediate),
                fake_tls_domain: Some(domain),
            })
        }
        _ => bail!("MTProxy secret must be 16 bytes, dd+16 bytes, or ee-prefixed fake-TLS format"),
    }
}

pub fn parse_obfuscated_secret(secret_hex: &str) -> Result<[u8; PLAIN_SECRET_LEN]> {
    let bytes = hex::decode(secret_hex).context("invalid obfuscated transport secret hex")?;
    if bytes.len() != PLAIN_SECRET_LEN {
        bail!("obfuscated transport secret must be exactly 16 bytes");
    }
    let mut key = [0_u8; PLAIN_SECRET_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn decode_inbound_mtproxy_handshake(
    received_header: [u8; INIT_LEN],
    secret: &ParsedMtProxySecret,
) -> Result<InboundMtProxyHandshake> {
    decode_inbound_mtproxy_handshake_with_framing(
        received_header,
        secret,
        MtProxyClientFraming::Direct,
    )
}

fn decode_inbound_mtproxy_handshake_with_framing(
    received_header: [u8; INIT_LEN],
    secret: &ParsedMtProxySecret,
    client_framing: MtProxyClientFraming,
) -> Result<InboundMtProxyHandshake> {
    let (transport, decrypted, codec) =
        decode_handshake_common(received_header, Some(secret.key()))?;
    if let Some(required) = secret.required_transport() {
        if required != transport {
            bail!("MTProxy secret requires {required}, but client requested {transport}");
        }
    }

    let target_dc = i16::from_le_bytes(decrypted[60..62].try_into().unwrap());
    if target_dc == 0 {
        bail!("client requested invalid DC 0");
    }

    Ok(InboundMtProxyHandshake {
        transport,
        target_dc,
        codec,
        client_framing,
    })
}

pub fn decode_inbound_obfuscated_handshake(
    received_header: [u8; INIT_LEN],
    secret: Option<&[u8; PLAIN_SECRET_LEN]>,
) -> Result<InboundMtProtoObfuscatedHandshake> {
    let (transport, _decrypted, codec) = decode_handshake_common(received_header, secret)?;
    Ok(InboundMtProtoObfuscatedHandshake { transport, codec })
}

pub fn build_outbound_mtproto_obfuscated_connection(
    transport: MtProtoTransport,
    secret: Option<&[u8; PLAIN_SECRET_LEN]>,
) -> Result<OutboundMtProtoConnection> {
    build_outbound_connection(transport, None, secret)
}

pub fn build_outbound_mtproxy_client_connection(
    transport: MtProtoTransport,
    target_dc: i16,
    secret: &ParsedMtProxySecret,
) -> Result<OutboundMtProtoConnection> {
    build_outbound_connection(transport, Some(target_dc), Some(secret.key()))
}

fn build_outbound_connection(
    transport: MtProtoTransport,
    target_dc: Option<i16>,
    secret: Option<&[u8; PLAIN_SECRET_LEN]>,
) -> Result<OutboundMtProtoConnection> {
    let init = generate_init_bytes(transport, target_dc);
    let mut encrypt = build_client_to_server_ctr(&init, secret);
    let decrypt = build_server_to_client_ctr(&init, secret);

    let mut encrypted = init;
    encrypt.apply_keystream(&mut encrypted);

    let mut payload = init;
    payload[56..64].copy_from_slice(&encrypted[56..64]);

    Ok(OutboundMtProtoConnection {
        init_payload: payload,
        codec: MtProtoCodecState { decrypt, encrypt },
    })
}

pub async fn read_inbound_mtproxy_handshake<S>(
    stream: &mut S,
    secret: &ParsedMtProxySecret,
    handshake_timeout: Duration,
) -> Result<InboundMtProxyHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(
        handshake_timeout,
        read_inbound_mtproxy_handshake_inner(stream, secret),
    )
    .await
    .map_err(|_| anyhow!("MTProxy handshake timed out"))?
}

pub async fn relay_fake_tls_mtproto_transforms<A, B>(
    inbound: A,
    outbound: B,
    fake_tls: FakeTlsFrameState,
    inbound_codec: MtProtoCodecState,
    outbound_codec: MtProtoCodecState,
    idle_timeout: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut inbound_decrypt, mut inbound_encrypt) = inbound_codec.into_parts();
    let (mut outbound_decrypt, mut outbound_encrypt) = outbound_codec.into_parts();
    let (inbound_reader, inbound_writer) = tokio::io::split(inbound);
    let (outbound_reader, outbound_writer) = tokio::io::split(outbound);

    let client_to_dc = relay_fake_tls_client_to_dc(
        inbound_reader,
        outbound_writer,
        fake_tls.into_pending_client_payload(),
        idle_timeout,
        move |bytes| {
            inbound_decrypt.apply_keystream(bytes);
            outbound_encrypt.apply_keystream(bytes);
        },
    );
    let dc_to_client =
        relay_dc_to_fake_tls_client(outbound_reader, inbound_writer, idle_timeout, move |bytes| {
            outbound_decrypt.apply_keystream(bytes);
            inbound_encrypt.apply_keystream(bytes);
        });

    let _ = tokio::try_join!(client_to_dc, dc_to_client)?;
    Ok(())
}

pub async fn relay_mtproto_transforms<A, B>(
    inbound: A,
    outbound: B,
    inbound_codec: MtProtoCodecState,
    outbound_codec: MtProtoCodecState,
    idle_timeout: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut inbound_decrypt, mut inbound_encrypt) = inbound_codec.into_parts();
    let (mut outbound_decrypt, mut outbound_encrypt) = outbound_codec.into_parts();
    let (inbound_reader, inbound_writer) = tokio::io::split(inbound);
    let (outbound_reader, outbound_writer) = tokio::io::split(outbound);

    let client_to_dc = relay_one_direction(
        inbound_reader,
        outbound_writer,
        idle_timeout,
        move |bytes| {
            inbound_decrypt.apply_keystream(bytes);
            outbound_encrypt.apply_keystream(bytes);
        },
    );
    let dc_to_client = relay_one_direction(
        outbound_reader,
        inbound_writer,
        idle_timeout,
        move |bytes| {
            outbound_decrypt.apply_keystream(bytes);
            inbound_encrypt.apply_keystream(bytes);
        },
    );

    let _ = tokio::try_join!(client_to_dc, dc_to_client)?;
    Ok(())
}

async fn relay_one_direction<R, W, F>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
    mut transform: F,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(&mut [u8]) + Send,
{
    let mut buffer = [0_u8; 16 * 1024];

    loop {
        let read = timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle read timeout"))??;

        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }

        transform(&mut buffer[..read]);

        timeout(idle_timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle write timeout"))??;
    }
}

fn generate_init_bytes(transport: MtProtoTransport, target_dc: Option<i16>) -> [u8; INIT_LEN] {
    loop {
        let mut init = [0_u8; INIT_LEN];
        OsRng.fill_bytes(&mut init);
        init[56..60].copy_from_slice(&transport.tag().to_le_bytes());
        if let Some(target_dc) = target_dc {
            init[60..62].copy_from_slice(&target_dc.to_le_bytes());
        }
        if valid_init_prefix(&init) {
            return init;
        }
    }
}

fn valid_init_prefix(init: &[u8; INIT_LEN]) -> bool {
    let first = u32::from_le_bytes(init[0..4].try_into().unwrap());
    let second = u32::from_le_bytes(init[4..8].try_into().unwrap());
    init[0] != 0xef
        && first != u32::from_le_bytes(*b"HEAD")
        && first != u32::from_le_bytes(*b"POST")
        && first != u32::from_le_bytes(*b"GET ")
        && first != u32::from_le_bytes(*b"OPTI")
        && second != 0
}

fn build_client_to_server_ctr(
    init: &[u8; INIT_LEN],
    secret: Option<&[u8; PLAIN_SECRET_LEN]>,
) -> Aes256Ctr {
    let key = derive_key(&init[8..40], secret);
    let iv: [u8; 16] = init[40..56].try_into().unwrap();
    Aes256Ctr::new((&key).into(), (&iv).into())
}

fn build_server_to_client_ctr(
    init: &[u8; INIT_LEN],
    secret: Option<&[u8; PLAIN_SECRET_LEN]>,
) -> Aes256Ctr {
    let mut reversed = *init;
    reversed.reverse();
    let key = derive_key(&reversed[8..40], secret);
    let iv: [u8; 16] = reversed[40..56].try_into().unwrap();
    Aes256Ctr::new((&key).into(), (&iv).into())
}

fn derive_key(key_material: &[u8], secret: Option<&[u8; PLAIN_SECRET_LEN]>) -> [u8; 32] {
    match secret {
        Some(secret) => {
            let mut hasher = Sha256::new();
            hasher.update(key_material);
            hasher.update(secret);
            hasher.finalize().into()
        }
        None => key_material.try_into().unwrap(),
    }
}

fn decode_handshake_common(
    received_header: [u8; INIT_LEN],
    secret: Option<&[u8; PLAIN_SECRET_LEN]>,
) -> Result<(MtProtoTransport, [u8; INIT_LEN], MtProtoCodecState)> {
    let mut decrypt = build_client_to_server_ctr(&received_header, secret);
    let encrypt = build_server_to_client_ctr(&received_header, secret);

    let mut decrypted = received_header;
    decrypt.apply_keystream(&mut decrypted);

    let transport =
        MtProtoTransport::from_tag(u32::from_le_bytes(decrypted[56..60].try_into().unwrap()))?;

    Ok((transport, decrypted, MtProtoCodecState { decrypt, encrypt }))
}

async fn read_inbound_mtproxy_handshake_inner<S>(
    stream: &mut S,
    secret: &ParsedMtProxySecret,
) -> Result<InboundMtProxyHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if secret.fake_tls_domain().is_some() {
        return read_inbound_fake_tls_mtproxy_handshake(stream, secret).await;
    }

    let mut header = [0_u8; INIT_LEN];
    stream.read_exact(&mut header).await?;
    decode_inbound_mtproxy_handshake(header, secret)
}

async fn read_inbound_fake_tls_mtproxy_handshake<S>(
    stream: &mut S,
    secret: &ParsedMtProxySecret,
) -> Result<InboundMtProxyHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_hello_record = read_required_tls_record(stream, MAX_FAKE_TLS_CLIENT_HELLO_LEN)
        .await
        .context("failed to read fake-TLS ClientHello")?;
    let client_hello = parse_fake_tls_client_hello(&client_hello_record)?;
    validate_fake_tls_client_hello(&client_hello_record, &client_hello, secret)?;

    let response = build_fake_tls_server_hello(&client_hello, secret.key());
    stream
        .write_all(&response)
        .await
        .context("failed to write fake-TLS ServerHello")?;

    let first_payload = read_fake_tls_first_application_payload(stream).await?;
    if first_payload.len() < INIT_LEN {
        bail!(
            "first fake-TLS application record was too short: expected at least {INIT_LEN} bytes, got {}",
            first_payload.len()
        );
    }

    let mut header = [0_u8; INIT_LEN];
    header.copy_from_slice(&first_payload[..INIT_LEN]);
    decode_inbound_mtproxy_handshake_with_framing(
        header,
        secret,
        MtProxyClientFraming::FakeTls(FakeTlsFrameState {
            pending_client_payload: first_payload[INIT_LEN..].to_vec(),
        }),
    )
}

async fn relay_fake_tls_client_to_dc<R, W, F>(
    mut reader: R,
    mut writer: W,
    mut pending_payload: Vec<u8>,
    idle_timeout: Duration,
    mut transform: F,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(&mut [u8]) + Send,
{
    if !pending_payload.is_empty() {
        transform(&mut pending_payload);
        timeout(idle_timeout, writer.write_all(&pending_payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle write timeout"))??;
    }

    loop {
        let payload = timeout(idle_timeout, read_optional_tls_record(&mut reader, MAX_FAKE_TLS_RECORD_PAYLOAD_LEN))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle read timeout"))??;

        let mut record = match payload {
            Some(record) => record,
            None => {
                writer.shutdown().await?;
                return Ok(());
            }
        };

        if record[0] != TLS_APPLICATION_RECORD_TYPE || record[1..3] != [0x03, 0x03] {
            return Err(io_invalid_data("expected TLS application data record"));
        }

        let mut payload = record.split_off(TLS_RECORD_HEADER_LEN);
        if payload.is_empty() {
            continue;
        }

        transform(&mut payload);
        timeout(idle_timeout, writer.write_all(&payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle write timeout"))??;
    }
}

async fn relay_dc_to_fake_tls_client<R, W, F>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
    mut transform: F,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(&mut [u8]) + Send,
{
    let mut buffer = [0_u8; 16 * 1024];

    loop {
        let read = timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle read timeout"))??;

        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }

        transform(&mut buffer[..read]);
        write_tls_application_payload(&mut writer, &buffer[..read], idle_timeout).await?;
    }
}

async fn read_fake_tls_first_application_payload<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut ccs = [0_u8; TLS_CHANGE_CIPHER_SPEC_RECORD.len()];
    stream.read_exact(&mut ccs).await?;
    if ccs != TLS_CHANGE_CIPHER_SPEC_RECORD {
        bail!("expected dummy TLS ChangeCipherSpec after fake-TLS ServerHello");
    }

    let record = read_required_tls_record(stream, MAX_FAKE_TLS_RECORD_PAYLOAD_LEN)
        .await
        .context("failed to read first fake-TLS application record")?;
    if record[0] != TLS_APPLICATION_RECORD_TYPE || record[1..3] != [0x03, 0x03] {
        bail!("expected TLS application data record after dummy ChangeCipherSpec");
    }

    Ok(record[TLS_RECORD_HEADER_LEN..].to_vec())
}

async fn read_required_tls_record<S>(stream: &mut S, max_payload_len: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    read_optional_tls_record(stream, max_payload_len)
        .await?
        .ok_or_else(|| anyhow!("peer closed connection"))
}

async fn read_optional_tls_record<S>(
    stream: &mut S,
    max_payload_len: usize,
) -> io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; TLS_RECORD_HEADER_LEN];
    let read = stream.read(&mut header[..1]).await?;
    if read == 0 {
        return Ok(None);
    }

    stream.read_exact(&mut header[1..]).await?;
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if payload_len > max_payload_len {
        return Err(io_invalid_data(format!(
            "TLS record payload exceeded limit: {payload_len} > {max_payload_len}"
        )));
    }

    let mut record = vec![0_u8; TLS_RECORD_HEADER_LEN + payload_len];
    record[..TLS_RECORD_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut record[TLS_RECORD_HEADER_LEN..]).await?;
    Ok(Some(record))
}

async fn write_tls_application_payload<W>(
    writer: &mut W,
    payload: &[u8],
    idle_timeout: Duration,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return Ok(());
    }

    for chunk in payload.chunks(MAX_FAKE_TLS_WRITE_CHUNK) {
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + chunk.len());
        record.extend_from_slice(&[
            TLS_APPLICATION_RECORD_TYPE,
            0x03,
            0x03,
            ((chunk.len() >> 8) & 0xff) as u8,
            (chunk.len() & 0xff) as u8,
        ]);
        record.extend_from_slice(chunk);
        timeout(idle_timeout, writer.write_all(&record))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle write timeout"))??;
    }

    Ok(())
}

fn parse_fake_tls_client_hello(record: &[u8]) -> Result<FakeTlsClientHello> {
    if record.len() < 5 + 4 + 2 + 32 + 1 + 2 + 1 + 2 {
        bail!("fake-TLS ClientHello was too short");
    }
    if record[0..3] != [0x16, 0x03, 0x01] {
        bail!("expected TLS ClientHello record prefix");
    }

    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record_len + TLS_RECORD_HEADER_LEN != record.len() {
        bail!("fake-TLS ClientHello length did not match TLS record header");
    }
    if record[5] != 0x01 {
        bail!("expected TLS handshake type ClientHello");
    }

    let handshake_len =
        ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    if handshake_len + 4 != record_len {
        bail!("fake-TLS ClientHello handshake length mismatch");
    }
    if record[9..11] != [0x03, 0x03] {
        bail!("expected TLS 1.2 ClientHello version");
    }

    let client_random: [u8; 32] = record[11..43].try_into().unwrap();
    let session_id_len = record[43] as usize;
    let mut pos = 44;
    ensure_length(record, pos, session_id_len, "fake-TLS ClientHello session id")?;
    let session_id = record[pos..pos + session_id_len].to_vec();
    pos += session_id_len;

    let cipher_suites_len = read_be_u16(record, &mut pos, "fake-TLS ClientHello cipher suites")?;
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        bail!("fake-TLS ClientHello cipher suites length must be a non-zero even number");
    }
    ensure_length(
        record,
        pos,
        cipher_suites_len,
        "fake-TLS ClientHello cipher suites payload",
    )?;
    let cipher_suites = &record[pos..pos + cipher_suites_len];
    pos += cipher_suites_len;

    let compression_methods_len =
        read_u8_len(record, &mut pos, "fake-TLS ClientHello compression methods")?;
    ensure_length(
        record,
        pos,
        compression_methods_len,
        "fake-TLS ClientHello compression methods payload",
    )?;
    pos += compression_methods_len;

    let extensions_len =
        read_be_u16(record, &mut pos, "fake-TLS ClientHello extensions")?;
    ensure_length(
        record,
        pos,
        extensions_len,
        "fake-TLS ClientHello extensions payload",
    )?;
    let extensions_end = pos + extensions_len;

    let mut sni_domain = None;
    while pos < extensions_end {
        let extension_id = read_be_u16(record, &mut pos, "fake-TLS extension id")?;
        let extension_len = read_be_u16(record, &mut pos, "fake-TLS extension length")?;
        ensure_length(record, pos, extension_len, "fake-TLS extension payload")?;
        if extension_id == 0 {
            sni_domain = Some(parse_fake_tls_sni_extension(
                &record[pos..pos + extension_len],
            )?);
        }
        pos += extension_len;
    }

    if pos != extensions_end || extensions_end != record.len() {
        bail!("fake-TLS ClientHello extensions were malformed");
    }

    let cipher_suite_id = select_tls13_cipher_suite(cipher_suites)?;
    Ok(FakeTlsClientHello {
        client_random,
        session_id,
        cipher_suite_id,
        sni_domain: sni_domain.ok_or_else(|| anyhow!("fake-TLS ClientHello was missing SNI"))?,
    })
}

fn validate_fake_tls_client_hello(
    client_hello_record: &[u8],
    client_hello: &FakeTlsClientHello,
    secret: &ParsedMtProxySecret,
) -> Result<()> {
    let expected_domain = secret
        .fake_tls_domain()
        .ok_or_else(|| anyhow!("fake-TLS validation requires an ee-prefixed secret"))?;
    if normalize_fake_tls_domain(&client_hello.sni_domain) != expected_domain {
        bail!(
            "fake-TLS ClientHello SNI {} did not match configured domain {}",
            client_hello.sni_domain,
            expected_domain
        );
    }

    let mut zeroed_client_hello = client_hello_record.to_vec();
    zeroed_client_hello[11..43].fill(0);
    let expected_random = hmac_sha256(secret.key(), &zeroed_client_hello);
    if expected_random[..28] != client_hello.client_random[..28] {
        bail!("fake-TLS ClientHello HMAC prefix did not match configured secret");
    }

    let expected_tail = u32::from_le_bytes(expected_random[28..32].try_into().unwrap());
    let masked_tail = u32::from_le_bytes(client_hello.client_random[28..32].try_into().unwrap());
    validate_fake_tls_timestamp((expected_tail ^ masked_tail) as i64)?;
    Ok(())
}

fn build_fake_tls_server_hello(
    client_hello: &FakeTlsClientHello,
    secret: &[u8; PLAIN_SECRET_LEN],
) -> Vec<u8> {
    let encrypted_payload_len = FAKE_TLS_ENCRYPTED_SERVER_PAYLOAD_BASE_LEN
        + ((OsRng.next_u32() as usize) % FAKE_TLS_ENCRYPTED_SERVER_PAYLOAD_VARIATION);
    let extensions_len = 40 + 6;
    let handshake_body_len = 2 + 32 + 1 + client_hello.session_id.len() + 2 + 1 + 2 + extensions_len;
    let record_len = 4 + handshake_body_len;

    let mut response = Vec::with_capacity(
        TLS_RECORD_HEADER_LEN + record_len + TLS_CHANGE_CIPHER_SPEC_RECORD.len() + TLS_RECORD_HEADER_LEN + encrypted_payload_len,
    );
    response.extend_from_slice(&[0x16, 0x03, 0x03]);
    response.extend_from_slice(&(record_len as u16).to_be_bytes());
    response.push(0x02);
    response.extend_from_slice(&(handshake_body_len as u32).to_be_bytes()[1..4]);
    response.extend_from_slice(&[0x03, 0x03]);

    let server_random_offset = response.len();
    response.extend_from_slice(&[0_u8; 32]);
    response.push(client_hello.session_id.len() as u8);
    response.extend_from_slice(&client_hello.session_id);
    response.extend_from_slice(&[0x13, client_hello.cipher_suite_id, 0x00]);
    response.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    response.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    let mut public_key = [0_u8; 32];
    OsRng.fill_bytes(&mut public_key);
    response.extend_from_slice(&public_key);
    response.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

    response.extend_from_slice(&TLS_CHANGE_CIPHER_SPEC_RECORD);
    response.extend_from_slice(&[
        TLS_APPLICATION_RECORD_TYPE,
        0x03,
        0x03,
        ((encrypted_payload_len >> 8) & 0xff) as u8,
        (encrypted_payload_len & 0xff) as u8,
    ]);
    let mut encrypted_payload = vec![0_u8; encrypted_payload_len];
    OsRng.fill_bytes(&mut encrypted_payload);
    response.extend_from_slice(&encrypted_payload);

    let mut hmac_input = Vec::with_capacity(client_hello.client_random.len() + response.len());
    hmac_input.extend_from_slice(&client_hello.client_random);
    hmac_input.extend_from_slice(&response);
    let server_random = hmac_sha256(secret, &hmac_input);
    response[server_random_offset..server_random_offset + 32].copy_from_slice(&server_random);
    response
}

fn read_be_u16(buffer: &[u8], pos: &mut usize, context: &str) -> Result<usize> {
    ensure_length(buffer, *pos, 2, context)?;
    let value = u16::from_be_bytes([buffer[*pos], buffer[*pos + 1]]) as usize;
    *pos += 2;
    Ok(value)
}

fn read_u8_len(buffer: &[u8], pos: &mut usize, context: &str) -> Result<usize> {
    ensure_length(buffer, *pos, 1, context)?;
    let value = buffer[*pos] as usize;
    *pos += 1;
    Ok(value)
}

fn ensure_length(buffer: &[u8], pos: usize, len: usize, context: &str) -> Result<()> {
    if pos + len > buffer.len() {
        bail!("{context} was truncated");
    }
    Ok(())
}

fn parse_fake_tls_sni_extension(extension: &[u8]) -> Result<String> {
    let mut pos = 0;
    let server_name_list_len = read_be_u16(extension, &mut pos, "fake-TLS SNI list")?;
    if server_name_list_len + 2 != extension.len() {
        bail!("fake-TLS SNI list length mismatch");
    }
    ensure_length(extension, pos, 1, "fake-TLS SNI name type")?;
    if extension[pos] != 0 {
        bail!("fake-TLS SNI name type must be host_name");
    }
    pos += 1;
    let name_len = read_be_u16(extension, &mut pos, "fake-TLS SNI host length")?;
    ensure_length(extension, pos, name_len, "fake-TLS SNI host payload")?;
    if pos + name_len != extension.len() {
        bail!("fake-TLS SNI extension had trailing data");
    }

    let domain = std::str::from_utf8(&extension[pos..pos + name_len])
        .context("fake-TLS SNI host was not valid UTF-8")?;
    let domain = normalize_fake_tls_domain(domain);
    validate_fake_tls_domain(&domain)?;
    Ok(domain)
}

fn select_tls13_cipher_suite(cipher_suites: &[u8]) -> Result<u8> {
    for suite in cipher_suites.chunks_exact(2) {
        if (suite[0] & 0x0f) == 0x0a && (suite[1] & 0x0f) == 0x0a {
            continue;
        }
        if suite[0] == 0x13 && (0x01..=0x03).contains(&suite[1]) {
            return Ok(suite[1]);
        }
    }

    bail!("fake-TLS ClientHello did not advertise a supported TLS 1.3 cipher suite")
}

fn validate_fake_tls_timestamp(timestamp: i64) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if timestamp > now + MAX_FAKE_TLS_FUTURE_SKEW_SECS {
        bail!("fake-TLS ClientHello timestamp was too far in the future");
    }
    if timestamp < now - MAX_FAKE_TLS_PAST_SKEW_SECS {
        bail!("fake-TLS ClientHello timestamp was too old");
    }

    Ok(())
}

fn normalize_fake_tls_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_fake_tls_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        bail!("fake-TLS domain must not be empty");
    }
    if !domain.is_ascii() {
        bail!("fake-TLS domain must be ASCII");
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        bail!("fake-TLS domain must not start or end with '.'");
    }
    if domain.bytes().any(|byte| byte == 0 || byte.is_ascii_whitespace()) {
        bail!("fake-TLS domain must not contain whitespace or NUL bytes");
    }

    Ok(())
}

fn hmac_sha256(secret: &[u8; PLAIN_SECRET_LEN], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts 16-byte MTProxy key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn io_invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug)]
struct FakeTlsClientHello {
    client_random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suite_id: u8,
    sni_domain: String,
}

#[cfg(test)]
mod tests {
    use super::{
        build_outbound_mtproxy_client_connection, decode_inbound_mtproxy_handshake,
        parse_mtproxy_secret, MtProtoTransport,
    };

    #[test]
    fn mtproxy_secret_parses_dd_prefix() {
        let secret = parse_mtproxy_secret("dd00112233445566778899aabbccddeeff").expect("secret");
        assert_eq!(
            secret.required_transport(),
            Some(MtProtoTransport::PaddedIntermediate)
        );
    }

    #[test]
    fn mtproxy_secret_parses_ee_prefix_and_domain() {
        let secret = parse_mtproxy_secret(
            "ee00112233445566778899aabbccddeeff6578616d706c652e636f6d",
        )
        .expect("secret");
        assert_eq!(
            secret.required_transport(),
            Some(MtProtoTransport::PaddedIntermediate)
        );
        assert_eq!(secret.fake_tls_domain(), Some("example.com"));
    }

    #[test]
    fn inbound_handshake_decodes_padded_transport_and_target() {
        let secret = parse_mtproxy_secret("dd00112233445566778899aabbccddeeff").expect("secret");
        let outbound = build_outbound_mtproxy_client_connection(
            MtProtoTransport::PaddedIntermediate,
            3,
            &secret,
        )
        .expect("connection");

        let inbound =
            decode_inbound_mtproxy_handshake(outbound.init_payload, &secret).expect("handshake");
        assert_eq!(inbound.transport, MtProtoTransport::PaddedIntermediate);
        assert_eq!(inbound.target_dc, 3);
    }
}
