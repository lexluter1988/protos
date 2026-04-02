use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_TOKEN_LEN: usize = 1024;
pub const MAX_DOMAIN_LEN: usize = 255;
pub const MAX_HANDSHAKE_OVERHEAD: usize = 10;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    Local,
    #[default]
    Remote,
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Remote => write!(f, "remote"),
        }
    }
}

impl FromStr for DnsMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            _ => Err(anyhow!("expected dns mode local or remote, got {s}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

impl TargetAddr {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Ip(_) => Ok(()),
            Self::Domain(domain) => validate_domain(domain),
        }
    }

    pub fn as_log_value(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Domain(domain) => domain.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub token: String,
    pub dns_mode: DnsMode,
    pub target: TargetAddr,
    pub port: u16,
}

impl ConnectRequest {
    pub fn encoded_len(&self) -> usize {
        MAX_HANDSHAKE_OVERHEAD + self.token.len() + self.addr_len()
    }

    fn addr_len(&self) -> usize {
        match &self.target {
            TargetAddr::Ip(IpAddr::V4(_)) => 4,
            TargetAddr::Ip(IpAddr::V6(_)) => 16,
            TargetAddr::Domain(domain) => domain.len(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.token.is_empty() {
            return Err(anyhow!("empty auth token"));
        }
        if self.token.len() > MAX_TOKEN_LEN {
            return Err(anyhow!("auth token exceeds {} bytes", MAX_TOKEN_LEN));
        }
        if self.port == 0 {
            return Err(anyhow!("port must be greater than zero"));
        }
        self.target.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectStatus {
    Ok = 0,
    AuthFailed = 1,
    UnsupportedVersion = 2,
    BadRequest = 3,
    ResolveFailed = 4,
    ConnectFailed = 5,
    ServerBusy = 6,
    InternalError = 7,
}

impl ConnectStatus {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::AuthFailed),
            2 => Ok(Self::UnsupportedVersion),
            3 => Ok(Self::BadRequest),
            4 => Ok(Self::ResolveFailed),
            5 => Ok(Self::ConnectFailed),
            6 => Ok(Self::ServerBusy),
            7 => Ok(Self::InternalError),
            _ => Err(anyhow!("unknown connect status {value}")),
        }
    }
}

impl fmt::Display for ConnectStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::AuthFailed => write!(f, "auth_failed"),
            Self::UnsupportedVersion => write!(f, "unsupported_version"),
            Self::BadRequest => write!(f, "bad_request"),
            Self::ResolveFailed => write!(f, "resolve_failed"),
            Self::ConnectFailed => write!(f, "connect_failed"),
            Self::ServerBusy => write!(f, "server_busy"),
            Self::InternalError => write!(f, "internal_error"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectResponse {
    pub status: ConnectStatus,
}

pub async fn write_connect_request<W>(writer: &mut W, request: &ConnectRequest) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    request.validate()?;

    let addr_type = match &request.target {
        TargetAddr::Ip(IpAddr::V4(_)) => 1_u8,
        TargetAddr::Domain(_) => 2_u8,
        TargetAddr::Ip(IpAddr::V6(_)) => 3_u8,
    };

    writer.write_u8(PROTOCOL_VERSION).await?;
    writer.write_u8(request.dns_mode as u8).await?;
    writer.write_u8(addr_type).await?;
    writer.write_u8(0).await?;
    writer.write_u16(request.token.len() as u16).await?;
    writer.write_u16(request.addr_len() as u16).await?;
    writer.write_u16(request.port).await?;
    writer.write_all(request.token.as_bytes()).await?;

    match &request.target {
        TargetAddr::Ip(IpAddr::V4(ip)) => writer.write_all(&ip.octets()).await?,
        TargetAddr::Ip(IpAddr::V6(ip)) => writer.write_all(&ip.octets()).await?,
        TargetAddr::Domain(domain) => writer.write_all(domain.as_bytes()).await?,
    }

    writer.flush().await?;
    Ok(())
}

pub async fn read_connect_request<R>(
    reader: &mut R,
    max_handshake_size: usize,
) -> Result<ConnectRequest>
where
    R: AsyncRead + Unpin,
{
    let version = reader.read_u8().await?;
    if version != PROTOCOL_VERSION {
        return Err(anyhow!("unsupported protocol version {version}"));
    }

    let dns_mode = parse_dns_mode(reader.read_u8().await?)?;
    let addr_type = reader.read_u8().await?;
    let _reserved = reader.read_u8().await?;
    let token_len = reader.read_u16().await? as usize;
    let addr_len = reader.read_u16().await? as usize;
    let port = reader.read_u16().await?;

    if token_len == 0 || token_len > MAX_TOKEN_LEN {
        return Err(anyhow!("invalid token length {token_len}"));
    }

    let max_addr_len = match addr_type {
        1 => 4,
        2 => MAX_DOMAIN_LEN,
        3 => 16,
        _ => return Err(anyhow!("unsupported address type {addr_type}")),
    };

    if addr_len == 0 || addr_len > max_addr_len {
        return Err(anyhow!(
            "invalid address length {addr_len} for type {addr_type}"
        ));
    }

    let total_len = MAX_HANDSHAKE_OVERHEAD + token_len + addr_len;
    if total_len > max_handshake_size {
        return Err(anyhow!(
            "handshake size {} exceeds configured limit {}",
            total_len,
            max_handshake_size
        ));
    }

    let mut token = vec![0_u8; token_len];
    reader.read_exact(&mut token).await?;
    let token = String::from_utf8(token).context("auth token is not valid UTF-8")?;

    let target = match addr_type {
        1 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        2 => {
            let mut bytes = vec![0_u8; addr_len];
            reader.read_exact(&mut bytes).await?;
            let domain = String::from_utf8(bytes).context("domain is not valid UTF-8")?;
            TargetAddr::Domain(domain)
        }
        3 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => unreachable!(),
    };

    let request = ConnectRequest {
        token,
        dns_mode,
        target,
        port,
    };
    request.validate()?;
    Ok(request)
}

pub async fn write_connect_response<W>(writer: &mut W, response: ConnectResponse) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(PROTOCOL_VERSION).await?;
    writer.write_u8(response.status as u8).await?;
    writer.write_u16(0).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_connect_response<R>(reader: &mut R) -> Result<ConnectResponse>
where
    R: AsyncRead + Unpin,
{
    let version = reader.read_u8().await?;
    if version != PROTOCOL_VERSION {
        return Err(anyhow!("unexpected response protocol version {version}"));
    }

    let status = ConnectStatus::from_byte(reader.read_u8().await?)?;
    let _reserved = reader.read_u16().await?;

    Ok(ConnectResponse { status })
}

fn parse_dns_mode(value: u8) -> Result<DnsMode> {
    match value {
        0 => Ok(DnsMode::Local),
        1 => Ok(DnsMode::Remote),
        _ => Err(anyhow!("unsupported dns mode {value}")),
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(anyhow!("domain must not be empty"));
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(anyhow!("domain exceeds {} bytes", MAX_DOMAIN_LEN));
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(anyhow!("domain must not start or end with a dot"));
    }
    if domain.bytes().any(|byte| {
        byte == 0 || byte.is_ascii_control() || byte == b'/' || byte == b'\\' || byte == b' '
    }) {
        return Err(anyhow!("domain contains invalid characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn request_round_trip_domain() {
        let request = ConnectRequest {
            token: "shared-secret".into(),
            dns_mode: DnsMode::Remote,
            target: TargetAddr::Domain("api.telegram.org".into()),
            port: 443,
        };

        let (mut writer, mut reader) = duplex(1024);
        let expected = request.clone();
        let writer_task =
            tokio::spawn(async move { write_connect_request(&mut writer, &expected).await });
        let decoded = read_connect_request(&mut reader, 1024).await.unwrap();
        writer_task.await.unwrap().unwrap();

        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn request_round_trip_ipv4() {
        let request = ConnectRequest {
            token: "shared-secret".into(),
            dns_mode: DnsMode::Local,
            target: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(149, 154, 167, 50))),
            port: 443,
        };

        let (mut writer, mut reader) = duplex(1024);
        let expected = request.clone();
        let writer_task =
            tokio::spawn(async move { write_connect_request(&mut writer, &expected).await });
        let decoded = read_connect_request(&mut reader, 1024).await.unwrap();
        writer_task.await.unwrap().unwrap();

        assert_eq!(decoded, request);
    }
}
