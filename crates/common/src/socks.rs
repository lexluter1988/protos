use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::SocksAuthConfig;
use crate::protocol::TargetAddr;

pub const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
pub const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const SOCKS_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const SOCKS_REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const SOCKS_REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_AUTH_VERSION: u8 = 0x01;
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS_METHOD_USERNAME_PASSWORD: u8 = 0x02;
const SOCKS_METHOD_NO_ACCEPTABLE: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksConnectRequest {
    pub target: TargetAddr,
    pub port: u16,
}

pub async fn accept_request<S>(
    stream: &mut S,
    auth: Option<&SocksAuthConfig>,
) -> io::Result<SocksConnectRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_method(stream, auth).await?;
    if let Some(auth) = auth {
        authenticate(stream, auth).await?;
    }
    read_connect_request(stream).await
}

pub async fn send_success_reply<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_reply_with_addr(
        stream,
        SOCKS_REPLY_SUCCEEDED,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        0,
    )
    .await
}

pub async fn send_reply<S>(stream: &mut S, code: u8) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_reply_with_addr(
        stream,
        code,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        0,
    )
    .await
}

async fn negotiate_method<S>(stream: &mut S, auth: Option<&SocksAuthConfig>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS version",
        ));
    }

    let method_count = stream.read_u8().await? as usize;
    if method_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing SOCKS auth methods",
        ));
    }

    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;

    let selected = match auth {
        Some(_) if methods.contains(&SOCKS_METHOD_USERNAME_PASSWORD) => {
            SOCKS_METHOD_USERNAME_PASSWORD
        }
        None if methods.contains(&SOCKS_METHOD_NO_AUTH) => SOCKS_METHOD_NO_AUTH,
        _ => SOCKS_METHOD_NO_ACCEPTABLE,
    };

    stream.write_all(&[SOCKS_VERSION, selected]).await?;
    stream.flush().await?;

    if selected == SOCKS_METHOD_NO_ACCEPTABLE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client did not offer a supported SOCKS5 auth method",
        ));
    }

    Ok(())
}

async fn authenticate<S>(stream: &mut S, auth: &SocksAuthConfig) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != SOCKS_AUTH_VERSION {
        let _ = stream.write_all(&[SOCKS_AUTH_VERSION, 0xff]).await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported username/password auth version",
        ));
    }

    let username_length = stream.read_u8().await? as usize;
    let mut username = vec![0_u8; username_length];
    stream.read_exact(&mut username).await?;

    let password_length = stream.read_u8().await? as usize;
    let mut password = vec![0_u8; password_length];
    stream.read_exact(&mut password).await?;

    let valid = username == auth.username.as_bytes() && password == auth.password.as_bytes();
    let status = if valid { 0x00 } else { 0xff };
    stream.write_all(&[SOCKS_AUTH_VERSION, status]).await?;
    stream.flush().await?;

    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SOCKS username/password",
        ))
    }
}

async fn read_connect_request<S>(stream: &mut S) -> io::Result<SocksConnectRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS request version",
        ));
    }

    let command = stream.read_u8().await?;
    let _reserved = stream.read_u8().await?;
    let addr_type = stream.read_u8().await?;

    if command != SOCKS_CMD_CONNECT {
        let _ = send_reply(stream, SOCKS_REPLY_COMMAND_NOT_SUPPORTED).await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only SOCKS5 CONNECT is supported",
        ));
    }

    let target = match addr_type {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                let _ = send_reply(stream, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "domain length cannot be zero",
                ));
            }
            let mut bytes = vec![0_u8; length];
            stream.read_exact(&mut bytes).await?;
            let domain = String::from_utf8(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "domain is not valid UTF-8")
            })?;
            TargetAddr::Domain(domain)
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => {
            let _ = send_reply(stream, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    };

    let port = stream.read_u16().await?;
    Ok(SocksConnectRequest { target, port })
}

async fn send_reply_with_addr<S>(
    stream: &mut S,
    code: u8,
    target: TargetAddr,
    port: u16,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_u8(SOCKS_VERSION).await?;
    stream.write_u8(code).await?;
    stream.write_u8(0).await?;

    match target {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            stream.write_u8(0x01).await?;
            stream.write_all(&ip.octets()).await?;
        }
        TargetAddr::Domain(domain) => {
            stream.write_u8(0x03).await?;
            stream.write_u8(domain.len() as u8).await?;
            stream.write_all(domain.as_bytes()).await?;
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            stream.write_u8(0x04).await?;
            stream.write_all(&ip.octets()).await?;
        }
    }

    stream.write_u16(port).await?;
    stream.flush().await?;
    Ok(())
}
