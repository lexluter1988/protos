use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const RELAY_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct RelayStats {
    pub left_to_right_bytes: u64,
    pub right_to_left_bytes: u64,
}

pub async fn relay_bidirectional<A, B>(
    left: A,
    right: B,
    idle_timeout: Duration,
) -> io::Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (left_reader, left_writer) = tokio::io::split(left);
    let (right_reader, right_writer) = tokio::io::split(right);

    let left_to_right = pipe_with_idle_timeout(left_reader, right_writer, idle_timeout);
    let right_to_left = pipe_with_idle_timeout(right_reader, left_writer, idle_timeout);

    let (left_to_right_bytes, right_to_left_bytes) =
        tokio::try_join!(left_to_right, right_to_left)?;

    Ok(RelayStats {
        left_to_right_bytes,
        right_to_left_bytes,
    })
}

async fn pipe_with_idle_timeout<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; RELAY_BUFFER_SIZE];
    let mut total = 0_u64;

    loop {
        let read = timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle read timeout"))??;

        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        timeout(idle_timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle write timeout"))??;

        total += read as u64;
    }
}
