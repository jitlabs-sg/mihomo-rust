//! WebSocket transport for VMess/Trojan

use crate::{Error, Result};
use base64::Engine;
use bytes::{BufMut, BytesMut};
use rand::Rng;
use sha1::{Digest, Sha1};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

/// WebSocket opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl TryFrom<u8> for OpCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x0 => Ok(OpCode::Continuation),
            0x1 => Ok(OpCode::Text),
            0x2 => Ok(OpCode::Binary),
            0x8 => Ok(OpCode::Close),
            0x9 => Ok(OpCode::Ping),
            0xA => Ok(OpCode::Pong),
            _ => Err(Error::protocol(format!("Unknown WebSocket opcode: {}", value))),
        }
    }
}

/// WebSocket frame header
#[derive(Debug)]
pub struct FrameHeader {
    pub fin: bool,
    pub opcode: OpCode,
    pub mask: bool,
    pub payload_len: u64,
    pub masking_key: Option<[u8; 4]>,
}

impl FrameHeader {
    /// Parse frame header from bytes
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;

        let fin = buf[0] & 0x80 != 0;
        let opcode = OpCode::try_from(buf[0] & 0x0F)?;
        let mask = buf[1] & 0x80 != 0;
        let len = buf[1] & 0x7F;

        let payload_len = match len {
            126 => {
                let mut len_buf = [0u8; 2];
                reader.read_exact(&mut len_buf).await?;
                u16::from_be_bytes(len_buf) as u64
            }
            127 => {
                let mut len_buf = [0u8; 8];
                reader.read_exact(&mut len_buf).await?;
                u64::from_be_bytes(len_buf)
            }
            _ => len as u64,
        };

        let masking_key = if mask {
            let mut key = [0u8; 4];
            reader.read_exact(&mut key).await?;
            Some(key)
        } else {
            None
        };

        Ok(FrameHeader {
            fin,
            opcode,
            mask,
            payload_len,
            masking_key,
        })
    }

    /// Write frame header to bytes
    pub fn write_to(&self, buf: &mut BytesMut) {
        let mut first_byte = if self.fin { 0x80 } else { 0 };
        first_byte |= self.opcode as u8;
        buf.put_u8(first_byte);

        let mut second_byte = if self.mask { 0x80 } else { 0 };
        if self.payload_len < 126 {
            second_byte |= self.payload_len as u8;
            buf.put_u8(second_byte);
        } else if self.payload_len <= u16::MAX as u64 {
            second_byte |= 126;
            buf.put_u8(second_byte);
            buf.put_u16(self.payload_len as u16);
        } else {
            second_byte |= 127;
            buf.put_u8(second_byte);
            buf.put_u64(self.payload_len);
        }

        if let Some(key) = self.masking_key {
            buf.put_slice(&key);
        }
    }
}

/// Apply WebSocket masking
pub fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

/// Generate random masking key
pub fn generate_mask_key() -> [u8; 4] {
    rand::random()
}

/// WebSocket connection wrapper
pub struct WebSocketStream<S> {
    inner: S,
    read_buf: BytesMut,
    pending_data: BytesMut,
}

impl<S> WebSocketStream<S> {
    pub fn new(inner: S) -> Self {
        WebSocketStream {
            inner,
            read_buf: BytesMut::with_capacity(4096),
            pending_data: BytesMut::new(),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> WebSocketStream<S> {
    /// Read a complete frame payload
    pub async fn read_frame(&mut self) -> Result<(OpCode, Vec<u8>)> {
        let header = FrameHeader::read_from(&mut self.inner).await?;

        let mut payload = vec![0u8; header.payload_len as usize];
        self.inner.read_exact(&mut payload).await?;

        // Unmask if needed
        if let Some(key) = header.masking_key {
            apply_mask(&mut payload, key);
        }

        Ok((header.opcode, payload))
    }
}

impl<S: AsyncWrite + Unpin> WebSocketStream<S> {
    /// Write a frame
    pub async fn write_frame(&mut self, opcode: OpCode, data: &[u8], mask: bool) -> Result<()> {
        let mut buf = BytesMut::new();

        let masking_key = if mask {
            Some(generate_mask_key())
        } else {
            None
        };

        let header = FrameHeader {
            fin: true,
            opcode,
            mask,
            payload_len: data.len() as u64,
            masking_key,
        };

        header.write_to(&mut buf);

        if let Some(key) = masking_key {
            let mut masked_data = data.to_vec();
            apply_mask(&mut masked_data, key);
            buf.put_slice(&masked_data);
        } else {
            buf.put_slice(data);
        }

        self.inner.write_all(&buf).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Return pending data first
        if !self.pending_data.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.pending_data.len());
            buf.put_slice(&self.pending_data.split_to(to_read));
            return Poll::Ready(Ok(()));
        }

        // Read from inner
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Perform WebSocket client handshake
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    path: &str,
    extra_headers: &[(String, String)],
) -> Result<()> {
    // Generate WebSocket key
    let ws_key: [u8; 16] = rand::random();
    let ws_key_b64 = base64::engine::general_purpose::STANDARD.encode(ws_key);

    // Build request
    let mut request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n",
        path, host, ws_key_b64
    );

    for (key, value) in extra_headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }
    request.push_str("\r\n");

    // Send request
    stream.write_all(request.as_bytes()).await?;

    // Read response
    let mut response = String::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await?;
        response.push(buf[0] as char);
        if response.ends_with("\r\n\r\n") {
            break;
        }
        if response.len() > 4096 {
            return Err(Error::protocol("WebSocket response too long"));
        }
    }

    // Check response
    if !response.starts_with("HTTP/1.1 101") {
        return Err(Error::protocol(format!(
            "WebSocket handshake failed: {}",
            response.lines().next().unwrap_or("unknown")
        )));
    }

    // Verify Sec-WebSocket-Accept
    let expected_accept = {
        let mut hasher = Sha1::new();
        hasher.update(ws_key_b64.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };

    let accept_header = response
        .lines()
        .find(|line| line.to_lowercase().starts_with("sec-websocket-accept:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|v| v.trim());

    if accept_header != Some(&expected_accept) {
        return Err(Error::protocol("Invalid Sec-WebSocket-Accept"));
    }

    debug!("WebSocket handshake completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode() {
        assert_eq!(OpCode::try_from(0x1).unwrap(), OpCode::Text);
        assert_eq!(OpCode::try_from(0x2).unwrap(), OpCode::Binary);
        assert!(OpCode::try_from(0xF).is_err());
    }

    #[test]
    fn test_masking() {
        let key = [0x12, 0x34, 0x56, 0x78];
        let mut data = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        apply_mask(&mut data, key);
        assert_eq!(data, vec![0x12, 0x34, 0x56, 0x78, 0x12]);
    }

    #[test]
    fn test_frame_header_write() {
        let header = FrameHeader {
            fin: true,
            opcode: OpCode::Binary,
            mask: false,
            payload_len: 100,
            masking_key: None,
        };

        let mut buf = BytesMut::new();
        header.write_to(&mut buf);

        assert_eq!(buf[0], 0x82); // FIN + Binary
        assert_eq!(buf[1], 100); // Length
    }
}
