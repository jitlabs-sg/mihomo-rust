//! HTTP Response Parser for connection pooling
//!
//! Parses HTTP responses to determine body length and enable connection reuse.
//! Supports Content-Length and Transfer-Encoding: chunked.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

/// Maximum response header size (32KB)
const MAX_RESPONSE_HEADER_SIZE: usize = 32 * 1024;

/// HTTP response metadata
#[derive(Debug)]
pub struct ResponseMeta {
    /// HTTP status code
    pub status_code: u16,
    /// Content-Length if present
    pub content_length: Option<u64>,
    /// Whether Transfer-Encoding: chunked
    pub chunked: bool,
    /// Whether Connection: close
    pub connection_close: bool,
    /// Total header length (including \r\n\r\n)
    pub header_len: usize,
}

/// Parse HTTP response headers from buffer
/// Returns None if headers are incomplete
pub fn parse_response_headers(buf: &[u8]) -> Option<ResponseMeta> {
    // Find end of headers
    let header_end = find_header_end(buf)?;
    let header_len = header_end + 4; // Include \r\n\r\n

    let header_str = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = header_str.lines();

    // Parse status line: HTTP/1.1 200 OK
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next()?; // HTTP/1.1
    let status_code: u16 = parts.next()?.parse().ok()?;

    let mut content_length = None;
    let mut chunked = false;
    let mut connection_close = false;

    // Parse headers
    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        let value = value.trim();

        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        } else if name.eq_ignore_ascii_case("connection") {
            connection_close = value.eq_ignore_ascii_case("close");
        } else if name.eq_ignore_ascii_case("proxy-connection") {
            // Also check Proxy-Connection
            if value.eq_ignore_ascii_case("close") {
                connection_close = true;
            }
        }
    }

    // Responses without body: 1xx, 204, 304
    if status_code < 200 || status_code == 204 || status_code == 304 {
        content_length = Some(0);
    }

    Some(ResponseMeta {
        status_code,
        content_length,
        chunked,
        connection_close,
        header_len,
    })
}

/// Find \r\n\r\n in buffer, returns index of first \r
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }

    for i in 0..buf.len() - 3 {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// Forward HTTP response from remote to client with proper body handling
/// Returns (bytes_written, can_reuse_connection)
pub async fn forward_response<R, W>(
    remote: &mut R,
    client: &mut W,
    initial_buf: &[u8],
) -> std::io::Result<(u64, bool)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(8 * 1024);
    buf.extend_from_slice(initial_buf);

    // Read until we have complete headers
    loop {
        if buf.len() >= MAX_RESPONSE_HEADER_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Response header too large",
            ));
        }

        if find_header_end(&buf).is_some() {
            break;
        }

        let mut tmp = [0u8; 4096];
        let n = remote.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before headers complete",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    // Parse response headers
    let meta = parse_response_headers(&buf).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid HTTP response")
    })?;

    trace!(
        "Response: status={}, content_length={:?}, chunked={}, close={}",
        meta.status_code,
        meta.content_length,
        meta.chunked,
        meta.connection_close
    );

    // Write headers to client
    client.write_all(&buf[..meta.header_len]).await?;
    let mut total_written = meta.header_len as u64;

    // Handle body based on transfer type
    let body_start = &buf[meta.header_len..];

    if let Some(content_length) = meta.content_length {
        // Fixed Content-Length
        total_written += forward_fixed_body(remote, client, body_start, content_length).await?;
    } else if meta.chunked {
        // Chunked transfer encoding
        total_written += forward_chunked_body(remote, client, body_start).await?;
    } else {
        // No Content-Length and not chunked - read until close
        // Write any buffered body data
        if !body_start.is_empty() {
            client.write_all(body_start).await?;
            total_written += body_start.len() as u64;
        }

        // Copy remaining data
        let mut tmp = [0u8; 8192];
        loop {
            let n = remote.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            client.write_all(&tmp[..n]).await?;
            total_written += n as u64;
        }

        // Can't reuse - had to read until close
        return Ok((total_written, false));
    }

    client.flush().await?;

    // Can reuse if not Connection: close
    Ok((total_written, !meta.connection_close))
}

/// Forward fixed-length body
async fn forward_fixed_body<R, W>(
    remote: &mut R,
    client: &mut W,
    initial_data: &[u8],
    content_length: u64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = content_length;

    // Write initial buffered data
    let to_write = std::cmp::min(initial_data.len() as u64, remaining) as usize;
    if to_write > 0 {
        client.write_all(&initial_data[..to_write]).await?;
        remaining -= to_write as u64;
    }

    // Read and forward remaining body
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = remote.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before body complete",
            ));
        }
        client.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }

    Ok(content_length)
}

/// Forward chunked body
async fn forward_chunked_body<R, W>(
    remote: &mut R,
    client: &mut W,
    initial_data: &[u8],
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(16 * 1024);
    buf.extend_from_slice(initial_data);
    let mut total_body = 0u64;

    loop {
        // Ensure we have a chunk header (line ending with \r\n)
        while !contains_line_end(&buf) {
            let mut tmp = [0u8; 4096];
            let n = remote.read(&mut tmp).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed in chunked body",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        // Parse chunk size
        let line_end = find_line_end(&buf).unwrap();
        let chunk_line = std::str::from_utf8(&buf[..line_end])
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid chunk header"))?;

        // Chunk size is hex, possibly followed by extensions
        let size_str = chunk_line.split(';').next().unwrap_or(chunk_line).trim();
        let chunk_size = u64::from_str_radix(size_str, 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid chunk size"))?;

        // Write chunk header to client
        let header_with_crlf = line_end + 2;
        client.write_all(&buf[..header_with_crlf]).await?;
        total_body += header_with_crlf as u64;
        buf.advance(header_with_crlf);

        if chunk_size == 0 {
            // Final chunk - read trailing CRLF and any trailers
            // For simplicity, just forward remaining buffered data and read final CRLF
            while !contains_crlf_crlf(&buf) && buf.len() < 1024 {
                let mut tmp = [0u8; 256];
                let n = remote.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }

            // Write final CRLF (or trailers + CRLF)
            if let Some(end) = find_crlf_crlf(&buf) {
                let trailer_len = end + 4;
                client.write_all(&buf[..trailer_len]).await?;
                total_body += trailer_len as u64;
            } else if buf.len() >= 2 {
                client.write_all(&buf[..2]).await?;
                total_body += 2;
            }
            break;
        }

        // Read chunk data + trailing CRLF
        let chunk_total = chunk_size as usize + 2; // data + \r\n

        // Forward what we have
        let have = std::cmp::min(buf.len(), chunk_total);
        if have > 0 {
            client.write_all(&buf[..have]).await?;
            total_body += have as u64;
            buf.advance(have);
        }

        // Read and forward remaining chunk data
        let mut remaining = chunk_total - have;
        let mut tmp = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(tmp.len(), remaining);
            let n = remote.read(&mut tmp[..to_read]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed in chunk data",
                ));
            }
            client.write_all(&tmp[..n]).await?;
            total_body += n as u64;
            remaining -= n;
        }
    }

    Ok(total_body)
}

fn contains_line_end(buf: &[u8]) -> bool {
    find_line_end(buf).is_some()
}

fn find_line_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

fn contains_crlf_crlf(buf: &[u8]) -> bool {
    find_crlf_crlf(buf).is_some()
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..buf.len() - 3 {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

// BytesMut advance helper
trait BytesMutExt {
    fn advance(&mut self, cnt: usize);
}

impl BytesMutExt for BytesMut {
    fn advance(&mut self, cnt: usize) {
        let _ = self.split_to(cnt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_headers() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\nbody";
        let meta = parse_response_headers(response).unwrap();
        assert_eq!(meta.status_code, 200);
        assert_eq!(meta.content_length, Some(100));
        assert!(!meta.chunked);
        assert!(!meta.connection_close);
    }

    #[test]
    fn test_parse_chunked_response() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let meta = parse_response_headers(response).unwrap();
        assert_eq!(meta.status_code, 200);
        assert!(meta.content_length.is_none());
        assert!(meta.chunked);
    }

    #[test]
    fn test_parse_connection_close() {
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        let meta = parse_response_headers(response).unwrap();
        assert!(meta.connection_close);
    }

    #[test]
    fn test_parse_204_no_content() {
        let response = b"HTTP/1.1 204 No Content\r\n\r\n";
        let meta = parse_response_headers(response).unwrap();
        assert_eq!(meta.status_code, 204);
        assert_eq!(meta.content_length, Some(0));
    }
}
