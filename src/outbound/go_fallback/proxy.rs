//! Go fallback proxy implementation
//!
//! Implements OutboundProxy trait by forwarding connections
//! through the Go mihomo child process via HTTP CONNECT.

use crate::common::Metadata;
use crate::dns::Resolver;
use crate::outbound::{OutboundProxy, ProxyConnection, ProxyType};
use crate::{Error, Result};
use async_trait::async_trait;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Connection timeout for Go fallback
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Go fallback proxy - forwards to Go mihomo via HTTP CONNECT
pub struct GoFallbackProxy {
    /// Proxy name (original proxy name from config)
    name: String,
    /// Original proxy type (e.g., "snell", "tuic")
    original_type: String,
    /// Server address (from original config)
    server: String,
    /// Go mihomo proxy address (e.g., "127.0.0.1:17890")
    go_proxy_addr: String,
    /// Whether UDP is supported
    udp_support: bool,
    /// Connection counter
    conn_count: AtomicU64,
}

impl GoFallbackProxy {
    /// Create a new Go fallback proxy
    pub fn new(
        name: String,
        original_type: String,
        server: String,
        go_proxy_addr: String,
        udp_support: bool,
    ) -> Self {
        GoFallbackProxy {
            name,
            original_type,
            server,
            go_proxy_addr,
            udp_support,
            conn_count: AtomicU64::new(0),
        }
    }

    /// Get the original proxy type
    pub fn original_type(&self) -> &str {
        &self.original_type
    }

    /// Get connection count
    pub fn connection_count(&self) -> u64 {
        self.conn_count.load(Ordering::Relaxed)
    }

    /// Perform HTTP CONNECT handshake
    async fn http_connect(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
    ) -> Result<()> {
        // Build CONNECT request
        let request = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Proxy-Connection: keep-alive\r\n\
             \r\n",
            host, port, host, port
        );

        debug!("Sending CONNECT to Go mihomo: {}:{}", host, port);

        // Send request
        stream.write_all(request.as_bytes()).await.map_err(|e| {
            Error::connection(format!("Failed to send CONNECT request: {}", e))
        })?;

        // Read response
        let mut response = [0u8; 1024];
        let mut total_read = 0;

        loop {
            let n = stream.read(&mut response[total_read..]).await.map_err(|e| {
                Error::connection(format!("Failed to read CONNECT response: {}", e))
            })?;

            if n == 0 {
                return Err(Error::connection("Connection closed during CONNECT"));
            }

            total_read += n;

            // Check if we have complete headers
            if let Some(header_end) = find_header_end(&response[..total_read]) {
                let response_str = String::from_utf8_lossy(&response[..header_end]);

                // Parse status line
                let status_line = response_str.lines().next().unwrap_or("");
                if status_line.contains("200") {
                    debug!("CONNECT handshake successful");
                    return Ok(());
                } else {
                    return Err(Error::connection(format!(
                        "CONNECT failed: {}",
                        status_line
                    )));
                }
            }

            if total_read >= response.len() {
                return Err(Error::connection("CONNECT response too large"));
            }
        }
    }
}

/// Find end of HTTP headers (double CRLF)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

#[async_trait]
impl OutboundProxy for GoFallbackProxy {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        // Return the closest matching type, or default to Socks5
        // since we're using HTTP CONNECT, the actual type doesn't matter much
        match self.original_type.to_lowercase().as_str() {
            "http" => ProxyType::Http,
            "socks5" | "socks" => ProxyType::Socks5,
            _ => ProxyType::Socks5, // Default for unknown types
        }
    }

    fn server(&self) -> &str {
        &self.server
    }

    fn support_udp(&self) -> bool {
        self.udp_support
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        let target_host = if !metadata.host.is_empty() {
            metadata.host.clone()
        } else if let Some(ip) = metadata.dst_ip {
            ip.to_string()
        } else {
            return Err(Error::connection("No destination address"));
        };

        let target_port = metadata.dst_port;

        debug!(
            "[{}] Go fallback connecting to {}:{} via {}",
            self.name, target_host, target_port, self.go_proxy_addr
        );

        // Connect to Go mihomo
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.go_proxy_addr))
            .await
            .map_err(|_| Error::timeout("Go mihomo connection timeout"))?
            .map_err(|e| {
                Error::connection(format!("Failed to connect to Go mihomo: {}", e))
            })?;

        // Set TCP options
        stream.set_nodelay(true).ok();

        // Perform HTTP CONNECT handshake
        self.http_connect(&mut stream, &target_host, target_port).await?;

        // Increment connection count
        self.conn_count.fetch_add(1, Ordering::Relaxed);

        debug!(
            "[{}] Go fallback connected to {}:{}",
            self.name, target_host, target_port
        );

        Ok(Box::new(GoFallbackConnection::new(stream, self.name.clone())))
    }

    async fn close(&self) -> Result<()> {
        debug!("[{}] Go fallback proxy closing", self.name);
        Ok(())
    }
}

/// Wrapper around TcpStream for Go fallback connections
pub struct GoFallbackConnection {
    inner: TcpStream,
    proxy_name: String,
}

impl GoFallbackConnection {
    pub fn new(stream: TcpStream, proxy_name: String) -> Self {
        GoFallbackConnection {
            inner: stream,
            proxy_name,
        }
    }
}

impl AsyncRead for GoFallbackConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for GoFallbackConnection {
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

impl std::fmt::Debug for GoFallbackConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoFallbackConnection")
            .field("proxy_name", &self.proxy_name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_fallback_proxy_creation() {
        let proxy = GoFallbackProxy::new(
            "snell-node".to_string(),
            "snell".to_string(),
            "example.com".to_string(),
            "127.0.0.1:17890".to_string(),
            false,
        );

        assert_eq!(proxy.name(), "snell-node");
        assert_eq!(proxy.original_type(), "snell");
        assert_eq!(proxy.server(), "example.com");
        assert!(!proxy.support_udp());
        assert_eq!(proxy.connection_count(), 0);
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(
            find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"),
            Some(19)
        );
        assert_eq!(
            find_header_end(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Some(38)
        );
        assert_eq!(find_header_end(b"incomplete"), None);
        assert_eq!(find_header_end(b"no\r\nend"), None);
    }

    #[test]
    fn test_proxy_type_mapping() {
        let proxy = GoFallbackProxy::new(
            "test".to_string(),
            "snell".to_string(),
            "server".to_string(),
            "127.0.0.1:17890".to_string(),
            false,
        );
        // Unknown types default to Socks5
        assert_eq!(proxy.proxy_type(), ProxyType::Socks5);
    }
}
