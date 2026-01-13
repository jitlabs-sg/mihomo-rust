//! HTTP proxy inbound

use super::InboundListener;
use crate::common::Metadata;
use crate::config::{AuthConfig, HttpInboundConfig};
use crate::tunnel::Tunnel;
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// HTTP proxy listener
pub struct HttpListener {
    config: HttpInboundConfig,
    tunnel: Arc<Tunnel>,
    running: AtomicBool,
}

impl HttpListener {
    pub fn new(config: HttpInboundConfig, tunnel: Arc<Tunnel>) -> Result<Self> {
        Ok(HttpListener {
            config,
            tunnel,
            running: AtomicBool::new(false),
        })
    }

    async fn handle_connection(
        tunnel: Arc<Tunnel>,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
    ) {
        if let Err(e) = Self::process_connection(&tunnel, &mut stream, peer_addr, auth).await {
            debug!("HTTP connection error from {}: {}", peer_addr, e);
        }
    }

    async fn process_connection(
        tunnel: &Tunnel,
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
    ) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read the first line to get the request
        let mut first_line = String::new();
        reader.read_line(&mut first_line).await?;
        let first_line = first_line.trim();

        if first_line.is_empty() {
            return Err(Error::protocol("Empty request"));
        }

        // Parse request line: METHOD URI HTTP/VERSION
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::protocol("Invalid HTTP request line"));
        }

        let method = parts[0];
        let uri = parts[1];
        let _version = parts[2];

        // Read headers
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let line = line.trim();

            if line.is_empty() {
                break;
            }

            if let Some(colon_idx) = line.find(':') {
                let key = line[..colon_idx].trim().to_lowercase();
                let value = line[colon_idx + 1..].trim().to_string();
                headers.push((key, value));
            }
        }

        // Check authentication
        if let Some(ref auth_config) = auth {
            let auth_header = headers.iter().find(|(k, _)| k == "proxy-authorization");

            let authenticated = if let Some((_, value)) = auth_header {
                // Parse "Basic base64(user:pass)"
                if value.starts_with("Basic ") {
                    let encoded = &value[6..];
                    if let Ok(decoded) =
                        base64::engine::general_purpose::STANDARD.decode(encoded)
                    {
                        if let Ok(creds) = String::from_utf8(decoded) {
                            if let Some(colon_idx) = creds.find(':') {
                                let user = &creds[..colon_idx];
                                let pass = &creds[colon_idx + 1..];
                                user == auth_config.username && pass == auth_config.password
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if !authenticated {
                let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                               Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
                               Connection: close\r\n\r\n";
                let stream = reader.into_inner();
                stream.write_all(response.as_bytes()).await?;
                return Err(Error::auth("Authentication required"));
            }
        }

        // Get the underlying stream back
        let stream = reader.into_inner();

        if method == "CONNECT" {
            // HTTPS tunnel (CONNECT method)
            Self::handle_connect(tunnel, stream, uri, peer_addr).await
        } else {
            // HTTP proxy (GET, POST, etc.)
            Self::handle_http(tunnel, stream, method, uri, &headers, peer_addr).await
        }
    }

    async fn handle_connect(
        tunnel: &Tunnel,
        stream: &mut TcpStream,
        uri: &str,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // Parse host:port from URI
        let (host, port) = parse_host_port(uri)?;

        debug!("HTTP CONNECT {} -> {}:{}", peer_addr, host, port);

        // Create metadata
        let metadata = Metadata::tcp()
            .with_source(peer_addr)
            .with_host(host.clone())
            .with_dst_port(port);

        // Try to establish connection through tunnel
        match tunnel.handle_tcp_with_dialer(&metadata).await {
            Ok((mut remote, _conn_id)) => {
                // Send success response
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;

                // Relay data bidirectionally
                let (sent, received) =
                    crate::common::net::copy_bidirectional(stream, &mut remote).await?;
                debug!(
                    "CONNECT {} -> {}:{} completed (sent: {}, received: {})",
                    peer_addr, host, port, sent, received
                );
            }
            Err(e) => {
                let response = format!(
                    "HTTP/1.1 502 Bad Gateway\r\n\
                     Content-Type: text/plain\r\n\
                     Connection: close\r\n\r\n\
                     Connection failed: {}",
                    e
                );
                stream.write_all(response.as_bytes()).await?;
                return Err(e);
            }
        }

        Ok(())
    }

    async fn handle_http(
        tunnel: &Tunnel,
        stream: &mut TcpStream,
        method: &str,
        uri: &str,
        headers: &[(String, String)],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // Parse the absolute URI
        let uri = if uri.starts_with("http://") {
            &uri[7..]
        } else if uri.starts_with("https://") {
            // HTTPS without CONNECT - this shouldn't happen normally
            return Err(Error::protocol("HTTPS must use CONNECT method"));
        } else {
            uri
        };

        // Split into host and path
        let (host_port, path) = if let Some(idx) = uri.find('/') {
            (&uri[..idx], &uri[idx..])
        } else {
            (uri, "/")
        };

        let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
            (
                &host_port[..colon_idx],
                host_port[colon_idx + 1..].parse().unwrap_or(80),
            )
        } else {
            (host_port, 80u16)
        };

        debug!("HTTP {} {} -> {}:{}", method, path, host, port);

        // Create metadata
        let metadata = Metadata::tcp()
            .with_source(peer_addr)
            .with_host(host.to_string())
            .with_dst_port(port);

        // Connect through tunnel
        match tunnel.handle_tcp_with_dialer(&metadata).await {
            Ok((mut remote, _conn_id)) => {
                // Reconstruct and send the HTTP request
                let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
                request.push_str(&format!("Host: {}\r\n", host_port));

                // Add headers (excluding hop-by-hop headers)
                for (key, value) in headers {
                    if !is_hop_by_hop_header(key) && key != "host" {
                        request.push_str(&format!("{}: {}\r\n", key, value));
                    }
                }
                request.push_str("Connection: close\r\n\r\n");

                remote.write_all(request.as_bytes()).await?;

                // Relay response back to client
                let (sent, received) =
                    crate::common::net::copy_bidirectional(stream, &mut remote).await?;
                debug!(
                    "HTTP {} {}:{}{} completed (sent: {}, received: {})",
                    method, host, port, path, sent, received
                );
            }
            Err(e) => {
                let response = format!(
                    "HTTP/1.1 502 Bad Gateway\r\n\
                     Content-Type: text/plain\r\n\
                     Connection: close\r\n\r\n\
                     Connection failed: {}",
                    e
                );
                stream.write_all(response.as_bytes()).await?;
                return Err(e);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl InboundListener for HttpListener {
    fn name(&self) -> &str {
        "HTTP"
    }

    async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        let addr = listener.local_addr()?;
        info!("HTTP proxy listening on {}", addr);

        self.running.store(true, Ordering::SeqCst);

        while self.running.load(Ordering::SeqCst) {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let tunnel = self.tunnel.clone();
                    let auth = self.config.auth.clone();
                    tokio::spawn(async move {
                        Self::handle_connection(tunnel, stream, peer_addr, auth).await;
                    });
                }
                Err(e) => {
                    if self.running.load(Ordering::SeqCst) {
                        error!("HTTP accept error: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Parse host:port from URI
fn parse_host_port(uri: &str) -> Result<(String, u16)> {
    if let Some(colon_idx) = uri.rfind(':') {
        let host = uri[..colon_idx].to_string();
        let port: u16 = uri[colon_idx + 1..]
            .parse()
            .map_err(|_| Error::parse("Invalid port"))?;
        Ok((host, port))
    } else {
        Ok((uri.to_string(), 80))
    }
}

/// Check if header is a hop-by-hop header
fn is_hop_by_hop_header(header: &str) -> bool {
    matches!(
        header.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        let (host, port) = parse_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let (host, port) = parse_host_port("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("Proxy-Connection"));
        assert!(!is_hop_by_hop_header("Content-Type"));
    }
}
