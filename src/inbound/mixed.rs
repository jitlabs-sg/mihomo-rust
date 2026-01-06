//! Mixed port inbound (HTTP + SOCKS5 auto-detection)

use super::InboundListener;
use crate::common::net::Address;
use crate::common::socks::{
    AuthRequest, AuthResponse, Command, Request, Response, UsernamePasswordAuth, AUTH_NO_AUTH,
    AUTH_NO_ACCEPTABLE, AUTH_USERNAME_PASSWORD, REP_COMMAND_NOT_SUPPORTED,
    REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_NETWORK_UNREACHABLE, SOCKS5_VERSION,
};
use crate::common::{ConnType, Metadata, Network};
use crate::config::{AuthConfig, MixedInboundConfig};
use crate::tunnel::Tunnel;
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Mixed port listener (auto-detects HTTP or SOCKS5)
pub struct MixedListener {
    config: MixedInboundConfig,
    tunnel: Arc<Tunnel>,
    running: AtomicBool,
}

impl MixedListener {
    pub fn new(config: MixedInboundConfig, tunnel: Arc<Tunnel>) -> Result<Self> {
        Ok(MixedListener {
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
        udp_enabled: bool,
    ) {
        if let Err(e) =
            Self::process_connection(&tunnel, &mut stream, peer_addr, auth, udp_enabled).await
        {
            debug!("Mixed connection error from {}: {}", peer_addr, e);
        }
    }

    async fn process_connection(
        tunnel: &Tunnel,
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
        udp_enabled: bool,
    ) -> Result<()> {
        // Peek first byte to detect protocol
        let mut peek_buf = [0u8; 1];
        stream.peek(&mut peek_buf).await?;

        if peek_buf[0] == SOCKS5_VERSION {
            // SOCKS5 protocol
            debug!("Mixed port: detected SOCKS5 from {}", peer_addr);
            Self::handle_socks5(tunnel, stream, peer_addr, auth, udp_enabled).await
        } else {
            // Assume HTTP
            debug!("Mixed port: detected HTTP from {}", peer_addr);
            Self::handle_http(tunnel, stream, peer_addr, auth).await
        }
    }

    async fn handle_socks5(
        tunnel: &Tunnel,
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
        udp_enabled: bool,
    ) -> Result<()> {
        // Step 1: Authentication negotiation
        let auth_req = AuthRequest::read_from(stream).await?;

        if let Some(ref auth_config) = auth {
            if !auth_req.supports(AUTH_USERNAME_PASSWORD) {
                AuthResponse::new(AUTH_NO_ACCEPTABLE)
                    .write_to(stream)
                    .await?;
                return Err(Error::auth("No acceptable authentication method"));
            }

            AuthResponse::new(AUTH_USERNAME_PASSWORD)
                .write_to(stream)
                .await?;

            let auth_data = UsernamePasswordAuth::read_from(stream).await?;
            if auth_data.username != auth_config.username
                || auth_data.password != auth_config.password
            {
                UsernamePasswordAuth::write_response(stream, false).await?;
                return Err(Error::auth("Invalid credentials"));
            }
            UsernamePasswordAuth::write_response(stream, true).await?;
        } else {
            if !auth_req.supports(AUTH_NO_AUTH) {
                AuthResponse::new(AUTH_NO_ACCEPTABLE)
                    .write_to(stream)
                    .await?;
                return Err(Error::auth("No acceptable authentication method"));
            }
            AuthResponse::new(AUTH_NO_AUTH).write_to(stream).await?;
        }

        // Step 2: Read request
        let request = Request::read_from(stream).await?;

        match request.command {
            Command::Connect => {
                let host = request.address.to_host();
                debug!("Mixed SOCKS5 CONNECT {} -> {}:{}", peer_addr, host, request.port);

                let mut metadata = Metadata::tcp()
                    .with_source(peer_addr)
                    .with_host(host.clone())
                    .with_dst_port(request.port);

                if let Some(ip) = request.address.to_ip() {
                    metadata = metadata.with_dst_ip(ip);
                }

                match tunnel.handle_tcp_with_dialer(&metadata).await {
                    Ok((mut remote, _conn_id)) => {
                        let local_addr = stream.local_addr().unwrap_or_else(|_| {
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                        });

                        Response::success(Address::from(local_addr.ip()), local_addr.port())
                            .write_to(stream)
                            .await?;

                        let (sent, received) =
                            crate::common::net::copy_bidirectional(stream, &mut remote).await?;
                        debug!(
                            "Mixed SOCKS5 {} -> {}:{} done (sent: {}, recv: {})",
                            peer_addr, host, request.port, sent, received
                        );
                        Ok(())
                    }
                    Err(e) => {
                        Response::failure(REP_GENERAL_FAILURE).write_to(stream).await?;
                        Err(e)
                    }
                }
            }
            Command::UdpAssociate => {
                if udp_enabled {
                    // Similar to socks5.rs UDP handling
                    Response::failure(REP_COMMAND_NOT_SUPPORTED)
                        .write_to(stream)
                        .await?;
                    Err(Error::unsupported("UDP not fully implemented"))
                } else {
                    Response::failure(REP_COMMAND_NOT_SUPPORTED)
                        .write_to(stream)
                        .await?;
                    Err(Error::unsupported("UDP not enabled"))
                }
            }
            Command::Bind => {
                Response::failure(REP_COMMAND_NOT_SUPPORTED)
                    .write_to(stream)
                    .await?;
                Err(Error::unsupported("BIND not supported"))
            }
        }
    }

    async fn handle_http(
        tunnel: &Tunnel,
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
    ) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read first line
        let mut first_line = String::new();
        reader.read_line(&mut first_line).await?;
        let first_line = first_line.trim();

        if first_line.is_empty() {
            return Err(Error::protocol("Empty request"));
        }

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::protocol("Invalid HTTP request line"));
        }

        let method = parts[0];
        let uri = parts[1];

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

        let stream = reader.into_inner();

        if method == "CONNECT" {
            // HTTPS tunnel
            let (host, port) = parse_host_port(uri)?;
            debug!("Mixed HTTP CONNECT {} -> {}:{}", peer_addr, host, port);

            let metadata = Metadata::tcp()
                .with_source(peer_addr)
                .with_host(host.clone())
                .with_dst_port(port);

            match tunnel.handle_tcp_with_dialer(&metadata).await {
                Ok((mut remote, _conn_id)) => {
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;

                    let (sent, received) =
                        crate::common::net::copy_bidirectional(stream, &mut remote).await?;
                    debug!(
                        "Mixed HTTP CONNECT {} -> {}:{} done (sent: {}, recv: {})",
                        peer_addr, host, port, sent, received
                    );
                    Ok(())
                }
                Err(e) => {
                    let response = format!(
                        "HTTP/1.1 502 Bad Gateway\r\n\
                         Connection: close\r\n\r\n{}",
                        e
                    );
                    stream.write_all(response.as_bytes()).await?;
                    Err(e)
                }
            }
        } else {
            // Plain HTTP proxy
            let uri = if uri.starts_with("http://") {
                &uri[7..]
            } else {
                uri
            };

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

            debug!("Mixed HTTP {} {} -> {}:{}", method, path, host, port);

            let metadata = Metadata::tcp()
                .with_source(peer_addr)
                .with_host(host.to_string())
                .with_dst_port(port);

            match tunnel.handle_tcp_with_dialer(&metadata).await {
                Ok((mut remote, _conn_id)) => {
                    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
                    request.push_str(&format!("Host: {}\r\n", host_port));

                    for (key, value) in &headers {
                        if !is_hop_by_hop_header(key) && key != "host" {
                            request.push_str(&format!("{}: {}\r\n", key, value));
                        }
                    }
                    request.push_str("Connection: close\r\n\r\n");

                    remote.write_all(request.as_bytes()).await?;

                    let (sent, received) =
                        crate::common::net::copy_bidirectional(stream, &mut remote).await?;
                    debug!(
                        "Mixed HTTP {} {}:{}{} done (sent: {}, recv: {})",
                        method, host, port, path, sent, received
                    );
                    Ok(())
                }
                Err(e) => {
                    let response = format!(
                        "HTTP/1.1 502 Bad Gateway\r\n\
                         Connection: close\r\n\r\n{}",
                        e
                    );
                    stream.write_all(response.as_bytes()).await?;
                    Err(e)
                }
            }
        }
    }
}

#[async_trait]
impl InboundListener for MixedListener {
    fn name(&self) -> &str {
        "Mixed"
    }

    async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        let addr = listener.local_addr()?;
        info!("Mixed proxy listening on {}", addr);

        self.running.store(true, Ordering::SeqCst);

        while self.running.load(Ordering::SeqCst) {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let tunnel = self.tunnel.clone();
                    let auth = self.config.auth.clone();
                    let udp = self.config.udp;
                    tokio::spawn(async move {
                        Self::handle_connection(tunnel, stream, peer_addr, auth, udp).await;
                    });
                }
                Err(e) => {
                    if self.running.load(Ordering::SeqCst) {
                        error!("Mixed accept error: {}", e);
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

fn is_hop_by_hop_header(header: &str) -> bool {
    matches!(
        header,
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
