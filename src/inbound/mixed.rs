//! Mixed port inbound (HTTP + SOCKS5 auto-detection)

use super::InboundListener;
use crate::common::net::{configure_tcp_stream, Address};
use crate::common::socks::{
    AuthMethodFlags, AuthResponse, Command, Request, Response, UsernamePasswordAuth,
    AUTH_NO_ACCEPTABLE, AUTH_NO_AUTH, AUTH_USERNAME_PASSWORD, REP_COMMAND_NOT_SUPPORTED,
    REP_GENERAL_FAILURE, SOCKS5_VERSION,
};
use crate::common::Metadata;
use crate::config::{AuthConfig, MixedInboundConfig};
use crate::tunnel::Tunnel;
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use bytes::BytesMut;
use httparse::{Request as HttpRequest, Status as HttpStatus, EMPTY_HEADER};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};
use std::pin::Pin;
use std::task::{Context, Poll};

struct HandshakeStream {
    reader: BufReader<TcpStream>,
}

impl HandshakeStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            reader: BufReader::with_capacity(4 * 1024, stream),
        }
    }

    async fn peek_u8(&mut self) -> Result<u8> {
        let buf = self.reader.fill_buf().await?;
        buf.first()
            .copied()
            .ok_or_else(|| Error::protocol("Unexpected EOF"))
    }

    fn get_mut(&mut self) -> &mut TcpStream {
        self.reader.get_mut()
    }

    fn into_prefixed(self) -> PrefixedStream {
        let reader = self.reader;
        let prefix = reader.buffer().to_vec();
        let inner = reader.into_inner();
        PrefixedStream {
            inner,
            prefix,
            pos: 0,
        }
    }
}

impl AsyncRead for HandshakeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for HandshakeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.reader.get_mut()).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.reader.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.reader.get_mut()).poll_shutdown(cx)
    }
}

struct PrefixedStream {
    inner: TcpStream,
    prefix: Vec<u8>,
    pos: usize,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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
        stream: TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
        udp_enabled: bool,
    ) {
        if let Err(e) =
            Self::process_connection(&tunnel, stream, peer_addr, auth, udp_enabled).await
        {
            debug!("Mixed connection error from {}: {}", peer_addr, e);
        }
    }

    async fn process_connection(
        tunnel: &Tunnel,
        stream: TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
        udp_enabled: bool,
    ) -> Result<()> {
        let mut stream = HandshakeStream::new(stream);
        let first = stream.peek_u8().await?;

        if first == SOCKS5_VERSION {
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
        mut stream: HandshakeStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
        udp_enabled: bool,
    ) -> Result<()> {
        static SOCKS5_TIMING_ENABLED: OnceLock<bool> = OnceLock::new();
        let timing_enabled =
            *SOCKS5_TIMING_ENABLED.get_or_init(|| std::env::var_os("MH_PERF_SOCKS5_TIMING").is_some());
        let t0 = timing_enabled.then(Instant::now);
        let mut t_after_auth = None;
        let mut t_after_req = None;
        let mut t_after_dial = None;
        // Only used when timing is enabled.

        // Step 1: Authentication negotiation
        let auth_methods = AuthMethodFlags::read_from(&mut stream).await?;

        if let Some(ref auth_config) = auth {
            if !auth_methods.username_password {
                AuthResponse::new(AUTH_NO_ACCEPTABLE)
                    .write_to(&mut stream)
                    .await?;
                return Err(Error::auth("No acceptable authentication method"));
            }

            AuthResponse::new(AUTH_USERNAME_PASSWORD)
                .write_to(&mut stream)
                .await?;

            let auth_data = UsernamePasswordAuth::read_from(&mut stream).await?;
            if auth_data.username != auth_config.username
                || auth_data.password != auth_config.password
            {
                UsernamePasswordAuth::write_response(&mut stream, false).await?;
                return Err(Error::auth("Invalid credentials"));
            }
            UsernamePasswordAuth::write_response(&mut stream, true).await?;
        } else {
            if !auth_methods.no_auth {
                AuthResponse::new(AUTH_NO_ACCEPTABLE)
                    .write_to(&mut stream)
                    .await?;
                return Err(Error::auth("No acceptable authentication method"));
            }
            AuthResponse::new(AUTH_NO_AUTH)
                .write_to(&mut stream)
                .await?;
        }

        if let Some(t0) = t0.as_ref() {
            t_after_auth = Some(t0.elapsed());
        }

        // Step 2: Read request
        let request = Request::read_from(&mut stream).await?;

        if let Some(t0) = t0.as_ref() {
            t_after_req = Some(t0.elapsed());
        }

        match request.command {
            Command::Connect => {
                let address = request.address;
                let port = request.port;
                debug!(
                    "Mixed SOCKS5 CONNECT {} -> {}:{}",
                    peer_addr,
                    address.to_host(),
                    port
                );

                let mut metadata = Metadata::tcp().with_source(peer_addr).with_dst_port(port);
                match address {
                    Address::Ipv4(ip) => metadata = metadata.with_dst_ip(IpAddr::V4(ip)),
                    Address::Ipv6(ip) => metadata = metadata.with_dst_ip(IpAddr::V6(ip)),
                    Address::Domain(domain) => metadata = metadata.with_host(domain),
                }

                match tunnel.handle_tcp_with_dialer(&metadata).await {
                    Ok((mut remote, _conn_id)) => {
                        if let Some(t0) = t0.as_ref() {
                            t_after_dial = Some(t0.elapsed());
                        }

                        let local_addr = stream.get_mut().local_addr().unwrap_or_else(|_| {
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                        });

                        Response::success(Address::from(local_addr.ip()), local_addr.port())
                            .write_to(&mut stream)
                            .await?;

                        if let Some(t0) = t0.as_ref() {
                            let t_after_reply = t0.elapsed();
                            info!(
                                "SOCKS5 timing peer={} auth={:?} req={:?} dial={:?} reply={:?}",
                                peer_addr,
                                t_after_auth,
                                t_after_req,
                                t_after_dial,
                                t_after_reply
                            );
                        }

                        let mut stream = stream.into_prefixed();
                        let (sent, received) =
                            crate::common::net::copy_bidirectional(&mut stream, &mut remote).await?;
                        debug!(
                            "Mixed SOCKS5 {} -> {}:{} done (sent: {}, recv: {})",
                            peer_addr,
                            metadata.destination(),
                            port,
                            sent,
                            received
                        );
                        Ok(())
                    }
                    Err(e) => {
                        Response::failure(REP_GENERAL_FAILURE)
                            .write_to(&mut stream)
                            .await?;
                        Err(e)
                    }
                }
            }
            Command::UdpAssociate => {
                if udp_enabled {
                    // Similar to socks5.rs UDP handling
                    Response::failure(REP_COMMAND_NOT_SUPPORTED)
                        .write_to(&mut stream)
                        .await?;
                    Err(Error::unsupported("UDP not fully implemented"))
                } else {
                    Response::failure(REP_COMMAND_NOT_SUPPORTED)
                        .write_to(&mut stream)
                        .await?;
                    Err(Error::unsupported("UDP not enabled"))
                }
            }
            Command::Bind => {
                Response::failure(REP_COMMAND_NOT_SUPPORTED)
                    .write_to(&mut stream)
                    .await?;
                Err(Error::unsupported("BIND not supported"))
            }
        }
    }

    async fn handle_http(
        tunnel: &Tunnel,
        mut stream: HandshakeStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
    ) -> Result<()> {
        const MAX_HTTP_HEAD_BYTES: usize = 32 * 1024;
        const MAX_HTTP_HEADERS: usize = 64;

        let mut buf = BytesMut::with_capacity(1024);
        while find_http_head_end(&buf).is_none() {
            if buf.len() >= MAX_HTTP_HEAD_BYTES {
                return Err(Error::protocol("HTTP header too large"));
            }

            let n = stream.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(Error::protocol("Unexpected EOF"));
            }
        }

        let mut headers_buf = [EMPTY_HEADER; MAX_HTTP_HEADERS];
        let (method, uri, head_len, headers_len) = {
            let mut req = HttpRequest::new(&mut headers_buf);
            let head_len = match req.parse(&buf) {
                Ok(HttpStatus::Complete(len)) => len,
                Ok(HttpStatus::Partial) => return Err(Error::protocol("Incomplete HTTP request")),
                Err(e) => return Err(Error::protocol(format!("Invalid HTTP request: {}", e))),
            };

            let method = req
                .method
                .ok_or_else(|| Error::protocol("Invalid HTTP request line"))?;
            let uri = req
                .path
                .ok_or_else(|| Error::protocol("Invalid HTTP request line"))?;
            let headers_len = req.headers.len();
            (method, uri, head_len, headers_len)
        };
        let headers = &headers_buf[..headers_len];

        // Check authentication
        if let Some(ref auth_config) = auth {
            let auth_header = headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
                .map(|h| h.value);

            let authenticated = auth_header.is_some_and(|value| {
                let value = trim_ascii_whitespace(value);
                let prefix = b"Basic ";
                if value.len() < prefix.len() || !value[..prefix.len()].eq_ignore_ascii_case(prefix)
                {
                    return false;
                }

                let encoded = trim_ascii_whitespace(&value[prefix.len()..]);
                if encoded.is_empty() {
                    return false;
                }

                let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
                    return false;
                };

                let mut parts = decoded.splitn(2, |b| *b == b':');
                let user = parts.next().unwrap_or_default();
                let pass = parts.next().unwrap_or_default();
                user == auth_config.username.as_bytes() && pass == auth_config.password.as_bytes()
            });

            if !authenticated {
                let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                               Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
                               Connection: close\r\n\r\n";
                stream.write_all(response.as_bytes()).await?;
                return Err(Error::auth("Authentication required"));
            }
        }

        let mut initial_data = if buf.len() <= head_len {
            None
        } else {
            Some(buf[head_len..].to_vec())
        };

        if method.eq_ignore_ascii_case("CONNECT") {
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

                    let mut pre_sent = 0u64;
                    if let Some(data) = initial_data.take() {
                        pre_sent = data.len() as u64;
                        remote.write_all(&data).await?;
                    }

                        let mut stream = stream.into_prefixed();
                        let (sent, received) = crate::common::net::copy_bidirectional(
                            &mut stream,
                            &mut remote,
                        )
                        .await?;
                    debug!(
                        "Mixed HTTP CONNECT {} -> {}:{} done (sent: {}, recv: {})",
                        peer_addr,
                        host,
                        port,
                        sent.saturating_add(pre_sent),
                        received
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
            let uri = if let Some(uri) = uri.strip_prefix("http://") {
                uri
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
                    let mut request = Vec::with_capacity(512);
                    request.extend_from_slice(method.as_bytes());
                    request.push(b' ');
                    request.extend_from_slice(path.as_bytes());
                    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
                    request.extend_from_slice(host_port.as_bytes());
                    request.extend_from_slice(b"\r\n");

                    for header in headers {
                        if !is_hop_by_hop_header(header.name)
                            && !header.name.eq_ignore_ascii_case("host")
                        {
                            request.extend_from_slice(header.name.as_bytes());
                            request.extend_from_slice(b": ");
                            request.extend_from_slice(trim_ascii_whitespace(header.value));
                            request.extend_from_slice(b"\r\n");
                        }
                    }
                    request.extend_from_slice(b"Connection: close\r\n\r\n");

                    remote.write_all(&request).await?;

                    let mut pre_sent = 0u64;
                    if let Some(data) = initial_data.take() {
                        pre_sent = data.len() as u64;
                        remote.write_all(&data).await?;
                    }

                        let mut stream = stream.into_prefixed();
                        let (sent, received) = crate::common::net::copy_bidirectional(
                            &mut stream,
                            &mut remote,
                        )
                        .await?;
                    debug!(
                        "Mixed HTTP {} {}:{}{} done (sent: {}, recv: {})",
                        method,
                        host,
                        port,
                        path,
                        sent.saturating_add(pre_sent),
                        received
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
                    configure_tcp_stream(&stream);
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

#[inline]
fn find_http_head_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }

    let end = buf.len() - 4;
    for i in 0..=end {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
    }
    None
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
    header.eq_ignore_ascii_case("connection")
        || header.eq_ignore_ascii_case("keep-alive")
        || header.eq_ignore_ascii_case("proxy-authenticate")
        || header.eq_ignore_ascii_case("proxy-authorization")
        || header.eq_ignore_ascii_case("te")
        || header.eq_ignore_ascii_case("trailers")
        || header.eq_ignore_ascii_case("transfer-encoding")
        || header.eq_ignore_ascii_case("upgrade")
        || header.eq_ignore_ascii_case("proxy-connection")
}

#[inline]
fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some(b) = bytes.first() {
        if b.is_ascii_whitespace() {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }

    while let Some(b) = bytes.last() {
        if b.is_ascii_whitespace() {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }

    bytes
}
