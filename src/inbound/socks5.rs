//! SOCKS5 proxy inbound

use super::InboundListener;
use crate::common::net::{configure_tcp_stream, Address};
use crate::common::socks::{
    AuthMethodFlags, AuthResponse, Command, Request, Response, UsernamePasswordAuth,
    AUTH_NO_ACCEPTABLE, AUTH_NO_AUTH, AUTH_USERNAME_PASSWORD, REP_COMMAND_NOT_SUPPORTED,
    REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_NETWORK_UNREACHABLE,
};
use crate::common::Metadata;
use crate::config::{AuthConfig, SocksInboundConfig};
use crate::tunnel::Tunnel;
use crate::{Error, Result};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, trace};

struct PrefixedStream {
    inner: TcpStream,
    prefix: Vec<u8>,
    pos: usize,
}

impl PrefixedStream {
    fn from_buf_reader(reader: BufReader<TcpStream>) -> Self {
        let prefix = reader.buffer().to_vec();
        let inner = reader.into_inner();
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }
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

/// SOCKS5 proxy listener
pub struct Socks5Listener {
    config: SocksInboundConfig,
    tunnel: Arc<Tunnel>,
    running: AtomicBool,
}

impl Socks5Listener {
    pub fn new(config: SocksInboundConfig, tunnel: Arc<Tunnel>) -> Result<Self> {
        Ok(Socks5Listener {
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
        if let Err(e) = Self::process_connection(&tunnel, stream, peer_addr, auth, udp_enabled).await {
            debug!("SOCKS5 connection error from {}: {}", peer_addr, e);
        }
    }

    async fn process_connection(
        tunnel: &Tunnel,
        stream: TcpStream,
        peer_addr: SocketAddr,
        auth: Option<AuthConfig>,
        udp_enabled: bool,
    ) -> Result<()> {
        let perf_t0 = tracing::enabled!(tracing::Level::TRACE).then(Instant::now);
        let mut stream = BufReader::with_capacity(4 * 1024, stream);

        // Step 1: Authentication negotiation
        let auth_methods = AuthMethodFlags::read_from(&mut stream).await?;
        if let Some(t0) = perf_t0.as_ref() {
            trace!(
                target = "perf.socks5",
                phase = "auth_read",
                elapsed_us = t0.elapsed().as_micros() as u64,
                "done"
            );
        }

            if let Some(ref auth_config) = auth {
                // Require username/password auth
                if !auth_methods.username_password {
                    AuthResponse::new(AUTH_NO_ACCEPTABLE)
                        .write_to(stream.get_mut())
                        .await?;
                    return Err(Error::auth("No acceptable authentication method"));
            }

            AuthResponse::new(AUTH_USERNAME_PASSWORD)
                .write_to(stream.get_mut())
                .await?;
            if let Some(t0) = perf_t0.as_ref() {
                trace!(
                    target = "perf.socks5",
                    phase = "auth_write",
                    elapsed_us = t0.elapsed().as_micros() as u64,
                    "done"
                );
            }

            // Verify credentials
            let auth_data = UsernamePasswordAuth::read_from(&mut stream).await?;
            if auth_data.username != auth_config.username
                || auth_data.password != auth_config.password
            {
                UsernamePasswordAuth::write_response(stream.get_mut(), false).await?;
                return Err(Error::auth("Invalid credentials"));
            }
            UsernamePasswordAuth::write_response(stream.get_mut(), true).await?;
        } else {
            // No auth required
            if !auth_methods.no_auth {
                AuthResponse::new(AUTH_NO_ACCEPTABLE)
                    .write_to(stream.get_mut())
                    .await?;
                return Err(Error::auth("No acceptable authentication method"));
            }
            AuthResponse::new(AUTH_NO_AUTH)
                .write_to(stream.get_mut())
                .await?;
            if let Some(t0) = perf_t0.as_ref() {
                trace!(
                    target = "perf.socks5",
                    phase = "auth_write",
                    elapsed_us = t0.elapsed().as_micros() as u64,
                    "done"
                );
            }
        }

        // Step 2: Read request
        let request = Request::read_from(&mut stream).await?;
        if let Some(t0) = perf_t0.as_ref() {
            trace!(
                target = "perf.socks5",
                phase = "connect_read",
                elapsed_us = t0.elapsed().as_micros() as u64,
                "done"
            );
        }

        match request.command {
            Command::Connect => {
                Self::handle_connect(
                    tunnel,
                    stream,
                    peer_addr,
                    request.address,
                    request.port,
                    perf_t0,
                )
                .await
            }
            Command::UdpAssociate => {
                if udp_enabled {
                    Self::handle_udp_associate(tunnel, &mut stream, peer_addr).await
                } else {
                    Response::failure(REP_COMMAND_NOT_SUPPORTED)
                        .write_to(stream.get_mut())
                        .await?;
                    Err(Error::unsupported("UDP not enabled"))
                }
            }
            Command::Bind => {
                Response::failure(REP_COMMAND_NOT_SUPPORTED)
                    .write_to(stream.get_mut())
                    .await?;
                Err(Error::unsupported("BIND not supported"))
            }
        }
    }

    async fn handle_connect(
        tunnel: &Tunnel,
        mut stream: BufReader<TcpStream>,
        peer_addr: SocketAddr,
        address: Address,
        port: u16,
        perf_t0: Option<Instant>,
    ) -> Result<()> {
        let host = address.to_host();
        debug!("SOCKS5 CONNECT {} -> {}:{}", peer_addr, host, port);

        // Create metadata
        let mut metadata = Metadata::tcp()
            .with_source(peer_addr)
            .with_host(host.clone())
            .with_dst_port(port);

        // Set destination IP if available
        if let Some(ip) = address.to_ip() {
            metadata = metadata.with_dst_ip(ip);
        }

        // Connect through tunnel
        match tunnel.handle_tcp_with_dialer(&metadata).await {
            Ok((remote, _conn_id)) => {
                // Get local bound address for response
                let local_addr = stream
                    .get_mut()
                    .local_addr()
                    .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

                // Send success response
                Response::success(Address::from(local_addr.ip()), local_addr.port())
                    .write_to(stream.get_mut())
                    .await?;
                if let Some(t0) = perf_t0.as_ref() {
                    trace!(
                        target = "perf.socks5",
                        phase = "connect_write",
                        elapsed_us = t0.elapsed().as_micros() as u64,
                        "done"
                    );
                }

                let stream = PrefixedStream::from_buf_reader(stream);

                // Relay data bidirectionally
                let (sent, received) =
                    crate::common::net::copy_bidirectional_owned(stream, remote).await?;
                debug!(
                    "SOCKS5 CONNECT {} -> {}:{} completed (sent: {}, received: {})",
                    peer_addr, host, port, sent, received
                );
                Ok(())
            }
            Err(e) => {
                let reply = if e.to_string().contains("refused") {
                    REP_CONNECTION_REFUSED
                } else if e.to_string().contains("unreachable") {
                    REP_NETWORK_UNREACHABLE
                } else {
                    REP_GENERAL_FAILURE
                };
                Response::failure(reply).write_to(stream.get_mut()).await?;
                Err(e)
            }
        }
    }

    async fn handle_udp_associate(
        _tunnel: &Tunnel,
        stream: &mut BufReader<TcpStream>,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        debug!("SOCKS5 UDP ASSOCIATE from {}", peer_addr);

        // Bind a UDP socket for relaying
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let udp_addr = udp_socket.local_addr()?;

        debug!("SOCKS5 UDP relay bound to {}", udp_addr);

        // Send success response with UDP relay address
        Response::success(Address::from(udp_addr.ip()), udp_addr.port())
            .write_to(stream.get_mut())
            .await?;

        // Keep TCP connection alive and relay UDP
        let udp_socket = Arc::new(udp_socket);

        // Spawn UDP relay task
        let udp_relay = udp_socket.clone();
        let relay_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match udp_relay.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        // Parse SOCKS5 UDP header
                        if let Ok((header, header_len)) =
                            crate::common::socks::UdpHeader::from_bytes(&buf[..len])
                        {
                            let payload = &buf[header_len..len];
                            let host = header.address.to_host();

                            debug!(
                                "SOCKS5 UDP {} -> {}:{} ({} bytes)",
                                src,
                                host,
                                header.port,
                                payload.len()
                            );

                            // Create metadata
                            let mut metadata = Metadata::udp()
                                .with_source(src)
                                .with_host(host.clone())
                                .with_dst_port(header.port);

                            if let Some(ip) = header.address.to_ip() {
                                metadata = metadata.with_dst_ip(ip);
                            }

                            // TODO: Route through tunnel and relay response
                            // For now, just log
                            debug!("UDP relay not fully implemented yet");
                        }
                    }
                    Err(e) => {
                        debug!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });

        // Wait for TCP connection to close (indicates client is done)
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    debug!("SOCKS5 UDP ASSOCIATE TCP connection closed");
                    break;
                }
                Err(e) => {
                    debug!("SOCKS5 UDP ASSOCIATE TCP error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        // Clean up
        relay_handle.abort();

        Ok(())
    }
}

#[async_trait]
impl InboundListener for Socks5Listener {
    fn name(&self) -> &str {
        "SOCKS5"
    }

    async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        let addr = listener.local_addr()?;
        info!("SOCKS5 proxy listening on {}", addr);

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
                        error!("SOCKS5 accept error: {}", e);
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

#[cfg(test)]
mod tests {
    // Add unit tests here
}
