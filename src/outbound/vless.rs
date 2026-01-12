//! VLESS protocol outbound
//!
//! Implements VLESS protocol (V2Ray's lightweight protocol variant).
//! VLESS removes the encryption layer from VMess, relying on TLS for security.

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use std::borrow::Cow;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use tracing::{debug, Level};
use uuid::Uuid;

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// VLESS protocol version
const VLESS_VERSION: u8 = 0x00;

/// VLESS command types
const CMD_TCP: u8 = 0x01;
const _CMD_UDP: u8 = 0x02;
const _CMD_MUX: u8 = 0x03;

/// VLESS address types (same as SOCKS5)
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// VLESS proxy outbound
pub struct Vless {
    name: String,
    server: String,
    port: u16,
    uuid: Uuid,
    _flow: Option<String>,
    _encryption: String,
    udp: bool,
    tls: bool,
    skip_cert_verify: bool,
    _network: String,
    dns_resolver: Arc<Resolver>,
    tls_server_name: Option<ServerName<'static>>,
}

impl Vless {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        server: String,
        port: u16,
        uuid_str: String,
        flow: Option<String>,
        encryption: Option<String>,
        udp: bool,
        tls: bool,
        skip_cert_verify: bool,
        server_name: Option<String>,
        network: String,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        let uuid = Uuid::parse_str(&uuid_str)
            .map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        // Validate flow
        if let Some(ref flow) = flow {
            if !matches!(flow.as_str(), "xtls-rprx-vision" | "xtls-rprx-direct" | "") {
                return Err(Error::config(format!("Invalid flow: {}", flow)));
            }
        }

        let tls_server_name: Option<ServerName<'static>> = if tls {
            let sni = server_name.as_deref().unwrap_or(&server);
            Some(sni.to_string().try_into().map_err(|_| {
                Error::tls(format!("Invalid server name: {}", sni))
            })?)
        } else {
            None
        };

        Ok(Vless {
            name,
            server,
            port,
            uuid,
            _flow: flow,
            _encryption: encryption.unwrap_or_else(|| "none".to_string()),
            udp,
            tls,
            skip_cert_verify,
            _network: network,
            dns_resolver,
            tls_server_name,
        })
    }

    /// Build VLESS request header
    fn build_request(&self, host: &str, port: u16, cmd: u8) -> Vec<u8> {        
        let mut request = Vec::with_capacity(128);

        // Version (1 byte)
        request.push(VLESS_VERSION);

        // UUID (16 bytes)
        request.extend_from_slice(self.uuid.as_bytes());

        // Addons length (1 byte)
        request.push(0);

        // Command (1 byte)
        request.push(cmd);

        // Port (2 bytes, big endian)
        request.extend_from_slice(&port.to_be_bytes());

        // Address type and address
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        } else {
            // Domain name
            request.push(ATYP_DOMAIN);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }

        request
    }

    fn configure_socket(stream: &TcpStream) {
        #[cfg(unix)]
        {
            use socket2::SockRef;

            // Reduce TIME_WAIT pressure under high connection churn by using an abortive close.
            // VLESS upstream (e.g. xray) tends to wait for the client to close first, so the
            // client side otherwise accumulates TIME_WAIT sockets and may exhaust the ephemeral
            // port range (os error 99).
            let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
        }

        #[cfg(not(unix))]
        {
            let _ = stream;
        }
    }

    /// Create TLS connector
    fn create_tls_connector(skip_cert_verify: bool) -> Result<TlsConnector> {
        use rustls::ClientConfig;
        use std::sync::Arc as StdArc;

        let config = if skip_cert_verify {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(StdArc::new(NoCertificateVerification))
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .with_root_certificates(Self::get_root_store())
                .with_no_client_auth()
        };

        Ok(TlsConnector::from(StdArc::new(config)))
    }

    fn get_root_store() -> rustls::RootCertStore {
        static ROOT_STORE: OnceLock<rustls::RootCertStore> = OnceLock::new();
        ROOT_STORE
            .get_or_init(|| {
                let mut root_store = rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                root_store
            })
            .clone()
    }
}

/// Certificate verifier that accepts any certificate
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[async_trait]
impl OutboundProxy for Vless {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Vless
    }

    fn server(&self) -> &str {
        &self.server
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        let target_host: Cow<'_, str> = if !metadata.host.is_empty() {
            Cow::Borrowed(&metadata.host)
        } else if let Some(ip) = metadata.dst_ip {
            Cow::Owned(ip.to_string())
        } else {
            return Err(Error::connection("No destination address"));
        };

        let target_port = metadata.dst_port;

        debug!(
            "[{}] VLESS connecting to {}:{} via {}:{}",
            self.name, target_host, target_port, self.server, self.port
        );

        // Connect to VLESS server
        let timing_enabled = tracing::enabled!(Level::DEBUG);
        let dns_start = if timing_enabled {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let resolved = self.dns_resolver.resolve(&self.server).await?;
        if let Some(dns_start) = dns_start {
            debug!(
                protocol = "vless",
                phase = "dns_resolve",
                elapsed_ms = dns_start.elapsed().as_millis(),
                "[{}] done",
                self.name
            );
        }

        let server_addr = std::net::SocketAddr::new(resolved, self.port);
        let connect_start = if timing_enabled {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr))
            .await
            .map_err(|_| Error::timeout("VLESS connection timeout"))?
            .map_err(|e| Error::connection(format!("Failed to connect to VLESS server: {}", e)))?;
        if let Some(connect_start) = connect_start {
            debug!(
                protocol = "vless",
                phase = "tcp_connect",
                elapsed_ms = connect_start.elapsed().as_millis(),
                "[{}] done",
                self.name
            );
        }

        stream.set_nodelay(true).ok();
        Self::configure_socket(&stream);

        // Build VLESS request
        let request = self.build_request(target_host.as_ref(), target_port, CMD_TCP);

        if self.tls {
            // TLS connection
            let connector = Self::create_tls_connector(self.skip_cert_verify)?;
            let server_name = self.tls_server_name.clone().ok_or_else(|| {
                Error::tls("Missing VLESS TLS server name")
            })?;

            let tls_start = if timing_enabled {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let mut tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::tls(format!("TLS handshake failed: {}", e)))?;
            if let Some(tls_start) = tls_start {
                debug!(
                    protocol = "vless",
                    phase = "tls_handshake",
                    elapsed_ms = tls_start.elapsed().as_millis(),
                    "[{}] done",
                    self.name
                );
            }

            // Send VLESS request
            let send_start = if timing_enabled {
                Some(std::time::Instant::now())
            } else {
                None
            };
            tls_stream
                .write_all(&request)
                .await
                .map_err(|e| Error::connection(format!("Failed to send VLESS request: {}", e)))?;
            if let Some(send_start) = send_start {
                debug!(
                    protocol = "vless",
                    phase = "send_request",
                    elapsed_ms = send_start.elapsed().as_millis(),
                    "[{}] done",
                    self.name
                );
            }

            debug!(
                "[{}] VLESS connected to {}:{} (TLS)",
                self.name, target_host, target_port
            );

            Ok(Box::new(VlessConnection::new(tls_stream)))
        } else {
            // Plain TCP (not recommended, but supported)
            let mut tcp_stream = stream;

            tcp_stream
                .write_all(&request)
                .await
                .map_err(|e| Error::connection(format!("Failed to send VLESS request: {}", e)))?;

            debug!(
                "[{}] VLESS connected to {}:{}",
                self.name, target_host, target_port
            );

            Ok(Box::new(VlessConnection::new(tcp_stream)))
        }
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// VLESS connection wrapper that strips the response header (version + addons)
/// from the first read.
///
/// Xray may not send the response header until the upstream returns data. To
/// avoid deadlocking CONNECT establishment, we consume it lazily on read rather
/// than during `dial_tcp`.
pub struct VlessConnection<S> {
    inner: S,
    response_header: [u8; 2],
    response_header_read: usize,
    response_addon_remaining: usize,
    response_ready: bool,
}

impl<S> VlessConnection<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            response_header: [0u8; 2],
            response_header_read: 0,
            response_addon_remaining: 0,
            response_ready: false,
        }
    }

    fn poll_recv_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        while !self.response_ready {
            if self.response_header_read < self.response_header.len() {
                let mut buf = ReadBuf::new(&mut self.response_header[self.response_header_read..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "VLESS response header EOF",
                            )));
                        }
                        self.response_header_read += n;
                    }
                }

                if self.response_header_read < self.response_header.len() {
                    continue;
                }

                if self.response_header[0] != VLESS_VERSION {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Unexpected VLESS response version: {}",
                            self.response_header[0]
                        ),
                    )));
                }

                self.response_addon_remaining = self.response_header[1] as usize;
            }

            if self.response_addon_remaining > 0 {
                let mut discard = [0u8; 256];
                let to_read = self.response_addon_remaining.min(discard.len());
                let mut buf = ReadBuf::new(&mut discard[..to_read]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "VLESS response addons EOF",
                            )));
                        }
                        self.response_addon_remaining = self.response_addon_remaining.saturating_sub(n);
                    }
                }

                continue;
            }

            self.response_ready = true;
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for VlessConnection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.response_ready {
            match self.poll_recv_response(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for VlessConnection<S>
where
    S: AsyncWrite + Unpin,
{
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Avoid initiating an active close (FIN) on high-churn VLESS upstream
        // connections. With `SO_LINGER=0` on the underlying TCP socket this
        // helps reduce TIME_WAIT pressure and ephemeral port exhaustion.
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_constants() {
        assert_eq!(VLESS_VERSION, 0x00);
        assert_eq!(CMD_TCP, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x02);
    }

    #[test]
    fn test_uuid_parsing() {
        let uuid_str = "00000000-0000-0000-0000-000000000000";
        let uuid = Uuid::parse_str(uuid_str).unwrap();
        assert_eq!(uuid.as_bytes().len(), 16);
    }
}
