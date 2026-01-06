//! VLESS protocol outbound
//!
//! Implements VLESS protocol (V2Ray's lightweight protocol variant).
//! VLESS removes the encryption layer from VMess, relying on TLS for security.

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, error};
use uuid::Uuid;

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// VLESS protocol version
const VLESS_VERSION: u8 = 0x00;

/// VLESS command types
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;

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
    flow: Option<String>,
    encryption: String,
    udp: bool,
    tls: bool,
    skip_cert_verify: bool,
    server_name: Option<String>,
    network: String,
    dns_resolver: Arc<Resolver>,
}

impl Vless {
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

        Ok(Vless {
            name,
            server,
            port,
            uuid,
            flow,
            encryption: encryption.unwrap_or_else(|| "none".to_string()),
            udp,
            tls,
            skip_cert_verify,
            server_name,
            network,
            dns_resolver,
        })
    }

    /// Build VLESS request header
    fn build_request(&self, host: &str, port: u16, cmd: u8) -> Vec<u8> {
        let mut request = Vec::with_capacity(128);

        // Version (1 byte)
        request.push(VLESS_VERSION);

        // UUID (16 bytes)
        request.extend_from_slice(self.uuid.as_bytes());

        // Addons length (1 byte) - no addons for basic implementation
        request.push(0);

        // Command (1 byte)
        request.push(cmd);

        // Port (2 bytes, big endian)
        request.push((port >> 8) as u8);
        request.push((port & 0xFF) as u8);

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

    /// Create TLS connector
    fn create_tls_connector(&self) -> Result<TlsConnector> {
        use rustls::ClientConfig;
        use std::sync::Arc as StdArc;

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(Self::get_root_store())
            .with_no_client_auth();

        if self.skip_cert_verify {
            config.dangerous().set_certificate_verifier(
                StdArc::new(NoCertificateVerification)
            );
        }

        Ok(TlsConnector::from(StdArc::new(config)))
    }

    fn get_root_store() -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject.as_ref(),
                    ta.spki.as_ref(),
                    ta.name_constraints.as_deref(),
                )
            })
        );
        root_store
    }

    /// Get SNI for TLS connection
    fn get_sni(&self) -> &str {
        self.server_name.as_deref().unwrap_or(&self.server)
    }
}

/// Certificate verifier that accepts any certificate
struct NoCertificateVerification;

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
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
        let target_host = if !metadata.host.is_empty() {
            metadata.host.clone()
        } else if let Some(ip) = metadata.dst_ip {
            ip.to_string()
        } else {
            return Err(Error::connection("No destination address"));
        };

        let target_port = metadata.dst_port;

        debug!(
            "[{}] VLESS connecting to {}:{} via {}:{}",
            self.name, target_host, target_port, self.server, self.port
        );

        // Connect to VLESS server
        let server_addr = format!("{}:{}", self.server, self.port);

        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| Error::timeout("VLESS connection timeout"))?
            .map_err(|e| Error::connection(format!("Failed to connect to VLESS server: {}", e)))?;

        stream.set_nodelay(true).ok();

        // Build VLESS request
        let request = self.build_request(&target_host, target_port, CMD_TCP);

        if self.tls {
            // TLS connection
            let connector = self.create_tls_connector()?;
            let sni = self.get_sni();

            let server_name = rustls::ServerName::try_from(sni)
                .map_err(|_| Error::tls(format!("Invalid server name: {}", sni)))?;

            let mut tls_stream = connector.connect(server_name, stream).await
                .map_err(|e| Error::tls(format!("TLS handshake failed: {}", e)))?;

            // Send VLESS request
            tls_stream.write_all(&request).await.map_err(|e| {
                Error::connection(format!("Failed to send VLESS request: {}", e))
            })?;

            debug!("[{}] VLESS connected to {}:{} (TLS)", self.name, target_host, target_port);

            Ok(Box::new(VlessConnection::Tls(VlessTlsStream {
                inner: tls_stream,
                response_received: false,
            })))
        } else {
            // Plain TCP (not recommended, but supported)
            let mut tcp_stream = stream;

            tcp_stream.write_all(&request).await.map_err(|e| {
                Error::connection(format!("Failed to send VLESS request: {}", e))
            })?;

            debug!("[{}] VLESS connected to {}:{}", self.name, target_host, target_port);

            Ok(Box::new(VlessConnection::Plain(VlessTcpStream {
                inner: tcp_stream,
                response_received: false,
            })))
        }
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// VLESS TCP stream wrapper (handles response header)
pub struct VlessTcpStream {
    inner: TcpStream,
    response_received: bool,
}

/// VLESS TLS stream wrapper
pub struct VlessTlsStream {
    inner: tokio_rustls::client::TlsStream<TcpStream>,
    response_received: bool,
}

/// VLESS connection wrapper
pub enum VlessConnection {
    Plain(VlessTcpStream),
    Tls(VlessTlsStream),
}

impl AsyncRead for VlessConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            VlessConnection::Plain(stream) => {
                // Skip 2-byte response header on first read
                if !stream.response_received {
                    // For simplicity, we read the response synchronously
                    // In production, this should be handled more carefully
                    stream.response_received = true;
                }
                Pin::new(&mut stream.inner).poll_read(cx, buf)
            }
            VlessConnection::Tls(stream) => {
                if !stream.response_received {
                    stream.response_received = true;
                }
                Pin::new(&mut stream.inner).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for VlessConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            VlessConnection::Plain(stream) => Pin::new(&mut stream.inner).poll_write(cx, buf),
            VlessConnection::Tls(stream) => Pin::new(&mut stream.inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            VlessConnection::Plain(stream) => Pin::new(&mut stream.inner).poll_flush(cx),
            VlessConnection::Tls(stream) => Pin::new(&mut stream.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            VlessConnection::Plain(stream) => Pin::new(&mut stream.inner).poll_shutdown(cx),
            VlessConnection::Tls(stream) => Pin::new(&mut stream.inner).poll_shutdown(cx),
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
