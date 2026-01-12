//! HTTP proxy outbound
//!
//! Implements HTTP CONNECT method for tunneling TCP connections
//! through an HTTP proxy server.

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use std::io::{self};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP proxy outbound
pub struct HttpProxy {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    skip_cert_verify: bool,
    dns_resolver: Arc<Resolver>,
}

impl HttpProxy {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: bool,
        skip_cert_verify: bool,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        Ok(HttpProxy {
            name,
            server,
            port,
            username,
            password,
            tls,
            skip_cert_verify,
            dns_resolver,
        })
    }

    /// Build the Authorization header value
    fn auth_header(&self) -> Option<String> {
        match (&self.username, &self.password) {
            (Some(user), Some(pass)) => {
                let credentials = format!("{}:{}", user, pass);
                let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
                Some(format!("Basic {}", encoded))
            }
            _ => None,
        }
    }

    /// Perform HTTP CONNECT handshake
    async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        host: &str,
        port: u16,
    ) -> Result<()> {
        // Build CONNECT request
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Proxy-Connection: keep-alive\r\n",
            host, port, host, port
        );

        // Add authorization if configured
        if let Some(auth) = self.auth_header() {
            request.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
        }

        request.push_str("\r\n");

        debug!("[{}] Sending CONNECT to {}:{}", self.name, host, port);

        // Send request
        stream.write_all(request.as_bytes()).await.map_err(|e| {
            Error::connection(format!("Failed to send CONNECT request: {}", e))
        })?;
        stream.flush().await?;

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
                    debug!("[{}] CONNECT handshake successful", self.name);
                    return Ok(());
                } else if status_line.contains("407") {
                    return Err(Error::auth("Proxy authentication required"));
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
impl OutboundProxy for HttpProxy {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Http
    }

    fn server(&self) -> &str {
        &self.server
    }

    fn support_udp(&self) -> bool {
        false // HTTP CONNECT only supports TCP
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
            "[{}] HTTP proxy connecting to {}:{} via {}:{}",
            self.name, target_host, target_port, self.server, self.port
        );

        // Resolve proxy server address
        let server_addr = format!("{}:{}", self.server, self.port);

        // Connect to HTTP proxy server
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| Error::timeout("HTTP proxy connection timeout"))?
            .map_err(|e| Error::connection(format!("Failed to connect to HTTP proxy: {}", e)))?;

        // Set TCP options
        stream.set_nodelay(true).ok();

        if self.tls {
            // TLS connection
            use tokio_rustls::TlsConnector;
            use rustls::ClientConfig;
            use rustls::pki_types::ServerName;
            use std::sync::Arc as StdArc;

            let config = if self.skip_cert_verify {
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(StdArc::new(NoCertificateVerification))
                    .with_no_client_auth()
            } else {
                ClientConfig::builder()
                    .with_root_certificates(Self::get_root_store())
                    .with_no_client_auth()
            };

            let connector = TlsConnector::from(StdArc::new(config));
            let server_name: ServerName<'static> = self.server.clone().try_into()
                .map_err(|_| Error::tls("Invalid server name"))?;

            let mut tls_stream = connector.connect(server_name, stream).await
                .map_err(|e| Error::tls(format!("TLS handshake failed: {}", e)))?;

            // Perform HTTP CONNECT over TLS
            self.http_connect(&mut tls_stream, &target_host, target_port).await?;

            debug!("[{}] HTTP proxy connected to {}:{} (TLS)", self.name, target_host, target_port);
            Ok(Box::new(HttpProxyConnection::Tls(tls_stream)))
        } else {
            // Plain TCP connection
            self.http_connect(&mut stream, &target_host, target_port).await?;

            debug!("[{}] HTTP proxy connected to {}:{}", self.name, target_host, target_port);
            Ok(Box::new(HttpProxyConnection::Plain(stream)))
        }
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl HttpProxy {
    fn get_root_store() -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
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

/// HTTP proxy connection wrapper
pub enum HttpProxyConnection {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for HttpProxyConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            HttpProxyConnection::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            HttpProxyConnection::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HttpProxyConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            HttpProxyConnection::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            HttpProxyConnection::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            HttpProxyConnection::Plain(stream) => Pin::new(stream).poll_flush(cx),
            HttpProxyConnection::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            HttpProxyConnection::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            HttpProxyConnection::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), Some(38));
        assert_eq!(find_header_end(b"incomplete"), None);
    }

    #[test]
    fn test_auth_header_none() {
        // auth_header logic test without dns_resolver
        assert!(make_auth_header(None, None).is_none());
    }

    #[test]
    fn test_auth_header_with_creds() {
        let auth = make_auth_header(Some("user".to_string()), Some("pass".to_string()));
        assert!(auth.is_some());
        assert!(auth.unwrap().starts_with("Basic "));
    }

    fn make_auth_header(username: Option<String>, password: Option<String>) -> Option<String> {
        match (&username, &password) {
            (Some(user), Some(pass)) => {
                let credentials = format!("{}:{}", user, pass);
                let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
                Some(format!("Basic {}", encoded))
            }
            _ => None,
        }
    }
}
