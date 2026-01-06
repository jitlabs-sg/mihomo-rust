//! Trojan outbound protocol

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::net::Address;
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Trojan command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    Connect = 0x01,
    #[allow(dead_code)]
    UdpAssociate = 0x03,
}

/// Trojan outbound
pub struct Trojan {
    name: String,
    server: String,
    port: u16,
    password_hash: String,
    udp: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    #[allow(dead_code)]
    network: String,
    dns_resolver: Arc<Resolver>,
}

impl Trojan {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        password: String,
        udp: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        network: String,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let password_hash = hex::encode(hash);

        Ok(Trojan {
            name, server, port, password_hash, udp, sni, skip_cert_verify, network, dns_resolver,
        })
    }

    #[allow(dead_code)]
    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    fn build_header(&self, command: TrojanCommand, address: &Address, port: u16) -> Vec<u8> {
        let mut header = BytesMut::new();
        header.put_slice(self.password_hash.as_bytes());
        header.put_slice(b"\r\n");
        header.put_u8(command as u8);
        match address {
            Address::Ipv4(ip) => { header.put_u8(0x01); header.put_slice(&ip.octets()); }
            Address::Ipv6(ip) => { header.put_u8(0x04); header.put_slice(&ip.octets()); }
            Address::Domain(d) => { header.put_u8(0x03); header.put_u8(d.len() as u8); header.put_slice(d.as_bytes()); }
        }
        header.put_u16(port);
        header.put_slice(b"\r\n");
        header.to_vec()
    }
}

#[async_trait]
impl OutboundProxy for Trojan {
    fn name(&self) -> &str { &self.name }
    fn proxy_type(&self) -> ProxyType { ProxyType::Trojan }
    fn server(&self) -> &str { &self.server }
    fn support_udp(&self) -> bool { self.udp }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        debug!("Trojan {} connecting to {}", self.name, metadata.remote_address());

        let resolved = self.dns_resolver.resolve(&self.server).await?;
        let addr = format!("{}:{}", resolved, self.port);
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| Error::connection(format!("Trojan connect failed: {}", e)))?;

        let sni = self.sni.as_deref().unwrap_or(&self.server);

        // Build TLS config for rustls 0.21
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.spki.as_ref(),
                ta.name_constraints.as_deref(),
            )
        }));

        let config = if self.skip_cert_verify {
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::ServerName::try_from(sni)
            .map_err(|_| Error::tls("Invalid SNI"))?;

        let mut tls_stream = connector.connect(server_name, stream).await
            .map_err(|e| Error::tls(format!("TLS handshake failed: {}", e)))?;

        let address = Address::from(metadata.destination());
        let header = self.build_header(TrojanCommand::Connect, &address, metadata.dst_port);
        tls_stream.write_all(&header).await?;

        debug!("Trojan {} connected to {}", self.name, metadata.remote_address());
        Ok(Box::new(tls_stream))
    }
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self, _end_entity: &rustls::Certificate, _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName, _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8], _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_password_hash() {
        let mut h = Sha224::new();
        h.update(b"test");
        assert_eq!(hex::encode(h.finalize()).len(), 56);
    }
}
