//! Trojan outbound protocol
use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::net::Address;
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use tracing::{debug, error};

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
    tls_connector: TlsConnector,
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

        let tls_config = build_tls_config(skip_cert_verify);
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Trojan {
            name,
            server,
            port,
            password_hash,
            udp,
            sni,
            skip_cert_verify,
            network,
            dns_resolver,
            tls_connector,
        })
    }

    #[allow(dead_code)]
    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    fn build_header(
        &self,
        command: TrojanCommand,
        address: &Address,
        port: u16,
    ) -> Result<Vec<u8>> {
        build_header_bytes(&self.password_hash, command, address, port)
    }
}

fn encode_socks5_addr(address: &Address, port: u16) -> Result<Vec<u8>> {
    let mut out = BytesMut::with_capacity(address.len());
    match address {
        Address::Ipv4(ip) => {
            out.put_u8(0x01);
            out.put_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            out.put_u8(0x04);
            out.put_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > 255 {
                return Err(Error::address("Domain name too long"));
            }
            out.put_u8(0x03);
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
        }
    }
    out.put_slice(&port.to_be_bytes());
    Ok(out.to_vec())
}

fn build_header_bytes(
    password_hash: &str,
    command: TrojanCommand,
    address: &Address,
    port: u16,
) -> Result<Vec<u8>> {
    let socks5_addr = encode_socks5_addr(address, port)?;
    let mut header =
        BytesMut::with_capacity(password_hash.len() + 2 + 1 + socks5_addr.len() + 2);
    header.put_slice(password_hash.as_bytes());
    header.put_slice(b"\r\n");
    header.put_u8(command as u8);
    header.put_slice(&socks5_addr);
    header.put_slice(b"\r\n");
    Ok(header.to_vec())
}

#[async_trait]
impl OutboundProxy for Trojan {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Trojan
    }

    fn server(&self) -> &str {
        &self.server
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        let sni = self.sni.as_deref().unwrap_or(&self.server);
        debug!(
            protocol = "trojan",
            phase = "dial_start",
            name = %self.name,
            server = %self.server,
            port = self.port,
            sni = %sni,
            dst = %metadata.remote_address(),
            "starting"
        );

        let server_name =
            rustls::ServerName::try_from(sni).map_err(|_| Error::tls("Invalid SNI"))?;

        let ips = self.dns_resolver.resolve_all(&self.server).await?;
        debug!(
            protocol = "trojan",
            phase = "resolve",
            server = %self.server,
            ips = ips.len(),
            "ok"
        );
        let mut stream: Option<TcpStream> = None;
        let mut last_err: Option<Error> = None;
        for ip in ips {
            let addr = SocketAddr::new(ip, self.port);
            match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    stream = Some(s);
                    break;
                }
                Ok(Err(e)) => {
                    let err =
                        Error::connection(format!("Trojan connect failed ({}): {}", addr, e));
                    debug!(
                        protocol = "trojan",
                        phase = "tcp_connect",
                        addr = %addr,
                        err = %err,
                        "failed"
                    );
                    last_err = Some(err);
                }
                Err(_) => {
                    let err = Error::connection(format!("Trojan connect timeout ({}): 5s", addr));
                    debug!(
                        protocol = "trojan",
                        phase = "tcp_connect",
                        addr = %addr,
                        err = %err,
                        "timeout"
                    );
                    last_err = Some(err);
                }
            }
        }
        let stream = match stream {
            Some(s) => s,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    Error::connection("Trojan connect failed (no IPs)")
                }));
            }
        };
        if let Some(ref e) = last_err {
            debug!(
                protocol = "trojan",
                phase = "tcp_connect",
                err = %e,
                "recovered after failures"
            );
        }

        let tls_stream = timeout(
            Duration::from_secs(10),
            self.tls_connector.clone().connect(server_name, stream),
        )
        .await;
        let mut tls_stream = match tls_stream {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let err = Error::tls(format!("TLS handshake failed: {}", e));
                error!(protocol = "trojan", phase = "tls_handshake", err = %err, "failed");
                return Err(err);
            }
            Err(_) => {
                let err = Error::tls("TLS handshake timeout: 10s");
                error!(protocol = "trojan", phase = "tls_handshake", err = %err, "timeout");
                return Err(err);
            }
        };

        let address = Address::from(metadata.destination());
        let header = self.build_header(TrojanCommand::Connect, &address, metadata.dst_port)?;
        debug!(
            protocol = "trojan",
            phase = "protocol_header",
            len = header.len(),
            "sending"
        );
        if let Err(e) = tls_stream.write_all(&header).await {
            let err = Error::protocol(format!("Trojan header write failed: {}", e));
            error!(protocol = "trojan", phase = "protocol_header", err = %err, "failed");
            return Err(err);
        }
        let _ = tls_stream.flush().await;

        debug!(
            protocol = "trojan",
            phase = "dial_ok",
            name = %self.name,
            dst = %metadata.remote_address(),
            "connected"
        );
        Ok(Box::new(tls_stream))
    }
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn build_tls_config(skip_cert_verify: bool) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.spki.as_ref(),
            ta.name_constraints.as_deref(),
        )
    }));

    let mut config = if skip_cert_verify {
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

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
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

    #[test]
    fn test_trojan_header_domain() {
        let mut hasher = Sha224::new();
        hasher.update(b"trojan-password");
        let password_hash = hex::encode(hasher.finalize());

        let addr = Address::Domain("mh-target".to_string());
        let header = build_header_bytes(&password_hash, TrojanCommand::Connect, &addr, 18080)
            .expect("header build");

        let mut expected = Vec::new();
        expected.extend_from_slice(password_hash.as_bytes());
        expected.extend_from_slice(b"\r\n");
        expected.push(TrojanCommand::Connect as u8);
        expected.extend_from_slice(&[
            0x03,
            9, // len("mh-target")
            b'm',
            b'h',
            b'-',
            b't',
            b'a',
            b'r',
            b'g',
            b'e',
            b't',
            0x46,
            0xA0, // 18080
        ]);
        expected.extend_from_slice(b"\r\n");

        assert_eq!(header, expected);
    }
}
