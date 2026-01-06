//! VMess outbound protocol

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::net::Address;
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use md5::{Digest, Md5};
use rand::Rng;
use sha2::Sha256;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;
use uuid::Uuid;

/// VMess security types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Auto,
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
    Zero,
}

impl TryFrom<&str> for VmessSecurity {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(VmessSecurity::Auto),
            "aes-128-gcm" => Ok(VmessSecurity::Aes128Gcm),
            "chacha20-poly1305" => Ok(VmessSecurity::ChaCha20Poly1305),
            "none" => Ok(VmessSecurity::None),
            "zero" => Ok(VmessSecurity::Zero),
            _ => Err(Error::config(format!("Unknown VMess security: {}", s))),
        }
    }
}

/// VMess outbound
pub struct Vmess {
    name: String,
    server: String,
    port: u16,
    uuid: Uuid,
    alter_id: u16,
    security: VmessSecurity,
    udp: bool,
    tls: bool,
    network: String,
    server_name: Option<String>,
    dns_resolver: Arc<Resolver>,
}

impl Vmess {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        uuid_str: String,
        alter_id: u16,
        security: String,
        udp: bool,
        tls: bool,
        network: String,
        server_name: Option<String>,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        let uuid = Uuid::parse_str(&uuid_str)
            .map_err(|e| Error::config(format!("Invalid VMess UUID: {}", e)))?;

        let security_type = VmessSecurity::try_from(security.as_str())?;

        Ok(Vmess {
            name,
            server,
            port,
            uuid,
            alter_id,
            security: security_type,
            udp,
            tls,
            network,
            server_name,
            dns_resolver,
        })
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// Generate VMess request header
    fn generate_header(&self, address: &Address, port: u16) -> Result<Vec<u8>> {
        let mut header = BytesMut::new();

        // Version
        header.put_u8(1);

        // Request IV (16 bytes)
        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv);
        header.put_slice(&iv);

        // Request Key (16 bytes)
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key);
        header.put_slice(&key);

        // Response Authentication V (1 byte)
        header.put_u8(rand::random());

        // Option (1 byte) - chunk stream
        header.put_u8(0x01);

        // Padding length + Security
        let padding_len: u8 = rand::thread_rng().gen_range(0..16);
        let security_byte = match self.security {
            VmessSecurity::Aes128Gcm => 0x03,
            VmessSecurity::ChaCha20Poly1305 => 0x04,
            VmessSecurity::None => 0x00,
            VmessSecurity::Zero => 0x02,
            VmessSecurity::Auto => 0x03, // Default to AES-128-GCM
        };
        header.put_u8((padding_len << 4) | security_byte);

        // Reserved (1 byte)
        header.put_u8(0x00);

        // Command (1 byte) - TCP = 0x01
        header.put_u8(0x01);

        // Port (2 bytes, big-endian)
        header.put_u16(port);

        // Address type and address
        match address {
            Address::Ipv4(ip) => {
                header.put_u8(0x01);
                header.put_slice(&ip.octets());
            }
            Address::Ipv6(ip) => {
                header.put_u8(0x03);
                header.put_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                header.put_u8(0x02);
                let bytes = domain.as_bytes();
                header.put_u8(bytes.len() as u8);
                header.put_slice(bytes);
            }
        }

        // Padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len as usize];
            rand::thread_rng().fill(&mut padding[..]);
            header.put_slice(&padding);
        }

        // F (4 bytes) - FNV1a hash of header
        let hash = fnv1a_hash(&header);
        header.put_slice(&hash.to_be_bytes());

        Ok(header.to_vec())
    }

    /// Generate authentication info
    fn generate_auth(&self) -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // auth = HMAC-MD5(uuid, timestamp)
        let uuid_bytes = self.uuid.as_bytes();
        let mut hasher = Md5::new();
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(uuid_bytes);
        hasher.finalize().to_vec()
    }

    /// Derive key for VMess
    fn derive_key(&self) -> [u8; 16] {
        let uuid_bytes = self.uuid.as_bytes();
        let mut hasher = Md5::new();
        hasher.update(uuid_bytes);
        hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21"); // VMess magic

        let mut key = [0u8; 16];
        key.copy_from_slice(&hasher.finalize());
        key
    }
}

#[async_trait]
impl OutboundProxy for Vmess {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Vmess
    }

    fn server(&self) -> &str {
        &self.server
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        let server_addr = self.server_addr();
        debug!(
            "VMess {} connecting to {} via {}",
            self.name,
            metadata.remote_address(),
            server_addr
        );

        // Resolve server address
        let resolved_addr = self.dns_resolver.resolve(&self.server).await?;
        let addr = format!("{}:{}", resolved_addr, self.port);

        // Connect to VMess server
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::connection(format!("Failed to connect to VMess server: {}", e)))?;

        // Generate and send header
        let address = Address::from(metadata.destination());
        let auth = self.generate_auth();
        let header = self.generate_header(&address, metadata.dst_port)?;

        // Encrypt header with key derived from UUID
        let key = self.derive_key();
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|e| Error::crypto(e.to_string()))?;

        let nonce_bytes: [u8; 12] = rand::random();
        let encrypted_header = cipher
            .encrypt(&Nonce::from(nonce_bytes), header.as_slice())
            .map_err(|e| Error::crypto(e.to_string()))?;

        // Send auth + nonce + encrypted header
        let mut request = BytesMut::new();
        request.put_slice(&auth);
        request.put_slice(&nonce_bytes);
        request.put_slice(&encrypted_header);

        stream.write_all(&request).await?;

        debug!(
            "VMess {} connected to {}",
            self.name,
            metadata.remote_address()
        );

        // Create VMess connection wrapper
        let conn = VmessConnection::new(stream, key);
        Ok(Box::new(conn))
    }
}

/// FNV1a hash (32-bit)
fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// VMess connection wrapper
pub struct VmessConnection {
    inner: TcpStream,
    key: [u8; 16],
    nonce_counter: u64,
    read_buf: BytesMut,
}

impl VmessConnection {
    pub fn new(inner: TcpStream, key: [u8; 16]) -> Self {
        VmessConnection {
            inner,
            key,
            nonce_counter: 0,
            read_buf: BytesMut::with_capacity(4096),
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        self.nonce_counter += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        nonce
    }
}

impl AsyncRead for VmessConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Simplified read - in production, handle VMess chunk format
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VmessConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Simplified write - in production, encrypt in VMess chunk format
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_security() {
        assert_eq!(
            VmessSecurity::try_from("auto").unwrap(),
            VmessSecurity::Auto
        );
        assert_eq!(
            VmessSecurity::try_from("aes-128-gcm").unwrap(),
            VmessSecurity::Aes128Gcm
        );
    }

    #[test]
    fn test_fnv1a() {
        let hash = fnv1a_hash(b"hello");
        assert!(hash != 0);
    }
}
