//! Shadowsocks outbound protocol

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::net::Address;
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

/// Shadowsocks cipher type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    pub fn key_size(&self) -> usize {
        match self {
            CipherKind::Aes128Gcm => 16,
            CipherKind::Aes256Gcm => 32,
            CipherKind::ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_size(&self) -> usize {
        self.key_size()
    }

    pub fn tag_size(&self) -> usize {
        16
    }

    pub fn nonce_size(&self) -> usize {
        12
    }
}

impl TryFrom<&str> for CipherKind {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(CipherKind::Aes128Gcm),
            "aes-256-gcm" => Ok(CipherKind::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(CipherKind::ChaCha20Poly1305),
            _ => Err(Error::config(format!("Unsupported cipher: {}", s))),
        }
    }
}

/// Shadowsocks outbound
pub struct Shadowsocks {
    name: String,
    server: String,
    port: u16,
    cipher: CipherKind,
    key: Vec<u8>,
    udp: bool,
    dns_resolver: Arc<Resolver>,
}

impl Shadowsocks {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        cipher: String,
        password: String,
        udp: bool,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        let cipher_kind = CipherKind::try_from(cipher.as_str())?;
        let key = derive_key(&password, cipher_kind.key_size());

        Ok(Shadowsocks {
            name,
            server,
            port,
            cipher: cipher_kind,
            key,
            udp,
            dns_resolver,
        })
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

#[async_trait]
impl OutboundProxy for Shadowsocks {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Shadowsocks
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
            "Shadowsocks {} connecting to {} via {}",
            self.name,
            metadata.remote_address(),
            server_addr
        );

        // Resolve server address if needed
        let resolved_addr = self.dns_resolver.resolve(&self.server).await?;
        let addr = format!("{}:{}", resolved_addr, self.port);

        // Connect to shadowsocks server
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::connection(format!("Failed to connect to SS server: {}", e)))?;

        // Create encrypted connection
        let conn = ShadowsocksConnection::new(
            stream,
            self.cipher,
            self.key.clone(),
            Address::from(metadata.destination()),
            metadata.dst_port,
        )
        .await?;

        debug!(
            "Shadowsocks {} connected to {}",
            self.name,
            metadata.remote_address()
        );

        Ok(Box::new(conn))
    }
}

/// Derive key from password using EVP_BytesToKey (compatible with original SS)
fn derive_key(password: &str, key_size: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_size);
    let mut prev: Vec<u8> = Vec::new();

    while key.len() < key_size {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&prev);
    }

    key.truncate(key_size);
    key
}

/// Derive subkey using HKDF-SHA1 (per Shadowsocks AEAD spec)
fn derive_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut subkey = vec![0u8; key.len()];
    hk.expand(b"ss-subkey", &mut subkey).unwrap();
    subkey
}

/// Increment nonce
fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Shadowsocks encrypted connection
pub struct ShadowsocksConnection {
    inner: TcpStream,
    cipher: CipherKind,
    master_key: Vec<u8>,
    // Encryption state
    enc_key: Vec<u8>,
    enc_nonce: Vec<u8>,
    enc_initialized: bool,
    // Decryption state
    dec_key: Option<Vec<u8>>,
    dec_nonce: Vec<u8>,
    dec_initialized: bool,
    // Buffer
    read_buf: BytesMut,
    pending_payload: BytesMut,
}

impl ShadowsocksConnection {
    pub async fn new(
        mut inner: TcpStream,
        cipher: CipherKind,
        key: Vec<u8>,
        address: Address,
        port: u16,
    ) -> Result<Self> {
        // Generate salt for encryption
        let mut salt = vec![0u8; cipher.salt_size()];
        getrandom::getrandom(&mut salt).map_err(|e| Error::crypto(e.to_string()))?;

        // Derive encryption subkey
        let enc_key = derive_subkey(&key, &salt);

        // Create connection
        let mut conn = ShadowsocksConnection {
            inner,
            cipher,
            master_key: key,
            enc_key,
            enc_nonce: vec![0u8; cipher.nonce_size()],
            enc_initialized: false,
            dec_key: None,
            dec_nonce: vec![0u8; cipher.nonce_size()],
            dec_initialized: false,
            read_buf: BytesMut::with_capacity(4096),
            pending_payload: BytesMut::new(),
        };

        // Send salt + encrypted header (target address)
        let mut header = BytesMut::new();
        header.put_slice(&salt);

        // Encode target address in SOCKS5 format
        let addr_bytes = encode_address(&address, port);
        let encrypted_header = conn.encrypt(&addr_bytes)?;
        header.put_slice(&encrypted_header);

        conn.inner.write_all(&header).await?;
        conn.enc_initialized = true;

        Ok(conn)
    }

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Encrypt length (2 bytes) + tag
        let len_bytes = (data.len() as u16).to_be_bytes();
        let encrypted_len = self.encrypt_chunk(&len_bytes)?;

        // Encrypt payload + tag
        let encrypted_payload = self.encrypt_chunk(data)?;

        let mut result = Vec::with_capacity(encrypted_len.len() + encrypted_payload.len());
        result.extend_from_slice(&encrypted_len);
        result.extend_from_slice(&encrypted_payload);
        Ok(result)
    }

    fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce_arr: [u8; 12] = self.enc_nonce[..12].try_into().unwrap();

        let encrypted = match self.cipher {
            CipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.enc_key[..16])
                    .map_err(|e| Error::crypto(e.to_string()))?;
                cipher
                    .encrypt(&Nonce::from(nonce_arr), data)
                    .map_err(|e| Error::crypto(e.to_string()))?
            }
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.enc_key)
                    .map_err(|e| Error::crypto(e.to_string()))?;
                cipher
                    .encrypt(&Nonce::from(nonce_arr), data)
                    .map_err(|e| Error::crypto(e.to_string()))?
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.enc_key)
                    .map_err(|e| Error::crypto(e.to_string()))?;
                cipher
                    .encrypt(&Nonce::from(nonce_arr), data)
                    .map_err(|e| Error::crypto(e.to_string()))?
            }
        };

        increment_nonce(&mut self.enc_nonce);
        Ok(encrypted)
    }

    fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let dec_key = self.dec_key.as_ref().ok_or_else(|| Error::crypto("Decryption not initialized"))?;
        let nonce_arr: [u8; 12] = self.dec_nonce[..12].try_into().unwrap();

        let decrypted = match self.cipher {
            CipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&dec_key[..16])
                    .map_err(|e| Error::crypto(e.to_string()))?;
                cipher
                    .decrypt(&Nonce::from(nonce_arr), data)
                    .map_err(|e| Error::crypto(e.to_string()))?
            }
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(dec_key)
                    .map_err(|e| Error::crypto(e.to_string()))?;
                cipher
                    .decrypt(&Nonce::from(nonce_arr), data)
                    .map_err(|e| Error::crypto(e.to_string()))?
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(dec_key)
                    .map_err(|e| Error::crypto(e.to_string()))?;
                cipher
                    .decrypt(&Nonce::from(nonce_arr), data)
                    .map_err(|e| Error::crypto(e.to_string()))?
            }
        };

        increment_nonce(&mut self.dec_nonce);
        Ok(decrypted)
    }
}

impl AsyncRead for ShadowsocksConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Return pending payload first
        if !self.pending_payload.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.pending_payload.len());
            buf.put_slice(&self.pending_payload.split_to(to_read));
            return Poll::Ready(Ok(()));
        }

        // Read from inner stream
        let mut inner_buf = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut inner_buf);

        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                self.read_buf.extend_from_slice(filled);

                // Initialize decryption if needed (read salt)
                if !self.dec_initialized {
                    let salt_size = self.cipher.salt_size();
                    if self.read_buf.len() < salt_size {
                        return Poll::Pending;
                    }
                    let salt = self.read_buf.split_to(salt_size);
                    let dec_key = derive_subkey(&self.master_key, &salt);
                    self.dec_key = Some(dec_key);
                    self.dec_initialized = true;
                }

                // Try to decrypt chunks
                loop {
                    let tag_size = self.cipher.tag_size();
                    // Need at least: encrypted_length (2 + tag)
                    let min_len = 2 + tag_size;
                    if self.read_buf.len() < min_len {
                        break;
                    }

                    // Copy encrypted length data to avoid borrow issues
                    let encrypted_len_data: Vec<u8> = self.read_buf[..min_len].to_vec();
                    let length_bytes = match self.decrypt_chunk(&encrypted_len_data) {
                        Ok(b) => b,
                        Err(_) => {
                            // Not enough data or decryption error
                            break;
                        }
                    };

                    if length_bytes.len() != 2 {
                        break;
                    }

                    let payload_len = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
                    // Mask off reserved bits
                    let payload_len = payload_len & 0x3FFF;

                    // Check if we have the full payload
                    let total_chunk_len = min_len + payload_len + tag_size;
                    if self.read_buf.len() < total_chunk_len {
                        break;
                    }

                    // Consume the length part
                    let _ = self.read_buf.split_to(min_len);

                    // Copy and decrypt payload
                    let encrypted_payload: Vec<u8> = self.read_buf[..payload_len + tag_size].to_vec();
                    let _ = self.read_buf.split_to(payload_len + tag_size);
                    match self.decrypt_chunk(&encrypted_payload) {
                        Ok(payload) => {
                            self.pending_payload.extend_from_slice(&payload);
                        }
                        Err(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "Decryption failed",
                            )));
                        }
                    }
                }

                // Return any decrypted data
                if !self.pending_payload.is_empty() {
                    let to_read = std::cmp::min(buf.remaining(), self.pending_payload.len());
                    buf.put_slice(&self.pending_payload.split_to(to_read));
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ShadowsocksConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Encrypt and write
        let encrypted = match self.encrypt(buf) {
            Ok(e) => e,
            Err(e) => return Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string()))),
        };

        match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Encode address in SOCKS5 format
fn encode_address(address: &Address, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();

    match address {
        Address::Ipv4(ip) => {
            buf.push(0x01);
            buf.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            buf.push(0x04);
            buf.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            buf.push(0x03);
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
    }

    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_kind() {
        assert_eq!(
            CipherKind::try_from("aes-128-gcm").unwrap(),
            CipherKind::Aes128Gcm
        );
        assert_eq!(
            CipherKind::try_from("aes-256-gcm").unwrap(),
            CipherKind::Aes256Gcm
        );
    }

    #[test]
    fn test_derive_key() {
        let key = derive_key("test", 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_encode_address() {
        let addr = Address::Domain("example.com".to_string());
        let encoded = encode_address(&addr, 443);
        assert_eq!(encoded[0], 0x03); // Domain type
        assert_eq!(encoded[1], 11); // "example.com" length
    }
}
