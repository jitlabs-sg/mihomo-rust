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
    cipher_kind: CipherKind,
    master_key: Vec<u8>,
    // Encryption state - cached cipher instance
    enc_cipher: CachedCipher,
    enc_nonce: [u8; 12],
    enc_initialized: bool,
    // Decryption state - cached cipher instance
    dec_cipher: Option<CachedCipher>,
    dec_nonce: [u8; 12],
    dec_initialized: bool,
    // Buffer - increased to 16KB for better throughput
    read_buf: BytesMut,
    pending_payload: BytesMut,
}

/// Cached cipher instance to avoid repeated creation
enum CachedCipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl CachedCipher {
    fn new(kind: CipherKind, key: &[u8]) -> Result<Self> {
        match kind {
            CipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&key[..16])
                    .map_err(|e| Error::crypto(e.to_string()))?;
                Ok(CachedCipher::Aes128Gcm(cipher))
            }
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Error::crypto(e.to_string()))?;
                Ok(CachedCipher::Aes256Gcm(cipher))
            }
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| Error::crypto(e.to_string()))?;
                Ok(CachedCipher::ChaCha20Poly1305(cipher))
            }
        }
    }

    #[inline]
    fn encrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from(*nonce);
        match self {
            CachedCipher::Aes128Gcm(c) => c.encrypt(&nonce, data)
                .map_err(|e| Error::crypto(e.to_string())),
            CachedCipher::Aes256Gcm(c) => c.encrypt(&nonce, data)
                .map_err(|e| Error::crypto(e.to_string())),
            CachedCipher::ChaCha20Poly1305(c) => c.encrypt(&nonce, data)
                .map_err(|e| Error::crypto(e.to_string())),
        }
    }

    #[inline]
    fn decrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from(*nonce);
        match self {
            CachedCipher::Aes128Gcm(c) => c.decrypt(&nonce, data)
                .map_err(|e| Error::crypto(e.to_string())),
            CachedCipher::Aes256Gcm(c) => c.decrypt(&nonce, data)
                .map_err(|e| Error::crypto(e.to_string())),
            CachedCipher::ChaCha20Poly1305(c) => c.decrypt(&nonce, data)
                .map_err(|e| Error::crypto(e.to_string())),
        }
    }
}

impl ShadowsocksConnection {
    pub async fn new(
        inner: TcpStream,
        cipher: CipherKind,
        key: Vec<u8>,
        address: Address,
        port: u16,
    ) -> Result<Self> {
        // Generate salt for encryption
        let mut salt = vec![0u8; cipher.salt_size()];
        getrandom::getrandom(&mut salt).map_err(|e| Error::crypto(e.to_string()))?;

        // Derive encryption subkey and create cached cipher
        let enc_key = derive_subkey(&key, &salt);
        let enc_cipher = CachedCipher::new(cipher, &enc_key)?;

        // Create connection with larger buffers (16KB instead of 4KB)
        let mut conn = ShadowsocksConnection {
            inner,
            cipher_kind: cipher,
            master_key: key,
            enc_cipher,
            enc_nonce: [0u8; 12],
            enc_initialized: false,
            dec_cipher: None,
            dec_nonce: [0u8; 12],
            dec_initialized: false,
            read_buf: BytesMut::with_capacity(16 * 1024),
            pending_payload: BytesMut::with_capacity(16 * 1024),
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

    #[inline]
    fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let encrypted = self.enc_cipher.encrypt(&self.enc_nonce, data)?;
        increment_nonce(&mut self.enc_nonce);
        Ok(encrypted)
    }

    #[inline]
    fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let dec_cipher = self.dec_cipher.as_ref()
            .ok_or_else(|| Error::crypto("Decryption not initialized"))?;
        let decrypted = dec_cipher.decrypt(&self.dec_nonce, data)?;
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

        // Read from inner stream - use 16KB buffer for better throughput
        let mut inner_buf = [0u8; 16 * 1024];
        let mut read_buf = ReadBuf::new(&mut inner_buf);

        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                self.read_buf.extend_from_slice(filled);

                // Initialize decryption if needed (read salt and create cached cipher)
                if !self.dec_initialized {
                    let salt_size = self.cipher_kind.salt_size();
                    if self.read_buf.len() < salt_size {
                        return Poll::Pending;
                    }
                    let salt = self.read_buf.split_to(salt_size);
                    let dec_key = derive_subkey(&self.master_key, &salt);
                    // Create cached cipher for decryption
                    match CachedCipher::new(self.cipher_kind, &dec_key) {
                        Ok(cipher) => self.dec_cipher = Some(cipher),
                        Err(e) => return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            e.to_string(),
                        ))),
                    }
                    self.dec_initialized = true;
                }

                // Try to decrypt chunks
                loop {
                    let tag_size = self.cipher_kind.tag_size();
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
