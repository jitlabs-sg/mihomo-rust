//! VMess outbound protocol
use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::net::Address;
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest as Md5Digest, Md5};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::Shake128;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, error};
use uuid::Uuid;

const VMESS_VERSION: u8 = 1;
const COMMAND_TCP: u8 = 1;

const SECURITY_TYPE_AES128_GCM: u8 = 3;
const SECURITY_TYPE_CHACHA20_POLY1305: u8 = 4;
const SECURITY_TYPE_NONE: u8 = 5;
const SECURITY_TYPE_ZERO: u8 = 6;

const OPTION_CHUNK_STREAM: u8 = 1;
const OPTION_CHUNK_MASKING: u8 = 4;

const CIPHER_OVERHEAD: usize = 16;
const WRITE_CHUNK_SIZE: usize = 15000;
const RESPONSE_HEADER_LEN_CIPHER_LEN: usize = 2 + CIPHER_OVERHEAD;
const RESPONSE_HEADER_READ_CHUNK: usize = 4096;

const KDF_ROOT: &[u8] = b"VMess AEAD KDF";

const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedSecurity {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
    Zero,
}

impl ResolvedSecurity {
    fn protocol_byte(self) -> u8 {
        match self {
            ResolvedSecurity::Aes128Gcm => SECURITY_TYPE_AES128_GCM,
            ResolvedSecurity::ChaCha20Poly1305 => SECURITY_TYPE_CHACHA20_POLY1305,
            ResolvedSecurity::None => SECURITY_TYPE_NONE,
            ResolvedSecurity::Zero => SECURITY_TYPE_ZERO,
        }
    }

    fn option(self) -> u8 {
        match self {
            ResolvedSecurity::Aes128Gcm
            | ResolvedSecurity::ChaCha20Poly1305
            | ResolvedSecurity::None
            | ResolvedSecurity::Zero => OPTION_CHUNK_STREAM,
        }
    }

    fn is_aead(self) -> bool {
        matches!(
            self,
            ResolvedSecurity::Aes128Gcm | ResolvedSecurity::ChaCha20Poly1305
        )
    }
}

fn resolve_security(security: VmessSecurity) -> ResolvedSecurity {
    match security {
        VmessSecurity::Auto => {
            if cfg!(target_arch = "x86_64")
                || cfg!(target_arch = "aarch64")
                || cfg!(target_arch = "s390x")
            {
                ResolvedSecurity::Aes128Gcm
            } else {
                ResolvedSecurity::ChaCha20Poly1305
            }
        }
        VmessSecurity::Aes128Gcm => ResolvedSecurity::Aes128Gcm,
        VmessSecurity::ChaCha20Poly1305 => ResolvedSecurity::ChaCha20Poly1305,
        VmessSecurity::None => ResolvedSecurity::None,
        VmessSecurity::Zero => ResolvedSecurity::Zero,
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
    #[allow(clippy::too_many_arguments)]
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
        if self.tls {
            return Err(Error::unsupported("VMess TLS transport not implemented"));
        }
        if self.network.to_lowercase() != "tcp" {
            return Err(Error::unsupported(format!(
                "VMess network '{}' not implemented",
                self.network
            )));
        }
        if self.alter_id != 0 {
            return Err(Error::unsupported(
                "VMess alterId>0 (legacy auth) not implemented",
            ));
        }

        let server_addr = self.server_addr();
        debug!(
            "VMess {} connecting to {} via {}",
            self.name,
            metadata.remote_address(),
            server_addr
        );

        let resolved_addr = self
            .dns_resolver
            .resolve(&self.server)
            .await
            .map_err(|e| {
                error!(
                    protocol = "vmess",
                    phase = "dns_resolve",
                    server = %self.server,
                    err = ?e,
                    "resolve failed"
                );
                e
            })?;
        let addr = format!("{}:{}", resolved_addr, self.port);
        let mut attempt: u32 = 0;
        let max_attempts: u32 = 10;
        let stream = loop {
            match TcpStream::connect(&addr).await {
                Ok(stream) => break stream,
                Err(e) if e.kind() == ErrorKind::AddrNotAvailable && attempt < max_attempts => {
                    attempt += 1;
                    debug!(
                        protocol = "vmess",
                        phase = "tcp_connect_retry",
                        server = %addr,
                        attempt,
                        err = ?e,
                        "connect failed, retrying"
                    );
                    let backoff_ms = 5u64.saturating_mul(attempt as u64).min(50);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(e) => {
                    error!(
                        protocol = "vmess",
                        phase = "tcp_connect",
                        server = %addr,
                        err = ?e,
                        "connect failed"
                    );
                    return Err(Error::connection(format!(
                        "Failed to connect to VMess server: {}",
                        e
                    )));
                }
            }
        };
        let _ = stream.set_nodelay(true);
        let _ = stream.set_linger(Some(Duration::from_secs(0)));

        let dest_addr = Address::from(metadata.destination());
        let security = resolve_security(self.security);
        let cmd_key = derive_cmd_key(&self.uuid);
        debug!(
            protocol = "vmess",
            phase = "encryption",
            cipher = ?security,
            "setup"
        );

        let conn =
            VmessConnection::connect(stream, cmd_key, security, dest_addr, metadata.dst_port)
                .await?;

        debug!(
            "VMess {} connected to {}",
            self.name,
            metadata.remote_address()
        );
        Ok(Box::new(conn))
    }
}

trait DynHash: Send + Sync {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
    fn block_size(&self) -> usize;
    fn output_size(&self) -> usize;
}

trait DynHashFactory: Send + Sync {
    fn create(&self) -> Box<dyn DynHash>;
    fn block_size(&self) -> usize;
    fn output_size(&self) -> usize;
}

struct Sha256Factory;

impl DynHashFactory for Sha256Factory {
    fn create(&self) -> Box<dyn DynHash> {
        Box::new(Sha256Hash {
            hasher: Sha256::new(),
        })
    }

    fn block_size(&self) -> usize {
        64
    }

    fn output_size(&self) -> usize {
        32
    }
}

struct Sha256Hash {
    hasher: Sha256,
}

impl DynHash for Sha256Hash {
    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(&mut self.hasher, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let Sha256Hash { hasher } = *self;
        hasher.finalize().to_vec()
    }

    fn block_size(&self) -> usize {
        64
    }

    fn output_size(&self) -> usize {
        32
    }
}

struct HmacFactory {
    key: Vec<u8>,
    inner: Arc<dyn DynHashFactory>,
}

impl HmacFactory {
    fn new(key: &[u8], inner: Arc<dyn DynHashFactory>) -> Self {
        Self {
            key: key.to_vec(),
            inner,
        }
    }
}

impl DynHashFactory for HmacFactory {
    fn create(&self) -> Box<dyn DynHash> {
        Box::new(DynHmac::new(self.key.clone(), self.inner.clone()))
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn output_size(&self) -> usize {
        self.inner.output_size()
    }
}

struct DynHmac {
    inner_factory: Arc<dyn DynHashFactory>,
    inner: Box<dyn DynHash>,
    opad: Vec<u8>,
}

impl DynHmac {
    fn new(key: Vec<u8>, inner_factory: Arc<dyn DynHashFactory>) -> Self {
        let block_size = inner_factory.block_size();
        let key = if key.len() > block_size {
            let mut h = inner_factory.create();
            h.update(&key);
            h.finalize()
        } else {
            key
        };

        let mut key_block = vec![0u8; block_size];
        key_block[..key.len()].copy_from_slice(&key);

        let mut ipad = key_block.clone();
        for b in &mut ipad {
            *b ^= 0x36;
        }

        let mut opad = key_block;
        for b in &mut opad {
            *b ^= 0x5c;
        }

        let mut inner = inner_factory.create();
        inner.update(&ipad);

        Self {
            inner_factory,
            inner,
            opad,
        }
    }
}

impl DynHash for DynHmac {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let DynHmac {
            inner_factory,
            inner,
            opad,
        } = *self;

        let inner_sum = inner.finalize();

        let mut outer = inner_factory.create();
        outer.update(&opad);
        outer.update(&inner_sum);
        outer.finalize()
    }

    fn block_size(&self) -> usize {
        self.inner_factory.block_size()
    }

    fn output_size(&self) -> usize {
        self.inner_factory.output_size()
    }
}

fn vmess_kdf(key: &[u8], salt: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut factory: Arc<dyn DynHashFactory> =
        Arc::new(HmacFactory::new(KDF_ROOT, Arc::new(Sha256Factory)));
    factory = Arc::new(HmacFactory::new(salt, factory));
    for p in path {
        factory = Arc::new(HmacFactory::new(p, factory));
    }

    let mut h = factory.create();
    h.update(key);
    let out = h.finalize();
    out.try_into()
        .unwrap_or_else(|_| unreachable!("sha256 output size mismatch"))
}

fn derive_cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, uuid.as_bytes());
    Md5Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn sha256_first16(data: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, data);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn generate_chacha20poly1305_key(key16: &[u8; 16]) -> [u8; 32] {
    let mut key32 = [0u8; 32];
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, key16);
    let t = hasher.finalize_reset();
    key32[..16].copy_from_slice(&t);

    Md5Digest::update(&mut hasher, &key32[..16]);
    let t = hasher.finalize();
    key32[16..].copy_from_slice(&t);
    key32
}

fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&timestamp.to_be_bytes());
    OsRng.fill_bytes(&mut buf[8..12]);

    let mut crc = Crc32Hasher::new();
    crc.update(&buf[..12]);
    let checksum = crc.finalize();
    buf[12..16].copy_from_slice(&checksum.to_be_bytes());

    let auth_key = vmess_kdf(cmd_key, KDF_SALT_AUTH_ID_ENCRYPTION_KEY, &[]);
    let cipher = Aes128::new_from_slice(&auth_key[..16]).expect("aes key length");
    let mut block = GenericArray::clone_from_slice(&buf);
    cipher.encrypt_block(&mut block);

    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn encode_vmess_address(address: &Address, port: u16, buf: &mut BytesMut) -> Result<()> {
    buf.put_u16(port);
    match address {
        Address::Ipv4(ip) => {
            buf.put_u8(0x01);
            buf.put_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            buf.put_u8(0x03);
            buf.put_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.len() > 255 {
                return Err(Error::address("Domain name too long"));
            }
            buf.put_u8(0x02);
            buf.put_u8(bytes.len() as u8);
            buf.put_slice(bytes);
        }
    }
    Ok(())
}

fn build_request_header(
    request_nonce: &[u8; 16],
    request_key: &[u8; 16],
    response_header: u8,
    option: u8,
    security: u8,
    command: u8,
    address: &Address,
    port: u16,
    padding_len: u8,
) -> Result<Vec<u8>> {
    let mut header = BytesMut::new();
    header.put_u8(VMESS_VERSION);
    header.put_slice(request_nonce);
    header.put_slice(request_key);
    header.put_u8(response_header);
    header.put_u8(option);
    header.put_u8((padding_len << 4) | (security & 0x0f));
    header.put_u8(0);
    header.put_u8(command);
    encode_vmess_address(address, port, &mut header)?;

    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        OsRng.fill_bytes(&mut padding);
        header.put_slice(&padding);
    }

    let checksum = fnv1a_hash(&header);
    header.put_u32(checksum);
    Ok(header.to_vec())
}

type Shake128Reader = <Shake128 as ExtendableOutput>::Reader;

struct VmessChunkMask {
    reader: Shake128Reader,
}

impl VmessChunkMask {
    fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        sha3::digest::Update::update(&mut shake, seed);
        let reader = shake.finalize_xof();
        Self { reader }
    }

    fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}

enum VmessBodyCipher {
    None,
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl VmessBodyCipher {
    fn overhead(&self) -> usize {
        match self {
            VmessBodyCipher::None => 0,
            VmessBodyCipher::Aes128Gcm(_) | VmessBodyCipher::ChaCha20Poly1305(_) => CIPHER_OVERHEAD,
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            VmessBodyCipher::None => Ok(plaintext.to_vec()),
            VmessBodyCipher::Aes128Gcm(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|e| Error::crypto(e.to_string())),
            VmessBodyCipher::ChaCha20Poly1305(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|e| Error::crypto(e.to_string())),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            VmessBodyCipher::None => Ok(ciphertext.to_vec()),
            VmessBodyCipher::Aes128Gcm(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| Error::crypto(e.to_string())),
            VmessBodyCipher::ChaCha20Poly1305(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|e| Error::crypto(e.to_string())),
        }
    }
}

struct VmessBodyCodec {
    cipher: VmessBodyCipher,
    nonce_suffix: [u8; 10],
    nonce_count: u16,
    chunk_mask: Option<VmessChunkMask>,
}

struct ResponseHeaderState {
    response_key: [u8; 16],
    response_nonce: [u8; 16],
    expected_header: u8,
    len_buf: BytesMut,
    header_buf: BytesMut,
    header_cipher_len: usize,
    stage: ResponseHeaderStage,
}

#[derive(Copy, Clone)]
enum ResponseHeaderStage {
    ReadingLen,
    ReadingHeader,
}

impl ResponseHeaderState {
    fn new(response_key: [u8; 16], response_nonce: [u8; 16], expected_header: u8) -> Self {
        Self {
            response_key,
            response_nonce,
            expected_header,
            len_buf: BytesMut::with_capacity(RESPONSE_HEADER_LEN_CIPHER_LEN),
            header_buf: BytesMut::new(),
            header_cipher_len: 0,
            stage: ResponseHeaderStage::ReadingLen,
        }
    }

    fn validate_header(self) -> Result<()> {
        let hdr_key = vmess_kdf(
            &self.response_key,
            KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY,
            &[],
        );
        let hdr_iv = vmess_kdf(
            &self.response_nonce,
            KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV,
            &[],
        );
        let hdr_cipher =
            Aes128Gcm::new_from_slice(&hdr_key[..16]).map_err(|e| Error::crypto(e.to_string()))?;

        let plain = hdr_cipher
            .decrypt(Nonce::from_slice(&hdr_iv[..12]), self.header_buf.as_ref())
            .map_err(|e| Error::crypto(e.to_string()))?;

        if plain.len() < 4 {
            return Err(Error::protocol("Unexpected VMess response header"));
        }
        if plain[0] != self.expected_header {
            return Err(Error::protocol("Unexpected VMess response header byte"));
        }
        if plain[2] != 0 {
            return Err(Error::unsupported("VMess dynamic port is not supported"));
        }
        Ok(())
    }
    fn decrypt_length(&self) -> Result<usize> {
        let len_key = vmess_kdf(&self.response_key, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, &[]);
        let len_iv = vmess_kdf(&self.response_nonce, KDF_SALT_AEAD_RESP_HEADER_LEN_IV, &[]);
        let len_cipher =
            Aes128Gcm::new_from_slice(&len_key[..16]).map_err(|e| Error::crypto(e.to_string()))?;

        let plain_len = len_cipher
            .decrypt(Nonce::from_slice(&len_iv[..12]), self.len_buf.as_ref())
            .map_err(|e| Error::crypto(e.to_string()))?;
        if plain_len.len() != 2 {
            return Err(Error::protocol("Invalid VMess response header length"));
        }

        Ok(u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize)
    }
}

impl VmessBodyCodec {
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.nonce_count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.nonce_suffix);
        self.nonce_count = self.nonce_count.wrapping_add(1);
        nonce
    }

    fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        self.cipher.encrypt(&nonce, plaintext)
    }

    fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        self.cipher.decrypt(&nonce, ciphertext)
    }

    fn mask_len(&mut self, len: u16) -> u16 {
        if let Some(mask) = &mut self.chunk_mask {
            len ^ mask.next_u16()
        } else {
            len
        }
    }
}

/// VMess connection wrapper (AEAD only)
pub struct VmessConnection {
    inner: TcpStream,

    enc: VmessBodyCodec,
    dec: VmessBodyCodec,

    dec_pending_len: Option<usize>,
    read_buf: BytesMut,
    pending_plain: BytesMut,

    write_buf: BytesMut,
    response_header_state: Option<ResponseHeaderState>,
}

impl VmessConnection {
    async fn connect(
        mut inner: TcpStream,
        cmd_key: [u8; 16],
        security: ResolvedSecurity,
        address: Address,
        port: u16,
    ) -> Result<Self> {
        if !security.is_aead() {
            return Err(Error::unsupported(
                "VMess security type without AEAD handshake not implemented",
            ));
        }

        let mut rng = OsRng;
        let mut request_key = [0u8; 16];
        let mut request_nonce = [0u8; 16];
        rng.fill_bytes(&mut request_key);
        rng.fill_bytes(&mut request_nonce);

        let response_header = (rng.next_u32() & 0xff) as u8;
        let padding_len = (rng.next_u32() % 16) as u8;

        let option = security.option();
        let security_byte = security.protocol_byte();

        let header = build_request_header(
            &request_nonce,
            &request_key,
            response_header,
            option,
            security_byte,
            COMMAND_TCP,
            &address,
            port,
            padding_len,
        )?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        debug!(protocol = "vmess", phase = "timestamp", ts = timestamp, "generated");
        let auth_id = create_auth_id(&cmd_key, timestamp);

        let mut connection_nonce = [0u8; 8];
        rng.fill_bytes(&mut connection_nonce);

        let header_len =
            u16::try_from(header.len()).map_err(|_| Error::protocol("VMess header too large"))?;
        let header_len_plain = header_len.to_be_bytes();

        let len_key = vmess_kdf(
            &cmd_key,
            KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &[&auth_id, &connection_nonce],
        );
        let len_iv = vmess_kdf(
            &cmd_key,
            KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &[&auth_id, &connection_nonce],
        );
        let len_cipher =
            Aes128Gcm::new_from_slice(&len_key[..16]).map_err(|e| Error::crypto(e.to_string()))?;
        let encrypted_len = len_cipher
            .encrypt(
                Nonce::from_slice(&len_iv[..12]),
                Payload {
                    msg: &header_len_plain,
                    aad: &auth_id,
                },
            )
            .map_err(|e| Error::crypto(e.to_string()))?;

        let hdr_key = vmess_kdf(
            &cmd_key,
            KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &[&auth_id, &connection_nonce],
        );
        let hdr_iv = vmess_kdf(
            &cmd_key,
            KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &[&auth_id, &connection_nonce],
        );
        let hdr_cipher =
            Aes128Gcm::new_from_slice(&hdr_key[..16]).map_err(|e| Error::crypto(e.to_string()))?;
        let encrypted_header = hdr_cipher
            .encrypt(
                Nonce::from_slice(&hdr_iv[..12]),
                Payload {
                    msg: &header,
                    aad: &auth_id,
                },
            )
            .map_err(|e| Error::crypto(e.to_string()))?;

        let mut request = BytesMut::new();
        request.put_slice(&auth_id);
        request.put_slice(&encrypted_len);
        request.put_slice(&connection_nonce);
        request.put_slice(&encrypted_header);
        inner.write_all(&request).await?;

        let response_key = sha256_first16(&request_key);
        let response_nonce = sha256_first16(&request_nonce);
        let response_header_state =
            ResponseHeaderState::new(response_key, response_nonce, response_header);

        let enc = new_body_codec(security, &request_key, &request_nonce)?;
        let dec = new_body_codec(security, &response_key, &response_nonce)?;

        Ok(VmessConnection {
            inner,
            enc,
            dec,
            dec_pending_len: None,
            read_buf: BytesMut::with_capacity(4096),
            pending_plain: BytesMut::new(),
            write_buf: BytesMut::new(),
            response_header_state: Some(response_header_state),
        })
    }

    fn map_vm_error(err: Error) -> io::Error {
        io::Error::new(ErrorKind::Other, err.to_string())
    }

    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_header_state.is_none() {
            return Poll::Ready(Ok(()));
        }

        loop {
            let stage = self.response_header_state.as_ref().unwrap().stage;
            match stage {
                ResponseHeaderStage::ReadingLen => {
                    let needed = {
                        let state = self.response_header_state.as_ref().unwrap();
                        RESPONSE_HEADER_LEN_CIPHER_LEN - state.len_buf.len()
                    };
                    if needed > 0 {
                        let mut tmp = [0u8; RESPONSE_HEADER_READ_CHUNK];
                        let read_size = std::cmp::min(RESPONSE_HEADER_READ_CHUNK, needed);
                        let mut read_buf = ReadBuf::new(&mut tmp[..read_size]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let filled = read_buf.filled();
                                if filled.is_empty() {
                                    return Poll::Ready(Err(io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "unexpected eof while reading vmess response header",
                                    )));
                                }
                                self.response_header_state
                                    .as_mut()
                                    .unwrap()
                                    .len_buf
                                    .extend_from_slice(filled);
                                continue;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let header_len = match self
                        .response_header_state
                        .as_ref()
                        .unwrap()
                        .decrypt_length()
                    {
                        Ok(len) => len,
                        Err(err) => return Poll::Ready(Err(Self::map_vm_error(err))),
                    };

                    if header_len < 4 || header_len > 4096 {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::Other,
                            Error::protocol(format!(
                                "Unexpected VMess response header length: {}",
                                header_len
                            ))
                            .to_string(),
                        )));
                    }

                    let state = self.response_header_state.as_mut().unwrap();
                    state.header_cipher_len = header_len + CIPHER_OVERHEAD;
                    state.header_buf.reserve(state.header_cipher_len);
                    state.stage = ResponseHeaderStage::ReadingHeader;
                    continue;
                }
                ResponseHeaderStage::ReadingHeader => {
                    let needed = {
                        let state = self.response_header_state.as_ref().unwrap();
                        state.header_cipher_len - state.header_buf.len()
                    };
                    if needed > 0 {
                        let mut tmp = [0u8; RESPONSE_HEADER_READ_CHUNK];
                        let read_size = std::cmp::min(RESPONSE_HEADER_READ_CHUNK, needed);
                        let mut read_buf = ReadBuf::new(&mut tmp[..read_size]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let filled = read_buf.filled();
                                if filled.is_empty() {
                                    return Poll::Ready(Err(io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "unexpected eof while reading vmess response header",
                                    )));
                                }
                                self.response_header_state
                                    .as_mut()
                                    .unwrap()
                                    .header_buf
                                    .extend_from_slice(filled);
                                continue;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let state = self.response_header_state.take().unwrap();
                    match state.validate_header() {
                        Ok(_) => return Poll::Ready(Ok(())),
                        Err(err) => return Poll::Ready(Err(Self::map_vm_error(err))),
                    }
                }
            }
        }
    }

    fn try_decrypt_into_pending(&mut self) -> Result<bool> {
        let mut produced = false;

        loop {
            if self.dec_pending_len.is_none() {
                if self.read_buf.len() < 2 {
                    break;
                }
                let len_enc = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]);
                self.read_buf.advance(2);
                let len = self.dec.mask_len(len_enc) as usize;
                if len == 0 {
                    return Ok(false);
                }
                self.dec_pending_len = Some(len);
            }

            let Some(payload_len) = self.dec_pending_len else {
                break;
            };
            if self.read_buf.len() < payload_len {
                break;
            }

            let ciphertext = self.read_buf.split_to(payload_len);
            let plaintext = self.dec.decrypt_chunk(&ciphertext)?;
            self.pending_plain.put_slice(&plaintext);
            self.dec_pending_len = None;
            produced = true;
        }

        Ok(produced)
    }

    fn poll_flush_write_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while !this.write_buf.is_empty() {
            let buf_slice: &[u8] = &this.write_buf;
            let n = match Pin::new(&mut this.inner).poll_write(cx, buf_slice) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write vmess data",
                )));
            }
            this.write_buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

fn new_body_codec(
    security: ResolvedSecurity,
    key16: &[u8; 16],
    nonce16: &[u8; 16],
) -> Result<VmessBodyCodec> {
    let cipher = match security {
        ResolvedSecurity::Aes128Gcm => VmessBodyCipher::Aes128Gcm(
            Aes128Gcm::new_from_slice(key16).map_err(|e| Error::crypto(e.to_string()))?,
        ),
        ResolvedSecurity::ChaCha20Poly1305 => {
            let key32 = generate_chacha20poly1305_key(key16);
            VmessBodyCipher::ChaCha20Poly1305(
                ChaCha20Poly1305::new_from_slice(&key32)
                    .map_err(|e| Error::crypto(e.to_string()))?,
            )
        }
        ResolvedSecurity::None | ResolvedSecurity::Zero => VmessBodyCipher::None,
    };

    let mut nonce_suffix = [0u8; 10];
    nonce_suffix.copy_from_slice(&nonce16[2..12]);

    let chunk_mask = if security.is_aead() && (security.option() & OPTION_CHUNK_MASKING != 0) {
        Some(VmessChunkMask::new(nonce16))
    } else {
        None
    };

    Ok(VmessBodyCodec {
        cipher,
        nonce_suffix,
        nonce_count: 0,
        chunk_mask,
    })
}

impl AsyncRead for VmessConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.response_header_state.is_some() {
            match this.poll_response_header(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !this.pending_plain.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), this.pending_plain.len());
            buf.put_slice(&this.pending_plain.split_to(to_read));
            return Poll::Ready(Ok(()));
        }

        loop {
            match this.try_decrypt_into_pending() {
                Ok(true) => {
                    let to_read = std::cmp::min(buf.remaining(), this.pending_plain.len());
                    buf.put_slice(&this.pending_plain.split_to(to_read));
                    return Poll::Ready(Ok(()));
                }
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
            }

            let mut inner_buf = [0u8; 16384];
            let mut read_buf = ReadBuf::new(&mut inner_buf);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.read_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for VmessConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.write_buf.is_empty() {
            match self.as_mut().poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let this = self.as_mut().get_mut();
        if !buf.is_empty() {
            for chunk in buf.chunks(WRITE_CHUNK_SIZE) {
                let ciphertext = match this.enc.encrypt_chunk(chunk) {
                    Ok(c) => c,
                    Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                };

                if ciphertext.len() > u16::MAX as usize {
                    return Poll::Ready(Err(io::Error::other("vmess chunk too large")));
                }
                let mut len = ciphertext.len() as u16;
                len = this.enc.mask_len(len);

                this.write_buf.put_u16(len);
                this.write_buf.put_slice(&ciphertext);
            }
        }

        match self.as_mut().poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any pending data, but avoid initiating an active close (FIN)
        // to reduce TIME_WAIT pressure. With SO_LINGER=0 on the underlying
        // TCP socket, dropping the connection will send RST instead.
        match self.as_mut().poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
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
        assert_eq!(
            VmessSecurity::try_from("chacha20-poly1305").unwrap(),
            VmessSecurity::ChaCha20Poly1305
        );
    }

    #[test]
    fn test_fnv1a() {
        let hash = fnv1a_hash(b"hello");
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_kdf_output_len() {
        let out = vmess_kdf(&[0u8; 16], b"test", &[b"path"]);
        assert_eq!(out.len(), 32);
    }
}
