//! Trojan outbound protocol with TLS connection pre-warming
//!
//! This implementation pre-establishes TLS connections to reduce handshake latency.
//! Fresh TLS connections are kept warm and used for new requests.

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::net::Address;
use crate::common::pool_predictor::{predict_pool_iter, PredictorConfig, TimestampRingBuffer};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use sha2::{Digest, Sha224};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use tracing::{debug, info, trace, warn};

/// Connection pool configuration (defaults, can be overridden via config)
/// NOTE: Pool size increased from 4 to 16 to handle concurrent requests better
/// NOTE: Max idle increased from 30s to 60s to keep warm connections longer
const DEFAULT_POOL_SIZE: usize = 16;          // Larger pool for high concurrency
const DEFAULT_POOL_MAX_IDLE_SECS: u64 = 60;   // Keep warm connections longer
const DEFAULT_WARMUP_BATCH_SIZE: usize = 4;   // Warm up more connections at once

/// TLS handshake latency estimate (milliseconds) for predictor
/// NOTE: Increased from 50ms to 250ms to match real-world latency (2 RTT to remote server)
const TLS_SETUP_LATENCY_MS: u64 = 250;

/// Runtime pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub size: usize,
    pub max_idle_secs: u64,
    pub warmup_batch_size: usize,
    /// Enable predictive warmup based on QPS
    pub predictive_warmup: bool,
    /// Predictor configuration
    pub predictor_config: PredictorConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: DEFAULT_POOL_SIZE,
            max_idle_secs: DEFAULT_POOL_MAX_IDLE_SECS,
            warmup_batch_size: DEFAULT_WARMUP_BATCH_SIZE,
            predictive_warmup: true,
            predictor_config: PredictorConfig::default(),
        }
    }
}

/// Trojan command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    Connect = 0x01,
    #[allow(dead_code)]
    UdpAssociate = 0x03,
}

/// A pre-warmed TLS connection (not yet used for any target)
struct WarmConnection {
    stream: TlsStream<TcpStream>,
    created_at: Instant,
}

impl WarmConnection {
    fn new(stream: TlsStream<TcpStream>) -> Self {
        Self {
            stream,
            created_at: Instant::now(),
        }
    }

    fn is_stale(&self, max_idle_secs: u64) -> bool {
        self.created_at.elapsed().as_secs() > max_idle_secs
    }
}

/// Pool of pre-warmed TLS connections with predictive warmup
struct WarmPool {
    connections: Mutex<VecDeque<WarmConnection>>,
    warming_count: AtomicU64,
    /// Current pool size (atomic for lock-free reads)
    current_size: AtomicUsize,
    /// Request timestamps for QPS prediction (10s window, max 4096 entries)
    request_timestamps: Mutex<TimestampRingBuffer>,
    config: PoolConfig,
    /// Pool statistics for diagnostics
    stats_hit: AtomicU64,
    stats_miss: AtomicU64,
}

impl WarmPool {
    fn new(config: PoolConfig) -> Self {
        Self {
            connections: Mutex::new(VecDeque::with_capacity(config.size)),
            warming_count: AtomicU64::new(0),
            current_size: AtomicUsize::new(0),
            // 10 second window, max 4096 entries to bound memory
            request_timestamps: Mutex::new(TimestampRingBuffer::new(10_000, 4096)),
            config,
            stats_hit: AtomicU64::new(0),
            stats_miss: AtomicU64::new(0),
        }
    }

    /// Get current timestamp in milliseconds
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Record a request for QPS tracking
    fn record_request(&self) {
        let now = Self::now_ms();
        self.request_timestamps.lock().push(now);
    }

    /// Try to get a fresh TLS connection from the pool
    fn try_get(&self) -> Option<TlsStream<TcpStream>> {
        // Record request timestamp for prediction
        self.record_request();

        let mut pool = self.connections.lock();

        // Find a non-stale connection
        while let Some(conn) = pool.pop_front() {
            if !conn.is_stale(self.config.max_idle_secs) {
                self.current_size.store(pool.len(), Ordering::Relaxed);
                self.stats_hit.fetch_add(1, Ordering::Relaxed);
                debug!(protocol = "trojan", phase = "pool", "using pre-warmed connection");
                return Some(conn.stream);
            }
            // Stale, drop it
        }
        self.current_size.store(0, Ordering::Relaxed);
        self.stats_miss.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Get pool statistics (hit, miss, hit_rate%)
    fn stats(&self) -> (u64, u64, f64) {
        let hit = self.stats_hit.load(Ordering::Relaxed);
        let miss = self.stats_miss.load(Ordering::Relaxed);
        let total = hit + miss;
        let rate = if total > 0 { (hit as f64 / total as f64) * 100.0 } else { 0.0 };
        (hit, miss, rate)
    }

    /// Add a fresh connection to the pool
    fn put(&self, stream: TlsStream<TcpStream>) {
        let mut pool = self.connections.lock();
        if pool.len() < self.config.size {
            pool.push_back(WarmConnection::new(stream));
            self.current_size.store(pool.len(), Ordering::Relaxed);
        }
        // Otherwise drop - pool is full
    }

    /// Get pool size without lock (approximate but fast)
    fn size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Get exact pool size (requires lock)
    fn size_exact(&self) -> usize {
        self.connections.lock().len()
    }

    /// Determine warmup count using predictor
    fn predict_warmup_count(&self) -> usize {
        if !self.config.predictive_warmup {
            // Fallback to simple logic
            let current = self.size();
            let warming = self.warming_count.load(Ordering::Relaxed) as usize;
            if current + warming < self.config.size {
                return self.config.warmup_batch_size;
            }
            return 0;
        }

        let now_ms = Self::now_ms();
        let available = self.size();
        let warming = self.warming_count.load(Ordering::Relaxed) as usize;

        let timestamps = self.request_timestamps.lock();
        let prediction = predict_pool_iter(
            timestamps.iter(),
            now_ms,
            TLS_SETUP_LATENCY_MS,
            available,
            warming,
            &self.config.predictor_config,
        );
        drop(timestamps);

        trace!(
            protocol = "trojan",
            qps_fast = %format!("{:.1}", prediction.qps_fast),
            qps_slow = %format!("{:.1}", prediction.qps_slow),
            suggested_cap = prediction.suggested_cap,
            warmup_count = prediction.warmup_count,
            available = available,
            warming = warming,
            "pool predictor"
        );

        prediction.warmup_count
    }

    fn need_warmup(&self) -> bool {
        self.predict_warmup_count() > 0
    }

    fn start_warming(&self) -> bool {
        let count = self.predict_warmup_count();
        if count > 0 {
            self.warming_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn finish_warming(&self) {
        self.warming_count.fetch_sub(1, Ordering::Relaxed);
    }

    fn warmup_batch_size(&self) -> usize {
        // Use predictor's suggested count, capped by config
        let predicted = self.predict_warmup_count();
        if predicted > 0 {
            predicted.min(self.config.warmup_batch_size.max(1))
        } else {
            self.config.warmup_batch_size
        }
    }
}

/// Trojan outbound with TLS pre-warming
pub struct Trojan {
    name: String,
    server: String,
    port: u16,
    password_hash: String,
    udp: bool,
    sni: Option<String>,
    #[allow(dead_code)]
    skip_cert_verify: bool,
    #[allow(dead_code)]
    network: String,
    dns_resolver: Arc<Resolver>,
    tls_connector: TlsConnector,
    /// Pool of pre-warmed TLS connections
    warm_pool: Arc<WarmPool>,
    /// Cached server name for TLS
    server_name: ServerName<'static>,
    /// Cached resolved IPs (with TTL)
    cached_ips: Mutex<Option<(Vec<std::net::IpAddr>, Instant)>>,
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
        Self::with_pool_config(
            name, server, port, password, udp, sni, skip_cert_verify, network,
            dns_resolver, PoolConfig::default(),
        )
    }

    pub fn with_pool_config(
        name: String,
        server: String,
        port: u16,
        password: String,
        udp: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        network: String,
        dns_resolver: Arc<Resolver>,
        pool_config: PoolConfig,
    ) -> Result<Self> {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let password_hash = hex::encode(hash);

        let tls_config = build_tls_config(skip_cert_verify);
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        // Pre-compute server name for TLS
        let sni_str = sni.as_deref().unwrap_or(&server);
        let server_name: ServerName<'static> = sni_str.to_string().try_into()
            .map_err(|_| Error::tls("Invalid SNI"))?;

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
            warm_pool: Arc::new(WarmPool::new(pool_config)),
            server_name,
            cached_ips: Mutex::new(None),
        })
    }

    /// Get cached IPs or resolve (with 60s TTL)
    async fn get_ips(&self) -> Result<Vec<std::net::IpAddr>> {
        {
            let cache = self.cached_ips.lock();
            if let Some((ips, created)) = cache.as_ref() {
                if created.elapsed().as_secs() < 60 {
                    return Ok(ips.clone());
                }
            }
        }

        let ips = self.dns_resolver.resolve_all(&self.server).await?;
        {
            let mut cache = self.cached_ips.lock();
            *cache = Some((ips.clone(), Instant::now()));
        }
        Ok(ips)
    }

    /// Create a new TLS connection
    async fn create_tls_connection(&self) -> Result<TlsStream<TcpStream>> {
        let ips = self.get_ips().await?;

        let mut tcp_stream: Option<TcpStream> = None;
        let mut last_err: Option<Error> = None;

        for ip in ips {
            let addr = SocketAddr::new(ip, self.port);
            match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    #[cfg(unix)]
                    {
                        use socket2::SockRef;
                        let _ = SockRef::from(&s).set_linger(Some(Duration::ZERO));
                    }
                    tcp_stream = Some(s);
                    break;
                }
                Ok(Err(e)) => {
                    last_err = Some(Error::connection(format!("TCP connect ({}): {}", addr, e)));
                }
                Err(_) => {
                    last_err = Some(Error::connection(format!("TCP timeout ({})", addr)));
                }
            }
        }

        let tcp_stream = tcp_stream.ok_or_else(|| {
            last_err.unwrap_or_else(|| Error::connection("No IPs"))
        })?;

        // TLS handshake
        timeout(
            Duration::from_secs(10),
            self.tls_connector.clone().connect(self.server_name.clone(), tcp_stream),
        )
        .await
        .map_err(|_| Error::tls("TLS timeout"))?
        .map_err(|e| Error::tls(format!("TLS failed: {}", e)))
    }

    /// Get a TLS connection (from pool or create new)
    async fn get_tls_connection(&self) -> Result<TlsStream<TcpStream>> {
        // Try warm pool first
        if let Some(stream) = self.warm_pool.try_get() {
            return Ok(stream);
        }


        // Create new connection
        self.create_tls_connection().await
    }

    /// Spawn background warmup tasks
    fn spawn_warmup(&self) {
        let batch_size = self.warm_pool.warmup_batch_size();
        for _ in 0..batch_size {
            if !self.warm_pool.start_warming() {
                break;
            }

            let pool = self.warm_pool.clone();
            let connector = self.tls_connector.clone();
            let server_name = self.server_name.clone();
            let resolver = self.dns_resolver.clone();
            let server = self.server.clone();
            let port = self.port;

            tokio::spawn(async move {
                let result = async {
                    let ips = resolver.resolve_all(&server).await?;

                    let mut tcp: Option<TcpStream> = None;
                    for ip in ips {
                        let addr = SocketAddr::new(ip, port);
                        if let Ok(Ok(s)) = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
                            let _ = s.set_nodelay(true);
                            #[cfg(unix)]
                            {
                                use socket2::SockRef;
                                let _ = SockRef::from(&s).set_linger(Some(Duration::ZERO));
                            }
                            tcp = Some(s);
                            break;
                        }
                    }
                    let tcp = tcp.ok_or_else(|| Error::connection("warmup: no TCP"))?;

                    timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
                        .await
                        .map_err(|_| Error::tls("warmup: TLS timeout"))?
                        .map_err(|e| Error::tls(format!("warmup: {}", e)))
                }
                .await;

                pool.finish_warming();

                if let Ok(stream) = result {
                    pool.put(stream);
                    debug!(protocol = "trojan", phase = "warmup", "connection warmed");
                }
            });
        }
    }

    fn build_header(&self, command: TrojanCommand, address: &Address, port: u16) -> Result<Vec<u8>> {
        build_header_bytes(&self.password_hash, command, address, port)
    }
    
    /// Get pool statistics: (hit, miss, hit_rate%)
    pub fn pool_stats(&self) -> (u64, u64, f64) {
        self.warm_pool.stats()
    }
    
    /// Print pool statistics to log
    pub fn log_pool_stats(&self) {
        let (hit, miss, rate) = self.pool_stats();
        info!(
            protocol = "trojan",
            name = %self.name,
            pool_hit = hit,
            pool_miss = miss,
            hit_rate = format!("{:.1}%", rate),
            "pool statistics"
        );
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
                return Err(Error::address("Domain too long"));
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
    let mut header = BytesMut::with_capacity(password_hash.len() + 2 + 1 + socks5_addr.len() + 2);
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
        debug!(
            protocol = "trojan",
            name = %self.name,
            dst = %metadata.remote_address(),
            pool = self.warm_pool.size(),
            "dial"
        );

        // Get TLS connection
        let mut tls_stream = self.get_tls_connection().await?;

        // Send Trojan header
        let address = Address::from(metadata.destination());
        let header = self.build_header(TrojanCommand::Connect, &address, metadata.dst_port)?;

        if let Err(e) = tls_stream.write_all(&header).await {
            // Stale connection, retry with fresh one
            warn!(protocol = "trojan", err = %e, "retry with fresh connection");
            tls_stream = self.create_tls_connection().await?;
            tls_stream.write_all(&header).await
                .map_err(|e| Error::protocol(format!("header write: {}", e)))?;
        }

        // Trigger background warmup
        self.spawn_warmup();

        // Log pool stats every 1000 requests
        let (hit, miss, _) = self.warm_pool.stats();
        let total = hit + miss;
        let every = super::pool_stats_log_every();
        if total > 0 && total % every == 0 {
            self.log_pool_stats();
        }

        Ok(Box::new(TrojanConnection::new(tls_stream)))
    }
}

/// Trojan connection wrapper
pub struct TrojanConnection<S> {
    inner: S,
}

impl<S> TrojanConnection<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> AsyncRead for TrojanConnection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TrojanConnection<S>
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

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Just flush, let SO_LINGER=0 handle close
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn build_tls_config(skip_cert_verify: bool) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = if skip_cert_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // Enable TLS session resumption (rustls 0.23+ defaults to enabled)
    config.resumption = rustls::client::Resumption::default()
        .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOrTickets);

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
            0x03, 9,
            b'm', b'h', b'-', b't', b'a', b'r', b'g', b'e', b't',
            0x46, 0xA0,
        ]);
        expected.extend_from_slice(b"\r\n");

        assert_eq!(header, expected);
    }
}
