//! VLESS protocol outbound with TLS connection pre-warming
//!
//! Implements VLESS protocol (V2Ray's lightweight protocol variant).
//! VLESS removes the encryption layer from VMess, relying on TLS for security.
//! This implementation pre-establishes TLS connections to reduce handshake latency.

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::pool_predictor::{predict_pool_iter, PredictorConfig, TimestampRingBuffer};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use tracing::{debug, info, trace, warn};
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

/// Connection pool configuration
const DEFAULT_POOL_SIZE: usize = 16;
const DEFAULT_POOL_MAX_IDLE_SECS: u64 = 60;
const DEFAULT_WARMUP_BATCH_SIZE: usize = 4;

/// TLS handshake latency estimate (milliseconds) for predictor
const TLS_SETUP_LATENCY_MS: u64 = 250;

/// Runtime pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub size: usize,
    pub max_idle_secs: u64,
    pub warmup_batch_size: usize,
    pub predictive_warmup: bool,
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
    current_size: AtomicUsize,
    request_timestamps: Mutex<TimestampRingBuffer>,
    config: PoolConfig,
    stats_hit: AtomicU64,
    stats_miss: AtomicU64,
}

impl WarmPool {
    fn new(config: PoolConfig) -> Self {
        Self {
            connections: Mutex::new(VecDeque::with_capacity(config.size)),
            warming_count: AtomicU64::new(0),
            current_size: AtomicUsize::new(0),
            request_timestamps: Mutex::new(TimestampRingBuffer::new(10_000, 4096)),
            config,
            stats_hit: AtomicU64::new(0),
            stats_miss: AtomicU64::new(0),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn record_request(&self) {
        let now = Self::now_ms();
        self.request_timestamps.lock().push(now);
    }

    fn try_get(&self) -> Option<TlsStream<TcpStream>> {
        self.record_request();

        let mut pool = self.connections.lock();

        while let Some(conn) = pool.pop_front() {
            if !conn.is_stale(self.config.max_idle_secs) {
                self.current_size.store(pool.len(), Ordering::Relaxed);
                self.stats_hit.fetch_add(1, Ordering::Relaxed);
                debug!(protocol = "vless", phase = "pool", "using pre-warmed connection");
                return Some(conn.stream);
            }
        }
        self.current_size.store(0, Ordering::Relaxed);
        self.stats_miss.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn stats(&self) -> (u64, u64, f64) {
        let hit = self.stats_hit.load(Ordering::Relaxed);
        let miss = self.stats_miss.load(Ordering::Relaxed);
        let total = hit + miss;
        let rate = if total > 0 { (hit as f64 / total as f64) * 100.0 } else { 0.0 };
        (hit, miss, rate)
    }

    fn put(&self, stream: TlsStream<TcpStream>) {
        let mut pool = self.connections.lock();
        if pool.len() < self.config.size {
            pool.push_back(WarmConnection::new(stream));
            self.current_size.store(pool.len(), Ordering::Relaxed);
        }
    }

    fn size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }

    fn predict_warmup_count(&self) -> usize {
        if !self.config.predictive_warmup {
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
            protocol = "vless",
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
        let predicted = self.predict_warmup_count();
        if predicted > 0 {
            predicted.min(self.config.warmup_batch_size.max(1))
        } else {
            self.config.warmup_batch_size
        }
    }
}

/// VLESS proxy outbound with TLS pre-warming
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
    tls_connector: Option<TlsConnector>,
    warm_pool: Option<Arc<WarmPool>>,
    cached_ips: Mutex<Option<(Vec<std::net::IpAddr>, Instant)>>,
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

        let (tls_connector, warm_pool) = if tls {
            let connector = Self::create_tls_connector(skip_cert_verify)?;
            let pool = Arc::new(WarmPool::new(PoolConfig::default()));
            (Some(connector), Some(pool))
        } else {
            (None, None)
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
            tls_connector,
            warm_pool,
            cached_ips: Mutex::new(None),
        })
    }

    /// Build VLESS request header
    fn build_request(&self, host: &str, port: u16, cmd: u8) -> Vec<u8> {
        let mut request = Vec::with_capacity(128);

        request.push(VLESS_VERSION);
        request.extend_from_slice(self.uuid.as_bytes());
        request.push(0); // Addons length
        request.push(cmd);
        request.extend_from_slice(&port.to_be_bytes());

        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        } else {
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
            let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
        }

        #[cfg(not(unix))]
        {
            let _ = stream;
        }
    }

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
        let connector = self.tls_connector.as_ref()
            .ok_or_else(|| Error::tls("TLS not enabled"))?;
        let server_name = self.tls_server_name.clone()
            .ok_or_else(|| Error::tls("Missing TLS server name"))?;

        let ips = self.get_ips().await?;

        let mut tcp_stream: Option<TcpStream> = None;
        let mut last_err: Option<Error> = None;

        for ip in ips {
            let addr = SocketAddr::new(ip, self.port);
            match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    Self::configure_socket(&s);
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

        timeout(
            CONNECT_TIMEOUT,
            connector.clone().connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| Error::tls("TLS timeout"))?
        .map_err(|e| Error::tls(format!("TLS failed: {}", e)))
    }

    /// Get a TLS connection (from pool or create new)
    async fn get_tls_connection(&self) -> Result<TlsStream<TcpStream>> {
        if let Some(pool) = &self.warm_pool {
            if let Some(stream) = pool.try_get() {
                return Ok(stream);
            }
        }
        self.create_tls_connection().await
    }

    /// Spawn background warmup tasks
    fn spawn_warmup(&self) {
        let pool = match &self.warm_pool {
            Some(p) => p.clone(),
            None => return,
        };
        let connector = match &self.tls_connector {
            Some(c) => c.clone(),
            None => return,
        };
        let server_name = match &self.tls_server_name {
            Some(s) => s.clone(),
            None => return,
        };

        let batch_size = pool.warmup_batch_size();
        for _ in 0..batch_size {
            if !pool.start_warming() {
                break;
            }

            let pool = pool.clone();
            let connector = connector.clone();
            let server_name = server_name.clone();
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
                    debug!(protocol = "vless", phase = "warmup", "connection warmed");
                }
            });
        }
    }

    /// Get pool statistics: (hit, miss, hit_rate%)
    pub fn pool_stats(&self) -> (u64, u64, f64) {
        self.warm_pool.as_ref()
            .map(|p| p.stats())
            .unwrap_or((0, 0, 0.0))
    }

    /// Print pool statistics to log
    pub fn log_pool_stats(&self) {
        let (hit, miss, rate) = self.pool_stats();
        info!(
            protocol = "vless",
            name = %self.name,
            pool_hit = hit,
            pool_miss = miss,
            hit_rate = format!("{:.1}%", rate),
            "pool statistics"
        );
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
            protocol = "vless",
            name = %self.name,
            dst = %format!("{}:{}", target_host, target_port),
            pool = self.warm_pool.as_ref().map(|p| p.size()).unwrap_or(0),
            "dial"
        );

        let request = self.build_request(target_host.as_ref(), target_port, CMD_TCP);

        if self.tls {
            let mut tls_stream = self.get_tls_connection().await?;

            if let Err(e) = tls_stream.write_all(&request).await {
                warn!(protocol = "vless", err = %e, "retry with fresh connection");
                tls_stream = self.create_tls_connection().await?;
                tls_stream.write_all(&request).await
                    .map_err(|e| Error::protocol(format!("header write: {}", e)))?;
            }

            // Trigger background warmup
            self.spawn_warmup();

            // Log pool stats every 1000 requests
            if let Some(pool) = &self.warm_pool {
                let (hit, miss, _) = pool.stats();
                let total = hit + miss;
                if total > 0 && total % 1000 == 0 {
                    self.log_pool_stats();
                }
            }

            Ok(Box::new(VlessConnection::new(tls_stream)))
        } else {
            // Plain TCP (not recommended, but supported)
            let resolved = self.dns_resolver.resolve(&self.server).await?;
            let server_addr = SocketAddr::new(resolved, self.port);
            let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr))
                .await
                .map_err(|_| Error::timeout("VLESS connection timeout"))?
                .map_err(|e| Error::connection(format!("Failed to connect to VLESS server: {}", e)))?;

            stream.set_nodelay(true).ok();
            Self::configure_socket(&stream);

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
