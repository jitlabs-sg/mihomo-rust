//! Shared TCP warm pool used by protocols with per-request handshakes.

use crate::common::pool_predictor::{predict_pool_iter, PredictorConfig, TimestampRingBuffer};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// Runtime TCP pool configuration
#[derive(Debug, Clone)]
pub(crate) struct TcpPoolConfig {
    pub size: usize,
    pub max_idle_secs: u64,
    pub warmup_batch_size: usize,
    pub predictive_warmup: bool,
    pub predictor_config: PredictorConfig,
    pub setup_latency_ms: u64,
}

impl TcpPoolConfig {
    pub fn new(
        size: usize,
        max_idle_secs: u64,
        warmup_batch_size: usize,
        setup_latency_ms: u64,
    ) -> Self {
        Self {
            size,
            max_idle_secs,
            warmup_batch_size,
            predictive_warmup: true,
            predictor_config: PredictorConfig::default(),
            setup_latency_ms,
        }
    }
}

/// A pre-warmed TCP connection (not yet used for any target)
struct WarmTcpConnection {
    stream: TcpStream,
    created_at: Instant,
}

impl WarmTcpConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            created_at: Instant::now(),
        }
    }

    fn is_stale(&self, max_idle_secs: u64) -> bool {
        self.created_at.elapsed().as_secs() > max_idle_secs
    }
}

/// Pool of pre-warmed TCP connections with predictive warmup
pub(crate) struct TcpWarmPool {
    protocol: &'static str,
    connections: Mutex<VecDeque<WarmTcpConnection>>,
    warming_count: AtomicU64,
    current_size: AtomicUsize,
    request_timestamps: Mutex<TimestampRingBuffer>,
    config: TcpPoolConfig,
    stats_hit: AtomicU64,
    stats_miss: AtomicU64,
}

impl TcpWarmPool {
    pub fn new(protocol: &'static str, config: TcpPoolConfig) -> Self {
        Self {
            protocol,
            connections: Mutex::new(VecDeque::with_capacity(config.size)),
            warming_count: AtomicU64::new(0),
            current_size: AtomicUsize::new(0),
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

    /// Try to get a fresh TCP connection from the pool
    pub fn try_get(&self) -> Option<TcpStream> {
        self.record_request();

        let mut pool = self.connections.lock();
        while let Some(conn) = pool.pop_front() {
            if !conn.is_stale(self.config.max_idle_secs) {
                self.current_size.store(pool.len(), Ordering::Relaxed);
                self.stats_hit.fetch_add(1, Ordering::Relaxed);
                debug!(
                    protocol = self.protocol,
                    phase = "pool",
                    "using pre-warmed connection"
                );
                return Some(conn.stream);
            }
        }
        self.current_size.store(0, Ordering::Relaxed);
        self.stats_miss.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Get pool statistics (hit, miss, hit_rate%)
    pub fn stats(&self) -> (u64, u64, f64) {
        let hit = self.stats_hit.load(Ordering::Relaxed);
        let miss = self.stats_miss.load(Ordering::Relaxed);
        let total = hit + miss;
        let rate = if total > 0 {
            (hit as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        (hit, miss, rate)
    }

    /// Add a fresh connection to the pool
    pub fn put(&self, stream: TcpStream) {
        let mut pool = self.connections.lock();
        if pool.len() < self.config.size {
            pool.push_back(WarmTcpConnection::new(stream));
            self.current_size.store(pool.len(), Ordering::Relaxed);
        }
    }

    /// Get pool size without lock (approximate but fast)
    pub fn size(&self) -> usize {
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
            self.config.setup_latency_ms,
            available,
            warming,
            &self.config.predictor_config,
        );
        drop(timestamps);

        trace!(
            protocol = self.protocol,
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

    pub fn start_warming(&self) -> bool {
        let count = self.predict_warmup_count();
        if count > 0 {
            self.warming_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn finish_warming(&self) {
        self.warming_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn warmup_batch_size(&self) -> usize {
        let predicted = self.predict_warmup_count();
        if predicted > 0 {
            predicted.min(self.config.warmup_batch_size.max(1))
        } else {
            self.config.warmup_batch_size
        }
    }
}
