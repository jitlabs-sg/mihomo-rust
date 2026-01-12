//! Connection pool capacity predictor with bounded memory usage.
//!
//! This module provides predictive scaling for connection pools based on
//! request arrival patterns. It uses exponential weighted moving average (EWMA)
//! for QPS estimation and Poisson quantiles for capacity planning.
//!
//! # Key Features
//! - `TimestampRingBuffer`: Bounded memory for timestamp storage (O(QPS*T) -> O(max_len))
//! - Dual-tau EWMA: Fast (1s) for burst response, slow (10s) for baseline
//! - Poisson p99 quantile for warmup count calculation
//!
//! # Example
//! ```ignore
//! use crate::common::pool_predictor::{TimestampRingBuffer, PredictorConfig, predict_pool_iter};
//!
//! let cfg = PredictorConfig::default();
//! let mut rb = TimestampRingBuffer::new(10_000, 4096); // 10s window, max 4096 entries
//!
//! // On each request
//! let now_ms = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH)
//!     .unwrap()
//!     .as_millis() as u64;
//! rb.push(now_ms);
//!
//! // Periodically predict pool capacity
//! let pred = predict_pool_iter(rb.iter(), now_ms, 50, available, warming, &cfg);
//! if pred.warmup_count > 0 {
//!     // Initiate warmup connections
//! }
//! ```

use std::collections::VecDeque;

/// Configuration for the pool capacity predictor.
#[derive(Debug, Clone)]
pub struct PredictorConfig {
    /// Fast EWMA time constant (seconds). Responds quickly to bursts.
    pub tau_fast_secs: f64,
    /// Slow EWMA time constant (seconds). Tracks baseline load.
    pub tau_slow_secs: f64,
    /// Window for burst detection (seconds).
    pub burst_window_secs: f64,
    /// Z-score for p99 calculation (2.33 for 99th percentile).
    pub p99_z: f64,
    /// Headroom multiplier for capacity (e.g., 1.2 = 20% extra).
    pub headroom: f64,
    /// Minimum pool capacity.
    pub min_cap: usize,
    /// Maximum pool capacity.
    pub max_cap: usize,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            tau_fast_secs: 1.0,
            tau_slow_secs: 10.0,
            burst_window_secs: 0.5,
            p99_z: 2.33,
            headroom: 1.2,
            min_cap: 1,
            max_cap: 4096,
        }
    }
}

/// Prediction result from the pool predictor.
#[derive(Debug, Clone, Copy)]
pub struct Prediction {
    /// Number of connections to warm up immediately.
    pub warmup_count: usize,
    /// Suggested total pool capacity.
    pub suggested_cap: usize,
    /// Fast EWMA QPS estimate.
    pub qps_fast: f64,
    /// Slow EWMA QPS estimate.
    pub qps_slow: f64,
    /// Burst window QPS estimate.
    pub qps_burst: f64,
}

/// Ring buffer for request timestamps with bounded memory.
///
/// Space complexity is `O(min(QPS*window_ms/1000, max_len))` instead of unbounded.
///
/// # Important
/// Always set `max_len` to prevent memory explosion under high QPS.
/// Recommended: `max_len = expected_peak_qps * window_secs * 2`
#[derive(Debug, Clone)]
pub struct TimestampRingBuffer {
    window_ms: u64,
    max_len: usize,
    buf: VecDeque<u64>,
}

impl TimestampRingBuffer {
    /// Create a new ring buffer.
    ///
    /// - `window_ms`: Time window to keep (milliseconds)
    /// - `max_len`: Maximum number of entries (hard limit for memory)
    pub fn new(window_ms: u64, max_len: usize) -> Self {
        Self {
            window_ms,
            max_len: max_len.max(1),
            buf: VecDeque::with_capacity(max_len.min(1024)),
        }
    }

    /// Push a timestamp (milliseconds).
    ///
    /// Uses the timestamp as `now_ms` for pruning (suitable for monotonic arrivals).
    pub fn push(&mut self, ts_ms: u64) {
        self.buf.push_back(ts_ms);
        self.prune(ts_ms);
    }

    /// Prune entries outside the window and exceeding max_len.
    pub fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(&front) = self.buf.front() {
            if front < cutoff {
                self.buf.pop_front();
            } else {
                break;
            }
        }
        while self.buf.len() > self.max_len {
            self.buf.pop_front();
        }
    }

    /// Iterate over timestamps.
    pub fn iter(&self) -> impl Iterator<Item = u64> + Clone + '_ {
        self.buf.iter().copied()
    }

    /// Number of entries in the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

fn clamp_usize(value: usize, min_value: usize, max_value: usize) -> usize {
    if value < min_value {
        return min_value;
    }
    if value > max_value {
        return max_value;
    }
    value
}

fn ceil_usize(value: f64) -> usize {
    if !value.is_finite() {
        return usize::MAX;
    }
    if value <= 0.0 {
        return 0;
    }
    let max = usize::MAX as f64;
    if value >= max {
        return usize::MAX;
    }
    value.ceil() as usize
}

fn safe_secs(ms: u64) -> f64 {
    let secs = (ms as f64) / 1000.0;
    if secs.is_finite() && secs > 0.0 {
        secs
    } else {
        0.001
    }
}

/// Calculate Poisson quantile using iterative CDF.
///
/// For small mean, this is exact. For large mean, use normal approximation instead.
fn poisson_quantile(mean: f64, p: f64) -> usize {
    if !mean.is_finite() || mean < 0.0 {
        return 0;
    }
    if !p.is_finite() || p <= 0.0 {
        return 0;
    }
    if p >= 1.0 {
        return usize::MAX;
    }
    if mean == 0.0 {
        return 0;
    }

    // Iterative CDF using recurrence:
    // P(X=0)=e^-m, P(X=k+1)=P(X=k)*m/(k+1)
    let mut k: usize = 0;
    let mut pmf = (-mean).exp();
    let mut cdf = pmf;

    // For small mean this converges very fast; protect against numerical edge cases.
    while cdf < p && k < 100_000 {
        k += 1;
        pmf *= mean / (k as f64);
        cdf += pmf;
        if pmf == 0.0 {
            break;
        }
    }
    k
}

/// Calculate required capacity for given QPS and setup latency.
fn cap_for_qps(qps: f64, setup_secs: f64, cfg: &PredictorConfig) -> usize {
    if !qps.is_finite() || qps <= 0.0 {
        return cfg.min_cap;
    }

    let m = qps * setup_secs;
    let m = if m.is_finite() && m > 0.0 { m } else { 0.0 };

    // Poisson 99th percentile:
    // - exact quantile when mean is small
    // - normal approximation when mean is large
    const P_TARGET: f64 = 0.99;
    const EXACT_MEAN_MAX: f64 = 64.0;

    let k99 = if m <= EXACT_MEAN_MAX {
        poisson_quantile(m, P_TARGET) as f64
    } else {
        // Normal approximation with continuity correction.
        (m + cfg.p99_z * m.sqrt() + 0.5).ceil()
    };

    let cap = (k99 * cfg.headroom).ceil();
    let cap = ceil_usize(cap);

    let min_cap = cfg.min_cap;
    let max_cap = cfg.max_cap.max(min_cap);
    clamp_usize(cap, min_cap, max_cap)
}

/// Predict pool capacity from an iterator of timestamps (stateless, O(n)).
///
/// This is the preferred method when using `TimestampRingBuffer` - use `rb.iter()` directly.
///
/// # Arguments
/// - `timestamps_ms`: Iterator of request timestamps in milliseconds
/// - `now_ms`: Current time in milliseconds
/// - `setup_latency_ms`: Connection setup latency (TLS handshake, etc.)
/// - `available`: Currently available (idle) connections
/// - `warming`: Connections currently being warmed up
/// - `cfg`: Predictor configuration
pub fn predict_pool_iter<I>(
    timestamps_ms: I,
    now_ms: u64,
    setup_latency_ms: u64,
    available: usize,
    warming: usize,
    cfg: &PredictorConfig,
) -> Prediction
where
    I: Clone + Iterator<Item = u64>,
{
    let mut min_ts: Option<u64> = None;
    for ts in timestamps_ms.clone() {
        min_ts = Some(min_ts.map_or(ts, |m| m.min(ts)));
    }

    let span_secs = min_ts
        .map(|min_ts| (now_ms.saturating_sub(min_ts) as f64) / 1000.0)
        .filter(|s| s.is_finite() && *s > 0.0);

    let mut tau_fast = if cfg.tau_fast_secs.is_finite() && cfg.tau_fast_secs > 0.0 {
        cfg.tau_fast_secs
    } else {
        1.0
    };
    let mut tau_slow = if cfg.tau_slow_secs.is_finite() && cfg.tau_slow_secs > 0.0 {
        cfg.tau_slow_secs
    } else {
        10.0
    };

    if let Some(span_secs) = span_secs {
        tau_fast = tau_fast.min(span_secs).max(0.001);
        tau_slow = tau_slow.min(span_secs).max(tau_fast);
    }

    let setup_secs = safe_secs(setup_latency_ms);

    let burst_window_secs = {
        let w = if cfg.burst_window_secs.is_finite() && cfg.burst_window_secs > 0.0 {
            cfg.burst_window_secs
        } else {
            0.5
        };
        let w = w.max(setup_secs).min(2.0);
        if let Some(span_secs) = span_secs {
            w.min(span_secs.max(setup_secs))
        } else {
            w
        }
    };

    let burst_window_ms = (burst_window_secs * 1000.0).round();
    let burst_window_ms = if burst_window_ms.is_finite() && burst_window_ms > 0.0 {
        burst_window_ms as u64
    } else {
        0
    };

    let mut sum_fast = 0.0_f64;
    let mut sum_slow = 0.0_f64;
    let mut burst_count: u64 = 0;

    for ts in timestamps_ms.clone() {
        let age_ms = now_ms.saturating_sub(ts);
        let age_secs = (age_ms as f64) / 1000.0;

        sum_fast += (-age_secs / tau_fast).exp();
        sum_slow += (-age_secs / tau_slow).exp();

        if age_ms <= burst_window_ms {
            burst_count += 1;
        }
    }

    let qps_fast = sum_fast / tau_fast;
    let qps_slow = sum_slow / tau_slow;
    let qps_burst = (burst_count as f64) / burst_window_secs;

    let qps_up = qps_fast.max(qps_burst);

    let cap_fast = cap_for_qps(qps_up, setup_secs, cfg);
    let cap_slow = cap_for_qps(qps_slow, setup_secs, cfg);
    let suggested_cap = cap_fast.max(cap_slow);

    let effective_supply = available.saturating_add(warming);
    let warmup_count = cap_fast.saturating_sub(effective_supply);

    Prediction {
        warmup_count,
        suggested_cap,
        qps_fast,
        qps_slow,
        qps_burst,
    }
}

/// Predict pool capacity from a slice of timestamps (stateless, O(n)).
///
/// # Arguments
/// - `timestamps_ms`: Slice of request timestamps in milliseconds
/// - `now_ms`: Current time in milliseconds (None = use max timestamp)
/// - `setup_latency_ms`: Connection setup latency (TLS handshake, etc.)
/// - `available`: Currently available (idle) connections
/// - `warming`: Connections currently being warmed up
/// - `cfg`: Predictor configuration
pub fn predict_pool(
    timestamps_ms: &[u64],
    now_ms: Option<u64>,
    setup_latency_ms: u64,
    available: usize,
    warming: usize,
    cfg: &PredictorConfig,
) -> Prediction {
    let now_ms = now_ms.unwrap_or_else(|| timestamps_ms.iter().copied().max().unwrap_or(0));
    predict_pool_iter(
        timestamps_ms.iter().copied(),
        now_ms,
        setup_latency_ms,
        available,
        warming,
        cfg,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_prunes_old_entries() {
        let mut rb = TimestampRingBuffer::new(1000, 100); // 1 second window
        rb.push(0);
        rb.push(500);
        rb.push(1500);

        assert_eq!(rb.len(), 2); // 0 should be pruned (> 1000ms from 1500)
    }

    #[test]
    fn ring_buffer_respects_max_len() {
        let mut rb = TimestampRingBuffer::new(10_000, 5);
        for i in 0..10 {
            rb.push(i * 100);
        }
        assert_eq!(rb.len(), 5);
    }

    #[test]
    fn prediction_with_empty_buffer() {
        let cfg = PredictorConfig::default();
        let rb = TimestampRingBuffer::new(10_000, 1000);
        let pred = predict_pool_iter(rb.iter(), 1000, 50, 0, 0, &cfg);

        assert_eq!(pred.warmup_count, cfg.min_cap);
        assert_eq!(pred.suggested_cap, cfg.min_cap);
    }

    #[test]
    fn prediction_scales_with_qps() {
        let cfg = PredictorConfig::default();
        let mut rb = TimestampRingBuffer::new(10_000, 10000);

        // Simulate 100 QPS for 1 second
        let now = 10_000u64;
        for i in 0..100 {
            rb.push(now - 1000 + i * 10);
        }

        let pred = predict_pool_iter(rb.iter(), now, 50, 0, 0, &cfg);

        // Should suggest more than min_cap for 100 QPS
        assert!(pred.suggested_cap > cfg.min_cap);
        assert!(pred.qps_fast > 50.0); // Should detect high QPS
    }

    #[test]
    fn poisson_quantile_basic() {
        // For mean=0, quantile should be 0
        assert_eq!(poisson_quantile(0.0, 0.99), 0);

        // For mean=1, p99 should be around 4-5
        let q = poisson_quantile(1.0, 0.99);
        assert!(q >= 3 && q <= 6, "q = {}", q);

        // For mean=10, p99 should be around 17-18
        let q = poisson_quantile(10.0, 0.99);
        assert!(q >= 15 && q <= 20, "q = {}", q);
    }
}
