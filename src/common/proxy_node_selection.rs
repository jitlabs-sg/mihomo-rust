//! Proxy node selection (Weighted P2C + slow-start + circuit breaker).
//!
//! This module implements a sophisticated load balancing algorithm that combines:
//! - **Weighted P2C (Power-of-Two-Choices)**: Pick two random nodes, choose the better one
//! - **Slow Start**: New nodes gradually ramp up traffic over a warmup period
//! - **Circuit Breaker**: Automatically exclude failing nodes with exponential backoff
//!
//! # Typical Usage
//! ```ignore
//! use crate::common::proxy_node_selection::*;
//!
//! let cfg = SelectorConfig::default();
//! let mut nodes = vec![
//!     Node::new(metrics_a, Instant::now()),
//!     Node::new(metrics_b, Instant::now()),
//! ];
//! let mut rng = SplitMix64::new(seed);
//!
//! // Select a node
//! if let Some(idx) = pick_node_index(&mut nodes, Instant::now(), &mut rng, &cfg) {
//!     // Use nodes[idx]
//!     let success = do_request(&nodes[idx]).await;
//!     record_result(&mut nodes[idx], Instant::now(), success, &cfg);
//! }
//! ```

use std::time::{Duration, Instant};

/// Metrics for a single proxy node.
#[derive(Debug, Clone)]
pub struct NodeMetrics {
    /// Median latency in milliseconds.
    pub latency_p50_ms: f64,
    /// 99th percentile latency in milliseconds.
    pub latency_p99_ms: f64,
    /// Success rate (0.0 to 1.0), ideally computed with EWMA.
    pub success_rate: f64,
    /// Current number of active connections.
    pub current_connections: u32,
    /// Maximum connection capacity.
    pub capacity: u32,
    /// Optional cost factor (0.0 if unused).
    pub cost: f64,
}

/// Circuit breaker state machine.
#[derive(Debug, Clone, Copy)]
pub enum BreakerState {
    /// Normal operation - node accepts all traffic.
    Closed,
    /// Node is excluded from selection until `until` expires.
    Open { until: Instant },
    /// Node accepts limited probe traffic to test recovery.
    HalfOpen {
        next_probe_at: Instant,
        in_flight_probes: u32,
    },
}

/// Per-node state for selection algorithm.
#[derive(Debug, Clone, Copy)]
pub struct NodeState {
    /// When this node was added (for slow start calculation).
    pub added_at: Instant,
    /// Count of consecutive failures.
    pub consecutive_failures: u32,
    /// Number of times breaker has been opened (for exponential backoff).
    pub open_retries: u32,
    /// Current circuit breaker state.
    pub breaker: BreakerState,
}

/// Complete node representation with metrics and state.
#[derive(Debug, Clone)]
pub struct Node {
    pub metrics: NodeMetrics,
    pub state: NodeState,
}

impl Node {
    /// Create a new node with initial metrics.
    pub fn new(metrics: NodeMetrics, now: Instant) -> Self {
        Self {
            metrics,
            state: NodeState {
                added_at: now,
                consecutive_failures: 0,
                open_retries: 0,
                breaker: BreakerState::Closed,
            },
        }
    }
}

/// Configuration for the node selector.
#[derive(Debug, Clone)]
pub struct SelectorConfig {
    // Score weights
    /// Weight for tail latency (p99 - p50) in score calculation.
    pub w_tail: f64,
    /// Weight for load factor in score calculation.
    pub w_load: f64,
    /// Exponent for load factor (higher = more aggressive load avoidance).
    pub beta: f64,
    /// Weight for failure rate in score calculation.
    pub w_fail: f64,
    /// Weight for cost factor in score calculation.
    pub w_cost: f64,

    // Slow start / weight mapping
    /// Duration for new nodes to reach full weight.
    pub warmup: Duration,
    /// Minimum weight factor during slow start (e.g., 0.05 = 5%).
    pub slow_start_min_factor: f64,
    /// Epsilon for score normalization (prevents division by zero).
    pub eps: f64,
    /// Power for weight calculation from score.
    pub weight_power: f64,
    /// Minimum health factor for weight calculation.
    pub min_health: f64,

    // Half-open probing
    /// Maximum weight for half-open nodes.
    pub half_open_weight_cap: f64,
    /// Maximum concurrent probes to half-open node.
    pub half_open_max_in_flight: u32,
    /// Interval between probe attempts.
    pub half_open_probe_interval: Duration,

    // Breaker rules
    /// Consecutive failures to trigger open state.
    pub failure_threshold: u32,
    /// Minimum success rate to stay closed.
    pub success_rate_min: f64,
    /// Base duration for open state.
    pub open_base: Duration,
    /// Maximum duration for open state (with backoff).
    pub open_max: Duration,
}

impl Default for SelectorConfig {
    fn default() -> Self {
        Self {
            w_tail: 1.0,
            w_load: 1.0,
            beta: 2.0,
            w_fail: 5.0,
            w_cost: 0.0,

            warmup: Duration::from_secs(300),
            slow_start_min_factor: 0.05,
            eps: 1.0,
            weight_power: 1.0,
            min_health: 0.05,

            half_open_weight_cap: 1.0,
            half_open_max_in_flight: 1,
            half_open_probe_interval: Duration::from_millis(1000),

            failure_threshold: 3,
            success_rate_min: 0.7,
            open_base: Duration::from_secs(5),
            open_max: Duration::from_secs(300),
        }
    }
}

/// Trait for random number generation.
pub trait RandomSource {
    fn next_u64(&mut self) -> u64;

    fn next_f64_0_1(&mut self) -> f64 {
        // 53-bit precision, [0,1)
        let v = self.next_u64() >> 11;
        (v as f64) * (1.0 / ((1u64 << 53) as f64))
    }
}

/// SplitMix64 PRNG - fast, good quality, no external dependencies.
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Create from current time (for quick seeding).
    pub fn from_time() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x12345678);
        Self::new(seed)
    }
}

impl RandomSource for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        // splitmix64 reference implementation
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

fn clamp_f64(v: f64, lo: f64, hi: f64) -> f64 {
    v.max(lo).min(hi)
}

fn backoff_duration(base: Duration, max: Duration, retries: u32) -> Duration {
    let factor = 1u128 << retries.min(32);
    let ms = base.as_millis().saturating_mul(factor).min(max.as_millis());
    Duration::from_millis(ms as u64)
}

fn refresh_breaker(state: &mut NodeState, now: Instant) {
    if let BreakerState::Open { until } = state.breaker {
        if now >= until {
            state.breaker = BreakerState::HalfOpen {
                next_probe_at: now,
                in_flight_probes: 0,
            };
        }
    }
}

/// Compute score for a node (lower is better).
///
/// Score formula: `p50 + w_tail*(p99-p50) + w_load*load^beta*p50 + w_fail*fail*p50 + w_cost*cost`
pub fn compute_score(m: &NodeMetrics, cfg: &SelectorConfig) -> f64 {
    if m.capacity == 0 {
        return f64::INFINITY;
    }

    let p50 = m.latency_p50_ms.max(0.0);
    let p99 = m.latency_p99_ms.max(p50);
    let tail = (p99 - p50).max(0.0);
    let load = (m.current_connections as f64) / (m.capacity as f64);
    let success_rate = clamp_f64(m.success_rate, 0.0, 1.0);
    let fail = 1.0 - success_rate;
    let cost = m.cost.max(0.0);

    p50 + cfg.w_tail * tail
        + cfg.w_load * load.powf(cfg.beta) * p50
        + cfg.w_fail * fail * p50
        + cfg.w_cost * cost
}

fn slow_start_factor(added_at: Instant, now: Instant, warmup: Duration) -> f64 {
    if warmup.is_zero() {
        return 1.0;
    }
    let elapsed = now
        .checked_duration_since(added_at)
        .unwrap_or(Duration::ZERO);
    clamp_f64(elapsed.as_secs_f64() / warmup.as_secs_f64(), 0.0, 1.0)
}

fn compute_weight(node: &Node, score: f64, now: Instant, cfg: &SelectorConfig) -> f64 {
    if node.metrics.capacity == 0 || !score.is_finite() {
        return 0.0;
    }

    match node.state.breaker {
        BreakerState::Open { until } if now < until => return 0.0,
        BreakerState::HalfOpen {
            next_probe_at,
            in_flight_probes,
        } => {
            if now < next_probe_at {
                return 0.0;
            }
            if in_flight_probes >= cfg.half_open_max_in_flight {
                return 0.0;
            }
        }
        _ => {}
    }

    let slow = slow_start_factor(node.state.added_at, now, cfg.warmup)
        .max(clamp_f64(cfg.slow_start_min_factor, 0.0, 1.0));
    let success_rate = clamp_f64(node.metrics.success_rate, 0.0, 1.0);
    let health = success_rate.max(cfg.min_health);

    let denom = (score + cfg.eps).max(1e-9);
    let mut weight = (node.metrics.capacity as f64) * slow * health / denom.powf(cfg.weight_power);

    if !weight.is_finite() || weight <= 0.0 {
        return 0.0;
    }

    if matches!(node.state.breaker, BreakerState::HalfOpen { .. }) {
        weight = weight.min(cfg.half_open_weight_cap.max(0.0));
    }

    weight
}

fn weighted_random_index(weights: &[f64], rng01: &mut impl FnMut() -> f64) -> Option<usize> {
    let mut sum = 0.0;
    for &w in weights {
        if w.is_finite() && w > 0.0 {
            sum += w;
        }
    }
    if !(sum.is_finite()) || sum <= 0.0 {
        return None;
    }

    let r = clamp_f64(rng01(), 0.0, 0.999_999_999_999) * sum;
    let mut acc = 0.0;
    for (i, &w) in weights.iter().enumerate() {
        if w.is_finite() && w > 0.0 {
            acc += w;
            if r < acc {
                return Some(i);
            }
        }
    }

    weights
        .iter()
        .rposition(|w| w.is_finite() && *w > 0.0)
}

fn better_of_two(a: usize, b: usize, scores: &[f64], nodes: &[Node]) -> usize {
    let sa = scores[a];
    let sb = scores[b];

    match (sa.is_finite(), sb.is_finite()) {
        (true, false) => return a,
        (false, true) => return b,
        _ => {}
    }

    if sa < sb {
        return a;
    }
    if sb < sa {
        return b;
    }

    // tie-break: fewer connections
    let ca = nodes[a].metrics.current_connections;
    let cb = nodes[b].metrics.current_connections;
    if ca <= cb { a } else { b }
}

/// Pick a node index using Weighted P2C (Power-of-Two-Choices).
///
/// # Side Effects
/// - Transitions `Open -> HalfOpen` when `until` elapses.
/// - If a `HalfOpen` node is selected, increments `in_flight_probes` and
///   sets `next_probe_at = now + probe_interval`.
///
/// Call `record_result(..)` after the request finishes to update state.
pub fn pick_node_index(
    nodes: &mut [Node],
    now: Instant,
    rng: &mut impl RandomSource,
    cfg: &SelectorConfig,
) -> Option<usize> {
    for node in nodes.iter_mut() {
        refresh_breaker(&mut node.state, now);
    }

    let mut scores = Vec::with_capacity(nodes.len());
    let mut weights = Vec::with_capacity(nodes.len());
    let mut candidate_count = 0usize;

    for node in nodes.iter() {
        let score = compute_score(&node.metrics, cfg);
        let weight = compute_weight(node, score, now, cfg);
        if weight > 0.0 {
            candidate_count += 1;
        }
        scores.push(score);
        weights.push(weight);
    }

    if candidate_count == 0 {
        return None;
    }

    let mut rng01 = || rng.next_f64_0_1();

    let chosen = if candidate_count == 1 {
        weights
            .iter()
            .position(|w| w.is_finite() && *w > 0.0)?
    } else {
        let a = weighted_random_index(&weights, &mut rng01)?;
        let mut b = weighted_random_index(&weights, &mut rng01)?;

        if b == a {
            for _ in 0..2 {
                if let Some(i) = weighted_random_index(&weights, &mut rng01) {
                    b = i;
                    if b != a {
                        break;
                    }
                }
            }
        }

        better_of_two(a, b, &scores, nodes)
    };

    if let BreakerState::HalfOpen {
        ref mut next_probe_at,
        ref mut in_flight_probes,
    } = nodes[chosen].state.breaker
    {
        *in_flight_probes = in_flight_probes.saturating_add(1);
        *next_probe_at = now + cfg.half_open_probe_interval;
    }

    Some(chosen)
}

fn open_breaker(state: &mut NodeState, now: Instant, cfg: &SelectorConfig) {
    let retries = state.open_retries.saturating_add(1);
    state.open_retries = retries;
    let open_for = backoff_duration(cfg.open_base, cfg.open_max, retries.saturating_sub(1));
    state.breaker = BreakerState::Open { until: now + open_for };
}

/// Record request outcome for a node selected by `pick_node_index(..)`.
///
/// # State Transitions
/// - **Success in HalfOpen**: Closes breaker, resets warmup (`added_at = now`)
/// - **Failure in HalfOpen**: Opens breaker immediately (with backoff)
/// - **Failure in Closed**: Opens when `consecutive_failures >= failure_threshold`
///   or `success_rate < success_rate_min`
pub fn record_result(node: &mut Node, now: Instant, success: bool, cfg: &SelectorConfig) {
    // Release probe slot if we were half-open.
    if let BreakerState::HalfOpen {
        in_flight_probes, ..
    } = &mut node.state.breaker
    {
        if *in_flight_probes > 0 {
            *in_flight_probes -= 1;
        }
    }

    if success {
        node.state.consecutive_failures = 0;
        if matches!(node.state.breaker, BreakerState::HalfOpen { .. }) {
            node.state.breaker = BreakerState::Closed;
            node.state.open_retries = 0;
            node.state.added_at = now;
        }
        return;
    }

    node.state.consecutive_failures = node.state.consecutive_failures.saturating_add(1);
    let success_rate = clamp_f64(node.metrics.success_rate, 0.0, 1.0);

    let half_open = matches!(node.state.breaker, BreakerState::HalfOpen { .. });
    let should_open = half_open
        || node.state.consecutive_failures >= cfg.failure_threshold
        || success_rate < cfg.success_rate_min;

    if should_open {
        open_breaker(&mut node.state, now, cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(capacity: u32, p50: f64, p99: f64, sr: f64, conns: u32) -> NodeMetrics {
        NodeMetrics {
            latency_p50_ms: p50,
            latency_p99_ms: p99,
            success_rate: sr,
            current_connections: conns,
            capacity,
            cost: 0.0,
        }
    }

    #[test]
    fn excludes_open_nodes() {
        let now = Instant::now();
        let mut nodes = vec![
            Node::new(m(100, 10.0, 20.0, 1.0, 0), now),
            Node::new(m(100, 10.0, 20.0, 1.0, 0), now),
        ];
        nodes[0].state.breaker = BreakerState::Open {
            until: now + Duration::from_secs(60),
        };

        let mut rng = SplitMix64::new(1);
        let cfg = SelectorConfig::default();
        let picked = pick_node_index(&mut nodes, now, &mut rng, &cfg).unwrap();
        assert_eq!(picked, 1);
    }

    #[test]
    fn half_open_consumes_and_releases_probe() {
        let now = Instant::now();
        let mut node = Node::new(m(100, 10.0, 20.0, 1.0, 0), now);
        node.state.breaker = BreakerState::HalfOpen {
            next_probe_at: now,
            in_flight_probes: 0,
        };

        let mut nodes = vec![node];
        let mut rng = SplitMix64::new(42);
        let cfg = SelectorConfig::default();

        let idx = pick_node_index(&mut nodes, now, &mut rng, &cfg).unwrap();
        assert_eq!(idx, 0);
        match nodes[0].state.breaker {
            BreakerState::HalfOpen {
                in_flight_probes, ..
            } => assert_eq!(in_flight_probes, 1),
            _ => panic!("expected half-open"),
        }

        record_result(&mut nodes[0], now, true, &cfg);
        assert!(matches!(nodes[0].state.breaker, BreakerState::Closed));
    }

    #[test]
    fn consecutive_failures_open_breaker() {
        let now = Instant::now();
        let mut node = Node::new(m(100, 10.0, 20.0, 1.0, 0), now);
        let cfg = SelectorConfig {
            failure_threshold: 3,
            ..Default::default()
        };

        // First two failures don't open
        record_result(&mut node, now, false, &cfg);
        record_result(&mut node, now, false, &cfg);
        assert!(matches!(node.state.breaker, BreakerState::Closed));

        // Third failure opens
        record_result(&mut node, now, false, &cfg);
        assert!(matches!(node.state.breaker, BreakerState::Open { .. }));
    }

    #[test]
    fn score_prefers_lower_latency() {
        let cfg = SelectorConfig::default();
        let fast = m(100, 10.0, 15.0, 1.0, 0);
        let slow = m(100, 50.0, 60.0, 1.0, 0);

        assert!(compute_score(&fast, &cfg) < compute_score(&slow, &cfg));
    }

    #[test]
    fn score_penalizes_high_load() {
        let cfg = SelectorConfig::default();
        let empty = m(100, 10.0, 15.0, 1.0, 0);
        let loaded = m(100, 10.0, 15.0, 1.0, 90);

        assert!(compute_score(&empty, &cfg) < compute_score(&loaded, &cfg));
    }

    #[test]
    fn splitmix64_produces_different_values() {
        let mut rng = SplitMix64::new(12345);
        let a = rng.next_u64();
        let b = rng.next_u64();
        let c = rng.next_u64();

        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
