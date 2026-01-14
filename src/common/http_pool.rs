//! HTTP Proxy Connection Pool
//!
//! Pools connections to target servers through upstream proxies.
//! This significantly reduces latency for HTTP proxy (non-CONNECT) requests
//! by reusing established connections instead of creating new ones per request.

use crate::outbound::ProxyConnection;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Default maximum connections per target
const DEFAULT_MAX_CONNS_PER_TARGET: usize = 8;

/// Default connection idle timeout (seconds)
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// Key for pooled connections: (host, port, proxy_name)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
    pub proxy_name: String,
}

impl PoolKey {
    pub fn new(host: String, port: u16, proxy_name: String) -> Self {
        Self { host, port, proxy_name }
    }
}

/// A pooled connection with creation timestamp
struct PooledConnection {
    conn: Box<dyn ProxyConnection>,
    created_at: Instant,
    last_used: Instant,
}

impl PooledConnection {
    fn new(conn: Box<dyn ProxyConnection>) -> Self {
        let now = Instant::now();
        Self {
            conn,
            created_at: now,
            last_used: now,
        }
    }

    fn is_stale(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// HTTP Proxy Connection Pool
///
/// Maintains pools of connections to target servers, keyed by (host, port, proxy_name).
/// Connections are reused across multiple HTTP requests to reduce latency.
pub struct HttpConnectionPool {
    /// Pooled connections by key
    pools: Mutex<HashMap<PoolKey, Vec<PooledConnection>>>,
    /// Maximum connections per target
    max_conns_per_target: usize,
    /// Connection idle timeout
    idle_timeout: Duration,
    /// Statistics: connections acquired from pool
    hits: AtomicU64,
    /// Statistics: connections created new
    misses: AtomicU64,
    /// Statistics: connections returned to pool
    returns: AtomicU64,
}

impl HttpConnectionPool {
    /// Create a new connection pool with default settings
    pub fn new() -> Self {
        Self::with_config(DEFAULT_MAX_CONNS_PER_TARGET, DEFAULT_IDLE_TIMEOUT_SECS)
    }

    /// Create a new connection pool with custom settings
    pub fn with_config(max_conns_per_target: usize, idle_timeout_secs: u64) -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
            max_conns_per_target,
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            returns: AtomicU64::new(0),
        }
    }

    /// Try to acquire a pooled connection for the given key
    /// Returns None if no suitable connection is available
    pub fn acquire(&self, key: &PoolKey) -> Option<Box<dyn ProxyConnection>> {
        let mut pools = self.pools.lock();

        if let Some(pool) = pools.get_mut(key) {
            // Remove stale connections from the end
            while let Some(conn) = pool.last() {
                if conn.is_stale(self.idle_timeout) {
                    pool.pop();
                    trace!("Removed stale connection for {}:{}", key.host, key.port);
                } else {
                    break;
                }
            }

            // Try to get a valid connection
            if let Some(mut pooled) = pool.pop() {
                pooled.touch();
                self.hits.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "Pool hit for {}:{} via {} (pool size: {})",
                    key.host, key.port, key.proxy_name, pool.len()
                );
                return Some(pooled.conn);
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Return a connection to the pool for reuse
    ///
    /// The connection should still be valid (not closed, no errors).
    /// If the pool for this key is full, the connection is dropped.
    pub fn release(&self, key: PoolKey, conn: Box<dyn ProxyConnection>) {
        let mut pools = self.pools.lock();

        let pool = pools.entry(key.clone()).or_insert_with(Vec::new);

        // Clean up stale connections first
        pool.retain(|c| !c.is_stale(self.idle_timeout));

        // Add if under limit
        if pool.len() < self.max_conns_per_target {
            pool.push(PooledConnection::new(conn));
            self.returns.fetch_add(1, Ordering::Relaxed);
            debug!(
                "Returned connection to pool for {}:{} (pool size: {})",
                key.host, key.port, pool.len()
            );
        } else {
            trace!(
                "Pool full for {}:{}, dropping connection",
                key.host, key.port
            );
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.returns.load(Ordering::Relaxed),
        )
    }

    /// Clean up all stale connections across all pools
    pub fn cleanup(&self) {
        let mut pools = self.pools.lock();
        let mut removed = 0;

        for pool in pools.values_mut() {
            let before = pool.len();
            pool.retain(|c| !c.is_stale(self.idle_timeout));
            removed += before - pool.len();
        }

        // Remove empty pools
        pools.retain(|_, pool| !pool.is_empty());

        if removed > 0 {
            debug!("Cleaned up {} stale connections", removed);
        }
    }

    /// Get total number of pooled connections
    pub fn size(&self) -> usize {
        self.pools.lock().values().map(|p| p.len()).sum()
    }
}

impl Default for HttpConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Global HTTP connection pool instance
static HTTP_POOL: std::sync::OnceLock<HttpConnectionPool> = std::sync::OnceLock::new();

/// Get the global HTTP connection pool
pub fn get_http_pool() -> &'static HttpConnectionPool {
    HTTP_POOL.get_or_init(HttpConnectionPool::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_key() {
        let key1 = PoolKey::new("example.com".to_string(), 80, "DIRECT".to_string());
        let key2 = PoolKey::new("example.com".to_string(), 80, "DIRECT".to_string());
        let key3 = PoolKey::new("example.com".to_string(), 443, "DIRECT".to_string());

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
