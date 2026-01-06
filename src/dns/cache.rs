//! DNS cache implementation

use lru::LruCache;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// DNS cache entry
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// Resolved IP addresses
    pub ips: Vec<IpAddr>,
    /// Entry creation time
    pub created: Instant,
    /// Time-to-live
    pub ttl: Duration,
}

impl CacheEntry {
    pub fn new(ips: Vec<IpAddr>, ttl: Duration) -> Self {
        CacheEntry {
            ips,
            created: Instant::now(),
            ttl,
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > self.ttl
    }

    /// Get first IP address
    pub fn first_ip(&self) -> Option<IpAddr> {
        self.ips.first().copied()
    }

    /// Get all IP addresses
    pub fn all_ips(&self) -> &[IpAddr] {
        &self.ips
    }
}

/// DNS cache with LRU eviction
pub struct DnsCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    max_size: usize,
    default_ttl: Duration,
}

impl DnsCache {
    /// Create new DNS cache
    pub fn new(max_size: usize) -> Self {
        DnsCache {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(max_size).unwrap_or(NonZeroUsize::new(1024).unwrap()),
            )),
            max_size,
            default_ttl: Duration::from_secs(300), // 5 minutes default
        }
    }

    /// Create with custom default TTL
    pub fn with_ttl(max_size: usize, default_ttl: Duration) -> Self {
        DnsCache {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(max_size).unwrap_or(NonZeroUsize::new(1024).unwrap()),
            )),
            max_size,
            default_ttl,
        }
    }

    /// Get entry from cache
    pub fn get(&self, domain: &str) -> Option<CacheEntry> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(domain) {
            if !entry.is_expired() {
                return Some(entry.clone());
            }
            // Entry expired, remove it
            cache.pop(domain);
        }
        None
    }

    /// Put entry into cache
    pub fn put(&self, domain: String, ips: Vec<IpAddr>) {
        self.put_with_ttl(domain, ips, self.default_ttl);
    }

    /// Put entry with specific TTL
    pub fn put_with_ttl(&self, domain: String, ips: Vec<IpAddr>, ttl: Duration) {
        let entry = CacheEntry::new(ips, ttl);
        let mut cache = self.cache.lock();
        cache.put(domain, entry);
    }

    /// Remove entry from cache
    pub fn remove(&self, domain: &str) {
        let mut cache = self.cache.lock();
        cache.pop(domain);
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut cache = self.cache.lock();
        cache.clear();
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.lock().is_empty()
    }

    /// Clean expired entries
    pub fn clean_expired(&self) {
        let mut cache = self.cache.lock();
        let expired: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            cache.pop(&key);
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(4096)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cache_put_get() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        cache.put("example.com".to_string(), vec![ip]);

        let entry = cache.get("example.com").unwrap();
        assert_eq!(entry.first_ip(), Some(ip));
    }

    #[test]
    fn test_cache_expiry() {
        let cache = DnsCache::with_ttl(100, Duration::from_millis(10));
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        cache.put("example.com".to_string(), vec![ip]);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        cache.put("example.com".to_string(), vec![ip]);
        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
    }
}
