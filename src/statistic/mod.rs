//! Connection tracking and traffic statistics
//!
//! Provides real-time statistics for:
//! - Traffic rate (bytes/second)
//! - Active connections
//! - Memory usage

mod tracker;

pub use tracker::TrackedConnection;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Statistics manager for connections and traffic
pub struct StatisticManager {
    /// Active connections (id -> connection)
    connections: DashMap<String, Arc<TrackedConnection>>,
    /// Total upload bytes
    upload_total: AtomicU64,
    /// Total download bytes
    download_total: AtomicU64,
    /// Upload bytes in current second
    upload_temp: AtomicU64,
    /// Download bytes in current second
    download_temp: AtomicU64,
}

impl StatisticManager {
    /// Create a new statistics manager
    pub fn new() -> Self {
        let manager = StatisticManager {
            connections: DashMap::new(),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
        };

        // Start the reset ticker in a separate task
        // This will be done by the caller
        manager
    }

    /// Start the background ticker to reset temp counters
    pub fn start_ticker(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                this.upload_temp.store(0, Ordering::Relaxed);
                this.download_temp.store(0, Ordering::Relaxed);
            }
        });
    }

    /// Get current traffic rate (bytes/second)
    pub fn now(&self) -> (i64, i64) {
        (
            self.upload_temp.load(Ordering::Relaxed) as i64,
            self.download_temp.load(Ordering::Relaxed) as i64,
        )
    }

    /// Get total traffic
    pub fn total(&self) -> (u64, u64) {
        (
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    /// Get memory usage in bytes
    pub fn memory(&self) -> u64 {
        // Try to get accurate memory usage
        #[cfg(feature = "jemalloc")]
        {
            jemalloc_ctl::stats::allocated::read().unwrap_or(0) as u64
        }

        #[cfg(not(feature = "jemalloc"))]
        {
            // Estimate based on connection count and typical sizes
            // Each connection roughly uses ~4KB of memory
            let conn_count = self.connections.len() as u64;
            let base_memory = 50 * 1024 * 1024; // 50MB base
            base_memory + conn_count * 4096
        }
    }

    /// Get snapshot of all connections
    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            download_total: self.download_total.load(Ordering::Relaxed),
            upload_total: self.upload_total.load(Ordering::Relaxed),
            connections: self
                .connections
                .iter()
                .map(|r| r.value().to_info())
                .collect(),
        }
    }

    /// Track a new connection
    pub fn track(&self, conn: TrackedConnection) -> String {
        let id = conn.id.clone();
        self.connections.insert(id.clone(), Arc::new(conn));
        id
    }

    /// Generate a unique connection ID
    pub fn generate_id(&self) -> String {
        Uuid::new_v4().to_string()
    }

    /// Get connection by ID
    pub fn get(&self, id: &str) -> Option<Arc<TrackedConnection>> {
        self.connections.get(id).map(|r| r.value().clone())
    }

    /// Close connection by ID
    pub fn close(&self, id: &str) -> bool {
        self.connections.remove(id).is_some()
    }

    /// Close all connections
    pub fn close_all(&self) -> usize {
        let count = self.connections.len();
        self.connections.clear();
        count
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Add upload bytes
    pub fn add_upload(&self, bytes: u64) {
        self.upload_total.fetch_add(bytes, Ordering::Relaxed);
        self.upload_temp.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add download bytes
    pub fn add_download(&self, bytes: u64) {
        self.download_total.fetch_add(bytes, Ordering::Relaxed);
        self.download_temp.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Default for StatisticManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all connections for API response
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSnapshot {
    /// Total download bytes
    #[serde(rename = "downloadTotal")]
    pub download_total: u64,
    /// Total upload bytes
    #[serde(rename = "uploadTotal")]
    pub upload_total: u64,
    /// List of active connections
    pub connections: Vec<ConnectionInfo>,
}

/// Connection info for API response
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    /// Unique connection ID
    pub id: String,
    /// Connection metadata
    pub metadata: ConnectionMetadata,
    /// Upload bytes for this connection
    pub upload: u64,
    /// Download bytes for this connection
    pub download: u64,
    /// Start time (ISO 8601)
    pub start: DateTime<Utc>,
    /// Proxy chain used
    pub chains: Vec<String>,
    /// Matched rule type
    pub rule: String,
    /// Matched rule payload
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
}

/// Connection metadata for API response
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMetadata {
    /// Network type (tcp/udp)
    pub network: String,
    /// Connection type (HTTP/HTTPS/SOCKS5/etc)
    #[serde(rename = "type")]
    pub conn_type: String,
    /// Source IP address
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    /// Destination IP address
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    /// Source port
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    /// Destination port
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    /// Host name (from SNI or HTTP Host header)
    pub host: String,
    /// DNS mode
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
    /// Process path (if available)
    #[serde(rename = "processPath")]
    pub process_path: String,
    /// Special proxy name
    #[serde(rename = "specialProxy")]
    pub special_proxy: String,
}

impl Default for ConnectionMetadata {
    fn default() -> Self {
        ConnectionMetadata {
            network: "tcp".to_string(),
            conn_type: String::new(),
            source_ip: String::new(),
            destination_ip: String::new(),
            source_port: String::new(),
            destination_port: String::new(),
            host: String::new(),
            dns_mode: "normal".to_string(),
            process_path: String::new(),
            special_proxy: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistic_manager_creation() {
        let manager = StatisticManager::new();
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.now(), (0, 0));
    }

    #[test]
    fn test_add_traffic() {
        let manager = StatisticManager::new();
        manager.add_upload(100);
        manager.add_download(200);

        let (up, down) = manager.now();
        assert_eq!(up, 100);
        assert_eq!(down, 200);

        let (total_up, total_down) = manager.total();
        assert_eq!(total_up, 100);
        assert_eq!(total_down, 200);
    }

    #[test]
    fn test_connection_tracking() {
        let manager = StatisticManager::new();

        let conn = TrackedConnection::new(
            manager.generate_id(),
            ConnectionMetadata::default(),
            vec!["DIRECT".to_string()],
            "MATCH".to_string(),
            String::new(),
        );

        let id = manager.track(conn);
        assert_eq!(manager.connection_count(), 1);

        assert!(manager.get(&id).is_some());
        assert!(manager.close(&id));
        assert_eq!(manager.connection_count(), 0);
    }

    #[test]
    fn test_snapshot() {
        let manager = StatisticManager::new();
        manager.add_upload(100);
        manager.add_download(200);

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.upload_total, 100);
        assert_eq!(snapshot.download_total, 200);
        assert!(snapshot.connections.is_empty());
    }
}
