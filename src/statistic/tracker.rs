//! Connection tracker implementation

use super::{ConnectionInfo, ConnectionMetadata};
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};

/// Tracked connection with statistics
pub struct TrackedConnection {
    /// Unique connection ID
    pub id: String,
    /// Connection metadata
    pub metadata: ConnectionMetadata,
    /// Proxy chain used
    pub chains: Vec<String>,
    /// Matched rule type
    pub rule: String,
    /// Matched rule payload
    pub rule_payload: String,
    /// Start time
    pub start: DateTime<Utc>,
    /// Upload bytes
    upload: AtomicU64,
    /// Download bytes
    download: AtomicU64,
}

impl TrackedConnection {
    /// Create a new tracked connection
    pub fn new(
        id: String,
        metadata: ConnectionMetadata,
        chains: Vec<String>,
        rule: String,
        rule_payload: String,
    ) -> Self {
        TrackedConnection {
            id,
            metadata,
            chains,
            rule,
            rule_payload,
            start: Utc::now(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        }
    }

    /// Add upload bytes
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add download bytes
    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get upload bytes
    pub fn upload(&self) -> u64 {
        self.upload.load(Ordering::Relaxed)
    }

    /// Get download bytes
    pub fn download(&self) -> u64 {
        self.download.load(Ordering::Relaxed)
    }

    /// Convert to API response format
    pub fn to_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            id: self.id.clone(),
            metadata: self.metadata.clone(),
            upload: self.upload(),
            download: self.download(),
            start: self.start,
            chains: self.chains.clone(),
            rule: self.rule.clone(),
            rule_payload: self.rule_payload.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracked_connection() {
        let conn = TrackedConnection::new(
            "test-id".to_string(),
            ConnectionMetadata::default(),
            vec!["proxy1".to_string(), "DIRECT".to_string()],
            "DOMAIN-SUFFIX".to_string(),
            "example.com".to_string(),
        );

        assert_eq!(conn.id, "test-id");
        assert_eq!(conn.upload(), 0);
        assert_eq!(conn.download(), 0);

        conn.add_upload(100);
        conn.add_download(200);

        assert_eq!(conn.upload(), 100);
        assert_eq!(conn.download(), 200);
    }

    #[test]
    fn test_to_info() {
        let conn = TrackedConnection::new(
            "test-id".to_string(),
            ConnectionMetadata::default(),
            vec!["DIRECT".to_string()],
            "MATCH".to_string(),
            String::new(),
        );

        conn.add_upload(100);
        conn.add_download(200);

        let info = conn.to_info();
        assert_eq!(info.id, "test-id");
        assert_eq!(info.upload, 100);
        assert_eq!(info.download, 200);
        assert_eq!(info.chains, vec!["DIRECT"]);
        assert_eq!(info.rule, "MATCH");
    }
}
