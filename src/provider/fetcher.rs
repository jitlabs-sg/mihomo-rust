//! HTTP Fetcher with auto-update
//!
//! To be fully implemented in Phase 3.

use crate::{Error, Result};
use std::path::PathBuf;
use std::time::Duration;

/// HTTP fetcher with caching and auto-update
pub struct Fetcher {
    url: String,
    path: PathBuf,
    interval: Duration,
}

impl Fetcher {
    pub fn new(url: String, path: PathBuf, interval: Duration) -> Self {
        Fetcher { url, path, interval }
    }

    /// Get update interval
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Fetch content from URL
    pub async fn fetch(&self) -> Result<(Vec<u8>, reqwest::header::HeaderMap)> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::network(e.to_string()))?;

        let resp = client.get(&self.url)
            .send()
            .await
            .map_err(|e| Error::network(e.to_string()))?;

        let headers = resp.headers().clone();
        let content = resp.bytes()
            .await
            .map_err(|e| Error::network(e.to_string()))?;

        // Save to cache
        if let Err(e) = tokio::fs::write(&self.path, &content).await {
            tracing::warn!("Failed to cache content: {}", e);
        }

        Ok((content.to_vec(), headers))
    }

    /// Load content from cache
    pub async fn load_cache(&self) -> Result<Vec<u8>> {
        tokio::fs::read(&self.path)
            .await
            .map_err(|e| Error::io_error(e.to_string()))
    }
}
