//! Health Check System
//!
//! To be fully implemented in Phase 3.

use crate::outbound::OutboundProxy;
use crate::proxy::ExpectedStatus;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};

/// Health check configuration and state
pub struct HealthCheck {
    url: String,
    interval: Duration,
    lazy: bool,
    expected_status: ExpectedStatus,
    proxies: RwLock<Vec<Arc<dyn OutboundProxy>>>,
    last_touch: AtomicU64,
    running: AtomicBool,
    shutdown: broadcast::Sender<()>,
}

impl HealthCheck {
    pub fn new(
        url: String,
        interval: Duration,
        lazy: bool,
        expected_status: ExpectedStatus,
    ) -> Self {
        let (shutdown, _) = broadcast::channel(1);

        HealthCheck {
            url,
            interval,
            lazy,
            expected_status,
            proxies: RwLock::new(Vec::new()),
            last_touch: AtomicU64::new(0),
            running: AtomicBool::new(false),
            shutdown,
        }
    }

    /// Get health check URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Check if auto health check is enabled
    pub fn is_auto(&self) -> bool {
        self.interval > Duration::ZERO
    }

    /// Set proxies to check
    /// Set proxies to check (async)
    pub async fn set_proxies_async(&self, proxies: Vec<Arc<dyn OutboundProxy>>) {
        *self.proxies.write().await = proxies;
    }

    /// Set proxies to check (sync - deprecated)
    pub fn set_proxies(&self, _proxies: Vec<Arc<dyn OutboundProxy>>) {
        // Deprecated: use set_proxies_async instead
    }

    /// Run health check for all proxies
    pub async fn check(&self) {
        let proxies = self.proxies.read().await.clone();

        let futures: Vec<_> = proxies
            .iter()
            .map(|proxy| {
                let url = self.url.clone();
                let expected = self.expected_status.clone();
                let proxy = proxy.clone();

                async move {
                    // TODO: Implement actual URL test
                    let start = std::time::Instant::now();
                    // let result = proxy.url_test(&url, Some(&expected)).await;
                    let elapsed = start.elapsed();
                    (proxy.name().to_string(), elapsed.as_millis() as u16)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (name, delay) in results {
            tracing::debug!("{}: {}ms", name, delay);
        }
    }

    /// Start background health check loop
    pub async fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let mut shutdown_rx = self.shutdown.subscribe();
        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Check if lazy mode and not touched recently
                    if self.lazy {
                        let last = self.last_touch.load(Ordering::Relaxed);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        if now - last > self.interval.as_secs() * 2 {
                            continue; // Skip check if not touched
                        }
                    }

                    self.check().await;
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
    }

    /// Touch to mark as recently used
    pub fn touch(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_touch.store(now, Ordering::Relaxed);
    }

    /// Close health check
    pub fn close(&self) {
        let _ = self.shutdown.send(());
    }
}
