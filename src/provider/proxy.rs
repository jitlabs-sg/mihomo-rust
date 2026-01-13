//! Proxy Provider (HTTP subscription)
//!
//! To be fully implemented in Phase 3.

use super::{Fetcher, HealthCheck, ProxyProvider, ProviderType, SubscriptionInfo, VehicleType};
use crate::outbound::OutboundProxy;
use crate::proxy::ExpectedStatus;
use crate::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Proxy set provider (HTTP subscription)
pub struct ProxySetProvider {
    name: String,
    proxies: RwLock<Vec<Arc<dyn OutboundProxy>>>,
    health_check: Arc<HealthCheck>,
    fetcher: Fetcher,
    subscription_info: RwLock<Option<SubscriptionInfo>>,
    updated_at: RwLock<Option<DateTime<Utc>>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        url: String,
        path: PathBuf,
        interval: Duration,
        health_check_url: String,
        health_check_interval: Duration,
        lazy: bool,
    ) -> Self {
        let fetcher = Fetcher::new(url, path, interval);
        let health_check = Arc::new(HealthCheck::new(
            health_check_url,
            health_check_interval,
            lazy,
            ExpectedStatus::default(),
        ));

        ProxySetProvider {
            name,
            proxies: RwLock::new(Vec::new()),
            health_check,
            fetcher,
            subscription_info: RwLock::new(None),
            updated_at: RwLock::new(None),
        }
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Proxy
    }

    fn vehicle_type(&self) -> VehicleType {
        VehicleType::HTTP
    }

    fn proxies(&self) -> Vec<Arc<dyn OutboundProxy>> {
        // Use blocking read for now (should be async in production)
        Vec::new()
    }

    fn count(&self) -> usize {
        0
    }

    async fn update(&self) -> Result<()> {
        let (_content, headers) = self.fetcher.fetch().await?;

        // Parse subscription info from headers
        if let Some(info_header) = headers.get("subscription-userinfo") {
            if let Ok(header_str) = info_header.to_str() {
                if let Some(info) = SubscriptionInfo::parse(header_str) {
                    *self.subscription_info.write().await = Some(info);
                }
            }
        }

        // TODO: Parse proxies from content
        // let proxies = parse_proxies(&content)?;
        // *self.proxies.write().await = proxies;

        *self.updated_at.write().await = Some(Utc::now());

        Ok(())
    }

    async fn initial(&self) -> Result<()> {
        // Try to load from cache first
        if let Ok(_content) = self.fetcher.load_cache().await {
            // TODO: Parse proxies from cache
        }

        // Start auto-update if configured
        if self.fetcher.interval() > Duration::ZERO {
            // TODO: Start update loop
        }

        // Start health check
        if self.health_check.is_auto() {
            let hc = self.health_check.clone();
            tokio::spawn(async move {
                hc.start().await;
            });
        }

        Ok(())
    }

    async fn health_check(&self) {
        self.health_check.check().await;
    }

    fn touch(&self) {
        self.health_check.touch();
    }

    fn health_check_url(&self) -> &str {
        self.health_check.url()
    }

    fn updated_at(&self) -> Option<DateTime<Utc>> {
        // Would need blocking read or async
        None
    }

    fn subscription_info(&self) -> Option<SubscriptionInfo> {
        // Would need blocking read or different approach
        None
    }

    async fn close(&self) {
        self.health_check.close();
    }
}

/// Inline provider (proxies defined directly in config)
pub struct InlineProvider {
    name: String,
    proxies: Vec<Arc<dyn OutboundProxy>>,
    health_check: Arc<HealthCheck>,
}

impl InlineProvider {
    pub fn new(
        name: String,
        proxies: Vec<Arc<dyn OutboundProxy>>,
        health_check_url: String,
        health_check_interval: Duration,
        lazy: bool,
    ) -> Self {
        let health_check = Arc::new(HealthCheck::new(
            health_check_url,
            health_check_interval,
            lazy,
            ExpectedStatus::default(),
        ));

        InlineProvider {
            name,
            proxies,
            health_check,
        }
    }
}

#[async_trait]
impl ProxyProvider for InlineProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Proxy
    }

    fn vehicle_type(&self) -> VehicleType {
        VehicleType::Inline
    }

    fn proxies(&self) -> Vec<Arc<dyn OutboundProxy>> {
        self.proxies.clone()
    }

    fn count(&self) -> usize {
        self.proxies.len()
    }

    async fn update(&self) -> Result<()> {
        // Inline providers do not update
        Ok(())
    }

    async fn initial(&self) -> Result<()> {
        if self.health_check.is_auto() {
            let hc = self.health_check.clone();
            tokio::spawn(async move {
                hc.start().await;
            });
        }
        Ok(())
    }

    async fn health_check(&self) {
        self.health_check.check().await;
    }

    fn touch(&self) {
        self.health_check.touch();
    }

    fn health_check_url(&self) -> &str {
        self.health_check.url()
    }

    fn updated_at(&self) -> Option<DateTime<Utc>> {
        None
    }

    fn subscription_info(&self) -> Option<SubscriptionInfo> {
        None
    }

    async fn close(&self) {
        self.health_check.close();
    }
}
