//! Subscription Providers (Proxy and Rule)
//!
//! This module will be fully implemented in Phase 3.

mod fetcher;
mod healthcheck;
mod proxy;
mod rule;

pub use fetcher::Fetcher;
pub use healthcheck::HealthCheck;
pub use proxy::{ProxySetProvider, InlineProvider};
pub use rule::{RuleProvider, RuleBehavior};

use crate::outbound::OutboundProxy;
use crate::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    Proxy,
    Rule,
}

/// Vehicle type (how data is loaded)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VehicleType {
    HTTP,
    File,
    Inline,
    Compatible,
}

impl std::fmt::Display for VehicleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleType::HTTP => write!(f, "HTTP"),
            VehicleType::File => write!(f, "File"),
            VehicleType::Inline => write!(f, "Inline"),
            VehicleType::Compatible => write!(f, "Compatible"),
        }
    }
}

/// Subscription information parsed from headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    /// Upload bytes used
    pub upload: u64,
    /// Download bytes used
    pub download: u64,
    /// Total bytes available
    pub total: u64,
    /// Expiration timestamp (Unix epoch)
    pub expire: u64,
}

impl SubscriptionInfo {
    /// Parse from Subscription-Userinfo header
    ///
    /// Format: "upload=xxx; download=xxx; total=xxx; expire=xxx"
    pub fn parse(header: &str) -> Option<Self> {
        let mut info = SubscriptionInfo {
            upload: 0,
            download: 0,
            total: 0,
            expire: 0,
        };

        for part in header.split(';') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let value: u64 = value.trim().parse().unwrap_or(0);
                match key.trim().to_lowercase().as_str() {
                    "upload" => info.upload = value,
                    "download" => info.download = value,
                    "total" => info.total = value,
                    "expire" => info.expire = value,
                    _ => {}
                }
            }
        }

        Some(info)
    }
}

/// Trait for proxy providers
#[async_trait]
pub trait ProxyProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;

    /// Provider type
    fn provider_type(&self) -> ProviderType;

    /// Vehicle type (how proxies are loaded)
    fn vehicle_type(&self) -> VehicleType;

    /// Get proxies
    fn proxies(&self) -> Vec<Arc<dyn OutboundProxy>>;

    /// Proxy count
    fn count(&self) -> usize;

    /// Update proxies (fetch from source)
    async fn update(&self) -> Result<()>;

    /// Initial load
    async fn initial(&self) -> Result<()>;

    /// Health check all proxies
    async fn health_check(&self);

    /// Touch (update last access time)
    fn touch(&self);

    /// Get health check URL
    fn health_check_url(&self) -> &str;

    /// Last update time
    fn updated_at(&self) -> Option<DateTime<Utc>>;

    /// Subscription info (for HTTP providers)
    fn subscription_info(&self) -> Option<SubscriptionInfo>;

    /// Close provider
    async fn close(&self);
}

/// Provider manager holding all providers
pub struct ProviderManager {
    /// Proxy providers
    proxy_providers: RwLock<HashMap<String, Arc<dyn ProxyProvider>>>,
    /// Rule providers
    rule_providers: RwLock<HashMap<String, Arc<RuleProvider>>>,
}

impl ProviderManager {
    /// Create new provider manager
    pub fn new() -> Self {
        ProviderManager {
            proxy_providers: RwLock::new(HashMap::new()),
            rule_providers: RwLock::new(HashMap::new()),
        }
    }

    /// Add proxy provider
    pub async fn add_proxy_provider(&self, provider: Arc<dyn ProxyProvider>) {
        let name = provider.name().to_string();
        self.proxy_providers.write().await.insert(name, provider);
    }

    /// Get proxy provider by name
    pub async fn get_proxy_provider(&self, name: &str) -> Option<Arc<dyn ProxyProvider>> {
        self.proxy_providers.read().await.get(name).cloned()
    }

    /// Get all proxy providers
    pub async fn proxy_providers(&self) -> HashMap<String, Arc<dyn ProxyProvider>> {
        self.proxy_providers.read().await.clone()
    }

    /// Add rule provider
    pub async fn add_rule_provider(&self, provider: Arc<RuleProvider>) {
        let name = provider.name().to_string();
        self.rule_providers.write().await.insert(name, provider);
    }

    /// Get rule provider by name
    pub async fn get_rule_provider(&self, name: &str) -> Option<Arc<RuleProvider>> {
        self.rule_providers.read().await.get(name).cloned()
    }

    /// Get all rule providers
    pub async fn rule_providers(&self) -> HashMap<String, Arc<RuleProvider>> {
        self.rule_providers.read().await.clone()
    }

    /// Update all providers
    pub async fn update_all(&self) -> Result<()> {
        for (_, provider) in self.proxy_providers.read().await.iter() {
            if let Err(e) = provider.update().await {
                tracing::warn!("Failed to update proxy provider {}: {}", provider.name(), e);
            }
        }
        for (_, provider) in self.rule_providers.read().await.iter() {
            if let Err(e) = provider.update().await {
                tracing::warn!("Failed to update rule provider {}: {}", provider.name(), e);
            }
        }
        Ok(())
    }

    /// Close all providers
    pub async fn close_all(&self) {
        for (_, provider) in self.proxy_providers.read().await.iter() {
            provider.close().await;
        }
    }
}

impl Default for ProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_info_parse() {
        let header = "upload=1234; download=5678; total=10000000; expire=1704067200";
        let info = SubscriptionInfo::parse(header).unwrap();

        assert_eq!(info.upload, 1234);
        assert_eq!(info.download, 5678);
        assert_eq!(info.total, 10000000);
        assert_eq!(info.expire, 1704067200);
    }

    #[test]
    fn test_vehicle_type_display() {
        assert_eq!(VehicleType::HTTP.to_string(), "HTTP");
        assert_eq!(VehicleType::File.to_string(), "File");
    }
}
