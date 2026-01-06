//! Rule Provider
//!
//! To be fully implemented in Phase 3.

use super::{Fetcher, ProviderType, VehicleType};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::RwLock;

/// Rule provider (HTTP/File)
pub struct RuleProvider {
    name: String,
    vehicle_type: VehicleType,
    behavior: RuleBehavior,
    rules: RwLock<Vec<String>>,
    fetcher: Option<Fetcher>,
    updated_at: RwLock<Option<DateTime<Utc>>>,
}

/// Rule behavior type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBehavior {
    /// Domain rules
    Domain,
    /// IP CIDR rules
    IpCidr,
    /// Classical rules (mixed)
    Classical,
}

impl RuleProvider {
    pub fn new_http(
        name: String,
        url: String,
        path: PathBuf,
        interval: Duration,
        behavior: RuleBehavior,
    ) -> Self {
        let fetcher = Fetcher::new(url, path, interval);

        RuleProvider {
            name,
            vehicle_type: VehicleType::HTTP,
            behavior,
            rules: RwLock::new(Vec::new()),
            fetcher: Some(fetcher),
            updated_at: RwLock::new(None),
        }
    }

    pub fn new_file(name: String, path: PathBuf, behavior: RuleBehavior) -> Self {
        RuleProvider {
            name,
            vehicle_type: VehicleType::File,
            behavior,
            rules: RwLock::new(Vec::new()),
            fetcher: None,
            updated_at: RwLock::new(None),
        }
    }

    /// Get provider name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get provider type
    pub fn provider_type(&self) -> ProviderType {
        ProviderType::Rule
    }

    /// Get vehicle type
    pub fn vehicle_type(&self) -> VehicleType {
        self.vehicle_type
    }

    /// Get rule behavior
    pub fn behavior(&self) -> RuleBehavior {
        self.behavior
    }

    /// Get rule count
    pub async fn count(&self) -> usize {
        self.rules.read().await.len()
    }

    /// Update rules from source
    pub async fn update(&self) -> Result<()> {
        if let Some(ref fetcher) = self.fetcher {
            let (content, _) = fetcher.fetch().await?;

            // Parse rules based on behavior
            let rules = self.parse_rules(&content)?;
            *self.rules.write().await = rules;
            *self.updated_at.write().await = Some(Utc::now());
        }

        Ok(())
    }

    /// Parse rules from content
    fn parse_rules(&self, content: &[u8]) -> Result<Vec<String>> {
        let text = String::from_utf8_lossy(content);
        let rules: Vec<String> = text
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|s| s.to_string())
            .collect();
        Ok(rules)
    }

    /// Match a domain/IP against rules
    pub async fn match_domain(&self, domain: &str) -> bool {
        let rules = self.rules.read().await;
        rules.iter().any(|rule| domain.ends_with(rule) || domain == rule)
    }

    /// Get last update time
    pub async fn updated_at(&self) -> Option<DateTime<Utc>> {
        *self.updated_at.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rule_provider_creation() {
        let provider = RuleProvider::new_file(
            "test".to_string(),
            PathBuf::from("/tmp/rules.txt"),
            RuleBehavior::Domain,
        );

        assert_eq!(provider.name(), "test");
        assert_eq!(provider.behavior(), RuleBehavior::Domain);
        assert_eq!(provider.vehicle_type(), VehicleType::File);
    }
}
