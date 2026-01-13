//! Proxy Groups (Selector, URLTest, Fallback, LoadBalance)
//!
//! This module will be fully implemented in Phase 2.

mod selector;
mod urltest;
mod fallback;
mod loadbalance;

pub use selector::Selector;
pub use urltest::URLTest;
pub use fallback::Fallback;
pub use loadbalance::LoadBalance;

use crate::outbound::OutboundProxy;
use crate::provider::ProxyProvider;
use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Type of proxy group
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupType {
    Selector,
    URLTest,
    Fallback,
    LoadBalance,
    Relay,
}

impl std::fmt::Display for GroupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupType::Selector => write!(f, "Selector"),
            GroupType::URLTest => write!(f, "URLTest"),
            GroupType::Fallback => write!(f, "Fallback"),
            GroupType::LoadBalance => write!(f, "LoadBalance"),
            GroupType::Relay => write!(f, "Relay"),
        }
    }
}

/// Expected HTTP status for URL test
#[derive(Debug, Clone)]
pub struct ExpectedStatus {
    pub codes: Vec<u16>,
}

impl ExpectedStatus {
    pub fn new(codes: Vec<u16>) -> Self {
        ExpectedStatus { codes }
    }

    pub fn matches(&self, status: u16) -> bool {
        self.codes.is_empty() || self.codes.contains(&status)
    }
}

impl Default for ExpectedStatus {
    fn default() -> Self {
        ExpectedStatus { codes: vec![200, 204, 301, 302] }
    }
}

/// Trait for proxy groups
#[async_trait]
pub trait ProxyGroup: OutboundProxy + Send + Sync {
    /// Get group type
    fn group_type(&self) -> GroupType;

    /// Get current selected proxy name
    fn now(&self) -> String;

    /// Get all proxy names in this group
    fn all(&self) -> Vec<String>;

    /// Set selected proxy (for Selector)
    fn set(&self, name: &str) -> Result<()>;

    /// Force set selected proxy (for URLTest/Fallback)
    fn force_set(&self, name: &str);

    /// Get providers
    fn providers(&self) -> &[Arc<dyn ProxyProvider>];

    /// Get test URL
    fn test_url(&self) -> &str;

    /// URL test all proxies in group
    async fn url_test(&self, url: &str, expected: Option<ExpectedStatus>)
        -> Result<HashMap<String, u16>>;

    /// Touch providers (update last access time)
    fn touch(&self);
}

/// Group option from configuration
#[derive(Debug, Clone)]
pub struct GroupOption {
    pub name: String,
    pub group_type: GroupType,
    pub proxies: Vec<String>,
    pub use_providers: Vec<String>,
    pub url: Option<String>,
    pub interval: u64,
    pub tolerance: u16,
    pub lazy: bool,
    pub disable_udp: bool,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_type: Option<String>,
    pub hidden: bool,
    pub icon: Option<String>,
}

impl Default for GroupOption {
    fn default() -> Self {
        GroupOption {
            name: String::new(),
            group_type: GroupType::Selector,
            proxies: Vec::new(),
            use_providers: Vec::new(),
            url: Some("http://www.gstatic.com/generate_204".to_string()),
            interval: 300,
            tolerance: 150,
            lazy: true,
            disable_udp: false,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            hidden: false,
            icon: None,
        }
    }
}

/// Default test URL
pub const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_type_display() {
        assert_eq!(GroupType::Selector.to_string(), "Selector");
        assert_eq!(GroupType::URLTest.to_string(), "URLTest");
    }

    #[test]
    fn test_expected_status() {
        let expected = ExpectedStatus::new(vec![200, 204]);
        assert!(expected.matches(200));
        assert!(expected.matches(204));
        assert!(!expected.matches(404));
    }
}
