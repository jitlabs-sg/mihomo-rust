//! LoadBalance proxy group - Distribute load across proxies
//!
//! To be fully implemented in Phase 2.

use super::{GroupOption, GroupType, ExpectedStatus, ProxyGroup, DEFAULT_TEST_URL};
use crate::common::Metadata;
use crate::outbound::{OutboundProxy, ProxyConnection, ProxyType};
use crate::provider::ProxyProvider;
use crate::{Error, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Load balance strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Round-robin selection
    RoundRobin,
    /// Consistent hashing based on destination
    ConsistentHashing,
    /// Sticky session based on destination IP
    StickySession,
}

/// LoadBalance proxy group - distributes load across proxies
pub struct LoadBalance {
    name: String,
    providers: Vec<Arc<dyn ProxyProvider>>,
    strategy: Strategy,
    test_url: String,
    interval: u64,
    disable_udp: bool,
    hidden: bool,
    icon: String,
    // Round-robin counter
    counter: AtomicUsize,
}

impl LoadBalance {
    pub fn new(option: GroupOption, providers: Vec<Arc<dyn ProxyProvider>>, strategy: Strategy) -> Self {
        LoadBalance {
            name: option.name,
            providers,
            strategy,
            test_url: option.url.unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
            interval: option.interval,
            disable_udp: option.disable_udp,
            hidden: option.hidden,
            icon: option.icon.unwrap_or_default(),
            counter: AtomicUsize::new(0),
        }
    }

    fn next_index(&self, total: usize) -> usize {
        if total == 0 {
            return 0;
        }
        self.counter.fetch_add(1, Ordering::Relaxed) % total
    }
}

#[async_trait]
impl OutboundProxy for LoadBalance {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Direct // Will add LoadBalance type later
    }

    fn server(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        !self.disable_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        Err(Error::unsupported("LoadBalance not fully implemented"))
    }
}

#[async_trait]
impl ProxyGroup for LoadBalance {
    fn group_type(&self) -> GroupType {
        GroupType::LoadBalance
    }

    fn now(&self) -> String {
        // LoadBalance doesn't have a single "current" proxy
        String::new()
    }

    fn all(&self) -> Vec<String> {
        let mut names = Vec::new();
        for provider in &self.providers {
            for proxy in provider.proxies() {
                names.push(proxy.name().to_string());
            }
        }
        names
    }

    fn set(&self, name: &str) -> Result<()> {
        Err(Error::unsupported("Cannot manually select in LoadBalance group"))
    }

    fn force_set(&self, _name: &str) {
        // No-op for load balance
    }

    fn providers(&self) -> &[Arc<dyn ProxyProvider>] {
        &self.providers
    }

    fn test_url(&self) -> &str {
        &self.test_url
    }

    async fn url_test(&self, url: &str, expected: Option<ExpectedStatus>)
        -> Result<HashMap<String, u16>> {
        Ok(HashMap::new())
    }

    fn touch(&self) {
        for p in &self.providers {
            p.touch();
        }
    }
}
