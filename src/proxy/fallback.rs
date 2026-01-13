//! Fallback proxy group - Use first available proxy
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

/// Fallback proxy group - uses first available proxy
pub struct Fallback {
    name: String,
    providers: Vec<Arc<dyn ProxyProvider>>,
    selected: RwLock<String>,
    test_url: String,
    interval: u64,
    disable_udp: bool,
    hidden: bool,
    icon: String,
}

impl Fallback {
    pub fn new(option: GroupOption, providers: Vec<Arc<dyn ProxyProvider>>) -> Self {
        Fallback {
            name: option.name,
            providers,
            selected: RwLock::new(String::new()),
            test_url: option.url.unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
            interval: option.interval,
            disable_udp: option.disable_udp,
            hidden: option.hidden,
            icon: option.icon.unwrap_or_default(),
        }
    }
}

#[async_trait]
impl OutboundProxy for Fallback {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Direct // Will add Fallback type later
    }

    fn server(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        !self.disable_udp
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        Err(Error::unsupported("Fallback not fully implemented"))
    }
}

#[async_trait]
impl ProxyGroup for Fallback {
    fn group_type(&self) -> GroupType {
        GroupType::Fallback
    }

    fn now(&self) -> String {
        self.selected.read().clone()
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

    fn set(&self, _name: &str) -> Result<()> {
        Err(Error::unsupported("Cannot manually select in Fallback group"))
    }

    fn force_set(&self, name: &str) {
        *self.selected.write() = name.to_string();
    }

    fn providers(&self) -> &[Arc<dyn ProxyProvider>] {
        &self.providers
    }

    fn test_url(&self) -> &str {
        &self.test_url
    }

    async fn url_test(&self, _url: &str, _expected: Option<ExpectedStatus>)
        -> Result<HashMap<String, u16>> {
        Ok(HashMap::new())
    }

    fn touch(&self) {
        for p in &self.providers {
            p.touch();
        }
    }
}
