//! URLTest proxy group - Auto-select fastest proxy
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

/// URLTest proxy group for auto-selecting fastest proxy
pub struct URLTest {
    name: String,
    providers: Vec<Arc<dyn ProxyProvider>>,
    selected: RwLock<String>,
    test_url: String,
    interval: u64,
    tolerance: u16,
    lazy: bool,
    disable_udp: bool,
    hidden: bool,
    icon: String,
}

impl URLTest {
    pub fn new(option: GroupOption, providers: Vec<Arc<dyn ProxyProvider>>) -> Self {
        URLTest {
            name: option.name,
            providers,
            selected: RwLock::new(String::new()),
            test_url: option.url.unwrap_or_else(|| DEFAULT_TEST_URL.to_string()),
            interval: option.interval,
            tolerance: option.tolerance,
            lazy: option.lazy,
            disable_udp: option.disable_udp,
            hidden: option.hidden,
            icon: option.icon.unwrap_or_default(),
        }
    }
}

#[async_trait]
impl OutboundProxy for URLTest {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Direct // Will add URLTest type later
    }

    fn server(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        !self.disable_udp
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        Err(Error::unsupported("URLTest not fully implemented"))
    }
}

#[async_trait]
impl ProxyGroup for URLTest {
    fn group_type(&self) -> GroupType {
        GroupType::URLTest
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
        Err(Error::unsupported("Cannot manually select in URLTest group"))
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
        // TODO: Implement URL test
        Ok(HashMap::new())
    }

    fn touch(&self) {
        for p in &self.providers {
            p.touch();
        }
    }
}
