//! Tunnel core - routes connections through proxies

mod connection;
mod router;

pub use connection::*;
pub use router::*;

use crate::common::{DnsMode, Metadata, Network};
use crate::dns::Resolver;
use crate::outbound::{ProxyConnection, ProxyManager};
use crate::rule::RuleEngine;
use crate::statistic::{
    ConnectionMetadata as StatConnectionMetadata, StatisticManager, TrackedConnection,
};
use crate::{Error, Result};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info, warn};

/// Tunnel mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    /// Use rules for routing
    Rule,
    /// All traffic to global proxy
    Global,
    /// All traffic direct
    Direct,
}

impl Default for TunnelMode {
    fn default() -> Self {
        TunnelMode::Rule
    }
}

impl TryFrom<&str> for TunnelMode {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rule" => Ok(TunnelMode::Rule),
            "global" => Ok(TunnelMode::Global),
            "direct" => Ok(TunnelMode::Direct),
            _ => Err(Error::config(format!("Unknown tunnel mode: {}", s))),
        }
    }
}

struct TrackedProxyConnection {
    id: String,
    statistic: Arc<StatisticManager>,
    tracked: Arc<TrackedConnection>,
    inner: Box<dyn ProxyConnection>,
}

impl TrackedProxyConnection {
    fn new(
        id: String,
        statistic: Arc<StatisticManager>,
        tracked: Arc<TrackedConnection>,
        inner: Box<dyn ProxyConnection>,
    ) -> Self {
        TrackedProxyConnection {
            id,
            statistic,
            tracked,
            inner,
        }
    }
}

impl Drop for TrackedProxyConnection {
    fn drop(&mut self) {
        let _ = self.statistic.close(&self.id);
    }
}

impl AsyncRead for TrackedProxyConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            let bytes = (after - before) as u64;
            if bytes > 0 {
                this.statistic.add_download(bytes);
                this.tracked.add_download(bytes);
            }
        }
        result
    }
}

impl AsyncWrite for TrackedProxyConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let bytes = *n as u64;
            if bytes > 0 {
                this.statistic.add_upload(bytes);
                this.tracked.add_upload(bytes);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

/// Tunnel core - manages routing and connections
pub struct Tunnel {
    /// Proxy manager
    proxies: ProxyManager,
    /// Rule engine
    rules: RuleEngine,
    /// DNS resolver
    resolver: Arc<Resolver>,
    /// Statistic manager (shared with API)
    statistic: Arc<StatisticManager>,
    /// Current mode
    mode: TunnelMode,
}

impl Tunnel {
    /// Create new tunnel
    pub fn new(
        proxies: ProxyManager,
        rules: RuleEngine,
        resolver: Arc<Resolver>,
        statistic: Arc<StatisticManager>,
    ) -> Self {
        Tunnel {
            proxies,
            rules,
            resolver,
            statistic,
            mode: TunnelMode::Rule,
        }
    }

    /// Handle TCP connection with dialer (returns proxy connection)
    pub async fn handle_tcp_with_dialer(
        &self,
        metadata: &Metadata,
    ) -> Result<(Box<dyn ProxyConnection>, String)> {
        let conn_id = self.statistic.generate_id();

        // Resolve routing
        let (proxy_name, rule_desc) = self.resolve(metadata);
        let (rule, rule_payload) = split_rule(&rule_desc);

        debug!(
            "[{}] {} -> {} via {} (rule: {})",
            conn_id,
            metadata.source_detail(),
            metadata.remote_address(),
            proxy_name,
            rule_desc
        );

        // Get proxy
        let proxy = self
            .proxies
            .get(&proxy_name)
            .ok_or_else(|| Error::proxy(format!("Proxy not found: {}", proxy_name)))?;

        // Dial through proxy
        match proxy.dial_tcp(metadata).await {
            Ok(conn) => {
                // Track connection for REST API endpoints
                let tracked = TrackedConnection::new(
                    conn_id.clone(),
                    to_stat_metadata(metadata),
                    vec![proxy_name.clone()],
                    rule,
                    rule_payload,
                );
                let conn_id = self.statistic.track(tracked);
                let tracked = self.statistic.get(&conn_id)
                    .ok_or_else(|| Error::internal("Tracked connection missing"))?;

                info!(
                    "[{}] Connected {} -> {} via {}",
                    conn_id,
                    metadata.source_detail(),
                    metadata.remote_address(),
                    proxy_name
                );

                Ok((
                    Box::new(TrackedProxyConnection::new(
                        conn_id.clone(),
                        self.statistic.clone(),
                        tracked,
                        conn,
                    )),
                    conn_id,
                ))
            }
            Err(e) => {
                warn!(
                    "[{}] Failed {} -> {} via {}: {}",
                    conn_id,
                    metadata.source_detail(),
                    metadata.remote_address(),
                    proxy_name,
                    e
                );
                Err(e)
            }
        }
    }

    /// Resolve routing for metadata
    fn resolve(&self, metadata: &Metadata) -> (String, String) {
        // Check for special proxy override
        if let Some(ref special) = metadata.special_proxy {
            return (special.clone(), "SPECIAL".to_string());
        }

        match self.mode {
            TunnelMode::Direct => ("DIRECT".to_string(), "MODE:DIRECT".to_string()),
            TunnelMode::Global => ("GLOBAL".to_string(), "MODE:GLOBAL".to_string()),
            TunnelMode::Rule => self.rules.match_rules(metadata),
        }
    }

    /// Set tunnel mode
    pub fn set_mode(&mut self, mode: TunnelMode) {
        self.mode = mode;
        info!("Tunnel mode changed to {:?}", mode);
    }

    /// Get current mode
    pub fn mode(&self) -> TunnelMode {
        self.mode
    }

    /// Get proxy manager reference
    pub fn proxies(&self) -> &ProxyManager {
        &self.proxies
    }

    /// Get rule engine reference
    pub fn rules(&self) -> &RuleEngine {
        &self.rules
    }

    /// Get rule engine reference (alias for API compatibility)
    pub fn rule_engine(&self) -> &RuleEngine {
        &self.rules
    }

    /// Get DNS resolver reference
    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }
}

fn split_rule(rule_desc: &str) -> (String, String) {
    if rule_desc.eq_ignore_ascii_case("default") {
        return ("MATCH".to_string(), String::new());
    }

    if let Some((rule, payload)) = rule_desc.split_once(',') {
        return (rule.to_string(), payload.to_string());
    }

    if let Some((rule, payload)) = rule_desc.split_once(':') {
        return (rule.to_string(), payload.to_string());
    }

    (rule_desc.to_string(), String::new())
}

fn to_stat_metadata(metadata: &Metadata) -> StatConnectionMetadata {
    let network = match metadata.network {
        Network::Tcp => "tcp",
        Network::Udp => "udp",
    };

    let dns_mode = match metadata.dns_mode {
        DnsMode::Normal => "normal",
        DnsMode::FakeIP => "fakeip",
        DnsMode::Mapping => "mapping",
        DnsMode::Hosts => "hosts",
    };

    StatConnectionMetadata {
        network: network.to_string(),
        conn_type: metadata.conn_type.to_string(),
        source_ip: metadata.src_ip.to_string(),
        destination_ip: metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        source_port: metadata.src_port.to_string(),
        destination_port: metadata.dst_port.to_string(),
        host: metadata.host.clone(),
        dns_mode: dns_mode.to_string(),
        process_path: metadata.process_path.clone().unwrap_or_default(),
        special_proxy: metadata.special_proxy.clone().unwrap_or_default(),
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        // Note: This creates a shallow clone with shared state
        // In production, you might want Arc<Tunnel> instead
        panic!("Tunnel should be wrapped in Arc, not cloned directly")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_mode() {
        assert_eq!(TunnelMode::try_from("rule").unwrap(), TunnelMode::Rule);
        assert_eq!(TunnelMode::try_from("global").unwrap(), TunnelMode::Global);
        assert_eq!(TunnelMode::try_from("direct").unwrap(), TunnelMode::Direct);
    }

    #[test]
    fn test_split_rule() {
        assert_eq!(
            split_rule("DOMAIN-SUFFIX,example.com"),
            ("DOMAIN-SUFFIX".to_string(), "example.com".to_string())
        );
        assert_eq!(
            split_rule("MODE:DIRECT"),
            ("MODE".to_string(), "DIRECT".to_string())
        );
        assert_eq!(
            split_rule("default"),
            ("MATCH".to_string(), String::new())
        );
        assert_eq!(
            split_rule("MATCH"),
            ("MATCH".to_string(), String::new())
        );
    }
}
