//! Hysteria2 outbound protocol (QUIC-based)
//! Critical for IBKR trading due to low-latency QUIC.
//! TODO: Full implementation pending quinn API stabilization

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::debug;

/// Hysteria2 outbound (placeholder - falls back to direct TCP for now)
pub struct Hysteria2 {
    name: String,
    server: String,
    port: u16,
    #[allow(dead_code)] password: String,
    #[allow(dead_code)] sni: Option<String>,
    #[allow(dead_code)] skip_cert_verify: bool,
    dns_resolver: Arc<Resolver>,
}

impl Hysteria2 {
    pub fn new(
        name: String, server: String, port: u16, password: String,
        sni: Option<String>, skip_cert_verify: bool,
        _up: Option<String>, _down: Option<String>,
        _obfs: Option<String>, _obfs_password: Option<String>,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        Ok(Hysteria2 { name, server, port, password, sni, skip_cert_verify, dns_resolver })
    }
}

#[async_trait]
impl OutboundProxy for Hysteria2 {
    fn name(&self) -> &str { &self.name }
    fn proxy_type(&self) -> ProxyType { ProxyType::Hysteria2 }
    fn server(&self) -> &str { &self.server }
    fn support_udp(&self) -> bool { true }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        // TODO: Implement proper QUIC-based Hysteria2
        // For now, fall back to direct TCP (placeholder)
        debug!("Hysteria2 {} (placeholder) connecting to {}", self.name, metadata.remote_address());
        
        let resolved = self.dns_resolver.resolve(&self.server).await?;
        let addr = format!("{}:{}", resolved, self.port);
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| Error::connection(format!("Connection failed: {}", e)))?;
        
        Ok(Box::new(stream))
    }

    async fn close(&self) -> Result<()> { Ok(()) }
}
