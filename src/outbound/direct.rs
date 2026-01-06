//! Direct outbound (no proxy)

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::{Error, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::debug;

/// Direct connection (no proxy)
pub struct Direct {
    name: String,
}

impl Direct {
    pub fn new() -> Self {
        Direct {
            name: "DIRECT".to_string(),
        }
    }

    pub fn with_name(name: String) -> Self {
        Direct { name }
    }
}

impl Default for Direct {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutboundProxy for Direct {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Direct
    }

    fn server(&self) -> &str {
        "DIRECT"
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        let addr = metadata.remote_address();
        debug!("Direct connecting to {}", addr);

        // Try to connect directly
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::connection(format!("Failed to connect to {}: {}", addr, e)))?;

        debug!("Direct connected to {}", addr);
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_creation() {
        let direct = Direct::new();
        assert_eq!(direct.name(), "DIRECT");
        assert_eq!(direct.proxy_type(), ProxyType::Direct);
        assert!(direct.support_udp());
    }
}
