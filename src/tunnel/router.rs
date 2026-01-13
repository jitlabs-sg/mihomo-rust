//! Router plugin integration
//!
//! This module provides integration with external router plugins,
//! similar to mihomo's router plugin support.

use crate::common::Metadata;
use crate::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Router plugin trait
#[async_trait]
pub trait RouterPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;

    /// Plugin version
    fn version(&self) -> &str;

    /// Health check
    async fn health(&self) -> Result<()>;

    /// Match metadata against plugin rules
    ///
    /// Returns (proxy_name, rule_description)
    async fn match_route(&self, metadata: &Metadata) -> Result<(String, String)>;

    /// Close plugin
    async fn close(&self) -> Result<()>;
}

/// Router plugin manager
pub struct RouterPluginManager {
    plugin: RwLock<Option<Arc<dyn RouterPlugin>>>,
    plugin_name: RwLock<String>,
}

impl Default for RouterPluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterPluginManager {
    /// Create new plugin manager
    pub fn new() -> Self {
        RouterPluginManager {
            plugin: RwLock::new(None),
            plugin_name: RwLock::new(String::new()),
        }
    }

    /// Set router plugin
    pub async fn set_plugin(&self, plugin: Arc<dyn RouterPlugin>) -> Result<()> {
        // Health check
        plugin.health().await?;

        let name = plugin.name().to_string();
        let version = plugin.version().to_string();

        // Close old plugin
        {
            let mut current = self.plugin.write().await;
            if let Some(ref old) = *current {
                let _ = old.close().await;
            }
            *current = Some(plugin);
        }

        // Update name
        {
            let mut pn = self.plugin_name.write().await;
            *pn = name.clone();
        }

        info!("Router plugin set: {} v{}", name, version);
        Ok(())
    }

    /// Get current plugin
    pub async fn get_plugin(&self) -> Option<Arc<dyn RouterPlugin>> {
        self.plugin.read().await.clone()
    }

    /// Check if plugin is configured
    pub async fn has_plugin(&self) -> bool {
        self.plugin.read().await.is_some()
    }

    /// Get plugin name
    pub async fn plugin_name(&self) -> String {
        self.plugin_name.read().await.clone()
    }

    /// Match using plugin
    pub async fn match_route(&self, metadata: &Metadata) -> Option<(String, String)> {
        let plugin = self.plugin.read().await;
        if let Some(ref p) = *plugin {
            match p.match_route(metadata).await {
                Ok(result) => return Some(result),
                Err(e) => {
                    warn!("Router plugin match failed: {}", e);
                }
            }
        }
        None
    }

    /// Clear plugin
    pub async fn clear(&self) -> Result<()> {
        let mut current = self.plugin.write().await;
        if let Some(ref plugin) = *current {
            plugin.close().await?;
        }
        *current = None;

        let mut name = self.plugin_name.write().await;
        *name = String::new();

        info!("Router plugin cleared");
        Ok(())
    }
}

/// Default router plugin that delegates to built-in rules
pub struct DefaultRouterPlugin {
    name: String,
}

impl DefaultRouterPlugin {
    pub fn new() -> Self {
        DefaultRouterPlugin {
            name: "default".to_string(),
        }
    }
}

impl Default for DefaultRouterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RouterPlugin for DefaultRouterPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    async fn health(&self) -> Result<()> {
        Ok(())
    }

    async fn match_route(&self, _metadata: &Metadata) -> Result<(String, String)> {
        // Default plugin returns DIRECT
        Ok(("DIRECT".to_string(), "default".to_string()))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// HTTP-based router plugin (connects to external service)
pub struct HttpRouterPlugin {
    name: String,
    url: String,
    timeout_ms: u64,
}

impl HttpRouterPlugin {
    pub fn new(name: String, url: String, timeout_ms: u64) -> Self {
        HttpRouterPlugin {
            name,
            url,
            timeout_ms,
        }
    }
}

#[async_trait]
impl RouterPlugin for HttpRouterPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    async fn health(&self) -> Result<()> {
        // TODO: HTTP health check
        Ok(())
    }

    async fn match_route(&self, metadata: &Metadata) -> Result<(String, String)> {
        // TODO: HTTP request to external router service
        // For now, return default
        debug!(
            "HTTP router plugin would query {} for {}",
            self.url,
            metadata.remote_address()
        );
        Ok(("DIRECT".to_string(), "http-plugin".to_string()))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_plugin() {
        let plugin = DefaultRouterPlugin::new();
        assert_eq!(plugin.name(), "default");
        assert!(plugin.health().await.is_ok());
    }

    #[tokio::test]
    async fn test_plugin_manager() {
        let manager = RouterPluginManager::new();
        assert!(!manager.has_plugin().await);

        let plugin = Arc::new(DefaultRouterPlugin::new());
        manager.set_plugin(plugin).await.unwrap();

        assert!(manager.has_plugin().await);
        assert_eq!(manager.plugin_name().await, "default");
    }
}
