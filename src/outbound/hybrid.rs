//! Hybrid proxy manager
//!
//! Unified interface for both Rust native and Go fallback proxies.
//! Automatically routes proxy lookups to the correct backend.

use super::classifier::{classify_protocol, ProtocolTier};
use super::go_fallback::{GoFallbackManager, GoFallbackStats, ManagerState, ProcessState};
use super::{OutboundProxy, ProxyManager};
use crate::config::ProxyConfig;
use crate::dns::Resolver;
use crate::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Hybrid proxy manager combining Rust native and Go fallback proxies
pub struct HybridProxyManager {
    /// Rust native proxy manager
    rust_manager: ProxyManager,
    /// Go fallback manager
    go_manager: Arc<GoFallbackManager>,
    /// DNS resolver reference
    dns_resolver: Arc<Resolver>,
    /// All proxy names (for quick listing)
    all_names: RwLock<Vec<String>>,
}

impl HybridProxyManager {
    /// Create a new hybrid proxy manager
    pub async fn new(
        configs: &[ProxyConfig],
        dns_resolver: Arc<Resolver>,
        go_executable: Option<PathBuf>,
        go_config_path: Option<PathBuf>,
        go_listen_port: Option<u16>,
    ) -> Result<Self> {
        // Separate Rust and Go proxy configs
        let rust_configs: Vec<_> = configs
            .iter()
            .filter(|c| matches!(classify_protocol(&c.proxy_type), ProtocolTier::Rust))
            .cloned()
            .collect();

        info!(
            "Initializing hybrid proxy manager: {} Rust, {} Go fallback",
            rust_configs.len(),
            configs.len() - rust_configs.len()
        );

        // Create Rust proxy manager with only Rust-supported proxies
        let rust_manager = ProxyManager::new(&rust_configs, dns_resolver.clone())?;

        // Create Go fallback manager
        let go_manager = Arc::new(GoFallbackManager::new(
            go_executable.unwrap_or_else(|| {
                #[cfg(windows)]
                {
                    PathBuf::from("mihomo.exe")
                }
                #[cfg(not(windows))]
                {
                    PathBuf::from("mihomo")
                }
            }),
            go_config_path.unwrap_or_else(|| PathBuf::from("go-fallback-config.yaml")),
            go_listen_port.unwrap_or(17890),
        ));

        // Initialize Go fallback manager with all configs
        // (it will filter to only Go-required proxies)
        go_manager.initialize(configs).await?;

        // Collect all proxy names
        let mut all_names: Vec<String> = rust_manager.names().into_iter().cloned().collect();
        all_names.extend(go_manager.proxy_names().await);

        // Remove duplicates (built-in proxies might overlap)
        all_names.sort();
        all_names.dedup();

        Ok(HybridProxyManager {
            rust_manager,
            go_manager,
            dns_resolver,
            all_names: RwLock::new(all_names),
        })
    }

    /// Create with default Go configuration
    pub async fn with_defaults(
        configs: &[ProxyConfig],
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        Self::new(configs, dns_resolver, None, None, None).await
    }

    /// Start the Go fallback process (if needed)
    pub async fn start_go_fallback(&self) -> Result<()> {
        if self.go_manager.proxy_count().await > 0 {
            self.go_manager.start().await
        } else {
            Ok(())
        }
    }

    /// Stop the Go fallback process
    pub async fn stop_go_fallback(&self) -> Result<()> {
        self.go_manager.stop().await
    }

    /// Get a proxy by name (auto-routes to Rust or Go)
    pub async fn get(&self, name: &str) -> Option<Arc<dyn OutboundProxy>> {
        // First check Rust proxies
        if let Some(proxy) = self.rust_manager.get(name) {
            debug!("[{}] Using Rust native proxy", name);
            return Some(proxy.clone());
        }

        // Then check Go fallback proxies
        if let Some(proxy) = self.go_manager.get_outbound(name).await {
            debug!("[{}] Using Go fallback proxy", name);
            return Some(proxy);
        }

        None
    }

    /// Check if a proxy exists
    pub async fn contains(&self, name: &str) -> bool {
        self.rust_manager.get(name).is_some() || self.go_manager.contains(name).await
    }

    /// Get all proxy names
    pub async fn names(&self) -> Vec<String> {
        self.all_names.read().await.clone()
    }

    /// Get total number of proxies
    pub async fn len(&self) -> usize {
        self.rust_manager.len() + self.go_manager.proxy_count().await
    }

    /// Check if empty
    pub async fn is_empty(&self) -> bool {
        self.rust_manager.is_empty() && self.go_manager.proxy_count().await == 0
    }

    /// Get Rust proxy count
    pub fn rust_proxy_count(&self) -> usize {
        self.rust_manager.len()
    }

    /// Get Go proxy count
    pub async fn go_proxy_count(&self) -> usize {
        self.go_manager.proxy_count().await
    }

    /// Check if a proxy is handled by Go fallback
    pub async fn is_go_fallback(&self, name: &str) -> bool {
        self.go_manager.contains(name).await
    }

    /// Get Go fallback manager state
    pub async fn go_manager_state(&self) -> ManagerState {
        self.go_manager.state().await
    }

    /// Get Go process state
    pub async fn go_process_state(&self) -> ProcessState {
        self.go_manager.process_state().await
    }

    /// Check if Go fallback is healthy
    pub async fn is_go_healthy(&self) -> bool {
        self.go_manager.is_healthy().await
    }

    /// Restart Go fallback process
    pub async fn restart_go_fallback(&self) -> Result<()> {
        self.go_manager.restart().await
    }

    /// Get Go fallback statistics
    pub async fn go_stats(&self) -> GoFallbackStats {
        self.go_manager.stats().await
    }

    /// Get hybrid statistics
    pub async fn stats(&self) -> HybridStats {
        let go_stats = self.go_manager.stats().await;

        HybridStats {
            rust_proxy_count: self.rust_manager.len(),
            go_proxy_count: go_stats.proxy_count,
            total_proxy_count: self.rust_manager.len() + go_stats.proxy_count,
            go_process_state: go_stats.process_state,
            go_restart_count: go_stats.restart_count,
            go_total_connections: go_stats.total_connections,
        }
    }

    /// Iterate over all Rust proxies
    pub fn rust_proxies(&self) -> impl Iterator<Item = (&String, &Arc<dyn OutboundProxy>)> {
        self.rust_manager.iter()
    }

    /// Get DNS resolver reference
    pub fn dns_resolver(&self) -> &Arc<Resolver> {
        &self.dns_resolver
    }
}

/// Hybrid manager statistics
#[derive(Debug, Clone)]
pub struct HybridStats {
    pub rust_proxy_count: usize,
    pub go_proxy_count: usize,
    pub total_proxy_count: usize,
    pub go_process_state: ProcessState,
    pub go_restart_count: u32,
    pub go_total_connections: u64,
}

impl HybridStats {
    /// Get percentage of proxies handled by Rust
    pub fn rust_percentage(&self) -> f64 {
        if self.total_proxy_count == 0 {
            100.0
        } else {
            (self.rust_proxy_count as f64 / self.total_proxy_count as f64) * 100.0
        }
    }

    /// Get percentage of proxies handled by Go
    pub fn go_percentage(&self) -> f64 {
        if self.total_proxy_count == 0 {
            0.0
        } else {
            (self.go_proxy_count as f64 / self.total_proxy_count as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;

    fn make_proxy(name: &str, proxy_type: &str) -> ProxyConfig {
        let mut extra = StdHashMap::new();

        // Add required fields based on proxy type
        match proxy_type {
            "ss" | "shadowsocks" => {
                extra.insert(
                    "cipher".to_string(),
                    serde_yaml::Value::String("aes-256-gcm".to_string()),
                );
                extra.insert(
                    "password".to_string(),
                    serde_yaml::Value::String("test-password".to_string()),
                );
            }
            _ => {}
        }

        ProxyConfig {
            name: name.to_string(),
            proxy_type: proxy_type.to_string(),
            server: "example.com".to_string(),
            port: 443,
            extra,
        }
    }

    #[test]
    fn test_hybrid_stats_percentages() {
        let stats = HybridStats {
            rust_proxy_count: 8,
            go_proxy_count: 2,
            total_proxy_count: 10,
            go_process_state: ProcessState::Running,
            go_restart_count: 0,
            go_total_connections: 100,
        };

        assert!((stats.rust_percentage() - 80.0).abs() < 0.01);
        assert!((stats.go_percentage() - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_hybrid_stats_empty() {
        let stats = HybridStats {
            rust_proxy_count: 0,
            go_proxy_count: 0,
            total_proxy_count: 0,
            go_process_state: ProcessState::Stopped,
            go_restart_count: 0,
            go_total_connections: 0,
        };

        assert!((stats.rust_percentage() - 100.0).abs() < 0.01);
        assert!(stats.go_percentage().abs() < 0.01);
    }
}
