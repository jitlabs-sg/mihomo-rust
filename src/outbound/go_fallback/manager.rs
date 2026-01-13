//! Go fallback manager
//!
//! Coordinates all Go fallback proxies:
//! - Manages Go mihomo process lifecycle
//! - Creates and tracks GoFallbackProxy instances
//! - Handles configuration updates

use super::process::{GoProcessConfig, GoProcessManager, ProcessState};
use super::proxy::GoFallbackProxy;
use crate::config::splitter::{split_proxies, GoFallbackConfig, DEFAULT_GO_FALLBACK_PORT};
use crate::config::ProxyConfig;
use crate::outbound::OutboundProxy;
use crate::{Error, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Default Go mihomo executable name
#[cfg(windows)]
pub const DEFAULT_MIHOMO_EXECUTABLE: &str = "mihomo.exe";

#[cfg(not(windows))]
pub const DEFAULT_MIHOMO_EXECUTABLE: &str = "mihomo";

/// Default fallback config file name
pub const DEFAULT_CONFIG_FILE: &str = "go-fallback-config.yaml";

/// Go fallback manager state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerState {
    /// Not initialized
    Uninitialized,
    /// Ready but process not started
    Ready,
    /// Process starting
    Starting,
    /// Process running
    Running,
    /// Process stopped
    Stopped,
    /// Error state
    Error,
}

/// Go fallback manager
pub struct GoFallbackManager {
    /// Process manager
    process: Arc<GoProcessManager>,
    /// Go fallback proxies by name
    proxies: RwLock<HashMap<String, Arc<GoFallbackProxy>>>,
    /// Configuration
    config: RwLock<GoFallbackConfig>,
    /// Manager state
    state: RwLock<ManagerState>,
    /// Config file path
    config_path: PathBuf,
    /// Listen port
    listen_port: u16,
}

impl GoFallbackManager {
    /// Create a new Go fallback manager
    pub fn new(
        executable_path: PathBuf,
        config_path: PathBuf,
        listen_port: u16,
    ) -> Self {
        let process_config = GoProcessConfig {
            executable: executable_path,
            config_path: config_path.clone(),
            listen_port,
            work_dir: None,
            auto_restart: true,
            max_restarts: 5,
        };

        GoFallbackManager {
            process: Arc::new(GoProcessManager::new(process_config)),
            proxies: RwLock::new(HashMap::new()),
            config: RwLock::new(GoFallbackConfig::empty(listen_port)),
            state: RwLock::new(ManagerState::Uninitialized),
            config_path,
            listen_port,
        }
    }

    /// Create with default paths
    pub fn with_defaults() -> Self {
        Self::new(
            PathBuf::from(DEFAULT_MIHOMO_EXECUTABLE),
            PathBuf::from(DEFAULT_CONFIG_FILE),
            DEFAULT_GO_FALLBACK_PORT,
        )
    }

    /// Initialize with proxy configurations
    pub async fn initialize(&self, proxy_configs: &[ProxyConfig]) -> Result<()> {
        info!("Initializing Go fallback manager...");

        // Split proxies
        let split = split_proxies(proxy_configs);

        if split.go_proxies.is_empty() {
            info!("No Go fallback proxies needed");
            *self.state.write().await = ManagerState::Ready;
            return Ok(());
        }

        info!(
            "Configuring {} Go fallback proxies: {:?}",
            split.go_proxies.len(),
            split.go_proxy_names
        );

        // Create Go fallback config
        let go_config = GoFallbackConfig::new(split.go_proxies.clone(), self.listen_port);

        // Write config file
        go_config.write_to_file(&self.config_path).await.map_err(|e| {
            Error::config(format!("Failed to write Go fallback config: {}", e))
        })?;

        info!("Wrote Go fallback config to {:?}", self.config_path);

        // Create proxy wrappers
        let proxy_addr = format!("127.0.0.1:{}", self.listen_port);
        let mut proxies = HashMap::new();

        for config in &split.go_proxies {
            let proxy = GoFallbackProxy::new(
                config.name.clone(),
                config.proxy_type.clone(),
                config.server.clone(),
                proxy_addr.clone(),
                config.get_bool("udp").unwrap_or(false),
            );
            proxies.insert(config.name.clone(), Arc::new(proxy));
        }

        // Store state
        *self.proxies.write().await = proxies;
        *self.config.write().await = go_config;
        *self.state.write().await = ManagerState::Ready;

        info!("Go fallback manager initialized");
        Ok(())
    }

    /// Start the Go mihomo process
    pub async fn start(&self) -> Result<()> {
        let state = *self.state.read().await;

        if state == ManagerState::Uninitialized {
            return Err(Error::internal("Go fallback manager not initialized"));
        }

        // Check if we have any proxies to handle
        if self.proxies.read().await.is_empty() {
            info!("No Go fallback proxies configured, skipping process start");
            return Ok(());
        }

        *self.state.write().await = ManagerState::Starting;

        match self.process.start().await {
            Ok(()) => {
                *self.state.write().await = ManagerState::Running;
                info!("Go fallback manager started");

                // Start health check loop
                let process = self.process.clone();
                tokio::spawn(async move {
                    process.run_health_loop().await;
                });

                Ok(())
            }
            Err(e) => {
                *self.state.write().await = ManagerState::Error;
                Err(e)
            }
        }
    }

    /// Stop the Go mihomo process
    pub async fn stop(&self) -> Result<()> {
        self.process.stop().await?;
        *self.state.write().await = ManagerState::Stopped;
        info!("Go fallback manager stopped");
        Ok(())
    }

    /// Get a Go fallback proxy by name
    pub async fn get_proxy(&self, name: &str) -> Option<Arc<GoFallbackProxy>> {
        self.proxies.read().await.get(name).cloned()
    }

    /// Get a Go fallback proxy as OutboundProxy trait object
    pub async fn get_outbound(&self, name: &str) -> Option<Arc<dyn OutboundProxy>> {
        self.proxies
            .read()
            .await
            .get(name)
            .map(|p| p.clone() as Arc<dyn OutboundProxy>)
    }

    /// Check if a proxy name is handled by Go fallback
    pub async fn contains(&self, name: &str) -> bool {
        self.proxies.read().await.contains_key(name)
    }

    /// Get all Go fallback proxy names
    pub async fn proxy_names(&self) -> Vec<String> {
        self.proxies.read().await.keys().cloned().collect()
    }

    /// Get number of Go fallback proxies
    pub async fn proxy_count(&self) -> usize {
        self.proxies.read().await.len()
    }

    /// Get current manager state
    pub async fn state(&self) -> ManagerState {
        *self.state.read().await
    }

    /// Get process state
    pub async fn process_state(&self) -> ProcessState {
        self.process.state().await
    }

    /// Check if the Go process is healthy
    pub async fn is_healthy(&self) -> bool {
        matches!(
            self.process.state().await,
            ProcessState::Running
        )
    }

    /// Get listen port
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Get proxy address
    pub fn proxy_address(&self) -> String {
        format!("127.0.0.1:{}", self.listen_port)
    }

    /// Force restart the Go process
    pub async fn restart(&self) -> Result<()> {
        self.process.force_restart().await
    }

    /// Update proxies (hot reload)
    pub async fn update_proxies(&self, proxy_configs: &[ProxyConfig]) -> Result<()> {
        info!("Updating Go fallback proxies...");

        // Split proxies
        let split = split_proxies(proxy_configs);

        if split.go_proxies.is_empty() {
            // Stop process if no more Go proxies
            if self.process.state().await == ProcessState::Running {
                self.stop().await?;
            }
            *self.proxies.write().await = HashMap::new();
            return Ok(());
        }

        // Create new config
        let go_config = GoFallbackConfig::new(split.go_proxies.clone(), self.listen_port);

        // Write config file
        go_config.write_to_file(&self.config_path).await.map_err(|e| {
            Error::config(format!("Failed to write Go fallback config: {}", e))
        })?;

        // Create new proxy wrappers
        let proxy_addr = format!("127.0.0.1:{}", self.listen_port);
        let mut new_proxies = HashMap::new();

        for config in &split.go_proxies {
            let proxy = GoFallbackProxy::new(
                config.name.clone(),
                config.proxy_type.clone(),
                config.server.clone(),
                proxy_addr.clone(),
                config.get_bool("udp").unwrap_or(false),
            );
            new_proxies.insert(config.name.clone(), Arc::new(proxy));
        }

        // Update state
        *self.proxies.write().await = new_proxies;
        *self.config.write().await = go_config;

        // Restart process to pick up new config
        if self.process.state().await == ProcessState::Running {
            self.restart().await?;
        }

        info!("Go fallback proxies updated");
        Ok(())
    }

    /// Get statistics
    pub async fn stats(&self) -> GoFallbackStats {
        let proxies = self.proxies.read().await;
        let mut total_connections = 0;

        for proxy in proxies.values() {
            total_connections += proxy.connection_count();
        }

        GoFallbackStats {
            proxy_count: proxies.len(),
            process_state: self.process.state().await,
            restart_count: self.process.restart_count(),
            total_connections,
        }
    }
}

/// Statistics for Go fallback manager
#[derive(Debug, Clone)]
pub struct GoFallbackStats {
    pub proxy_count: usize,
    pub process_state: ProcessState,
    pub restart_count: u32,
    pub total_connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;

    fn make_proxy(name: &str, proxy_type: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.to_string(),
            proxy_type: proxy_type.to_string(),
            server: "example.com".to_string(),
            port: 443,
            extra: StdHashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_manager_creation() {
        let manager = GoFallbackManager::with_defaults();
        assert_eq!(manager.state().await, ManagerState::Uninitialized);
        assert_eq!(manager.proxy_count().await, 0);
    }

    #[tokio::test]
    async fn test_manager_no_go_proxies() {
        let manager = GoFallbackManager::with_defaults();
        let proxies = vec![
            make_proxy("ss-node", "ss"),
            make_proxy("vmess-node", "vmess"),
        ];

        manager.initialize(&proxies).await.unwrap();

        assert_eq!(manager.state().await, ManagerState::Ready);
        assert_eq!(manager.proxy_count().await, 0);
    }

    #[tokio::test]
    async fn test_manager_contains() {
        let manager = GoFallbackManager::new(
            PathBuf::from("mihomo"),
            PathBuf::from("/tmp/test-go-config.yaml"),
            17899,
        );

        let proxies = vec![
            make_proxy("ss-node", "ss"),
            make_proxy("snell-node", "snell"),
        ];

        manager.initialize(&proxies).await.unwrap();

        assert!(!manager.contains("ss-node").await);
        assert!(manager.contains("snell-node").await);
    }

    #[tokio::test]
    async fn test_manager_proxy_names() {
        let manager = GoFallbackManager::new(
            PathBuf::from("mihomo"),
            PathBuf::from("/tmp/test-go-config2.yaml"),
            17898,
        );

        let proxies = vec![
            make_proxy("snell-1", "snell"),
            make_proxy("tuic-1", "tuic"),
        ];

        manager.initialize(&proxies).await.unwrap();

        let names = manager.proxy_names().await;
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"snell-1".to_string()));
        assert!(names.contains(&"tuic-1".to_string()));
    }
}
