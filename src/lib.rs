//! Mihomo Rust - High-performance Rust implementation of mihomo
//!
//! This crate provides 100% REST API compatibility with mihomo v1.10.0:
//! - 30+ REST API endpoints
//! - WebSocket streaming (traffic, logs, connections)
//! - Proxy groups (Selector, URLTest, Fallback, LoadBalance)
//! - Subscription providers with auto-update
//! - Health check system
//! - IPC support (Named Pipe on Windows, Unix Socket on Linux/macOS)
//!
//! # Architecture
//!
//! ```text
//!                     +----------------+
//!                     |   hub/ (API)   |
//!                     +-------+--------+
//!                             |
//!        +--------------------+--------------------+
//!        |                    |                    |
//! +------v------+     +-------v-------+    +------v------+
//! |   config/   |     |   statistic/  |    |   tunnel/   |
//! +-------------+     +---------------+    +------+------+
//!                                                 |
//!        +----------------------------------------+
//!        |                    |                   |
//! +------v------+     +-------v-------+   +------v------+
//! |   proxy/    |     |   outbound/   |   |    rule/    |
//! |  (groups)   |     |  (protocols)  |   |  (engine)   |
//! +------+------+     +---------------+   +-------------+
//!        |
//! +------v------+
//! |  provider/  |
//! | (subscript) |
//! +-------------+
//! ```

pub mod common;
pub mod config;
pub mod dns;
pub mod hub;
pub mod inbound;
pub mod outbound;
pub mod provider;
pub mod proxy;
pub mod rule;
pub mod statistic;
pub mod transport;
pub mod tunnel;

pub use common::error::{Error, Result};
pub use config::Config;

use hub::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Mihomo version (compatible with Go version)
pub const VERSION: &str = "1.10.0";
pub const META: bool = true;

/// Gateway instance managing all components
pub struct Gateway {
    config: Arc<RwLock<Config>>,
    tunnel: Arc<tunnel::Tunnel>,
    dns_resolver: Arc<dns::Resolver>,
    statistic: Arc<statistic::StatisticManager>,
    provider_manager: Arc<provider::ProviderManager>,
    inbounds: Vec<Arc<dyn inbound::InboundListener>>,
    api_addr: Option<SocketAddr>,
    api_secret: String,
    #[cfg(windows)]
    api_pipe: Option<String>,
    #[cfg(unix)]
    api_unix: Option<String>,
}

impl Gateway {
    /// Create a new Gateway from configuration
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing Mihomo Rust v{}", VERSION);

        // Extract API config before moving config
        let api_addr = config.external_controller.as_ref().and_then(|addr| {
            addr.parse::<SocketAddr>().ok()
        });
        let api_secret = config.secret.clone().unwrap_or_default();

        #[cfg(windows)]
        let api_pipe = config.external_controller_pipe.clone();

        #[cfg(unix)]
        let api_unix = config.external_controller_unix.clone();

        // Initialize DNS resolver
        let dns_resolver = Arc::new(dns::Resolver::new(&config.dns).await?);
        info!("DNS resolver initialized");

        // Initialize statistic manager
        let statistic = Arc::new(statistic::StatisticManager::new());
        statistic.start_ticker();
        info!("Statistic manager initialized");

        // Initialize outbound proxies
        let proxies = outbound::ProxyManager::new(&config.proxies, dns_resolver.clone())?;
        info!("Loaded {} proxies", proxies.len());

        // Initialize rule engine
        let rule_engine = rule::RuleEngine::new(&config.rules)?;
        info!("Loaded {} rules", rule_engine.rule_count());

        // Initialize tunnel (with shared StatisticManager)
        let tunnel = Arc::new(tunnel::Tunnel::new(
            proxies,
            rule_engine,
            dns_resolver.clone(),
            statistic.clone(),
        ));

        // Initialize inbound listeners
        let mut inbounds: Vec<Arc<dyn inbound::InboundListener>> = Vec::new();

        // HTTP proxy
        if let Some(http_config) = &config.inbound.http {
            let listener = inbound::HttpListener::new(http_config.clone(), tunnel.clone())?;
            inbounds.push(Arc::new(listener));
            info!("HTTP proxy configured on {}", http_config.listen);
        }

        // SOCKS5 proxy
        if let Some(socks_config) = &config.inbound.socks {
            let listener = inbound::Socks5Listener::new(socks_config.clone(), tunnel.clone())?;
            inbounds.push(Arc::new(listener));
            info!("SOCKS5 proxy configured on {}", socks_config.listen);
        }

        // Mixed port
        if let Some(mixed_config) = &config.inbound.mixed {
            let listener = inbound::MixedListener::new(mixed_config.clone(), tunnel.clone())?;
            inbounds.push(Arc::new(listener));
            info!("Mixed proxy configured on {}", mixed_config.listen);
        }

        // Initialize provider manager
        let provider_manager = Arc::new(provider::ProviderManager::new());
        info!("Provider manager initialized");

        Ok(Gateway {
            config: Arc::new(RwLock::new(config)),
            tunnel,
            dns_resolver,
            statistic,
            provider_manager,
            inbounds,
            api_addr,
            api_secret,
            #[cfg(windows)]
            api_pipe,
            #[cfg(unix)]
            api_unix,
        })
    }

    /// Start all services (inbound listeners + REST API + IPC)
    pub async fn run(&self) -> Result<()> {
        info!("Starting gateway...");

        let mut handles = Vec::new();

        // Start inbound listeners
        for inbound in &self.inbounds {
            let inbound = inbound.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = inbound.start().await {
                    warn!("Inbound listener error: {}", e);
                }
            });
            handles.push(handle);
        }

        // Start REST API server if configured
        if let Some(addr) = self.api_addr {
            let state = self.create_app_state();
            let handle = tokio::spawn(async move {
                if let Err(e) = hub::start_server(state, addr).await {
                    warn!("REST API server error: {}", e);
                }
            });
            handles.push(handle);
            info!("REST API server started on {}", addr);
        }

        // Start Named Pipe server (Windows)
        #[cfg(windows)]
        if let Some(ref pipe) = self.api_pipe {
            let state = self.create_app_state();
            let pipe_name = pipe.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = hub::start_named_pipe_server(state, &pipe_name).await {
                    warn!("Named Pipe server error: {}", e);
                }
            });
            handles.push(handle);
            info!("Named Pipe server started on {}", pipe);
        }

        // Start Unix Socket server (Unix)
        #[cfg(unix)]
        if let Some(ref unix_path) = self.api_unix {
            let state = self.create_app_state();
            let socket_path = unix_path.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = hub::start_unix_socket_server(state, &socket_path).await {
                    warn!("Unix Socket server error: {}", e);
                }
            });
            handles.push(handle);
            info!("Unix Socket server started on {}", unix_path);
        }

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        info!("Received shutdown signal");

        // Graceful shutdown
        for handle in handles {
            handle.abort();
        }

        // Cleanup Unix socket file
        #[cfg(unix)]
        if let Some(ref unix_path) = self.api_unix {
            hub::cleanup_socket(unix_path);
        }

        info!("Gateway stopped");
        Ok(())
    }

    /// Create AppState for the REST API
    fn create_app_state(&self) -> AppState {
        AppState::new(
            self.secret().to_string(),
            self.config.clone(),
            self.tunnel.clone(),
            self.statistic.clone(),
            self.dns_resolver.clone(),
            self.provider_manager.clone(),
        )
    }

    /// Get current configuration
    pub async fn config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Reload configuration
    pub async fn reload(&self, config: Config) -> Result<()> {
        let mut current = self.config.write().await;
        *current = config;
        // TODO: Hot reload proxies and rules
        Ok(())
    }

    /// Get tunnel reference
    pub fn tunnel(&self) -> &Arc<tunnel::Tunnel> {
        &self.tunnel
    }

    /// Get DNS resolver reference
    pub fn dns_resolver(&self) -> &Arc<dns::Resolver> {
        &self.dns_resolver
    }

    /// Get statistic manager reference
    pub fn statistic(&self) -> &Arc<statistic::StatisticManager> {
        &self.statistic
    }

    /// Get API secret
    pub fn secret(&self) -> &str {
        &self.api_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, "1.10.0");
        assert!(META);
    }
}
