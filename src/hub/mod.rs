//! REST API Server (hub) - 100% compatible with mihomo REST API
//!
//! Implements all 30+ endpoints as defined in the mihomo API specification.
//! Supports HTTP, Unix Domain Socket (Linux/macOS), and Windows Named Pipe interfaces.

mod auth;
mod common;

// IPC modules (platform-specific)
#[cfg(unix)]
pub mod ipc_unix;

#[cfg(windows)]
pub mod ipc_windows;

// Endpoint modules
mod configs;
mod connections;
mod dns;
mod groups;
mod logs;
mod memory;
mod providers;
mod proxies;
mod rules;
mod traffic;
mod upgrade;

pub use auth::auth_middleware;
pub use common::{ApiError, ApiResult};

// Re-export IPC server functions
#[cfg(unix)]
pub use ipc_unix::{start_unix_socket_server, cleanup_socket};

#[cfg(windows)]
pub use ipc_windows::start_named_pipe_server;

use crate::config::Config;
use crate::dns::Resolver;
use crate::provider::ProviderManager;
use crate::statistic::StatisticManager;
use crate::tunnel::Tunnel;
use crate::{Result, VERSION, META};

use axum::{
    extract::State,
    middleware,
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// API secret for authentication
    pub secret: String,
    /// Configuration (shared, read-write)
    pub config: Arc<RwLock<Config>>,
    /// Tunnel core
    pub tunnel: Arc<Tunnel>,
    /// Statistics manager
    pub statistic: Arc<StatisticManager>,
    /// DNS resolver
    pub dns_resolver: Arc<Resolver>,
    /// Log subscriber for streaming logs
    pub log_tx: tokio::sync::broadcast::Sender<logs::LogEvent>,
    /// Provider manager
    pub provider_manager: Arc<ProviderManager>,
}

impl AppState {
    pub fn new(
        secret: String,
        config: Arc<RwLock<Config>>,
        tunnel: Arc<Tunnel>,
        statistic: Arc<StatisticManager>,
        dns_resolver: Arc<Resolver>,
        provider_manager: Arc<ProviderManager>,
    ) -> Self {
        let (log_tx, _) = tokio::sync::broadcast::channel(1024);

        AppState {
            secret,
            config,
            tunnel,
            statistic,
            dns_resolver,
            log_tx,
            provider_manager,
        }
    }
}

/// Create the main router with all endpoints
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/traffic", get(traffic::traffic_ws))
        .route("/logs", get(logs::logs_ws))
        .route("/memory", get(memory::memory_ws))
        .route("/connections", get(connections::get_connections))
        .route("/connections", delete(connections::close_all_connections))
        .route("/connections/:id", delete(connections::close_connection))
        .route("/proxies", get(proxies::get_proxies))
        .route("/proxies/:name", get(proxies::get_proxy))
        .route("/proxies/:name", put(proxies::update_proxy))
        .route("/proxies/:name", delete(proxies::unfix_proxy))
        .route("/proxies/:name/delay", get(proxies::get_proxy_delay))
        .route("/group", get(groups::get_groups))
        .route("/group/:name", get(groups::get_group))
        .route("/group/:name/delay", get(groups::get_group_delay))
        .route("/rules", get(rules::get_rules))
        .route("/configs", get(configs::get_configs))
        .route("/configs", put(configs::reload_configs))
        .route("/configs", patch(configs::patch_configs))
        .route("/configs/geo", post(configs::update_geo))
        .route("/providers/proxies", get(providers::get_proxy_providers))
        .route("/providers/proxies/:name", get(providers::get_proxy_provider))
        .route("/providers/proxies/:name", put(providers::update_proxy_provider))
        .route("/providers/proxies/:name/healthcheck", get(providers::healthcheck_proxy_provider))
        .route("/providers/proxies/:name/:proxy", get(providers::get_provider_proxy))
        .route("/providers/proxies/:name/:proxy/healthcheck", get(providers::healthcheck_provider_proxy))
        .route("/providers/rules", get(providers::get_rule_providers))
        .route("/providers/rules/:name", put(providers::update_rule_provider))
        .route("/dns/query", get(dns::dns_query))
        .route("/cache/fakeip/flush", post(dns::flush_fakeip_cache))
        .route("/cache/dns/flush", post(dns::flush_dns_cache))
        .route("/restart", post(upgrade::restart))
        .route("/upgrade", post(upgrade::upgrade))
        .route("/debug/gc", put(upgrade::force_gc))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Start the REST API server
pub async fn start_server(state: AppState, addr: SocketAddr) -> Result<()> {
    let router = create_router(state);
    info!("Starting REST API server on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn hello() -> Json<Value> {
    Json(json!({ "hello": "mihomo" }))
}

async fn version() -> Json<Value> {
    Json(json!({
        "version": format!("mihomo Rust {}", VERSION),
        "meta": META,
        "premium": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hello() {
        let response = hello().await;
        assert_eq!(response.0["hello"], "mihomo");
    }

    #[tokio::test]
    async fn test_version() {
        let response = version().await;
        assert!(response.0["version"].as_str().unwrap().contains("mihomo"));
        assert!(response.0["meta"].as_bool().unwrap());
    }
}
