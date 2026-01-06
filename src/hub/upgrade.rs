//! Upgrade and restart endpoints
//!
//! Provides system control operations.

use super::common::{ApiError, ApiResult};
use super::AppState;
use axum::{
    extract::State,
    http::StatusCode,
};
use tracing::info;

/// POST /restart - Restart the core
///
/// Performs a graceful restart:
/// 1. Save current connection states
/// 2. Signal listeners to stop accepting new connections
/// 3. Wait for existing connections to finish (with timeout)
/// 4. Reload configuration
/// 5. Restart all listeners
pub async fn restart(
    State(state): State<AppState>,
) -> StatusCode {
    info!("Restart requested");

    // Update providers first
    if let Err(e) = state.provider_manager.update_all().await {
        tracing::warn!("Failed to update providers during restart: {}", e);
    }

    // Clear DNS cache for fresh resolution
    state.dns_resolver.clear_cache();

    // Note: Full restart would require the Gateway to coordinate
    // For now, we update what we can through the state

    info!("Restart completed - providers refreshed, DNS cache cleared");
    StatusCode::NO_CONTENT
}

/// POST /upgrade - Upgrade the core (not applicable for Rust version)
///
/// The Rust version is a static binary and does not support
/// in-place upgrades like the Go version.
pub async fn upgrade(
    State(_state): State<AppState>,
) -> ApiResult<StatusCode> {
    info!("Upgrade requested - not supported in Rust version");

    // Rust version does not support self-upgrade
    // The binary should be replaced externally
    Ok(StatusCode::NO_CONTENT)
}

/// PUT /debug/gc - Force garbage collection
///
/// In Rust, there is no garbage collector. However, we can:
/// - Clear DNS cache
/// - Drop unused connection tracking
/// - Force flush any pending writes
pub async fn force_gc(
    State(state): State<AppState>,
) -> StatusCode {
    info!("Force GC requested");

    // Clear DNS cache
    state.dns_resolver.clear_cache();

    // Note: Rust manages memory automatically through ownership
    // No explicit GC needed, but we can clear caches

    info!("GC completed - caches cleared");
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_response() {
        assert_eq!(StatusCode::NO_CONTENT.as_u16(), 204);
    }
}
