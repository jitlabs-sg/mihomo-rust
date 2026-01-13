//! Configs endpoints
//!
//! Manages configuration (get, reload, patch).

use super::common::{ApiError, ApiResult, ConfigPatch, ConfigReload};
use super::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use tracing::{debug, info};

/// GET /configs - Get current configuration
pub async fn get_configs(
    State(state): State<AppState>,
) -> Json<Value> {
    let config = state.config.read().await;

    Json(json!({
        "port": config.inbound.http.as_ref().map(|c| c.port()).unwrap_or(0),
        "socks-port": config.inbound.socks.as_ref().map(|c| c.port()).unwrap_or(0),
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": config.inbound.mixed.as_ref().map(|c| c.port()).unwrap_or(0),
        "allow-lan": config.allow_lan.unwrap_or(false),
        "bind-address": config.bind_address.as_deref().unwrap_or("*"),
        "mode": config.mode.as_deref().unwrap_or("rule"),
        "log-level": config.log_level.as_deref().unwrap_or("info"),
        "ipv6": config.ipv6.unwrap_or(false),
        "sniffing": true,
        "tcp-concurrent": false,
        "interface-name": "",
        "tun": {
            "enable": false,
            "device": "",
            "stack": "system",
            "dns-hijack": [],
            "auto-route": true,
            "auto-detect-interface": true
        }
    }))
}

/// PUT /configs - Reload configuration from file or payload
pub async fn reload_configs(
    State(state): State<AppState>,
    Json(body): Json<ConfigReload>,
) -> ApiResult<StatusCode> {
    info!("Reloading configuration");

    // Load new config
    let new_config = if let Some(path) = body.path {
        debug!("Loading config from path: {}", path);
        match crate::config::Config::load(&path) {
            Ok(c) => c,
            Err(e) => return Err(ApiError::bad_request(format!("Failed to load config: {}", e))),
        }
    } else if let Some(payload) = body.payload {
        debug!("Loading config from payload");
        match serde_yaml::from_str(&payload) {
            Ok(c) => c,
            Err(e) => return Err(ApiError::bad_request(format!("Failed to parse config: {}", e))),
        }
    } else {
        return Err(ApiError::bad_request("Either path or payload must be provided"));
    };

    // Update config
    {
        let mut config = state.config.write().await;
        *config = new_config;
    }

    // TODO: Hot reload proxies, rules, and listeners
    info!("Configuration reloaded");

    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /configs - Patch configuration (partial update)
pub async fn patch_configs(
    State(state): State<AppState>,
    Json(patch): Json<ConfigPatch>,
) -> ApiResult<StatusCode> {
    info!("Patching configuration");

    // Apply patches
    {
        let mut config = state.config.write().await;

        // TODO: Apply each patch field
        if let Some(mode) = patch.mode {
            debug!("Setting mode to: {}", mode);
            config.mode = Some(mode);
        }

        if let Some(log_level) = patch.log_level {
            debug!("Setting log level to: {}", log_level);
            config.log_level = Some(log_level);
        }

        if let Some(allow_lan) = patch.allow_lan {
            debug!("Setting allow-lan to: {}", allow_lan);
            config.allow_lan = Some(allow_lan);
        }

        if let Some(bind_address) = patch.bind_address {
            debug!("Setting bind-address to: {}", bind_address);
            config.bind_address = Some(bind_address);
        }

        if let Some(ipv6) = patch.ipv6 {
            debug!("Setting ipv6 to: {}", ipv6);
            config.ipv6 = Some(ipv6);
        }

        // Port changes require listener restart
        // TODO: Implement port changes

    }

    info!("Configuration patched");
    Ok(StatusCode::NO_CONTENT)
}

/// POST /configs/geo - Update GeoIP/GeoSite databases
pub async fn update_geo(
    State(_state): State<AppState>,
) -> ApiResult<StatusCode> {
    info!("Updating GeoIP databases");

    // TODO: Implement GeoIP database update
    // 1. Download new databases
    // 2. Verify checksums
    // 3. Replace old databases
    // 4. Reload rule engine

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_patch_parsing() {
        let json = r#"{"mode": "global", "log-level": "debug"}"#;
        let patch: ConfigPatch = serde_json::from_str(json).unwrap();
        assert_eq!(patch.mode, Some("global".to_string()));
        assert_eq!(patch.log_level, Some("debug".to_string()));
    }
}
