//! Proxies endpoints
//!
//! Manages proxy listing, selection, and delay testing.

use super::common::{ApiError, ApiResult, DelayParams, UpdateProxyRequest};
use super::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;
use tracing::debug;

/// GET /proxies - Get all proxies
pub async fn get_proxies(
    State(state): State<AppState>,
) -> Json<Value> {
    let proxies = get_all_proxies(&state);
    Json(json!({ "proxies": proxies }))
}

/// Get all proxies as a JSON map
fn get_all_proxies(state: &AppState) -> Value {
    let mut proxies = serde_json::Map::new();

    // Add built-in proxies
    proxies.insert("DIRECT".to_string(), json!({
        "type": "Direct",
        "name": "DIRECT",
        "all": [],
        "history": [],
        "udp": true
    }));

    proxies.insert("REJECT".to_string(), json!({
        "type": "Reject",
        "name": "REJECT",
        "all": [],
        "history": [],
        "udp": true
    }));

    proxies.insert("REJECT-DROP".to_string(), json!({
        "type": "Reject",
        "name": "REJECT-DROP",
        "all": [],
        "history": [],
        "udp": true
    }));

    // Add configured proxies from tunnel
    for (name, proxy) in state.tunnel.proxies().iter() {
        if !proxies.contains_key(name) {
            proxies.insert(name.clone(), json!({
                "type": proxy.proxy_type().to_string(),
                "name": name,
                "all": [],
                "history": [],
                "udp": proxy.support_udp()
            }));
        }
    }

    // TODO: Add proxy groups from config

    Value::Object(proxies)
}

/// GET /proxies/:name - Get a specific proxy
pub async fn get_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    // Check built-in proxies first
    if name == "DIRECT" {
        return Ok(Json(json!({
            "type": "Direct",
            "name": "DIRECT",
            "all": [],
            "history": [],
            "udp": true
        })));
    }

    if name == "REJECT" || name == "REJECT-DROP" {
        return Ok(Json(json!({
            "type": "Reject",
            "name": name,
            "all": [],
            "history": [],
            "udp": true
        })));
    }

    // Check configured proxies
    if let Some(proxy) = state.tunnel.proxies().get(&name) {
        return Ok(Json(json!({
            "type": proxy.proxy_type().to_string(),
            "name": name,
            "all": [],
            "history": [],
            "udp": proxy.support_udp()
        })));
    }

    Err(ApiError::not_found("Proxy"))
}

/// PUT /proxies/:name - Update proxy selection (for groups)
pub async fn update_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateProxyRequest>,
) -> ApiResult<StatusCode> {
    debug!("Update proxy {} to select {}", name, body.name);

    // Check if it's a proxy group in config
    let config = state.config.read().await;
    
    for group in &config.proxy_groups {
        if group.name == name {
            // Check group type - only Selector allows manual selection
            let group_type = group.group_type.to_lowercase();
            if group_type != "select" && group_type != "selector" {
                return Err(ApiError::bad_request("Must be a Selector proxy group"));
            }

            // Check if selected proxy is in the group
            if !group.proxies.contains(&body.name) {
                return Err(ApiError::not_found("Proxy not in group"));
            }

            // TODO: Actually persist the selection
            // For now, just return success
            return Ok(StatusCode::NO_CONTENT);
        }
    }

    // Check if it's a regular proxy (not a group)
    if state.tunnel.proxies().get(&name).is_some() {
        return Err(ApiError::bad_request("Must be a Selector proxy group"));
    }

    Err(ApiError::not_found("Proxy"))
}

/// DELETE /proxies/:name - Unfix proxy selection
pub async fn unfix_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    debug!("Unfix proxy: {}", name);

    // TODO: Implement unfix for selector groups
    // For now, just verify the proxy exists
    if state.tunnel.proxies().get(&name).is_some() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("Proxy"))
    }
}

/// GET /proxies/:name/delay - Test proxy delay
pub async fn get_proxy_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> ApiResult<Json<Value>> {
    debug!("Testing delay for proxy: {} with url: {}", name, params.url);

    // Get the proxy
    let proxy = match name.as_str() {
        "DIRECT" => {
            // For DIRECT, we test direct connection
            return test_direct_delay(&params).await;
        }
        "REJECT" | "REJECT-DROP" => {
            return Err(ApiError::service_unavailable("REJECT proxy has no delay"));
        }
        _ => {
            state.tunnel.proxies().get(&name).cloned()
        }
    };

    let _proxy = match proxy {
        Some(p) => p,
        None => return Err(ApiError::not_found("Proxy")),
    };

    // Test delay
    let _timeout = Duration::from_millis(params.timeout);
    let start = std::time::Instant::now();

    // TODO: Implement actual delay test via proxy
    // For now, return a placeholder

    let elapsed = start.elapsed();
    let delay = elapsed.as_millis() as u16;

    Ok(Json(json!({ "delay": delay })))
}

/// Test delay for direct connection
async fn test_direct_delay(params: &DelayParams) -> ApiResult<Json<Value>> {
    let timeout = Duration::from_millis(params.timeout);
    let start = std::time::Instant::now();

    // Make HTTP request
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| ApiError::internal(e.to_string()))?;

    match client.get(&params.url).send().await {
        Ok(resp) => {
            // Check expected status if specified
            if let Some(expected) = params.expected {
                if resp.status().as_u16() != expected {
                    return Err(ApiError::service_unavailable(format!(
                        "Expected status {}, got {}",
                        expected,
                        resp.status()
                    )));
                }
            }

            let delay = start.elapsed().as_millis() as u16;
            Ok(Json(json!({ "delay": delay })))
        }
        Err(e) => {
            if e.is_timeout() {
                Err(ApiError::gateway_timeout("Timeout"))
            } else {
                Err(ApiError::service_unavailable(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delay_params() {
        let json = r#"{"url": "http://test.com", "timeout": 3000}"#;
        let params: DelayParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.url, "http://test.com");
        assert_eq!(params.timeout, 3000);
    }
}
