//! Providers endpoints
//!
//! Manages proxy and rule providers (subscriptions).

use super::common::{ApiError, ApiResult, DelayParams};
use super::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use tracing::debug;

/// Format proxy provider as JSON
fn format_proxy_provider(provider: &dyn crate::provider::ProxyProvider) -> Value {
    let proxies: Vec<Value> = provider.proxies()
        .iter()
        .map(|p| json!({
            "name": p.name(),
            "type": p.proxy_type().to_string(),
        }))
        .collect();

    let mut result = json!({
        "name": provider.name(),
        "type": provider.vehicle_type().to_string(),
        "vehicleType": provider.vehicle_type().to_string(),
        "proxies": proxies,
        "testUrl": provider.health_check_url(),
    });

    if let Some(info) = provider.subscription_info() {
        result["subscriptionInfo"] = json!({
            "upload": info.upload,
            "download": info.download,
            "total": info.total,
            "expire": info.expire,
        });
    }

    if let Some(updated) = provider.updated_at() {
        result["updatedAt"] = json!(updated.to_rfc3339());
    }

    result
}

/// GET /providers/proxies - Get all proxy providers
pub async fn get_proxy_providers(
    State(state): State<AppState>,
) -> Json<Value> {
    let providers = state.provider_manager.proxy_providers().await;

    let mut providers_map = serde_json::Map::new();
    for (name, provider) in providers.iter() {
        providers_map.insert(name.clone(), format_proxy_provider(provider.as_ref()));
    }

    Json(json!({ "providers": providers_map }))
}

/// GET /providers/proxies/:name - Get a specific proxy provider
pub async fn get_proxy_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    debug!("Get proxy provider: {}", name);

    let provider = state.provider_manager.get_proxy_provider(&name).await
        .ok_or_else(|| ApiError::not_found("Provider"))?;

    Ok(Json(format_proxy_provider(provider.as_ref())))
}

/// PUT /providers/proxies/:name - Update (refresh) a proxy provider
pub async fn update_proxy_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    debug!("Update proxy provider: {}", name);

    let provider = state.provider_manager.get_proxy_provider(&name).await
        .ok_or_else(|| ApiError::not_found("Provider"))?;

    provider.update().await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /providers/proxies/:name/healthcheck - Health check all proxies in provider
pub async fn healthcheck_proxy_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    debug!("Health check proxy provider: {}", name);

    let provider = state.provider_manager.get_proxy_provider(&name).await
        .ok_or_else(|| ApiError::not_found("Provider"))?;

    provider.health_check().await;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /providers/proxies/:name/:proxy - Get a specific proxy from provider
pub async fn get_provider_proxy(
    State(state): State<AppState>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    debug!("Get proxy {} from provider {}", proxy_name, provider_name);

    let provider = state.provider_manager.get_proxy_provider(&provider_name).await
        .ok_or_else(|| ApiError::not_found("Provider"))?;

    let proxies = provider.proxies();
    let proxy = proxies.iter()
        .find(|p| p.name() == proxy_name)
        .ok_or_else(|| ApiError::not_found("Proxy"))?;

    Ok(Json(json!({
        "name": proxy.name(),
        "type": proxy.proxy_type().to_string(),
    })))
}

/// GET /providers/proxies/:name/:proxy/healthcheck - Test specific proxy delay
pub async fn healthcheck_provider_proxy(
    State(state): State<AppState>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
    Query(params): Query<DelayParams>,
) -> ApiResult<Json<Value>> {
    debug!("Health check proxy {} from provider {} with url: {}",
        proxy_name, provider_name, params.url);

    let provider = state.provider_manager.get_proxy_provider(&provider_name).await
        .ok_or_else(|| ApiError::not_found("Provider"))?;

    let proxies = provider.proxies();
    let _proxy = proxies.iter()
        .find(|p| p.name() == proxy_name)
        .ok_or_else(|| ApiError::not_found("Proxy"))?;

    // TODO: Implement actual URL test through proxy
    Ok(Json(json!({
        "delay": 0,
    })))
}

/// GET /providers/rules - Get all rule providers
pub async fn get_rule_providers(
    State(state): State<AppState>,
) -> Json<Value> {
    let providers = state.provider_manager.rule_providers().await;

    let mut providers_map = serde_json::Map::new();
    for (name, provider) in providers.iter() {
        providers_map.insert(name.clone(), json!({
            "name": provider.name(),
            "type": provider.vehicle_type().to_string(),
            "vehicleType": provider.vehicle_type().to_string(),
            "behavior": format!("{:?}", provider.behavior()),
            "ruleCount": provider.count().await,
        }));
    }

    Json(json!({ "providers": providers_map }))
}

/// PUT /providers/rules/:name - Update (refresh) a rule provider
pub async fn update_rule_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    debug!("Update rule provider: {}", name);

    let provider = state.provider_manager.get_rule_provider(&name).await
        .ok_or_else(|| ApiError::not_found("Provider"))?;

    provider.update().await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_json_format() {
        let provider = json!({
            "name": "subscription",
            "type": "HTTP",
            "vehicleType": "HTTP",
            "proxies": [],
            "testUrl": "http://www.gstatic.com/generate_204",
            "subscriptionInfo": {
                "upload": 0,
                "download": 1000000,
                "total": 10000000000_u64,
                "expire": 1704067200
            }
        });

        assert_eq!(provider["type"], "HTTP");
        assert!(provider["subscriptionInfo"]["total"].as_u64().unwrap() > 0);
    }
}
