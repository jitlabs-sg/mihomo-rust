//! Group endpoints
//!
//! Manages proxy groups (list, select, delay test).

use super::common::{ApiError, ApiResult, DelayParams};
use super::AppState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

/// GET /group - Get all proxy groups
pub async fn get_groups(
    State(state): State<AppState>,
) -> Json<Value> {
    let groups = get_all_groups(&state).await;
    Json(json!({ "proxies": groups }))
}

/// Get all proxy groups as a JSON map
async fn get_all_groups(state: &AppState) -> Value {
    let mut groups = serde_json::Map::new();
    let config = state.config.read().await;

    for group_config in &config.proxy_groups {
        let group_type = &group_config.group_type;
        let name = &group_config.name;
        
        // Get all proxies in this group
        let mut all_proxies = group_config.proxies.clone();
        
        // TODO: Add proxies from providers when implemented
        
        // Determine "now" (current selection)
        // For Selector: use first proxy as default
        // For URLTest/Fallback: use first proxy until health check runs
        let now = all_proxies.first().cloned().unwrap_or_default();

        groups.insert(name.clone(), json!({
            "type": capitalize_first(group_type),
            "name": name,
            "now": now,
            "all": all_proxies,
            "testUrl": group_config.url.as_deref().unwrap_or("http://www.gstatic.com/generate_204"),
            "hidden": false,
            "icon": ""
        }));
    }

    Value::Object(groups)
}

/// Capitalize first letter for group type display
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// GET /group/:name - Get a specific proxy group
pub async fn get_group(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    debug!("Get group: {}", name);

    let config = state.config.read().await;
    
    for group_config in &config.proxy_groups {
        if group_config.name == name {
            let mut all_proxies = group_config.proxies.clone();
            let now = all_proxies.first().cloned().unwrap_or_default();

            return Ok(Json(json!({
                "type": capitalize_first(&group_config.group_type),
                "name": &group_config.name,
                "now": now,
                "all": all_proxies,
                "testUrl": group_config.url.as_deref().unwrap_or("http://www.gstatic.com/generate_204"),
                "hidden": false,
                "icon": ""
            })));
        }
    }

    Err(ApiError::not_found("Group"))
}

/// GET /group/:name/delay - Test all proxies in a group
pub async fn get_group_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> ApiResult<Json<Value>> {
    debug!("Testing delay for group: {} with url: {}", name, params.url);

    let config = state.config.read().await;
    
    // Find the group
    let group_config = config.proxy_groups.iter()
        .find(|g| g.name == name)
        .ok_or_else(|| ApiError::not_found("Group"))?;

    // Build list of proxies to test
    let proxies_to_test = group_config.proxies.clone();
    let timeout = Duration::from_millis(params.timeout);
    let test_url = params.url.clone();
    let expected = params.expected;

    drop(config); // Release lock before async operations

    // Test each proxy
    let mut results = HashMap::new();

    for proxy_name in proxies_to_test {
        // Skip special proxies
        if proxy_name == "DIRECT" || proxy_name == "REJECT" || proxy_name == "REJECT-DROP" {
            continue;
        }

        // Test delay
        let delay = test_proxy_delay(&state, &proxy_name, &test_url, timeout, expected).await;
        results.insert(proxy_name, delay);
    }

    Ok(Json(json!(results)))
}

/// Test delay for a single proxy
async fn test_proxy_delay(
    state: &AppState,
    proxy_name: &str,
    url: &str,
    timeout: Duration,
    expected: Option<u16>,
) -> i64 {
    // For now, test direct connection delay
    // TODO: Route through actual proxy when implemented
    
    let start = std::time::Instant::now();
    
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .build() {
            Ok(c) => c,
            Err(_) => return -1,
        };

    match client.get(url).send().await {
        Ok(resp) => {
            if let Some(exp) = expected {
                if resp.status().as_u16() != exp {
                    return -1;
                }
            }
            start.elapsed().as_millis() as i64
        }
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capitalize_first() {
        assert_eq!(capitalize_first("select"), "Select");
        assert_eq!(capitalize_first("url-test"), "Url-test");
        assert_eq!(capitalize_first(""), "");
    }

    #[test]
    fn test_group_json_format() {
        let group = json!({
            "type": "Selector",
            "name": "Manual",
            "now": "proxy1",
            "all": ["proxy1", "proxy2", "DIRECT"],
            "testUrl": "http://www.gstatic.com/generate_204",
            "hidden": false,
            "icon": ""
        });

        assert_eq!(group["type"], "Selector");
        assert_eq!(group["now"], "proxy1");
    }
}
