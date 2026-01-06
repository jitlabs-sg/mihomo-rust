//! Rules endpoint
//!
//! Lists all configured routing rules.

use super::AppState;
use axum::{extract::State, Json};
use serde_json::{json, Value};

/// GET /rules - Get all rules
pub async fn get_rules(
    State(state): State<AppState>,
) -> Json<Value> {
    let rules = get_all_rules(&state).await;
    Json(json!({ "rules": rules }))
}

/// Get all rules as a JSON array
async fn get_all_rules(state: &AppState) -> Vec<Value> {
    let mut rules = Vec::new();

    // Get rules from config
    let config = state.config.read().await;
    for rule_str in &config.rules {
        // Parse rule string: TYPE,payload,target[,no-resolve]
        let parts: Vec<&str> = rule_str.split(',').collect();
        if parts.len() >= 2 {
            let rule_type = parts[0].trim();
            let (payload, proxy) = if rule_type.to_uppercase() == "MATCH" {
                ("".to_string(), parts[1].trim().to_string())
            } else if parts.len() >= 3 {
                (parts[1].trim().to_string(), parts[2].trim().to_string())
            } else {
                continue;
            };

            rules.push(json!({
                "type": rule_type,
                "payload": payload,
                "proxy": proxy,
                "size": -1  // -1 for regular rules, count for GEOIP/GEOSITE
            }));
        }
    }

    // Add default MATCH rule if not present
    if rules.is_empty() || !rules.iter().any(|r| r["type"].as_str() == Some("MATCH")) {
        rules.push(json!({
            "type": "MATCH",
            "payload": "",
            "proxy": "DIRECT",
            "size": -1
        }));
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_json_format() {
        let rule = json!({
            "type": "DOMAIN-SUFFIX",
            "payload": "google.com",
            "proxy": "PROXY",
            "size": -1
        });

        assert_eq!(rule["type"], "DOMAIN-SUFFIX");
        assert_eq!(rule["payload"], "google.com");
        assert_eq!(rule["proxy"], "PROXY");
        assert_eq!(rule["size"], -1);
    }
}
