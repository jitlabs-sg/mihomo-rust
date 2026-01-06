//! DNS endpoints
//!
//! Provides DNS query and cache management.

use super::common::{ApiError, ApiResult, DnsQueryParams};
use super::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use tracing::debug;

/// GET /dns/query - Query DNS
pub async fn dns_query(
    State(state): State<AppState>,
    Query(params): Query<DnsQueryParams>,
) -> ApiResult<Json<Value>> {
    debug!("DNS query: {} type: {}", params.name, params.query_type);

    // Perform DNS query
    match state.dns_resolver.resolve_all(&params.name).await {
        Ok(ips) => {
            let answers: Vec<Value> = ips
                .iter()
                .map(|ip| {
                    json!({
                        "name": params.name,
                        "type": if ip.is_ipv4() { 1 } else { 28 },
                        "TTL": 300,
                        "data": ip.to_string()
                    })
                })
                .collect();

            Ok(Json(json!({
                "Status": 0,
                "Question": [{
                    "name": params.name,
                    "type": match params.query_type.as_str() {
                        "A" => 1,
                        "AAAA" => 28,
                        "CNAME" => 5,
                        "MX" => 15,
                        "TXT" => 16,
                        _ => 1
                    }
                }],
                "Answer": answers
            })))
        }
        Err(e) => {
            debug!("DNS query failed: {}", e);
            Ok(Json(json!({
                "Status": 2,  // SERVFAIL
                "Question": [{
                    "name": params.name,
                    "type": 1
                }],
                "Answer": []
            })))
        }
    }
}

/// POST /cache/fakeip/flush - Flush FakeIP cache
pub async fn flush_fakeip_cache(
    State(state): State<AppState>,
) -> StatusCode {
    debug!("Flushing FakeIP cache");

    // Clear FakeIP cache (part of DNS cache)
    state.dns_resolver.clear_cache();

    StatusCode::NO_CONTENT
}

/// POST /cache/dns/flush - Flush DNS cache
pub async fn flush_dns_cache(
    State(state): State<AppState>,
) -> StatusCode {
    debug!("Flushing DNS cache");

    // Clear the entire DNS cache
    state.dns_resolver.clear_cache();

    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_response_format() {
        let response = json!({
            "Status": 0,
            "Question": [{
                "name": "example.com",
                "type": 1
            }],
            "Answer": [{
                "name": "example.com",
                "type": 1,
                "TTL": 300,
                "data": "93.184.216.34"
            }]
        });

        assert_eq!(response["Status"], 0);
        assert_eq!(response["Answer"][0]["type"], 1);
    }
}
