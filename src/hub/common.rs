//! Common types for REST API responses and errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// API error response
#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub message: String,
}

impl ApiError {
    pub fn new(message: impl Into<String>) -> Self {
        ApiError {
            message: message.into(),
        }
    }

    pub fn not_found(resource: &str) -> (StatusCode, Json<ApiError>) {
        (
            StatusCode::NOT_FOUND,
            Json(ApiError::new(format!("{} not found", resource))),
        )
    }

    pub fn bad_request(message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::BAD_REQUEST, Json(ApiError::new(message)))
    }

    pub fn internal(message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError::new(message)))
    }

    pub fn service_unavailable(message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::SERVICE_UNAVAILABLE, Json(ApiError::new(message)))
    }

    pub fn gateway_timeout(message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::GATEWAY_TIMEOUT, Json(ApiError::new(message)))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// Result type for API handlers
pub type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

/// Delay query parameters (for proxy delay testing)
#[derive(Debug, Deserialize)]
pub struct DelayParams {
    /// URL to test
    pub url: String,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Expected HTTP status (optional)
    pub expected: Option<u16>,
}

fn default_timeout() -> u64 {
    5000
}

/// Proxy update request body
#[derive(Debug, Deserialize)]
pub struct UpdateProxyRequest {
    /// Name of the proxy to select
    pub name: String,
}

/// Config patch request body
#[derive(Debug, Deserialize)]
pub struct ConfigPatch {
    /// HTTP proxy port
    pub port: Option<u16>,
    /// SOCKS proxy port
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    /// Redirect port
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    /// TProxy port
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    /// Mixed port
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
    /// Allow LAN connections
    #[serde(rename = "allow-lan")]
    pub allow_lan: Option<bool>,
    /// Bind address
    #[serde(rename = "bind-address")]
    pub bind_address: Option<String>,
    /// Proxy mode (rule/global/direct)
    pub mode: Option<String>,
    /// Log level
    #[serde(rename = "log-level")]
    pub log_level: Option<String>,
    /// IPv6 enabled
    pub ipv6: Option<bool>,
    /// Sniffing enabled
    pub sniffing: Option<bool>,
    /// TCP concurrent
    #[serde(rename = "tcp-concurrent")]
    pub tcp_concurrent: Option<bool>,
    /// Interface name
    #[serde(rename = "interface-name")]
    pub interface_name: Option<String>,
}

/// Config reload request body
#[derive(Debug, Deserialize)]
pub struct ConfigReload {
    /// Path to config file
    pub path: Option<String>,
    /// Raw config content
    pub payload: Option<String>,
}

/// DNS query parameters
#[derive(Debug, Deserialize)]
pub struct DnsQueryParams {
    /// Domain name to query
    pub name: String,
    /// Query type (A, AAAA, etc.)
    #[serde(rename = "type", default = "default_dns_type")]
    pub query_type: String,
}

fn default_dns_type() -> String {
    "A".to_string()
}

/// Log query parameters
#[derive(Debug, Deserialize)]
pub struct LogParams {
    /// Minimum log level (debug, info, warning, error)
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format (default or structured)
    #[serde(default)]
    pub format: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Connections query parameters
#[derive(Debug, Deserialize)]
pub struct ConnectionsParams {
    /// Update interval in milliseconds (for WebSocket)
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error() {
        let err = ApiError::new("test error");
        assert_eq!(err.message, "test error");
    }

    #[test]
    fn test_delay_params_defaults() {
        let json = r#"{"url": "http://test.com"}"#;
        let params: DelayParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.url, "http://test.com");
        assert_eq!(params.timeout, 5000);
        assert!(params.expected.is_none());
    }
}
