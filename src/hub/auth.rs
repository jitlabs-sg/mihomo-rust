//! Authentication middleware for REST API
//!
//! Implements Bearer token authentication with constant-time comparison.

use super::AppState;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;
use tracing::debug;

/// List of paths that don't require authentication
const PUBLIC_PATHS: &[&str] = &["/", "/version"];

/// Authentication middleware
///
/// Checks for Bearer token in Authorization header or token query parameter.
/// Uses constant-time comparison to prevent timing attacks.
pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth if no secret configured
    if state.secret.is_empty() {
        return Ok(next.run(req).await);
    }

    // Check if path is public
    let path = req.uri().path();
    if PUBLIC_PATHS.iter().any(|p| *p == path) {
        return Ok(next.run(req).await);
    }

    // Check WebSocket upgrade with token query param
    let is_websocket = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_websocket {
        // Extract token from query string
        if let Some(query) = req.uri().query() {
            for pair in query.split('&') {
                if let Some(token) = pair.strip_prefix("token=") {
                    let token = urlencoding::decode(token).unwrap_or_default();
                    if constant_time_eq(token.as_bytes(), state.secret.as_bytes()) {
                        debug!("WebSocket auth successful via query param");
                        return Ok(next.run(req).await);
                    }
                }
            }
        }
    }

    // Check Authorization header
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if constant_time_eq(token.as_bytes(), state.secret.as_bytes()) {
                    debug!("Auth successful via Bearer token");
                    return Ok(next.run(req).await);
                }
            }
        }
    }

    debug!("Auth failed - missing or invalid token");
    Err(StatusCode::UNAUTHORIZED)
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Use subtle crate for constant-time comparison
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"wrong"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"secret", b"secrets"));
    }

    #[test]
    fn test_public_paths() {
        assert!(PUBLIC_PATHS.contains(&"/"));
        assert!(PUBLIC_PATHS.contains(&"/version"));
        assert!(!PUBLIC_PATHS.contains(&"/proxies"));
    }
}
