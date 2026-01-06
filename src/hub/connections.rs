//! Connections endpoints
//!
//! Manages active connections (list, close).

use super::common::ApiError;
use super::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use tracing::debug;

/// GET /connections - Get all active connections
pub async fn get_connections(
    State(state): State<AppState>,
) -> Json<Value> {
    let snapshot = state.statistic.snapshot();
    Json(json!(snapshot))
}

/// DELETE /connections - Close all connections
pub async fn close_all_connections(
    State(state): State<AppState>,
) -> StatusCode {
    let count = state.statistic.close_all();
    debug!("Closed {} connections", count);
    StatusCode::NO_CONTENT
}

/// DELETE /connections/:id - Close a specific connection
pub async fn close_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    if state.statistic.close(&id) {
        debug!("Closed connection: {}", id);
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("Connection"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_format() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(id.len(), 36);
    }
}
