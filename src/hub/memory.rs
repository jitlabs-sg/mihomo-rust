//! Memory WebSocket endpoint
//!
//! Streams real-time memory usage statistics.

use super::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};

use serde_json::json;
use std::time::Duration;
use tracing::debug;

/// GET /memory - WebSocket for memory usage streaming
pub async fn memory_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(|socket| handle_memory(socket, state))
}

async fn handle_memory(mut socket: WebSocket, state: AppState) {
    debug!("Memory WebSocket connected");

    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        ticker.tick().await;

        let inuse = state.statistic.memory();
        let memory = json!({
            "inuse": inuse,
            "oslimit": 0_u64  // OS limit (reserved for future use)
        });

        match socket.send(Message::Text(memory.to_string())).await {
            Ok(_) => {}
            Err(_) => {
                debug!("Memory WebSocket disconnected");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_json_format() {
        let memory = json!({
            "inuse": 123456789_u64,
            "oslimit": 0_u64
        });

        assert!(memory["inuse"].as_u64().is_some());
        assert_eq!(memory["oslimit"], 0);
    }
}
