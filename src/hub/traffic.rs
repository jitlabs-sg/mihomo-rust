//! Traffic WebSocket endpoint
//!
//! Streams real-time traffic statistics every second.

use super::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures_util::SinkExt;
use serde_json::json;
use std::time::Duration;
use tracing::debug;

/// GET /traffic - WebSocket for traffic streaming
pub async fn traffic_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(|socket| handle_traffic(socket, state))
}

async fn handle_traffic(mut socket: WebSocket, state: AppState) {
    debug!("Traffic WebSocket connected");

    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        ticker.tick().await;

        let (up, down) = state.statistic.now();
        let traffic = json!({
            "up": up,
            "down": down
        });

        match socket.send(Message::Text(traffic.to_string())).await {
            Ok(_) => {}
            Err(_) => {
                debug!("Traffic WebSocket disconnected");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_json_format() {
        let traffic = json!({
            "up": 12345_i64,
            "down": 67890_i64
        });

        assert_eq!(traffic["up"], 12345);
        assert_eq!(traffic["down"], 67890);
    }
}
