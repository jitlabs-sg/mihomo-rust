//! Logs WebSocket endpoint
//!
//! Streams real-time logs with level filtering.

use super::common::LogParams;
use super::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::Response,
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;

/// Log event for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Log level (debug, info, warning, error)
    #[serde(rename = "type")]
    pub level: String,
    /// Log message
    pub payload: String,
}

impl LogEvent {
    pub fn new(level: &str, payload: &str) -> Self {
        LogEvent {
            level: level.to_string(),
            payload: payload.to_string(),
        }
    }

    /// Check if this log should be shown at the given minimum level
    pub fn should_show(&self, min_level: &str) -> bool {
        let self_priority = level_priority(&self.level);
        let min_priority = level_priority(min_level);
        self_priority >= min_priority
    }
}

/// Get priority for log level (higher = more severe)
fn level_priority(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "debug" => 0,
        "info" => 1,
        "warning" | "warn" => 2,
        "error" => 3,
        "silent" => 4,
        _ => 1,
    }
}

/// Structured log format
#[derive(Debug, Clone, Serialize)]
pub struct StructuredLog {
    pub time: String,
    pub level: String,
    pub message: String,
    pub fields: Vec<String>,
}

/// GET /logs - WebSocket for log streaming
pub async fn logs_ws(
    ws: WebSocketUpgrade,
    Query(params): Query<LogParams>,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_logs(socket, state, params))
}

async fn handle_logs(mut socket: WebSocket, state: AppState, params: LogParams) {
    debug!("Logs WebSocket connected with level: {}", params.level);

    let mut rx = state.log_tx.subscribe();
    let is_structured = params.format.as_deref() == Some("structured");

    loop {
        match rx.recv().await {
            Ok(event) => {
                if !event.should_show(&params.level) {
                    continue;
                }

                let msg = if is_structured {
                    json!({
                        "time": chrono::Utc::now().format("%H:%M:%S").to_string(),
                        "level": event.level,
                        "message": event.payload,
                        "fields": []
                    })
                } else {
                    json!({
                        "type": event.level,
                        "payload": event.payload
                    })
                };

                if socket.send(Message::Text(msg.to_string())).await.is_err() {
                    debug!("Logs WebSocket disconnected");
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                debug!("Log channel closed");
                break;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                debug!("Log receiver lagged by {} messages", n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_priority() {
        assert!(level_priority("debug") < level_priority("info"));
        assert!(level_priority("info") < level_priority("warning"));
        assert!(level_priority("warning") < level_priority("error"));
    }

    #[test]
    fn test_log_event_should_show() {
        let event = LogEvent::new("info", "test message");

        assert!(event.should_show("debug"));
        assert!(event.should_show("info"));
        assert!(!event.should_show("warning"));
        assert!(!event.should_show("error"));
    }
}
