//! Windows Named Pipe server for IPC communication
//!
//! Provides Named Pipe support for Windows, enabling GUI clients like clash-verge-rev
//! to communicate with mihomo-rust via IPC.

use crate::Result;
use super::{create_router, AppState};

use axum::{body::Body, extract::Request};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
use tower::ServiceExt;
use tracing::{info, warn, error};

/// Start Named Pipe server for IPC communication
///
/// # Arguments
/// * `state` - Application state shared with HTTP server
/// * `pipe_name` - Named Pipe path (e.g., `\\.\pipe\mihomo-12345`)
///
/// # Example
/// ```ignore
/// start_named_pipe_server(state, r"\\.\pipe\mihomo-control").await?;
/// ```
pub async fn start_named_pipe_server(state: AppState, pipe_name: &str) -> Result<()> {
    info!("Starting Named Pipe server on {}", pipe_name);

    let router = create_router(state);

    // Configure Named Pipe options
    let mut options = ServerOptions::new();
    options.pipe_mode(PipeMode::Byte);
    // Reject remote clients for security
    options.reject_remote_clients(true);

    // Pre-create the first server instance
    let mut next_server = match options.create(pipe_name) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create Named Pipe server on {}: {}", pipe_name, e);
            return Err(e.into());
        }
    };

    info!("Named Pipe server listening on {}", pipe_name);

    // Accept loop
    loop {
        // Wait for client connection on current server
        if let Err(e) = next_server.connect().await {
            warn!("Named Pipe connect error: {}", e);
            // Recreate server instance on error
            next_server = match options.create(pipe_name) {
                Ok(s) => s,
                Err(e2) => {
                    error!("Failed to recreate Named Pipe: {}", e2);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            continue;
        }

        // Connection established - create replacement server for next connection
        let new_server = match options.create(pipe_name) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create next Named Pipe instance: {}", e);
                // Use connected server anyway, retry creating next one on next iteration
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let server = std::mem::replace(&mut next_server, new_server);

        // Wrap in TokioIo for hyper compatibility
        let io = TokioIo::new(server);

        // Clone router for this connection
        let app = router.clone();

        // Spawn connection handler
        tokio::spawn(async move {
            // Map request body type: hyper gives Request<Incoming>, axum expects Request<Body>
            let tower_service = app.map_request(|req: Request<Incoming>| req.map(Body::new));
            let hyper_service = TowerToHyperService::new(tower_service);

            // Serve the connection with upgrade support (for WebSocket)
            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                // Connection errors are common (client disconnect), only log at debug level
                tracing::debug!("Named Pipe connection closed: {:?}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_name_format() {
        let name = r"\\.\pipe\mihomo-test";
        assert!(name.starts_with(r"\\.\pipe\"));
    }
}
