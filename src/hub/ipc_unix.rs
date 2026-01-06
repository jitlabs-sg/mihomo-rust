//! Unix Domain Socket server for IPC communication
//!
//! Provides Unix Socket support for Linux/macOS, enabling GUI clients
//! to communicate with mihomo-rust via IPC.

use crate::Result;
use super::{create_router, AppState};

use std::path::Path;
use tokio::net::UnixListener;
use tracing::{info, warn, error};
use hyper_util::rt::TokioIo;
use tower::Service;

/// Start Unix Domain Socket server for IPC communication
///
/// # Arguments
/// * `state` - Application state shared with HTTP server
/// * `socket_path` - Unix socket path (e.g., `/tmp/mihomo-12345.sock`)
///
/// # Example
/// ```ignore
/// start_unix_socket_server(state, "/tmp/mihomo.sock").await?;
/// ```
pub async fn start_unix_socket_server(state: AppState, socket_path: &str) -> Result<()> {
    let path = Path::new(socket_path);

    // Remove existing socket file if it exists
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!("Failed to remove existing socket file: {}", e);
        }
    }

    info!("Starting Unix Socket server on {}", socket_path);

    // Create the Unix listener
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind Unix Socket on {}: {}", socket_path, e);
            return Err(e.into());
        }
    };

    // Set socket permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!("Failed to set socket permissions: {}", e);
        }
    }

    info!("Unix Socket server listening on {}", socket_path);

    let router = create_router(state);
    let mut make_service = router.into_make_service();

    // Accept loop for Unix socket
    loop {
        let (socket, _addr) = listener.accept().await?;
        let tower_service = make_service.call(&socket).await.unwrap();

        tokio::spawn(async move {
            let socket = TokioIo::new(socket);
            let hyper_service = hyper::service::service_fn(move |req| {
                tower_service.clone().call(req)
            });

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new()
            )
            .serve_connection(socket, hyper_service)
            .await
            {
                warn!("Unix socket connection error: {}", e);
            }
        });
    }
}

/// Cleanup Unix socket file on shutdown
pub fn cleanup_socket(socket_path: &str) {
    let path = Path::new(socket_path);
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!("Failed to cleanup socket file {}: {}", socket_path, e);
        } else {
            info!("Cleaned up socket file: {}", socket_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path_format() {
        let path = "/tmp/mihomo-12345.sock";
        assert!(path.ends_with(".sock"));
    }

    #[test]
    fn test_cleanup_nonexistent() {
        // Should not panic when socket doesn't exist
        cleanup_socket("/tmp/nonexistent-socket-12345.sock");
    }
}
