//! Go fallback module
//!
//! This module implements the Go mihomo fallback mechanism for protocols
//! that are not natively implemented in Rust.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +-------------------+
//! | Rust Application |     | Go mihomo Process |
//! |                  |     |                   |
//! | +--------------+ |     | +---------------+ |
//! | | GoFallback   | | HTTP | | Snell/TUIC/  | |
//! | | Proxy        |<----->| | WireGuard    | |
//! | +--------------+ |CONNECT| +---------------+ |
//! |                  |     |                   |
//! +------------------+     +-------------------+
//!         ^                        ^
//!         |                        |
//!         v                        v
//! +------------------+     +-------------------+
//! | GoFallback       |     | go-fallback-      |
//! | Manager          |---->| config.yaml       |
//! +------------------+     +-------------------+
//! ```
//!
//! # Components
//!
//! - `GoProcessManager`: Manages the Go mihomo child process lifecycle
//! - `GoFallbackProxy`: Implements `OutboundProxy` by forwarding via HTTP CONNECT
//! - `GoFallbackManager`: Coordinates proxies and process management
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::outbound::go_fallback::GoFallbackManager;
//!
//! let manager = GoFallbackManager::with_defaults();
//! manager.initialize(&proxy_configs).await?;
//! manager.start().await?;
//!
//! // Get a Go fallback proxy
//! if let Some(proxy) = manager.get_outbound("snell-node").await {
//!     let conn = proxy.dial_tcp(&metadata).await?;
//! }
//! ```

mod manager;
mod process;
mod proxy;

pub use manager::{GoFallbackManager, GoFallbackStats, ManagerState};
pub use process::{GoProcessConfig, GoProcessManager, ProcessState};
pub use proxy::GoFallbackProxy;

/// Default port for Go fallback proxy
pub const DEFAULT_GO_FALLBACK_PORT: u16 = 17890;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are exported
        let _: ProcessState = ProcessState::Stopped;
        let _: ManagerState = ManagerState::Uninitialized;
    }
}
