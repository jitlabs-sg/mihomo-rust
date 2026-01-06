//! Inbound adapters (listeners)

mod http;
mod mixed;
mod socks5;

pub use http::HttpListener;
pub use mixed::MixedListener;
pub use socks5::Socks5Listener;

use crate::Result;
use async_trait::async_trait;

/// Trait for inbound listeners
#[async_trait]
pub trait InboundListener: Send + Sync {
    /// Get listener name
    fn name(&self) -> &str;

    /// Start the listener
    async fn start(&self) -> Result<()>;

    /// Stop the listener
    async fn stop(&self) -> Result<()>;

    /// Check if listener is running
    fn is_running(&self) -> bool;
}
