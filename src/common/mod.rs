//! Common utilities and types

pub mod error;
pub mod buffer;
pub mod metadata;
pub mod net;
pub mod socks;

// Performance optimization algorithms
pub mod memory_pressure;
pub mod pool_predictor;
pub mod proxy_node_selection;
pub mod http_pool;

pub use error::{Error, Result};
pub use metadata::{ConnType, DnsMode, Metadata, Network};
