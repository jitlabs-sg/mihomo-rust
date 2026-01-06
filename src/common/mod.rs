//! Common utilities and types

pub mod error;
pub mod metadata;
pub mod net;
pub mod socks;

pub use error::{Error, Result};
pub use metadata::{ConnType, DnsMode, Metadata, Network};
