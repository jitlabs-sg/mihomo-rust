//! Error types for the gateway

use std::io;
use thiserror::Error;

/// Gateway error type
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Rule matching error: {0}")]
    Rule(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid address: {0}")]
    Address(String),

    #[error("Unsupported: {0}")]
    Unsupported(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Error::Config(msg.into())
    }

    pub fn parse<S: Into<String>>(msg: S) -> Self {
        Error::Parse(msg.into())
    }

    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Error::Protocol(msg.into())
    }

    pub fn dns<S: Into<String>>(msg: S) -> Self {
        Error::Dns(msg.into())
    }

    pub fn proxy<S: Into<String>>(msg: S) -> Self {
        Error::Proxy(msg.into())
    }

    pub fn connection<S: Into<String>>(msg: S) -> Self {
        Error::Connection(msg.into())
    }

    pub fn timeout<S: Into<String>>(msg: S) -> Self {
        Error::Timeout(msg.into())
    }

    pub fn auth<S: Into<String>>(msg: S) -> Self {
        Error::Auth(msg.into())
    }

    pub fn tls<S: Into<String>>(msg: S) -> Self {
        Error::Tls(msg.into())
    }

    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn address<S: Into<String>>(msg: S) -> Self {
        Error::Address(msg.into())
    }

    pub fn unsupported<S: Into<String>>(msg: S) -> Self {
        Error::Unsupported(msg.into())
    }

    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Error::Internal(msg.into())
    }

    pub fn network<S: Into<String>>(msg: S) -> Self {
        Error::Connection(msg.into())
    }

    pub fn io_error<S: Into<String>>(msg: S) -> Self {
        Error::Io(std::io::Error::new(std::io::ErrorKind::Other, msg.into()))
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Error::Config(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(e: tokio::time::error::Elapsed) -> Self {
        Error::Timeout(e.to_string())
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e.to_string())
    }
}

/// Result type alias using our Error
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let e = Error::config("test error");
        assert!(matches!(e, Error::Config(_)));
    }

    #[test]
    fn test_error_display() {
        let e = Error::protocol("invalid header");
        assert_eq!(e.to_string(), "Protocol error: invalid header");
    }
}
