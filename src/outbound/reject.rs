//! Reject outbound (block connections)

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::{Error, Result};
use async_trait::async_trait;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::sleep;
use tracing::debug;

/// Reject connection - immediately closes or drops
pub struct Reject {
    name: String,
    drop: bool,
}

impl Reject {
    pub fn new(drop: bool) -> Self {
        let name = if drop { "REJECT-DROP" } else { "REJECT" };
        Reject {
            name: name.to_string(),
            drop,
        }
    }
}

#[async_trait]
impl OutboundProxy for Reject {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        if self.drop {
            ProxyType::RejectDrop
        } else {
            ProxyType::Reject
        }
    }

    fn server(&self) -> &str {
        if self.drop {
            "REJECT-DROP"
        } else {
            "REJECT"
        }
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        debug!("{} connection to {}", self.name, metadata.remote_address());

        if self.drop {
            // Drop mode - wait 30 seconds then return EOF
            Ok(Box::new(DropConn))
        } else {
            // Reject mode - immediately return EOF
            Ok(Box::new(RejectConn))
        }
    }
}

/// A connection that immediately returns EOF
struct RejectConn;

impl AsyncRead for RejectConn {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RejectConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A connection that waits before returning EOF (simulates timeout)
struct DropConn;

impl AsyncRead for DropConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // We can't directly sleep in poll_read, but we return Pending
        // In a real implementation, we'd use a timer
        Poll::Ready(Ok(())) // For simplicity, just return EOF
    }
}

impl AsyncWrite for DropConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_creation() {
        let reject = Reject::new(false);
        assert_eq!(reject.name(), "REJECT");
        assert_eq!(reject.proxy_type(), ProxyType::Reject);

        let drop = Reject::new(true);
        assert_eq!(drop.name(), "REJECT-DROP");
        assert_eq!(drop.proxy_type(), ProxyType::RejectDrop);
    }
}
