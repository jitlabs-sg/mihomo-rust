//! HTTP Client with connection pooling through proxy tunnel
//!
//! This module provides an HTTP client that pools connections to target servers
//! through the proxy tunnel, similar to Go's http.Client with custom DialContext.

use crate::common::Metadata;
use crate::outbound::ProxyConnection;
use crate::tunnel::Tunnel;
use crate::{Error, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::{Request, Response};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::trace;

/// Maximum idle connections per target
const MAX_IDLE_PER_TARGET: usize = 8;

/// Connection idle timeout
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Key for pooled connections
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct PoolKey {
    host: String,
    port: u16,
}

/// A pooled HTTP/1 sender
struct PooledSender {
    sender: http1::SendRequest<Full<Bytes>>,
    created_at: Instant,
    last_used: Instant,
}

impl PooledSender {
    fn is_stale(&self) -> bool {
        self.last_used.elapsed() > IDLE_TIMEOUT
    }

    fn is_ready(&mut self) -> bool {
        self.sender.is_ready()
    }
}

/// HTTP Client with connection pooling
///
/// Maintains a pool of HTTP/1 connections to target servers, established
/// through the proxy tunnel. This dramatically reduces latency for HTTP
/// proxy requests by reusing connections.
pub struct PooledHttpClient {
    tunnel: Arc<Tunnel>,
    /// Pool of ready-to-use HTTP/1 senders
    pool: Mutex<HashMap<PoolKey, Vec<PooledSender>>>,
}

impl PooledHttpClient {
    /// Create a new pooled HTTP client
    pub fn new(tunnel: Arc<Tunnel>) -> Self {
        Self {
            tunnel,
            pool: Mutex::new(HashMap::new()),
        }
    }

    /// Send an HTTP request through the tunnel with connection pooling
    ///
    /// Returns the sender back to the pool after use for connection reuse.
    pub async fn send_request(
        &self,
        peer_addr: std::net::SocketAddr,
        host: &str,
        port: u16,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>> {
        let key = PoolKey {
            host: host.to_string(),
            port,
        };

        // Try to get a pooled sender first
        if let Some(mut sender) = self.acquire_sender(&key) {
            // Use pooled connection
            trace!("Using pooled connection for {}:{}", host, port);
            let response = sender.send_request(request).await
                .map_err(|e| Error::connection(format!("HTTP request failed: {}", e)))?;

            // Return sender to pool if still usable
            if sender.is_ready() {
                self.release_sender(key, sender);
            }
            return Ok(response);
        }

        // No pooled connection, create new one through tunnel
        let metadata = Metadata::tcp()
            .with_source(peer_addr)
            .with_host(host.to_string())
            .with_dst_port(port);

        let (conn, _conn_id) = self.tunnel.handle_tcp_with_dialer(&metadata).await?;

        // Wrap the ProxyConnection for hyper
        let io = ProxyConnectionIO::new(conn);

        // Perform HTTP/1 handshake
        let (mut sender, connection) = http1::handshake(io).await
            .map_err(|e| Error::connection(format!("HTTP handshake failed: {}", e)))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                trace!("HTTP connection ended: {}", e);
            }
        });

        // Send request
        let response = sender.send_request(request).await
            .map_err(|e| Error::connection(format!("HTTP request failed: {}", e)))?;

        // Return sender to pool if still usable
        // Note: is_ready() will be false until response body is fully consumed
        // Since we return Response<Incoming> to caller, body isn't consumed yet
        let is_ready = sender.is_ready();
        trace!("New connection to {}:{} - sender.is_ready() = {}", host, port, is_ready);
        if is_ready {
            self.release_sender(key, sender);
        }

        Ok(response)
    }

    /// Try to acquire a sender from the pool
    fn acquire_sender(&self, key: &PoolKey) -> Option<http1::SendRequest<Full<Bytes>>> {
        let mut pool = self.pool.lock();

        if let Some(senders) = pool.get_mut(key) {
            // Remove stale connections
            senders.retain(|s| !s.is_stale());

            // Find a ready sender
            while let Some(mut pooled) = senders.pop() {
                if pooled.is_ready() && !pooled.is_stale() {
                    return Some(pooled.sender);
                }
            }
        }

        None
    }

    /// Return a sender to the pool
    fn release_sender(&self, key: PoolKey, sender: http1::SendRequest<Full<Bytes>>) {
        let mut pool = self.pool.lock();

        let senders = pool.entry(key.clone()).or_insert_with(Vec::new);

        // Clean up stale connections
        senders.retain(|s| !s.is_stale());

        // Add if under limit
        if senders.len() < MAX_IDLE_PER_TARGET {
            senders.push(PooledSender {
                sender,
                created_at: Instant::now(),
                last_used: Instant::now(),
            });
            trace!("Returned connection to pool for {}:{}", key.host, key.port);
        }
    }

    /// Clean up stale connections
    pub fn cleanup(&self) {
        let mut pool = self.pool.lock();
        for senders in pool.values_mut() {
            senders.retain(|s| !s.is_stale());
        }
        pool.retain(|_, senders| !senders.is_empty());
    }

    /// Get pool statistics
    pub fn stats(&self) -> usize {
        self.pool.lock().values().map(|v| v.len()).sum()
    }
}

/// Wrapper to make ProxyConnection compatible with hyper's IO traits
struct ProxyConnectionIO {
    inner: Box<dyn ProxyConnection>,
}

impl ProxyConnectionIO {
    fn new(conn: Box<dyn ProxyConnection>) -> Self {
        Self { inner: conn }
    }
}

impl AsyncRead for ProxyConnectionIO {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyConnectionIO {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// hyper requires Unpin
impl Unpin for ProxyConnectionIO {}

// hyper-util requires these additional traits
impl hyper::rt::Read for ProxyConnectionIO {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Get mutable access to inner
        let this = self.get_mut();

        // Create a temporary buffer
        unsafe {
            let slice = buf.as_mut();
            let mut read_buf = ReadBuf::uninit(slice);

            match Pin::new(&mut *this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled().len();
                    buf.advance(filled);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

impl hyper::rt::Write for ProxyConnectionIO {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_key() {
        let key1 = PoolKey { host: "example.com".to_string(), port: 80 };
        let key2 = PoolKey { host: "example.com".to_string(), port: 80 };
        let key3 = PoolKey { host: "example.com".to_string(), port: 443 };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
