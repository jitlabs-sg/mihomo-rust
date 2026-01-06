//! Connection utilities

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional copy between two streams
pub struct BidirectionalCopy<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: CopyDirection,
    b_to_a: CopyDirection,
}

#[derive(Default)]
struct CopyDirection {
    bytes_copied: u64,
    done: bool,
}

impl<'a, A, B> BidirectionalCopy<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(a: &'a mut A, b: &'a mut B) -> Self {
        BidirectionalCopy {
            a,
            b,
            a_to_b: CopyDirection::default(),
            b_to_a: CopyDirection::default(),
        }
    }
}

/// Track bytes transferred through a connection
pub struct TrackedStream<S> {
    inner: S,
    upload: u64,
    download: u64,
}

impl<S> TrackedStream<S> {
    pub fn new(inner: S) -> Self {
        TrackedStream {
            inner,
            upload: 0,
            download: 0,
        }
    }

    pub fn upload(&self) -> u64 {
        self.upload
    }

    pub fn download(&self) -> u64 {
        self.download
    }

    pub fn total(&self) -> u64 {
        self.upload + self.download
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            self.download += (after - before) as u64;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.upload += *n as u64;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Buffered copy helper
pub struct CopyBuffer {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl CopyBuffer {
    pub fn new() -> Self {
        CopyBuffer {
            buf: vec![0; 8192].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    pub fn with_size(size: usize) -> Self {
        CopyBuffer {
            buf: vec![0; size].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_buffer_creation() {
        let buf = CopyBuffer::new();
        assert_eq!(buf.buf.len(), 8192);
        assert_eq!(buf.pos, 0);
        assert_eq!(buf.cap, 0);
    }

    #[test]
    fn test_copy_buffer_custom_size() {
        let buf = CopyBuffer::with_size(4096);
        assert_eq!(buf.buf.len(), 4096);
    }
}
