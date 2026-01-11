//! Greedy buffering / copying utilities (latency & jitter focused).
//!
//! This module implements a greedy, non-timer-based bidirectional copy algorithm designed for
//! local proxy clients: prefer low latency and low jitter over synthetic high throughput.

use crate::Result;
use std::cmp;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const INIT_CAP: usize = 8 * 1024;
const MAX_CAP: usize = 256 * 1024;
const GROW_FACTOR: usize = 2;

const MAX_READ_SYSCALLS_PER_POLL: usize = 16;
const MAX_WRITE_SYSCALLS_PER_POLL: usize = 16;
const MAX_IO_BYTES_PER_POLL: usize = 256 * 1024;
const MAX_READ_CHUNK: usize = 64 * 1024;

pub struct GreedyBuf {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl GreedyBuf {
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == self.cap
    }

    #[inline]
    pub fn readable(&self) -> &[u8] {
        &self.buf[self.pos..self.cap]
    }

    #[inline]
    pub fn writable_len(&self) -> usize {
        self.buf.len().saturating_sub(self.cap)
    }

    #[inline]
    pub fn writable_slice(&mut self, n: usize) -> &mut [u8] {
        let start = self.cap;
        let end = self.cap + n;
        &mut self.buf[start..end]
    }

    #[inline]
    pub fn commit(&mut self, n: usize) {
        self.cap += n;
    }

    #[inline]
    pub fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.cap {
            self.pos = 0;
            self.cap = 0;
        }
    }
}

pub struct DirState {
    pub buf: GreedyBuf,
    pub target_cap: usize,
    pub eof: bool,
    shutdown: bool,
    bytes: u64,
}

impl DirState {
    fn new() -> Self {
        Self {
            buf: GreedyBuf::with_capacity(INIT_CAP),
            target_cap: INIT_CAP,
            eof: false,
            shutdown: false,
            bytes: 0,
        }
    }

    #[inline]
    fn done(&self) -> bool {
        self.eof && self.buf.is_empty() && self.shutdown
    }
}

#[inline]
fn clamp_target_cap(target_cap: usize) -> usize {
    target_cap.clamp(INIT_CAP, MAX_CAP)
}

fn fill_greedy<R: AsyncRead + Unpin>(
    mut src: Pin<&mut R>,
    cx: &mut Context<'_>,
    dir: &mut DirState,
) -> Result<bool> {
    debug_assert!(dir.buf.is_empty(), "fill_greedy expects empty buffer");

    let mut made_progress = false;
    let mut syscalls = 0usize;
    let mut bytes_budget = MAX_IO_BYTES_PER_POLL;

    while !dir.eof
        && syscalls < MAX_READ_SYSCALLS_PER_POLL
        && bytes_budget > 0
        && dir.buf.writable_len() > 0
    {
        let want = cmp::min(
            cmp::min(dir.buf.writable_len(), bytes_budget),
            MAX_READ_CHUNK,
        );

        let mut read_buf = ReadBuf::new(dir.buf.writable_slice(want));
        match src.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    dir.eof = true;
                    break;
                }
                dir.buf.commit(n);
                made_progress = true;
                syscalls += 1;
                bytes_budget -= n;

                if dir.buf.writable_len() == 0 && dir.target_cap < MAX_CAP {
                    dir.target_cap = clamp_target_cap(dir.target_cap.saturating_mul(GROW_FACTOR));
                    break;
                }
            }
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Pending => break,
        }
    }

    Ok(made_progress)
}

fn flush_greedy<W: AsyncWrite + Unpin>(
    mut dst: Pin<&mut W>,
    cx: &mut Context<'_>,
    dir: &mut DirState,
) -> Result<bool> {
    let mut made_progress = false;
    let mut syscalls = 0usize;
    let mut bytes_budget = MAX_IO_BYTES_PER_POLL;

    while !dir.buf.is_empty() && syscalls < MAX_WRITE_SYSCALLS_PER_POLL && bytes_budget > 0 {
        let chunk = dir.buf.readable();
        let max = cmp::min(chunk.len(), bytes_budget);
        let chunk = &chunk[..max];

        match dst.as_mut().poll_write(cx, chunk) {
            Poll::Ready(Ok(0)) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero").into());
            }
            Poll::Ready(Ok(n)) => {
                dir.buf.consume(n);
                dir.bytes = dir.bytes.saturating_add(n as u64);
                made_progress = true;
                syscalls += 1;
                bytes_budget -= n;
            }
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Pending => break,
        }
    }

    Ok(made_progress)
}

fn pump_one_direction<R, W>(
    mut src: Pin<&mut R>,
    mut dst: Pin<&mut W>,
    cx: &mut Context<'_>,
    dir: &mut DirState,
) -> Result<bool>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncRead + AsyncWrite + Unpin,
{
    let mut made_progress = false;

    if dir.buf.is_empty() && dir.buf.capacity() != dir.target_cap {
        dir.buf = GreedyBuf::with_capacity(clamp_target_cap(dir.target_cap));
    }

    // Greedy write first.
    made_progress |= flush_greedy(dst.as_mut(), cx, dir)?;

    if !dir.buf.is_empty() {
        return Ok(made_progress);
    }

    if dir.eof && !dir.shutdown {
        match dst.as_mut().poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                dir.shutdown = true;
                made_progress = true;
            }
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Pending => return Ok(made_progress),
        }
    }

    if !dir.eof {
        made_progress |= fill_greedy(src.as_mut(), cx, dir)?;
        made_progress |= flush_greedy(dst.as_mut(), cx, dir)?;

        if dir.eof && dir.buf.is_empty() && !dir.shutdown {
            match dst.as_mut().poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    dir.shutdown = true;
                    made_progress = true;
                }
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Pending => return Ok(made_progress),
            }
        }
    }

    Ok(made_progress)
}

pub async fn greedy_copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    struct Fut<'a, A, B> {
        a: &'a mut A,
        b: &'a mut B,
        a2b: DirState,
        b2a: DirState,
    }

    impl<'a, A, B> std::future::Future for Fut<'a, A, B>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        type Output = Result<(u64, u64)>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            loop {
                let this = self.as_mut().get_mut();
                let mut progress = false;

                // `self.a` and `self.b` are distinct `&mut` references coming from the caller.
                // We need to use them in both directions without fighting the borrow checker over
                // overlapping borrows of `self`'s fields.
                let a_ptr = this.a as *mut A;
                let b_ptr = this.b as *mut B;

                // a -> b
                match pump_one_direction(
                    Pin::new(unsafe { &mut *a_ptr }),
                    Pin::new(unsafe { &mut *b_ptr }),
                    cx,
                    &mut this.a2b,
                ) {
                    Ok(p) => progress |= p,
                    Err(e) => return Poll::Ready(Err(e)),
                }

                // b -> a
                match pump_one_direction(
                    Pin::new(unsafe { &mut *b_ptr }),
                    Pin::new(unsafe { &mut *a_ptr }),
                    cx,
                    &mut this.b2a,
                ) {
                    Ok(p) => progress |= p,
                    Err(e) => return Poll::Ready(Err(e)),
                }

                if this.a2b.done() && this.b2a.done() {
                    return Poll::Ready(Ok((this.a2b.bytes, this.b2a.bytes)));
                }

                if !progress {
                    return Poll::Pending;
                }
            }
        }
    }

    Fut {
        a,
        b,
        a2b: DirState::new(),
        b2a: DirState::new(),
    }
    .await
}
