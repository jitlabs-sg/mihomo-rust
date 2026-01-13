//! Greedy buffering / copying utilities (latency & jitter focused).
//!
//! This module implements a greedy, non-timer-based bidirectional copy algorithm designed for
//! local proxy clients: prefer low latency and low jitter over synthetic high throughput.

use crate::Result;
use std::cmp;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const INIT_CAP: usize = 8 * 1024;
const MAX_CAP: usize = 256 * 1024;
const GROW_FACTOR: usize = 2;

const MAX_READ_SYSCALLS_PER_POLL: usize = 16;
const MAX_WRITE_SYSCALLS_PER_POLL: usize = 16;
const MAX_IO_BYTES_PER_POLL: usize = 256 * 1024;
const MAX_READ_CHUNK: usize = 64 * 1024;

const MAX_BIDIR_SYSCALLS_PER_POLL: usize =
    2 * (MAX_READ_SYSCALLS_PER_POLL + MAX_WRITE_SYSCALLS_PER_POLL);
const MAX_BIDIR_WRITE_BYTES_PER_POLL: usize = 2 * MAX_IO_BYTES_PER_POLL;

#[derive(Clone, Copy)]
struct StepBudget {
    syscalls: usize,
    write_bytes: usize,
}

#[inline]
fn clamp_f64(x: f64, lo: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

fn awa_syscall_split(now: Instant, a: &DirState, b: &DirState, max_syscalls: usize) -> (usize, usize) {
    let n = max_syscalls;
    if n == 0 {
        return (0, 0);
    }
    if a.done() && b.done() {
        return (0, 0);
    }
    if a.done() {
        return (0, n);
    }
    if b.done() {
        return (n, 0);
    }
    if n == 1 {
        let idle_a_ms = now.duration_since(a.last_activity).as_millis() as f64;
        let idle_b_ms = now.duration_since(b.last_activity).as_millis() as f64;
        let choose_a = idle_a_ms >= idle_b_ms;
        return if choose_a { (1, 0) } else { (0, 1) };
    }

    let pending_a = a.buf.readable().len() as f64;
    let pending_b = b.buf.readable().len() as f64;
    let pending_sum = pending_a + pending_b;

    let backlog_a = if pending_sum > 0.0 {
        pending_a / pending_sum
    } else {
        0.5
    };
    let backlog_b = 1.0 - backlog_a;

    let mut ratio = (a.bytes.saturating_add(1)) as f64 / (b.bytes.saturating_add(1)) as f64;
    ratio = clamp_f64(ratio, 1.0 / 64.0, 64.0);
    let hist_a = ratio / (1.0 + ratio);
    let hist_b = 1.0 - hist_a;

    let gamma = 0.2;
    let mix_a = (1.0 - gamma) * backlog_a + gamma * hist_a;
    let mix_b = (1.0 - gamma) * backlog_b + gamma * hist_b;

    let idle_a_ms = now.duration_since(a.last_activity).as_millis() as f64;
    let idle_b_ms = now.duration_since(b.last_activity).as_millis() as f64;
    let age_tau_ms = 50.0;
    let age_max_extra = 1.0;

    let boost_a = 1.0 + (idle_a_ms / age_tau_ms).min(1.0) * age_max_extra;
    let boost_b = 1.0 + (idle_b_ms / age_tau_ms).min(1.0) * age_max_extra;

    let score_a = mix_a * boost_a;
    let score_b = mix_b * boost_b;
    let score_sum = score_a + score_b;
    let share_a = if score_sum > 0.0 {
        score_a / score_sum
    } else {
        0.5
    };

    let mut sa = ((n as f64) * share_a).round() as usize;
    sa = sa.clamp(1, n - 1);
    let sb = n - sa;
    (sa, sb)
}

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
    last_activity: Instant,
}

impl DirState {
    fn new() -> Self {
        Self {
            buf: GreedyBuf::with_capacity(INIT_CAP),
            target_cap: INIT_CAP,
            eof: false,
            shutdown: false,
            bytes: 0,
            last_activity: Instant::now(),
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
    budget: &mut StepBudget,
) -> Result<bool> {
    debug_assert!(dir.buf.is_empty(), "fill_greedy expects empty buffer");

    let mut made_progress = false;
    let mut syscalls = 0usize;

    while !dir.eof
        && syscalls < MAX_READ_SYSCALLS_PER_POLL
        && budget.syscalls > 0
        && budget.write_bytes > 0
        && dir.buf.writable_len() > 0
    {
        let want = cmp::min(dir.buf.writable_len(), MAX_READ_CHUNK);

        let mut read_buf = ReadBuf::new(dir.buf.writable_slice(want));    
        match src.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                budget.syscalls -= 1;
                dir.last_activity = Instant::now();
                made_progress = true;
                if n == 0 {
                    dir.eof = true;
                    break;
                }
                dir.buf.commit(n);
                syscalls += 1;

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
    budget: &mut StepBudget,
) -> Result<bool> {
    let mut made_progress = false;
    let mut syscalls = 0usize;

    while !dir.buf.is_empty()
        && syscalls < MAX_WRITE_SYSCALLS_PER_POLL
        && budget.syscalls > 0
        && budget.write_bytes > 0
    {
        let chunk = dir.buf.readable();
        let max = cmp::min(cmp::min(chunk.len(), budget.write_bytes), MAX_READ_CHUNK);
        let chunk = &chunk[..max];

        match dst.as_mut().poll_write(cx, chunk) {
            Poll::Ready(Ok(0)) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero").into());
            }
            Poll::Ready(Ok(n)) => {
                dir.buf.consume(n);
                dir.bytes = dir.bytes.saturating_add(n as u64);
                dir.last_activity = Instant::now();
                made_progress = true;
                syscalls += 1;
                budget.syscalls -= 1;
                budget.write_bytes -= n;
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
    budget: &mut StepBudget,
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
    made_progress |= flush_greedy(dst.as_mut(), cx, dir, budget)?;
    if budget.syscalls == 0 {
        return Ok(made_progress);
    }

    if !dir.buf.is_empty() {
        return Ok(made_progress);
    }

    if dir.eof && !dir.shutdown {
        if budget.syscalls == 0 {
            return Ok(made_progress);
        }
        match dst.as_mut().poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                dir.shutdown = true;
                made_progress = true;
                budget.syscalls -= 1;
                dir.last_activity = Instant::now();
            }
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Pending => return Ok(made_progress),
        }
    }

    if !dir.eof && budget.syscalls > 0 && budget.write_bytes > 0 {
        made_progress |= fill_greedy(src.as_mut(), cx, dir, budget)?;
        if budget.syscalls == 0 {
            return Ok(made_progress);
        }
        made_progress |= flush_greedy(dst.as_mut(), cx, dir, budget)?;

        if dir.eof && dir.buf.is_empty() && !dir.shutdown && budget.syscalls > 0 {
            match dst.as_mut().poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    dir.shutdown = true;
                    made_progress = true;
                    budget.syscalls -= 1;
                    dir.last_activity = Instant::now();
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
            let this = self.as_mut().get_mut();

            if this.a2b.done() && this.b2a.done() {
                return Poll::Ready(Ok((this.a2b.bytes, this.b2a.bytes)));
            }

            // `self.a` and `self.b` are distinct `&mut` references coming from the caller.
            // We need to use them in both directions without fighting the borrow checker over
            // overlapping borrows of `self`'s fields.
            let a_ptr = this.a as *mut A;
            let b_ptr = this.b as *mut B;

            let now = Instant::now();
            let max_syscalls = MAX_BIDIR_SYSCALLS_PER_POLL;
            let (syscalls_a, syscalls_b) = awa_syscall_split(now, &this.a2b, &this.b2a, max_syscalls);
            let total_weight = syscalls_a + syscalls_b;

            let mut syscalls_left = max_syscalls;
            let mut write_bytes_left = MAX_BIDIR_WRITE_BYTES_PER_POLL;
            let mut err = total_weight / 2;
            let mut made_progress = false;

            while syscalls_left > 0 {
                if this.a2b.done() && this.b2a.done() {
                    return Poll::Ready(Ok((this.a2b.bytes, this.b2a.bytes)));
                }
                if total_weight == 0 {
                    break;
                }

                err += syscalls_a;
                let prefer_a = if err >= total_weight {
                    err -= total_weight;
                    true
                } else {
                    false
                };

                // Helper macro to try one direction - avoids type mismatch and closure borrow issues
                macro_rules! try_direction {
                    ($src:expr, $dst:expr, $dir:expr) => {{
                        let mut budget = StepBudget {
                            syscalls: 1,
                            write_bytes: cmp::min(write_bytes_left, MAX_READ_CHUNK),
                        };
                        let before_syscalls = budget.syscalls;
                        let before_write_bytes = budget.write_bytes;

                        pump_one_direction(
                            Pin::new(unsafe { &mut *$src }),
                            Pin::new(unsafe { &mut *$dst }),
                            cx,
                            $dir,
                            &mut budget,
                        )?;

                        let used_syscalls = before_syscalls - budget.syscalls;
                        let used_write_bytes = before_write_bytes - budget.write_bytes;
                        if used_syscalls > 0 {
                            syscalls_left -= used_syscalls;
                            write_bytes_left -= used_write_bytes;
                            true
                        } else {
                            false
                        }
                    }};
                }

                let progressed: bool = if prefer_a {
                    let a = try_direction!(a_ptr, b_ptr, &mut this.a2b);
                    if a { true } else { try_direction!(b_ptr, a_ptr, &mut this.b2a) }
                } else {
                    let b = try_direction!(b_ptr, a_ptr, &mut this.b2a);
                    if b { true } else { try_direction!(a_ptr, b_ptr, &mut this.a2b) }
                };

                if !progressed {
                    break;
                }
                made_progress = true;
                if write_bytes_left == 0 {
                    break;
                }
            }

            if this.a2b.done() && this.b2a.done() {
                return Poll::Ready(Ok((this.a2b.bytes, this.b2a.bytes)));
            }

            if made_progress && (syscalls_left == 0 || write_bytes_left == 0) {
                cx.waker().wake_by_ref();
            }

            Poll::Pending
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
