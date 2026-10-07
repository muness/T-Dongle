//! A bounded byte queue of variable-length records with a wake-up, the only way the engine's outputs leave `Engine::handle`.
//!
//! The engine's `Output::emit` runs inside the engine lock and must neither wait nor re-enter the engine, so every output that needs I/O is copied into one
//! of these and picked up by the task that owns the I/O. A push that does not fit is **refused** (returns `false`; the engine counts it as `TxRefused` /
//! `HostTxRefused`) and counted here; nothing is ever dropped silently and nothing blocks. One consumer per queue (the wake-up is a [`Signal`]).
//!
//! Records are `[len: u16][kind: u8][meta: n bytes][payload]` where the queue does not interpret `meta`; callers pass `meta` and `payload` as two slices so
//! that no temporary buffer is needed.

use core::cell::RefCell;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::signal::Signal;

const HDR: usize = 3;

/// Counters of one queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Records accepted.
    pub pushed: u32,
    /// Records refused because they did not fit.
    pub refused: u32,
    /// Records taken.
    pub popped: u32,
    /// The most bytes ever queued.
    pub high_water: u32,
}

struct Ring<const N: usize> {
    buf: [u8; N],
    head: usize,
    used: usize,
    stats: QueueStats,
}

impl<const N: usize> Ring<N> {
    const fn new() -> Self {
        Ring { buf: [0; N], head: 0, used: 0, stats: QueueStats { pushed: 0, refused: 0, popped: 0, high_water: 0 } }
    }
    fn put(&mut self, at: usize, src: &[u8]) {
        let start = (self.head + at) % N;
        let first = src.len().min(N - start);
        self.buf[start..start + first].copy_from_slice(&src[..first]);
        self.buf[..src.len() - first].copy_from_slice(&src[first..]);
    }
    fn get(&self, at: usize, dst: &mut [u8]) {
        let start = (self.head + at) % N;
        let first = dst.len().min(N - start);
        dst[..first].copy_from_slice(&self.buf[start..start + first]);
        let rest = dst.len() - first;
        dst[first..].copy_from_slice(&self.buf[..rest]);
    }
    fn push(&mut self, kind: u8, meta: &[u8], payload: &[u8]) -> bool {
        let body = meta.len() + payload.len();
        if body > u16::MAX as usize || self.used + HDR + body > N {
            self.stats.refused += 1;
            return false;
        }
        let at = self.used;
        self.put(at, &(body as u16).to_le_bytes());
        self.put(at + 2, &[kind]);
        self.put(at + HDR, meta);
        self.put(at + HDR + meta.len(), payload);
        self.used += HDR + body;
        self.stats.pushed += 1;
        self.stats.high_water = self.stats.high_water.max(self.used as u32);
        true
    }
    fn peek(&self, out: &mut [u8]) -> Option<(u8, usize)> {
        if self.used == 0 {
            return None;
        }
        let mut h = [0u8; HDR];
        self.get(0, &mut h);
        let body = u16::from_le_bytes([h[0], h[1]]) as usize;
        let n = body.min(out.len());
        self.get(HDR, &mut out[..n]);
        Some((h[2], n))
    }
    fn discard(&mut self) {
        if self.used == 0 {
            return;
        }
        let mut h = [0u8; HDR];
        self.get(0, &mut h);
        let body = u16::from_le_bytes([h[0], h[1]]) as usize;
        self.head = (self.head + HDR + body) % N;
        self.used -= HDR + body;
        self.stats.popped += 1;
    }
    fn pop(&mut self, out: &mut [u8]) -> Option<(u8, usize)> {
        if self.used == 0 {
            return None;
        }
        let mut h = [0u8; HDR];
        self.get(0, &mut h);
        let body = u16::from_le_bytes([h[0], h[1]]) as usize;
        let n = body.min(out.len());
        self.get(HDR, &mut out[..n]);
        self.head = (self.head + HDR + body) % N;
        self.used -= HDR + body;
        self.stats.popped += 1;
        Some((h[2], n))
    }
}

/// The queue. `N` is its capacity in bytes (headers included).
pub struct ByteQueue<R: RawMutex, const N: usize> {
    ring: Mutex<R, RefCell<Ring<N>>>,
    ready: Signal<R, ()>,
    room: Signal<R, ()>,
}

impl<R: RawMutex, const N: usize> core::fmt::Debug for ByteQueue<R, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ByteQueue<{N}>({} used)", self.len_bytes())
    }
}

impl<R: RawMutex, const N: usize> Default for ByteQueue<R, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RawMutex, const N: usize> ByteQueue<R, N> {
    /// An empty queue.
    #[inline(always)]
    pub const fn new() -> Self {
        Self { ring: Mutex::new(RefCell::new(Ring::new())), ready: Signal::new(), room: Signal::new() }
    }
    /// Bytes of the queue's own storage.
    pub const CAPACITY: usize = N;
    /// Append a record (`meta` then `payload`); `false` (counted) if it does not fit. Never waits.
    pub fn push(&self, kind: u8, meta: &[u8], payload: &[u8]) -> bool {
        let ok = self.ring.lock(|r| r.borrow_mut().push(kind, meta, payload));
        if ok {
            self.ready.signal(());
        }
        ok
    }
    /// Take the oldest record into `out` (a record longer than `out` is truncated; callers size `out` for the largest record they push).
    pub fn try_pop(&self, out: &mut [u8]) -> Option<(u8, usize)> {
        let r = self.ring.lock(|r| r.borrow_mut().pop(out));
        if r.is_some() {
            self.room.signal(());
        }
        r
    }
    /// Copy the oldest record into `out` without taking it (see [`ByteQueue::discard_front`]): a consumer that may not be able to use it yet leaves it
    /// queued instead of holding it in a buffer of its own across a wait. One consumer per queue.
    pub fn try_peek(&self, out: &mut [u8]) -> Option<(u8, usize)> {
        self.ring.lock(|r| r.borrow().peek(out))
    }
    /// Take the oldest record away (after [`ByteQueue::try_peek`] showed it).
    pub fn discard_front(&self) {
        self.ring.lock(|r| r.borrow_mut().discard());
        self.room.signal(());
    }
    /// Wait for a record. Cancel-safe.
    pub async fn pop(&self, out: &mut [u8]) -> (u8, usize) {
        loop {
            if let Some(r) = self.try_pop(out) {
                return r;
            }
            self.ready.wait().await;
        }
    }
    /// Wait until the queue is not empty, without taking anything. Cancel-safe.
    pub async fn wait_nonempty(&self) {
        loop {
            if self.len_bytes() != 0 {
                return;
            }
            self.ready.wait().await;
        }
    }
    /// Wait until at least `n` bytes are free (woken by every pop, not by polling). Cancel-safe.
    pub async fn wait_free(&self, n: usize) {
        loop {
            if self.free_bytes() >= n {
                return;
            }
            self.room.wait().await;
        }
    }
    /// Bytes free now (a record needs its payload plus three bytes of header).
    pub fn free_bytes(&self) -> usize {
        N - self.len_bytes()
    }
    /// Bytes queued now.
    pub fn len_bytes(&self) -> usize {
        self.ring.lock(|r| r.borrow().used)
    }
    /// Drop everything queued; returns the number of bytes dropped.
    pub fn clear(&self) -> usize {
        self.ring.lock(|r| {
            let mut r = r.borrow_mut();
            let n = r.used;
            r.used = 0;
            r.head = 0;
            n
        })
    }
    /// The counters.
    pub fn stats(&self) -> QueueStats {
        self.ring.lock(|r| r.borrow().stats)
    }
    /// Wake the consumer without a record (a state change it must look at).
    pub fn kick(&self) {
        self.ready.signal(());
    }
}

/// A queue of records on the heap, bounded in bytes, for what has to hold more than a static ring can afford: the relay's egress (a window of TCP segments waits while
/// the link writes at the relay's pace). A record is a heap block taken above the elastic floor like every elastic consumer ([`ElasticQueue::push_admit`]); a push that
/// does not fit or cannot be admitted is refused and counted, as in [`ByteQueue`]. One consumer.
pub struct ElasticQueue<R: RawMutex, const CAP: usize> {
    inner: Mutex<R, RefCell<ElasticInner>>,
    ready: Signal<R, ()>,
    room: Signal<R, ()>,
}

struct ElasticInner {
    /// `[kind][meta][payload]` per record.
    q: alloc::collections::VecDeque<alloc::vec::Vec<u8>>,
    used: usize,
    stats: QueueStats,
}

impl<R: RawMutex, const CAP: usize> core::fmt::Debug for ElasticQueue<R, CAP> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ElasticQueue<{CAP}>({} used)", self.len_bytes())
    }
}

impl<R: RawMutex, const CAP: usize> Default for ElasticQueue<R, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RawMutex, const CAP: usize> ElasticQueue<R, CAP> {
    /// An empty queue (no heap taken).
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(ElasticInner {
                q: alloc::collections::VecDeque::new(),
                used: 0,
                stats: QueueStats { pushed: 0, refused: 0, popped: 0, high_water: 0 },
            })),
            ready: Signal::new(),
            room: Signal::new(),
        }
    }
    /// Bytes the queue may hold (headers included).
    pub const CAPACITY: usize = CAP;
    /// Append a record (`meta` then `payload`) if it fits the byte bound and `heap_free` (the free heap now) admits a block of its size above the floor; `false`
    /// (counted) otherwise. Never waits.
    pub fn push_admit(&self, kind: u8, meta: &[u8], payload: &[u8], heap_free: usize) -> bool {
        let body = 1 + meta.len() + payload.len();
        let ok = self.inner.lock(|i| {
            let mut i = i.borrow_mut();
            if i.used + body + 8 > CAP || !tdongle_tailnet_admission::heap::hb_ok(heap_free, body + 32) {
                i.stats.refused += 1;
                return false;
            }
            let mut v = alloc::vec::Vec::new();
            if v.try_reserve_exact(body).is_err() {
                i.stats.refused += 1;
                return false;
            }
            v.push(kind);
            v.extend_from_slice(meta);
            v.extend_from_slice(payload);
            i.used += body + 8;
            i.q.push_back(v);
            i.stats.pushed += 1;
            i.stats.high_water = i.stats.high_water.max(i.used as u32);
            true
        });
        if ok {
            self.ready.signal(());
        }
        ok
    }
    /// Copy the oldest record into `out` without taking it. One consumer.
    pub fn try_peek(&self, out: &mut [u8]) -> Option<(u8, usize)> {
        self.inner.lock(|i| {
            let i = i.borrow();
            let v = i.q.front()?;
            let n = (v.len() - 1).min(out.len());
            out[..n].copy_from_slice(&v[1..1 + n]);
            Some((v[0], n))
        })
    }
    /// Take the oldest record away (after [`ElasticQueue::try_peek`] showed it).
    pub fn discard_front(&self) {
        self.inner.lock(|i| {
            let mut i = i.borrow_mut();
            if let Some(v) = i.q.pop_front() {
                i.used -= v.len() + 8;
                i.stats.popped += 1;
            }
        });
        self.room.signal(());
    }
    /// Wait until the queue is not empty. Cancel-safe.
    pub async fn wait_nonempty(&self) {
        loop {
            if self.len_bytes() != 0 {
                return;
            }
            self.ready.wait().await;
        }
    }
    /// Bytes free under the byte bound now.
    pub fn free_bytes(&self) -> usize {
        CAP.saturating_sub(self.len_bytes())
    }
    /// Would a record of `n` bytes be accepted now, in the byte bound and for the heap (`heap_free`)?
    pub fn has_room(&self, n: usize, heap_free: usize) -> bool {
        self.free_bytes() >= n + 8 && tdongle_tailnet_admission::heap::hb_ok(heap_free, n + 32)
    }
    /// Bytes queued now.
    pub fn len_bytes(&self) -> usize {
        self.inner.lock(|i| i.borrow().used)
    }
    /// Drop everything queued; returns the number of bytes dropped.
    pub fn clear(&self) -> usize {
        self.inner.lock(|i| {
            let mut i = i.borrow_mut();
            let n = i.used;
            i.q.clear();
            i.used = 0;
            n
        })
    }
    /// The counters.
    pub fn stats(&self) -> QueueStats {
        self.inner.lock(|i| i.borrow().stats)
    }
    /// Wake the consumer without a record.
    pub fn kick(&self) {
        self.ready.signal(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use futures::executor::block_on;

    #[test]
    fn records_round_trip_across_the_wrap() {
        let q = ByteQueue::<NoopRawMutex, 64>::new();
        let mut out = [0u8; 64];
        for round in 0..50u8 {
            let payload: std::vec::Vec<u8> = (0..(round % 17 + 1)).map(|i| i ^ round).collect();
            assert!(q.push(round, &[round, 1], &payload));
            assert!(q.push(round.wrapping_add(1), &[], &payload));
            let (k, n) = q.try_pop(&mut out).unwrap();
            assert_eq!((k, &out[..n]), (round, &[&[round, 1][..], &payload].concat()[..]));
            let (k, n) = q.try_pop(&mut out).unwrap();
            assert_eq!((k, &out[..n]), (round.wrapping_add(1), &payload[..]));
            assert!(q.try_pop(&mut out).is_none());
        }
    }

    #[test]
    fn peek_leaves_the_record_queued_until_it_is_discarded() {
        // the UDP and DNS tasks hold no buffer across a wait: a record the socket has no room for stays in the queue, in order, across the wrap
        let q = ByteQueue::<NoopRawMutex, 48>::new();
        let mut out = [0u8; 48];
        for round in 0..40u8 {
            let a: std::vec::Vec<u8> = (0..(round % 11 + 1)).map(|i| i ^ round).collect();
            assert!(q.push(round, &[round], &a));
            assert!(q.push(round.wrapping_add(100), &[], &a));
            for _ in 0..3 {
                let (k, n) = q.try_peek(&mut out).unwrap();
                assert_eq!((k, &out[..n]), (round, &[&[round][..], &a].concat()[..]), "peeking twice gives the same record");
            }
            assert_eq!(q.stats().popped, u32::from(round) * 2, "peeking is not taking");
            q.discard_front();
            let (k, n) = q.try_peek(&mut out).unwrap();
            assert_eq!((k, &out[..n]), (round.wrapping_add(100), &a[..]));
            q.discard_front();
            assert!(q.try_peek(&mut out).is_none());
            q.discard_front(); // discarding an empty queue is a no-op
            assert_eq!(q.len_bytes(), 0);
        }
    }

    #[test]
    fn a_full_queue_refuses_and_counts() {
        let q = ByteQueue::<NoopRawMutex, 32>::new();
        assert!(q.push(1, &[], &[0; 20]));
        assert!(!q.push(2, &[], &[0; 10]));
        assert_eq!(q.stats().refused, 1);
        assert_eq!(q.stats().high_water, 23);
        assert_eq!(q.clear(), 23);
        assert!(q.push(3, &[], &[0; 10]));
    }

    #[test]
    fn pop_waits_for_a_push() {
        let q = ByteQueue::<NoopRawMutex, 64>::new();
        let mut out = [0u8; 8];
        let got = block_on(async {
            let push = async {
                let mut yielded = false;
                futures::future::poll_fn(|cx| {
                    if yielded {
                        return core::task::Poll::Ready(());
                    }
                    yielded = true;
                    cx.waker().wake_by_ref();
                    core::task::Poll::Pending
                })
                .await;
                q.push(9, &[], b"hi");
            };
            let (a, ()) = futures::future::join(q.pop(&mut out), push).await;
            a
        });
        assert_eq!(got, (9, 2));
    }
}
