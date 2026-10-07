//! One dynamic buffer pool for the tailnet runtime (ADR 0002, "RAM fit"; the C's counterpart is lwIP's pbuf and the mbedTLS heap, bounded by ADR 0022).
//!
//! The runtime used to hold every buffer as a static: socket windows (22.7 KB per membership), the TLS record buffer (16.7 KB), the control session's
//! workspace (17.7 KB). A static is paid whether or not a membership runs and whatever the heap looks like. A [`Pool`] allocation is paid only while it
//! is held, and it is **admitted** like every elastic consumer of the C: after taking `len` bytes the free heap must still be at least
//! [`ML_HB_FLOOR`] (`hb_ok`), or [`ML_ADM_RECOVERY_BYTES`] for a [`Class::Negotiation`] allocation, which *is* the negotiation peak the floor was sized to
//! leave free. A refusal is a [`Denied`] the caller turns into backpressure (wait and retry, drop the datagram, back off the connection), counted in
//! [`Stats`]; nothing here panics and nothing allocates unbounded: the pool has a byte cap of its own too.
//!
//! Three rules keep it honest:
//!
//! * the charge happens **before** the allocation and is given back on every path (drop of the [`PoolBuf`], or [`Pool::refund`] for memory a platform
//!   adapter hands out as raw slices), so `in_use` is exact and a test can assert it returns to zero;
//! * the floor is read from the platform's [`HeapProbe`] at the moment of the call (the same probe admission reads);
//! * waiting is event-driven: [`Pool::alloc_wait`] sleeps until something is given back (or a short tick: the heap can recover without a refund here,
//!   because other consumers free too).
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::waitqueue::MultiWakerRegistration;
use tdongle_tailnet_admission::adm::ML_ADM_RECOVERY_BYTES;
use tdongle_tailnet_admission::heap::{ML_HB_FLOOR, hb_ok};
use tdongle_tailnet_admission::probe::HeapProbe;

/// What an allocation is for: decides the floor it must leave and the counter it is reported under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A socket's window or ring (held while the connection exists). Leaves [`ML_HB_FLOOR`].
    Socket,
    /// A TLS record (held for one record's body). Leaves [`ML_HB_FLOOR`].
    Record,
    /// The control session's workspace during a negotiation or a map message: the negotiation peak the floor reserves, so it leaves only
    /// [`ML_ADM_RECOVERY_BYTES`] (the token admits one join at a time).
    Negotiation,
}

impl Class {
    /// Number of classes.
    pub const COUNT: usize = 3;
    const fn index(self) -> usize {
        match self {
            Class::Socket => 0,
            Class::Record => 1,
            Class::Negotiation => 2,
        }
    }
    /// Free heap that must remain after an allocation of this class.
    pub const fn floor(self) -> usize {
        match self {
            Class::Socket | Class::Record => ML_HB_FLOOR,
            Class::Negotiation => ML_ADM_RECOVERY_BYTES,
        }
    }
}

/// Why an allocation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The pool's own byte cap would be exceeded.
    Cap,
    /// The free heap would fall below the floor of the class.
    Floor,
    /// The allocator had no block of that size (fragmentation, or the probe was optimistic).
    Heap,
}

/// A snapshot of the pool's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes held now.
    pub in_use: u32,
    /// The most bytes ever held at once.
    pub high_water: u32,
    /// Allocations made, per class.
    pub takes: [u32; Class::COUNT],
    /// Allocations refused by the cap.
    pub denied_cap: u32,
    /// Allocations refused by the floor.
    pub denied_floor: u32,
    /// Allocations the allocator refused.
    pub denied_heap: u32,
    /// Times a caller had to wait for memory ([`Pool::alloc_wait`]).
    pub waits: u32,
}

/// The pool: counters, a byte cap and the wakers of whoever waits for memory. Put one in `Shared`.
pub struct Pool {
    cap: u32,
    in_use: AtomicU32,
    high: AtomicU32,
    takes: [AtomicU32; Class::COUNT],
    denied_cap: AtomicU32,
    denied_floor: AtomicU32,
    denied_heap: AtomicU32,
    waits: AtomicU32,
    /// Bumped by every refund: a waiter that saw an older value knows something was given back.
    freed: AtomicU32,
    wakers: Mutex<CriticalSectionRawMutex, RefCell<MultiWakerRegistration<6>>>,
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool").field("cap", &self.cap).field("stats", &self.stats()).finish()
    }
}

impl Pool {
    /// An empty pool that may hold at most `cap` bytes.
    pub const fn new(cap: usize) -> Self {
        Self {
            cap: cap as u32,
            in_use: AtomicU32::new(0),
            high: AtomicU32::new(0),
            takes: [const { AtomicU32::new(0) }; Class::COUNT],
            denied_cap: AtomicU32::new(0),
            denied_floor: AtomicU32::new(0),
            denied_heap: AtomicU32::new(0),
            waits: AtomicU32::new(0),
            freed: AtomicU32::new(0),
            wakers: Mutex::new(RefCell::new(MultiWakerRegistration::new())),
        }
    }

    /// The byte cap.
    pub const fn cap(&self) -> usize {
        self.cap as usize
    }

    /// Bytes held now.
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed) as usize
    }

    /// The counters.
    pub fn stats(&self) -> Stats {
        Stats {
            in_use: self.in_use.load(Ordering::Relaxed),
            high_water: self.high.load(Ordering::Relaxed),
            takes: core::array::from_fn(|i| self.takes[i].load(Ordering::Relaxed)),
            denied_cap: self.denied_cap.load(Ordering::Relaxed),
            denied_floor: self.denied_floor.load(Ordering::Relaxed),
            denied_heap: self.denied_heap.load(Ordering::Relaxed),
            waits: self.waits.load(Ordering::Relaxed),
        }
    }

    /// Account for `len` bytes about to be taken, without taking them: the cap and the floor are checked and the bytes are counted as held until
    /// [`Pool::refund`]. For memory a platform adapter allocates itself (the socket windows embassy-net wants as `&'static mut [u8]`).
    pub fn charge(&self, heap: &dyn HeapProbe, class: Class, len: usize) -> Result<(), Denied> {
        let len32 = u32::try_from(len).map_err(|_| Denied::Cap)?;
        // the heap as it is now, before this allocation (the allocator has not taken it yet); the elastic consumers' `ml_hb_ok` reads it the same way
        let free = heap.free();
        // reserve the bytes before checking: two tasks racing for the last bytes cannot both pass the cap
        let before = self.in_use.fetch_add(len32, Ordering::Relaxed);
        let after = before.saturating_add(len32);
        if after > self.cap {
            self.in_use.fetch_sub(len32, Ordering::Relaxed);
            self.denied_cap.fetch_add(1, Ordering::Relaxed);
            return Err(Denied::Cap);
        }
        // the floor: after this allocation at least `class.floor()` stays free (`hb_ok` for the elastic classes)
        let ok = match class {
            Class::Socket | Class::Record => hb_ok(free, len),
            Class::Negotiation => free >= class.floor() + len,
        };
        if !ok {
            self.in_use.fetch_sub(len32, Ordering::Relaxed);
            self.denied_floor.fetch_add(1, Ordering::Relaxed);
            return Err(Denied::Floor);
        }
        self.high.fetch_max(after, Ordering::Relaxed);
        self.takes[class.index()].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Give back bytes that [`Pool::charge`] counted (also what a dropped [`PoolBuf`] does), and wake whoever waits for memory.
    pub fn refund(&self, len: usize) {
        let len32 = len as u32;
        // saturating: a double refund is a bug, but it must not wrap the counter and starve everything after it
        let _ = self.in_use.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(len32)));
        self.freed.fetch_add(1, Ordering::Release);
        self.wakers.lock(|w| w.borrow_mut().wake());
    }

    /// A zeroed buffer of `len` bytes, or why not. The bytes are counted until the buffer is dropped.
    pub fn alloc(&self, heap: &dyn HeapProbe, class: Class, len: usize) -> Result<PoolBuf<'_>, Denied> {
        self.charge(heap, class, len)?;
        let mut v: Vec<u8> = Vec::new();
        if v.try_reserve_exact(len).is_err() {
            self.refund(len);
            self.denied_heap.fetch_add(1, Ordering::Relaxed);
            return Err(Denied::Heap);
        }
        v.resize(len, 0);
        Ok(PoolBuf { buf: v, pool: self })
    }

    /// As [`Pool::alloc`], waiting until the allocation is admitted: the caller is backpressured (its connection stalls, its negotiation waits) rather
    /// than failed. Wakes on every refund and ticks every 100 ms (the heap also recovers when other consumers free). Cancel-safe: nothing is held while
    /// waiting.
    pub async fn alloc_wait(&self, heap: &dyn HeapProbe, class: Class, len: usize) -> PoolBuf<'_> {
        let mut counted = false;
        loop {
            let seen = self.freed.load(Ordering::Acquire);
            match self.alloc(heap, class, len) {
                Ok(b) => return b,
                Err(_) => {
                    if !counted {
                        self.waits.fetch_add(1, Ordering::Relaxed);
                        counted = true;
                    }
                    embassy_futures::select::select(self.wait_freed(seen), embassy_time::Timer::after_millis(100)).await;
                }
            }
        }
    }

    /// Complete once a refund newer than `seen` (a value of the internal counter read before the failed allocation) has happened.
    async fn wait_freed(&self, seen: u32) {
        core::future::poll_fn(|cx| {
            if self.freed.load(Ordering::Acquire) != seen {
                return core::task::Poll::Ready(());
            }
            self.wakers.lock(|w| {
                // a full registry wakes its oldest waiter, which retries: nobody is lost, only re-polled
                w.borrow_mut().register(cx.waker());
            });
            if self.freed.load(Ordering::Acquire) != seen { core::task::Poll::Ready(()) } else { core::task::Poll::Pending }
        })
        .await;
    }
}

/// The pool together with the heap probe its admission reads: what a task is handed to take buffers from (both are borrowed from the shared state).
#[derive(Clone, Copy)]
pub struct Mem<'a> {
    /// The pool.
    pub pool: &'a Pool,
    /// The platform's heap probe (the same one admission reads).
    pub heap: &'a dyn HeapProbe,
}

impl core::fmt::Debug for Mem<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mem").field("pool", self.pool).finish_non_exhaustive()
    }
}

impl<'a> Mem<'a> {
    /// [`Pool::alloc`].
    pub fn alloc(&self, class: Class, len: usize) -> Result<PoolBuf<'a>, Denied> {
        self.pool.alloc(self.heap, class, len)
    }
    /// [`Pool::alloc_wait`].
    pub async fn alloc_wait(&self, class: Class, len: usize) -> PoolBuf<'a> {
        self.pool.alloc_wait(self.heap, class, len).await
    }
    /// [`Pool::charge`].
    pub fn charge(&self, class: Class, len: usize) -> Result<(), Denied> {
        self.pool.charge(self.heap, class, len)
    }
    /// [`Pool::refund`].
    pub fn refund(&self, len: usize) {
        self.pool.refund(len);
    }
}

/// A buffer taken from the [`Pool`]; the bytes are given back when it drops.
pub struct PoolBuf<'p> {
    buf: Vec<u8>,
    pool: &'p Pool,
}

impl core::fmt::Debug for PoolBuf<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PoolBuf({})", self.buf.len())
    }
}

impl<'p> PoolBuf<'p> {
    /// Keep the accounting, release the memory: what remains is a [`Charge`] that gives the bytes back when it drops. For a caller that builds a typed value
    /// (a `Box<T>`) into the block this buffer proved the allocator can serve: the allocation just freed is the one the box takes next.
    pub fn into_charge(mut self) -> Charge<'p> {
        let len = self.buf.len();
        self.buf = Vec::new();
        let pool = self.pool;
        core::mem::forget(self);
        Charge { pool, len }
    }
}

/// Bytes the [`Pool`] counts as held without holding memory itself (see [`PoolBuf::into_charge`]); given back on drop.
pub struct Charge<'p> {
    pool: &'p Pool,
    len: usize,
}

impl core::fmt::Debug for Charge<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Charge({})", self.len)
    }
}

impl Drop for Charge<'_> {
    fn drop(&mut self) {
        self.pool.refund(self.len);
    }
}

impl core::ops::Deref for PoolBuf<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl core::ops::DerefMut for PoolBuf<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for PoolBuf<'_> {
    fn drop(&mut self) {
        let n = self.buf.len();
        self.buf = Vec::new();
        self.pool.refund(n);
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
