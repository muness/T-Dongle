//! A single-producer, single-consumer array of slots with two free-running 32-bit counters (no lock), whose slots can only be reached through
//! **move-only handles**: a [`Reservation`] (producer) and a [`Lease`] (consumer). This is the one place the bridge's host queue needs `unsafe`;
//! `tdongle-bridge` itself is `#![forbid(unsafe_code)]`.
//!
//! Why handles. In the C firmware the slot was a pointer plus a counter store that the caller had to remember to do exactly once. Here:
//!
//! * a [`Lease`] is not `Clone` or `Copy`; dropping it is the **single** release of the slot back to the producer (`tail + 1`), so a slot cannot
//!   be released twice or forgotten on an early return;
//! * a [`Reservation`] is consumed by [`publish`](Reservation::publish); dropping it unpublished abandons the slot (nothing moves).
//!
//! The protocol that makes it sound:
//! * `head` is advanced only by the producer, `tail` only by the consumer; both only grow and wrap at 2^32, so `N` divides 2^32 and
//!   `head - tail` is the depth whatever the interleaving provided `tail` is read first ([`depth`](Spsc::depth) does);
//! * the producer writes slot `head & MASK` only while `head - tail < limit <= N`, publishing with a release store of `head + 1`;
//! * the consumer reads slot `tail & MASK` only while `tail != head` (acquire load of `head`) and releases it with a `SeqCst` store of `tail + 1`.
//!
//! Built with `--cfg loom` the atomics and cells are loom's, and `tests/loom.rs` explores the interleavings.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

/// Atomics and cells: `core`'s, or loom's under `--cfg loom`. Everything above this crate (the bridge's held flag, the epoch) uses these too, so a
/// loom model of the whole protocol is a recompile.
pub mod sync {
    #[cfg(not(loom))]
    pub use core::sync::atomic;
    #[cfg(loom)]
    pub use loom::sync::atomic;

    #[cfg(loom)]
    pub use loom::cell::UnsafeCell;

    /// `core::cell::UnsafeCell` with loom's `with`/`with_mut` shape.
    #[cfg(not(loom))]
    #[derive(Debug)]
    pub struct UnsafeCell<T>(core::cell::UnsafeCell<T>);

    #[cfg(not(loom))]
    impl<T> UnsafeCell<T> {
        /// A new cell.
        pub const fn new(value: T) -> Self {
            Self(core::cell::UnsafeCell::new(value))
        }

        /// Run `f` with a raw pointer to the contents.
        pub fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
            f(self.0.get())
        }
    }
}

use core::marker::PhantomData;

use sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The queue. `N` slots of `T`, a power of two.
#[derive(Debug)]
pub struct Spsc<T, const N: usize> {
    cells: [sync::UnsafeCell<T>; N],
    head: AtomicU32,
    tail: AtomicU32,
    producer_taken: AtomicBool,
    consumer_taken: AtomicBool,
}

// SAFETY: access to each cell is exclusive by the protocol in the module documentation, enforced by the move-only handles and the single
// producer / single consumer handles; the hand-over is a release/acquire pair on `head` and `tail`.
unsafe impl<T: Send, const N: usize> Sync for Spsc<T, N> {}

impl<T, const N: usize> Spsc<T, N> {
    const MASK: u32 = {
        assert!(N.is_power_of_two() && N <= 1 << 16, "the counters run free: the slot count must divide 2^32");
        N as u32 - 1
    };

    /// A queue over `cells` (built by the caller so a `static` can use a `const` initialiser).
    pub fn from_cells(cells: [sync::UnsafeCell<T>; N]) -> Self {
        let _ = Self::MASK;
        Self { cells, head: AtomicU32::new(0), tail: AtomicU32::new(0), producer_taken: AtomicBool::new(false), consumer_taken: AtomicBool::new(false) }
    }

    /// The single producer handle, or `None` while one is alive.
    pub fn producer(&self) -> Option<Producer<'_, T, N>> {
        (!self.producer_taken.swap(true, Ordering::AcqRel)).then_some(Producer { queue: self })
    }

    /// The single consumer handle, or `None` while one is alive.
    pub fn consumer(&self) -> Option<Consumer<'_, T, N>> {
        (!self.consumer_taken.swap(true, Ordering::AcqRel)).then_some(Consumer { queue: self })
    }

    /// Frames standing now. `tail` is read before `head`: head only grows, so the difference cannot go negative (and wrap to 4 billion)
    /// however the consumer interleaves.
    pub fn depth(&self) -> u32 {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// Read the consumer counter (for the hold/resume handshake, which needs a `SeqCst` view of it).
    pub fn tail(&self, order: Ordering) -> u32 {
        self.tail.load(order)
    }

    /// Read the producer counter.
    pub fn head(&self, order: Ordering) -> u32 {
        self.head.load(order)
    }

    /// Start both counters at `value`: the wrap tests. Only while the queue is empty and idle.
    #[doc(hidden)]
    pub fn __set_counters(&self, value: u32) {
        self.head.store(value, Ordering::SeqCst);
        self.tail.store(value, Ordering::SeqCst);
    }
}

/// Callback context safety (rule 4 of ADR 0001). The capability to block is a value: every call that may block takes `&TaskContext`; the
/// receive callbacks (the Wi-Fi RX callback, the TinyUSB receive callback) are never given one, so a blocking call from a callback does not
/// compile. (The C firmware's "20 x `vTaskDelay(1)` in the TinyUSB callback" was exactly that bug.)
///
/// Not `Clone` or `Copy`.
#[derive(Debug)]
pub struct TaskContext(());

impl TaskContext {
    /// Claim the capability for the calling task.
    ///
    /// # Safety
    /// The caller must be a task that may block (the Wi-Fi event task, a worker), and must not hand the value to an ISR or to a driver callback
    /// that runs in the Wi-Fi task or the TinyUSB task.
    #[must_use]
    pub const unsafe fn assume() -> Self {
        Self(())
    }

    /// A capability for host tests, whose "callbacks" are scripted.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn for_tests() -> Self {
        Self(())
    }
}

impl<T, const N: usize> Consumer<'_, T, N> {
    /// The holder of the single consumer handle is the worker task, which is allowed to block: its capability.
    #[must_use]
    pub const fn blocking_context(&self) -> TaskContext {
        TaskContext(())
    }
}

/// The producer's handle: the only way to reserve slots.
#[derive(Debug)]
pub struct Producer<'a, T, const N: usize> {
    queue: &'a Spsc<T, N>,
}

impl<T, const N: usize> Drop for Producer<'_, T, N> {
    fn drop(&mut self) {
        self.queue.producer_taken.store(false, Ordering::Release);
    }
}

impl<'a, T, const N: usize> Producer<'a, T, N> {
    /// Reserve the next slot if fewer than `limit` (`<= N`) are standing. `tail` is loaded with `Acquire` first, then `head`.
    pub fn reserve(&mut self, limit: u32) -> Result<Reservation<'_, T, N>, Full> {
        let tail = self.queue.tail.load(Ordering::Acquire);
        let head = self.queue.head.load(Ordering::Relaxed);
        self.reserve_with(head, tail, limit)
    }

    /// As [`reserve`](Self::reserve) with a `tail` the caller has just re-read (the hold handshake publishes its flag and looks again with
    /// `SeqCst`).
    pub fn reserve_after(&mut self, tail: u32, limit: u32) -> Result<Reservation<'_, T, N>, Full> {
        let head = self.queue.head.load(Ordering::Relaxed);
        self.reserve_with(head, tail, limit)
    }

    fn reserve_with(&mut self, head: u32, tail: u32, limit: u32) -> Result<Reservation<'_, T, N>, Full> {
        if limit as usize > N || head.wrapping_sub(tail) >= limit {
            return Err(Full { head, tail });
        }
        Ok(Reservation { queue: self.queue, head, tail, _producer: PhantomData })
    }

    /// The counters as the producer sees them: `(head, tail)`, `tail` loaded first.
    pub fn view(&self) -> (u32, u32) {
        let tail = self.queue.tail.load(Ordering::Acquire);
        (self.queue.head.load(Ordering::Relaxed), tail)
    }
}

/// The queue is at its limit; the counters it saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full {
    /// The producer counter.
    pub head: u32,
    /// The consumer counter.
    pub tail: u32,
}

/// A slot the producer may write. Move-only: [`publish`](Self::publish) consumes it; dropping it abandons the slot.
#[derive(Debug)]
pub struct Reservation<'q, T, const N: usize> {
    queue: &'q Spsc<T, N>,
    head: u32,
    tail: u32,
    _producer: PhantomData<&'q mut ()>,
}

impl<T, const N: usize> Reservation<'_, T, N> {
    /// The consumer counter when the slot was reserved (for the queue's high-water mark: `head + 1 - tail`).
    pub fn tail_seen(&self) -> u32 {
        self.tail
    }

    /// Write the slot through `f`, then make it visible to the consumer (release store of `head + 1`). Returns the new depth as the producer saw it.
    pub fn publish(self, f: impl FnOnce(&mut T)) -> u32 {
        let idx = (self.head & Spsc::<T, N>::MASK) as usize;
        // SAFETY: this `Reservation` exists only while `head - tail < limit <= N`, so the consumer has released this slot (a `Lease` for it was
        // dropped before `tail` moved past it) and will not look at it before `head` is published below; there is one producer handle, and this
        // handle is consumed, so nothing else can write the slot.
        self.queue.cells[idx].with_mut(|slot| f(unsafe { &mut *slot }));
        self.queue.head.store(self.head.wrapping_add(1), Ordering::Release);
        self.head.wrapping_add(1).wrapping_sub(self.tail)
    }
}

/// The consumer's handle: the only way to claim slots.
#[derive(Debug)]
pub struct Consumer<'a, T, const N: usize> {
    queue: &'a Spsc<T, N>,
}

impl<T, const N: usize> Drop for Consumer<'_, T, N> {
    fn drop(&mut self) {
        self.queue.consumer_taken.store(false, Ordering::Release);
    }
}

impl<T, const N: usize> Consumer<'_, T, N> {
    /// Claim the oldest published slot, if any. The returned [`Lease`] derefs to the slot; **dropping it releases the slot**, exactly once.
    pub fn claim(&mut self) -> Option<Lease<'_, T, N>> {
        let tail = self.queue.tail.load(Ordering::Relaxed);
        if tail == self.queue.head.load(Ordering::Acquire) {
            return None;
        }
        Some(Lease { queue: self.queue, tail, _consumer: PhantomData })
    }
}

/// A published slot the consumer holds. Move-only; its `Drop` is the one release back to the producer (`SeqCst` store of `tail + 1`).
#[derive(Debug)]
#[must_use = "a lease releases its slot when dropped: bind it for as long as the slot is in use"]
pub struct Lease<'q, T, const N: usize> {
    queue: &'q Spsc<T, N>,
    tail: u32,
    _consumer: PhantomData<&'q mut ()>,
}

impl<T, const N: usize> Lease<'_, T, N> {
    /// Run `f` on the slot.
    pub fn with<R>(&mut self, f: impl FnOnce(&mut T) -> R) -> R {
        let idx = (self.tail & Spsc::<T, N>::MASK) as usize;
        // SAFETY: a `Lease` is created only when `tail != head` (the producer published this slot with a release store the consumer acquired),
        // the producer will not write it until `tail` moves, there is one consumer handle and `&mut self` excludes a second reference.
        self.queue.cells[idx].with_mut(|slot| f(unsafe { &mut *slot }))
    }

    /// The consumer counter value this lease holds (`tail`).
    pub fn counter(&self) -> u32 {
        self.tail
    }
}

impl<T, const N: usize> Drop for Lease<'_, T, N> {
    fn drop(&mut self) {
        // The slot is the producer's again.
        self.queue.tail.store(self.tail.wrapping_add(1), Ordering::SeqCst);
    }
}

// `Deref` is deliberately not implemented on `Lease`: access goes through `with`, so no reference to the slot can outlive the lease.

#[cfg(all(test, not(loom)))]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    use super::*;

    fn queue() -> Spsc<u32, 8> {
        Spsc::from_cells([const { sync::UnsafeCell::new(0) }; 8])
    }

    #[test]
    fn fifo_with_limit_and_wrap() {
        let q = queue();
        q.__set_counters(0xffff_fffc);
        let (mut p, mut c) = (q.producer().unwrap(), q.consumer().unwrap());
        for round in 0..10u32 {
            for i in 0..3 {
                p.reserve(3).unwrap().publish(|s| *s = round * 3 + i);
            }
            assert!(p.reserve(3).is_err(), "at the limit");
            for i in 0..3 {
                let mut lease = c.claim().unwrap();
                assert_eq!(lease.with(|s| *s), round * 3 + i);
            }
            assert!(c.claim().is_none());
        }
        assert_eq!(q.depth(), 0);
        assert_eq!(q.head(Ordering::SeqCst), 0xffff_fffcu32.wrapping_add(30));
    }

    #[test]
    fn a_lease_releases_on_drop_only() {
        let q = queue();
        let (mut p, mut c) = (q.producer().unwrap(), q.consumer().unwrap());
        p.reserve(1).unwrap().publish(|s| *s = 1);
        let lease = c.claim().unwrap();
        assert_eq!(q.depth(), 1, "held: still standing");
        assert!(p.reserve(1).is_err());
        drop(lease);
        assert_eq!(q.depth(), 0);
        assert!(p.reserve(1).is_ok());
    }

    #[test]
    fn abandoned_reservation_publishes_nothing() {
        let q = queue();
        let (mut p, mut c) = (q.producer().unwrap(), q.consumer().unwrap());
        drop(p.reserve(4).unwrap());
        assert!(c.claim().is_none());
        assert_eq!(q.depth(), 0);
    }

    #[test]
    fn one_producer_one_consumer() {
        let q = queue();
        let p = q.producer().unwrap();
        assert!(q.producer().is_none());
        drop(p);
        assert!(q.producer().is_some());
        let _c = q.consumer().unwrap();
        assert!(q.consumer().is_none());
    }

    #[test]
    fn threads_deliver_in_order_exactly_once() {
        let q = Arc::new(queue());
        let producer = {
            let q = q.clone();
            thread::spawn(move || {
                let mut p = q.producer().unwrap();
                for n in 0..200_000u32 {
                    while p.reserve(5).map(|r| r.publish(|s| *s = n)).is_err() {
                        thread::yield_now();
                    }
                }
            })
        };
        let mut seen = Vec::new();
        let mut c = q.consumer().unwrap();
        while seen.len() < 200_000 {
            match c.claim() {
                Some(mut lease) => seen.push(lease.with(|s| *s)),
                None => thread::yield_now(),
            }
        }
        producer.join().unwrap();
        assert!(seen.iter().copied().eq(0..200_000));
    }
}
