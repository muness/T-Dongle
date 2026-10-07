//! The per-owner heap ledger (ADR 0001 rule 7, "memory made visible"; `tdongle_memory` in the C).
//!
//! Live and peak bytes, allocation, free and failure counts per owner. A free larger than what the owner holds is an *underflow*: counted, never
//! hidden, and the live figure saturates at zero instead of wrapping. The firmware's `GlobalAlloc` wrapper calls [`Ledger::alloc`] and
//! [`Ledger::free`] with the current thread's scoped owner tag; this type is the arithmetic and the counters, atomic so it can sit in a `static`.

use core::sync::atomic::{AtomicU32, Ordering};

/// Who owns a heap block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Owner {
    /// Everything not otherwise tagged.
    Other = 0,
    /// TLS records and handshakes.
    Tls,
    /// The Noise/control channel buffers.
    Noise,
    /// The network map.
    Map,
    /// The peer directory.
    Peer,
    /// WireGuard state and queued handshakes.
    WireGuard,
    /// Packet buffers.
    Packet,
}

/// Number of [`Owner`]s.
pub const OWNER_COUNT: usize = 7;

impl Owner {
    /// Every owner, in index order.
    pub const ALL: [Owner; OWNER_COUNT] = [Owner::Other, Owner::Tls, Owner::Noise, Owner::Map, Owner::Peer, Owner::WireGuard, Owner::Packet];
    /// The name used in reports (the `Owner` names of `firmware/src/alloc.rs`, lower case; the C's `owner_names` where the owner exists there:
    /// `other`, `tls`, `map`, `peer`, `packet`; the C's `control` is `noise` and its `wg` is `wireguard` here).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Owner::Other => "other",
            Owner::Tls => "tls",
            Owner::Noise => "noise",
            Owner::Map => "map",
            Owner::Peer => "peer",
            Owner::WireGuard => "wireguard",
            Owner::Packet => "packet",
        }
    }
}

/// One owner's counters, as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OwnerStats {
    /// Bytes held now.
    pub live: u32,
    /// Highest `live` since boot.
    pub peak: u32,
    /// Allocations.
    pub allocs: u32,
    /// Frees.
    pub frees: u32,
    /// Allocations that failed.
    pub failed: u32,
    /// Allocations refused by a floor before the allocator was asked.
    pub denied: u32,
}

#[derive(Debug)]
struct Slot {
    live: AtomicU32,
    peak: AtomicU32,
    allocs: AtomicU32,
    frees: AtomicU32,
    failed: AtomicU32,
    denied: AtomicU32,
}

impl Slot {
    const fn new() -> Self {
        Self {
            live: AtomicU32::new(0),
            peak: AtomicU32::new(0),
            allocs: AtomicU32::new(0),
            frees: AtomicU32::new(0),
            failed: AtomicU32::new(0),
            denied: AtomicU32::new(0),
        }
    }
}

/// The ledger: one slot per [`Owner`] and the underflow count.
#[derive(Debug)]
pub struct Ledger {
    slots: [Slot; OWNER_COUNT],
    underflows: AtomicU32,
}

impl Ledger {
    /// Empty.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: [const { Slot::new() }; OWNER_COUNT], underflows: AtomicU32::new(0) }
    }

    /// A block of `bytes` was allocated for `owner`.
    pub fn alloc(&self, owner: Owner, bytes: usize) {
        let s = &self.slots[owner as usize];
        let b = u32::try_from(bytes).unwrap_or(u32::MAX);
        s.allocs.fetch_add(1, Ordering::Relaxed);
        let now = s.live.fetch_add(b, Ordering::Relaxed).saturating_add(b);
        s.peak.fetch_max(now, Ordering::Relaxed);
    }

    /// A block of `bytes` held by `owner` was freed. Freeing more than the owner holds is counted as an underflow and `live` stops at zero.
    pub fn free(&self, owner: Owner, bytes: usize) {
        let s = &self.slots[owner as usize];
        let b = u32::try_from(bytes).unwrap_or(u32::MAX);
        s.frees.fetch_add(1, Ordering::Relaxed);
        let mut underflow = false;
        let _ = s.live.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
            underflow = live < b;
            Some(live.saturating_sub(b))
        });
        if underflow {
            self.underflows.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An allocation for `owner` failed.
    pub fn fail(&self, owner: Owner) {
        self.slots[owner as usize].failed.fetch_add(1, Ordering::Relaxed);
    }

    /// An allocation for `owner` was refused by a floor before the allocator was asked.
    pub fn deny(&self, owner: Owner) {
        self.slots[owner as usize].denied.fetch_add(1, Ordering::Relaxed);
    }

    /// One owner's counters.
    #[must_use]
    pub fn owner(&self, owner: Owner) -> OwnerStats {
        let s = &self.slots[owner as usize];
        OwnerStats {
            live: s.live.load(Ordering::Relaxed),
            peak: s.peak.load(Ordering::Relaxed),
            allocs: s.allocs.load(Ordering::Relaxed),
            frees: s.frees.load(Ordering::Relaxed),
            failed: s.failed.load(Ordering::Relaxed),
            denied: s.denied.load(Ordering::Relaxed),
        }
    }

    /// Test hook: set one owner's counters outright (used to reproduce golden scenarios).
    pub fn set_for_test(&self, owner: Owner, s: OwnerStats) {
        let sl = &self.slots[owner as usize];
        sl.live.store(s.live, Ordering::Relaxed);
        sl.peak.store(s.peak, Ordering::Relaxed);
        sl.allocs.store(s.allocs, Ordering::Relaxed);
        sl.frees.store(s.frees, Ordering::Relaxed);
        sl.failed.store(s.failed, Ordering::Relaxed);
        sl.denied.store(s.denied, Ordering::Relaxed);
    }

    /// Sum over all owners (`peak` is the sum of the peaks, an upper bound of the true joint peak).
    #[must_use]
    pub fn total(&self) -> OwnerStats {
        let mut t = OwnerStats::default();
        for o in Owner::ALL {
            let s = self.owner(o);
            t.live = t.live.saturating_add(s.live);
            t.peak = t.peak.saturating_add(s.peak);
            t.allocs = t.allocs.wrapping_add(s.allocs);
            t.frees = t.frees.wrapping_add(s.frees);
            t.failed = t.failed.wrapping_add(s.failed);
            t.denied = t.denied.wrapping_add(s.denied);
        }
        t
    }

    /// Frees that exceeded what their owner held (`tdongle_heap_underflows`).
    #[must_use]
    pub fn underflows(&self) -> u32 {
        self.underflows.load(Ordering::Relaxed)
    }

    /// Size of the ledger in bytes (`tdongle_memory_ledger_bytes`).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}
