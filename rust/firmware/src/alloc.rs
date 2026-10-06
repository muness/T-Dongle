//! Memory made visible (rule 7 of ADR 0001): a `GlobalAlloc` that counts live and peak bytes, allocations and failures, in total and per owner.
//!
//! The C firmware could not say where its last "about 6 KB unattributed" went (`tdongle_heap_note_alloc` was opt-in and only the diagnostics image
//! had it). Here every Rust allocation passes through this wrapper in every image: two relaxed atomic adds, nothing else. The allocator underneath
//! is the system one (`heap_caps_malloc`, internal RAM: there is no PSRAM), so the numbers are comparable with `free_heap`.
//!
//! **Owners.** A task tags what it is doing with [`with_owner`] (the TLS, Noise, map, peer, WireGuard and packet owners of the C ledger exist
//! in phase 3; phase 1 has `Other` and the bridge's own). The tag is per thread and costs no allocation (a const `thread_local`). A block freed
//! under a different tag than it was allocated under makes that owner's `live` underflow, which is counted (`underflows`) rather than hidden: the
//! same honesty as the C ledger's. Memory that C code allocates (the Wi-Fi driver, lwIP, mbedTLS, TinyUSB) never passes through here: that is the
//! part of the heap Rust cannot account for (see ADR 0001, "What Rust does not fix").

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::alloc::System;

/// Who an allocation is for. Phase 3 (the tailnet runtime) tags with these; phase 1 allocates under `Other` only.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Owner {
    /// Everything not otherwise tagged.
    Other = 0,
    /// TLS records and handshakes (phase 3).
    Tls,
    /// The Noise/control channel buffers (phase 3).
    Noise,
    /// The network map (phase 3).
    Map,
    /// The peer directory (phase 3).
    Peer,
    /// WireGuard state and queued handshakes (phase 3).
    WireGuard,
    /// Relay and receive payloads (phase 3).
    Packet,
}

const OWNERS: usize = 7;

thread_local! {
    static CURRENT: Cell<u8> = const { Cell::new(0) };
}

#[allow(dead_code)]
/// Run `f` with allocations attributed to `owner`.
pub fn with_owner<R>(owner: Owner, f: impl FnOnce() -> R) -> R {
    let previous = CURRENT.with(|c| c.replace(owner as u8));
    let result = f();
    CURRENT.with(|c| c.set(previous));
    result
}

#[derive(Debug)]
struct Ledger {
    live: AtomicU32,
    peak: AtomicU32,
    allocs: AtomicU32,
    frees: AtomicU32,
    failed: AtomicU32,
    underflows: AtomicU32,
}

impl Ledger {
    const fn new() -> Self {
        Self {
            live: AtomicU32::new(0),
            peak: AtomicU32::new(0),
            allocs: AtomicU32::new(0),
            frees: AtomicU32::new(0),
            failed: AtomicU32::new(0),
            underflows: AtomicU32::new(0),
        }
    }
}

static TOTAL: Ledger = Ledger::new();
static OWNED: [Ledger; OWNERS] = [const { Ledger::new() }; OWNERS];

/// The accounting allocator: install with `#[global_allocator]`.
#[derive(Debug)]
pub struct Accounting;

// SAFETY: every operation is forwarded unchanged to the system allocator; the counters are side bookkeeping on atomics and never touch the block.
unsafe impl GlobalAlloc for Accounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded under the caller's contract.
        let block = unsafe { System.alloc(layout) };
        note_alloc(layout.size(), block.is_null());
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        note_free(layout.size());
        // SAFETY: forwarded under the caller's contract.
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded under the caller's contract.
        let block = unsafe { System.alloc_zeroed(layout) };
        note_alloc(layout.size(), block.is_null());
        block
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded under the caller's contract.
        let moved = unsafe { System.realloc(block, layout, new_size) };
        if moved.is_null() {
            note_alloc(new_size, true);
        } else {
            note_free(layout.size());
            note_alloc(new_size, false);
        }
        moved
    }
}

fn owner_index() -> usize {
    // A const thread_local without a destructor never allocates, so it is safe to read inside the allocator.
    usize::from(CURRENT.try_with(Cell::get).unwrap_or(0)).min(OWNERS - 1)
}

fn note_alloc(size: usize, failed: bool) {
    let owner = &OWNED[owner_index()];
    for ledger in [&TOTAL, owner] {
        if failed {
            ledger.failed.fetch_add(1, Relaxed);
        } else {
            ledger.allocs.fetch_add(1, Relaxed);
            let live = ledger.live.fetch_add(size as u32, Relaxed).wrapping_add(size as u32);
            ledger.peak.fetch_max(live, Relaxed);
        }
    }
}

fn note_free(size: usize) {
    let owner = &OWNED[owner_index()];
    TOTAL.frees.fetch_add(1, Relaxed);
    TOTAL.live.fetch_sub(size as u32, Relaxed);
    owner.frees.fetch_add(1, Relaxed);
    if owner.live.fetch_update(Relaxed, Relaxed, |live| live.checked_sub(size as u32)).is_err() {
        owner.underflows.fetch_add(1, Relaxed);
        owner.live.store(0, Relaxed);
    }
}

/// A reading of one ledger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// Bytes held now.
    pub live: u32,
    /// Most bytes ever held.
    pub peak: u32,
    /// Allocations made.
    pub allocs: u32,
    /// Allocations freed.
    pub frees: u32,
    /// Allocation requests the heap refused.
    pub failed: u32,
    /// Frees larger than the owner's live bytes (a block freed under another tag).
    pub underflows: u32,
}

fn read(ledger: &Ledger) -> Reading {
    Reading {
        live: ledger.live.load(Relaxed),
        peak: ledger.peak.load(Relaxed),
        allocs: ledger.allocs.load(Relaxed),
        frees: ledger.frees.load(Relaxed),
        failed: ledger.failed.load(Relaxed),
        underflows: ledger.underflows.load(Relaxed),
    }
}

/// Everything Rust allocated.
pub fn total() -> Reading {
    read(&TOTAL)
}

#[allow(dead_code)]
/// One owner's allocations.
pub fn owner(owner: Owner) -> Reading {
    read(&OWNED[owner as usize])
}
