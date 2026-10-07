//! The datagrams waiting for the WireGuard task: their byte budget (`ml_wg_rx_budget.h`, ADR 0020) and the planner of inbound runs
//! (`ml_wg_rx_batch.h`).
//!
//! # Byte budget
//!
//! A queued datagram is copied out of the Wi-Fi RX buffer into a heap block, so it pins HEAP (`len` + allocator overhead), not a driver
//! buffer. Heap is what is scarce, so the queue is bounded by BYTES across every membership (one counter: N memberships do not multiply it),
//! and by the free heap: a datagram is refused when it would take the bytes past [`ML_WG_RX_QUEUE_BYTES`], or leave less free internal heap than
//! the one elastic floor ([`crate::heap::ML_HB_FLOOR`], ADR 0022). 12 KiB holds 9 full-size WireGuard datagrams (1,264 B) and, by the slot bound
//! ([`crate::limits::ML_WG_RX_QUEUE_DEPTH`]), 12 small ones.
//!
//! # Runs
//!
//! Up to [`ML_WG_RX_BATCH`] transport datagrams taken off the queue by one wake are authenticated, decrypted and delivered together. The planner
//! is the pure part of `ml_wg_rx_run`: which datagrams form a run, where the core lock is taken. The cryptographic steps belong to the WireGuard
//! crate; this module only decides the grouping and counts it.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::heap::{ML_HB_FLOOR, hb_ok};

/// `ML_WG_RX_QUEUE_BYTES`.
pub const ML_WG_RX_QUEUE_BYTES: u32 = 12_288;
/// `ML_WG_RX_FLOOR_FREE`: ONE floor, always (ADR 0022).
pub const ML_WG_RX_FLOOR_FREE: usize = ML_HB_FLOOR;
/// `ML_WG_RX_JOIN_FLOOR_FREE`: the join floor IS the floor.
pub const ML_WG_RX_JOIN_FLOOR_FREE: usize = ML_HB_FLOOR;
/// `ML_WG_RX_OVERHEAD`: allocator header and rounding, charged per datagram.
pub const ML_WG_RX_OVERHEAD: u32 = 16;
/// `ML_WG_RX_BATCH`: datagrams per run, the largest burst one begin/complete hold covers.
pub const ML_WG_RX_BATCH: usize = 8;

const _: () = assert!(ML_WG_RX_FLOOR_FREE == ML_WG_RX_JOIN_FLOOR_FREE);

/// `ml_wgrx_verdict_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// Admitted; the bytes are reserved.
    Ok,
    /// Would take the queued bytes past [`ML_WG_RX_QUEUE_BYTES`].
    Bytes,
    /// Would leave less free internal heap than the floor.
    Heap,
}

/// `ml_wgrx_budget_t`: queued bytes and their peak. Shared by every producer (net_io, the DERP loop) and the consumer (wg_mgr).
#[derive(Debug)]
pub struct Budget {
    bytes: AtomicU32,
    peak: AtomicU32,
}

impl Budget {
    /// Empty.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: AtomicU32::new(0), peak: AtomicU32::new(0) }
    }

    /// `ml_wgrx_admit`: reserve `len` bytes for a datagram about to be queued; the caller releases them when it is popped or freed.
    /// `free_internal` is the free internal heap measured by the caller. Nothing is reserved on refusal.
    pub fn admit(&self, len: usize, free_internal: usize) -> Verdict {
        let cost = len as u32 + ML_WG_RX_OVERHEAD;
        if !hb_ok(free_internal, cost as usize) {
            return Verdict::Heap;
        }
        let mut seen = self.bytes.load(Ordering::Relaxed);
        loop {
            if seen + cost > ML_WG_RX_QUEUE_BYTES {
                return Verdict::Bytes;
            }
            match self.bytes.compare_exchange_weak(seen, seen + cost, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(s) => seen = s,
            }
        }
        self.peak.fetch_max(seen + cost, Ordering::Relaxed);
        Verdict::Ok
    }

    /// `ml_wgrx_queued`: bytes waiting now. Admission counts them as free heap (they drain as soon as wg_mgr runs), so a burst in the queue at
    /// the moment of a join cannot make the join look short.
    #[must_use]
    pub fn queued(&self) -> u32 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// High-water mark since boot.
    #[must_use]
    pub fn peak(&self) -> u32 {
        self.peak.load(Ordering::Relaxed)
    }

    /// `ml_wgrx_release_to`: the datagram of `len` bytes was popped or freed. Saturates at zero instead of wrapping on a double release.
    pub fn release(&self, len: usize) {
        let cost = len as u32 + ML_WG_RX_OVERHEAD;
        let _ = self.bytes.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |b| Some(b.saturating_sub(cost)));
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

/// The core-lock site a step of a run takes (`ML_WG_RX_SITE_*`, for the caller's lock accounting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// Keypair lookup and key copy for every datagram of a run (one hold).
    Begin,
    /// Replay window, endpoint, timers, AllowedIPs (one hold).
    Commit,
    /// A message that is not transport data: handled alone, in one piece.
    Other,
}

/// One group of the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// Transport data `start..end` (1..=[`ML_WG_RX_BATCH`] datagrams): begin hold, decrypt without the lock, commit hold, deliver.
    Data {
        /// First index.
        start: usize,
        /// One past the last index.
        end: usize,
    },
    /// A handshake, cookie or refused message at `index`: its own hold.
    Single {
        /// The datagram's index.
        index: usize,
    },
}

impl Run {
    /// The core-lock sites this group takes, in order.
    #[must_use]
    pub const fn sites(&self) -> &'static [Site] {
        match self {
            Run::Data { .. } => &[Site::Begin, Site::Commit],
            Run::Single { .. } => &[Site::Other],
        }
    }
}

/// Counters of the planner (`rx_run`, `rx_runs`, `rx_runs_full`, `rx_runs_cut` of the wgperf stage).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStats {
    /// Sum of data-run lengths (`WGPERF_ADD(rx_run, ..)`).
    pub run_datagrams: u32,
    /// Data runs (`rx_runs`).
    pub runs: u32,
    /// Runs that hit [`ML_WG_RX_BATCH`] (`rx_runs_full`).
    pub runs_full: u32,
    /// Runs cut short by a non-data message (`rx_runs_cut`).
    pub runs_cut: u32,
}

/// The pure grouping of `ml_wg_rx_run`: `is_data[i]` says whether datagram `i` is transport data. Calls `visit` for each group in order;
/// datagrams complete and are delivered in the order they were taken off the queue. Allocation-free.
pub fn plan_runs(is_data: &[bool], stats: &mut RunStats, mut visit: impl FnMut(Run)) {
    let n = is_data.len();
    let mut at = 0;
    while at < n {
        if !is_data[at] {
            visit(Run::Single { index: at });
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < n && end - at < ML_WG_RX_BATCH && is_data[end] {
            end += 1;
        }
        stats.run_datagrams += (end - at) as u32;
        stats.runs += 1;
        if end - at == ML_WG_RX_BATCH {
            stats.runs_full += 1;
        }
        if end < n && end - at < ML_WG_RX_BATCH {
            stats.runs_cut += 1;
        }
        visit(Run::Data { start: at, end });
        at = end;
    }
}
