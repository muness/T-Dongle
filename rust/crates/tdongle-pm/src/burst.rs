//! A nesting counter around a power-management lock: the lock is held while work is pending and only then.
//!
//! Port of `components/tdongle_runtime/include/tdongle_pm_burst.h` and the burst half of `tdongle_pm_burst.c`.
//!
//! * `begin()`: idle to busy takes the lock (nested calls only count).
//! * `end()`: busy to idle releases it when the outermost section ends.
//!
//! The backend is a trait ([`PmBackend`]), so the host tests drive the real counting and error-path logic against a fake lock;
//! [`Pm`](crate::Pm) binds it to `ESP_PM_CPU_FREQ_MAX`.
//!
//! Rules the callers keep (`docs/adr/0016-dfs-power-management.md`):
//!
//! * task context only. In an interrupt, begin/end do nothing and are counted in `isr_rejects`;
//! * a section covers processing, never an indefinite wait: `end()` runs before the task blocks;
//! * a task that can exit calls [`release_all`](PmBurst::release_all) on the way out, so no exit path leaks the lock.
//!
//! Concurrency: the nesting depth is atomic and the backend lock is itself a counting lock, so an interleaving of begin/end from several tasks
//! always leaves the backend balanced (one acquire per 0 to 1, one release per 1 to 0). In practice each object has one owning task. The time
//! accounting is approximate under such interleaving.

use core::sync::atomic::{
    AtomicU32,
    Ordering::{AcqRel, Acquire, Relaxed},
};

/// The lock behind a burst (`tdongle_pm_ops_t`).
pub trait PmBackend: Sync {
    /// Take the lock (`acquire`); `false`: it could not be taken. A refused acquire leaves nothing held; the matching release is then a
    /// harmless error in the backend.
    fn acquire(&self) -> bool;
    /// Release the lock (`release`).
    fn release(&self);
    /// Microsecond clock (`now_us`, optional in the C): without a clock `held_us` stays 0. Default: 0.
    fn now_us(&self) -> u32 {
        0
    }
    /// `true` in an interrupt (`in_isr`, optional): the burst then refuses to run the backend. Default: never.
    fn in_isr(&self) -> bool {
        false
    }
}

/// No backend at all (the C's `ops == NULL`): the burst counts and never touches a lock.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoBackend;

impl PmBackend for NoBackend {
    fn acquire(&self) -> bool {
        true
    }
    fn release(&self) {}
}

/// What the activity hold and the registry need of a burst, object-safe (`tdongle_pm_burst_begin`/`_end` and the interrupt refusal).
pub trait Burst: Sync {
    /// Open a section.
    fn begin(&self);
    /// Close the innermost section.
    fn end(&self);
    /// `true` (and counted in `isr_rejects`) when called from an interrupt: the caller must then do nothing (`refuse_in_isr`).
    fn refuse_in_isr(&self) -> bool;
}

/// Longest burst name kept ([`BurstName`] is inline: no allocation, no lifetimes in the status struct).
pub const NAME_MAX: usize = 23;

/// A burst's name, inline, at most [`NAME_MAX`] bytes (longer names are cut at a character boundary). Replaces the C's `const char *`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BurstName {
    len: u8,
    bytes: [u8; NAME_MAX],
}

impl BurstName {
    /// The name `s`, truncated to [`NAME_MAX`] bytes on a UTF-8 boundary.
    #[must_use]
    pub const fn new(s: &str) -> Self {
        let b = s.as_bytes();
        let mut n = if b.len() > NAME_MAX { NAME_MAX } else { b.len() };
        // back up to a character boundary: a continuation byte is 0b10xxxxxx
        while n > 0 && n < b.len() && (b[n] & 0xC0) == 0x80 {
            n -= 1;
        }
        let mut bytes = [0u8; NAME_MAX];
        let mut i = 0;
        while i < n {
            bytes[i] = b[i];
            i += 1;
        }
        Self { len: n as u8, bytes }
    }

    /// The empty name.
    pub const EMPTY: Self = Self::new("");

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The bytes were copied from a `&str` and cut on a character boundary, so this cannot fail; the fallback keeps the function total.
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

impl core::fmt::Debug for BurstName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl core::fmt::Display for BurstName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A snapshot of one burst's counters (`tdongle_pm_burst_stats_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurstStats {
    /// The burst's name.
    pub name: BurstName,
    /// Sections open now.
    pub depth: u32,
    /// Idle to busy transitions.
    pub acquires: u32,
    /// Busy to idle transitions, including forced ones.
    pub releases: u32,
    /// Total time busy, microseconds; wraps at 2^32 us (71.6 min), consumers take differences.
    pub held_us: u32,
    /// Deepest nesting seen.
    pub max_depth: u32,
    /// `end()` without `begin()`: a caller bug, ignored.
    pub underflows: u32,
    /// `release_all()` found the section still open: a task exited mid-burst.
    pub forced_releases: u32,
    /// The backend refused an acquire.
    pub backend_failures: u32,
    /// `begin`/`end`/`release_all` calls refused because they came from an interrupt.
    pub isr_rejects: u32,
}

/// The atomics of a burst (the data half of `tdongle_pm_burst_t`), independent of how its backend is stored.
#[derive(Debug)]
pub(crate) struct BurstCounters {
    depth: AtomicU32,
    since_us: AtomicU32,
    acquires: AtomicU32,
    releases: AtomicU32,
    held_us: AtomicU32,
    max_depth: AtomicU32,
    underflows: AtomicU32,
    forced_releases: AtomicU32,
    backend_failures: AtomicU32,
    isr_rejects: AtomicU32,
}

impl BurstCounters {
    pub(crate) const fn new() -> Self {
        Self {
            depth: AtomicU32::new(0),
            since_us: AtomicU32::new(0),
            acquires: AtomicU32::new(0),
            releases: AtomicU32::new(0),
            held_us: AtomicU32::new(0),
            max_depth: AtomicU32::new(0),
            underflows: AtomicU32::new(0),
            forced_releases: AtomicU32::new(0),
            backend_failures: AtomicU32::new(0),
            isr_rejects: AtomicU32::new(0),
        }
    }

    pub(crate) fn refuse_in_isr(&self, be: &(impl PmBackend + ?Sized)) -> bool {
        if be.in_isr() {
            self.isr_rejects.fetch_add(1, Relaxed);
            return true;
        }
        false
    }

    pub(crate) fn begin(&self, be: &(impl PmBackend + ?Sized)) {
        if self.refuse_in_isr(be) {
            return;
        }
        let previous = self.depth.fetch_add(1, AcqRel);
        self.max_depth.fetch_max(previous + 1, Relaxed);
        if previous != 0 {
            return;
        }
        self.since_us.store(be.now_us(), Relaxed);
        self.acquires.fetch_add(1, Relaxed);
        // A refused acquire leaves nothing held; the matching release is then a harmless error in the backend.
        if !be.acquire() {
            self.backend_failures.fetch_add(1, Relaxed);
        }
    }

    fn leave(&self, be: &(impl PmBackend + ?Sized)) {
        let held = be.now_us().wrapping_sub(self.since_us.load(Relaxed));
        self.held_us.fetch_add(held, Relaxed);
        self.releases.fetch_add(1, Relaxed);
        be.release();
    }

    pub(crate) fn end(&self, be: &(impl PmBackend + ?Sized)) {
        if self.refuse_in_isr(be) {
            return;
        }
        let mut depth = self.depth.load(Acquire);
        loop {
            if depth == 0 {
                self.underflows.fetch_add(1, Relaxed);
                return;
            }
            match self.depth.compare_exchange_weak(depth, depth - 1, AcqRel, Acquire) {
                Ok(_) => break,
                Err(seen) => depth = seen,
            }
        }
        if depth == 1 {
            self.leave(be);
        }
    }

    pub(crate) fn release_all(&self, be: &(impl PmBackend + ?Sized)) {
        if self.refuse_in_isr(be) {
            return;
        }
        if self.depth.swap(0, AcqRel) == 0 {
            return;
        }
        self.forced_releases.fetch_add(1, Relaxed);
        self.leave(be);
    }

    pub(crate) fn stats(&self, name: BurstName) -> BurstStats {
        BurstStats {
            name,
            depth: self.depth.load(Relaxed),
            acquires: self.acquires.load(Relaxed),
            releases: self.releases.load(Relaxed),
            held_us: self.held_us.load(Relaxed),
            max_depth: self.max_depth.load(Relaxed),
            underflows: self.underflows.load(Relaxed),
            forced_releases: self.forced_releases.load(Relaxed),
            backend_failures: self.backend_failures.load(Relaxed),
            isr_rejects: self.isr_rejects.load(Relaxed),
        }
    }
}

/// A nesting counter bound to a backend lock (`tdongle_pm_burst_t`).
#[derive(Debug)]
pub struct PmBurst<B: PmBackend> {
    name: BurstName,
    backend: B,
    counters: BurstCounters,
}

impl<B: PmBackend> PmBurst<B> {
    /// A burst named `name` over `backend` (`tdongle_pm_burst_init`).
    #[must_use]
    pub const fn new(name: &str, backend: B) -> Self {
        Self { name: BurstName::new(name), backend, counters: BurstCounters::new() }
    }

    /// The backend.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Idle to busy takes the lock; nested calls only count (`tdongle_pm_burst_begin`). From an interrupt: counted in `isr_rejects`, nothing else.
    pub fn begin(&self) {
        self.counters.begin(&self.backend);
    }

    /// Busy to idle releases the lock when the outermost section ends (`tdongle_pm_burst_end`). An `end` without a `begin` is counted in
    /// `underflows` and ignored.
    pub fn end(&self) {
        self.counters.end(&self.backend);
    }

    /// Close every open section at once (task exit, membership stop); a no-op when idle (`tdongle_pm_burst_release_all`).
    pub fn release_all(&self) {
        self.counters.release_all(&self.backend);
    }

    /// Snapshot the counters (`tdongle_pm_burst_stats`).
    #[must_use]
    pub fn stats(&self) -> BurstStats {
        self.counters.stats(self.name)
    }
}

impl<B: PmBackend> Burst for PmBurst<B> {
    fn begin(&self) {
        PmBurst::begin(self);
    }
    fn end(&self) {
        PmBurst::end(self);
    }
    fn refuse_in_isr(&self) -> bool {
        self.counters.refuse_in_isr(&self.backend)
    }
}
