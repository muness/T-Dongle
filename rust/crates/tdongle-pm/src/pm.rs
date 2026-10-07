//! Dynamic frequency scaling for the gateway: 240 MHz while forwarding work is pending, 80 MHz when idle.
//!
//! Port of `components/tdongle_runtime/include/tdongle_pm.h` and `tdongle_pm.c`; design, evidence and the measurement plan are in
//! `alternative/tailnet/docs/adr/0016-dfs-power-management.md`. The hardware (`esp_pm_configure`, `esp_pm_lock_*`, `esp_timer`, the clock) is
//! the [`PmHardware`] trait; what remains here is the registry of bursts, the activity hold, and the status the serial `pm` command prints.
//!
//! [`Pm::start`] configures `esp_pm`. Each forwarding task owns one burst registered here: a counted `ESP_PM_CPU_FREQ_MAX` lock held only
//! while that task has work (see [`crate::burst`] for the rules). Without power management (the legacy bridge, host builds) everything still
//! compiles and counts, and holds no lock.

use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU8, AtomicU32,
    Ordering::{AcqRel, Acquire, Relaxed, Release},
};

use crate::activity::{ActivityState, ArmTimer};
use crate::burst::{Burst, BurstCounters, BurstName, BurstStats, NAME_MAX, PmBackend};

/// The CPU clock while forwarding work is pending, MHz (`TDONGLE_PM_MAX_MHZ`).
pub const MAX_MHZ: u32 = 240;
/// The CPU clock when idle, MHz (`TDONGLE_PM_MIN_MHZ`). Never below 80: the APB clock (UART, SPI LCD, the Wi-Fi driver's
/// `ESP_PM_APB_FREQ_MAX` lock) is 80 MHz and drops with the CPU below that.
pub const MIN_MHZ: u32 = 80;
/// Bursts the registry holds (`TDONGLE_PM_MAX_BURSTS`).
pub const MAX_BURSTS: usize = 8;
/// How long the clock stays at maximum after the last forwarded packet (`TDONGLE_PM_ACTIVITY_HOLD_US`), microseconds. Long enough to bridge
/// the gaps inside a stream and the fairness sleeps, short enough that the chip cools within a fraction of a second of the last packet.
pub const ACTIVITY_HOLD_US: u32 = 200_000;
/// Name of the burst the activity hold registers (`"fwd_activity"` in `tdongle_pm_start`).
pub const ACTIVITY_BURST_NAME: &str = "fwd_activity";

const _: () = assert!(ACTIVITY_HOLD_US == 200_000 && ACTIVITY_HOLD_US < 1 << 31);
const _: () = assert!(MIN_MHZ <= MAX_MHZ && MAX_BURSTS <= u8::MAX as usize);

/// Outcome of creating one CPU-frequency-max lock (`esp_pm_lock_create`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockCreate {
    /// `ESP_OK`: the slot has a lock.
    Created,
    /// `ESP_ERR_NOT_SUPPORTED` (no `CONFIG_PM_ENABLE`): no lock, and not an error: the burst counts and holds nothing.
    NotSupported,
    /// Any other error: no lock, counted in `lock_create_failures`.
    Failed(i32),
}

/// The ESP-IDF side of power management. Slots are the registry indices `0..MAX_BURSTS`; the implementation keeps its lock handle for each in
/// its own table (the C's `pm.slot[i].lock`).
pub trait PmHardware: Sync {
    /// `esp_pm_configure` with [`MAX_MHZ`], [`MIN_MHZ`] and light sleep off (USB must stay enumerated: no tickless idle, no light sleep).
    /// `Err(esp_err_t)` on failure: the CPU then stays at its boot frequency.
    ///
    /// # Errors
    ///
    /// The `esp_err_t` of the failed call.
    fn configure(&self, max_mhz: u32, min_mhz: u32) -> Result<(), i32>;
    /// The CPU clock now, MHz (`esp_clk_cpu_freq() / 1000000`).
    fn cpu_mhz(&self) -> u32;
    /// Microsecond clock (`esp_timer_get_time`), truncated to 32 bits.
    fn now_us(&self) -> u32;
    /// `true` in an interrupt (`xPortInIsrContext`).
    fn in_isr(&self) -> bool;
    /// Create the lock of `slot` (`esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, name, &lock)`).
    fn lock_create(&self, slot: usize, name: &str) -> LockCreate;
    /// Take the lock of `slot` (`esp_pm_lock_acquire`); `false` on error.
    fn lock_acquire(&self, slot: usize) -> bool;
    /// Release the lock of `slot` (`esp_pm_lock_release`).
    fn lock_release(&self, slot: usize);
    /// Create the one-shot timer of the activity hold, whose callback calls [`Pm::activity_fire`] (`esp_timer_create`). `false`: unavailable.
    fn timer_create(&self) -> bool;
    /// Start the timer once after `delay_us` (`esp_timer_start_once`); already armed: nothing to do.
    fn timer_start_once(&self, delay_us: u32);
    /// `esp_pm_dump_locks` into `buf` through `fmemopen`: write as much text as fits, NUL terminated when there is room, and return the bytes
    /// written. Default: none (no `CONFIG_PM_ENABLE`).
    fn dump_locks(&self, _buf: &mut [u8]) -> usize {
        0
    }
}

/// The handle of a registered burst: an index into the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurstId(u8);

impl BurstId {
    /// The registry slot.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Why [`Pm::register_burst`] did not give a fully working burst (the `false` returns of `tdongle_pm_burst_register`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The registry is full: there is no slot, so there is nothing to begin or end. (The C re-initialises the caller's burst with no backend
    /// so it counts; in Rust keep a standalone [`PmBurst<NoBackend>`](crate::PmBurst) for that.)
    Full,
    /// The lock could not be created: the slot exists and its burst counts, but every acquire fails (`backend_failures`) while scaling is on.
    LockFailed(BurstId),
}

impl RegisterError {
    /// The burst that exists despite the error, if any ([`RegisterError::LockFailed`]).
    #[must_use]
    pub const fn failed_id(self) -> Option<BurstId> {
        match self {
            Self::LockFailed(id) => Some(id),
            Self::Full => None,
        }
    }
}

/// What the serial `pm` command prints (`tdongle_pm_status_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmStatus {
    /// `esp_pm_configure` succeeded: the CPU moves between min and max.
    pub scaling: bool,
    /// `esp_err_t` of the last [`Pm::start`] (0 = `ESP_OK`).
    pub configure_error: i32,
    /// As configured; 0 when scaling is off.
    pub max_mhz: u32,
    /// As configured; 0 when scaling is off.
    pub min_mhz: u32,
    /// The clock right now.
    pub cpu_mhz: u32,
    /// Locks `esp_pm_lock_create` refused (other than not-supported).
    pub lock_create_failures: u32,
    /// Valid entries of `burst`.
    pub bursts: u32,
    /// The registered bursts' counters, in registration order.
    pub burst: [BurstStats; MAX_BURSTS],
}

impl PmStatus {
    /// The valid entries of `burst`.
    #[must_use]
    pub fn bursts(&self) -> &[BurstStats] {
        &self.burst[..self.bursts as usize]
    }
}

/// One registry slot: counters, name bytes, the "slot has a lock" flag. All atomic, so the registry needs no lock and no `unsafe`.
#[derive(Debug)]
struct Slot {
    counters: BurstCounters,
    name_len: AtomicU8,
    name: [AtomicU8; NAME_MAX],
    has_lock: AtomicBool,
    /// Published last: status never sees a half-built slot.
    published: AtomicBool,
}

impl Slot {
    const fn new() -> Self {
        Self {
            counters: BurstCounters::new(),
            name_len: AtomicU8::new(0),
            name: [const { AtomicU8::new(0) }; NAME_MAX],
            has_lock: AtomicBool::new(false),
            published: AtomicBool::new(false),
        }
    }

    fn set_name(&self, name: &str) {
        let n = BurstName::new(name);
        for (cell, b) in self.name.iter().zip(n.as_str().bytes()) {
            cell.store(b, Relaxed);
        }
        self.name_len.store(n.as_str().len() as u8, Relaxed);
    }

    fn name(&self) -> BurstName {
        let len = usize::from(self.name_len.load(Relaxed)).min(NAME_MAX);
        let mut buf = [0u8; NAME_MAX];
        for (b, cell) in buf.iter_mut().zip(&self.name).take(len) {
            *b = cell.load(Relaxed);
        }
        BurstName::new(core::str::from_utf8(&buf[..len]).unwrap_or(""))
    }
}

/// The power-management registry over a hardware backend (`pm`, `activity`, `activity_burst` and the functions of `tdongle_pm.c`).
#[derive(Debug)]
pub struct Pm<H: PmHardware> {
    hw: H,
    scaling: AtomicBool,
    configure_error: AtomicI32,
    lock_create_failures: AtomicU32,
    used: AtomicU32,
    slot: [Slot; MAX_BURSTS],
    /// Forwarding activity: the lwIP input hook notes every unicast packet, a one-shot timer drops the lock [`ACTIVITY_HOLD_US`] after the last
    /// one.
    activity: ActivityState,
    activity_slot: AtomicU8,
    activity_ready: AtomicBool,
}

/// The backend of one registry slot (`backend_acquire`, `backend_release`, `backend_now_us`, `backend_in_isr`). While scaling is off the lock
/// is not taken: there is nothing to hold, the CPU is already fixed. A burst begun before [`Pm::start`] and ended after it would hold nothing at
/// the begin and release nothing at the end only if scaling flips between them, which start-once-before-tasks rules out; the release is guarded
/// by the same flag for that reason.
struct SlotBackend<'a, H: PmHardware> {
    pm: &'a Pm<H>,
    idx: usize,
}

impl<H: PmHardware> PmBackend for SlotBackend<'_, H> {
    fn acquire(&self) -> bool {
        if !self.pm.scaling.load(Relaxed) {
            return true;
        }
        self.pm.slot[self.idx].has_lock.load(Acquire) && self.pm.hw.lock_acquire(self.idx)
    }

    fn release(&self) {
        if self.pm.scaling.load(Relaxed) && self.pm.slot[self.idx].has_lock.load(Acquire) {
            self.pm.hw.lock_release(self.idx);
        }
    }

    fn now_us(&self) -> u32 {
        self.pm.hw.now_us()
    }

    fn in_isr(&self) -> bool {
        self.pm.hw.in_isr()
    }
}

/// A registered burst as a [`Burst`], for code that takes `&dyn Burst` (the USB ring's PM hooks, the activity hold).
#[derive(Debug)]
pub struct SlotBurst<'a, H: PmHardware> {
    pm: &'a Pm<H>,
    id: BurstId,
}

impl<H: PmHardware> Clone for SlotBurst<'_, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: PmHardware> Copy for SlotBurst<'_, H> {}

impl<H: PmHardware> Burst for SlotBurst<'_, H> {
    fn begin(&self) {
        self.pm.begin(self.id);
    }
    fn end(&self) {
        self.pm.end(self.id);
    }
    fn refuse_in_isr(&self) -> bool {
        self.pm.slot[self.id.index()].counters.refuse_in_isr(&self.pm.backend(self.id))
    }
}

/// The activity hold's timer: the hardware's one-shot.
struct HwTimer<'a, H: PmHardware>(&'a H);

impl<H: PmHardware> ArmTimer for HwTimer<'_, H> {
    fn arm(&self, delay_us: u32) {
        self.0.timer_start_once(delay_us); // already armed: nothing to do
    }
}

impl<H: PmHardware> Pm<H> {
    /// An unconfigured registry over `hw`: scaling off, nothing registered.
    #[must_use]
    pub const fn new(hw: H) -> Self {
        Self {
            hw,
            scaling: AtomicBool::new(false),
            configure_error: AtomicI32::new(0),
            lock_create_failures: AtomicU32::new(0),
            used: AtomicU32::new(0),
            slot: [const { Slot::new() }; MAX_BURSTS],
            activity: ActivityState::new(ACTIVITY_HOLD_US),
            activity_slot: AtomicU8::new(0),
            activity_ready: AtomicBool::new(false),
        }
    }

    /// The hardware.
    #[must_use]
    pub fn hw(&self) -> &H {
        &self.hw
    }

    fn backend(&self, id: BurstId) -> SlotBackend<'_, H> {
        SlotBackend { pm: self, idx: id.index() }
    }

    /// Enable scaling (max 240, min 80 MHz, no light sleep) (`tdongle_pm_start`). On failure the CPU stays at its boot frequency
    /// (`CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ`, 240 in the gateway image), i.e. fixed at the maximum, and the error is returned for the caller to log.
    /// On success it also registers the `fwd_activity` burst and creates the activity timer; if either fails [`activity_ready`](Self::activity_ready)
    /// stays `false` and hops outside the shared tasks run at the idle clock. Call once, before the forwarding tasks start.
    ///
    /// # Errors
    ///
    /// The `esp_err_t` of `esp_pm_configure`.
    pub fn start(&self) -> Result<(), i32> {
        let result = self.hw.configure(MAX_MHZ, MIN_MHZ);
        self.configure_error.store(result.err().unwrap_or(0), Relaxed);
        self.scaling.store(result.is_ok(), Relaxed);
        // A second start does not register a second activity burst or create a second timer (the C's register was idempotent per object).
        if result.is_ok()
            && !self.activity_ready()
            && let Ok(id) = self.register_burst(ACTIVITY_BURST_NAME)
            && self.hw.timer_create()
        {
            self.activity_slot.store(id.0, Relaxed);
            self.activity_ready.store(true, Release);
        }
        result
    }

    /// The forwarding-activity hold is available (`activity_ready`).
    #[must_use]
    pub fn activity_ready(&self) -> bool {
        self.activity_ready.load(Acquire)
    }

    /// Create a CPU-frequency-max lock called `name` and list a new burst in the status (`tdongle_pm_burst_register`). Bind the returned id with
    /// [`begin`](Self::begin)/[`end`](Self::end)/[`release_all`](Self::release_all) or [`burst`](Self::burst). Unlike the C, which registers a
    /// caller-owned object, the registry owns the burst; a name is registered once per call.
    ///
    /// # Errors
    ///
    /// [`RegisterError::Full`] (no slot), [`RegisterError::LockFailed`] (a slot whose lock could not be created: it counts but holds nothing).
    pub fn register_burst(&self, name: &str) -> Result<BurstId, RegisterError> {
        let claimed = self.used.fetch_update(AcqRel, Relaxed, |u| (u < MAX_BURSTS as u32).then_some(u + 1));
        let Ok(index) = claimed else {
            return Err(RegisterError::Full);
        };
        let index = index as usize;
        let slot = &self.slot[index];
        slot.set_name(name);
        let created = self.hw.lock_create(index, name);
        match created {
            LockCreate::Created => slot.has_lock.store(true, Release),
            LockCreate::NotSupported => {}
            LockCreate::Failed(_) => {
                self.lock_create_failures.fetch_add(1, Relaxed);
            }
        }
        slot.published.store(true, Release); // published last: status never sees a half-built slot
        let id = BurstId(index as u8);
        match created {
            LockCreate::Failed(_) => Err(RegisterError::LockFailed(id)),
            _ => Ok(id),
        }
    }

    /// A registered burst as a [`Burst`] value.
    #[must_use]
    pub fn burst(&self, id: BurstId) -> SlotBurst<'_, H> {
        SlotBurst { pm: self, id }
    }

    /// `tdongle_pm_burst_begin` on a registered burst.
    pub fn begin(&self, id: BurstId) {
        self.slot[id.index()].counters.begin(&self.backend(id));
    }

    /// `tdongle_pm_burst_end` on a registered burst.
    pub fn end(&self, id: BurstId) {
        self.slot[id.index()].counters.end(&self.backend(id));
    }

    /// `tdongle_pm_burst_release_all` on a registered burst.
    pub fn release_all(&self, id: BurstId) {
        self.slot[id.index()].counters.release_all(&self.backend(id));
    }

    /// `tdongle_pm_burst_stats` on a registered burst.
    #[must_use]
    pub fn burst_stats(&self, id: BurstId) -> BurstStats {
        let slot = &self.slot[id.index()];
        slot.counters.stats(slot.name())
    }

    /// A packet is passing through a stage that has no queue of ours to wait on (the lwIP input hook: every forwarded packet, from USB or from
    /// Wi-Fi, goes through it) (`tdongle_pm_note_activity`). Task context, cheap (one atomic load while active), a no-op while scaling is off. The
    /// first call after a quiet spell raises the clock for every core; ADR 0016.
    pub fn note_activity(&self) {
        if self.activity_ready() {
            let burst = self.burst(BurstId(self.activity_slot.load(Relaxed)));
            self.activity.note(&burst, &HwTimer(&self.hw), self.hw.now_us());
        }
    }

    /// The activity timer fired: the hardware's `esp_timer` callback calls this (`activity_fire`).
    pub fn activity_fire(&self) {
        if self.activity_ready() {
            let burst = self.burst(BurstId(self.activity_slot.load(Relaxed)));
            self.activity.tick(&burst, &HwTimer(&self.hw), self.hw.now_us());
        }
    }

    /// The activity hold's state (for diagnostics and the tests).
    #[must_use]
    pub fn activity(&self) -> &ActivityState {
        &self.activity
    }

    /// Snapshot what the serial `pm` command prints (`tdongle_pm_status`).
    #[must_use]
    pub fn status(&self) -> PmStatus {
        let scaling = self.scaling.load(Relaxed);
        let empty = BurstStats {
            name: BurstName::EMPTY,
            depth: 0,
            acquires: 0,
            releases: 0,
            held_us: 0,
            max_depth: 0,
            underflows: 0,
            forced_releases: 0,
            backend_failures: 0,
            isr_rejects: 0,
        };
        let mut out = PmStatus {
            scaling,
            configure_error: self.configure_error.load(Relaxed),
            max_mhz: if scaling { MAX_MHZ } else { 0 },
            min_mhz: if scaling { MIN_MHZ } else { 0 },
            cpu_mhz: self.hw.cpu_mhz(),
            lock_create_failures: self.lock_create_failures.load(Relaxed),
            bursts: 0,
            burst: [empty; MAX_BURSTS],
        };
        let used = (self.used.load(Relaxed) as usize).min(MAX_BURSTS);
        for slot in &self.slot[..used] {
            if !slot.published.load(Acquire) {
                continue;
            }
            out.burst[out.bursts as usize] = slot.counters.stats(slot.name());
            out.bursts += 1;
        }
        out
    }

    /// `esp_pm_dump_locks()` into `buf`, truncated and NUL terminated. Returns the length (`tdongle_pm_dump_locks`).
    pub fn dump_locks(&self, buf: &mut [u8]) -> usize {
        let Some(last) = buf.len().checked_sub(1) else {
            return 0;
        };
        buf[0] = 0;
        let _written = self.hw.dump_locks(buf);
        buf[last] = 0; // NUL terminates when there is room, else the buffer is full
        buf.iter().position(|&b| b == 0).unwrap_or(last)
    }
}
