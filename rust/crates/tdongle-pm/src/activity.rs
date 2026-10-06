//! The forwarding-activity hold.
//!
//! Port of the "activity hold" half of `tdongle_pm_burst.h`/`.c`. Some stages of the forwarded data path (the Wi-Fi driver, the lwIP tcpip
//! task, the USB class task) never wait on a queue of ours, so there is no loop of ours to bracket. They call [`note`](ActivityState::note)
//! when a packet passes. The first note after a quiet spell takes the lock (idle to active) and arms a one-shot timer; the timer calls
//! [`tick`](ActivityState::tick), which keeps the lock until `hold_us` have passed without a note and then drops it. A stream therefore
//! pays for one lock acquire, not one per packet, and the CPU returns to its low frequency about `hold_us` after the last packet.
//!
//! `note()` runs in the caller's task (any task, many at once); `tick()` runs in the timer task. Both are safe against each other: `held` is
//! flipped with an exchange and the burst counter absorbs a begin/end that cross. Never from an interrupt (`note()` then counts an
//! `isr_reject` and does nothing).

use core::sync::atomic::{
    AtomicBool, AtomicU32,
    Ordering::{AcqRel, Acquire, Relaxed},
};

use crate::burst::Burst;

/// Starts the one-shot timer whose expiry calls `tick` (`tdongle_pm_activity_t::arm`). Already armed: nothing to do.
pub trait ArmTimer {
    /// Start the timer to fire once after `delay_us` microseconds.
    fn arm(&self, delay_us: u32);
}

/// No timer (the C's `arm == NULL`): the owner calls `tick` itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTimer;

impl ArmTimer for NoTimer {
    fn arm(&self, _delay_us: u32) {}
}

/// The activity hold's state without its collaborators: the caller passes the burst and the timer to each call. This is the form [`Pm`](crate::Pm)
/// uses (its burst lives in its own registry); [`PmActivity`] binds the collaborators for everyone else.
#[derive(Debug)]
pub struct ActivityState {
    hold_us: u32,
    /// Time of the latest note.
    last_us: AtomicU32,
    /// This object owns one `begin()` on the burst.
    held: AtomicBool,
    /// Idle to active transitions (lock acquires caused by this object).
    starts: AtomicU32,
}

impl ActivityState {
    /// An idle hold of `hold_us` microseconds (`tdongle_pm_activity_init`). `hold_us` must be below 2^31.
    #[must_use]
    pub const fn new(hold_us: u32) -> Self {
        assert!(hold_us < 1 << 31, "hold_us must be below 2^31");
        Self { hold_us, last_us: AtomicU32::new(0), held: AtomicBool::new(false), starts: AtomicU32::new(0) }
    }

    /// The lock is held on behalf of this object.
    #[must_use]
    pub fn held(&self) -> bool {
        self.held.load(Acquire)
    }

    /// Idle to active transitions so far.
    #[must_use]
    pub fn starts(&self) -> u32 {
        self.starts.load(Relaxed)
    }

    /// The lock is taken BEFORE `held` is published. The other order (flag first) left a window in which a tick saw the flag, cleared it and
    /// ended a burst that had not begun (an underflow, ignored), after which the begin completed with the flag clear: the CPU stayed pinned at
    /// maximum until some later note happened to restart the cycle. Now a tick that sees `held` always finds the begin that goes with it. A
    /// note that loses the race for the flag undoes its own begin; the counter nests, so the lock itself is never released in between.
    fn start(&self, burst: &(impl Burst + ?Sized), timer: &(impl ArmTimer + ?Sized)) {
        burst.begin();
        if self.held.swap(true, AcqRel) {
            burst.end();
            return;
        }
        self.starts.fetch_add(1, Relaxed);
        timer.arm(self.hold_us);
    }

    /// A packet is passing (`tdongle_pm_activity_note`): one atomic load while held, otherwise the lock and the timer.
    pub fn note(&self, burst: &(impl Burst + ?Sized), timer: &(impl ArmTimer + ?Sized), now_us: u32) {
        if burst.refuse_in_isr() {
            return;
        }
        self.last_us.store(now_us, Relaxed);
        if self.held.load(Acquire) {
            return; // the common case: one load
        }
        self.start(burst, timer);
    }

    /// The timer fired (`tdongle_pm_activity_tick`): re-arm for what is left of the hold, or drop the lock when `hold_us` have passed since the
    /// last note.
    pub fn tick(&self, burst: &(impl Burst + ?Sized), timer: &(impl ArmTimer + ?Sized), now_us: u32) {
        if !self.held.load(Acquire) {
            return;
        }
        // Signed: a note newer than `now_us` (this tick read the clock first) means "just now", not "71 minutes ago".
        let last = self.last_us.load(Relaxed);
        let idle = (now_us.wrapping_sub(last) as i32).max(0) as u32;
        if idle < self.hold_us {
            let left = self.hold_us - idle;
            timer.arm(left.max(1000));
            return;
        }
        if !self.held.swap(false, AcqRel) {
            return;
        }
        burst.end();
        // A note between the idle test and the exchange saw `held` and returned: take the lock again for it.
        if self.last_us.load(Relaxed) != last {
            self.start(burst, timer);
        }
    }
}

/// The activity hold bound to its burst and timer (`tdongle_pm_activity_t`).
pub struct PmActivity<'a, T: ArmTimer = NoTimer> {
    burst: &'a dyn Burst,
    timer: T,
    state: ActivityState,
}

impl<T: ArmTimer> core::fmt::Debug for PmActivity<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmActivity").field("state", &self.state).finish_non_exhaustive()
    }
}

impl<'a, T: ArmTimer> PmActivity<'a, T> {
    /// A hold on `burst` of `hold_us` microseconds (below 2^31) re-armed through `timer` (`tdongle_pm_activity_init`).
    #[must_use]
    pub const fn new(burst: &'a dyn Burst, hold_us: u32, timer: T) -> Self {
        Self { burst, timer, state: ActivityState::new(hold_us) }
    }

    /// A packet is passing (`tdongle_pm_activity_note`). Task context; from an interrupt it counts an `isr_reject` and does nothing.
    pub fn note(&self, now_us: u32) {
        self.state.note(self.burst, &self.timer, now_us);
    }

    /// The timer fired (`tdongle_pm_activity_tick`).
    pub fn tick(&self, now_us: u32) {
        self.state.tick(self.burst, &self.timer, now_us);
    }

    /// The lock is held on behalf of this object.
    #[must_use]
    pub fn held(&self) -> bool {
        self.state.held()
    }

    /// Idle to active transitions so far.
    #[must_use]
    pub fn starts(&self) -> u32 {
        self.state.starts()
    }

    /// The timer.
    #[must_use]
    pub fn timer(&self) -> &T {
        &self.timer
    }
}
