//! The global negotiation token (`ml_negotiation.h` / `ml_negotiation.c`, ADR 0013 N1 and N1.2).
//!
//! A membership's join has a memory peak far above its steady cost: the Noise handshake, registration and the initial map (control phase) and
//! the DERP TLS handshake (about 16 KB of TLS state while the certificate is verified). Two joins overlapping add their peaks; that is what
//! took v120 to a 6 KB largest block and a panic. The token serialises them: at most one membership is in a negotiation phase at any moment.
//!
//! * mutual exclusion: one holder;
//! * ordered: highest priority first, FIFO within a priority, a waiter older than `aging_ms` is promoted one class per period;
//! * bounded: [`Acquire`] gives up after its timeout and leaves no trace in the queue, so the failure is retryable;
//! * self-healing: a holder that never releases loses the token after `lease_ms` (counted); a waiter that stops polling is dropped after
//!   `stale_ms`;
//! * non-blocking: [`Negotiation::request`] never waits, it is the call the DERP and control tasks poll.
//!
//! Holders are identified by an opaque non-zero [`Key`], not by a task, so the token passes from the gateway's start path to the control task
//! without a hand-over.
//!
//! # Sans-IO and async
//!
//! There is no clock, lock or sleep in here: time is a [`Millis`] argument. The runtime wraps one `Negotiation` in a mutex (a critical section
//! or an embassy `Mutex<NoopRawMutex, _>` on the single executor) and builds `async fn acquire` from [`Acquire::poll`]:
//!
//! ```ignore
//! let mut a = Acquire::new(now(), timeout_ms, key, prio, phase);
//! loop {
//!     match neg.lock(|n| a.poll(n, now())) {
//!         AcquirePoll::Granted => return Ok(()),
//!         AcquirePoll::Pending { retry_at } => Timer::at(retry_at).await,
//!         AcquirePoll::Failed(why) => return Err(why),
//!     }
//! }
//! ```
//!
//! A future dropped mid-wait must call [`Negotiation::release`] (it is idempotent) so it also leaves the queue at once instead of waiting to be
//! reaped as stale. The observer ([`Observer`]) is told, after the state changed, every time the token moves between free and held.

use crate::Millis;
use core::num::NonZeroU32;

/// `ML_NEG_MAX_WAITERS`.
pub const ML_NEG_MAX_WAITERS: usize = 6;
/// `ML_NEG_LEASE_MS`: a negotiation phase is bounded well below 60 s (the DERP attempt ends at 30 s).
pub const ML_NEG_LEASE_MS: u32 = 90_000;
/// `ML_NEG_STALE_MS`: a poller polls at least every 100 ms.
pub const ML_NEG_STALE_MS: u32 = 2000;
/// `ML_NEG_AGING_MS`.
pub const ML_NEG_AGING_MS: u32 = 20_000;
/// The poll interval of the blocking `ml_neg_acquire` (`ml_sleep_ms(10)`).
pub const ACQUIRE_POLL_MS: u32 = 10;

/// `ml_neg_prio_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Prio {
    /// First join of a membership.
    Start = 0,
    /// The control session dropped: register again.
    Rejoin = 1,
    /// A membership without a relay: DERP handshake.
    Relay = 2,
}

/// `ml_neg_phase_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Phase {
    /// No holder.
    #[default]
    None = 0,
    /// `microlink_init` / `microlink_start` allocations.
    Start,
    /// Noise, registration, initial map.
    Control,
    /// DERP TLS handshake.
    Derp,
}

impl Phase {
    /// `ml_neg_phase_name`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Phase::Start => "start",
            Phase::Control => "control",
            Phase::Derp => "derp",
            Phase::None => "none",
        }
    }
    const fn from_u8(v: u8) -> Phase {
        match v {
            1 => Phase::Start,
            2 => Phase::Control,
            3 => Phase::Derp,
            _ => Phase::None,
        }
    }
}

/// The opaque, never-zero holder key of one membership's phase (`ml_neg_key`). Phase A (START and CONTROL) is one key, so the token passes from
/// the gateway's start path to the control task without a hand-over; phase B (DERP) is another, so a membership's two phases are separate
/// acquisitions and the token is free between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(NonZeroU32);

impl Key {
    /// `ml_neg_key(member_id, phase)`: `((member_id + 1) << 1) | (phase != Derp)`.
    #[must_use]
    pub const fn new(member_id: u32, phase: Phase) -> Key {
        let v = ((member_id.wrapping_add(1)) << 1) | if matches!(phase, Phase::Derp) { 0 } else { 1 };
        match NonZeroU32::new(v) {
            Some(n) => Key(n),
            None => Key(NonZeroU32::MIN), // unreachable for member ids below 2^31
        }
    }
    /// A key from a raw non-zero value (tests, callers with their own numbering).
    #[must_use]
    pub const fn from_raw(v: u32) -> Option<Key> {
        match NonZeroU32::new(v) {
            Some(n) => Some(Key(n)),
            None => None,
        }
    }
    /// The raw value (what `/status` reports as the holder, were it printed).
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0.get()
    }
}

/// `ml_neg_result_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Grant {
    /// The caller holds the token.
    Granted,
    /// The caller waits in the queue; ask again.
    Queued,
    /// The queue is full: refused (counted), nothing queued.
    Full,
}

/// Told, with the new state already visible, every time the token changes hands between "free" and "held" (a grant, a release, a lease
/// expiry). Must not block: the USB transmit buffer uses it to wake its worker.
pub trait Observer {
    /// `busy` is the state after the change.
    fn changed(&mut self, busy: bool);
}

/// The default observer: nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoObserver;
impl Observer for NoObserver {
    fn changed(&mut self, _busy: bool) {}
}

#[derive(Debug, Clone, Copy)]
struct Waiter {
    key: Key,
    prio: u8,
    phase: u8,
    enq_ms: Millis,
    poll_ms: Millis,
    seq: u32,
}

/// `ml_neg_status_t` (plus `releases` and `cancelled`, which the C keeps but does not report).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {
    /// Raw holder key, 0 when free.
    pub holder: u32,
    /// Phase of the holder ([`Phase::None`] when free).
    pub phase: Phase,
    /// Time the holder has held the token.
    pub held_ms: u32,
    /// Waiters queued.
    pub waiting: u32,
    /// Grants since boot.
    pub grants: u32,
    /// Bounded acquisitions that gave up.
    pub timeouts: u32,
    /// Holders that lost the token to the lease.
    pub lease_expired: u32,
    /// Waiters dropped for not polling.
    pub stale_dropped: u32,
    /// Requests refused because the queue was full.
    pub refused_full: u32,
    /// Longest time a grant waited.
    pub max_wait_ms: u32,
    /// Longest hold.
    pub max_hold_ms: u32,
    /// Releases by the holder (not in the C's status).
    pub releases: u32,
    /// Waiters that left the queue by releasing (not in the C's status).
    pub cancelled: u32,
}

/// The token. `O` receives state-change notifications.
#[derive(Debug)]
pub struct Negotiation<O: Observer = NoObserver> {
    lease_ms: u32,
    stale_ms: u32,
    aging_ms: u32,
    holder: Option<Key>,
    holder_phase: Phase,
    granted_ms: Millis,
    q: [Option<Waiter>; ML_NEG_MAX_WAITERS],
    nq: usize,
    seq: u32,
    grants: u32,
    releases: u32,
    timeouts: u32,
    cancelled: u32,
    lease_expired: u32,
    stale_dropped: u32,
    refused_full: u32,
    max_wait_ms: u32,
    max_hold_ms: u32,
    observer: O,
}

impl Negotiation<NoObserver> {
    /// `ml_neg_init`: a zero argument means the default.
    #[must_use]
    pub const fn new(lease_ms: u32, stale_ms: u32, aging_ms: u32) -> Self {
        Self::with_observer(lease_ms, stale_ms, aging_ms, NoObserver)
    }
}

impl<O: Observer> Negotiation<O> {
    /// `ml_neg_init` with an observer (`ml_neg_set_observer`).
    #[must_use]
    pub const fn with_observer(lease_ms: u32, stale_ms: u32, aging_ms: u32, observer: O) -> Self {
        Self {
            lease_ms: if lease_ms != 0 { lease_ms } else { ML_NEG_LEASE_MS },
            stale_ms: if stale_ms != 0 { stale_ms } else { ML_NEG_STALE_MS },
            aging_ms: if aging_ms != 0 { aging_ms } else { ML_NEG_AGING_MS },
            holder: None,
            holder_phase: Phase::None,
            granted_ms: 0,
            q: [None; ML_NEG_MAX_WAITERS],
            nq: 0,
            seq: 0,
            grants: 0,
            releases: 0,
            timeouts: 0,
            cancelled: 0,
            lease_expired: 0,
            stale_dropped: 0,
            refused_full: 0,
            max_wait_ms: 0,
            max_hold_ms: 0,
            observer,
        }
    }

    /// The observer (to replace or inspect it: the C's `ml_neg_set_observer(NULL)`).
    pub fn observer_mut(&mut self) -> &mut O {
        &mut self.observer
    }

    fn find(&self, key: Key) -> Option<usize> {
        (0..self.nq).find(|&i| matches!(self.q[i], Some(w) if w.key == key))
    }

    fn drop_waiter(&mut self, i: usize) {
        for j in i..self.nq - 1 {
            self.q[j] = self.q[j + 1];
        }
        self.nq -= 1;
        self.q[self.nq] = None;
    }

    fn end_hold(&mut self, now: Millis) {
        let held = now.saturating_sub(self.granted_ms) as u32;
        if held > self.max_hold_ms {
            self.max_hold_ms = held;
        }
        self.holder = None;
        self.holder_phase = Phase::None;
        self.observer.changed(false);
    }

    fn waiter(&self, i: usize) -> Waiter {
        // `i < nq` always holds where this is called; the fallback keeps the function total without a panic path.
        self.q[i].unwrap_or(Waiter { key: Key(NonZeroU32::MIN), prio: 0, phase: 0, enq_ms: 0, poll_ms: 0, seq: 0 })
    }

    /// Effective priority: the class, plus one per aging period spent waiting.
    fn effective_prio(&self, i: usize, now: Millis) -> u64 {
        let w = self.waiter(i);
        u64::from(w.prio) + now.saturating_sub(w.enq_ms) / u64::from(self.aging_ms)
    }

    fn reap(&mut self, now: Millis) {
        if self.holder.is_some() && now.saturating_sub(self.granted_ms) > u64::from(self.lease_ms) {
            // The holder never released: a bug or a dead task. Free the token (counted) rather than wedge every join.
            self.lease_expired += 1;
            self.end_hold(now);
        }
        let mut i = 0;
        while i < self.nq {
            if now.saturating_sub(self.waiter(i).poll_ms) > u64::from(self.stale_ms) {
                self.stale_dropped += 1;
                self.drop_waiter(i);
            } else {
                i += 1;
            }
        }
    }

    /// `ml_neg_request`: non-blocking and idempotent. Call repeatedly until [`Grant::Granted`] (a holder asking again stays the holder).
    pub fn request(&mut self, now: Millis, key: Key, prio: Prio, phase: Phase) -> Grant {
        if self.holder == Some(key) {
            return Grant::Granted;
        }
        let mut idx = self.find(key);
        if idx.is_none() {
            if self.nq >= ML_NEG_MAX_WAITERS {
                self.refused_full += 1;
                return Grant::Full;
            }
            let i = self.nq;
            self.nq += 1;
            self.q[i] = Some(Waiter { key, prio: prio as u8, phase: phase as u8, enq_ms: now, poll_ms: now, seq: self.seq });
            self.seq = self.seq.wrapping_add(1);
            idx = Some(i);
        }
        if let Some(i) = idx
            && let Some(w) = self.q[i].as_mut()
        {
            w.poll_ms = now;
        }
        self.reap(now);
        // `reap` may have dropped waiters: look the caller up again.
        if self.find(key).is_none() {
            return Grant::Queued; // cannot happen: the caller just polled, so it is not stale
        }
        if self.holder.is_none() {
            // The best waiter takes the token: highest effective priority, then oldest.
            let mut best = 0;
            for i in 1..self.nq {
                let (pi, pb) = (self.effective_prio(i, now), self.effective_prio(best, now));
                if pi > pb || (pi == pb && self.waiter(i).seq < self.waiter(best).seq) {
                    best = i;
                }
            }
            let w = self.waiter(best);
            if w.key == key {
                let waited = now.saturating_sub(w.enq_ms) as u32;
                if waited > self.max_wait_ms {
                    self.max_wait_ms = waited;
                }
                self.holder = Some(key);
                self.holder_phase = Phase::from_u8(w.phase);
                self.granted_ms = now;
                self.grants += 1;
                self.drop_waiter(best);
                self.observer.changed(true);
                return Grant::Granted;
            }
        }
        Grant::Queued
    }

    /// Leave the queue without releasing (the bounded-acquire timeout path): counts a timeout. Returns whether `key` was queued.
    fn abandon(&mut self, key: Key) -> bool {
        let queued = if let Some(i) = self.find(key) {
            self.drop_waiter(i);
            true
        } else {
            false
        };
        self.timeouts += 1;
        queued
    }

    /// `ml_neg_release`: release the token if `key` holds it, and leave the queue if it waits. Safe at any time, any number of times: this is what
    /// every error path calls. Returns true when `key` was the holder.
    pub fn release(&mut self, now: Millis, key: Key) -> bool {
        let mut was_holder = false;
        if self.holder == Some(key) {
            self.end_hold(now);
            self.releases += 1;
            was_holder = true;
        }
        if let Some(i) = self.find(key) {
            self.drop_waiter(i);
            self.cancelled += 1;
        }
        was_holder
    }

    /// `ml_neg_holds`.
    #[must_use]
    pub fn holds(&self, key: Key) -> bool {
        self.holder == Some(key)
    }

    /// `ml_neg_busy`: true while any membership holds the token (a negotiation is, or may be, allocating its peak). For gates that must not grow
    /// while a join is in progress (the elastic USB transmit buffer, ADR 0015).
    #[must_use]
    pub fn busy(&self) -> bool {
        self.holder.is_some()
    }

    /// `ml_neg_status`.
    #[must_use]
    pub fn status(&self, now: Millis) -> Status {
        Status {
            holder: self.holder.map_or(0, Key::raw),
            phase: self.holder_phase,
            held_ms: if self.holder.is_some() { now.saturating_sub(self.granted_ms) as u32 } else { 0 },
            waiting: self.nq as u32,
            grants: self.grants,
            timeouts: self.timeouts,
            lease_expired: self.lease_expired,
            stale_dropped: self.stale_dropped,
            refused_full: self.refused_full,
            max_wait_ms: self.max_wait_ms,
            max_hold_ms: self.max_hold_ms,
            releases: self.releases,
            cancelled: self.cancelled,
        }
    }

    /// The earliest time at which something time-driven can change if nobody asks: the holder's lease expiring or a waiter going stale. A hint for
    /// the runtime's timer; the C has no equivalent (it reaps only inside requests, and so does this).
    #[must_use]
    pub fn next_deadline(&self) -> Option<Millis> {
        let mut d = self.holder.map(|_| self.granted_ms + u64::from(self.lease_ms) + 1);
        for i in 0..self.nq {
            let t = self.waiter(i).poll_ms + u64::from(self.stale_ms) + 1;
            d = Some(d.map_or(t, |x| x.min(t)));
        }
        d
    }

    /// Size of the token's state in bytes (`size_of::<Self>()`).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
}

/// Why a bounded acquisition failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireFailure {
    /// The timeout elapsed; the caller is out of the queue and may retry later.
    TimedOut,
    /// The queue was full.
    Full,
}

/// One result of [`Acquire::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum AcquirePoll {
    /// The caller holds the token.
    Granted,
    /// Not yet: poll again at `retry_at` (at most [`ACQUIRE_POLL_MS`] ahead, never past the deadline).
    Pending {
        /// When to poll next.
        retry_at: Millis,
    },
    /// Gave up, leaving no trace in the queue.
    Failed(AcquireFailure),
}

/// The pollable form of the blocking `ml_neg_acquire`: bounded, leaves no trace on timeout, retryable.
#[derive(Debug, Clone, Copy)]
pub struct Acquire {
    key: Key,
    prio: Prio,
    phase: Phase,
    deadline: Millis,
}

impl Acquire {
    /// Start an acquisition at `now` that gives up `timeout_ms` later.
    #[must_use]
    pub const fn new(now: Millis, timeout_ms: u32, key: Key, prio: Prio, phase: Phase) -> Self {
        Self { key, prio, phase, deadline: now + timeout_ms as u64 }
    }
    /// One step, exactly the body of the C's loop.
    pub fn poll<O: Observer>(&mut self, neg: &mut Negotiation<O>, now: Millis) -> AcquirePoll {
        match neg.request(now, self.key, self.prio, self.phase) {
            Grant::Granted => AcquirePoll::Granted,
            r => {
                if r == Grant::Full || now >= self.deadline {
                    let _ = neg.abandon(self.key);
                    AcquirePoll::Failed(if r == Grant::Full { AcquireFailure::Full } else { AcquireFailure::TimedOut })
                } else {
                    AcquirePoll::Pending { retry_at: (now + u64::from(ACQUIRE_POLL_MS)).min(self.deadline) }
                }
            }
        }
    }
}
