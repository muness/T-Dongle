//! Who may take a peer slot, and what an unauthenticated claim may cost: `ml_peer_policy.h` and the trial machinery of `ml_wg_mgr.c`
//! (`directory_trial_*`, ADR 0012/0013).
//!
//! A DERP packet names its sender in 32 bytes nothing authenticates, and a DISCO packet names its sender in a key only the box proves. Either claim can
//! select a directory record and ask for a peer slot. [`TrialGate`] bounds what such claims can cost: a token budget limits how often one may cause a
//! directory lookup (and a box open), one trial slot per membership, a deadline after which an unconfirmed trial is removed and a cool-down before
//! the next. [`pick_victim`] decides who gives up a slot when the pool is full: never a recent peer, never the priority peer, never a trial.

use tdongle_tailnet_types::{Counter, Millis};

/// How long a trial peer has to be authenticated by WireGuard before it is removed.
pub const TRIAL_MS: u64 = 5_000;
/// After a trial expires, no new one for this long.
pub const TRIAL_COOLDOWN_MS: u64 = 30_000;
/// A trial may evict only a peer idle this long (six times the authenticated window).
pub const TRIAL_EVICT_IDLE_MS: u64 = 60_000;
/// An authenticated activation may evict a peer idle this long.
pub const ACTIVATE_EVICT_IDLE_MS: u64 = 10_000;
/// Token bucket capacity: unauthenticated claims allowed in a burst.
pub const TRIAL_TOKEN_BURST: u8 = 3;
/// One token comes back this often.
pub const TRIAL_TOKEN_REFILL_MS: u64 = 1_000;

/// What the caller knows about the trial peer when polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialPeer {
    /// Removed, replaced, or no longer marked unconfirmed.
    Gone,
    /// WireGuard has authenticated it.
    Authenticated,
    /// Still waiting.
    Waiting,
}

/// What [`TrialGate::poll`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialPoll {
    /// No trial pending, or it is still waiting.
    Idle,
    /// The trial peer vanished meanwhile; the gate is free again.
    Cleared,
    /// The trial peer authenticated: make it an ordinary peer (clear its unconfirmed mark).
    Confirmed(u8),
    /// The deadline passed: remove this peer. A cool-down has started.
    Expired(u8),
}

/// Admission control for activations on unauthenticated claims. 40 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrialGate {
    tokens: u8,
    pending: u8,
    refill_ms: u64,
    deadline_ms: u64,
    cooldown_until_ms: u64,
    /// Trials started.
    pub started: Counter,
    /// Trials that WireGuard authenticated.
    pub confirmed: Counter,
    /// Trials removed at their deadline.
    pub expired: Counter,
    /// Claims refused (no token, a trial pending or cooling down, a forged DISCO box).
    pub refused: Counter,
}

impl TrialGate {
    /// Fresh gate (a full bucket on first use).
    pub const fn new() -> Self {
        TrialGate {
            tokens: 0,
            pending: 0,
            refill_ms: 0,
            deadline_ms: 0,
            cooldown_until_ms: 0,
            started: Counter(0),
            confirmed: Counter(0),
            expired: Counter(0),
            refused: Counter(0),
        }
    }

    /// Spend a token for a lookup an unauthenticated packet asks for. Counts a refusal when there is none.
    pub fn token(&mut self, now: Millis) -> bool {
        if self.refill_ms == 0 {
            self.tokens = TRIAL_TOKEN_BURST;
            self.refill_ms = now.max(1);
        }
        let gained = now.saturating_sub(self.refill_ms) / TRIAL_TOKEN_REFILL_MS;
        if gained > 0 {
            let add = gained.min(u64::from(TRIAL_TOKEN_BURST)) as u8;
            self.tokens = self.tokens.saturating_add(add).min(TRIAL_TOKEN_BURST);
            self.refill_ms += gained * TRIAL_TOKEN_REFILL_MS;
        }
        if self.tokens == 0 {
            self.refused.bump();
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// May a DERP claim cause a lookup and a trial now? No while a trial is pending or cooling down; otherwise it costs a token. (Call [`poll`]
    /// first, as the C does, so an expired trial does not block.)
    ///
    /// [`poll`]: TrialGate::poll
    pub fn open(&mut self, now: Millis) -> bool {
        if self.pending != 0 || now < self.cooldown_until_ms {
            self.refused.bump();
            return false;
        }
        self.token(now)
    }

    /// The trial peer sits in `slot` now; it has [`TRIAL_MS`] to authenticate.
    pub fn start(&mut self, slot: u8, now: Millis) {
        self.pending = slot.saturating_add(1);
        self.deadline_ms = now.saturating_add(TRIAL_MS);
        self.started.bump();
    }

    /// The pending trial's slot.
    pub fn pending_slot(&self) -> Option<u8> {
        self.pending.checked_sub(1)
    }

    /// Confirm or expire the trial. Cheap: call after any WireGuard input and from the periodic loop. `peer` reports the state of the trial slot.
    pub fn poll(&mut self, now: Millis, peer: impl FnOnce(u8) -> TrialPeer) -> TrialPoll {
        let Some(slot) = self.pending_slot() else {
            return TrialPoll::Idle;
        };
        match peer(slot) {
            TrialPeer::Gone => {
                self.pending = 0;
                TrialPoll::Cleared
            }
            TrialPeer::Authenticated => {
                self.pending = 0;
                self.confirmed.bump();
                TrialPoll::Confirmed(slot)
            }
            TrialPeer::Waiting if now >= self.deadline_ms => {
                self.pending = 0;
                self.expired.bump();
                self.cooldown_until_ms = now.saturating_add(TRIAL_COOLDOWN_MS);
                TrialPoll::Expired(slot)
            }
            TrialPeer::Waiting => TrialPoll::Idle,
        }
    }

    /// A DISCO box from a non-resident directory peer did not open: count it as a refused claim.
    pub fn note_forged(&mut self) {
        self.refused.bump();
    }
}

/// A resident peer as the eviction policy sees it (`ml_victim_candidate_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VictimCandidate {
    /// When the peer last carried (or was activated for) traffic.
    pub last_used_ms: Millis,
    /// Slots its membership currently holds.
    pub owner_slots: u32,
    /// The membership's priority peer.
    pub pinned: bool,
    /// Activated on an unauthenticated claim and not yet confirmed.
    pub trial: bool,
}

/// Index of the peer that gives up its slot, or `None` when nobody may be evicted (the request is refused, and the caller counts it).
///
/// A peer used within `idle_ms` is never evicted; the priority peer and a trial peer never are; among the rest the least recently used goes, and on a
/// tie the one whose membership holds the most slots. (The C computed the idle time with an unsigned subtraction, so a peer stamped *after* `now` looked
/// idle for ever; here it counts as just used.)
pub fn pick_victim(c: &[VictimCandidate], now: Millis, idle_ms: u64) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, x) in c.iter().enumerate() {
        if x.pinned || x.trial || now.saturating_sub(x.last_used_ms) < idle_ms {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => x.last_used_ms < c[b].last_used_ms || (x.last_used_ms == c[b].last_used_ms && x.owner_slots > c[b].owner_slots),
        };
        if better {
            best = Some(i);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vc(last: u64, slots: u32) -> VictimCandidate {
        VictimCandidate { last_used_ms: last, owner_slots: slots, pinned: false, trial: false }
    }

    /// `tests/test_peer_policy.c`, `picks()`.
    #[test]
    fn picks_like_the_c() {
        let mut c = [vc(1000, 4), vc(500, 2), VictimCandidate { pinned: true, ..vc(200, 4) }, VictimCandidate { trial: true, ..vc(100, 4) }, vc(90000, 2)];
        assert_eq!(pick_victim(&c, 100_000, 10_000), Some(1));
        assert_eq!(pick_victim(&c, 100_000, 20_000), Some(1));
        for x in &mut c {
            x.last_used_ms = 99_000;
        }
        assert_eq!(pick_victim(&c, 100_000, 10_000), None);
        let t = [vc(10, 2), vc(10, 6), vc(10, 3)];
        assert_eq!(pick_victim(&t, 100_000, 10_000), Some(1));
        let w = [vc(50_000, 3)];
        assert_eq!(pick_victim(&w, 100_000, 10_000), Some(0));
        assert_eq!(pick_victim(&w, 100_000, 60_000), None);
        assert_eq!(pick_victim(&[], 1, 1), None);
        // a stamp from the future is "just used"
        assert_eq!(pick_victim(&[vc(200_000, 1)], 100_000, 10_000), None);
    }

    #[test]
    fn token_bucket_burst_then_one_a_second() {
        let mut g = TrialGate::new();
        let t0 = 100_000;
        assert!(g.token(t0) && g.token(t0) && g.token(t0));
        assert!(!g.token(t0));
        assert_eq!(g.refused.get(), 1);
        assert!(!g.token(t0 + 999));
        assert!(g.token(t0 + 1000));
        assert!(!g.token(t0 + 1000));
        // a long quiet period refills only the burst
        let t1 = t0 + 3_600_000;
        assert!(g.token(t1) && g.token(t1) && g.token(t1));
        assert!(!g.token(t1));
    }

    #[test]
    fn trial_lifecycle() {
        let mut g = TrialGate::new();
        let t = 100_000;
        assert!(g.open(t));
        g.start(2, t);
        assert_eq!(g.pending_slot(), Some(2));
        // another unknown key is refused while pending
        assert!(!g.open(t + 1));
        assert_eq!(g.poll(t + 4_999, |_| TrialPeer::Waiting), TrialPoll::Idle);
        assert_eq!(
            g.poll(t + 5_000, |s| {
                assert_eq!(s, 2);
                TrialPeer::Waiting
            }),
            TrialPoll::Expired(2)
        );
        assert_eq!((g.started.get(), g.expired.get()), (1, 1));
        // cool-down
        assert!(!g.open(t + 6_000));
        assert!(!g.open(t + 34_999));
        assert!(g.open(t + 35_000));
        g.start(0, t + 35_000);
        assert_eq!(g.poll(t + 35_001, |_| TrialPeer::Authenticated), TrialPoll::Confirmed(0));
        assert_eq!(g.confirmed.get(), 1);
        assert_eq!(g.pending_slot(), None);
        // confirmed trials never expire
        assert_eq!(g.poll(t + 400_000, |_| unreachable!()), TrialPoll::Idle);
        g.start(1, t + 400_000);
        assert_eq!(g.poll(t + 400_001, |_| TrialPeer::Gone), TrialPoll::Cleared);
        assert!(g.open(t + 400_002));
    }
}
