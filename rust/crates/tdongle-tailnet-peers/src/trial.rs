//! Activation on an unauthenticated claim (`directory_trial_*`, `ml_wg_mgr.c`; ADR 0012 amendment, PR 27).
//!
//! A DERP RecvPacket's source key is a claim: the relay (or anyone able to alter the TLS stream) writes it. WireGuard cannot authenticate an
//! initiation from a peer it has no entry for, so the claim has to select a directory record and give it a slot before the packet can be tested.
//! What the claim must not do is buy lasting state. So an inbound activation is a TRIAL:
//!
//! * only a WireGuard initiation with a valid mac1 for our key is eligible (the caller checks), and everything else from an unknown key is dropped
//!   before any flash read;
//! * one trial slot per membership. While it is held, other unknown keys are refused; a trial that does not authenticate within [`TRIAL_MS`] is removed
//!   and opens a [`TRIAL_COOLDOWN_MS`] cool-down before the next one;
//! * a token bucket ([`TRIAL_TOKEN_BURST`], one refill per [`TRIAL_TOKEN_REFILL_MS`]) limits how often an unauthenticated packet can cost a directory
//!   lookup at all;
//! * a trial uses a free slot, or evicts only a peer idle for [`TRIAL_EVICT_IDLE_MS`] (six times the idle window authenticated traffic needs);
//! * the peer becomes ordinary (confirmed) only once WireGuard reports an authenticated session key for it.

use crate::Millis;

/// `TRIAL_MS`: time a trial peer has to authenticate.
pub const TRIAL_MS: u64 = 5000;
/// `TRIAL_COOLDOWN_MS`: pause after a trial expired unconfirmed.
pub const TRIAL_COOLDOWN_MS: u64 = 30_000;
/// `TRIAL_EVICT_IDLE_MS`: the idle time a peer needs to be evictable for a trial.
pub const TRIAL_EVICT_IDLE_MS: u64 = 60_000;
/// `TRIAL_TOKEN_BURST`.
pub const TRIAL_TOKEN_BURST: u32 = 3;
/// `TRIAL_TOKEN_REFILL_MS`.
pub const TRIAL_TOKEN_REFILL_MS: u64 = 1000;
/// The idle window of authenticated activation (`directory_activate`).
pub const ACTIVATE_IDLE_MS: u64 = 10_000;

/// `microlink_t.inbound_trial`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Trial {
    /// `peer index + 1` of the trial peer, 0 = none.
    pub pending: u8,
    /// Lookup tokens left.
    pub tokens: u32,
    /// When tokens were last refilled; 0 = bucket not started.
    pub refill_ms: Millis,
    /// When the pending trial expires.
    pub deadline_ms: Millis,
    /// No new trial before this time.
    pub cooldown_until_ms: Millis,
    /// Trials started.
    pub started: u32,
    /// Trials confirmed by an authenticated session.
    pub confirmed: u32,
    /// Trials removed unconfirmed.
    pub expired: u32,
    /// Claims refused (busy, cool-down, no token, failed authentication).
    pub refused: u32,
}

/// What [`Trial::poll`] did to the trial peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum PollOutcome {
    /// No trial pending.
    Idle,
    /// The trial peer was removed or replaced meanwhile: the slot is forgotten.
    Forgotten,
    /// WireGuard authenticated the peer: it is ordinary now.
    Confirmed {
        /// The peer's table index.
        peer: usize,
    },
    /// Still within its deadline.
    Waiting,
    /// The deadline passed: the caller removes the peer; a cool-down is running.
    Expired {
        /// The peer's table index.
        peer: usize,
    },
}

impl Trial {
    /// A fresh state.
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: 0, tokens: 0, refill_ms: 0, deadline_ms: 0, cooldown_until_ms: 0, started: 0, confirmed: 0, expired: 0, refused: 0 }
    }

    /// `directory_trial_token`: may an unauthenticated packet cost a lookup now? A burst of three, then one a second.
    pub fn take_token(&mut self, now: Millis) -> bool {
        if self.refill_ms == 0 {
            self.tokens = TRIAL_TOKEN_BURST;
            self.refill_ms = now;
        }
        let gained = (now.saturating_sub(self.refill_ms)) / TRIAL_TOKEN_REFILL_MS;
        if gained != 0 {
            let tokens = u64::from(self.tokens) + gained.min(u64::from(TRIAL_TOKEN_BURST));
            self.tokens = tokens.min(u64::from(TRIAL_TOKEN_BURST)) as u32;
            self.refill_ms += gained * TRIAL_TOKEN_REFILL_MS;
        }
        if self.tokens == 0 {
            self.refused += 1;
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// `directory_trial_poll`: confirm or expire the trial peer. `peer_state(idx)` returns `(active && unconfirmed, authenticated)` for the table
    /// entry. Cheap; call after any WireGuard input and from the periodic loop.
    pub fn poll(&mut self, now: Millis, mut peer_state: impl FnMut(usize) -> (bool, bool)) -> PollOutcome {
        if self.pending == 0 {
            return PollOutcome::Idle;
        }
        let idx = usize::from(self.pending) - 1;
        let (on_trial, authenticated) = peer_state(idx);
        if !on_trial {
            self.pending = 0; // removed or replaced meanwhile
            return PollOutcome::Forgotten;
        }
        if authenticated {
            self.pending = 0;
            self.confirmed += 1;
            return PollOutcome::Confirmed { peer: idx };
        }
        if now >= self.deadline_ms {
            self.pending = 0;
            self.expired += 1;
            self.cooldown_until_ms = now + TRIAL_COOLDOWN_MS;
            return PollOutcome::Expired { peer: idx };
        }
        PollOutcome::Waiting
    }

    /// `directory_trial_open` (after the caller has polled): may an unauthenticated packet cost a directory lookup and a trial now?
    pub fn open(&mut self, now: Millis) -> bool {
        if self.pending != 0 || now < self.cooldown_until_ms {
            self.refused += 1;
            return false;
        }
        self.take_token(now)
    }

    /// `directory_trial_start` (the bookkeeping after the peer was inserted at table index `idx`).
    pub fn start(&mut self, idx: usize, now: Millis) {
        self.pending = (idx + 1) as u8;
        self.deadline_ms = now + TRIAL_MS;
        self.started += 1;
    }
}
