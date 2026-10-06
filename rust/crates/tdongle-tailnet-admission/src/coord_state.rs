//! The control task's states, and which of them hold the negotiation token (`ml_coord_state.h`).
//!
//! The control task is a loop around `match state`. Every attempt walks `StunProbe` .. `FetchPeers` -> `LongPoll`, and every failure lands in
//! `Reconnecting`. The token ([`crate::negotiation`]) covers exactly the walk from `StunProbe` through `FetchPeers`: the Noise handshake,
//! registration and the initial map, the control channel's memory peak. `LongPoll` (steady state), `Reconnecting` (backing off) and `Idle` do not.
//!
//! "Release on every error path" is not a matter of remembering a call at each failure: [`token_sync`] runs at the top of every loop iteration and
//! makes the token follow the state. Any path that leaves a negotiation state, however it got there, lets go at the next iteration, and the
//! loop's exit calls it with [`CoordState::Idle`].

use crate::Millis;
use crate::negotiation::{Grant, Key, Negotiation, Observer, Phase, Prio};

/// `coord_state_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CoordState {
    /// Not running.
    Idle = 0,
    /// STUN probe (first negotiating state).
    StunProbe,
    /// DNS resolve.
    DnsResolve,
    /// TCP connect.
    TcpConnect,
    /// Noise handshake.
    NoiseHandshake,
    /// HTTP/2 preface.
    H2Preface,
    /// Registration.
    Register,
    /// Initial map fetch (last negotiating state).
    FetchPeers,
    /// Steady-state long poll.
    LongPoll,
    /// Backing off after a failure.
    Reconnecting,
}

impl CoordState {
    /// Every state, in order (for exhaustive tests).
    pub const ALL: [CoordState; 10] = [
        CoordState::Idle,
        CoordState::StunProbe,
        CoordState::DnsResolve,
        CoordState::TcpConnect,
        CoordState::NoiseHandshake,
        CoordState::H2Preface,
        CoordState::Register,
        CoordState::FetchPeers,
        CoordState::LongPoll,
        CoordState::Reconnecting,
    ];
    /// `coord_state_negotiates`.
    #[must_use]
    pub const fn negotiates(self) -> bool {
        (self as u8) >= CoordState::StunProbe as u8 && (self as u8) <= CoordState::FetchPeers as u8
    }
}

/// `coord_token_sync`: bring the token in line with `state`. Returns true when the work of `state` may run now: always for a state that does
/// not negotiate, and for a negotiating state only once the token is granted. `engaged` records that this task holds the token OR waits in its
/// queue, so a task that gave up waiting (shutdown, a command, a failure) also leaves the queue instead of lingering until reaped as stale, and
/// steady states never touch the token. Idempotent.
pub fn token_sync<O: Observer>(neg: &mut Negotiation<O>, now: Millis, key: Key, state: CoordState, prio: Prio, engaged: &mut bool) -> bool {
    if state.negotiates() {
        // Ask every time: for the holder this is a cheap "yes", and it notices a token that was reaped.
        *engaged = true;
        return neg.request(now, key, prio, Phase::Control) == Grant::Granted;
    }
    if *engaged {
        let _ = neg.release(now, key);
        *engaged = false;
    }
    true
}
