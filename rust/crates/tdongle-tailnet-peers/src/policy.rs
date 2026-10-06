//! Which resident peer gives up its WireGuard slot when the global pool is full (`ml_peer_policy.h`, ADR 0013 P2, ADR 0012).
//!
//! The pool of WireGuard peer slots is shared by every membership. When a membership needs a slot and none is free, one resident peer of ANY
//! membership is evicted; the eviction is not forced on recent traffic:
//!
//! * a peer used within `idle_ms` is never evicted (authenticated activation: 10 s; an activation on an unauthenticated claim: 60 s, so a forged
//!   DERP sender cannot push out another membership's warm peers);
//! * the configured priority peer of its membership is never evicted;
//! * a peer on trial (activated by an inbound claim nobody has authenticated yet) belongs to the trial machinery of its membership, which expires
//!   or confirms it: it is not a victim;
//! * among the rest the least recently used goes, across memberships; on a tie it comes from the membership holding the MOST slots;
//! * when nothing is eligible the request is REFUSED (counted by the caller).
//!
//! Pure function, no heap, bounded.

use crate::Millis;

/// `ML_POLICY_MAX_CANDIDATES`: `ML_MUX_MAX` (4) memberships x 8 resident peers.
pub const ML_POLICY_MAX_CANDIDATES: usize = 32;

/// `ml_victim_candidate_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

/// `ml_policy_pick_victim`: the index of the victim in `c`, or `None` when no candidate may be evicted.
#[must_use]
pub fn pick_victim(c: &[VictimCandidate], now_ms: Millis, idle_ms: Millis) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, x) in c.iter().enumerate() {
        if x.pinned || x.trial {
            continue;
        }
        if now_ms.saturating_sub(x.last_used_ms) < idle_ms {
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
