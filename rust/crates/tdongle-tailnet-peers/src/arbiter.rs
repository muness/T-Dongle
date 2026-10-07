//! Making room in the shared pool (`peer_pool_reserve`, `ml_wg_mgr.c`; ADR 0013 P2, ADR 0012).
//!
//! Every membership's WireGuard device draws its peer slots from ONE pool with a hard cap. The cap is arbitrated here: when no slot is free, the
//! least recently used idle peer of ANY membership is evicted ([`crate::policy::pick_victim`]), never recent traffic. A refusal is counted and
//! surfaces to the caller as the existing "activation rejected" outcome. The eviction itself (removing the victim from its table, releasing its
//! slot, bumping its membership's generation counter) is the caller's: the arbiter decides and counts.

use crate::Millis;
use crate::policy::{ML_POLICY_MAX_CANDIDATES, VictimCandidate, pick_victim};

/// One resident peer that holds a pool slot, as the arbiter sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resident {
    /// The membership (device) that owns it.
    pub member: u8,
    /// Its index in that membership's peer table.
    pub peer: u8,
    /// Last use, trial and pin status.
    pub cand: VictimCandidate,
}

/// What [`Arbiter::reserve`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Reservation {
    /// A slot is free already.
    Free,
    /// Evict this peer, then the slot is free.
    Evict {
        /// Membership of the victim.
        member: u8,
        /// Victim's peer-table index.
        peer: u8,
    },
    /// No peer may be evicted: the activation is rejected (counted).
    Refused,
}

/// The `pool_policy_stats` of the C.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArbiterStats {
    /// The victim belonged to the membership asking for the slot.
    pub evictions_own: u32,
    /// The victim belonged to another membership.
    pub evictions_other: u32,
    /// No eligible victim: the activation was rejected.
    pub refused: u32,
}

/// The arbiter: stateless policy plus its counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct Arbiter {
    stats: ArbiterStats,
}

impl Arbiter {
    /// New, counters zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { stats: ArbiterStats { evictions_own: 0, evictions_other: 0, refused: 0 } }
    }

    /// The counters.
    #[must_use]
    pub const fn stats(&self) -> ArbiterStats {
        self.stats
    }

    /// `peer_pool_reserve`: make sure a slot is free for `requester`. `used` and `capacity` are the pool's; `residents` every peer of every
    /// membership that holds a slot (at most [`ML_POLICY_MAX_CANDIDATES`] are considered, as in the C). `idle_ms` is the protection window
    /// (10 s authenticated, 60 s for a claim). Each membership's `owner_slots` in the candidates is what the caller computed; use
    /// [`Arbiter::with_owner_slots`] to fill it from the list itself.
    pub fn reserve(&mut self, used: usize, capacity: usize, requester: u8, now: Millis, idle_ms: Millis, residents: &[Resident]) -> Reservation {
        if used < capacity {
            return Reservation::Free;
        }
        let n = residents.len().min(ML_POLICY_MAX_CANDIDATES);
        let mut cands = [VictimCandidate::default(); ML_POLICY_MAX_CANDIDATES];
        for (c, r) in cands.iter_mut().zip(&residents[..n]) {
            *c = r.cand;
        }
        match pick_victim(&cands[..n], now, idle_ms) {
            None => {
                self.stats.refused += 1;
                Reservation::Refused
            }
            Some(v) => {
                let r = residents[v];
                if r.member == requester {
                    self.stats.evictions_own += 1;
                } else {
                    self.stats.evictions_other += 1;
                }
                Reservation::Evict { member: r.member, peer: r.peer }
            }
        }
    }

    /// Fill `owner_slots` of every resident with the number of residents of its membership (what `scan_member_peers` computes).
    pub fn with_owner_slots(residents: &mut [Resident]) {
        let mut counts = [0u32; 256];
        for r in residents.iter() {
            counts[usize::from(r.member)] += 1;
        }
        for r in residents.iter_mut() {
            r.cand.owner_slots = counts[usize::from(r.member)];
        }
    }
}
