//! A membership's peer activation: the working set, the trial machinery and the counters (`directory_activate*`, `directory_trial_*`,
//! `derp_sender_admit`, `directory_disco_admit` of `ml_wg_mgr.c`; ADR 0012).
//!
//! Map discovery does not populate the working set: outbound packets and authorized inbound relay/discovery traffic activate peers on demand
//! from the flash directory. A peer used within the idle window (10 s) is never evicted; pressure evicts the least recently used idle peer, preserving
//! the configured priority peer; exhaustion REJECTS the activation rather than evicting recent traffic. Everything the C reaches out to is a [`Host`]
//! method here, so the rules run on the host against a test double (`tests/inbound_trial.rs` ports `test_inbound_trial.c`).

use crate::Millis;
use crate::policy::VictimCandidate;
use crate::record::{DirRecord, PubKey};
use crate::table::{ML_MAX_PEERS, PeerTable};
use crate::trial::{ACTIVATE_IDLE_MS, PollOutcome, TRIAL_EVICT_IDLE_MS, Trial};

/// NaCl box MAC bytes: a DISCO ciphertext shorter than this cannot be authentic (`NACL_BOX_MACBYTES`).
pub const NACL_BOX_MACBYTES: usize = 16;

/// The answer of [`Host::pool_reserve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Room {
    /// A pool slot is free now.
    Free,
    /// Evict this membership's own peer at `peer`; the slot is free afterwards.
    EvictOwn {
        /// Table index of the victim.
        peer: u8,
    },
    /// Nothing may be evicted: the activation is rejected.
    Refused,
}

/// What the membership needs from the rest of the gateway.
pub trait Host {
    /// The directory record for a WireGuard key (`ml_directory_find` by key).
    fn directory_by_key(&mut self, key: &PubKey) -> Option<DirRecord>;
    /// The directory record for a DISCO key.
    fn directory_by_disco(&mut self, key: &PubKey) -> Option<DirRecord>;
    /// `peer_pool_reserve`: make a pool slot free for this membership. `idle_ms` is the protection window; `own` are this membership's residents that
    /// hold a pool slot (table index and eviction candidate), for the host to weigh against every other membership's
    /// ([`crate::arbiter::Arbiter::reserve`]). The host evicts a victim of ANOTHER membership itself and answers [`Room::Free`]; a victim of this one
    /// is answered as [`Room::EvictOwn`] and removed by the membership (which then calls [`Host::peer_removed`]).
    fn pool_reserve(&mut self, idle_ms: Millis, own: &[(u8, VictimCandidate)]) -> Room;
    /// A peer left the table (evicted or trial expired): release its WireGuard slot, bump generation counters.
    fn peer_removed(&mut self, table_index: usize, wg_slot: Option<u8>);
    /// WireGuard reports an authenticated session key for the peer (`wg_peer_authenticated`).
    fn wg_authenticated(&mut self, table_index: usize) -> bool;
    /// The datagram is a plausible WireGuard initiation for our key: size, type and a valid mac1 (`wg_initiation_plausible`).
    fn initiation_plausible(&mut self) -> bool;
    /// The DISCO box opens with the directory record's key (`disco_authenticates`): one X25519 and one box open.
    fn disco_authenticates(&mut self, sender_disco_key: &PubKey, nonce: &[u8; 24], ciphertext_len: usize) -> bool;
}

/// The `jit_*` counters of `microlink_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActivationStats {
    /// Activations of an already-resident peer.
    pub hits: u32,
    /// Activations that needed a slot.
    pub misses: u32,
    /// Peers evicted from the membership's own table.
    pub evictions: u32,
    /// Activations rejected (own table full of recent peers, or the pool refused).
    pub rejected: u32,
}

/// A membership's working set and activation state.
#[derive(Debug, Clone)]
pub struct Membership<const N: usize = ML_MAX_PEERS> {
    /// The resident peers.
    pub table: PeerTable<N>,
    /// The unauthenticated-claim trial.
    pub trial: Trial,
    /// Activation counters.
    pub stats: ActivationStats,
    /// `config.priority_peer_ip`: never evicted, 0 = none.
    pub priority_peer_ip: u32,
    /// A current authoritative map was committed: saved records do not authorize a session before this.
    pub session_valid: bool,
}

impl<const N: usize> Default for Membership<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Membership<N> {
    /// Bytes of one membership's peer state.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// Empty.
    #[must_use]
    pub fn new() -> Self {
        Self { table: PeerTable::new(), trial: Trial::new(), stats: ActivationStats::default(), priority_peer_ip: 0, session_valid: false }
    }

    fn remove(&mut self, host: &mut impl Host, idx: usize) {
        if let Some(slot) = self.table.remove(idx) {
            host.peer_removed(idx, slot);
        }
    }

    /// `directory_activate_idle`: make `record` resident. Returns its table index, or `None` (rejected, counted).
    pub fn activate_idle(&mut self, host: &mut impl Host, now: Millis, record: &DirRecord, idle_ms: Millis) -> Option<usize> {
        if !self.session_valid {
            return None;
        }
        if let Some(i) = self.table.by_key(&record.public_key) {
            self.stats.hits += 1;
            if let Some(p) = self.table.get_mut(i) {
                p.jit_used_ms = now;
            }
            return Some(i);
        }
        self.stats.misses += 1;
        if self.table.is_full() {
            let Some(victim) = self.table.pick_own_victim(now, idle_ms, self.priority_peer_ip) else {
                self.stats.rejected += 1;
                return None;
            };
            self.stats.evictions += 1;
            self.remove(host, victim);
        }
        // The pool of WireGuard slots is shared by every membership: a free peer entry is not enough.
        let mut own = [(0u8, VictimCandidate::default()); N];
        let mut n = 0;
        self.table.candidates(self.priority_peer_ip, |i, c| {
            own[n] = (i as u8, c);
            n += 1;
        });
        match host.pool_reserve(idle_ms, &own[..n]) {
            Room::Free => {}
            Room::EvictOwn { peer } => self.remove(host, usize::from(peer)),
            Room::Refused => {
                self.stats.rejected += 1;
                return None;
            }
        }
        let idx = self.table.insert(record, now)?;
        if let Some(p) = self.table.get_mut(idx) {
            p.jit_used_ms = now;
        }
        Some(idx)
    }

    /// `directory_activate`: activation for traffic the local host or an authenticated packet asked for (10 s protection window).
    pub fn activate(&mut self, host: &mut impl Host, now: Millis, record: &DirRecord) -> Option<usize> {
        self.activate_idle(host, now, record, ACTIVATE_IDLE_MS)
    }

    /// `directory_trial_poll`: confirm or expire the trial peer.
    pub fn trial_poll(&mut self, host: &mut impl Host, now: Millis) {
        let table = &self.table;
        let outcome = self.trial.poll(now, |i| {
            let on_trial = table.get(i).is_some_and(|p| p.unconfirmed);
            (on_trial, on_trial && host.wg_authenticated(i))
        });
        match outcome {
            PollOutcome::Confirmed { peer } => {
                if let Some(p) = self.table.get_mut(peer) {
                    p.unconfirmed = false;
                }
            }
            PollOutcome::Expired { peer } => self.remove(host, peer),
            PollOutcome::Idle | PollOutcome::Forgotten | PollOutcome::Waiting => {}
        }
    }

    /// `directory_trial_open`: may an unauthenticated packet cost a directory lookup and a trial now?
    pub fn trial_open(&mut self, host: &mut impl Host, now: Millis) -> bool {
        self.trial_poll(host, now);
        self.trial.open(now)
    }

    /// `directory_trial_start`: give the record a trial slot. Returns the peer index or `None`.
    pub fn trial_start(&mut self, host: &mut impl Host, now: Millis, record: &DirRecord) -> Option<usize> {
        if let Some(i) = self.table.by_key(&record.public_key) {
            return Some(i); // already resident: nothing to trial
        }
        let idx = self.activate_idle(host, now, record, TRIAL_EVICT_IDLE_MS)?;
        if let Some(p) = self.table.get_mut(idx) {
            p.unconfirmed = true;
        }
        self.trial.start(idx, now);
        Some(idx)
    }

    /// `derp_sender_admit`: resolve the sender of a DERP-relayed WireGuard packet: the resident peer, or a trial activation for a directory peer that
    /// opens with a plausible initiation. `None` means drop the packet; nothing was activated.
    pub fn derp_sender_admit(&mut self, host: &mut impl Host, now: Millis, src_key: &PubKey) -> Option<usize> {
        if let Some(i) = self.table.by_key(src_key) {
            return Some(i);
        }
        if !host.initiation_plausible() || !self.trial_open(host, now) {
            return None;
        }
        let record = host.directory_by_key(src_key)?;
        self.trial_start(host, now, &record)
    }

    /// `directory_disco_admit`: the sender is identified by a key inside the packet, which only the holder of the matching private key can box
    /// correctly. Authenticate first (one X25519 and one box open, bounded by the token budget), activate second: a forged sender key never reaches
    /// the peer table. A resident sender is returned at once.
    pub fn disco_admit(&mut self, host: &mut impl Host, now: Millis, sender_key: &PubKey, nonce: &[u8; 24], ciphertext_len: usize) -> Option<usize> {
        if let Some(i) = self.table.by_disco_key(sender_key) {
            if let Some(p) = self.table.get_mut(i) {
                p.jit_used_ms = now;
            }
            return Some(i);
        }
        if ciphertext_len < NACL_BOX_MACBYTES || !self.trial.take_token(now) {
            return None;
        }
        let record = host.directory_by_disco(sender_key)?;
        if !host.disco_authenticates(sender_key, nonce, ciphertext_len) {
            self.trial.refused += 1;
            return None;
        }
        let idx = self.activate(host, now, &record)?;
        if let Some(p) = self.table.get_mut(idx) {
            p.jit_used_ms = now;
        }
        Some(idx)
    }
}
