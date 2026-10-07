//! The global WireGuard peer-slot pool: a hard-capped set of `K` slots shared by every membership (`wireguard_pool.{c,h}` and the pool rules of
//! `wireguard.c`; ADR 0013 P2).
//!
//! # Why one pool
//!
//! Embedding eight peer structs (session keys included) in every WireGuard device costs the same RAM for an idle membership as for a busy one and
//! multiplies by the number of memberships. All devices draw from ONE pool: a membership with three peers costs three slots, and the sum over all
//! memberships can never exceed `K` (12: one full single-membership working set of eight, plus four shared).
//!
//! # Static, generic, policy only
//!
//! The pool is `Pool<S, K>`, a plain array: no allocator, `const fn new`, so it lives in a `static`. `S` is the slot payload: the WireGuard crate's
//! hot peer state (keys, keypairs, handshake). This crate never looks inside it except through [`SlotMeta`]: the receiver indices the slot has
//! reserved, whether a session or handshake owns an index, the peer's public key, its handshake state, and how to wipe it. The C's allocator hooks
//! are replaced by a [`Gate`]: the admission rules that, in C, run inside the allocation (heap floor, largest-block guard). A static pool passes
//! [`Ungated`]; an allocator-backed build passes [`HeapGate`].
//!
//! # Rules, all from the C and its tests
//!
//! * Each slot is tagged with an owner (the device); the per-device peer index is the lowest free index below [`WIREGUARD_MAX_PEERS`] (8). A full
//!   device table is not a pool refusal and is not counted as one.
//! * Receiver indices are unique pool-wide: [`Pool::receiver_index_in_use`] looks at EVERY slot of EVERY owner and every field (current, previous,
//!   next keypair and handshake), whether or not it is marked valid (a stale index is harmless to skip, and the check stays conservative).
//! * Lookups by receiver index, handshake index and public key are scoped to the asking owner: an index live in another device's slot never
//!   resolves here.
//! * A slot is wiped before it is reused or released ([`SlotMeta::wipe`]); releasing twice is harmless; releasing an owner frees exactly its slots.
//! * Split crypto: an initiation computed outside the core lock is committed only if the peer is still the same (same slot generation, same key, same
//!   handshake state) and the index drawn at `begin` is still unused pool-wide ([`Pool::commit_initiation`]); a received datagram's keypair is
//!   re-validated when its decryption completes ([`Pool::rx_commit_valid`]).

use crate::Entropy;
use tdongle_tailnet_admission::HeapProbe;
use tdongle_tailnet_admission::adm::{ML_ADM_TLS_BLOCK_FLOOR, slot_heap_ok};

/// `WIREGUARD_POOL_SLOTS`: the global pool's capacity in the firmware.
pub const WIREGUARD_POOL_SLOTS: usize = 12;
/// `WIREGUARD_MAX_PEERS`: a device's own table size (the device-local peer index is below this).
pub const WIREGUARD_MAX_PEERS: usize = 8;
/// Attempts [`Pool::generate_unique_index`] makes before giving up (the C loops for ever; 12 slots reserve at most 48 values of 2^32).
pub const INDEX_ATTEMPTS: usize = 64;

/// A device (membership) tag. The C uses the device pointer; any stable small number works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerId(pub u8);

/// What the pool must know about a slot payload. Implemented by the WireGuard crate's peer state.
pub trait SlotMeta {
    /// The all-zero state (a freshly acquired slot is zeroed).
    const ZEROED: Self;
    /// Overwrite every byte of key material in a way the compiler may not elide (`wg_pool_secure_zero`); called before a slot is released or reused.
    fn wipe(&mut self);
    /// Every receiver index the slot has reserved: current, previous and next keypair and the handshake. Flags are ignored on purpose
    /// (`index_probe_cb`): a stale index in a destroyed or idle state is harmless to skip, and the check stays conservative.
    fn reserved_indices(&self) -> [u32; 4];
    /// The peer is valid (`peer->valid`).
    fn is_valid(&self) -> bool;
    /// A valid keypair of this (valid) peer has local index `index` (current, next or previous; `peer_lookup_by_receiver`).
    fn session_has_index(&self, index: u32) -> bool;
    /// The (valid) peer has a valid initiator handshake with local index `index` (`peer_lookup_by_handshake`).
    fn handshake_has_index(&self, index: u32) -> bool;
    /// The peer's WireGuard public key.
    fn public_key(&self) -> &[u8; 32];
    /// `(handshake.valid, handshake.local_index)`.
    fn handshake_state(&self) -> (bool, u32);
}

/// Why a [`Gate`] refused a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// A slot beyond the guaranteed ones would leave less free heap than the recovery reserve plus one negotiation peak (`refused_heap`).
    Heap,
    /// The slot would be the allocation that takes the largest free block under the TLS floor (`refused_largest`).
    Largest,
    /// The allocator itself failed (`refused_nomem`).
    NoMemory,
}

/// The admission rules the C runs inside the slot allocation.
pub trait Gate {
    /// May a slot of `slot_bytes` be taken when `live` slots are resident? `Ok(largest_after)` reports the largest free block after the
    /// allocation when the gate knows it (for the `largest_low` gauge).
    fn admit(&mut self, live: u32, slot_bytes: usize) -> Result<Option<usize>, GateRefusal>;
}

/// No gate: the slot's memory is already reserved (a static pool). Heap-floor and largest-block rules have nothing to protect.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ungated;
impl Gate for Ungated {
    fn admit(&mut self, _live: u32, _slot_bytes: usize) -> Result<Option<usize>, GateRefusal> {
        Ok(None)
    }
}

/// The C's rules for an allocator-backed pool: [`slot_heap_ok`] on the free heap, and the largest-block guard, predicted conservatively as "the slot
/// is carved out of the largest block" (the C measures before and after the real allocation; without an allocation to measure, this is the worst
/// case of it). `floor` is [`ML_ADM_TLS_BLOCK_FLOOR`] in the firmware.
#[derive(Debug)]
pub struct HeapGate<'a, P: HeapProbe> {
    probe: &'a P,
    floor: usize,
}
impl<'a, P: HeapProbe> HeapGate<'a, P> {
    /// With the firmware's TLS block floor.
    pub fn new(probe: &'a P) -> Self {
        Self { probe, floor: ML_ADM_TLS_BLOCK_FLOOR }
    }
}
impl<P: HeapProbe> Gate for HeapGate<'_, P> {
    fn admit(&mut self, live: u32, slot_bytes: usize) -> Result<Option<usize>, GateRefusal> {
        let s = self.probe.snapshot();
        if !slot_heap_ok(live, s.free, slot_bytes) {
            return Err(GateRefusal::Heap);
        }
        let after = s.largest.saturating_sub(slot_bytes);
        if !tdongle_tailnet_admission::adm::slot_alloc_ok(s.largest, after, self.floor) {
            return Err(GateRefusal::Largest);
        }
        Ok(Some(after))
    }
}

/// Why [`Pool::acquire`] gave no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum AcquireError {
    /// The owner's own table of [`WIREGUARD_MAX_PEERS`] is full (not a pool refusal: `refused_full` is not counted).
    DeviceTableFull,
    /// The pool is at capacity (`refused_full`).
    PoolFull,
    /// The gate refused (`refused_heap`, `refused_largest`, `refused_nomem`).
    Gate(GateRefusal),
}

/// A held slot: the owner's table index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotRef {
    /// Device-local peer index, `0..WIREGUARD_MAX_PEERS`.
    pub index: u8,
}

/// `wg_pool_stats_t` plus the guard counters of `slot_guard` (`ml_wg_mgr.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Configured capacity `K`.
    pub capacity: u32,
    /// Live slots now.
    pub used: u32,
    /// High-water mark of `used`.
    pub peak_used: u32,
    /// Successful acquisitions.
    pub acquired: u32,
    /// Slots returned.
    pub released: u32,
    /// Refused: the pool was at capacity.
    pub refused_full: u32,
    /// Refused: the allocator failed.
    pub refused_nomem: u32,
    /// Refused: heap floor (`slot_guard.refused_heap`).
    pub refused_heap: u32,
    /// Refused: largest-block guard (`slot_guard.refused_largest`).
    pub refused_largest: u32,
    /// Refused: the owner's device table was full (not in the C's counters).
    pub refused_device_full: u32,
    /// Smallest largest-free-block seen right after a slot allocation (`u32::MAX`: none yet).
    pub largest_low: u32,
    /// Initiation commits refused (not in the C's counters).
    pub commits_refused: u32,
    /// Received-datagram commits refused because the keypair was gone (not in the C's counters).
    pub rx_commits_refused: u32,
}

#[derive(Debug)]
struct Entry<S> {
    owner: Option<OwnerId>,
    index: u8,
    generation: u32,
    payload: S,
}

/// The pool.
#[derive(Debug)]
pub struct Pool<S: SlotMeta, const K: usize = WIREGUARD_POOL_SLOTS> {
    entries: [Entry<S>; K],
    next_generation: u32,
    acquired: u32,
    released: u32,
    peak_used: u32,
    refused_full: u32,
    refused_nomem: u32,
    refused_heap: u32,
    refused_largest: u32,
    refused_device_full: u32,
    largest_low: u32,
    commits_refused: u32,
    rx_commits_refused: u32,
}

/// What `begin_initiation` took under the lock: the checks `commit_initiation` repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiationTicket {
    owner: OwnerId,
    index: u8,
    generation: u32,
    peer_key: [u8; 32],
    prior_valid: bool,
    prior_index: u32,
    /// The receiver index drawn for the new handshake. It is drawn, not reserved: nothing records it until the commit.
    pub receiver_index: u32,
}

/// Why `commit_initiation` installed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum CommitOutcome {
    /// The handshake was installed.
    Installed,
    /// The computation itself failed (`job->ok` false).
    ComputeFailed,
    /// The peer was removed while the lock was free.
    PeerGone,
    /// The slot was released and acquired again for another peer.
    PeerReplaced,
    /// The slot holds a different public key now.
    KeyChanged,
    /// Another initiation or an inbound handshake changed the peer's handshake state (a competing initiation must not be orphaned).
    HandshakeChanged,
    /// The drawn receiver index was taken pool-wide in the meantime.
    IndexTaken,
}

/// What `rx_ticket` took before the decryption ran outside the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxTicket {
    owner: OwnerId,
    index: u8,
    generation: u32,
    local_index: u32,
}

impl<S: SlotMeta, const K: usize> Pool<S, K> {
    /// An empty pool; `const`, so it can be a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [const { Entry { owner: None, index: 0, generation: 0, payload: S::ZEROED } }; K],
            next_generation: 1,
            acquired: 0,
            released: 0,
            peak_used: 0,
            refused_full: 0,
            refused_nomem: 0,
            refused_heap: 0,
            refused_largest: 0,
            refused_device_full: 0,
            largest_low: u32::MAX,
            commits_refused: 0,
            rx_commits_refused: 0,
        }
    }

    /// Bytes of the whole pool (`K` slots of `S` plus bookkeeping): what a static pool pins.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Bytes one slot costs (`sizeof(struct wireguard_peer)` in the C): the payload.
    pub const SLOT_BYTES: usize = core::mem::size_of::<S>();

    /// Capacity `K`.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        K
    }

    /// Live slots.
    #[must_use]
    pub fn used(&self) -> usize {
        self.entries.iter().filter(|e| e.owner.is_some()).count()
    }

    /// Live slots of `owner` (`wireguard_device_peer_count`, `wg_pool_owner_count`).
    #[must_use]
    pub fn owner_count(&self, owner: OwnerId) -> usize {
        self.entries.iter().filter(|e| e.owner == Some(owner)).count()
    }

    fn find(&self, owner: OwnerId, index: u8) -> Option<usize> {
        self.entries.iter().position(|e| e.owner == Some(owner) && e.index == index)
    }

    /// `peer_alloc` + `wg_pool_acquire`: the lowest free device index of `owner`, a zeroed slot from the pool, after the gate's say.
    pub fn acquire<G: Gate>(&mut self, owner: OwnerId, gate: &mut G) -> Result<SlotRef, AcquireError> {
        let Some(index) = (0..WIREGUARD_MAX_PEERS as u8).find(|&x| self.find(owner, x).is_none()) else {
            self.refused_device_full += 1;
            return Err(AcquireError::DeviceTableFull);
        };
        let used = self.used();
        if used >= K {
            self.refused_full += 1;
            return Err(AcquireError::PoolFull);
        }
        match gate.admit(used as u32, Self::SLOT_BYTES) {
            Ok(after) => {
                if let Some(a) = after {
                    self.largest_low = self.largest_low.min(u32::try_from(a).unwrap_or(u32::MAX));
                }
            }
            Err(r) => {
                match r {
                    GateRefusal::Heap => self.refused_heap += 1,
                    GateRefusal::Largest => self.refused_largest += 1,
                    GateRefusal::NoMemory => self.refused_nomem += 1,
                }
                return Err(AcquireError::Gate(r));
            }
        }
        let Some(slot) = self.entries.iter().position(|e| e.owner.is_none()) else {
            // Unreachable: used < K guarantees a free entry. Counted as full rather than panicking.
            self.refused_full += 1;
            return Err(AcquireError::PoolFull);
        };
        let e = &mut self.entries[slot];
        e.payload.wipe();
        e.payload = S::ZEROED;
        e.owner = Some(owner);
        e.index = index;
        e.generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        self.acquired += 1;
        self.peak_used = self.peak_used.max((used + 1) as u32);
        Ok(SlotRef { index })
    }

    /// The slot's payload.
    #[must_use]
    pub fn get(&self, owner: OwnerId, index: u8) -> Option<&S> {
        self.find(owner, index).map(|i| &self.entries[i].payload)
    }

    /// The slot's payload, mutably.
    pub fn get_mut(&mut self, owner: OwnerId, index: u8) -> Option<&mut S> {
        let i = self.find(owner, index)?;
        Some(&mut self.entries[i].payload)
    }

    /// `peer_free`: wipe and release one slot. False (no effect) if it is not live, so a double release is harmless.
    pub fn release(&mut self, owner: OwnerId, index: u8) -> bool {
        match self.find(owner, index) {
            Some(i) => {
                self.free_entry(i);
                true
            }
            None => false,
        }
    }

    fn free_entry(&mut self, i: usize) {
        let e = &mut self.entries[i];
        e.payload.wipe();
        e.payload = S::ZEROED;
        e.owner = None;
        e.index = 0;
        self.released += 1;
    }

    /// `wireguard_device_release_peers`: release every slot of `owner`; returns how many.
    pub fn release_owner(&mut self, owner: OwnerId) -> usize {
        let mut n = 0;
        for i in 0..K {
            if self.entries[i].owner == Some(owner) {
                self.free_entry(i);
                n += 1;
            }
        }
        n
    }

    /// `wireguard_receiver_index_in_use`: is `index` reserved by ANY slot of ANY owner?
    #[must_use]
    pub fn receiver_index_in_use(&self, index: u32) -> bool {
        self.entries.iter().any(|e| e.owner.is_some() && e.payload.reserved_indices().contains(&index))
    }

    /// `wireguard_generate_unique_index`: a random receiver index, never 0 or 0xFFFFFFFF, not reserved anywhere in the pool. `None` after
    /// [`INDEX_ATTEMPTS`] draws (practically impossible: at most `4K` values are reserved).
    pub fn generate_unique_index(&self, rng: &mut impl Entropy) -> Option<u32> {
        for _ in 0..INDEX_ATTEMPTS {
            let mut b = [0u8; 4];
            rng.fill(&mut b);
            let r = u32::from_le_bytes(b);
            if r == 0 || r == u32::MAX {
                continue;
            }
            if !self.receiver_index_in_use(r) {
                return Some(r);
            }
        }
        None
    }

    fn lowest<F: Fn(&S) -> bool>(&self, owner: OwnerId, f: F) -> Option<u8> {
        self.entries.iter().filter(|e| e.owner == Some(owner) && e.payload.is_valid() && f(&e.payload)).map(|e| e.index).min()
    }

    /// `peer_lookup_by_receiver`, scoped to `owner`'s table: the device index of the peer with a valid keypair of that local index.
    #[must_use]
    pub fn lookup_by_receiver(&self, owner: OwnerId, receiver: u32) -> Option<u8> {
        self.lowest(owner, |s| s.session_has_index(receiver))
    }

    /// `peer_lookup_by_handshake`, scoped to `owner`'s table.
    #[must_use]
    pub fn lookup_by_handshake(&self, owner: OwnerId, receiver: u32) -> Option<u8> {
        self.lowest(owner, |s| s.handshake_has_index(receiver))
    }

    /// `peer_lookup_by_pubkey`, scoped to `owner`'s table.
    #[must_use]
    pub fn lookup_by_pubkey(&self, owner: OwnerId, key: &[u8; 32]) -> Option<u8> {
        self.lowest(owner, |s| s.public_key() == key)
    }

    /// `wireguard_initiation_begin` (the part that touches the pool): under the core lock, remember what the peer looked like and draw the
    /// receiver index. `None` when the peer is not valid, or no index could be drawn.
    pub fn begin_initiation(&self, owner: OwnerId, index: u8, rng: &mut impl Entropy) -> Option<InitiationTicket> {
        let i = self.find(owner, index)?;
        let e = &self.entries[i];
        if !e.payload.is_valid() {
            return None;
        }
        let (prior_valid, prior_index) = e.payload.handshake_state();
        Some(InitiationTicket {
            owner,
            index,
            generation: e.generation,
            peer_key: *e.payload.public_key(),
            prior_valid,
            prior_index,
            receiver_index: self.generate_unique_index(rng)?,
        })
    }

    /// `wireguard_initiation_commit`: after the cryptography ran outside the lock (about 40 ms during which the lock was free), install the new
    /// handshake only if nothing relevant changed: `compute_ok`, the peer still there, still the same slot (generation) and key, its handshake state
    /// as at `begin`, and the drawn index still unused pool-wide (which makes "unique across every device" exact rather than 1 - 2^-32).
    /// `install` writes the handshake into the payload.
    pub fn commit_initiation(&mut self, t: &InitiationTicket, compute_ok: bool, install: impl FnOnce(&mut S)) -> CommitOutcome {
        let verdict = (|| {
            if !compute_ok {
                return CommitOutcome::ComputeFailed;
            }
            let Some(i) = self.find(t.owner, t.index) else { return CommitOutcome::PeerGone };
            let e = &self.entries[i];
            if e.generation != t.generation {
                return CommitOutcome::PeerReplaced;
            }
            if !e.payload.is_valid() || e.payload.public_key() != &t.peer_key {
                return CommitOutcome::KeyChanged;
            }
            if e.payload.handshake_state() != (t.prior_valid, t.prior_index) {
                return CommitOutcome::HandshakeChanged;
            }
            if self.receiver_index_in_use(t.receiver_index) {
                return CommitOutcome::IndexTaken;
            }
            CommitOutcome::Installed
        })();
        if verdict == CommitOutcome::Installed {
            if let Some(i) = self.find(t.owner, t.index) {
                install(&mut self.entries[i].payload);
            }
        } else {
            self.commits_refused += 1;
        }
        verdict
    }

    /// `wireguardif_rx_begin`: under the core lock, take what the decryption needs and remember which keypair it belongs to. `None` when no valid
    /// keypair of that index exists for the slot.
    #[must_use]
    pub fn rx_ticket(&self, owner: OwnerId, index: u8, local_index: u32) -> Option<RxTicket> {
        let i = self.find(owner, index)?;
        let e = &self.entries[i];
        (e.payload.is_valid() && e.payload.session_has_index(local_index)).then_some(RxTicket { owner, index, generation: e.generation, local_index })
    }

    /// `wireguardif_rx_complete`: re-validate on completion. False (counted) when the peer was removed or replaced, or the keypair was retired,
    /// while the datagram was being decrypted; the plaintext must then be dropped.
    pub fn rx_commit_valid(&mut self, t: &RxTicket) -> bool {
        let ok = self
            .find(t.owner, t.index)
            .map(|i| &self.entries[i])
            .is_some_and(|e| e.generation == t.generation && e.payload.is_valid() && e.payload.session_has_index(t.local_index));
        if !ok {
            self.rx_commits_refused += 1;
        }
        ok
    }

    /// Visit every live slot in table order (`wg_pool_each`): `(owner, device index, payload)`.
    pub fn each(&self, mut f: impl FnMut(OwnerId, u8, &S)) {
        for e in &self.entries {
            if let Some(o) = e.owner {
                f(o, e.index, &e.payload);
            }
        }
    }

    /// The counters (`wg_pool_get_stats` and the slot guard).
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            capacity: K as u32,
            used: self.used() as u32,
            peak_used: self.peak_used,
            acquired: self.acquired,
            released: self.released,
            refused_full: self.refused_full,
            refused_nomem: self.refused_nomem,
            refused_heap: self.refused_heap,
            refused_largest: self.refused_largest,
            refused_device_full: self.refused_device_full,
            largest_low: self.largest_low,
            commits_refused: self.commits_refused,
            rx_commits_refused: self.rx_commits_refused,
        }
    }

    /// Record the largest free block measured right after an allocation made outside [`Gate::admit`] (allocator-backed builds).
    pub fn note_largest_after(&mut self, largest: usize) {
        self.largest_low = self.largest_low.min(u32::try_from(largest).unwrap_or(u32::MAX));
    }
}

impl<S: SlotMeta, const K: usize> Default for Pool<S, K> {
    fn default() -> Self {
        Self::new()
    }
}
