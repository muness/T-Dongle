//! Property tests of the pool against a naive model, the whole activation world (several memberships, one shared pool, the arbiter) under random
//! schedules, and deterministic mini-fuzzing of the byte decoders.

mod common;
use common::*;
use proptest::prelude::*;
use std::collections::BTreeMap;
use tdongle_tailnet_peers::PubKey;
use tdongle_tailnet_peers::arbiter::{Arbiter, Reservation, Resident};
use tdongle_tailnet_peers::membership::{Host, Membership, Room};
use tdongle_tailnet_peers::policy::VictimCandidate;
use tdongle_tailnet_peers::pool::*;
use tdongle_tailnet_peers::record::DirRecord;

// ---------------------------------------------------------------------------------------------------------------------------------
// Pool against a naive model
// ---------------------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum PoolOp {
    Acquire(u8),
    Release(u8, u8),
    ReleaseOwner(u8),
    /// Start and commit an initiation for (owner, index); `interleave` makes a rival commit first.
    Initiate(u8, u8, bool),
    /// Promote the handshake of (owner, index) to the current keypair (what a completed handshake does).
    Complete(u8, u8),
    Retire(u8, u8),
}

fn pool_op() -> impl Strategy<Value = PoolOp> {
    prop_oneof![
        4 => (0u8..4).prop_map(PoolOp::Acquire),
        2 => (0u8..4, 0u8..9).prop_map(|(o, i)| PoolOp::Release(o, i)),
        1 => (0u8..4).prop_map(PoolOp::ReleaseOwner),
        4 => (0u8..4, 0u8..8, any::<bool>()).prop_map(|(o, i, r)| PoolOp::Initiate(o, i, r)),
        2 => (0u8..4, 0u8..8).prop_map(|(o, i)| PoolOp::Complete(o, i)),
        1 => (0u8..4, 0u8..8).prop_map(|(o, i)| PoolOp::Retire(o, i)),
    ]
}

proptest! {
    /// Allocation semantics equal a naive map; receiver indices stay unique across the whole pool (also through rival commits and keypair
    /// rotation); lookups are scoped; nothing leaks after every owner detaches.
    #[test]
    fn pool_matches_the_naive_model(ops in prop::collection::vec(pool_op(), 1..400), cap_seed in 0u64..1000) {
        let mut pool: Pool<TestSlot, 12> = Pool::new();
        let mut model: BTreeMap<(u8, u8), u8> = BTreeMap::new(); // (owner, index) -> seed
        let mut rng = Script::new(&[]);
        rng.state ^= cap_seed;
        let (mut acquired, mut released) = (0u32, 0u32);
        for (n, op) in ops.iter().enumerate() {
            match *op {
                PoolOp::Acquire(o) => {
                    let owned = model.keys().filter(|k| k.0 == o).count();
                    let r = pool.acquire(OwnerId(o), &mut Ungated);
                    if owned >= WIREGUARD_MAX_PEERS {
                        prop_assert_eq!(r, Err(AcquireError::DeviceTableFull));
                    } else if model.len() >= 12 {
                        prop_assert_eq!(r, Err(AcquireError::PoolFull));
                    } else {
                        let lowest = (0..8u8).find(|i| !model.contains_key(&(o, *i))).unwrap();
                        let slot = r.unwrap();
                        prop_assert_eq!(slot.index, lowest);
                        prop_assert_eq!(*pool.get(OwnerId(o), slot.index).unwrap(), TestSlot::ZEROED);
                        *pool.get_mut(OwnerId(o), slot.index).unwrap() = TestSlot::peer(n as u8 | 1);
                        model.insert((o, slot.index), n as u8 | 1);
                        acquired += 1;
                    }
                }
                PoolOp::Release(o, i) => {
                    let had = model.remove(&(o, i)).is_some();
                    prop_assert_eq!(pool.release(OwnerId(o), i), had);
                    released += u32::from(had);
                }
                PoolOp::ReleaseOwner(o) => {
                    let keys: Vec<_> = model.keys().filter(|k| k.0 == o).copied().collect();
                    for k in &keys { model.remove(k); }
                    prop_assert_eq!(pool.release_owner(OwnerId(o)), keys.len());
                    released += keys.len() as u32;
                }
                PoolOp::Initiate(o, i, rival) => {
                    if let Some(t) = pool.begin_initiation(OwnerId(o), i, &mut rng) {
                        prop_assert!(model.contains_key(&(o, i)));
                        let rival_t = if rival { pool.begin_initiation(OwnerId(o), i, &mut rng) } else { None };
                        if let Some(rt) = &rival_t {
                            let outcome = pool.commit_initiation(rt, true, |s| { s.hs_valid = true; s.hs_initiator = true; s.hs_index = rt.receiver_index; });
                            prop_assert_eq!(outcome, CommitOutcome::Installed);
                        }
                        let out = pool.commit_initiation(&t, true, |s| { s.hs_valid = true; s.hs_initiator = true; s.hs_index = t.receiver_index; });
                        if rival_t.is_some() { prop_assert_eq!(out, CommitOutcome::HandshakeChanged); } else { prop_assert_eq!(out, CommitOutcome::Installed); }
                    } else {
                        prop_assert!(!model.contains_key(&(o, i)));
                    }
                }
                PoolOp::Complete(o, i) => {
                    if let Some(s) = pool.get_mut(OwnerId(o), i)
                        && s.hs_valid
                    {
                        s.prev = s.curr;
                        s.curr = Keypair { valid: true, local_index: s.hs_index };
                        s.hs_valid = false;
                        s.hs_index = 0;
                    }
                }
                PoolOp::Retire(o, i) => {
                    if let Some(s) = pool.get_mut(OwnerId(o), i) { s.prev = Keypair { valid: false, local_index: s.prev.local_index }; }
                }
            }
            // invariants
            prop_assert_eq!(pool.used(), model.len());
            prop_assert!(pool.used() <= 12);
            let mut seen = std::collections::HashSet::new();
            let mut dup = false;
            pool.each(|_, _, s| {
                for ix in s.reserved_indices() {
                    if ix != 0 && !seen.insert(ix) { dup = true; }
                }
            });
            prop_assert!(!dup, "a receiver index is reserved by two slots");
            for o in 0..4u8 { prop_assert_eq!(pool.owner_count(OwnerId(o)), model.keys().filter(|k| k.0 == o).count()); }
        }
        // lookups are scoped to the owner and agree with a brute-force scan
        let mut all: Vec<(u8, u8, u32)> = Vec::new();
        pool.each(|o, i, s| if s.valid && s.curr.valid { all.push((o.0, i, s.curr.local_index)); });
        for (o, i, idx) in &all {
            prop_assert_eq!(pool.lookup_by_receiver(OwnerId(*o), *idx), Some(*i));
            for other in 0..4u8 { if other != *o { prop_assert_eq!(pool.lookup_by_receiver(OwnerId(other), *idx), None); } }
        }
        for o in 0..4u8 { released += pool.release_owner(OwnerId(o)) as u32; }
        let s = pool.stats();
        prop_assert_eq!((s.used, s.acquired, s.released), (0, acquired, released));
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The activation world: several memberships, one pool, the arbiter
// ---------------------------------------------------------------------------------------------------------------------------------

const MEMBERS: usize = 4;

struct World {
    members: Vec<Membership>,
    pool: Pool<TestSlot, 12>,
    arb: Arbiter,
    dir: Vec<DirRecord>,
    authenticated: Vec<[bool; 8]>,
    pinned_ips: [u32; MEMBERS],
    now: u64,
    evicted_recent: u32,
    evicted_protected: u32,
    wrong_victim: u32,
}

struct Ctx<'a> {
    me: usize,
    others: &'a mut [Membership],
    pool: &'a mut Pool<TestSlot, 12>,
    arb: &'a mut Arbiter,
    dir: &'a [DirRecord],
    authenticated: &'a [bool; 8],
    now: u64,
    evicted_recent: &'a mut u32,
    evicted_protected: &'a mut u32,
    wrong_victim: &'a mut u32,
    pinned: &'a [u32; MEMBERS],
}

impl Host for Ctx<'_> {
    fn directory_by_key(&mut self, key: &PubKey) -> Option<DirRecord> {
        self.dir.iter().find(|r| r.public_key == *key).cloned()
    }
    fn directory_by_disco(&mut self, key: &PubKey) -> Option<DirRecord> {
        self.dir.iter().find(|r| r.disco_key == *key).cloned()
    }
    fn pool_reserve(&mut self, idle_ms: u64, own: &[(u8, VictimCandidate)]) -> Room {
        let mut residents: Vec<Resident> = own.iter().map(|(p, c)| Resident { member: self.me as u8, peer: *p, cand: *c }).collect();
        for (m, mem) in self.others.iter().enumerate() {
            if m == self.me {
                continue;
            } // `others` leaves a hole at `me`, an empty membership
            mem.table.candidates(self.pinned[m], |i, c| residents.push(Resident { member: m as u8, peer: i as u8, cand: c }));
        }
        Arbiter::with_owner_slots(&mut residents);
        match self.arb.reserve(self.pool.used(), 12, self.me as u8, self.now, idle_ms, &residents) {
            Reservation::Free => Room::Free,
            Reservation::Refused => Room::Refused,
            Reservation::Evict { member, peer } => {
                let v = residents.iter().find(|r| r.member == member && r.peer == peer).unwrap();
                // the policy, checked independently: nothing recent, pinned or on trial is taken, and the choice is the LRU of the eligible
                if self.now - v.cand.last_used_ms < idle_ms {
                    *self.evicted_recent += 1;
                }
                if v.cand.pinned || v.cand.trial {
                    *self.evicted_protected += 1;
                }
                let best = residents
                    .iter()
                    .filter(|r| !r.cand.pinned && !r.cand.trial && self.now - r.cand.last_used_ms >= idle_ms)
                    .map(|r| (r.cand.last_used_ms, std::cmp::Reverse(r.cand.owner_slots)))
                    .min();
                if best != Some((v.cand.last_used_ms, std::cmp::Reverse(v.cand.owner_slots))) {
                    *self.wrong_victim += 1;
                }
                if usize::from(member) == self.me {
                    Room::EvictOwn { peer }
                } else {
                    let slot = self.others[usize::from(member)].table.remove(usize::from(peer)).unwrap();
                    self.pool.release(OwnerId(member), slot.unwrap());
                    Room::Free
                }
            }
        }
    }
    fn peer_removed(&mut self, _i: usize, wg_slot: Option<u8>) {
        if let Some(s) = wg_slot {
            assert!(self.pool.release(OwnerId(self.me as u8), s));
        }
    }
    fn wg_authenticated(&mut self, i: usize) -> bool {
        self.authenticated[i]
    }
    fn initiation_plausible(&mut self) -> bool {
        true
    }
    fn disco_authenticates(&mut self, _k: &PubKey, _n: &[u8; 24], _l: usize) -> bool {
        true
    }
}

impl World {
    fn new() -> World {
        let dir = (1..=30u32)
            .map(|id| {
                let mut r = DirRecord { vpn_ip: 0x6440_0000 + id, node_id: u64::from(id), has_node_id: true, ..DirRecord::default() };
                r.public_key[..4].copy_from_slice(&id.to_le_bytes());
                r.disco_key[..4].copy_from_slice(&id.to_le_bytes());
                r.disco_key[31] = 1;
                r
            })
            .collect();
        let mut members: Vec<Membership> = (0..MEMBERS).map(|_| Membership::new()).collect();
        for m in &mut members {
            m.session_valid = true;
        }
        World {
            members,
            pool: Pool::new(),
            arb: Arbiter::new(),
            dir,
            authenticated: vec![[false; 8]; MEMBERS],
            pinned_ips: [0; MEMBERS],
            now: 100_000,
            evicted_recent: 0,
            evicted_protected: 0,
            wrong_victim: 0,
        }
    }

    /// Run `f` for membership `me` with a host that sees the others.
    fn with<R>(&mut self, me: usize, f: impl FnOnce(&mut Membership, &mut Ctx<'_>) -> R) -> R {
        let mut mine = std::mem::take(&mut self.members[me]);
        mine.priority_peer_ip = self.pinned_ips[me];
        let r = {
            let mut ctx = Ctx {
                me,
                others: &mut self.members,
                pool: &mut self.pool,
                arb: &mut self.arb,
                dir: &self.dir,
                authenticated: &self.authenticated[me],
                now: self.now,
                evicted_recent: &mut self.evicted_recent,
                evicted_protected: &mut self.evicted_protected,
                wrong_victim: &mut self.wrong_victim,
                pinned: &self.pinned_ips,
            };
            f(&mut mine, &mut ctx)
        };
        self.members[me] = mine;
        r
    }

    /// What the WireGuard crate does after an activation: take the slot, put the peer in it.
    fn attach_slot(&mut self, me: usize, idx: usize) {
        let m = &mut self.members[me];
        if m.table.get(idx).is_some_and(|p| p.wg_slot.is_none()) {
            let r = self.pool.acquire(OwnerId(me as u8), &mut Ungated).expect("reserve guaranteed room");
            let key = m.table.get(idx).unwrap().public_key;
            let mut s = TestSlot::peer(1);
            s.public_key = key;
            *self.pool.get_mut(OwnerId(me as u8), r.index).unwrap() = s;
            m.table.get_mut(idx).unwrap().wg_slot = Some(r.index);
        }
    }

    fn check(&self) {
        let residents: usize = self.members.iter().map(|m| m.table.residents()).sum();
        assert_eq!(self.pool.used(), residents, "every pool slot belongs to one resident peer");
        assert!(self.pool.used() <= 12);
        for (me, m) in self.members.iter().enumerate() {
            assert!(m.table.len() <= 8);
            assert_eq!(self.pool.owner_count(OwnerId(me as u8)), m.table.residents());
            for (_, p) in m.table.iter() {
                if let Some(s) = p.wg_slot {
                    assert_eq!(self.pool.get(OwnerId(me as u8), s).map(|x| x.public_key), Some(p.public_key));
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum WorldOp {
    Activate(u8, u8),
    Claim(u8, u8),
    Touch(u8, u8),
    Advance(u16),
    Confirm(u8),
    Detach(u8),
    Pin(u8, u8),
}

fn world_op() -> impl Strategy<Value = WorldOp> {
    prop_oneof![
        6 => (0u8..MEMBERS as u8, 1u8..31).prop_map(|(m, r)| WorldOp::Activate(m, r)),
        3 => (0u8..MEMBERS as u8, 1u8..31).prop_map(|(m, r)| WorldOp::Claim(m, r)),
        3 => (0u8..MEMBERS as u8, 0u8..8).prop_map(|(m, i)| WorldOp::Touch(m, i)),
        4 => (0u16..30_000).prop_map(WorldOp::Advance),
        2 => (0u8..MEMBERS as u8).prop_map(WorldOp::Confirm),
        1 => (0u8..MEMBERS as u8).prop_map(WorldOp::Detach),
        1 => (0u8..MEMBERS as u8, 1u8..31).prop_map(|(m, r)| WorldOp::Pin(m, r)),
    ]
}

proptest! {
    /// Under random traffic across memberships: the pool never overflows, every slot belongs to exactly one resident peer, no victim is recent,
    /// pinned or on trial, the victim is the least recently used of the eligible, and detaching a membership releases exactly its slots.
    #[test]
    fn activation_world_invariants(ops in prop::collection::vec(world_op(), 1..300)) {
        let mut w = World::new();
        for op in ops {
            match op {
                WorldOp::Activate(m, r) => {
                    let (m, rec) = (usize::from(m), w.dir[usize::from(r) - 1].clone());
                    let now = w.now;
                    if let Some(idx) = w.with(m, |mem, host| mem.activate(host, now, &rec)) { w.attach_slot(m, idx); }
                }
                WorldOp::Claim(m, r) => {
                    let (m, key) = (usize::from(m), w.dir[usize::from(r) - 1].public_key);
                    let now = w.now;
                    if let Some(idx) = w.with(m, |mem, host| mem.derp_sender_admit(host, now, &key)) { w.attach_slot(m, idx); }
                }
                WorldOp::Touch(m, i) => { let now = w.now; if let Some(p) = w.members[usize::from(m)].table.get_mut(usize::from(i)) { p.jit_used_ms = now; } }
                WorldOp::Advance(dt) => w.now += u64::from(dt),
                WorldOp::Confirm(m) => {
                    let m = usize::from(m);
                    if let Some(i) = w.members[m].trial.pending.checked_sub(1) { w.authenticated[m][usize::from(i)] = true; }
                    let now = w.now;
                    w.with(m, |mem, host| mem.trial_poll(host, now));
                    w.authenticated[m] = [false; 8];
                }
                WorldOp::Detach(m) => {
                    let m = usize::from(m);
                    let n = w.members[m].table.residents();
                    prop_assert_eq!(w.pool.release_owner(OwnerId(m as u8)), n);
                    w.members[m] = Membership::new();
                    w.members[m].session_valid = true;
                    prop_assert_eq!(w.pool.owner_count(OwnerId(m as u8)), 0);
                }
                WorldOp::Pin(m, r) => { w.pinned_ips[usize::from(m)] = w.dir[usize::from(r) - 1].vpn_ip; }
            }
            // an expired trial is removed by the poll inside derp_sender_admit; run the poll for everyone like the periodic loop does
            w.check();
        }
        prop_assert_eq!((w.evicted_recent, w.evicted_protected, w.wrong_victim), (0, 0, 0));
        for m in 0..MEMBERS { w.pool.release_owner(OwnerId(m as u8)); }
        let s = w.pool.stats();
        prop_assert_eq!((s.used, s.acquired), (0, s.released));
    }
}

#[test]
fn world_sanity_pool_fills_and_evicts_across_memberships() {
    let mut w = World::new();
    let activate = |w: &mut World, m: usize, r: usize| {
        let rec = w.dir[r - 1].clone();
        let now = w.now;
        let got = w.with(m, |mem, host| mem.activate(host, now, &rec));
        if let Some(idx) = got {
            w.attach_slot(m, idx);
        }
        w.check();
        got
    };
    // Memberships 1 and 2 fill the whole pool between them (8 + 4).
    for r in 1..=8 {
        w.now += 11_000;
        assert!(activate(&mut w, 1, r).is_some());
    }
    for r in 9..=12 {
        w.now += 11_000;
        assert!(activate(&mut w, 2, r).is_some());
    }
    assert_eq!(w.pool.used(), 12);
    // Membership 0 asks for six: each is made room for by evicting the least recently used idle peer of ANOTHER membership, oldest first.
    for r in 13..=18 {
        w.now += 11_000;
        assert!(activate(&mut w, 0, r).is_some());
    }
    let a = w.arb.stats();
    assert_eq!((a.evictions_other, a.evictions_own, a.refused), (6, 0, 0), "{a:?}");
    assert_eq!(w.members[1].table.len() + w.members[2].table.len(), 6);
    assert!(w.members[1].table.by_key(&w.dir[0].public_key).is_none(), "membership 1's oldest peer went first");
    assert_eq!((w.members[1].table.len(), w.members[2].table.len(), w.members[0].table.len()), (2, 4, 6), "the six oldest were all membership 1's");
    let s = w.pool.stats();
    assert!(s.peak_used == 12 && s.refused_full == 0, "the arbiter makes room before the pool refuses: {s:?}");
    assert_eq!((w.evicted_recent, w.evicted_protected, w.wrong_victim), (0, 0, 0));
    // Everything hot: the request is refused rather than evicting recent traffic.
    let mut w = World::new();
    for r in 1..=12 {
        w.now += 100;
        let m = if r <= 8 { 1 } else { 2 };
        assert!(activate(&mut w, m, r).is_some());
    }
    w.now += 100;
    assert!(activate(&mut w, 0, 20).is_none());
    assert_eq!(w.arb.stats().refused, 1);
    assert_eq!(w.members[0].stats.rejected, 1);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Mini-fuzz of the decoders
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn minifuzz_decoders_never_panic() {
    use tdongle_tailnet_peers::{directory, nvs_cache};
    let mut seed = 0xfeed_beef_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    // a valid blob, then mutated
    let mut cache: nvs_cache::PeerCache = nvs_cache::PeerCache::new();
    for i in 0..70u32 {
        let r = DirRecord { vpn_ip: 0x6440_0000 + i, ..DirRecord::default() };
        cache.save(&nvs_cache::SaveInput::from_record(&r));
    }
    let mut blob = vec![0u8; nvs_cache::PeerCache::<64>::MAX_BLOB_BYTES];
    let n = cache.to_blob(&mut blob).unwrap();
    blob.truncate(n);
    let img = {
        let mut b = directory::encode_header(3).to_vec();
        for i in 0..5u32 {
            b.extend_from_slice(&directory::encode_record(&DirRecord { vpn_ip: i + 1, ..DirRecord::default() }));
        }
        let crc = directory::image_crc(&b.as_slice(), b.len()).unwrap();
        b.extend_from_slice(&crc.to_le_bytes());
        b
    };
    for round in 0..4000 {
        let mut b = blob.clone();
        let mut c = img.clone();
        for _ in 0..(next() % 6) {
            let (i, j) = ((next() as usize) % b.len(), (next() as usize) % c.len());
            b[i] ^= 1 << (next() % 8);
            c[j] ^= 1 << (next() % 8);
        }
        if round % 5 == 0 {
            b.truncate((next() as usize) % (b.len() + 1));
            c.truncate((next() as usize) % (c.len() + 1));
        }
        let (t, _) = nvs_cache::PeerCache::<64>::from_blob(&b);
        assert!(t.len() <= 64);
        for p in t.load_all(64, 0) {
            let _ = p.meta.hostname.as_str();
        }
        let _ = directory::validate(&c.as_slice());
        let mut out = vec![0u8; nvs_cache::PeerCache::<64>::MAX_BLOB_BYTES];
        assert!(t.to_blob(&mut out).is_some());
        let mut a = 0usize;
        directory::alias_scan(&c.as_slice(), |_| a += 1);
        let _ = directory::alias_find(&c.as_slice(), 1, 2, 3);
    }
}
