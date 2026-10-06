//! Ports of tests/test_wg_peer_pool.c (the pool core) and tests/test_wg_peer_pool_if.c (what the pool decides for the WireGuard devices:
//! sharing, exhaustion, atomic failures, receiver-index uniqueness and scoping, the initiation commit guards).

mod common;
use common::*;
use core::sync::atomic::Ordering;
use tdongle_tailnet_admission::adm::{ML_ADM_PEER_SLOTS, ML_ADM_TLS_BLOCK_FLOOR};
use tdongle_tailnet_peers::pool::*;

type P = Pool<TestSlot, 12>;
const A: OwnerId = OwnerId(1);
const B: OwnerId = OwnerId(2);
const C: OwnerId = OwnerId(3);

fn put(p: &mut P, o: OwnerId, seed: u8) -> u8 {
    let r = p.acquire(o, &mut Ungated).unwrap();
    *p.get_mut(o, r.index).unwrap() = TestSlot::peer(seed);
    r.index
}

#[test]
fn capacity_cap_zeroed_slots_refusal_and_counters() {
    // test_wg_peer_pool.c: capacity cap, zeroed slots, full refusal, tagging
    let mut p: Pool<TestSlot, 4> = Pool::new();
    let mut idx = std::vec::Vec::new();
    for o in [A, A, B, C] {
        let r = p.acquire(o, &mut Ungated).unwrap();
        assert_eq!(*p.get(o, r.index).unwrap(), TestSlot::ZEROED, "a fresh slot is zeroed");
        idx.push((o, r.index));
    }
    assert_eq!((p.used(), p.capacity()), (4, 4));
    assert_eq!(p.acquire(A, &mut Ungated), Err(AcquireError::PoolFull));
    let st = p.stats();
    assert!(st.refused_full == 1 && st.refused_nomem == 0 && st.acquired == 4 && st.peak_used == 4 && st.used == 4 && st.capacity == 4);
    assert!(p.owner_count(A) == 2 && p.owner_count(B) == 1 && p.owner_count(C) == 1);
    assert_eq!(idx, [(A, 0), (A, 1), (B, 0), (C, 0)], "the lowest free device index");
    let mut visited = 0;
    p.each(|o, i, _| {
        assert!(idx.contains(&(o, i)));
        visited += 1;
    });
    assert_eq!(visited, 4);
    // release wipes before reuse; double release harmless; slot reuse
    p.get_mut(A, 1).unwrap().secret = [0x5C; 32];
    let before = WIPES_WITH_SECRET.load(Ordering::Relaxed);
    assert!(p.release(A, 1));
    assert!(WIPES_WITH_SECRET.load(Ordering::Relaxed) > before, "the secret was wiped on release");
    assert!(!p.release(A, 1), "double release: no effect");
    assert!(!p.release(OwnerId(9), 0) && !p.release(A, 7));
    assert_eq!((p.used(), p.owner_count(A)), (3, 1));
    let again = p.acquire(B, &mut Ungated).unwrap();
    assert_eq!((again.index, p.used()), (1, 4), "freed capacity is reusable");
    let st = p.stats();
    assert!(st.released == 1 && st.acquired == 5 && st.peak_used == 4);
    // release_owner frees only that owner
    p.get_mut(A, 0).unwrap().secret = [0x77; 32];
    p.get_mut(B, 0).unwrap().secret = [0x77; 32];
    let before = WIPES_WITH_SECRET.load(Ordering::Relaxed);
    assert_eq!(p.release_owner(B), 2);
    assert!(WIPES_WITH_SECRET.load(Ordering::Relaxed) > before);
    assert!(p.owner_count(B) == 0 && p.owner_count(A) == 1 && p.owner_count(C) == 1 && p.used() == 2);
    assert_eq!(p.release_owner(B), 0, "idempotent");
    // peak survives release
    assert!(p.stats().peak_used == 4 && p.stats().used == 2);
    // allocator failure is "nomem", distinct from "full"
    let mut fail = FailAfter { left: Some(0), why: GateRefusal::NoMemory };
    assert_eq!(p.acquire(A, &mut fail), Err(AcquireError::Gate(GateRefusal::NoMemory)));
    let st = p.stats();
    assert!(st.refused_nomem == 1 && st.refused_full == 1 && st.used == 2);
    let mut fail = FailAfter { left: Some(1), why: GateRefusal::NoMemory };
    assert!(p.acquire(A, &mut fail).is_ok());
    assert!(p.acquire(A, &mut fail).is_err());
    assert!(p.stats().refused_nomem == 2 && p.used() == 3);
    // release everything: no leak
    assert_eq!(p.release_owner(A) + p.release_owner(C), 3);
    let st = p.stats();
    assert!(st.used == 0 && st.acquired == st.released);
}

#[test]
fn two_devices_share_the_pool() {
    let mut p = P::new();
    for k in 0..3 {
        assert_eq!(put(&mut p, A, 10 + k), k);
    }
    for k in 0..2 {
        assert_eq!(put(&mut p, B, 10 + k), k, "same keys, own indices");
    }
    let s = p.stats();
    assert!(s.used == 5 && s.acquired == 5 && s.peak_used == 5);
    assert!(p.owner_count(A) == 3 && p.owner_count(B) == 2);
    assert_eq!(p.lookup_by_pubkey(A, &[10; 32]), Some(0));
    assert_eq!(p.lookup_by_pubkey(B, &[10; 32]), Some(0));
    assert_eq!(p.lookup_by_pubkey(A, &[12; 32]), Some(2));
    assert_eq!(p.lookup_by_pubkey(B, &[12; 32]), None);
    assert!(p.get(A, 3).is_none() && p.get(A, 8).is_none() && p.get(A, 255).is_none());
    // tearing one device down frees exactly its slots
    assert_eq!(p.release_owner(A), 3);
    assert!(p.stats().used == 2 && p.owner_count(B) == 2);
    assert_eq!(p.release_owner(A), 0, "double free: no-op");
    assert_eq!(p.release_owner(B), 2);
    let s = p.stats();
    assert!(s.used == 0 && s.acquired == s.released && s.peak_used == 5);
}

#[test]
fn exhaustion_across_devices_and_the_per_device_table() {
    let mut p: Pool<TestSlot, 6> = Pool::new();
    for k in 0..6 {
        let r = p.acquire(A, &mut Ungated).unwrap();
        *p.get_mut(A, r.index).unwrap() = TestSlot::peer(20 + k);
    }
    let s0 = p.stats();
    assert_eq!(p.acquire(B, &mut Ungated), Err(AcquireError::PoolFull));
    let s1 = p.stats();
    assert!(s1.refused_full == s0.refused_full + 1 && s1.refused_nomem == 0 && s1.used == 6);
    assert_eq!((p.owner_count(B), p.owner_count(A)), (0, 6));
    for k in 0..6u8 {
        assert_eq!(p.get(A, k).unwrap().public_key, [20 + k; 32], "A's peers are untouched by B's refusal");
    }
    // A frees one -> B gets exactly that capacity
    assert!(p.release(A, 2));
    assert!(p.get(A, 2).is_none() && p.stats().used == 5);
    assert!(!p.release(A, 2), "double remove");
    assert_eq!(p.acquire(B, &mut Ungated).unwrap().index, 0);
    assert_eq!(p.stats().used, 6);
    assert!(p.acquire(B, &mut Ungated).is_err() && p.stats().refused_full == 2);
    // A's freed table index is reused (lowest free) and other indices stayed put
    assert!(p.release(B, 0));
    assert_eq!(p.acquire(A, &mut Ungated).unwrap().index, 2);
    assert_eq!(p.get(A, 5).unwrap().public_key, [25; 32]);
    // per-device table limit is independent of the pool: the 9th peer on one device fails but is not a pool refusal
    let mut q: Pool<TestSlot, 12> = Pool::new();
    for _ in 0..WIREGUARD_MAX_PEERS {
        q.acquire(A, &mut Ungated).unwrap();
    }
    let full_before = q.stats().refused_full;
    assert_eq!(q.acquire(A, &mut Ungated), Err(AcquireError::DeviceTableFull));
    let s = q.stats();
    assert!(s.refused_full == full_before && s.used == 8 && s.refused_device_full == 1);
}

#[test]
fn receiver_indices_are_unique_pool_wide_and_lookups_are_scoped() {
    let mut p = P::new();
    for (o, seed) in [(A, 80), (A, 81), (B, 80), (B, 81)] {
        put(&mut p, o, seed);
    }
    let (x, h, n, m, y, z) = (0x1111_1111u32, 0x2222_2222u32, 0x3333_3333u32, 0x4444_4444u32, 0x5555_5555u32, 0x6666_6666u32);
    p.get_mut(A, 0).unwrap().curr = Keypair { valid: true, local_index: x };
    {
        let s = p.get_mut(A, 1).unwrap();
        s.hs_valid = true;
        s.hs_index = h;
        s.next.local_index = n; // not even marked valid: still reserved
    }
    p.get_mut(A, 0).unwrap().prev.local_index = m;
    p.get_mut(B, 0).unwrap().curr = Keypair { valid: true, local_index: y };
    for i in [x, h, n, m, y] {
        assert!(p.receiver_index_in_use(i));
    }
    assert!(!p.receiver_index_in_use(z));
    // generator skips: invalid values, other device's slots (any field), this device's slots
    let mut rng = Script::new(&[0, 0xFFFF_FFFF, x, x, h, n, m, y, z, 0x7777_7777]);
    assert_eq!(p.generate_unique_index(&mut rng), Some(z));
    assert_eq!(rng.draws, 9);
    // ... and through the begin/commit path: the survivor is the new handshake's index
    let mut rng = Script::new(&[x, h, y, 0x8888_8888]);
    let t = p.begin_initiation(B, 1, &mut rng).unwrap();
    assert_eq!((t.receiver_index, rng.draws), (0x8888_8888, 4));
    assert_eq!(p.commit_initiation(&t, true, |s| (s.hs_valid, s.hs_initiator, s.hs_index) = (true, true, t.receiver_index)), CommitOutcome::Installed);
    assert_eq!(p.get(B, 1).unwrap().hs_index, 0x8888_8888);
    assert!(p.receiver_index_in_use(0x8888_8888));
    // same-device slots are checked too: the old code only ever looked at the LAST table entry
    let mut rng = Script::new(&[0x8888_8888, z]);
    assert_eq!(p.generate_unique_index(&mut rng), Some(z));
    assert_eq!(rng.draws, 2);
    // lookups are scoped to the device, even if two devices were to hold the same index
    let l = 0xCAFE_BABEu32;
    p.get_mut(A, 1).unwrap().curr = Keypair { valid: true, local_index: l };
    assert_eq!((p.lookup_by_receiver(A, l), p.lookup_by_receiver(B, l)), (Some(1), None));
    p.get_mut(B, 1).unwrap().prev = Keypair { valid: true, local_index: l }; // forced duplicate across devices
    assert_eq!((p.lookup_by_receiver(A, l), p.lookup_by_receiver(B, l)), (Some(1), Some(1)));
    {
        let s = p.get_mut(A, 0).unwrap();
        s.hs_valid = true;
        s.hs_initiator = true;
        s.hs_index = 0xDEAD_BEEF;
    }
    assert_eq!((p.lookup_by_handshake(A, 0xDEAD_BEEF), p.lookup_by_handshake(B, 0xDEAD_BEEF)), (Some(0), None));
    // an index valid in a keypair that is not marked valid does not resolve, though it stays reserved
    assert_eq!(p.lookup_by_receiver(A, n), None);
    // a removed peer's indices leave the pool with it
    assert!(p.release(A, 0));
    assert!(!p.receiver_index_in_use(0xDEAD_BEEF) && !p.receiver_index_in_use(x));
    assert_eq!(p.lookup_by_handshake(A, 0xDEAD_BEEF), None);
    p.release_owner(A);
    p.release_owner(B);
    assert!(!p.receiver_index_in_use(l));
    assert_eq!(p.stats().used, 0);
}

#[test]
fn initiation_commit_guards() {
    let mut p = P::new();
    let (ia, ib) = (put(&mut p, A, 41), put(&mut p, B, 42));
    let mut rng = Script::new(&[]);
    // (1) Another initiation for the same peer was installed while ours was computed: ours is dropped, theirs stays.
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    let rival = p.begin_initiation(A, ia, &mut rng).unwrap();
    assert_eq!(p.commit_initiation(&rival, true, |s| (s.hs_valid, s.hs_initiator, s.hs_index) = (true, true, rival.receiver_index)), CommitOutcome::Installed);
    assert_eq!(p.commit_initiation(&t, true, |_| panic!("must not install")), CommitOutcome::HandshakeChanged);
    assert_eq!(p.get(A, ia).unwrap().hs_index, rival.receiver_index);
    // (2) An inbound handshake changed the state instead: same refusal.
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    p.get_mut(A, ia).unwrap().hs_valid = false; // what consuming a handshake does
    assert_eq!(p.commit_initiation(&t, true, |_| panic!()), CommitOutcome::HandshakeChanged);
    // (3) Untouched in between: installed (the single-membership case).
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    assert_eq!(p.commit_initiation(&t, true, |s| s.hs_index = t.receiver_index), CommitOutcome::Installed);
    assert_eq!(p.get(A, ia).unwrap().hs_index, t.receiver_index);
    // (4) The index drawn by begin was taken by someone (another device, another peer) before the commit.
    p.get_mut(A, ia).unwrap().hs_valid = false;
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    p.get_mut(B, ib).unwrap().curr.local_index = t.receiver_index;
    assert!(p.receiver_index_in_use(t.receiver_index));
    assert_eq!(p.commit_initiation(&t, true, |_| panic!()), CommitOutcome::IndexTaken);
    // (5) The computation failed.
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    assert_eq!(p.commit_initiation(&t, false, |_| panic!()), CommitOutcome::ComputeFailed);
    // (6) A peer removed while the crypto ran outside the lock: the commit installs nothing.
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    assert!(p.release(A, ia));
    assert_eq!(p.commit_initiation(&t, true, |_| panic!()), CommitOutcome::PeerGone);
    // (7) ... and the slot re-used by another peer (even with the same key and state): refused, because it is a different slot generation.
    let ia = put(&mut p, A, 43);
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    assert!(p.release(A, ia));
    let ia2 = put(&mut p, A, 43);
    assert_eq!(ia2, ia);
    assert_eq!(p.commit_initiation(&t, true, |_| panic!()), CommitOutcome::PeerReplaced);
    // (8) The key changed under the same slot.
    let t = p.begin_initiation(A, ia, &mut rng).unwrap();
    p.get_mut(A, ia).unwrap().public_key = [99; 32];
    assert_eq!(p.commit_initiation(&t, true, |_| panic!()), CommitOutcome::KeyChanged);
    assert_eq!(p.stats().commits_refused, 7);
    // begin refuses an invalid peer
    let r = p.acquire(A, &mut Ungated).unwrap();
    assert!(p.begin_initiation(A, r.index, &mut rng).is_none());
    assert!(p.begin_initiation(A, 7, &mut rng).is_none());
    // The pool-wide check also covers a NON-last slot of the SAME device.
    let extra = put(&mut p, A, 99);
    assert!(extra != ia);
    let (tt, u) = (0x1357_2468u32, 0x2468_1357u32);
    p.get_mut(A, 0).unwrap().prev.local_index = tt;
    let mut rng = Script::new(&[tt, u]);
    assert_eq!(p.generate_unique_index(&mut rng), Some(u));
}

#[test]
fn rx_commit_revalidates_the_keypair() {
    let mut p = P::new();
    let i = put(&mut p, A, 7);
    p.get_mut(A, i).unwrap().curr = Keypair { valid: true, local_index: 77 };
    assert!(p.rx_ticket(A, i, 78).is_none() && p.rx_ticket(B, i, 77).is_none());
    let t = p.rx_ticket(A, i, 77).unwrap();
    assert!(p.rx_commit_valid(&t));
    // keypair rotated out while decrypting
    p.get_mut(A, i).unwrap().curr.valid = false;
    assert!(!p.rx_commit_valid(&t));
    p.get_mut(A, i).unwrap().curr.valid = true;
    assert!(p.rx_commit_valid(&t));
    // peer replaced while decrypting
    assert!(p.release(A, i));
    let i2 = put(&mut p, A, 7);
    p.get_mut(A, i2).unwrap().curr = Keypair { valid: true, local_index: 77 };
    assert!(!p.rx_commit_valid(&t), "a different slot generation");
    assert_eq!(p.stats().rx_commits_refused, 2);
}

#[test]
fn gates_apply_the_admission_rules() {
    // HeapGate: the first ML_ADM_PEER_SLOTS keep the recovery reserve; the rest also one negotiation peak.
    let slot = P::SLOT_BYTES;
    let mut p = P::new();
    let ok = Probe(16384 + slot, 40_000, 0);
    let mut g = HeapGate::new(&ok);
    assert!(p.acquire(A, &mut g).is_ok());
    let tight = Probe(16384 + slot - 1, 40_000, 0);
    assert_eq!(p.acquire(A, &mut HeapGate::new(&tight)), Err(AcquireError::Gate(GateRefusal::Heap)));
    for _ in 1..ML_ADM_PEER_SLOTS {
        p.acquire(A, &mut Ungated).unwrap();
    }
    // beyond the guaranteed slots: needs reserve + negotiation peak (29,884) + slot
    let not_enough = Probe(16384 + slot, 40_000, 0);
    assert_eq!(p.acquire(A, &mut HeapGate::new(&not_enough)), Err(AcquireError::Gate(GateRefusal::Heap)));
    let enough = Probe(29_884 + slot, 40_000, 0);
    assert!(p.acquire(A, &mut HeapGate::new(&enough)).is_ok());
    // the largest-block guard: this slot would be the one to take the largest block under the TLS floor
    let carve = Probe(100_000, ML_ADM_TLS_BLOCK_FLOOR + 10, 0);
    assert_eq!(p.acquire(A, &mut HeapGate::new(&carve)), Err(AcquireError::Gate(GateRefusal::Largest)));
    let already_below = Probe(100_000, ML_ADM_TLS_BLOCK_FLOOR - 1, 0);
    assert!(p.acquire(A, &mut HeapGate::new(&already_below)).is_ok(), "already below the floor: not this allocation's doing");
    let s = p.stats();
    assert!(s.refused_heap == 2 && s.refused_largest == 1);
    assert!(s.largest_low <= (ML_ADM_TLS_BLOCK_FLOOR - 1) as u32);
    p.note_largest_after(5);
    assert_eq!(p.stats().largest_low, 5);
}

#[test]
fn const_pool_and_sizes() {
    static POOL: P = P::new(); // `const fn new`: usable in a static
    assert_eq!(POOL.capacity(), 12);
    std::println!("pool: slot payload (test double) {} B, Pool<_, 12> {} B; WIREGUARD_POOL_SLOTS={}", P::SLOT_BYTES, P::STATE_BYTES, WIREGUARD_POOL_SLOTS);
}
