//! Three memberships share one WireGuard pool (ADR 0013, `test_peer_policy`, `test_wg_peer_pool`): eviction across memberships, the idle window, the
//! pinned priority peer, own-table eviction, and what leaves with an evicted peer.

mod common;
use common::*;
use tdongle_tailnet_engine::{HostFate, ParkEnd, TxFate};

fn flows(s: &mut Solo, member: u32, peers: std::ops::RangeInclusive<u32>) {
    for p in peers {
        let a = s.alias(member, p);
        assert_eq!(s.send(a, 20), tdongle_tailnet_engine::Handled::Host(HostFate::Forwarded));
    }
}

#[test]
fn recent_peers_are_protected_then_the_largest_idle_membership_gives_up_a_slot() {
    let mut s = Solo::new(1);
    s.member(1, 10, Solo::ip(1, 1)); // peer 1 of member 1 is the priority peer
    s.member(2, 10, 0);
    s.member(3, 10, 0);
    flows(&mut s, 1, 1..=8);
    flows(&mut s, 2, 1..=4);
    assert_eq!(s.eng.pool().used(), 12);
    assert_eq!(s.resident(1), 8);
    s.eng.check_identities().unwrap();
    // member 3 asks while everything is recent (inside the 10 s idle window): rejected, counted, nothing evicted
    s.advance(2_000);
    let a = s.alias(3, 1);
    s.send(a, 20);
    assert_eq!(s.eng.stats().tx_count(TxFate::Rejected), 1);
    assert_eq!(s.eng.arbiter_stats().refused, 1);
    assert_eq!(s.resident(3), 0);
    assert_eq!(s.eng.pool().used(), 12);
    // after the window the idle peers of the membership with the most slots (member 1) are evictable, the priority peer never
    s.advance(10_000);
    for p in 1..=3 {
        let a = s.alias(3, p);
        s.send(a, 20);
    }
    assert_eq!(s.resident(3), 3);
    assert_eq!(s.eng.pool().used(), 12, "the cap holds");
    assert_eq!(s.resident(1), 5, "member 1 paid for it");
    assert_eq!(s.eng.arbiter_stats().evictions_other, 3);
    assert!(s.eng.member(1).unwrap().mship.table.by_ip(Solo::ip(1, 1)).is_some(), "the priority peer stays");
    // every packet parked for a peer that never answered ended as a counted expiry (5 s), none was lost silently; the 12 first ones expired before
    // the idle window ended, the three new ones are still waiting
    assert_eq!(s.eng.stats().park_count(ParkEnd::Expired), 12);
    assert_eq!(s.eng.member(3).unwrap().rt.park.len(), 3);
    s.eng.check_identities().unwrap();
    // evicted peers can come back: they are activated again from the directory
    s.advance(11_000);
    let a = s.alias(1, 9);
    s.send(a, 20);
    assert!(s.resident(1) >= 5);
    s.eng.check_identities().unwrap();
}

#[test]
fn own_table_full_evicts_its_own_idle_peer() {
    let mut s = Solo::new(2);
    s.member(1, 12, 0);
    flows(&mut s, 1, 1..=8);
    assert_eq!(s.resident(1), 8);
    s.advance(11_000);
    let a = s.alias(1, 9);
    s.send(a, 20);
    assert_eq!(s.resident(1), 8);
    let m = s.eng.member(1).unwrap();
    assert_eq!(m.mship.stats.evictions, 1, "the C's jit_evictions");
    assert!(m.mship.table.by_ip(Solo::ip(1, 9)).is_some());
    assert!(m.mship.table.by_ip(Solo::ip(1, 1)).is_none(), "the least recently used went");
    assert_eq!(s.eng.pool().used(), 8);
    s.eng.check_identities().unwrap();
}

#[test]
fn full_own_table_of_recent_peers_rejects_instead_of_evicting() {
    let mut s = Solo::new(3);
    s.member(1, 12, 0);
    flows(&mut s, 1, 1..=8);
    let a = s.alias(1, 9);
    s.send(a, 20);
    assert_eq!(s.resident(1), 8);
    assert_eq!(s.eng.member(1).unwrap().mship.stats.rejected, 1);
    assert_eq!(s.eng.stats().tx_count(TxFate::Rejected), 1);
    s.eng.check_identities().unwrap();
}

#[test]
fn receiver_indices_are_unique_across_memberships_and_slots() {
    let mut s = Solo::new(4);
    s.member(1, 8, 0);
    s.member(2, 8, 0);
    s.member(3, 8, 0);
    for m in 1..=3 {
        flows(&mut s, m, 1..=4);
    }
    assert_eq!(s.eng.pool().used(), 12);
    // twelve handshakes in flight, twelve distinct indices (check_identities verifies the pool-wide uniqueness)
    s.eng.check_identities().unwrap();
    let mut seen = std::collections::HashSet::new();
    s.eng.pool().each(|_, _, sl| sl.hot.for_each_index(|i| assert!(seen.insert(i), "duplicate index {i}")));
    assert_eq!(seen.len(), 12);
}
