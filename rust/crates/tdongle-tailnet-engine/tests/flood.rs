//! Floods and heap pressure (ADR 0012, 0018, 0019, 0022): the elastic drops are counted per site, the one heap floor is never crossed in a model heap,
//! and every packet still ends in exactly one outcome.

mod common;
use common::*;
use std::vec::Vec;
use tdongle_tailnet_admission::heap::{HbSite, ML_HB_FLOOR};
use tdongle_tailnet_admission::probe::HeapSnapshot;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::jit::{JIT_BLOCK, JIT_PENDING};
use tdongle_tailnet_engine::{Handled, HostFate, Input, RxFate, TxFate};

const B_EP: Ep = Ep::v4([198, 51, 100, 7], 41641);

#[test]
fn a_flood_to_a_peer_without_a_session_parks_eight_and_counts_the_rest() {
    let mut s = Solo::new(21);
    s.member(1, 4, 0);
    let a = s.alias(1, 1);
    for _ in 0..40 {
        assert_eq!(s.send(a, 100), Handled::Host(HostFate::Forwarded));
    }
    let st = s.eng.stats();
    assert_eq!(st.tx_count(TxFate::Parked), JIT_PENDING as u32);
    assert_eq!(st.tx_count(TxFate::JitBudget), 40 - JIT_PENDING as u32);
    assert_eq!(st.host_count(HostFate::Forwarded), 40);
    s.eng.check_identities().unwrap();
    // 5 s later they all expire, each counted; the budget is back
    s.advance(5_500);
    assert_eq!(s.eng.stats().park_count(tdongle_tailnet_engine::ParkEnd::Expired), JIT_PENDING as u32);
    assert_eq!(s.eng.jit_store().used_blocks(), 0);
    assert_eq!(s.send(a, 100), Handled::Host(HostFate::Forwarded));
    assert_eq!(s.eng.stats().tx_count(TxFate::Parked), JIT_PENDING as u32 + 1);
    s.eng.check_identities().unwrap();
}

#[test]
fn the_heap_floor_is_never_crossed_by_parking() {
    let mut s = Solo::new(22);
    for m in 1..=3 {
        s.member(m, 8, 0);
    }
    // a model heap: the floor plus room for ten arena blocks; the engine is told the free bytes before every packet
    let total = ML_HB_FLOOR + 10 * JIT_BLOCK + 100;
    let mut min_free = usize::MAX;
    let mut aliases = Vec::new();
    for m in 1..=3 {
        for p in 1..=4 {
            aliases.push(s.alias(m, p));
        }
    }
    for round in 0..3 {
        for &a in &aliases {
            let used = s.eng.jit_store().used_blocks() * JIT_BLOCK;
            let free = total - used;
            s.eng.set_heap(HeapSnapshot { free, largest: free, minimum: free });
            s.send(a, 200 + round);
            let used = s.eng.jit_store().used_blocks() * JIT_BLOCK;
            min_free = min_free.min(total - used);
        }
    }
    assert!(min_free >= ML_HB_FLOOR, "the floor held: min free {min_free} floor {ML_HB_FLOOR}");
    assert!(s.eng.jit_store().peak_blocks() <= 10, "peak {}", s.eng.jit_store().peak_blocks());
    let refused = s.eng.heap_refusals().get(HbSite::Jit);
    assert_eq!(refused, s.eng.stats().tx_count(TxFate::JitNoMem), "every refusal is counted at its site and as a fate");
    assert!(refused > 20);
    s.eng.check_identities().unwrap();
}

#[test]
fn receive_flood_with_the_heap_at_the_floor_counts_big_datagrams_and_lets_small_ones_through() {
    let mut s = Solo::new(23);
    s.member(1, 2, 0);
    s.eng.set_heap(HeapSnapshot { free: ML_HB_FLOOR + 100, largest: 20_000, minimum: 0 });
    let mut data = Vec::new();
    let src = Ep::v4([198, 51, 100, 9], 5555);
    let (mut big, mut small) = (0, 0);
    for n in 0..300usize {
        let len = [10, 40, 148, 400, 512, 513, 700, 1300][n % 8];
        data.clear();
        data.extend((0..len).map(|i| (i * 7 + n) as u8));
        let h = s.input(Input::Udp { member: 1, src, data: &mut data });
        match h {
            Handled::Rx(RxFate::HeapRefused) => big += 1,
            Handled::Rx(_) => small += 1,
            o => panic!("{o:?}"),
        }
    }
    assert_eq!(big, 300 / 8 * 3, "513, 700 and 1300 byte datagrams are refused");
    assert_eq!(small, 300 - big);
    assert_eq!(s.eng.heap_refusals().get(HbSite::WgCopy) as usize, big);
    assert_eq!(s.eng.stats().rx_count(RxFate::HeapRefused) as usize, big);
    // with room, the same datagrams are classified instead
    s.eng.set_heap(HeapSnapshot { free: ML_HB_FLOOR + 100_000, largest: 50_000, minimum: 0 });
    data.clear();
    data.extend(std::iter::repeat_n(0x55u8, 700));
    assert_eq!(s.input(Input::Udp { member: 1, src, data: &mut data }), Handled::Rx(RxFate::Garbage));
    s.eng.check_identities().unwrap();
}

#[test]
fn derp_transmit_below_the_floor_is_refused_and_counted_not_sent() {
    let mut s = Sim::new(5);
    s.udp_up = false;
    let a = s.add_node("a", 1, 0x6440_0001, Ep::v4([203, 0, 113, 1], 41641));
    let b = s.add_node("b", 2, 0x6440_0002, B_EP);
    let rb = peer_record(2, s.nodes[b].vpn_ip, &s.nodes[b].keys.clone(), "b.net.ts.net", None);
    let ra = peer_record(1, s.nodes[a].vpn_ip, &s.nodes[a].keys.clone(), "a.net.ts.net", None);
    s.netmap(a, &[rb]);
    s.netmap(b, &[ra]);
    s.enable(a);
    s.enable(b);
    let alias_b = s.resolve(a, "b.net.tailnet").unwrap();
    let alias_a = s.resolve(b, "a.net.tailnet").unwrap();
    s.nodes[b].echo_to = Some((alias_a, 40000));
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 400);
    s.host_send_to(a, alias_b, 6000, 40000, b"hi");
    s.run_until(s.now + 400);
    assert_eq!(s.nodes[a].eng.status(s.now).members[0].unwrap().sessions, 1);
    // now the heap is at the floor: nothing may be queued for the relay
    s.nodes[a].eng.set_heap(HeapSnapshot { free: ML_HB_FLOOR + 50, largest: 10_000, minimum: 0 });
    let derp_sends = s.nodes[a].outs.iter().filter(|o| matches!(o, Owned::Derp { .. })).count();
    for n in 0..20u32 {
        s.host_send_to(a, alias_b, 6000, 40000, &n.to_be_bytes());
    }
    let after = s.nodes[a].outs.iter().filter(|o| matches!(o, Owned::Derp { .. })).count();
    assert_eq!(after, derp_sends, "no relay copy below the floor");
    assert_eq!(s.nodes[a].eng.stats().tx_count(TxFate::HeapRefused), 20);
    assert_eq!(s.nodes[a].eng.heap_refusals().get(HbSite::DerpTx), 20);
    s.nodes[a].eng.check_identities().unwrap();
}
