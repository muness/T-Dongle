//! The responder side: trial activation of unauthenticated claims (ADR 0012's amendment), unknown claimants, replays, flood and the under-load
//! cookie rule (ADR 0019 / 0020 / 0022).

mod common;
use common::*;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{Handled, Input, RxFate};
use tdongle_tailnet_wg::Dropped;

const A_EP: Ep = Ep::v4([203, 0, 113, 1], 41641);
const B_EP: Ep = Ep::v4([198, 51, 100, 7], 41641);
const C_EP: Ep = Ep::v4([198, 51, 100, 8], 41641);

fn trio() -> (Sim, usize, usize, usize, u32, u32) {
    let mut s = Sim::new(3);
    s.udp_up = false;
    s.drop_disco = true; // WireGuard first: no DISCO admission, only the handshake claim
    let a = s.add_node("a", 1, 0x6440_0001, A_EP);
    let b = s.add_node("b", 2, 0x6440_0002, B_EP);
    let c = s.add_node("c", 3, 0x6440_0003, C_EP);
    let (ka, kb) = (s.nodes[a].keys.clone(), s.nodes[b].keys.clone());
    let ra = peer_record(1, s.nodes[a].vpn_ip, &ka, "a.net.ts.net", None);
    let rb = peer_record(2, s.nodes[b].vpn_ip, &kb, "b.net.ts.net", None);
    // A knows B only; B knows A; C knows A but A does not know C
    s.netmap(a, &[rb]);
    s.netmap(b, std::slice::from_ref(&ra));
    s.netmap(c, &[ra]);
    for n in [a, b, c] {
        s.enable(n);
    }
    let alias_a = s.resolve(b, "a.net.tailnet").unwrap();
    let alias_a_c = s.resolve(c, "a.net.tailnet").unwrap();
    s.nodes[b].echo_to = Some((alias_a, 40000));
    (s, a, b, c, alias_a, alias_a_c)
}

#[test]
fn an_unknown_claimant_costs_no_slot_and_a_directory_peer_gets_one_trial_that_confirms() {
    let (mut s, a, b, c, alias_a, alias_a_c) = trio();
    // C is not in A's directory: its (valid mac1) initiation is a counted handshake drop, no slot, no table entry
    s.host_send_to(c, alias_a_c, 5000, 40000, b"hi");
    s.run_until(s.now + 500);
    assert_eq!(s.nodes[a].eng.pool().used(), 0);
    assert_eq!(s.nodes[a].eng.member(1).unwrap().rt.wg_drops.get(Dropped::HsUnknownPeer), 1);
    assert_eq!(s.nodes[a].eng.member(1).unwrap().mship.trial.started, 0);
    s.check();
    // B is in the directory: its initiation opens ONE trial, the session confirms it
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 500);
    let m = s.nodes[a].eng.member(1).unwrap();
    assert_eq!(m.mship.trial.started, 1, "{:?}", m.mship.trial);
    assert_eq!(m.mship.table.len(), 1);
    assert_eq!(s.nodes[a].eng.pool().used(), 1);
    // B's first transport message confirms A's responder session and the trial
    s.run_until(s.now + 1500);
    let m = s.nodes[a].eng.member(1).unwrap();
    assert_eq!(m.mship.trial.confirmed, 1, "{:?}", m.mship.trial);
    assert!(m.mship.table.iter().all(|(_, p)| !p.unconfirmed));
    s.check();
}

#[test]
fn replayed_initiations_are_dropped_a_flood_goes_under_load_and_gets_cookie_replies() {
    let (mut s, a, b, _c, alias_a, _) = trio();
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 500);
    // B's initiation, as it left B
    let init = s.nodes[b]
        .outs
        .iter()
        .find_map(|o| if let Owned::Derp { data, .. } = o { (data.first() == Some(&1) && data.len() == 148).then(|| data.clone()) } else { None })
        .expect("B sent an initiation");
    let kb = s.nodes[b].keys.node_pub.0;
    let used = s.nodes[a].eng.pool().used();
    let mut fates = std::vec::Vec::new();
    for _ in 0..14 {
        let mut d = init.clone();
        let h = s.input(a, Input::DerpPacket { member: 1, src: &kb, data: &mut d });
        match h {
            Handled::Rx(f) => fates.push(f),
            o => panic!("{o:?}"),
        }
    }
    assert!(fates.iter().all(|f| matches!(f, RxFate::WgHandshakeDropped | RxFate::WgCookie)), "{fates:?}");
    assert!(fates.contains(&RxFate::WgCookie), "after eight initiations in a second the responder answers with cookies: {fates:?}");
    let st = s.nodes[a].eng.stats();
    assert!(st.cookie_tx.get() >= 1 && st.under_load_screens.get() >= 1);
    let m = s.nodes[a].eng.member(1).unwrap();
    assert!(m.rt.wg_drops.get(Dropped::HsTimestampReplay) + m.rt.wg_drops.get(Dropped::HsFlood) >= 1, "the replays were refused by the timestamp/flood rule");
    assert_eq!(s.nodes[a].eng.pool().used(), used, "replays took no slot and made no second session");
    s.check();
    // the cookie replies went back to B: it can open them (or counted them), never panic
    s.run_until(s.now + 1500);
    s.check();
}

#[test]
fn garbage_with_valid_framing_is_counted_and_never_panics() {
    let (mut s, a, _b, _c, _, _) = trio();
    let kb = s.nodes[1].keys.node_pub.0;
    // handshake-shaped garbage: right type and length, wrong MACs
    for (ty, len) in [(1u8, 148usize), (2, 92), (3, 64), (4, 64), (4, 32)] {
        let mut d = std::vec![0x5au8; len];
        d[0] = ty;
        d[1] = 0;
        d[2] = 0;
        d[3] = 0;
        let h = s.input(a, Input::DerpPacket { member: 1, src: &kb, data: &mut d });
        assert!(matches!(h, Handled::Rx(RxFate::WgHandshakeDropped | RxFate::WgDataDropped | RxFate::WgCookie)), "{ty}: {h:?}");
    }
    s.check();
}
