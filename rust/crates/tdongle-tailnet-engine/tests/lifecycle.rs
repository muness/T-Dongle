//! Membership life cycle (ADR 0013, "Merge with the router hot path"): a membership removed mid-handshake or mid-traffic leaks nothing, and what
//! arrives for it afterwards is a counted drop.

mod common;
use common::*;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{Handled, HostFate, Input, NetmapEvent, Out, ParkEnd, PeerDirectory, RxFate};

const A_EP: Ep = Ep::v4([203, 0, 113, 1], 41641);
const B_EP: Ep = Ep::v4([198, 51, 100, 7], 41641);

fn pair() -> (Sim, usize, usize, u32, u32) {
    let mut s = Sim::new(9);
    s.udp_up = false;
    let a = s.add_node("a", 1, 0x6440_0001, A_EP);
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
    (s, a, b, alias_a, alias_b)
}

fn assert_empty(s: &Sim, n: usize) {
    let e = &s.nodes[n].eng;
    assert_eq!(e.pool().used(), 0, "wiped pool");
    assert_eq!(e.jit_store().used_blocks(), 0, "no parked bytes");
    assert_eq!(e.router().flows().len(), 0, "no flows");
    assert_eq!(e.member_count(), 0);
    e.check_identities().unwrap();
}

#[test]
fn removed_mid_handshake_leaks_nothing_and_late_packets_are_counted() {
    let (mut s, a, b, alias_a, alias_b) = pair();
    // A's packet is parked and the initiation is on its way over DERP (40 ms delay): remove the membership before it arrives
    assert_eq!(s.host_send_to(a, alias_b, 6000, 40000, b"ping"), Handled::Host(HostFate::Forwarded));
    assert_eq!(s.nodes[a].eng.member(1).unwrap().rt.park.len(), 1);
    assert_eq!(s.nodes[a].eng.pool().used(), 1);
    let m = s.nodes[a].member;
    s.input(a, Input::MemberRemoved { member: m });
    assert!(s.nodes[a].outs.iter().any(|o| matches!(o, Owned::Gone)));
    assert!(s.nodes[a].outs.iter().any(|o| matches!(o, Owned::DerpClose)));
    assert_empty(&s, a);
    assert_eq!(s.nodes[a].eng.stats().park_count(ParkEnd::MemberGone), 1);
    // B answers the initiation; its response (and everything else) now arrives at a membership that no longer exists
    let rx_before = s.nodes[a].eng.stats().rx_count(RxFate::NoMember);
    s.run_until(s.now + 5_000);
    assert!(s.nodes[a].eng.stats().rx_count(RxFate::NoMember) > rx_before, "late datagrams are counted drops");
    assert_empty(&s, a);
    s.check();
    // a host packet for the old alias: the alias is still allocated (never reassigned), the router asks for a fill, the released packet finds no
    // membership and is a counted router drop
    let nm_before = s.nodes[a].eng.router().stats().get(tdongle_tailnet_router::Stat::NoMember);
    let h = s.host_send_to(a, alias_b, 6000, 40000, b"late");
    assert!(matches!(h, Handled::Host(HostFate::Held | HostFate::RouterDrop)), "{h:?}");
    s.run_until(s.now + 200);
    assert!(s.nodes[a].eng.router().stats().get(tdongle_tailnet_router::Stat::NoMember) > nm_before);
    s.check();
    // the membership can be created again and works from scratch (stale receiver indices are gone with the old pool slots)
    let k = s.nodes[a].keys.clone();
    let mut label = tdongle_tailnet_types::FixedStr::new();
    label.set("net");
    let cfg = tdongle_tailnet_engine::MemberConfig {
        id: 1,
        node_private: k.node_priv,
        disco_private: k.disco_priv,
        label,
        priority_peer_ip: 0,
        persistent_keepalive_s: 0,
        enabled: false,
    };
    s.input(a, Input::MemberAdded(&cfg));
    let rb = peer_record(2, s.nodes[b].vpn_ip, &s.nodes[b].keys.clone(), "b.net.ts.net", None);
    s.netmap(a, &[rb]);
    s.enable(a);
    let alias_b = s.resolve(a, "b.net.tailnet").unwrap();
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 500);
    let mut got = 0;
    for n in 0..10u32 {
        s.host_send_to(a, alias_b, 6000, 40000, &n.to_be_bytes());
        s.run_until(s.now + 1000);
        got += s.nodes[a].host_rx.drain(..).count();
    }
    assert!(got >= 5, "echoes after re-adding: {got}");
    s.check();
}

#[test]
fn removed_mid_traffic_leaks_nothing() {
    let (mut s, a, b, alias_a, alias_b) = pair();
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 300);
    let mut got = 0;
    for n in 0..6u32 {
        s.host_send_to(a, alias_b, 6000, 40000, &n.to_be_bytes());
        s.run_until(s.now + 1000);
        got += s.nodes[a].host_rx.drain(..).count();
    }
    assert!(got >= 4);
    assert_eq!(s.nodes[a].eng.status(s.now).members[0].unwrap().sessions, 1);
    // in flight: a ping from A (arrives at B), B's echo is on its way back when A's membership goes away
    s.host_send_to(a, alias_b, 6000, 40000, b"x");
    s.run_until(s.now + 60);
    let m = s.nodes[a].member;
    s.input(a, Input::MemberRemoved { member: m });
    assert_empty(&s, a);
    let rx = s.nodes[a].eng.stats().rx_count(RxFate::NoMember);
    s.run_until(s.now + 3_000);
    assert!(s.nodes[a].eng.stats().rx_count(RxFate::NoMember) > rx, "B's echo and B's retries hit a removed membership: counted");
    assert_empty(&s, a);
    s.check();
    // inputs for ids that never existed are counted as well
    let mut junk = [0u8; 32];
    assert_eq!(s.input(a, Input::Udp { member: 77, src: B_EP, data: &mut junk }), Handled::Rx(RxFate::NoMember));
    let _ = Out::Wake(None);
}

#[test]
fn disable_releases_everything_but_the_netmap_and_enable_restarts() {
    let (mut s, a, b, alias_a, alias_b) = pair();
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 300);
    for n in 0..4u32 {
        s.host_send_to(a, alias_b, 6000, 40000, &n.to_be_bytes());
        s.run_until(s.now + 800);
    }
    s.nodes[a].host_rx.clear();
    let m = s.nodes[a].member;
    s.input(a, Input::MemberDisabled { member: m });
    let e = &s.nodes[a].eng;
    assert_eq!(e.pool().used(), 0);
    assert_eq!(e.router().flows().len(), 0);
    assert_eq!(e.member_count(), 1, "the membership and its netmap stay");
    assert_eq!(e.dir().count(0), 1);
    assert!(!e.status(s.now).members[0].unwrap().ready);
    e.check_identities().unwrap();
    // disabled: datagrams are MemberDown, host packets are dropped by the router (not ready)
    assert_eq!(s.input(a, Input::Udp { member: m, src: B_EP, data: &mut [0u8; 40] }), Handled::Rx(RxFate::MemberDown));
    assert_eq!(s.host_send_to(a, alias_b, 6000, 40000, b"x"), Handled::Host(HostFate::RouterDrop));
    s.run_until(s.now + 2000);
    s.check();
    // enabling again: peers are activated from the directory on demand, a new handshake runs
    s.enable(a);
    let alias_b = s.resolve(a, "b.net.tailnet").unwrap();
    let mut got = 0;
    for n in 0..8u32 {
        s.host_send_to(a, alias_b, 6000, 40000, &n.to_be_bytes());
        s.run_until(s.now + 1000);
        got += s.nodes[a].host_rx.drain(..).count();
    }
    assert!(got >= 4, "echoes after re-enabling: {got}");
    s.check();
}

#[test]
fn a_revoked_peer_leaves_with_its_parked_packets() {
    let mut s = Solo::new(11);
    s.member(1, 3, 0);
    let a = s.alias(1, 1);
    s.send(a, 30);
    assert_eq!(s.eng.member(1).unwrap().rt.park.len(), 1);
    // an authoritative map without peer 1 revokes it
    let ev = [
        NetmapEvent::Peer(peer_record(1002, Solo::ip(1, 2), &Solo::peer_keys(1, 2), "p2.m1.ts.net", None)),
        NetmapEvent::Commit { authoritative: true, self_expired: false },
    ];
    for e in &ev {
        s.input(Input::Netmap { member: 1, event: e });
    }
    assert_eq!(s.resident(1), 0);
    assert_eq!(s.eng.pool().used(), 0);
    assert_eq!(s.eng.stats().park_count(ParkEnd::PeerGone), 1);
    s.eng.check_identities().unwrap();
}
