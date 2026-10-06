//! Two engines wired through the simulated network: DERP only, then DISCO finds the direct path, then the direct path is cut and traffic falls back.

mod common;
use common::*;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{Input, Out, TxFate as TxFateExt};

const A_EP: Ep = Ep::v4([203, 0, 113, 1], 41641);
const B_EP: Ep = Ep::v4([198, 51, 100, 7], 41641);

fn two() -> (Sim, usize, usize, u32, u32) {
    let mut s = Sim::new(7);
    let a = s.add_node("a", 1, 0x6440_0001, A_EP);
    let b = s.add_node("b", 2, 0x6440_0002, B_EP);
    s.nodes[b].nat_filter = true; // address-restricted: B accepts from an address only after it sent to it
    let rb = peer_record(2, s.nodes[b].vpn_ip, &s.nodes[b].keys.clone(), "b.net.ts.net", Some(B_EP));
    let ra = peer_record(1, s.nodes[a].vpn_ip, &s.nodes[a].keys.clone(), "a.net.ts.net", Some(A_EP));
    s.netmap(a, &[rb]);
    s.netmap(b, &[ra]);
    s.enable(a);
    s.enable(b);
    for (i, ep) in [(a, A_EP), (b, B_EP)] {
        let m = s.nodes[i].member;
        s.input(i, Input::EndpointsChanged { member: m, endpoints: &[ep] });
    }
    let alias_b = s.resolve(a, "b.net.tailnet").expect("alias of b");
    let alias_a = s.resolve(b, "a.net.tailnet").expect("alias of a");
    s.nodes[b].echo_to = Some((alias_a, 40000));
    (s, a, b, alias_a, alias_b)
}

#[test]
fn derp_only_then_direct_then_back_to_derp() {
    let (mut s, a, b, alias_a, alias_b) = two();
    let _ = Out::Wake(None);
    s.udp_up = false; // DERP only
    // B's host opens its flow towards A, then A's host starts "pinging" B; B's host echoes
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 500);
    let mut got = 0;
    let ping = |s: &mut Sim, n: u32| {
        s.host_send_to(a, alias_b, 6000, 40000, &n.to_be_bytes());
    };
    for n in 0..8 {
        ping(&mut s, n);
        let end = s.now + 1000;
        s.run_until(end);
        // keep B's flow alive (an echo refreshes it; the opener is only needed at the start)
        got += s.nodes[a].host_rx.drain(..).count();
    }
    s.check();
    assert!(got >= 5, "echoes through DERP: {got}");
    let st = s.nodes[a].eng.stats().clone();
    assert!(st.tx_count(TxFateExt::SentDerp) > 0 && st.tx_count(TxFateExt::SentDirect) == 0, "DERP only");
    assert_eq!(s.nodes[a].eng.status(s.now).members[0].unwrap().direct_paths, 0);

    // UDP works now: DISCO (pings over DERP and to the known endpoints, call-me-maybe) finds the direct path
    s.udp_up = true;
    let mut direct_at = None;
    for n in 8..70 {
        ping(&mut s, n);
        let end = s.now + 1000;
        s.run_until(end);
        s.nodes[a].host_rx.clear();
        if direct_at.is_none() && s.nodes[a].eng.status(s.now).members[0].unwrap().direct_paths == 1 {
            direct_at = Some(n);
        }
    }
    s.check();
    let direct_at = direct_at.expect("a direct path was found");
    assert!(direct_at < 40, "found at {direct_at}");
    let before = s.nodes[a].eng.stats().tx_count(TxFateExt::SentDirect);
    for n in 100..110 {
        ping(&mut s, n);
        let end = s.now + 1000;
        s.run_until(end);
    }
    let after = s.nodes[a].eng.stats().tx_count(TxFateExt::SentDirect);
    assert!(after >= before + 8, "traffic moved to UDP: {before} -> {after}");
    let echoes_direct = s.nodes[a].host_rx.drain(..).count();
    assert!(echoes_direct >= 8, "echoes over the direct path: {echoes_direct}");
    assert!(s.nat_dropped > 0, "B's address-restricted NAT dropped early probes until it had sent to A");

    // cut the direct path: trust lapses, no data flows, DISCO reverts to DERP and traffic continues through the relay
    s.udp_up = false;
    let derp_before = s.nodes[a].eng.stats().tx_count(TxFateExt::SentDerp);
    let mut echoed_late = 0;
    for n in 200..420 {
        ping(&mut s, n);
        let end = s.now + 1000;
        s.run_until(end);
        let r = s.nodes[a].host_rx.drain(..).count();
        if n > 380 {
            echoed_late += r;
        }
    }
    s.check();
    assert_eq!(s.nodes[a].eng.status(s.now).members[0].unwrap().direct_paths, 0, "fell back");
    assert!(s.nodes[a].eng.stats().tx_count(TxFateExt::SentDerp) > derp_before + 20, "traffic went through DERP again");
    assert!(echoed_late >= 30, "echoes after the fallback: {echoed_late}");
}

#[test]
fn parked_packets_leave_in_arrival_order_and_nothing_overtakes_them() {
    let (mut s, a, b, alias_a, alias_b) = two();
    s.nodes[b].echo_to = None; // B's host only listens
    s.udp_up = false;
    // B opens its flow while muted (its handshake never leaves), so A's packets can be received once A's handshake has completed
    s.nodes[b].muted = true;
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.nodes[b].muted = false;
    for n in 0u8..5 {
        s.host_send_to(a, alias_b, 6000, 40000, &[n]);
    }
    assert_eq!(s.nodes[a].eng.member(1).unwrap().rt.park.len(), 5);
    s.run_until(s.now + 2_000);
    // a packet sent now, with the session up, goes after everything that was parked
    s.host_send_to(a, alias_b, 6000, 40000, &[5]);
    s.run_until(s.now + 2_000);
    let got: Vec<u8> = s.nodes[b].host_rx.iter().filter_map(|p| parse_udp(p).map(|u| u.payload[0])).collect();
    // (B's own parked "open" packet is a reply-less request on A's side: dropped there, not seen here)
    assert_eq!(got, [0, 1, 2, 3, 4, 5], "in order, exactly once");
    assert_eq!(s.nodes[a].eng.stats().park_count(tdongle_tailnet_engine::ParkEnd::Sent), 5);
    s.check();
}

#[test]
fn initiations_that_cross_recover_at_the_retransmit() {
    // Both hosts send at once: both sides initiate, both consume the other's initiation, both responses find no handshake outstanding. WireGuard
    // (the C, wireguard-go) recovers at the next retransmit (REKEY_TIMEOUT 5 s + jitter); the engine must too, without help.
    let (mut s, a, b, alias_a, alias_b) = two();
    s.nodes[b].echo_to = None;
    s.udp_up = false;
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.host_send_to(a, alias_b, 6000, 40000, b"hi");
    let mut ok = false;
    for _ in 0..16 {
        s.run_until(s.now + 1000);
        s.host_send_to(a, alias_b, 6000, 40000, b"again");
        if s.nodes[b].host_rx.iter().any(|p| parse_udp(p).is_some()) {
            ok = true;
            break;
        }
    }
    assert!(ok, "the handshake completed after the crossing");
    assert!(s.nodes[a].eng.stats().tx_count(TxFateExt::Parked) >= 1);
    s.check();
}
