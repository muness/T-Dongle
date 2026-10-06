//! Timers of the packet path: persistent keepalive, the bounded handshake series towards an unreachable peer, and a quiet engine goes to sleep.

mod common;
use common::*;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{HostFate, Input};

const A_EP: Ep = Ep::v4([203, 0, 113, 1], 41641);
const B_EP: Ep = Ep::v4([198, 51, 100, 7], 41641);

fn pair(keepalive_s: u16) -> (Sim, usize, usize, u32, u32) {
    let mut s = Sim::new(4);
    s.keepalive_s = keepalive_s;
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
    (s, a, b, alias_a, alias_b)
}

fn derp_len(o: &Owned, len: usize) -> bool {
    matches!(o, Owned::Derp { data, .. } if data.len() == len)
}

#[test]
fn persistent_keepalive_sends_an_empty_message_on_schedule() {
    let (mut s, a, b, alias_a, alias_b) = pair(25);
    s.nodes[b].echo_to = Some((alias_a, 40000));
    s.host_send_to(b, alias_a, 5000, 40000, b"open");
    s.run_until(s.now + 300);
    s.host_send_to(a, alias_b, 6000, 40000, b"hi");
    s.run_until(s.now + 2_000);
    assert_eq!(s.nodes[a].eng.status(s.now).members[0].unwrap().sessions, 1);
    let before = s.nodes[a].outs.iter().filter(|o| derp_len(o, 32)).count();
    // 100 s of silence: WireGuard keepalives (32 bytes) leave about every 25 s
    s.run_until(s.now + 100_000);
    let n = s.nodes[a].outs.iter().filter(|o| derp_len(o, 32)).count() - before;
    assert!((3..=6).contains(&n), "keepalives in 100 s: {n}");
    assert!(s.nodes[a].eng.stats().keepalive_tx.get() >= 3);
    s.check();
}

#[test]
fn an_unreachable_peer_gets_a_bounded_series_of_initiations_then_a_pause() {
    let (mut s, a, b, _alias_a, alias_b) = pair(0);
    s.nodes[b].muted = true; // B never answers
    s.nodes[b].derp_up = false;
    s.host_send_to(a, alias_b, 6000, 40000, b"hi");
    s.run_until(s.now + 100_000);
    let inits = s.nodes[a].eng.stats().hs_init_tx.get();
    // REKEY_ATTEMPT_TIME 90 s / MAX_HANDSHAKE_ATTEMPTS 18: one initiation per 5 s plus jitter, then the series is abandoned
    assert!((17..=19).contains(&inits), "initiations in the first series: {inits}");
    assert!(s.nodes[a].eng.member(1).unwrap().rt.park.is_empty());
    // abandoned: quiet until DISCO's 30 s rule for a peer without a session starts the next series
    s.run_until(s.now + 15_000);
    assert_eq!(s.nodes[a].eng.stats().hs_init_tx.get(), inits, "a pause between series");
    s.run_until(s.now + 60_000);
    let later = s.nodes[a].eng.stats().hs_init_tx.get();
    assert!(later > inits, "the next series follows (DISCO retries a session-less peer every 30 s)");
    assert!(later - inits <= 19, "and it is bounded too: {}", later - inits);
    s.check();
}

#[test]
fn an_idle_engine_sleeps_between_its_own_deadlines() {
    let mut s = Solo::new(5);
    s.member(1, 2, 0);
    // nothing resident, STUN has no servers: the only deadline is the netcheck/STUN schedule, then nothing at all
    s.advance(60_000);
    let w = s.wake;
    assert!(w.is_none_or(|w| w > s.now), "{w:?} {}", s.now);
    let a = s.alias(1, 1);
    assert_eq!(s.send(a, 30), tdongle_tailnet_engine::Handled::Host(HostFate::Forwarded));
    // a parked packet and a handshake in flight: the wake is the earliest of their deadlines, and it is soon
    let w = s.wake.expect("a deadline");
    assert!(w > s.now && w <= s.now + 5_100, "{w} vs {}", s.now);
    let _ = Input::Tick;
}
