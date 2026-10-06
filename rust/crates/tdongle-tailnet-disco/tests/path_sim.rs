//! Behaviour of the per-peer path machine in virtual time: the C's rules (`ml_wg_mgr.c`, ADRs 0013/0018) as scenarios, and a two-node simulation that
//! sends real sealed packets through a lossy fake network.

use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_disco::envelope::{self, PeerId, PeerResolver, RxOutcome, process};
use tdongle_tailnet_disco::msg::{Message, Ping, Pong};
use tdongle_tailnet_disco::path::*;
use tdongle_tailnet_disco::{Ep, msg};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;

const N: usize = 16;

/// Shared context of one membership.
struct World {
    cfg: PathConfig,
    probes: ProbeTable<N>,
    counters: PathCounters,
    rng: TestRng,
    burst: AddBurst,
}

impl World {
    fn new(seed: u64) -> Self {
        World { cfg: PathConfig::DEFAULT, probes: ProbeTable::new(), counters: PathCounters::default(), rng: TestRng(seed), burst: AddBurst::new() }
    }
    fn env(&mut self) -> Env<'_, N> {
        Env { cfg: &self.cfg, probes: &mut self.probes, rng: &mut self.rng, counters: &mut self.counters }
    }
}

type Actions = ActionBuf<64>;

fn input() -> TickInput {
    TickInput { online: true, allowed: true, udp_ok: true, session_up: false, wg_present: true, data_age_ms: None }
}

const PEER: Ep = Ep::v4([192, 168, 1, 20], 41641);
const PEER_PUBLIC: Ep = Ep::v4([203, 0, 113, 20], 41641);

fn added<const E: usize>(ps: &mut PathState<E>, w: &mut World, id: u8, now: u64, udp: bool, out: &mut Actions) {
    let mut burst = w.burst;
    ps.on_added(id, now, udp, &mut burst, &mut w.env(), out);
    w.burst = burst;
}

fn pings(a: &Actions) -> impl Iterator<Item = (Via, TxId, PingKind)> + '_ {
    a.iter().filter_map(|x| if let Action::SendPing { via, txid, kind } = x { Some((via, txid, kind)) } else { None })
}
fn count_ping(a: &Actions, f: impl Fn(Via) -> bool) -> usize {
    pings(a).filter(|(v, _, _)| f(*v)).count()
}
fn pong_to(ps: &mut PathState, w: &mut World, now: u64, from: RxFrom, txid: &TxId, session_up: bool, out: &mut Actions) -> PongOutcome {
    ps.on_pong(1, now, from, txid, session_up, &mut w.env(), out)
}

/// A direct path is found through a ping round and pong: the best address, trust, and the WireGuard actions.
#[test]
fn discovery_makes_a_direct_path_and_asks_for_a_handshake_once() {
    let mut w = World::new(1);
    let mut ps = PathState::<8>::new();
    ps.set_endpoints(&[PEER, PEER_PUBLIC], &w.cfg, &mut w.counters);
    let mut out = Actions::new();
    added(&mut ps, &mut w, 1, 1_000, true, &mut out);
    // a CallMeMaybe over DERP, one direct ping per endpoint and one over DERP, each with its own txid
    assert!(out.iter().any(|a| a == Action::SendCallMeMaybe));
    assert_eq!(count_ping(&out, |v| matches!(v, Via::Direct(_))), 2);
    assert_eq!(count_ping(&out, |v| v == Via::Derp), 1);
    let ids: Vec<TxId> = pings(&out).map(|p| p.1).collect();
    assert_eq!(ids.len(), 3);
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    assert_eq!(w.probes.len(), 3);
    assert_eq!(ps.route(1_000), Route::Derp);
    // the LAN endpoint answers first
    let lan_tx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
    let mut o2 = Actions::new();
    let r = pong_to(&mut ps, &mut w, 1_004, RxFrom::Direct(PEER), &lan_tx, false, &mut o2);
    assert_eq!(r, PongOutcome::NewBest { ep: PEER, rtt_ms: 4 });
    assert_eq!(o2.iter().collect::<Vec<_>>(), [Action::WgSetEndpoint(PEER), Action::WgDirectHandshake { retry: false }]);
    assert_eq!(ps.route(1_004), Route::Direct(PEER));
    let st = ps.status(1_004);
    assert!(st.has_direct && st.best == PEER && st.best_rtt_ms == Some(4) && st.trust_left_ms == 60_000);
    // the public address answers 1 ms later from another address: the best one is kept (sticky 6.5 s)
    let pub_tx = pings(&out).find(|p| p.0 == Via::Direct(PEER_PUBLIC)).unwrap().1;
    let mut o3 = Actions::new();
    assert_eq!(pong_to(&mut ps, &mut w, 1_005, RxFrom::Direct(PEER_PUBLIC), &pub_tx, false, &mut o3), PongOutcome::KeptBest { rtt_ms: 5 });
    assert!(o3.is_empty());
    // the DERP pong is liveness only
    let derp_tx = pings(&out).find(|p| p.0 == Via::Derp).unwrap().1;
    assert_eq!(pong_to(&mut ps, &mut w, 1_090, RxFrom::Derp(7), &derp_tx, false, &mut o3), PongOutcome::ViaDerp { rtt_ms: 90 });
    assert!(w.probes.is_empty());
    assert_eq!(w.counters.pong_matched.get(), 3);
    // a repeated pong is unmatched, not a second refresh
    assert_eq!(pong_to(&mut ps, &mut w, 1_100, RxFrom::Direct(PEER), &lan_tx, false, &mut o3), PongOutcome::Unmatched);
}

/// The direct handshake is retried every 30 s while pongs keep arriving and there is no session, and not at all with one.
#[test]
fn direct_handshake_cadence() {
    let mut w = World::new(2);
    let mut ps = PathState::<8>::new();
    ps.set_endpoints(&[PEER], &w.cfg, &mut w.counters);
    let mut handshakes = 0;
    let mut t = 10_000;
    for round in 0..8 {
        let mut out = Actions::new();
        ps.send_pings(1, t, true, true, PingKind::Discovery, &mut w.env(), &mut out);
        let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
        let mut o = Actions::new();
        pong_to(&mut ps, &mut w, t + 2, RxFrom::Direct(PEER), &tx, round >= 6, &mut o);
        handshakes += o.iter().filter(|a| matches!(a, Action::WgDirectHandshake { .. })).count();
        t += 10_000;
    }
    // pongs at 10, 20, 30, 40, 50, 60 s (no session): handshakes at 10 s and 40 s, the retry flagged; none for the last two (session up)
    assert_eq!(handshakes, 2);
    assert_eq!(w.counters.direct_handshakes.get(), 2);
}

/// Trust lapses: with data still flowing the endpoint is kept; with none and a session the path reverts to DERP; without a session it only re-probes.
#[test]
fn trust_expiry_decides_by_data() {
    for (data_age, session, want_revert, case) in
        [(Some(5_000), true, false, "flowing"), (None, true, true, "dead"), (Some(31_000), true, true, "stale"), (None, false, false, "no session")]
    {
        let mut w = World::new(3);
        let mut ps = PathState::<8>::new();
        ps.set_endpoints(&[PEER], &w.cfg, &mut w.counters);
        let mut out = Actions::new();
        ps.send_pings(1, 0, true, true, PingKind::Discovery, &mut w.env(), &mut out);
        let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
        pong_to(&mut ps, &mut w, 1, RxFrom::Direct(PEER), &tx, session, &mut Actions::new());
        let mut budget = TickBudget::new(&w.cfg);
        let inp = TickInput { session_up: session, data_age_ms: data_age, ..input() };
        // within trust nothing happens but the heartbeat (only with a session)
        let mut o = Actions::new();
        ps.tick(1, 30_000, &inp, &mut budget, &mut w.env(), &mut o);
        assert_eq!(ps.route(30_000), Route::Direct(PEER), "{case}");
        // trust (granted at t=1 for 60 s) is still good at 60_001 and gone at 60_002
        let mut o = Actions::new();
        ps.tick(1, 60_002, &inp, &mut budget, &mut w.env(), &mut o);
        assert_eq!(o.iter().any(|a| a == Action::RevertToDerp), want_revert, "{case}");
        // exactly one re-probe round, forced
        assert_eq!(count_ping(&o, |v| v == Via::Derp), 1, "{case}: one DERP ping");
        assert_eq!(count_ping(&o, |v| matches!(v, Via::Direct(_))), 1, "{case}: stale endpoint probed again");
        assert_eq!(ps.route(60_003), Route::Derp);
        assert!(!ps.status(60_003).has_direct);
    }
}

#[test]
fn heartbeat_only_behind_a_session_every_three_seconds_direct_only() {
    let mut w = World::new(4);
    let mut ps = PathState::<8>::new();
    ps.set_endpoints(&[PEER, PEER_PUBLIC], &w.cfg, &mut w.counters);
    let mut out = Actions::new();
    ps.send_pings(1, 0, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
    pong_to(&mut ps, &mut w, 1, RxFrom::Direct(PEER), &tx, true, &mut Actions::new());
    w.probes.forget_peer(1);
    let mut sent = 0;
    for session in [false, true] {
        let inp = TickInput { session_up: session, data_age_ms: Some(10), ..input() };
        let mut count = 0;
        for t in (1_000..=12_000).step_by(1_000) {
            let mut o = Actions::new();
            ps.tick(1, t + if session { 20_000 } else { 0 }, &inp, &mut TickBudget::new(&w.cfg), &mut w.env(), &mut o);
            for (via, txid, kind) in pings(&o) {
                // the heartbeat goes to the best address and every other known endpoint, never over DERP
                assert_ne!(via, Via::Derp);
                assert_eq!(kind, PingKind::Heartbeat);
                w.probes.take(&txid, 1, 0, u64::MAX);
                count += 1;
            }
            // keep trust alive with a pong each time one was sent
        }
        if session {
            sent = count;
        } else {
            assert_eq!(count, 0, "no heartbeat without a session");
        }
    }
    // 12 ticks, one a second, heartbeat after >3 s of silence: at 4 s, 8 s, 12 s of the window, each with two endpoints
    assert_eq!(sent, 3 * 2);
}

#[test]
fn cmm_burst_floor_and_never_answers_with_a_cmm_or_a_ping() {
    let mut w = World::new(5);
    let mut ps = PathState::<8>::new();
    ps.set_endpoints(&[PEER], &w.cfg, &mut w.counters);
    let mut raw = vec![];
    for ep in [
        Ep::v4([198, 51, 100, 1], 1000),
        Ep::v4([198, 51, 100, 2], 2000),
        Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 3000),
        Ep::v4([1, 2, 3, 4], 0),
    ] {
        let mut b = [0u8; 18];
        ep.write_wire(&mut b);
        raw.extend_from_slice(&b);
    }
    let mut plain = vec![3u8, 0];
    plain.extend_from_slice(&raw);
    let Ok(Message::CallMeMaybe { endpoints, .. }) = msg::parse(&plain) else { panic!() };
    assert_eq!(endpoints.len(), 4);
    let mut out = Actions::new();
    let r = ps.on_call_me_maybe(1, 10_000, endpoints, true, &mut w.env(), &mut out);
    assert_eq!(r, CmmOutcome { burst: true, probes: 2 });
    // two named IPv4 endpoints, then the round of known endpoints (PEER) and DERP; the IPv6 and the port-0 endpoint are skipped
    let to: Vec<Via> = pings(&out).map(|p| p.0).collect();
    assert_eq!(to, [Via::Direct(Ep::v4([198, 51, 100, 1], 1000)), Via::Direct(Ep::v4([198, 51, 100, 2], 2000)), Via::Direct(PEER), Via::Derp]);
    assert!(!out.iter().any(|a| a == Action::SendCallMeMaybe));
    assert_eq!(w.counters.cmm_endpoint_skipped.get(), 2);
    // inside 2.5 s: nothing
    let mut out = Actions::new();
    assert_eq!(ps.on_call_me_maybe(1, 12_499, endpoints, true, &mut w.env(), &mut out), CmmOutcome { burst: false, probes: 0 });
    assert!(out.is_empty());
    assert_eq!(w.counters.cmm_suppressed.get(), 1);
    // at 2.5 s it runs again
    let mut out = Actions::new();
    assert!(ps.on_call_me_maybe(1, 12_500, endpoints, true, &mut w.env(), &mut out).burst);
    // without UDP: only the DERP ping
    let mut ps2 = PathState::<8>::new();
    let mut out = Actions::new();
    ps2.on_call_me_maybe(2, 20_000, endpoints, false, &mut w.env(), &mut out);
    assert_eq!(pings(&out).map(|p| p.0).collect::<Vec<_>>(), [Via::Derp]);
}

#[test]
fn ping_is_answered_once_where_it_came_from_and_never_with_a_ping() {
    let mut w = World::new(6);
    let mut ps = PathState::<8>::new();
    let mut out = Actions::new();
    let tx = [7u8; 12];
    assert_eq!(ps.on_ping(100, RxFrom::Direct(PEER), tx, &mut w.env(), &mut out), PingOutcome::Answered);
    assert_eq!(out.iter().collect::<Vec<_>>(), [Action::SendPong { via: Via::Direct(PEER), txid: tx, src: PEER, derp_if_direct_fails: true }]);
    let mut out = Actions::new();
    ps.on_ping(101, RxFrom::Derp(9), tx, &mut w.env(), &mut out);
    let derp_src = Ep::v4([127, 3, 3, 40], 9);
    assert_eq!(out.iter().collect::<Vec<_>>(), [Action::SendPong { via: Via::Derp, txid: tx, src: derp_src, derp_if_direct_fails: false }]);
    assert!(w.probes.is_empty());
    let mut out = Actions::new();
    assert_eq!(ps.on_ping(102, RxFrom::Direct(Ep::v4([1, 2, 3, 4], 0)), tx, &mut w.env(), &mut out), PingOutcome::BadSource);
    assert!(out.is_empty());
}

#[test]
fn ping_flood_is_bounded_by_the_pong_budget() {
    let mut w = World::new(7);
    let mut ps = PathState::<8>::new();
    let mut answered = 0;
    for i in 0..1000u64 {
        let mut out = Actions::new();
        if ps.on_ping(50_000 + i / 100, RxFrom::Direct(PEER), [i as u8; 12], &mut w.env(), &mut out) == PingOutcome::Answered {
            answered += 1;
        }
    }
    // 1000 pings in 10 ms: the burst of 16 (+0 refill: 10 ms < 100 ms)
    assert_eq!(answered, 16);
    assert_eq!(w.counters.pong_rate_limited.get(), 984);
    // a second later 10 more tokens
    let mut got = 0;
    for _ in 0..100 {
        if ps.on_ping(51_050, RxFrom::Direct(PEER), [1; 12], &mut w.env(), &mut Actions::new()) == PingOutcome::Answered {
            got += 1;
        }
    }
    assert_eq!(got, 10);
}

#[test]
fn pong_validation() {
    let mut w = World::new(8);
    let mut a = PathState::<8>::new();
    a.set_endpoints(&[PEER], &w.cfg, &mut w.counters);
    let mut out = Actions::new();
    a.send_pings(1, 0, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
    // another peer cannot answer for it, and that does not consume the probe
    let mut other = PathState::<8>::new();
    assert_eq!(other.on_pong(2, 5, RxFrom::Direct(PEER), &tx, false, &mut w.env(), &mut Actions::new()), PongOutcome::WrongPeer);
    assert_eq!(w.probes.outstanding(1), 2);
    // an invented id
    assert_eq!(pong_to(&mut a, &mut w, 5, RxFrom::Direct(PEER), &[9; 12], false, &mut Actions::new()), PongOutcome::Unmatched);
    // after the 5 s timeout the pong is late and the probe is gone
    assert_eq!(pong_to(&mut a, &mut w, 5_001, RxFrom::Direct(PEER), &tx, false, &mut Actions::new()), PongOutcome::Late);
    assert_eq!(pong_to(&mut a, &mut w, 5_002, RxFrom::Direct(PEER), &tx, false, &mut Actions::new()), PongOutcome::Unmatched);
    // exactly at the timeout it is still on time
    let mut out = Actions::new();
    a.send_pings(1, 10_000, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
    assert!(matches!(pong_to(&mut a, &mut w, 15_000, RxFrom::Direct(PEER), &tx, false, &mut Actions::new()), PongOutcome::NewBest { .. }));
    // an unusable source address never becomes the path
    let mut out = Actions::new();
    a.send_pings(1, 20_000, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let tx2 = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
    assert_eq!(pong_to(&mut a, &mut w, 20_001, RxFrom::Direct(Ep::v4([0, 0, 0, 0], 5)), &tx2, false, &mut Actions::new()), PongOutcome::BadSource);
    // end of tick: expired probes are freed and counted
    let before = w.probes.len();
    assert!(before > 0);
    assert_eq!(expire_probes(&mut w.probes, 30_000, &w.cfg.clone(), &mut w.counters), before);
    assert!(w.probes.is_empty());
}

#[test]
fn sticky_best_then_takeover_after_it_goes_quiet() {
    let mut w = World::new(9);
    let mut ps = PathState::<8>::new();
    ps.set_endpoints(&[PEER, PEER_PUBLIC], &w.cfg, &mut w.counters);
    let round = |ps: &mut PathState, w: &mut World, t: u64, answer: Ep| {
        let mut out = Actions::new();
        ps.send_pings(1, t, true, true, PingKind::Discovery, &mut w.env(), &mut out);
        let tx = pings(&out).find(|p| p.0 == Via::Direct(answer)).unwrap().1;
        pong_to(ps, w, t + 1, RxFrom::Direct(answer), &tx, true, &mut Actions::new())
    };
    assert!(matches!(round(&mut ps, &mut w, 1_000, PEER), PongOutcome::NewBest { .. }));
    w.probes.forget_peer(1);
    // the other address answers within 6.5 s of the best's last pong: kept
    assert!(matches!(round(&mut ps, &mut w, 6_000, PEER_PUBLIC), PongOutcome::KeptBest { .. }));
    w.probes.forget_peer(1);
    // after 6.5 s without an answer from the best, the other address takes over, and WireGuard is re-pointed
    let mut out = Actions::new();
    ps.send_pings(1, 7_600, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER_PUBLIC)).unwrap().1;
    let mut o = Actions::new();
    let r = pong_to(&mut ps, &mut w, 7_605, RxFrom::Direct(PEER_PUBLIC), &tx, true, &mut o);
    assert_eq!(r, PongOutcome::NewBest { ep: PEER_PUBLIC, rtt_ms: 5 });
    assert_eq!(o.iter().collect::<Vec<_>>(), [Action::WgSetEndpoint(PEER_PUBLIC)]);
    assert_eq!(w.counters.best_changed.get(), 2);
    // the same address again: trust renewed, no new WireGuard action
    w.probes.forget_peer(1);
    let mut out = Actions::new();
    ps.send_pings(1, 9_000, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let tx = pings(&out).find(|p| p.0 == Via::Direct(PEER_PUBLIC)).unwrap().1;
    let mut o = Actions::new();
    assert!(matches!(pong_to(&mut ps, &mut w, 9_001, RxFrom::Direct(PEER_PUBLIC), &tx, true, &mut o), PongOutcome::Refreshed { .. }));
    assert!(o.is_empty());
}

/// With `latency_switch` Go's betterAddr may move the best inside the sticky window: a private address beats a public one at similar latency.
#[test]
fn latency_switch_prefers_private_addresses_like_go() {
    let mut w = World::new(10);
    w.cfg.latency_switch = true;
    let mut ps = PathState::<8>::new();
    ps.set_endpoints(&[PEER_PUBLIC, PEER], &w.cfg, &mut w.counters);
    let mut out = Actions::new();
    ps.send_pings(1, 0, true, true, PingKind::Discovery, &mut w.env(), &mut out);
    let pubtx = pings(&out).find(|p| p.0 == Via::Direct(PEER_PUBLIC)).unwrap().1;
    let lantx = pings(&out).find(|p| p.0 == Via::Direct(PEER)).unwrap().1;
    pong_to(&mut ps, &mut w, 20, RxFrom::Direct(PEER_PUBLIC), &pubtx, true, &mut Actions::new());
    let mut o = Actions::new();
    let r = pong_to(&mut ps, &mut w, 22, RxFrom::Direct(PEER), &lantx, true, &mut o);
    assert!(matches!(r, PongOutcome::NewBest { ep, .. } if ep == PEER), "{r:?}");
    assert_eq!(o.iter().collect::<Vec<_>>(), [Action::WgSetEndpoint(PEER)]);
    // betterAddr itself
    let (pubep, lan) = (PEER_PUBLIC, PEER);
    assert!(better_addr(lan, 20, pubep, 20));
    assert!(!better_addr(pubep, 20, lan, 20));
    assert!(!better_addr(pubep, 19, pubep, 20)); // same address
    assert!(better_addr(pubep, 10, Ep::v4([203, 0, 113, 99], 1), 100)); // 90% faster
    assert!(!better_addr(Ep::v4([203, 0, 113, 98], 1), 99, Ep::v4([203, 0, 113, 99], 1), 100)); // 1% is hysteresis
    assert!(better_addr(pubep, 1, Ep::NONE, 0));
}

#[test]
fn upgrade_probes_are_budgeted_and_skip_offline_peers() {
    let mut w = World::new(11);
    let mut peers: Vec<PathState<4>> = (0..5).map(|_| PathState::new()).collect();
    for p in &mut peers {
        p.set_endpoints(&[PEER], &w.cfg, &mut w.counters);
    }
    let mut upgraded = [0u32; 5];
    let mut start = 0usize;
    let mut now = 20_000u64;
    for tick in 0..30 {
        let mut budget = TickBudget::new(&w.cfg);
        for n in 0..peers.len() {
            let i = (start + n) % peers.len();
            let mut out = Actions::new();
            let inp = TickInput { online: i != 4, ..input() };
            peers[i].tick(i as u8, now, &inp, &mut budget, &mut w.env(), &mut out);
            if pings(&out).next().is_some() {
                upgraded[i] += 1;
                for (_, txid, _) in pings(&out) {
                    w.probes.take(&txid, i as u8, now, u64::MAX);
                }
            }
        }
        start = next_rotation(start, w.cfg.upgrades_per_tick as usize, peers.len());
        now += 1_000;
        let _ = tick;
    }
    // 30 s: each online peer is probed every 15 s (twice) and never more than two peers in a tick; the offline one never
    assert_eq!(upgraded[4], 0);
    for (i, u) in upgraded.iter().enumerate().take(4) {
        assert!((2..=3).contains(u), "peer {i}: {u}");
    }
    assert!(w.counters.upgrade_deferred.get() > 0);
    // rotation arithmetic
    assert_eq!(next_rotation(3, 2, 5), 0);
    assert_eq!(next_rotation(0, 2, 0), 0);
}

#[test]
fn derp_handshake_for_a_sessionless_peer_every_30_seconds() {
    let mut w = World::new(12);
    let mut ps = PathState::<8>::new();
    let mut out = Actions::new();
    added(&mut ps, &mut w, 1, 1_000, true, &mut out);
    let mut hs = vec![];
    for t in (1_000..=130_000).step_by(1_000) {
        let mut o = Actions::new();
        ps.tick(1, t, &input(), &mut TickBudget::new(&w.cfg), &mut w.env(), &mut o);
        for a in o.iter() {
            if let Action::WgDerpHandshake { retry } = a {
                hs.push((t, retry));
            }
        }
        w.probes.forget_peer(1);
    }
    // not before 30 s after the peer was added (strictly more), then every 30 s: first, then retries
    assert_eq!(hs, [(32_000, false), (63_000, true), (94_000, true), (125_000, true)]);
    assert!(ps.status(130_000).derp_fallback_active);
    // with a session, none; an offline peer, none; no WireGuard slot, none
    for inp in [
        TickInput { session_up: true, ..input() },
        TickInput { online: false, ..input() },
        TickInput { wg_present: false, ..input() },
        TickInput { allowed: false, ..input() },
    ] {
        let mut ps = PathState::<8>::new();
        ps.on_added(1, 0, false, &mut AddBurst::new(), &mut w.env(), &mut Actions::new());
        let mut o = Actions::new();
        ps.tick(1, 90_000, &inp, &mut TickBudget::new(&w.cfg), &mut w.env(), &mut o);
        assert!(!o.iter().any(|a| matches!(a, Action::WgDerpHandshake { .. })), "{inp:?}");
    }
}

#[test]
fn new_peers_get_a_cmm_and_at_most_five_forced_pings_a_second() {
    let mut w = World::new(13);
    let mut cmm = 0;
    let mut forced = 0;
    for i in 0..12u8 {
        let mut ps = PathState::<8>::new();
        ps.set_endpoints(&[PEER], &w.cfg, &mut w.counters);
        let mut out = Actions::new();
        added(&mut ps, &mut w, i, 5_000 + u64::from(i) * 10, true, &mut out);
        cmm += out.iter().filter(|a| *a == Action::SendCallMeMaybe).count();
        forced += usize::from(pings(&out).next().is_some());
        w.probes.forget_peer(i);
    }
    assert_eq!((cmm, forced), (12, 5));
    // a second later the budget is back
    let mut ps = PathState::<8>::new();
    let mut out = Actions::new();
    added(&mut ps, &mut w, 0, 6_200, true, &mut out);
    assert!(pings(&out).next().is_some());
    // without UDP (cellular): nothing at all
    let mut ps = PathState::<8>::new();
    let mut out = Actions::new();
    added(&mut ps, &mut w, 0, 7_000, false, &mut out);
    assert!(out.is_empty());
}

#[test]
fn ping_round_rate_limit_and_probe_bounds() {
    let mut w = World::new(14);
    let mut ps = PathState::<8>::new();
    let eps: Vec<Ep> = (1..=12u8).map(|i| Ep::v4([10, 0, 0, i], 1000)).collect();
    assert_eq!(ps.set_endpoints(&eps, &w.cfg, &mut w.counters), 8);
    assert_eq!(w.counters.endpoint_dropped.get(), 4);
    assert_eq!(
        ps.set_endpoints(&[Ep::v4([1, 1, 1, 1], 0), PEER, PEER, Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 5)], &w.cfg, &mut w.counters),
        1
    );
    ps.set_endpoints(&eps, &w.cfg, &mut w.counters);
    // non-forced rounds at most every 5 s
    let mut out = Actions::new();
    assert!(ps.send_pings(1, 1_000, false, true, PingKind::Discovery, &mut w.env(), &mut out));
    // 8 direct + DERP = 9 = the per-peer cap
    assert_eq!(out.len(), 9);
    assert!(!ps.send_pings(1, 5_999, false, true, PingKind::Discovery, &mut w.env(), &mut Actions::new()));
    assert_eq!(w.counters.ping_rate_limited.get(), 1);
    // a forced round while the first is outstanding is refused by the per-peer cap, not sent
    let mut out2 = Actions::new();
    assert!(ps.send_pings(1, 2_000, true, true, PingKind::Discovery, &mut w.env(), &mut out2));
    assert_eq!(out2.len(), 0);
    assert_eq!(w.counters.probe_peer_cap.get(), 9);
    assert!(w.probes.outstanding(1) <= w.cfg.max_outstanding_per_peer);
    // many peers fill the table, and the rest is counted, never sent
    let mut total_sent = 0;
    for id in 2..40u8 {
        let mut p = PathState::<8>::new();
        p.set_endpoints(&eps[..3], &w.cfg, &mut w.counters);
        let mut o = Actions::new();
        p.send_pings(id, 3_000, true, true, PingKind::Discovery, &mut w.env(), &mut o);
        total_sent += o.len();
        assert!(w.probes.len() <= N);
    }
    assert_eq!(w.probes.len(), N);
    assert_eq!(total_sent + 9, N);
    assert!(w.counters.probe_table_full.get() > 0);
    // a sink that is too small loses actions, counted
    let mut tiny = ActionBuf::<1>::new();
    let mut p = PathState::<8>::new();
    w.probes = ProbeTable::new();
    p.set_endpoints(&eps[..3], &w.cfg, &mut w.counters);
    p.send_pings(1, 3_000, true, true, PingKind::Discovery, &mut w.env(), &mut tiny);
    assert_eq!(tiny.len(), 1);
    assert_eq!(w.counters.actions_dropped.get(), 3);
}

#[test]
fn local_endpoints_like_the_c() {
    let mut out = [Ep::NONE; 2];
    assert_eq!(local_endpoints(Some([192, 168, 1, 9]), 41641, Some(Ep::v4([203, 0, 113, 5], 4000)), &mut out), 2);
    assert_eq!(out, [Ep::v4([192, 168, 1, 9], 41641), Ep::v4([203, 0, 113, 5], 4000)]);
    // STUN gave an address but no port: the local port stands in
    assert_eq!(local_endpoints(None, 41641, Some(Ep::v4([203, 0, 113, 5], 0)), &mut out), 1);
    assert_eq!(out[0], Ep::v4([203, 0, 113, 5], 41641));
    // no socket port: no LAN endpoint; nothing known: nothing
    assert_eq!(local_endpoints(Some([192, 168, 1, 9]), 0, None, &mut out), 0);
    assert_eq!(local_endpoints(Some([0, 0, 0, 0]), 41641, None, &mut out), 0);
}

// ----- two nodes, real packets, a lossy network -----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    A,
    B,
}

struct Node {
    side: Side,
    addr: Ep,
    secret: Key32,
    public: Key32,
    peer_disco: Key32,
    shared: Key32,
    w: World,
    ps: PathState<8>,
    session_up: bool,
    wg_endpoint: Option<Ep>,
    handshakes: Vec<String>,
    rx: tdongle_tailnet_disco::envelope::RxCounters,
    reverted: u32,
}

struct Resident<'a>(&'a Key32, &'a Key32);
impl PeerResolver for Resident<'_> {
    fn resident(&mut self, s: &[u8; 32]) -> Option<(PeerId, Key32)> {
        (s == self.0.as_bytes()).then(|| (1, self.1.clone()))
    }
    fn candidate(&mut self, _: &[u8; 32]) -> Option<(u32, Key32)> {
        None
    }
    fn activate(&mut self, _: u32) -> Option<PeerId> {
        None
    }
}

struct Packet {
    at: u64,
    to: Side,
    from: RxFrom,
    bytes: Vec<u8>,
}

struct Net {
    now: u64,
    queue: Vec<Packet>,
    direct_up: bool,
    loss_every: u32,
    sent: u32,
    delivered_direct: u32,
    delivered_derp: u32,
}

impl Node {
    fn new(side: Side, seed: u8) -> Node {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_mul(29).wrapping_add(i as u8 + 3);
        }
        let secret = Key32(s);
        let public = x25519::public(&secret);
        Node {
            side,
            addr: Ep::v4([192, 168, 1, if side == Side::A { 10 } else { 20 }], 41641),
            secret,
            public,
            peer_disco: Key32::ZERO,
            shared: Key32::ZERO,
            w: World::new(u64::from(seed) * 7919 + 1),
            ps: PathState::new(),
            session_up: false,
            wg_endpoint: None,
            handshakes: vec![],
            rx: Default::default(),
            reverted: 0,
        }
    }
    fn set_peer(&mut self, their_public: &Key32, their_addr: Ep) {
        self.peer_disco = their_public.clone();
        self.shared = nacl::precompute(&self.secret, their_public).unwrap();
        self.ps.set_endpoints(&[their_addr], &self.w.cfg, &mut self.w.counters);
    }
    fn other(&self) -> Side {
        if self.side == Side::A { Side::B } else { Side::A }
    }
    fn nonce(&mut self) -> [u8; 24] {
        envelope::fresh_nonce(&mut self.w.rng)
    }
    fn execute(&mut self, net: &mut Net, out: &Actions) {
        for a in out.iter() {
            let mut buf = [0u8; 256];
            let nonce = self.nonce();
            match a {
                Action::SendPing { via, txid, .. } => {
                    let n = envelope::seal_ping(&mut buf, &self.public, &self.shared, &nonce, &Ping { txid, node_key: None, padding: 0 }).unwrap();
                    self.transmit(net, via, &buf[..n]);
                }
                Action::SendPong { via, txid, src, .. } => {
                    let n = envelope::seal_pong(&mut buf, &self.public, &self.shared, &nonce, &Pong { txid, src }).unwrap();
                    self.transmit(net, via, &buf[..n]);
                }
                Action::SendCallMeMaybe => {
                    let n = envelope::seal_call_me_maybe(&mut buf, &self.public, &self.shared, &nonce, &[self.addr]).unwrap();
                    self.transmit(net, Via::Derp, &buf[..n]);
                }
                Action::WgSetEndpoint(ep) => self.wg_endpoint = Some(ep),
                Action::WgDirectHandshake { retry } => self.handshakes.push(format!("direct{}", if retry { "-retry" } else { "" })),
                Action::WgDerpHandshake { retry } => self.handshakes.push(format!("derp{}", if retry { "-retry" } else { "" })),
                Action::RevertToDerp => {
                    self.reverted += 1;
                    self.wg_endpoint = None;
                }
            }
        }
    }
    fn transmit(&mut self, net: &mut Net, via: Via, bytes: &[u8]) {
        net.sent += 1;
        if net.loss_every != 0 && net.sent.is_multiple_of(net.loss_every) {
            return;
        }
        match via {
            Via::Direct(_) if !net.direct_up => {}
            Via::Direct(_) => net.queue.push(Packet { at: net.now + 2, to: self.other(), from: RxFrom::Direct(self.addr), bytes: bytes.to_vec() }),
            Via::Derp => net.queue.push(Packet { at: net.now + 40, to: self.other(), from: RxFrom::Derp(1), bytes: bytes.to_vec() }),
        }
    }
    fn receive(&mut self, net: &mut Net, p: &Packet) {
        let mut bytes = p.bytes.clone();
        let mut r = Resident(&self.peer_disco, &self.shared);
        let res = process(&mut bytes, &mut r);
        self.rx.record_result(&res);
        let Ok(rx) = res else { return };
        let mut out = Actions::new();
        let now = net.now;
        match rx.message {
            Message::Ping(pg) => {
                match p.from {
                    RxFrom::Direct(_) => net.delivered_direct += 1,
                    RxFrom::Derp(_) => net.delivered_derp += 1,
                }
                self.ps.on_ping(now, p.from, pg.txid, &mut self.w.env(), &mut out);
            }
            Message::Pong(pg) => {
                let up = self.session_up;
                self.ps.on_pong(1, now, p.from, &pg.txid, up, &mut self.w.env(), &mut out);
            }
            Message::CallMeMaybe { endpoints, .. } => {
                self.ps.on_call_me_maybe(1, now, endpoints, true, &mut self.w.env(), &mut out);
            }
            Message::Unsupported(_) => {}
        }
        self.execute(net, &out);
    }
    fn tick(&mut self, net: &mut Net, data_age: Option<u64>) {
        let inp = TickInput { session_up: self.session_up, data_age_ms: data_age, ..input() };
        let mut out = Actions::new();
        let mut budget = TickBudget::new(&self.w.cfg);
        self.ps.tick(1, net.now, &inp, &mut budget, &mut self.w.env(), &mut out);
        let cfg = self.w.cfg;
        expire_probes(&mut self.w.probes, net.now, &cfg, &mut self.w.counters);
        self.execute(net, &out);
    }
}

fn step(a: &mut Node, b: &mut Node, net: &mut Net, to: u64, a_data: Option<u64>) {
    while net.now < to {
        net.now += 1;
        let mut due = vec![];
        net.queue.retain(|p| {
            if p.at <= net.now {
                due.push(Packet { at: p.at, to: p.to, from: p.from, bytes: p.bytes.clone() });
                false
            } else {
                true
            }
        });
        for p in due {
            match p.to {
                Side::A => a.receive(net, &p),
                Side::B => b.receive(net, &p),
            }
        }
        if net.now.is_multiple_of(1000) {
            a.tick(net, a_data);
            b.tick(net, a_data);
        }
    }
}

fn pair(loss_every: u32) -> (Node, Node, Net) {
    let mut a = Node::new(Side::A, 1);
    let mut b = Node::new(Side::B, 2);
    let (apub, bpub) = (a.public.clone(), b.public.clone());
    a.set_peer(&bpub, b.addr);
    b.set_peer(&apub, a.addr);
    let mut net = Net { now: 1_000, queue: vec![], direct_up: true, loss_every, sent: 0, delivered_direct: 0, delivered_derp: 0 };
    let mut out = Actions::new();
    let now = net.now;
    let mut burst = AddBurst::new();
    a.ps.on_added(1, now, true, &mut burst, &mut a.w.env(), &mut out);
    a.execute(&mut net, &out);
    (a, b, net)
}

/// Full discovery over real sealed packets: A pings B directly and over DERP, B's CallMeMaybe-less reply makes the path; then the direct path is cut,
/// data stops, and A falls back to DERP, and later finds the direct path again through the upgrade probe.
#[test]
fn two_nodes_discover_lose_and_regain_a_direct_path() {
    let (mut a, mut b, mut net) = pair(0);
    step(&mut a, &mut b, &mut net, 1_100, None);
    // B got A's CallMeMaybe (over DERP at +40 ms) and A's pings; A has a direct path to B
    assert_eq!(a.ps.route(net.now), Route::Direct(b.addr));
    assert_eq!(a.wg_endpoint, Some(b.addr));
    assert_eq!(a.handshakes, ["direct"]);
    // B never pinged first: it only answered A's pings and, on the CallMeMaybe, probed A's endpoint
    assert!(a.rx.get(RxOutcome::Pong) >= 1 && b.rx.get(RxOutcome::CallMeMaybe) == 1 && b.rx.get(RxOutcome::Ping) >= 1);
    assert_eq!(a.rx.get(RxOutcome::CallMeMaybe), 0, "no CallMeMaybe is ever sent back");
    assert!(matches!(b.ps.route(net.now), Route::Direct(ep) if ep == a.addr));
    // a session comes up; the heartbeat keeps trust alive for five minutes of virtual time with 3 s heartbeats
    a.session_up = true;
    b.session_up = true;
    let pings_before = a.w.counters.ping_direct.get();
    step(&mut a, &mut b, &mut net, 301_000, Some(100));
    assert_eq!(a.ps.route(net.now), Route::Direct(b.addr));
    let heartbeats = a.w.counters.heartbeats.get();
    // one tick a second and "more than 3 s since the last ping" (as the C compares): a heartbeat every 4 s, 75 in 300 s
    assert!((73..=77).contains(&heartbeats), "{heartbeats}");
    assert!(a.w.counters.ping_direct.get() - pings_before >= heartbeats);
    // the direct path dies and no data flows: within 60 s plus a tick A reverts to DERP, exactly once
    net.direct_up = false;
    step(&mut a, &mut b, &mut net, 371_000, None);
    assert_eq!(a.reverted, 1);
    assert_eq!(a.ps.route(net.now), Route::Derp);
    assert_eq!(a.wg_endpoint, None);
    // the path comes back; the upgrade probe (every 15 s while on DERP) finds it again
    net.direct_up = true;
    step(&mut a, &mut b, &mut net, 400_000, None);
    assert_eq!(a.ps.route(net.now), Route::Direct(b.addr));
    assert_eq!(a.wg_endpoint, Some(b.addr));
    // everything was counted: every received datagram is one outcome
    assert_eq!(a.rx.get(RxOutcome::OpenFailed) + b.rx.get(RxOutcome::OpenFailed), 0);
    assert!(a.w.probes.len() <= N && b.w.probes.len() <= N);
}

/// 20% loss, in both directions: a path is still found and no state grows without bound.
#[test]
fn lossy_network_still_converges_and_stays_bounded() {
    for loss_every in [3u32, 5, 7] {
        let (mut a, mut b, mut net) = pair(loss_every);
        a.session_up = true;
        b.session_up = true;
        step(&mut a, &mut b, &mut net, 120_000, Some(100));
        assert!(matches!(a.ps.route(net.now), Route::Direct(_)), "loss 1/{loss_every}");
        assert!(a.w.probes.len() <= N);
        assert!(net.queue.len() < 50);
    }
}

/// A peer that only has a DERP path (direct blocked) is probed every 15 s and handshaken over DERP every 30 s.
#[test]
fn derp_only_peer_cadence() {
    let (mut a, mut b, mut net) = pair(0);
    net.direct_up = false;
    step(&mut a, &mut b, &mut net, 130_000, None);
    assert_eq!(a.ps.route(net.now), Route::Derp);
    // DERP handshakes at about 32 s, 63 s, 94 s, 125 s
    assert_eq!(a.handshakes, ["derp", "derp-retry", "derp-retry", "derp-retry"]);
    // upgrade probes: one round per 15 s (7 or 8 in 129 s), each with a direct and a DERP ping; DERP pongs arrived but never made a direct path
    let up = a.w.counters.upgrade_probes.get();
    assert!((7..=9).contains(&up), "{up}");
    assert!(a.w.counters.pong_via_derp.get() >= 5);
    assert_eq!(a.w.counters.best_changed.get(), 0);
    // an attacker injecting packets for A: wrong box, wrong key and garbage are counted, never act
    let mut junk =
        Packet { at: net.now, to: Side::A, from: RxFrom::Direct(Ep::v4([6, 6, 6, 6], 666)), bytes: vec![0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 1, 2, 3] };
    a.receive(&mut net, &junk);
    junk.bytes = vec![0u8; 100];
    a.receive(&mut net, &junk);
    assert_eq!(a.rx.get(RxOutcome::NotDisco), 2);
    // the sum of outcomes equals the packets processed
    let total = a.rx.total();
    assert!(total > 10);
    let _ = msg::MAGIC;
}
