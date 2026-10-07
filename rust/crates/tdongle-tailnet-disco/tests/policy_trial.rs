//! `tests/test_inbound_trial.c` and the simulation of `tests/test_peer_policy.c`: activation on an unauthenticated claim.
//!
//! The C test slices the real `ml_wg_mgr.c` decision code around stubs for WireGuard and the directory. Here the decision pieces are `TrialGate` and
//! `pick_victim`; the peer table, the directory and "WireGuard authenticated this peer" are the test's model of them, and the DISCO case runs the real
//! `envelope::process` with a resolver built from the same pieces.

use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::envelope::{self, PeerId, PeerResolver, RxOutcome, process};
use tdongle_tailnet_disco::msg::Pong;
use tdongle_tailnet_disco::policy::*;
use tdongle_tailnet_types::Key32;

const SLOTS: usize = 8;

#[derive(Clone, Copy, Default)]
struct P {
    key: u32,
    used: u64,
    unconfirmed: bool,
}

#[derive(Default)]
struct Model {
    peers: [Option<P>; SLOTS],
    gate: TrialGate,
    directory: Vec<u32>,
    authenticated: Vec<u32>,
    pinned: Option<u32>,
    removals: u32,
}

impl Model {
    fn resident(&self) -> usize {
        self.peers.iter().flatten().count()
    }
    fn find(&self, key: u32) -> Option<usize> {
        self.peers.iter().position(|p| p.is_some_and(|p| p.key == key))
    }
    fn fill(&mut self, first: u32, count: u32, used: u64) {
        for i in 0..count {
            let slot = self.peers.iter().position(Option::is_none).unwrap();
            self.peers[slot] = Some(P { key: first + i, used, unconfirmed: false });
        }
    }
    /// `directory_activate_idle`: a free slot, or evict a peer idle for `idle_ms` (never the priority peer or a trial).
    fn activate(&mut self, key: u32, now: u64, idle_ms: u64) -> Option<usize> {
        if let Some(i) = self.peers.iter().position(Option::is_none) {
            self.peers[i] = Some(P { key, used: now, unconfirmed: false });
            return Some(i);
        }
        let cands: Vec<(usize, VictimCandidate)> = self
            .peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let p = p.unwrap();
                (i, VictimCandidate { last_used_ms: p.used, owner_slots: self.resident() as u32, pinned: Some(p.key) == self.pinned, trial: p.unconfirmed })
            })
            .collect();
        let v = pick_victim(&cands.iter().map(|c| c.1).collect::<Vec<_>>(), now, idle_ms)?;
        let slot = cands[v].0;
        self.removals += 1;
        self.peers[slot] = Some(P { key, used: now, unconfirmed: false });
        Some(slot)
    }
    fn poll(&mut self, now: u64) {
        let (peers, auth) = (&self.peers, &self.authenticated);
        let r = self.gate.poll(now, |slot| match peers[usize::from(slot)] {
            Some(p) if p.unconfirmed => {
                if auth.contains(&p.key) {
                    TrialPeer::Authenticated
                } else {
                    TrialPeer::Waiting
                }
            }
            _ => TrialPeer::Gone,
        });
        match r {
            TrialPoll::Confirmed(s) => self.peers[usize::from(s)].as_mut().unwrap().unconfirmed = false,
            TrialPoll::Expired(s) => {
                self.peers[usize::from(s)] = None;
                self.removals += 1;
            }
            TrialPoll::Idle | TrialPoll::Cleared => {}
        }
    }
    /// `derp_sender_admit`.
    fn derp_sender_admit(&mut self, key: u32, now: u64, plausible_initiation: bool) -> Option<usize> {
        if let Some(i) = self.find(key) {
            return Some(i);
        }
        if !plausible_initiation {
            return None;
        }
        self.poll(now);
        if !self.gate.open(now) || !self.directory.contains(&key) {
            return None;
        }
        let i = self.activate(key, now, TRIAL_EVICT_IDLE_MS)?;
        self.peers[i].as_mut().unwrap().unconfirmed = true;
        self.gate.start(i as u8, now);
        Some(i)
    }
}

fn model() -> Model {
    Model { directory: (1..=40).collect(), ..Default::default() }
}

#[test]
fn forged_derp_key_that_is_not_an_initiation_never_reaches_the_directory() {
    let mut m = model();
    for k in 1..=40 {
        assert!(m.derp_sender_admit(k, 100_000, false).is_none());
    }
    assert_eq!((m.resident(), m.gate.started.get(), m.gate.pending_slot()), (0, 0, None));
    assert_eq!(m.gate.refused.get(), 0, "no token was spent either");
}

#[test]
fn plausible_initiation_for_an_unknown_key_activates_nothing() {
    let mut m = model();
    assert!(m.derp_sender_admit(9999, 100_000, true).is_none());
    assert_eq!((m.resident(), m.gate.pending_slot()), (0, None));
}

#[test]
fn a_trial_gets_a_slot_not_standing_and_expires_into_a_cooldown() {
    let mut m = model();
    let now = 100_000;
    let i = m.derp_sender_admit(5, now, true).unwrap();
    assert!(m.peers[i].unwrap().unconfirmed);
    assert_eq!((m.gate.pending_slot(), m.gate.started.get()), (Some(i as u8), 1));
    // while pending, no other unknown key gets in
    assert!(m.derp_sender_admit(6, now, true).is_none());
    assert_eq!(m.resident(), 1);
    assert!(m.gate.refused.get() >= 1);
    m.poll(now + 4_999);
    assert_eq!(m.resident(), 1);
    m.poll(now + 5_000);
    assert_eq!((m.resident(), m.removals, m.gate.expired.get(), m.gate.pending_slot()), (0, 1, 1, None));
    // cool-down
    assert!(m.derp_sender_admit(6, now + 6_000, true).is_none());
    assert_eq!(m.resident(), 0);
    let i = m.derp_sender_admit(6, now + 5_000 + 30_000, true).unwrap();
    assert!(m.peers[i].unwrap().unconfirmed);
}

#[test]
fn the_genuine_peer_is_confirmed_and_kept() {
    let mut m = model();
    let now = 100_000;
    let i = m.derp_sender_admit(7, now, true).unwrap();
    m.authenticated.push(7);
    m.poll(now + 1);
    assert!(!m.peers[i].unwrap().unconfirmed);
    assert_eq!((m.gate.pending_slot(), m.gate.confirmed.get()), (None, 1));
    m.poll(now + 60_000);
    assert!(m.peers[i].is_some(), "never expires");
    assert!(m.derp_sender_admit(8, now + 60_000, true).is_some(), "the slot is free for the next");
    assert_eq!(m.derp_sender_admit(7, now + 60_001, true), Some(i), "resident: no trial");
}

#[test]
fn a_forged_key_never_evicts_a_warm_peer() {
    // all hot
    let mut m = model();
    m.fill(1, 8, 99_000);
    assert!(m.derp_sender_admit(20, 100_000, true).is_none());
    assert_eq!((m.resident(), m.removals), (8, 0));
    // idle 20 s: evictable for an authenticated activation, not for a claim
    let mut m = model();
    m.fill(1, 8, 80_000);
    assert!(m.derp_sender_admit(20, 100_000, true).is_none());
    assert_eq!((m.resident(), m.removals), (8, 0));
    // idle a minute: the coldest one may go
    let mut m = model();
    m.fill(1, 8, 100_000 - 61_000);
    m.peers[3].as_mut().unwrap().used = 100_000 - 90_000;
    let i = m.derp_sender_admit(20, 100_000, true).unwrap();
    assert_eq!((i, m.removals, m.resident()), (3, 1, 8));
    assert!(m.peers[i].unwrap().unconfirmed);
    // the authenticated path is unchanged: 10 s window
    let mut m = model();
    m.fill(1, 8, 99_000);
    assert!(m.activate(20, 100_000, ACTIVATE_EVICT_IDLE_MS).is_none());
    for p in m.peers.iter_mut().flatten() {
        p.used = 80_000;
    }
    assert!(m.activate(20, 100_000, ACTIVATE_EVICT_IDLE_MS).is_some());
    assert_eq!(m.removals, 1);
}

#[test]
fn the_priority_peer_is_never_the_victim_of_a_trial() {
    let mut m = model();
    m.fill(1, 8, 100_000 - 90_000);
    m.pinned = Some(1);
    let i = m.derp_sender_admit(30, 100_000, true).unwrap();
    assert_ne!(i, 0);
    assert!(m.peers[0].is_some());
}

#[test]
fn lookups_an_unauthenticated_packet_can_cause_are_budgeted() {
    let mut m = model();
    let now = 100_000;
    for k in 9000..9003 {
        assert!(m.derp_sender_admit(k, now, true).is_none());
    }
    assert_eq!(m.gate.refused.get(), 0, "three lookups reached the directory");
    assert!(m.derp_sender_admit(5, now, true).is_none(), "even a real key waits");
    assert_eq!(m.gate.refused.get(), 1);
    assert!(m.derp_sender_admit(5, now + 1000, true).is_some(), "one token back after a second");
}

/// DISCO: a forged sender key is dropped before it can activate anything; a box that opens activates; a flood of forgeries costs three box opens.
struct DiscoSide {
    model: Model,
    my_secret: Key32,
    /// disco key (public) -> peer record id in the directory
    directory: Vec<(Key32, u32)>,
    now: u64,
    opens: u32,
}

impl PeerResolver for DiscoSide {
    fn resident(&mut self, sender: &[u8; 32]) -> Option<(PeerId, Key32)> {
        let (_, id) = self.directory.iter().find(|(k, _)| k.as_bytes() == sender)?;
        let slot = self.model.find(*id)?;
        self.model.peers[slot].as_mut().unwrap().used = self.now;
        Some((slot as u8, nacl::precompute(&self.my_secret, &Key32(*sender))?))
    }
    fn candidate(&mut self, sender: &[u8; 32]) -> Option<(u32, Key32)> {
        if !self.model.gate.token(self.now) {
            return None;
        }
        let (_, id) = self.directory.iter().find(|(k, _)| k.as_bytes() == sender)?;
        self.opens += 1;
        Some((*id, nacl::precompute(&self.my_secret, &Key32(*sender))?))
    }
    fn activate(&mut self, id: u32) -> Option<PeerId> {
        let slot = self.model.activate(id, self.now, ACTIVATE_EVICT_IDLE_MS)?;
        Some(slot as u8)
    }
}

fn disco_world() -> (DiscoSide, Vec<(Key32, Key32)>) {
    let kp = |s: u8| {
        let sec = Key32([s; 32]);
        let public = x25519::public(&sec);
        (sec, public)
    };
    let (me_sec, _me_pub) = kp(0x71);
    let peers: Vec<(Key32, Key32)> = (1..=14u8).map(kp).collect();
    let directory = peers.iter().enumerate().map(|(i, (_, p))| (p.clone(), 100 + i as u32)).collect();
    (DiscoSide { model: Model::default(), my_secret: me_sec, directory, now: 100_000, opens: 0 }, peers)
}

fn packet_from(sec: &Key32, public: &Key32, to_public: &Key32, forged_with: Option<&Key32>) -> Vec<u8> {
    let signer = forged_with.unwrap_or(sec);
    let shared = nacl::precompute(signer, to_public).unwrap();
    let mut out = [0u8; 200];
    let n = envelope::seal_pong(&mut out, public, &shared, &[3u8; 24], &Pong { txid: [1; 12], src: Ep::NONE }).unwrap();
    out[..n].to_vec()
}

#[test]
fn disco_admission() {
    let (mut side, peers) = disco_world();
    let me_pub = x25519::public(&side.my_secret);
    // nobody signed it: a stranger's key is dropped without a box open; a directory key with a forged box costs one open and buys nothing
    let stranger = Key32([0xee; 32]);
    let mut p = packet_from(&Key32([9; 32]), &stranger, &me_pub, None);
    assert_eq!(process(&mut p, &mut side).unwrap_err(), RxOutcome::UnknownSender);
    assert_eq!(side.opens, 0);
    let mut p = packet_from(&peers[11].0, &peers[11].1, &me_pub, Some(&Key32([0x55; 32])));
    assert_eq!(process(&mut p, &mut side).unwrap_err(), RxOutcome::CandidateFailed);
    assert_eq!((side.opens, side.model.resident()), (1, 0));
    // the real peer's box opens: activated, and an ordinary (not trial) peer
    let mut p = packet_from(&peers[11].0, &peers[11].1, &me_pub, None);
    let rx = process(&mut p, &mut side).unwrap();
    assert!(rx.activated);
    assert_eq!(side.model.resident(), 1);
    assert!(!side.model.peers[usize::from(rx.peer)].unwrap().unconfirmed);
    // resident now: no directory lookup, no new candidate open, no token
    let before = side.model.gate.refused.get();
    let mut p = packet_from(&peers[11].0, &peers[11].1, &me_pub, None);
    let rx = process(&mut p, &mut side).unwrap();
    assert!(!rx.activated);
    assert_eq!((side.opens, side.model.gate.refused.get()), (2, before));
}

#[test]
fn forged_disco_flood_reaches_crypto_three_times() {
    let (mut side, peers) = disco_world();
    let me_pub = x25519::public(&side.my_secret);
    let mut failed = 0;
    for (sec, public) in peers.iter().take(10) {
        let mut p = packet_from(sec, public, &me_pub, Some(&Key32([0x55; 32])));
        match process(&mut p, &mut side) {
            Err(RxOutcome::CandidateFailed) => failed += 1,
            Err(RxOutcome::UnknownSender) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(side.opens, 3, "only the burst reaches the box");
    assert_eq!(failed, 3);
    assert_eq!(side.model.resident(), 0);
}

#[test]
fn authentic_disco_but_no_slot() {
    let (mut side, peers) = disco_world();
    side.model.fill(1000, 8, 99_000);
    let me_pub = x25519::public(&side.my_secret);
    let mut p = packet_from(&peers[0].0, &peers[0].1, &me_pub, None);
    assert_eq!(process(&mut p, &mut side).unwrap_err(), RxOutcome::NoSlot);
    assert_eq!((side.model.resident(), side.model.removals), (8, 0));
}

/// `test_peer_policy.c` `simulate()`: two memberships sharing a pool of 12, random traffic. No peer is evicted inside its window, evictions never
/// exceed activations, and dense traffic is refused instead.
fn simulate(step_ms: u64, expect_rejections: bool) {
    const CAP: usize = 12;
    const M: usize = 2;
    const PEERS: usize = 20;
    let mut peer = [[(0u64, false); PEERS]; M];
    let (mut used, mut evictions, mut rejected, mut activations, mut seed) = (0usize, 0u32, 0u32, 0u32, 7u32);
    let mut now = 100_000u64;
    for _ in 0..20_000 {
        now += step_ms;
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let m = ((seed >> 16) as usize) % M;
        let mut p = ((seed >> 8) as usize) % PEERS;
        if m == 1 && p >= 4 {
            p %= 4;
        }
        if peer[m][p].1 {
            peer[m][p].0 = now;
            continue;
        }
        if used >= CAP {
            let mut c = Vec::new();
            let mut who = Vec::new();
            for (a, row) in peer.iter().enumerate() {
                let slots = row.iter().filter(|x| x.1).count() as u32;
                for (b, x) in row.iter().enumerate().filter(|(_, x)| x.1) {
                    c.push(VictimCandidate { last_used_ms: x.0, owner_slots: slots, pinned: false, trial: false });
                    who.push((a, b));
                }
            }
            match pick_victim(&c, now, 10_000) {
                None => {
                    rejected += 1;
                    continue;
                }
                Some(v) => {
                    let (a, b) = who[v];
                    assert!(now - peer[a][b].0 >= 10_000, "evicted recent traffic");
                    peer[a][b].1 = false;
                    used -= 1;
                    evictions += 1;
                }
            }
        }
        peer[m][p] = (now, true);
        used += 1;
        activations += 1;
        assert!(used <= CAP);
    }
    assert!(evictions <= activations && evictions > 0);
    if expect_rejections {
        assert!(rejected > 0);
    } else {
        assert!(evictions > 10);
    }
}

#[test]
fn pool_simulation_sparse_traffic_rotates_peers() {
    simulate(2_000, false);
}

#[test]
fn pool_simulation_dense_traffic_is_refused_not_evicted() {
    simulate(50, true);
}
