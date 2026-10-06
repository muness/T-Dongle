//! Property tests: message and envelope round trips, tamper rejection, STUN round trips, and state-machine invariants under random event sequences.

use proptest::prelude::*;
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_disco::envelope::{self, PeerId, PeerResolver, RxCounters, RxOutcome, process};
use tdongle_tailnet_disco::msg::{self, Message, Ping, Pong};
use tdongle_tailnet_disco::path::*;
use tdongle_tailnet_disco::policy::*;
use tdongle_tailnet_disco::{Ep, fuzz, stun};
use tdongle_tailnet_types::Key32;

fn arb_ep() -> impl Strategy<Value = Ep> {
    prop_oneof![(any::<[u8; 4]>(), any::<u16>()).prop_map(|(o, p)| Ep::v4(o, p)), (any::<[u8; 16]>(), any::<u16>()).prop_map(|(o, p)| Ep::v6(o, p)),]
}

struct Fixed(Key32, Key32);
impl PeerResolver for Fixed {
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

fn keys() -> (Key32, Key32, Key32, Key32) {
    let (a, b) = (Key32([0x12; 32]), Key32([0x34; 32]));
    let (ap, bp) = (x25519::public(&a), x25519::public(&b));
    let ab = nacl::precompute(&a, &bp).unwrap();
    let ba = nacl::precompute(&b, &ap).unwrap();
    (ap, bp, ab, ba)
}

proptest! {
    #[test]
    fn ping_round_trip(txid in any::<[u8; 12]>(), key in proptest::option::of(any::<[u8; 32]>()), padding in 0usize..300) {
        let p = Ping { txid, node_key: key.as_ref(), padding };
        let mut out = [0u8; 400];
        let n = msg::encode_ping(&mut out, &p).unwrap();
        prop_assert_eq!(n, msg::ping_len(&p));
        let parsed = msg::parse(&out[..n]).unwrap();
        // an all-zero key is not a key: encoding omits it and parsing reads what is left as the padding that was asked for
        let zero = key.is_some_and(|k| k == [0u8; 32]);
        let expect = if zero { Ping { txid, node_key: None, padding } } else { p };
        prop_assert_eq!(parsed, Message::Ping(expect));
    }

    #[test]
    fn pong_and_cmm_round_trip(txid in any::<[u8; 12]>(), src in arb_ep(), eps in proptest::collection::vec(arb_ep(), 0..40)) {
        let mut out = [0u8; 1024];
        let n = msg::encode_pong(&mut out, &Pong { txid, src }).unwrap();
        prop_assert_eq!(msg::parse(&out[..n]).unwrap(), Message::Pong(Pong { txid, src }));
        let n = msg::encode_call_me_maybe(&mut out, &eps).unwrap();
        match msg::parse(&out[..n]).unwrap() {
            Message::CallMeMaybe { endpoints, lax } => {
                prop_assert!(!lax);
                prop_assert!(endpoints.iter().eq(eps.iter().copied()));
            }
            m => prop_assert!(false, "{m:?}"),
        }
    }

    #[test]
    fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        fuzz::message(&bytes);
    }

    #[test]
    fn envelope_round_trip_and_any_bit_flip_is_refused(
        txid in any::<[u8; 12]>(), nonce in any::<[u8; 24]>(), eps in proptest::collection::vec(arb_ep(), 0..10),
        flip in any::<prop::sample::Index>(), bit in 0u8..8,
    ) {
        let (ap, _bp, ab, ba) = keys();
        let mut buf = [0u8; 512];
        let n = envelope::seal_call_me_maybe(&mut buf, &ap, &ab, &nonce, &eps).unwrap();
        let _ = txid;
        let good = buf[..n].to_vec();
        let mut r = Fixed(ap.clone(), ba.clone());
        let mut p = good.clone();
        let rx = process(&mut p, &mut r).unwrap();
        match rx.message {
            Message::CallMeMaybe { endpoints, .. } => prop_assert_eq!(endpoints.len(), eps.len()),
            m => prop_assert!(false, "{m:?}"),
        }
        let mut bad = good.clone();
        let i = flip.index(bad.len());
        bad[i] ^= 1 << bit;
        prop_assert!(process(&mut bad, &mut r).is_err());
        // truncation
        let mut cut = good.clone();
        cut.truncate(i);
        prop_assert!(process(&mut cut, &mut r).is_err());
    }

    #[test]
    fn receive_counts_every_datagram_once(pkts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 1..40)) {
        let (ap, _bp, _ab, ba) = keys();
        let mut c = RxCounters::new();
        let mut r = Fixed(ap, ba);
        for mut p in pkts.clone() {
            let res = process(&mut p, &mut r);
            c.record_result(&res);
        }
        prop_assert_eq!(c.total(), pkts.len() as u64);
    }

    #[test]
    fn stun_response_round_trip(txid in any::<[u8; 12]>(), ep in arb_ep()) {
        let mut b = [0u8; 64];
        let n = stun::build_response(&txid, &ep, &mut b).unwrap();
        let r = stun::parse_response(&b[..n]).unwrap();
        prop_assert_eq!(r.txid, txid);
        prop_assert_eq!(r.mapped, ep);
        prop_assert!(r.xor);
    }

    #[test]
    fn stun_request_round_trip(txid in any::<[u8; 12]>()) {
        let mut b = [0u8; stun::REQUEST_LEN];
        stun::build_request(&txid, &mut b);
        prop_assert!(stun::is_stun(&b));
        prop_assert_eq!(stun::parse_binding_request(&b), Ok(txid));
        prop_assert_eq!(stun::check_fingerprint(&b), stun::Fingerprint::Valid);
        // a request is not a response
        prop_assert!(stun::parse_response(&b).is_err());
    }

    #[test]
    fn stun_parse_never_panics_and_agrees_with_itself(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        fuzz::stun_response(&bytes);
        fuzz::stun_request(&bytes);
        let mut with_header = vec![0x01u8, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        with_header.extend_from_slice(&bytes);
        let l = bytes.len().min(0xffff) as u16;
        with_header[2..4].copy_from_slice(&l.to_be_bytes());
        fuzz::stun_response(&with_header);
    }

    #[test]
    fn path_machine_invariants(script in proptest::collection::vec(any::<u8>(), 0..600)) {
        fuzz::path(&script);
    }

    #[test]
    fn probe_table_matches_a_model(ops in proptest::collection::vec((0u8..4, 0u8..5, 0u8..6, 0u64..9000), 0..200)) {
        const N: usize = 5;
        let mut t = ProbeTable::<N>::new();
        let mut model: Vec<(u8, u8, u64)> = vec![]; // (txid byte, peer, sent)
        let mut now = 0u64;
        for (op, peer, tx, dt) in ops {
            now += dt;
            let txid = [tx; 12];
            match op {
                0 => {
                    // register only fresh ids, as random 96-bit ids are in practice
                    if model.iter().all(|m| m.0 != tx) {
                        let ok = t.register(txid, peer, PingKind::Discovery, now);
                        prop_assert_eq!(ok, model.len() < N);
                        if ok { model.push((tx, peer, now)); }
                    }
                }
                1 => {
                    let r = t.take(&txid, peer, now, 5000);
                    match model.iter().position(|m| m.0 == tx) {
                        None => prop_assert_eq!(r, Take::NotFound),
                        Some(i) if model[i].1 != peer => prop_assert_eq!(r, Take::WrongPeer),
                        Some(i) => {
                            let age = now - model[i].2;
                            if age > 5000 { prop_assert_eq!(r, Take::Late) } else { let hit = matches!(r, Take::Hit { rtt_ms, .. } if u64::from(rtt_ms) == age); prop_assert!(hit) }
                            model.remove(i);
                        }
                    }
                }
                2 => {
                    let n = t.expire(now, 5000);
                    let before = model.len();
                    model.retain(|m| now - m.2 <= 5000);
                    prop_assert_eq!(n, before - model.len());
                }
                _ => {
                    t.forget_peer(peer);
                    model.retain(|m| m.1 != peer);
                }
            }
            prop_assert_eq!(t.len(), model.len());
            prop_assert!(t.len() <= N);
        }
    }

    #[test]
    fn pick_victim_is_the_eligible_lru(
        c in proptest::collection::vec((0u64..200_000, 0u32..6, any::<bool>(), any::<bool>()), 0..20), idle in 0u64..70_000,
    ) {
        let v: Vec<VictimCandidate> = c.iter().map(|&(l, o, p, t)| VictimCandidate { last_used_ms: l, owner_slots: o, pinned: p, trial: t }).collect();
        let now = 100_000u64;
        let eligible = |x: &VictimCandidate| !x.pinned && !x.trial && now.saturating_sub(x.last_used_ms) >= idle;
        match pick_victim(&v, now, idle) {
            None => prop_assert!(!v.iter().any(eligible)),
            Some(i) => {
                prop_assert!(eligible(&v[i]));
                for (j, x) in v.iter().enumerate().filter(|(_, x)| eligible(x)) {
                    prop_assert!(v[i].last_used_ms < x.last_used_ms || (v[i].last_used_ms == x.last_used_ms && (v[i].owner_slots > x.owner_slots || (v[i].owner_slots == x.owner_slots && i <= j))));
                }
            }
        }
    }

    #[test]
    fn trial_gate_never_exceeds_its_bounds(ops in proptest::collection::vec((0u8..4, 0u64..4000, any::<bool>()), 0..300)) {
        let mut g = TrialGate::new();
        let mut now = 1_000u64;
        let mut tokens_spent_in_window = vec![];
        for (op, dt, flag) in ops {
            now += dt;
            match op {
                0 => { if g.token(now) { tokens_spent_in_window.push(now); } }
                1 => { if g.open(now) { g.start(3, now); } }
                2 => {
                    let r = g.poll(now, |_| if flag { TrialPeer::Authenticated } else { TrialPeer::Waiting });
                    if let TrialPoll::Expired(_) = r { prop_assert!(!g.open(now)); }
                }
                _ => { g.poll(now, |_| TrialPeer::Gone); }
            }
            prop_assert!(g.pending_slot().is_none_or(|s| s == 3));
        }
        // the bucket holds at most a burst and gives one back a second: over the whole run at most burst + elapsed seconds tokens were spent
        let elapsed = (now - 1_000) / TRIAL_TOKEN_REFILL_MS;
        prop_assert!(tokens_spent_in_window.len() as u64 <= u64::from(TRIAL_TOKEN_BURST) + elapsed);
    }

    #[test]
    fn unknown_outcomes_are_exhaustive(b in any::<u8>()) {
        let _ = b;
        for (i, o) in RxOutcome::ALL.iter().enumerate() {
            prop_assert_eq!(*o as usize, i);
        }
    }
}
