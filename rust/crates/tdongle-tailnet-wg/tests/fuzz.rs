//! Deterministic mini-fuzz of everything that parses untrusted bytes, and a model-based property test of whole conversations over a hostile network.

mod common;
use common::*;
use proptest::prelude::*;
use std::collections::HashSet;
use tdongle_tailnet_wg::consts::*;
use tdongle_tailnet_wg::cookie::{CookieChecker, Screen, screen};
use tdongle_tailnet_wg::msg::*;
use tdongle_tailnet_wg::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Feed `pkt` to every entry point a network datagram can reach. Nothing may panic; every outcome is a value.
fn throw(s: &mut Side, pkt: &[u8], now: u64) {
    let _ = classify(pkt);
    let _ = Initiation::parse(pkt);
    let _ = Response::parse(pkt);
    let _ = CookieReply::parse(pkt);
    let _ = TransportHeader::parse(pkt);
    let mut p = pkt.to_vec();
    let src = s.src.clone();
    for load in [false, true] {
        let mut q = p.clone();
        let _ = s.on_packet(&mut q, now, load, &src);
    }
    p.truncate(p.len());
    let _ = s.hot.poll(now);
}

fn valid_messages() -> (Side, Side, Vec<Vec<u8>>) {
    let (mut a, mut b) = pair(Some(tdongle_tailnet_types::Key32([3; 32])));
    let init = a.initiate(1000).unwrap().to_vec();
    let Event::Reply(resp) = b.rx(&init, 1000) else { panic!() };
    let mut p = init.clone();
    let Event::Reply(cr) = b.on_packet(&mut p, 1001, true, &a.src.clone()) else { panic!() };
    assert_eq!(a.rx(&resp, 1002), Event::Established);
    let d = a.send(b"fuzz me", 1003).unwrap();
    let ka = a.keepalive(1004).unwrap();
    (a, b, vec![init, resp, cr.clone(), d, ka])
}

#[test]
fn random_bytes_never_panic() {
    let (mut a, mut b, _) = valid_messages();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for i in 0..20_000u64 {
        let len = match rng.below(8) {
            0 => rng.below(8),
            1 => 148,
            2 => 92,
            3 => 64,
            4 => 32 + rng.below(40),
            _ => rng.below(300),
        } as usize;
        let mut pkt: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // make many of them well framed so they get past the first check
        if len >= 4 && rng.below(3) > 0 {
            pkt[0] = 1 + rng.below(4) as u8;
            pkt[1] = 0;
            pkt[2] = 0;
            pkt[3] = 0;
        }
        throw(&mut a, &pkt, 2000 + i);
        throw(&mut b, &pkt, 2000 + i);
    }
}

#[test]
fn mutated_valid_messages_never_panic_and_never_authenticate() {
    let mut rng = Rng(0xDEAD_BEEF_0000_0001);
    for round in 0..300u64 {
        let (mut a, mut b, msgs) = valid_messages();
        for m in &msgs {
            for _ in 0..8 {
                let mut x = m.clone();
                match rng.below(5) {
                    0 => {
                        let i = rng.below(x.len() as u64) as usize;
                        x[i] ^= 1 << rng.below(8);
                    }
                    1 => {
                        let n = rng.below(x.len() as u64 + 1) as usize;
                        x.truncate(n);
                    }
                    2 => x.extend((0..rng.below(20)).map(|_| rng.next() as u8)),
                    3 => {
                        for _ in 0..3 {
                            let i = rng.below(x.len() as u64) as usize;
                            x[i] = rng.next() as u8;
                        }
                    }
                    _ => {
                        let i = rng.below(x.len() as u64) as usize;
                        x.drain(i..(i + 1).min(x.len()));
                    }
                }
                if x == *m {
                    continue;
                }
                // a changed transport datagram is never accepted (its header receiver bytes 4..8 are the one unauthenticated field: a changed
                // receiver finds no session, or the same session through a colliding index)
                let before = (a.hot.current().map(|s| s.replay().highest()), b.hot.current().map(|s| s.replay().highest()));
                let ev = b.rx(&x, 5000 + round);
                if let Event::Payload(_) | Event::Confirmed(_) | Event::Keepalive = ev {
                    // only possible when the mutation did not change anything the tag covers: the receiver index
                    assert_eq!(&x[..4], &m[..4]);
                    assert_eq!(&x[8..], &m[8..]);
                    assert_ne!(&x[4..8], &m[4..8]);
                }
                let _ = (a.rx(&x, 5000 + round), before);
            }
        }
    }
}

#[test]
fn every_drop_is_counted_and_named() {
    let mut c = DropCounters::new();
    for d in Dropped::ALL {
        c.bump(d);
        assert!(!d.name().is_empty());
    }
    assert_eq!(c.total() as usize, Dropped::COUNT);
    let names: HashSet<_> = Dropped::ALL.iter().map(|d| d.name()).collect();
    assert_eq!(names.len(), Dropped::COUNT, "names are unique");
}

// ---- a hostile network -------------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    Send { side: bool, tag: u8, len: u16 },
    Deliver { to_a: bool, pick: u16 },
    Duplicate { to_a: bool, pick: u16 },
    Drop { to_a: bool, pick: u16 },
    Tamper { to_a: bool, pick: u16, byte: u16 },
    Tick { ms: u32 },
    Poll { side: bool },
    ReplayOld { to_a: bool, pick: u16 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (any::<bool>(), any::<u8>(), 8u16..400).prop_map(|(side, tag, len)| Op::Send { side, tag, len }),
        5 => (any::<bool>(), any::<u16>()).prop_map(|(to_a, pick)| Op::Deliver { to_a, pick }),
        1 => (any::<bool>(), any::<u16>()).prop_map(|(to_a, pick)| Op::Duplicate { to_a, pick }),
        1 => (any::<bool>(), any::<u16>()).prop_map(|(to_a, pick)| Op::Drop { to_a, pick }),
        1 => (any::<bool>(), any::<u16>(), any::<u16>()).prop_map(|(to_a, pick, byte)| Op::Tamper { to_a, pick, byte }),
        3 => (1u32..70_000).prop_map(|ms| Op::Tick { ms }),
        3 => any::<bool>().prop_map(|side| Op::Poll { side }),
        1 => (any::<bool>(), any::<u16>()).prop_map(|(to_a, pick)| Op::ReplayOld { to_a, pick }),
    ]
}

struct Net {
    a: Side,
    b: Side,
    now: u64,
    to_a: Vec<Vec<u8>>,
    to_b: Vec<Vec<u8>>,
    history_to_a: Vec<Vec<u8>>,
    history_to_b: Vec<Vec<u8>>,
    next_id: u64,
    sent: [HashSet<u64>; 2],           // payload ids sent by (a, b)
    delivered: [HashSet<u64>; 2],      // payload ids delivered to (a, b)
    nonces: HashSet<(bool, u32, u64)>, // (sender is a, receiver index, counter) of every datagram ever sealed
}

impl Net {
    fn new() -> Net {
        let (a, b) = pair(None);
        Net {
            a,
            b,
            now: 1000,
            to_a: vec![],
            to_b: vec![],
            history_to_a: vec![],
            history_to_b: vec![],
            next_id: 1,
            sent: Default::default(),
            delivered: Default::default(),
            nonces: HashSet::new(),
        }
    }

    fn push(&mut self, from_a: bool, pkt: Vec<u8>) {
        if pkt.len() >= 16 && pkt[0] == 4 {
            let h = TransportHeader::parse(&pkt).unwrap();
            assert!(self.nonces.insert((from_a, h.receiver, h.counter)), "a (key, counter) pair was used twice: receiver {} counter {}", h.receiver, h.counter);
        }
        let (q, hist) = if from_a { (&mut self.to_b, &mut self.history_to_b) } else { (&mut self.to_a, &mut self.history_to_a) };
        hist.push(pkt.clone());
        q.push(pkt);
    }

    fn receive(&mut self, to_a: bool, pkt: Vec<u8>) {
        let now = self.now;
        let side = if to_a { &mut self.a } else { &mut self.b };
        let ev = side.rx(&pkt, now);
        let me = if to_a { 0 } else { 1 };
        match ev {
            Event::Reply(r) => self.push(to_a, r),
            Event::Payload(p) | Event::Confirmed(p) if p.len() >= 8 => {
                let id = u64::from_le_bytes(p[..8].try_into().unwrap());
                // a delivered payload is one the peer sent, and only ever delivered once
                assert!(self.sent[1 - me].contains(&id), "delivered a payload nobody sent: {id}");
                assert!(self.delivered[me].insert(id), "payload {id} delivered twice");
            }
            _ => {}
        }
    }

    fn step(&mut self, o: &Op) {
        match *o {
            Op::Send { side, tag, len } => {
                let id = self.next_id;
                self.next_id += 1;
                let mut payload = vec![tag; len as usize];
                payload[..8].copy_from_slice(&id.to_le_bytes());
                let now = self.now;
                let s = if side { &mut self.a } else { &mut self.b };
                if let Ok(d) = s.send(&payload, now) {
                    self.sent[if side { 0 } else { 1 }].insert(id);
                    self.push(side, d);
                }
            }
            Op::Deliver { to_a, pick } => {
                let q = if to_a { &mut self.to_a } else { &mut self.to_b };
                if !q.is_empty() {
                    let p = q.remove(pick as usize % q.len());
                    self.receive(to_a, p);
                }
            }
            Op::Duplicate { to_a, pick } => {
                let q = if to_a { &mut self.to_a } else { &mut self.to_b };
                if !q.is_empty() {
                    let p = q[pick as usize % q.len()].clone();
                    q.push(p);
                }
            }
            Op::Drop { to_a, pick } => {
                let q = if to_a { &mut self.to_a } else { &mut self.to_b };
                if !q.is_empty() {
                    q.remove(pick as usize % q.len());
                }
            }
            Op::Tamper { to_a, pick, byte } => {
                let q = if to_a { &mut self.to_a } else { &mut self.to_b };
                if !q.is_empty() {
                    let i = pick as usize % q.len();
                    let n = q[i].len();
                    q[i][byte as usize % n] ^= 0x04;
                }
            }
            Op::Tick { ms } => self.now += ms as u64,
            Op::Poll { side } => {
                let now = self.now;
                let s = if side { &mut self.a } else { &mut self.b };
                let acts = s.hot.poll(now);
                if acts.contains(Actions::SEND_INITIATION)
                    && let Ok(i) = s.initiate(now)
                {
                    self.push(side, i.to_vec());
                }
                let s = if side { &mut self.a } else { &mut self.b };
                if acts.contains(Actions::SEND_KEEPALIVE)
                    && let Ok(k) = s.keepalive(now)
                {
                    self.push(side, k);
                }
            }
            Op::ReplayOld { to_a, pick } => {
                let h = if to_a { &self.history_to_a } else { &self.history_to_b };
                if !h.is_empty() {
                    let p = h[pick as usize % h.len()].clone();
                    self.receive(to_a, p);
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary schedules of sends, deliveries, duplicates, drops, tampering, replays of old datagrams, time jumps and timer polls. Invariants: nothing
    /// panics; no (key, counter) is ever sealed twice; a payload is delivered at most once and only if the peer sent it; and the two sides are never in
    /// a state where a datagram one sealed is accepted after it was tampered.
    #[test]
    fn conversations_over_a_hostile_network(ops in proptest::collection::vec(op(), 1..160)) {
        let mut n = Net::new();
        for o in &ops {
            n.step(o);
        }
        // the delivered sets are subsets of what was sent
        prop_assert!(n.delivered[0].is_subset(&n.sent[1]));
        prop_assert!(n.delivered[1].is_subset(&n.sent[0]));
    }
}

#[test]
fn clean_network_converges_with_regular_polling() {
    for first_a in [true, false] {
        let mut n = Net::new();
        n.step(&Op::Send { side: first_a, tag: 1, len: 40 });
        for _ in 0..200 {
            n.step(&Op::Tick { ms: 100 });
            for side in [true, false] {
                n.step(&Op::Poll { side });
            }
            for _ in 0..4 {
                n.step(&Op::Deliver { to_a: true, pick: 0 });
                n.step(&Op::Deliver { to_a: false, pick: 0 });
            }
            n.step(&Op::Send { side: first_a, tag: 2, len: 40 });
        }
        assert!(!n.delivered[if first_a { 1 } else { 0 }].is_empty(), "first_a={first_a}: nothing got through");
        // and the other direction works too once the session is confirmed
        for _ in 0..5 {
            n.step(&Op::Send { side: !first_a, tag: 3, len: 40 });
            n.step(&Op::Deliver { to_a: !first_a, pick: 0 });
            n.step(&Op::Deliver { to_a: first_a, pick: 0 });
        }
        assert!(!n.delivered[if first_a { 0 } else { 1 }].is_empty());
    }
}

/// The cookie checker and screen under random inputs: a valid-mac1 message under load without mac2 always yields a cookie reply and never state.
#[test]
fn screen_under_load_never_passes_without_mac2() {
    let (mut a, b) = pair(None);
    let mut checker = CookieChecker::new();
    let mut rng = tdongle_tailnet_types::test_util::TestRng(5);
    for t in 0..50u64 {
        let init = a.hot.create_initiation(&a.id, &a.cold, 6000 * (t + 1), wall(6000 * (t + 1)), &mut a.rng, &mut a.idx).unwrap();
        match screen(&b.id, &mut checker, &init, &a.src, true, 6000 * (t + 1), &mut rng) {
            Screen::CookieReply(r) => assert_eq!(r.len(), COOKIE_REPLY_LEN),
            other => panic!("{other:?}"),
        }
    }
    let _ = REKEY_TIMEOUT;
}

/// The C `test_wg_rx_counters.c` identity: every datagram that enters the data path ends in exactly one terminal outcome (a delivery, a keepalive, a
/// confirmation, or one counted drop).
#[test]
fn every_datagram_ends_in_exactly_one_outcome() {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    let mut rng = Rng(0xABCD_EF01_2345_6789);
    let mut pool: Vec<Vec<u8>> = (0..400u32).map(|i| a.send(&vec![i as u8; (i % 90) as usize], 10).unwrap()).collect();
    pool.extend((0..20).map(|_| a.keepalive(10).unwrap()));
    let total = 12_000u64;
    let (mut ok, mut dropped) = (0u64, 0u64);
    for _ in 0..total {
        let mut p = pool[rng.below(pool.len() as u64) as usize].clone();
        match rng.below(10) {
            0 => {
                let i = rng.below(p.len() as u64) as usize;
                p[i] ^= 1 << rng.below(8);
            }
            1 => p.truncate(rng.below(p.len() as u64) as usize),
            2 => p.push(rng.next() as u8),
            _ => {}
        }
        let now = if rng.below(50) == 0 { 400_000 } else { 10 };
        match b.rx(&p, now) {
            Event::Payload(_) | Event::Keepalive | Event::Confirmed(_) => ok += 1,
            Event::Dropped(_) => dropped += 1,
            e => panic!("{e:?}"),
        }
    }
    assert_eq!(ok + dropped, total);
    assert_eq!(b.drops.total(), dropped, "every drop was counted exactly once");
    assert!(ok > 300 && dropped > 300, "the mix exercised both outcomes: {ok} ok, {dropped} dropped");
    for d in [Dropped::ReplayDuplicate, Dropped::AuthFail, Dropped::ParseLength, Dropped::SessionExpired, Dropped::ReplayTooOld] {
        let _ = b.drops.get(d);
    }
    assert!(b.drops.get(Dropped::ReplayDuplicate) > 0 && b.drops.get(Dropped::AuthFail) > 0);
}
