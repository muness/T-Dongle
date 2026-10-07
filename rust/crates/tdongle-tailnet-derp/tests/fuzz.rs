//! Property tests and a deterministic mini-fuzz: arbitrary and mutated input to the frame reader and the link must never panic, never exceed the
//! bounds, and keep the link's own bookkeeping consistent (one send outstanding, token and transport balanced).

mod common;

use common::{Owned, raw_frame, recv_frame, stamped};
use proptest::prelude::*;
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_derp::frame::{FrameType, Poll, encode_frame};
use tdongle_tailnet_derp::{Action, Event, FrameReader, Link, MAGIC, MAX_FRAME, MAX_RECV_BODY, State, Target, Timing};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;

fn frames_strategy() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    proptest::collection::vec(
        (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..300)).prop_map(|(t, mut b)| {
            if t == FrameType::RECV_PACKET.0 && b.len() <= 32 {
                b.resize(33, 0);
            }
            (t, b)
        }),
        0..12,
    )
}

fn encode_all(frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (t, b) in frames {
        v.extend_from_slice(&raw_frame(FrameType(*t), b));
    }
    v
}

proptest! {
    /// Any cut of a valid stream yields exactly the frames that were written, in order.
    #[test]
    fn reader_any_chunking_yields_the_same_frames(frames in frames_strategy(), cuts in proptest::collection::vec(1usize..64, 1..40)) {
        let data = encode_all(&frames);
        let mut r = FrameReader::new();
        let mut got: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut at = 0;
        let mut ci = 0;
        while at < data.len() {
            let end = (at + cuts[ci % cuts.len()]).min(data.len());
            ci += 1;
            r.feed_all(&data[at..end], |t, b| got.push((t.0, b.to_vec()))).unwrap();
            at = end;
        }
        prop_assert_eq!(got, frames);
        prop_assert!(!r.in_frame());
    }

    /// Arbitrary bytes: no panic, consumption within bounds, an error is sticky, a frame never exceeds the buffer.
    #[test]
    fn reader_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..3000), cuts in proptest::collection::vec(1usize..200, 1..20)) {
        let mut r = FrameReader::new();
        let mut at = 0;
        let mut ci = 0;
        let mut failed = false;
        while at < data.len() {
            let end = (at + cuts[ci % cuts.len()]).min(data.len());
            ci += 1;
            let mut chunk = &data[at..end];
            while !chunk.is_empty() {
                let (n, p) = r.feed(chunk);
                prop_assert!(n <= chunk.len());
                match p {
                    Poll::NeedMore => prop_assert_eq!(n, chunk.len()),
                    Poll::Frame(info) => {
                        prop_assert!(info.len <= MAX_RECV_BODY);
                        if info.ty != FrameType::RECV_PACKET {
                            prop_assert!(info.len <= MAX_FRAME);
                        }
                        prop_assert_eq!(r.body().len(), info.len);
                        prop_assert!(!failed);
                    }
                    Poll::Error(_) => {
                        failed = true;
                        prop_assert_eq!(r.feed(&[0, 1, 2]).0, 0);
                    }
                }
                if failed { break; }
                chunk = &chunk[n..];
            }
            if failed { break; }
            at = end;
        }
    }

    /// Whatever bytes follow a good handshake, the link ends Ready or redialling, with its bookkeeping intact.
    #[test]
    fn link_survives_arbitrary_stream_after_handshake(data in proptest::collection::vec(any::<u8>(), 0..2500), cuts in proptest::collection::vec(1usize..300, 1..10)) {
        let mut h = Harness::new(1);
        h.handshake();
        let mut at = 0;
        let mut ci = 0;
        while at < data.len() {
            let end = (at + cuts[ci % cuts.len()]).min(data.len());
            ci += 1;
            h.ev(Event::Bytes(&data[at..end]));
            h.check();
            at = end;
        }
        prop_assert!(matches!(h.link.state(), State::Ready | State::Waiting | State::Token | State::Dns));
    }

    /// Random event sequences from any starting point.
    #[test]
    fn link_random_events(seed in any::<u64>()) {
        let mut h = Harness::new(seed);
        h.random_run(400);
    }
}

/// A link plus a bookkeeping checker over every action it emits.
struct Harness {
    link: Link<2048>,
    now: u64,
    rng: TestRng,
    r: TestRng,
    server_secret: Key32,
    sends_outstanding: u32,
    dials: i64,
    token: i64,
    server_pub: Key32,
}

impl Harness {
    fn new(seed: u64) -> Harness {
        let secret = Key32(core::array::from_fn(|i| (seed as u8).wrapping_add(i as u8)));
        let server_secret = Key32(core::array::from_fn(|i| 0x40u8.wrapping_add(i as u8)));
        Harness {
            link: Link::new(secret, Target::new(1, "derp.test", 443), Timing::DEFAULT),
            now: 10_000,
            rng: TestRng(seed | 1),
            r: TestRng(seed ^ 0x9e37_79b9_7f4a_7c15 | 1),
            server_pub: x25519::public(&server_secret),
            server_secret,
            sends_outstanding: 0,
            dials: 0,
            token: 0,
        }
    }

    fn rand(&mut self, n: u64) -> u64 {
        use tdongle_tailnet_types::Entropy;
        let mut b = [0u8; 8];
        self.r.fill(&mut b);
        u64::from_le_bytes(b) % n.max(1)
    }

    fn ev(&mut self, ev: Event<'_>) -> Vec<Owned> {
        let mut out: Vec<Owned> = Vec::new();
        {
            let mut sink = |a: Action<'_>| out.push(Owned::from(a));
            self.link.handle(self.now, ev, &mut self.rng, &mut sink);
        }
        for o in &out {
            match o {
                Owned::Send(b) => {
                    self.sends_outstanding += 1;
                    assert!(b.len() >= 5 && b.len() <= 5 + 256 + 1600, "send size {}", b.len());
                }
                Owned::Dial => self.dials += 1,
                Owned::Close => self.dials -= 1,
                Owned::ReleaseToken => self.token -= 1,
                Owned::Deliver { payload, .. } => assert!(payload.len() <= MAX_RECV_BODY - 32),
                _ => {}
            }
        }
        if matches!(ev, Event::TxDone) {
            self.sends_outstanding = self.sends_outstanding.saturating_sub(1);
        }
        out
    }

    /// The invariants that must hold after every call.
    fn check(&mut self) {
        // at most one write outstanding as seen by the driver; a failure forgets it
        if !self.link.state().is_connecting() && self.link.state() != State::Ready {
            self.sends_outstanding = 0;
        }
        assert!(self.sends_outstanding <= 1, "two sends outstanding in {:?}", self.link.state());
        assert!((0..=1).contains(&self.dials), "dials {}", self.dials);
        assert!(self.token <= 1);
        if let Some(d) = self.link.next_deadline_ms(self.now) {
            assert!(d <= 120_000, "deadline {d} in {:?}", self.link.state());
        }
    }

    /// Every grant is one token taken; the link gives it back at ready, on teardown, or at once when it did not want it.
    fn grant(&mut self) {
        self.token += 1;
        self.ev(Event::TokenGranted);
    }

    fn handshake(&mut self) {
        self.ev(Event::ClockValid(true));
        self.ev(Event::Connect);
        self.grant();
        self.ev(Event::Dns(true));
        self.ev(Event::Connected(true));
        self.ev(Event::TlsDone(true));
        self.ev(Event::TxDone);
        let mut g = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        let mut body = MAGIC.to_vec();
        body.extend_from_slice(&self.server_pub.0);
        g.extend_from_slice(&raw_frame(FrameType::SERVER_KEY, &body));
        self.ev(Event::Bytes(&g));
        self.ev(Event::TxDone);
        let me = self.link.public_key();
        let nonce = [3u8; 24];
        let mut sb = vec![0u8; 24 + 16 + 2];
        sb[..24].copy_from_slice(&nonce);
        sb[40..].copy_from_slice(b"{}");
        nacl::box_seal(&self.server_secret, &me, &nonce, &mut sb[24..]).unwrap();
        self.ev(Event::Bytes(&raw_frame(FrameType::SERVER_INFO, &sb)));
        self.ev(Event::TxDone);
        assert_eq!(self.link.state(), State::Ready);
        self.check();
    }

    fn random_run(&mut self, steps: usize) {
        let valid_stream = {
            let mut v = recv_frame(0xAA, &stamped(0, 1, 100));
            v.extend_from_slice(&raw_frame(FrameType::PING, &[1; 8]));
            v.extend_from_slice(&raw_frame(FrameType::KEEP_ALIVE, &[]));
            v
        };
        for _ in 0..steps {
            self.now += self.rand(4000);
            match self.rand(16) {
                0 => {
                    self.ev(Event::Connect);
                }
                1 => {
                    self.ev(Event::Reconnect);
                }
                2 => {
                    if self.rand(4) == 0 {
                        self.ev(Event::Close);
                    }
                }
                3 => {
                    let v = self.rand(2) == 1;
                    self.ev(Event::ClockValid(v));
                }
                4 => {
                    if self.link.want_token() || self.rand(4) == 0 {
                        self.grant();
                    }
                }
                5 => {
                    let ok = self.rand(5) != 0;
                    self.ev(Event::Dns(ok));
                }
                6 => {
                    let ok = self.rand(5) != 0;
                    self.ev(Event::Connected(ok));
                }
                7 => {
                    let ok = self.rand(5) != 0;
                    self.ev(Event::TlsDone(ok));
                }
                8 | 9 => {
                    self.ev(Event::TxDone);
                }
                10 => {
                    self.ev(Event::TxProgress);
                }
                11 => {
                    let n = self.rand(valid_stream.len() as u64 + 1) as usize;
                    self.ev(Event::Bytes(&valid_stream[..n]));
                }
                12 => {
                    let n = self.rand(80) as usize;
                    let junk: Vec<u8> = (0..n).map(|_| self.rand(256) as u8).collect();
                    self.ev(Event::Bytes(&junk));
                }
                13 => {
                    let mut resp = b"HTTP/1.1 101 x\r\n\r\n".to_vec();
                    let mut body = MAGIC.to_vec();
                    body.extend_from_slice(&[7u8; 32]);
                    resp.extend_from_slice(&raw_frame(FrameType::SERVER_KEY, &body));
                    self.ev(Event::Bytes(&resp));
                }
                14 => {
                    let n = self.rand(1800) as usize;
                    let mut sink = |_: Action<'_>| {};
                    let payload = vec![0u8; n];
                    let _ = self.link.send_packet(self.now, &[9; 32], &payload, &mut sink);
                }
                _ => {
                    self.ev(Event::Timer);
                }
            }
            self.sync_after_random();
        }
        self.ev(Event::Close);
        assert_eq!(self.link.state(), State::Idle);
    }

    /// The random driver does not track the protocol precisely, so it re-derives what it can from the link: writes are only outstanding while connecting
    /// or ready, a dial is open exactly while the link is in an attempt or ready.
    fn sync_after_random(&mut self) {
        let s = self.link.state();
        if !(s.is_connecting() || s == State::Ready) {
            self.sends_outstanding = 0;
            assert_eq!(self.dials, 0, "transport left open in {s:?}");
        } else {
            assert_eq!(self.dials, 1, "no transport in {s:?}");
        }
        if matches!(s, State::Idle | State::Waiting | State::Token) {
            assert_eq!(self.token, 0, "token held in {s:?}");
        }
        assert!(self.link.tx_queued() <= 2048);
    }
}

/// Deterministic mini-fuzz: many seeds, long random event sequences, mutated handshakes.
#[test]
fn mini_fuzz_random_event_sequences() {
    for seed in 1..=300u64 {
        let mut h = Harness::new(seed);
        h.random_run(300);
    }
}

#[test]
fn mini_fuzz_mutated_sessions() {
    // a good session script with random bytes flipped, deleted or duplicated, fed in random chunks
    let mut base = Harness::new(5);
    let mut script = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n".to_vec();
    let mut body = MAGIC.to_vec();
    body.extend_from_slice(&base.server_pub.0);
    script.extend_from_slice(&raw_frame(FrameType::SERVER_KEY, &body));
    for i in 0..6u32 {
        script.extend_from_slice(&recv_frame(0xAA, &stamped(0, i, 50 + i as usize * 40)));
        script.extend_from_slice(&raw_frame(FrameType::PING, &[i as u8; 8]));
    }
    let _ = &mut base;
    let mut rng = TestRng(0xfeed);
    for round in 0..800u64 {
        use tdongle_tailnet_types::Entropy;
        let mut h = Harness::new(round + 1);
        h.ev(Event::ClockValid(true));
        h.ev(Event::Connect);
        h.grant();
        h.ev(Event::Dns(true));
        h.ev(Event::Connected(true));
        h.ev(Event::TlsDone(true));
        h.ev(Event::TxDone);
        let mut s = script.clone();
        let mut r = [0u8; 16];
        rng.fill(&mut r);
        for k in 0..(r[0] % 6) as usize {
            let at = (r[1 + k] as usize * 7 + k * 13) % s.len();
            match r[8 + k] % 3 {
                0 => s[at] ^= 1 << (r[9] % 8),
                1 => {
                    s.remove(at);
                }
                _ => {
                    let b = s[at];
                    s.insert(at, b);
                }
            }
        }
        let mut at = 0;
        while at < s.len() {
            let n = 1 + (rng_next(&mut rng) % 90) as usize;
            let end = (at + n).min(s.len());
            h.ev(Event::Bytes(&s[at..end]));
            if h.link.state().is_connecting() {
                h.ev(Event::TxDone);
            }
            h.sync_after_random();
            at = end;
        }
        h.ev(Event::Close);
        assert_eq!(h.link.state(), State::Idle);
        assert_eq!(h.dials, 0);
    }
}

fn rng_next(r: &mut TestRng) -> u64 {
    use tdongle_tailnet_types::Entropy;
    let mut b = [0u8; 8];
    r.fill(&mut b);
    u64::from_le_bytes(b)
}

#[test]
fn encode_frame_matches_the_streaming_reader() {
    let mut out = [0u8; 2000];
    for len in [0usize, 1, 8, 32, 33, 1000, MAX_FRAME] {
        let payload = vec![0xA5u8; len];
        let n = encode_frame(FrameType::HEALTH, &[&payload], &mut out).unwrap();
        let mut r = FrameReader::new();
        let mut seen = 0;
        r.feed_all(&out[..n], |t, b| {
            assert_eq!((t, b.len()), (FrameType::HEALTH, len));
            seen += 1;
        })
        .unwrap();
        assert_eq!(seen, 1);
    }
}
