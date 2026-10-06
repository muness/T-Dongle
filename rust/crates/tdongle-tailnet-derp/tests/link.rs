//! The link driven directly with scripted events: handshake, retry ladder, deadlines, control frames, transmit policy.

mod common;

use common::{Owned, raw_frame, recv_frame, stamped};
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_derp::frame::FrameType;
use tdongle_tailnet_derp::handshake::{CLIENT_INFO_BODY_LEN, CLIENT_INFO_JSON};
use tdongle_tailnet_derp::{Action, Event, Link, LinkEvent, MAGIC, State, Target, Timing, TxDrop, TxPolicy};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;

type L = Link<4096>;

struct Drv {
    link: L,
    now: u64,
    rng: TestRng,
    server_secret: Key32,
    server_pub: Key32,
    /// Everything the link ever emitted, in order.
    log: Vec<Owned>,
}

fn key(seed: u8) -> Key32 {
    Key32(core::array::from_fn(|i| seed.wrapping_mul(13).wrapping_add(i as u8 + 1)))
}

impl Drv {
    fn new() -> Drv {
        let server_secret = key(200);
        let server_pub = x25519::public(&server_secret);
        Drv {
            link: Link::new(key(1), Target::new(7, "derp.test", 443), Timing::DEFAULT),
            now: 1000,
            rng: TestRng(99),
            server_secret,
            server_pub,
            log: Vec::new(),
        }
    }
    fn ev(&mut self, ev: Event<'_>) -> Vec<Owned> {
        let mut out = Vec::new();
        {
            let mut sink = |a: Action<'_>| out.push(Owned::from(a));
            self.link.handle(self.now, ev, &mut self.rng, &mut sink);
        }
        self.log.extend(out.iter().map(|o| match o {
            Owned::Send(b) => Owned::Send(b.clone()),
            Owned::Deliver { src, payload } => Owned::Deliver { src: *src, payload: payload.clone() },
            Owned::Health(h) => Owned::Health(h.clone()),
            Owned::Notify(n) => Owned::Notify(*n),
            Owned::WantToken => Owned::WantToken,
            Owned::ReleaseToken => Owned::ReleaseToken,
            Owned::Dial => Owned::Dial,
            Owned::StartTls => Owned::StartTls,
            Owned::Close => Owned::Close,
            Owned::PeerGone => Owned::PeerGone,
            Owned::Restarting(a, b) => Owned::Restarting(*a, *b),
        }));
        out
    }
    fn at(&mut self, now: u64) {
        assert!(now >= self.now);
        self.now = now;
    }
    fn advance(&mut self, ms: u64) -> Vec<Owned> {
        self.now += ms;
        self.ev(Event::Timer)
    }
    /// Run to the point where the link has sent its upgrade request.
    fn run_to_upgrade(&mut self) -> Vec<u8> {
        self.ev(Event::ClockValid(true));
        let o = self.ev(Event::Connect);
        assert!(matches!(o.as_slice(), [Owned::WantToken]), "{o:?}");
        assert!(self.link.want_token());
        let o = self.ev(Event::TokenGranted);
        assert!(matches!(o.as_slice(), [Owned::Dial]), "{o:?}");
        assert_eq!(self.link.state(), State::Dns);
        assert!(self.ev(Event::Dns(true)).is_empty());
        assert_eq!(self.link.state(), State::Connecting);
        let o = self.ev(Event::Connected(true));
        assert!(matches!(o.as_slice(), [Owned::StartTls]), "{o:?}");
        let o = self.ev(Event::TlsDone(true));
        let [Owned::Send(req)] = o.as_slice() else { panic!("{o:?}") };
        assert_eq!(self.link.state(), State::Upgrade);
        req.clone()
    }
    fn server_greeting(&self) -> Vec<u8> {
        let mut v = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".to_vec();
        let mut body = MAGIC.to_vec();
        body.extend_from_slice(&self.server_pub.0);
        v.extend_from_slice(&raw_frame(FrameType::SERVER_KEY, &body));
        v
    }
    fn server_info(&self) -> Vec<u8> {
        let me = self.link.public_key();
        let nonce = [5u8; 24];
        let json = br#"{"version":2,"TokenBucketBytesPerSecond":1000,"TokenBucketBytesBurst":2000}"#;
        let mut sb = vec![0u8; 24 + 16 + json.len()];
        sb[..24].copy_from_slice(&nonce);
        sb[40..].copy_from_slice(json);
        nacl::box_seal(&self.server_secret, &me, &nonce, &mut sb[24..]).unwrap();
        raw_frame(FrameType::SERVER_INFO, &sb)
    }
    /// Through the whole handshake to Ready. Returns the actions of the last step.
    fn run_to_ready(&mut self) -> Vec<Owned> {
        self.run_to_upgrade();
        assert!(self.ev(Event::TxDone).is_empty());
        let g = self.server_greeting();
        let o = self.ev(Event::Bytes(&g));
        let [Owned::Send(ci)] = o.as_slice() else { panic!("{o:?}") };
        self.check_client_info(ci);
        assert_eq!(self.link.state(), State::ClientInfo);
        assert!(self.ev(Event::TxDone).is_empty());
        assert_eq!(self.link.state(), State::ServerInfo);
        let si = self.server_info();
        let o = self.ev(Event::Bytes(&si));
        assert_eq!(self.link.state(), State::Ready);
        o
    }
    fn check_client_info(&self, frame: &[u8]) {
        assert_eq!(frame[0], FrameType::CLIENT_INFO.0);
        assert_eq!(u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize, CLIENT_INFO_BODY_LEN);
        assert_eq!(frame.len(), 5 + CLIENT_INFO_BODY_LEN);
        let body = &frame[5..];
        let client_pub = Key32(body[..32].try_into().unwrap());
        assert_eq!(client_pub, self.link.public_key());
        let nonce: [u8; 24] = body[32..56].try_into().unwrap();
        let mut boxed = body[56..].to_vec();
        nacl::box_open(&self.server_secret, &client_pub, &nonce, &mut boxed).unwrap();
        assert_eq!(&boxed[16..], CLIENT_INFO_JSON);
    }
    fn count(&self, f: impl Fn(&Owned) -> bool) -> usize {
        self.log.iter().filter(|o| f(o)).count()
    }
}

fn notified(o: &[Owned], e: LinkEvent) -> bool {
    o.iter().any(|x| matches!(x, Owned::Notify(n) if *n == e))
}

#[test]
fn full_handshake_action_sequence() {
    let mut d = Drv::new();
    let req = d.run_to_upgrade();
    assert_eq!(req, b"GET /derp HTTP/1.1\r\nHost: derp.test\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n");
    assert!(d.ev(Event::TxDone).is_empty());
    let g = d.server_greeting();
    let o = d.ev(Event::Bytes(&g));
    let [Owned::Send(ci)] = o.as_slice() else { panic!("{o:?}") };
    d.check_client_info(&ci.clone());
    assert!(d.ev(Event::TxDone).is_empty());
    let si = d.server_info();
    let o = d.ev(Event::Bytes(&si));
    // ready: the token goes back, the preferred note goes out, the owner is told
    assert!(
        matches!(
            o.as_slice(),
            [Owned::ReleaseToken, Owned::Notify(LinkEvent::Connected), Owned::Send(np)] if np == &[0x07, 0, 0, 0, 1, 1]
        ),
        "{o:?}"
    );
    assert!(d.ev(Event::TxDone).is_empty());
    assert_eq!(d.link.stats().connects.get(), 1);
    assert_eq!(d.link.server_info().bytes_per_second, 1000);
    assert_eq!(d.link.server_info().burst, 2000);
    assert!(d.link.is_ready() && !d.link.is_busy());
}

#[test]
fn handshake_in_one_chunk_and_byte_by_byte() {
    for chunk in [1usize, 3, 10_000] {
        let mut d = Drv::new();
        d.run_to_upgrade();
        d.ev(Event::TxDone);
        let mut stream = d.server_greeting();
        let mut sent_ci = false;
        let mut at = 0;
        let mut after_ci: Vec<u8> = Vec::new();
        while at < stream.len() {
            let end = (at + chunk).min(stream.len());
            let o = d.ev(Event::Bytes(&stream[at..end]));
            if o.iter().any(|x| matches!(x, Owned::Send(_))) {
                sent_ci = true;
                d.ev(Event::TxDone);
                after_ci = d.server_info();
                stream.truncate(end); // the rest of the script is the ServerInfo, sent after ClientInfo
            }
            at = end;
        }
        assert!(sent_ci, "chunk {chunk}");
        let mut at = 0;
        while at < after_ci.len() {
            let end = (at + chunk).min(after_ci.len());
            d.ev(Event::Bytes(&after_ci[at..end]));
            at = end;
        }
        assert_eq!(d.link.state(), State::Ready, "chunk {chunk}");
    }
}

#[test]
fn the_clock_holds_the_first_attempt_without_counting_a_failure() {
    let mut d = Drv::new();
    let o = d.ev(Event::Connect);
    assert!(notified(&o, LinkEvent::ClockDeferred) && !o.iter().any(|x| matches!(x, Owned::WantToken)), "{o:?}");
    assert_eq!(d.link.state(), State::Waiting);
    assert_eq!(d.link.next_deadline_ms(d.now), Some(1000), "look at the clock now and then");
    for _ in 0..5 {
        let o = d.advance(1000);
        assert!(o.is_empty(), "the deferral is announced once: {o:?}");
    }
    assert_eq!(d.link.stats().connect_failures.get(), 0);
    d.at(d.now + 123);
    let o = d.ev(Event::ClockValid(true));
    assert!(matches!(o.as_slice(), [Owned::WantToken]), "the clock arrived: connect at once, not after the wait: {o:?}");
    assert_eq!(d.link.pace().deferrals, 1);
}

/// The ladder as the C code behaves (not as its comment says: "three attempts 2 s apart"): after the first failure the burst gap of 2 s applies; the
/// second failure uses up the burst, and the ladder arms its first rung (5 s) from there, so the gaps are 2, 5, 10, 20, 40, 60, 60 s.
#[test]
fn retry_ladder_timeline() {
    let mut d = Drv::new();
    d.ev(Event::ClockValid(true));
    d.ev(Event::Connect);
    let mut attempts = vec![d.now];
    d.ev(Event::TokenGranted);
    d.ev(Event::Dns(false));
    for _ in 0..7 {
        // sleep exactly as long as the link asks, then see what it does
        let wait = d.link.next_deadline_ms(d.now).expect("a wanted link always has a next wake");
        let o = d.advance(wait as u64);
        if o.iter().any(|x| matches!(x, Owned::WantToken)) {
            attempts.push(d.now);
            d.ev(Event::TokenGranted);
            d.ev(Event::Dns(false));
        }
    }
    let gaps: Vec<u64> = attempts.windows(2).map(|w| w[1] - w[0]).collect();
    // each wait is the deadline plus the 1 ms the link adds so that "now > deadline" has certainly fired
    let expect = [2000u64, 5000, 10_000, 20_000, 40_000, 60_000, 60_000];
    assert_eq!(gaps.len(), expect.len(), "{attempts:?}");
    for (g, e) in gaps.iter().zip(expect) {
        assert!(*g >= e && *g <= e + 2, "gap {g} expected {e}: {attempts:?}");
    }
    assert_eq!(d.link.stats().connect_failures.get() as usize, attempts.len());
}

#[test]
fn a_dropped_relay_redials_after_200ms_then_500ms_gaps() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    // the stream dies: the driver reports nothing, the stale watchdog does
    d.now += 91_000;
    let o = d.ev(Event::Timer);
    assert!(notified(&o, LinkEvent::RxStale) && notified(&o, LinkEvent::Disconnected), "{o:?}");
    assert!(o.iter().any(|x| matches!(x, Owned::Close)));
    assert_eq!(d.link.stats().stale.get(), 1);
    assert_eq!(d.link.state(), State::Waiting);
    let t0 = d.now;
    let o = d.advance(199);
    assert!(o.is_empty());
    let o = d.advance(1);
    assert!(o.iter().any(|x| matches!(x, Owned::WantToken)), "{o:?}");
    assert_eq!(d.now - t0, 200);
    // the redial fails: next attempt 500 ms later
    d.ev(Event::TokenGranted);
    let t1 = d.now;
    let o = d.ev(Event::Dns(false));
    assert!(notified(&o, LinkEvent::ConnectFailed));
    assert!(d.advance(499).is_empty());
    assert!(d.advance(1).iter().any(|x| matches!(x, Owned::WantToken)));
    assert_eq!(d.now - t1, 500);
}

#[test]
fn reconnect_and_close() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    let o = d.ev(Event::Reconnect);
    assert!(notified(&o, LinkEvent::Disconnected) && o.iter().any(|x| matches!(x, Owned::Close)));
    assert!(d.link.is_wanted());
    let o = d.advance(200);
    assert!(o.iter().any(|x| matches!(x, Owned::WantToken)));
    // close while waiting for the token, then again: idempotent, no events the second time
    let o = d.ev(Event::Close);
    assert!(o.is_empty(), "{o:?}");
    assert_eq!((d.link.state(), d.link.is_wanted()), (State::Idle, false));
    assert!(d.ev(Event::Close).is_empty());
    assert_eq!(d.link.next_deadline_ms(d.now), None);
    // close mid-attempt releases the token and closes the transport
    d.ev(Event::Connect);
    d.ev(Event::TokenGranted);
    d.ev(Event::Dns(true));
    let o = d.ev(Event::Close);
    assert!(matches!(o.as_slice(), [Owned::Close, Owned::ReleaseToken]), "{o:?}");
    // close of a ready link announces the disconnect
    d.run_to_ready();
    let o = d.ev(Event::Close);
    assert!(notified(&o, LinkEvent::Disconnected));
    assert_eq!(d.link.state(), State::Idle);
}

#[test]
fn a_token_grant_nobody_asked_for_is_given_straight_back() {
    let mut d = Drv::new();
    let o = d.ev(Event::TokenGranted);
    assert!(matches!(o.as_slice(), [Owned::ReleaseToken]));
    d.run_to_ready();
    let o = d.ev(Event::TokenGranted);
    assert!(matches!(o.as_slice(), [Owned::ReleaseToken]));
    assert!(d.link.stats().stray_events.get() >= 2);
    assert!(d.link.is_ready());
}

#[test]
fn stray_events_are_counted_and_harmless() {
    let mut d = Drv::new();
    d.ev(Event::Dns(true));
    d.ev(Event::Connected(true));
    d.ev(Event::TlsDone(true));
    d.ev(Event::TxDone);
    d.ev(Event::TxProgress);
    d.ev(Event::Bytes(b"junk"));
    assert_eq!(d.link.state(), State::Idle);
    assert_eq!(d.link.stats().stray_events.get(), 5);
    assert_eq!(d.link.stats().stray_bytes.get(), 1);
}

#[test]
fn a_refused_upgrade_fails_the_attempt() {
    for resp in [&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nX: 101\r\n\r\n", b"garbage\r\n\r\n"] {
        let mut d = Drv::new();
        d.run_to_upgrade();
        d.ev(Event::TxDone);
        let o = d.ev(Event::Bytes(resp));
        assert!(notified(&o, LinkEvent::ConnectFailed) && o.iter().any(|x| matches!(x, Owned::Close | Owned::ReleaseToken)));
        assert_eq!(d.link.stats().protocol_errors.get(), 1);
        assert_eq!(d.link.state(), State::Waiting);
    }
    // a response that never ends is bounded
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    let o = d.ev(Event::Bytes(&[b'x'; 600]));
    assert!(notified(&o, LinkEvent::ConnectFailed));
}

#[test]
fn a_bad_server_greeting_fails_the_attempt() {
    let mk = |body: Vec<u8>, ty: FrameType| {
        let mut v = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        v.extend_from_slice(&raw_frame(ty, &body));
        v
    };
    let mut good = MAGIC.to_vec();
    good.extend_from_slice(&[9u8; 32]);
    let mut bad_magic = good.clone();
    bad_magic[3] ^= 1;
    for g in [mk(bad_magic, FrameType::SERVER_KEY), mk(good[..39].to_vec(), FrameType::SERVER_KEY), mk(good.clone(), FrameType::KEEP_ALIVE)] {
        let mut d = Drv::new();
        d.run_to_upgrade();
        d.ev(Event::TxDone);
        let o = d.ev(Event::Bytes(&g));
        assert!(notified(&o, LinkEvent::ConnectFailed), "{o:?}");
        assert_eq!(d.link.stats().protocol_errors.get(), 1);
    }
    // more bytes after the key (a future server) are fine
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    good.extend_from_slice(b"future");
    let o = d.ev(Event::Bytes(&mk(good, FrameType::SERVER_KEY)));
    assert!(matches!(o.as_slice(), [Owned::Send(_)]));
}

#[test]
fn server_info_variants() {
    // a ServerInfo box that does not open (wrong server key) fails the attempt, as Go's parseServerInfo does
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    let g = d.server_greeting();
    d.ev(Event::Bytes(&g));
    d.ev(Event::TxDone);
    let mut si = d.server_info();
    si[40] ^= 1;
    let o = d.ev(Event::Bytes(&si));
    assert!(notified(&o, LinkEvent::ConnectFailed));
    assert_eq!(d.link.stats().server_info_bad.get(), 1);

    // no ServerInfo within the phase deadline: carry on, as the blocking client did
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    let g = d.server_greeting();
    d.ev(Event::Bytes(&g));
    d.ev(Event::TxDone);
    d.advance(9000);
    assert_eq!(d.link.state(), State::ServerInfo);
    let o = d.advance(1500);
    assert!(notified(&o, LinkEvent::Connected), "{o:?}");
    assert!(d.link.is_ready());

    // ... but not in the middle of a frame: that would desynchronise the stream
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    let g = d.server_greeting();
    d.ev(Event::Bytes(&g));
    d.ev(Event::TxDone);
    let si = d.server_info();
    d.ev(Event::Bytes(&si[..10]));
    let o = d.advance(10_500);
    assert!(notified(&o, LinkEvent::ConnectFailed), "{o:?}");

    // ServerInfo arriving before the driver reported the ClientInfo write as done
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    let g = d.server_greeting();
    d.ev(Event::Bytes(&g));
    assert_eq!(d.link.state(), State::ClientInfo);
    let si = d.server_info();
    assert!(d.ev(Event::Bytes(&si)).is_empty());
    assert_eq!(d.link.state(), State::ClientInfo);
    let o = d.ev(Event::TxDone);
    assert!(notified(&o, LinkEvent::Connected), "{o:?}");
}

#[test]
fn a_reply_before_the_request_write_completed_is_a_driver_ordering_error() {
    let mut d = Drv::new();
    d.run_to_upgrade();
    let g = d.server_greeting(); // no TxDone first
    let o = d.ev(Event::Bytes(&g));
    assert!(notified(&o, LinkEvent::ConnectFailed));
    assert_eq!(d.link.stats().order_errors.get(), 1);
}

#[test]
fn deadlines_per_phase() {
    // Dns, Connecting, Tls: the 30 s attempt deadline
    for steps in 0..3 {
        let mut d = Drv::new();
        d.ev(Event::ClockValid(true));
        d.ev(Event::Connect);
        d.ev(Event::TokenGranted);
        if steps > 0 {
            d.ev(Event::Dns(true));
        }
        if steps > 1 {
            d.ev(Event::Connected(true));
        }
        assert_eq!(d.link.next_deadline_ms(d.now), Some(30_001));
        assert!(d.advance(30_000).is_empty());
        let o = d.advance(1);
        assert!(notified(&o, LinkEvent::ConnectFailed) && o.iter().any(|x| matches!(x, Owned::Close)), "steps {steps}: {o:?}");
        assert!(o.iter().any(|x| matches!(x, Owned::ReleaseToken)));
    }
    // upgrade with no answer: the 10 s phase deadline
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    assert!(d.advance(10_000).is_empty());
    assert!(notified(&d.advance(1), LinkEvent::ConnectFailed));
    // ServerKey with no frame: the phase deadline, counted as a receive timeout
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.ev(Event::TxDone);
    d.ev(Event::Bytes(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"));
    assert_eq!(d.link.state(), State::ServerKey);
    assert!(notified(&d.advance(10_001), LinkEvent::ConnectFailed));
    assert_eq!(d.link.stats().rx_timeouts.get(), 1);
    // a write that makes no progress (the upgrade request)
    let mut d = Drv::new();
    d.run_to_upgrade();
    d.advance(2900);
    d.ev(Event::TxProgress); // some bytes moved: the clock restarts
    d.advance(2900);
    assert_eq!(d.link.state(), State::Upgrade);
    assert!(notified(&d.advance(200), LinkEvent::ConnectFailed));
    assert_eq!(d.link.stats().tx_stalls.get(), 1);
}

#[test]
fn a_record_that_started_must_finish_within_5s() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    let f = recv_frame(0xAA, &stamped(0, 1, 500));
    d.ev(Event::Bytes(&f[..7]));
    // the receive deadline is the earliest wake of an otherwise idle relay
    assert_eq!(d.link.next_deadline_ms(d.now), Some(5001));
    d.advance(2000);
    d.ev(Event::Bytes(&f[7..20])); // progress does not extend a record's deadline
    assert_eq!(d.link.next_deadline_ms(d.now), Some(3001));
    assert!(d.advance(3000).is_empty());
    assert_eq!(d.link.state(), State::Ready);
    let o = d.advance(1);
    assert!(notified(&o, LinkEvent::Disconnected));
    assert_eq!(d.link.stats().rx_timeouts.get(), 1);
    // a record that finishes in time costs nothing, and the next record's clock starts at its own first byte
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    d.ev(Event::Bytes(&f[..100]));
    d.advance(4900);
    let o = d.ev(Event::Bytes(&f[100..]));
    assert!(o.iter().any(|x| matches!(x, Owned::Deliver { .. })));
    assert_eq!(d.link.next_deadline_ms(d.now), Some(90_001));
}

#[test]
fn stale_after_90s_of_silence_and_keepalives_prevent_it() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    for _ in 0..5 {
        d.advance(60_000);
        let o = d.ev(Event::Bytes(&raw_frame(FrameType::KEEP_ALIVE, &[])));
        assert!(o.is_empty());
        assert!(d.link.is_ready());
    }
    assert_eq!(d.link.stats().keepalives.get(), 5);
    let o = d.advance(90_001);
    assert!(notified(&o, LinkEvent::RxStale));
}

#[test]
fn ping_is_echoed_and_only_one_control_frame_queues() {
    let mut d = Drv::new();
    let o = d.run_to_ready();
    assert!(o.iter().any(|x| matches!(x, Owned::Send(_))), "NotePreferred in flight");
    // a ping while NotePreferred is still being written: dropped and counted, never interleaved
    let ping = raw_frame(FrameType::PING, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(d.ev(Event::Bytes(&ping)).is_empty());
    assert_eq!(d.link.stats().pings_dropped.get(), 1);
    assert!(d.ev(Event::TxDone).is_empty());
    // idle: answered at once
    let o = d.ev(Event::Bytes(&ping));
    assert!(matches!(o.as_slice(), [Owned::Send(p)] if p == &[0x13, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]), "{o:?}");
    assert_eq!(d.link.stats().pings_answered.get(), 1);
    // a second ping while the pong is in flight: dropped
    assert!(d.ev(Event::Bytes(&ping)).is_empty());
    assert_eq!(d.link.stats().pings_dropped.get(), 2);
    assert!(d.ev(Event::TxDone).is_empty());
    // the C echoes up to 64 bytes; Go sends 8. Longer or shorter pings are dropped
    let p64 = raw_frame(FrameType::PING, &[7u8; 64]);
    let o = d.ev(Event::Bytes(&p64));
    assert!(matches!(o.as_slice(), [Owned::Send(p)] if p.len() == 5 + 64));
    d.ev(Event::TxDone);
    let p65 = raw_frame(FrameType::PING, &[7u8; 65]);
    assert!(d.ev(Event::Bytes(&p65)).is_empty());
    let p4 = raw_frame(FrameType::PING, &[7u8; 4]);
    assert!(d.ev(Event::Bytes(&p4)).is_empty());
    assert_eq!(d.link.stats().pings_dropped.get(), 4);
    assert!(d.link.is_ready());
}

#[test]
fn received_frames_are_dispatched_and_unknown_ones_skipped_in_sync() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    let src = [0xAAu8; 32];
    let mut stream = Vec::new();
    stream.extend_from_slice(&recv_frame(0xAA, b"first"));
    stream.extend_from_slice(&raw_frame(FrameType(0x7e), &[1, 2, 3])); // a type from the future
    stream.extend_from_slice(&raw_frame(FrameType::HEALTH, b"derp is sad"));
    let mut gone = vec![0xBB; 32];
    gone.push(1);
    stream.extend_from_slice(&raw_frame(FrameType::PEER_GONE, &gone));
    stream.extend_from_slice(&raw_frame(FrameType::PEER_PRESENT, &[0xCC; 32]));
    stream.extend_from_slice(&raw_frame(FrameType::RESTARTING, &[0, 0, 0x0e, 0x10, 0, 0, 0x3a, 0x98]));
    stream.extend_from_slice(&raw_frame(FrameType::PONG, &[0; 8]));
    stream.extend_from_slice(&raw_frame(FrameType::RESTARTING, &[0; 3])); // too short: skipped
    stream.extend_from_slice(&recv_frame(0xAA, b"second"));
    for chunk in [1usize, 5, 33, 100_000] {
        let mut d2 = Drv::new();
        d2.run_to_ready();
        d2.ev(Event::TxDone);
        let mut out = Vec::new();
        for c in stream.chunks(chunk) {
            out.extend(d2.ev(Event::Bytes(c)));
        }
        let delivered: Vec<&[u8]> = out
            .iter()
            .filter_map(|o| {
                if let Owned::Deliver { src: s, payload } = o {
                    assert_eq!(*s, src);
                    Some(payload.as_slice())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(delivered, [&b"first"[..], b"second"], "chunk {chunk}");
        assert_eq!(out.iter().filter(|o| matches!(o, Owned::Health(h) if h == b"derp is sad")).count(), 1);
        assert_eq!(out.iter().filter(|o| matches!(o, Owned::PeerGone)).count(), 1);
        assert_eq!(out.iter().filter(|o| matches!(o, Owned::Restarting(3600, 15000))).count(), 1);
        let s = d2.link.stats();
        assert_eq!((s.unknown_frames.get(), s.malformed_frames.get(), s.pongs_rx.get()), (1, 1, 1));
        assert!(d2.link.is_ready());
    }
    let _ = d;
}

#[test]
fn frames_beyond_the_bounds_drop_the_link() {
    // KeepAlive claiming 1 MiB (the C test's frame), a relayed packet over the cap, and one too short to carry a source key
    for hdr in [[0x06u8, 0x00, 0x10, 0x00, 0x00], [0x05, 0, 0, 0x06, 0x3d], [0x05, 0, 0, 0, 20]] {
        let mut d = Drv::new();
        d.run_to_ready();
        d.ev(Event::TxDone);
        let o = d.ev(Event::Bytes(&hdr));
        assert!(notified(&o, LinkEvent::Disconnected), "{hdr:?}: {o:?}");
        assert_eq!(d.link.stats().oversize.get(), 1);
        assert_eq!(d.link.state(), State::Waiting);
    }
    // the inclusive limits are carried: 1,564 bytes after the key
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    let f = recv_frame(1, &vec![0x5a; tdongle_tailnet_derp::MAX_FRAME]);
    let o = d.ev(Event::Bytes(&f));
    assert!(matches!(o.as_slice(), [Owned::Deliver { payload, .. }] if payload.len() == tdongle_tailnet_derp::MAX_FRAME));
}

#[test]
fn transmit_queue_policy_and_one_frame_in_flight() {
    let mut d = Drv::new();
    // not ready: counted refusal
    let mut sink = |_: Action<'_>| {};
    assert_eq!(d.link.send_packet(d.now, &[1; 32], b"x", &mut sink), Err(TxDrop::NotReady));
    d.run_to_ready();
    d.ev(Event::TxDone);
    let mut sent: Vec<Vec<u8>> = Vec::new();
    {
        let mut sink = |a: Action<'_>| {
            if let Action::Send(b) = a {
                sent.push(b.to_vec());
            }
        };
        for i in 0..5u8 {
            d.link.send_packet(d.now, &[i; 32], &[i; 50], &mut sink).unwrap();
        }
    }
    assert_eq!(sent.len(), 1, "exactly one send outstanding");
    assert_eq!(d.link.tx_queued(), 5);
    assert_eq!(&sent[0][..5], &[0x04, 0, 0, 0, 82]);
    assert_eq!(&sent[0][5..37], &[0u8; 32]);
    // each TxDone releases the next, oldest first
    for i in 1..5u8 {
        let o = d.ev(Event::TxDone);
        let [Owned::Send(b)] = o.as_slice() else { panic!("{o:?}") };
        assert_eq!(&b[5..37], &[i; 32]);
    }
    assert!(d.ev(Event::TxDone).is_empty());
    assert_eq!(d.link.tx_queued(), 0);
    assert_eq!(d.link.stats().frames_tx.get(), 1 + 5, "NotePreferred and five packets");
    // refusals: too big, over budget (with the small exemption), no space
    let mut sink = |_: Action<'_>| {};
    assert_eq!(d.link.send_packet(d.now, &[1; 32], &[0; 1565], &mut sink), Err(TxDrop::TooBig));
    d.link.set_tx_policy(TxPolicy { soft_limit: 1000, small_bytes: 200, small_slots: 1 });
    d.link.send_packet(d.now, &[1; 32], &[0; 900], &mut sink).unwrap(); // in flight, counts against the budget
    assert_eq!(d.link.send_packet(d.now, &[1; 32], &[0; 300], &mut sink), Err(TxDrop::OverBudget));
    d.link.send_packet(d.now, &[1; 32], &[0; 100], &mut sink).unwrap(); // small: exempt
    assert_eq!(d.link.send_packet(d.now, &[1; 32], &[0; 100], &mut sink), Err(TxDrop::OverBudget));
    d.link.set_tx_policy(TxPolicy::DEFAULT);
    for _ in 0..40 {
        if d.link.send_packet(d.now, &[1; 32], &[0; 1500], &mut sink).is_err() {
            break;
        }
    }
    assert_eq!(d.link.send_packet(d.now, &[1; 32], &[0; 1500], &mut sink), Err(TxDrop::NoSpace));
    let s = d.link.stats();
    assert_eq!((s.tx_drop_not_ready.get(), s.tx_drop_too_big.get(), s.tx_drop_over_budget.get(), s.tx_drop_no_space.get()), (1, 1, 2, 2));
    // a dropped connection flushes the ring and says so
    let queued = d.link.tx_queued() as u32;
    d.ev(Event::Reconnect);
    assert_eq!(d.link.tx_queued(), 0);
    assert_eq!(d.link.stats().tx_flushed.get(), queued);
}

#[test]
fn sizes_are_bounded_and_reported() {
    use tdongle_tailnet_derp::FrameReader;
    let (link, reader) = (std::hint::black_box(L::STATE_BYTES), std::hint::black_box(FrameReader::STATE_BYTES));
    std::println!("Link<4096>: {link} bytes, FrameReader: {reader} bytes (host {}-bit)", usize::BITS);
    assert!(reader < 1800);
    assert!(link < 4096 + 1800 + 600);
    let bare = std::hint::black_box(Link::<0>::STATE_BYTES);
    assert!(bare < 2600, "{bare}");
}

#[test]
fn no_work_after_failure_until_the_redial() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    let o = d.ev(Event::Bytes(&[0x06, 0x00, 0x10, 0x00, 0x00]));
    assert!(notified(&o, LinkEvent::Disconnected));
    let before = d.log.len();
    // anything the transport still delivers is ignored, nothing is sent
    d.ev(Event::Bytes(&raw_frame(FrameType::PING, &[0; 8])));
    d.ev(Event::TxDone);
    d.advance(100);
    assert_eq!(d.log.len(), before);
    assert_eq!(d.link.state(), State::Waiting);
}

#[test]
fn restarting_is_advice_the_link_does_not_act_on() {
    let mut d = Drv::new();
    d.run_to_ready();
    d.ev(Event::TxDone);
    let o = d.ev(Event::Bytes(&raw_frame(FrameType::RESTARTING, &[0, 0, 0, 1, 0, 0, 0, 2])));
    assert!(matches!(o.as_slice(), [Owned::Restarting(1, 2)]));
    assert!(d.link.is_ready());
    assert_eq!(d.count(|o| matches!(o, Owned::Close)), 0);
    let _ = (nacl::TAG_LEN, Key32::ZERO);
}
