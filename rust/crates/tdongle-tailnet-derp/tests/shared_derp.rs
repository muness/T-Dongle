//! ADR 0013 adversarial slicing check, ported from `tests/test_shared_derp.c`.
//!
//! Members share ONE service loop (the real `Link` state machines, scheduled by the real `Mux`). Member A's DERP server misbehaves in each way a
//! server can: it stalls 5 s in the middle of a record, it stops reading our writes, it never answers the TLS handshake, it never answers the HTTP
//! upgrade. Member B's relay traffic, in both directions, must keep flowing with bounded latency throughout, and A must recover on its own. Time is
//! virtual (10 ms per pass, the real task's cadence), so the checks are exact. `test_shared_derp_realtime.c` (threads, sockets, wall clock) is not
//! ported: the property it adds is that no call blocks, which a sans-IO link cannot do by construction; the churn it exercises is `Mux`
//! attach/detach, covered below.

mod common;

use common::*;
use tdongle_tailnet_derp::frame::FrameType;
use tdongle_tailnet_derp::mux::{Mux, Slot};
use tdongle_tailnet_derp::{Event, State, Timing};

const PASS_MS: u64 = 10;
const MAX_LAT_MS: u64 = 15; // data pushed mid-pass-period is read by the next pass: <= PASS_MS

struct World {
    now: u64,
    mux: Mux<Fake, 4>,
    neg: Neg,
    a: Slot,
    b: Slot,
    b_seq_rx: u32,
    b_seq_tx: u32,
    next_b_rx: u64,
    next_b_tx: u64,
    /// The negative control: A's pass blocks on its record like the old per-membership task did.
    blocking_a: bool,
}

impl World {
    fn new(read_chunk: usize, write_chunk: usize) -> Box<World> {
        let mut mux = Mux::new();
        let mut a = Fake::new("A", 1);
        let mut b = Fake::new("B", 2);
        for f in [&mut a, &mut b] {
            f.read_chunk = read_chunk;
            f.write_chunk = write_chunk;
            f.transport_delay_ms = 30;
        }
        let sa = mux.attach(a).map_err(|_| ()).unwrap();
        let sb = mux.attach(b).map_err(|_| ()).unwrap();
        Box::new(World { now: 1000, mux, neg: Neg::default(), a: sa, b: sb, b_seq_rx: 0, b_seq_tx: 0, next_b_rx: 0, next_b_tx: 0, blocking_a: false })
    }
    fn a(&mut self) -> &mut Fake {
        self.mux.get_mut(self.a).unwrap()
    }
    fn b(&mut self) -> &mut Fake {
        self.mux.get_mut(self.b).unwrap()
    }
    fn ev(&mut self, slot: Slot, ev: Event<'_>) {
        let now = self.now;
        let f = self.mux.get_mut(slot).unwrap();
        f.step(now, ev, &mut self.neg);
    }
    fn server_polls(&mut self) {
        let now = self.now;
        self.mux.for_each(|_, f| f.server_poll(now));
    }

    /// One pass period of virtual time: traffic arrives and is queued mid-period, then the shared loop runs.
    fn tick(&mut self) {
        self.now += PASS_MS / 2;
        let now = self.now;
        if self.b().state() == State::Ready {
            if now >= self.next_b_rx {
                let q = self.b_seq_rx;
                self.b_seq_rx += 1;
                self.b().server_send(now, q, 200 + (q as usize % 5) * 100);
                self.next_b_rx = now + 20;
            }
            if now >= self.next_b_tx {
                let q = self.b_seq_tx;
                self.b_seq_tx += 1;
                let mut neg = std::mem::take(&mut self.neg);
                self.b().enqueue(now, q, 150 + (q as usize % 7) * 90, &mut neg).expect("B's queue accepts");
                self.neg = neg;
                self.next_b_tx = now + 20;
            }
        }
        self.server_polls();
        self.now += PASS_MS / 2;
        let now = self.now;
        let (a_slot, b_slot, blocking) = (self.a, self.b, self.blocking_a);
        if !blocking {
            let neg = &mut self.neg;
            self.mux.pass(|_, f| f.service(now, neg));
        } else {
            // the old per-membership task on the shared loop: A first, and A waits for its record (vTaskDelay(10) inside derp_read_exact)
            self.mux.get_mut(a_slot).unwrap().service(now, &mut self.neg);
            let start = self.now;
            loop {
                let f = self.mux.get_mut(a_slot).unwrap();
                let held = f.s2c.d.len() > f.s2c.visible;
                if !(f.link.state() == State::Ready && held && self.now - start < 5000) {
                    break;
                }
                self.now += PASS_MS;
                let now = self.now;
                let f = self.mux.get_mut(a_slot).unwrap();
                f.server_poll(now);
                f.service(now, &mut self.neg);
            }
            let now = self.now;
            self.mux.get_mut(b_slot).unwrap().service(now, &mut self.neg);
        }
        self.server_polls();
    }
    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            self.tick();
        }
    }
    fn connect_both(&mut self) {
        self.ev(self.a, Event::Connect);
        self.ev(self.b, Event::Connect);
        self.run(500);
        assert_eq!(self.a().state(), State::Ready);
        assert_eq!(self.b().state(), State::Ready);
        assert_eq!((self.a().note_preferred, self.b().note_preferred), (1, 1));
    }
    fn end_checks(&mut self) {
        self.ev(self.a, Event::Close);
        self.ev(self.b, Event::Close);
        assert_eq!(self.neg.holder, None, "no leaked token on any path");
        assert!(self.neg.queue.is_empty());
        for s in [self.a, self.b] {
            let f = self.mux.detach(s).unwrap();
            assert_eq!(f.link.tx_queued(), 0);
        }
    }
    fn b_bounded(&mut self, what: &str) {
        let b = self.b();
        assert_eq!((b.delivered_bad, b.server_bad), (0, 0));
        assert_eq!(b.state(), State::Ready);
        assert_eq!(b.disconnected_events, 0);
        assert!(b.max_rx_latency <= MAX_LAT_MS, "{what}: rx latency {}", b.max_rx_latency);
        assert!(b.max_tx_latency <= MAX_LAT_MS, "{what}: tx latency {}", b.max_tx_latency);
        assert!(b.delivered > 20 && b.server_saw > 20, "{what}: B moved {} / {}", b.delivered, b.server_saw);
        std::println!(
            "  B during {what}: rx {} (max latency {} ms), tx {} (max latency {} ms), link never dropped",
            b.delivered,
            b.max_rx_latency,
            b.server_saw,
            b.max_tx_latency
        );
    }

    /// A's server sends the first 100 bytes of a 1,000-byte record, then goes silent for `stall_ms`.
    fn stall_mid_record(&mut self, stall_ms: u64, expect_recovery_without_reconnect: bool) {
        self.connect_both();
        self.run(1000);
        let now = self.now;
        let frame = recv_frame(0xAA, &stamped(now, 7, 1000));
        let a = self.a();
        a.s2c.hold = false;
        a.s2c.push(&frame[..100]);
        a.s2c.hold = true;
        a.s2c.push(&frame[100..]); // invisible until released
        let a_conn = a.connected_events;
        let t0 = self.now;
        while self.now < t0 + stall_ms {
            self.tick();
        }
        if expect_recovery_without_reconnect {
            self.a().s2c.release();
            self.run(100);
            let a = self.a();
            assert_eq!((a.delivered, a.delivered_bad), (1, 0));
            assert!(a.state() == State::Ready && a.link.stats().rx_timeouts.get() == 0 && a.disconnected_events == 0);
        } else {
            // the 5 s record deadline fired exactly once: A dropped and redialled by itself
            let a = self.a();
            assert_eq!((a.link.stats().rx_timeouts.get(), a.disconnected_events), (1, 1));
            self.run(3000);
            let a = self.a();
            assert!(a.state() == State::Ready && a.connected_events == a_conn + 1);
            assert_eq!(a.delivered, 0, "the torn record was never delivered half-way");
        }
    }
}

const CHUNKS: [(usize, usize); 4] = [(0, 0), (1, 1), (7, 37), (64, 5)];

#[test]
fn a_stalls_4_5s_mid_record_then_resumes() {
    for (rc, wc) in CHUNKS {
        std::println!(" transport chunking read={rc} write={wc}");
        let mut w = World::new(rc, wc);
        w.stall_mid_record(4500, true);
        w.b_bounded("A stalled 4.5 s mid-record, then resumed");
        w.end_checks();
    }
}

#[test]
fn a_stalls_past_5s_mid_record_and_redials() {
    for (rc, wc) in CHUNKS {
        let mut w = World::new(rc, wc);
        w.stall_mid_record(5200, false);
        w.b_bounded("A stalled past 5 s mid-record (A redialled)");
        w.end_checks();
    }
}

/// The record deadline is 5 s from its first byte, so a 5 s stall lands on the boundary. Either outcome is acceptable for A; no effect on B is.
#[test]
fn a_stalls_exactly_5s() {
    let mut w = World::new(0, 0);
    w.connect_both();
    w.run(1000);
    let now = w.now;
    let frame = recv_frame(0xAA, &stamped(now, 9, 1000));
    let a = w.a();
    a.s2c.push(&frame[..100]);
    a.s2c.hold = true;
    a.s2c.push(&frame[100..]);
    let t0 = w.now;
    while w.now < t0 + 5000 {
        w.tick();
    }
    w.a().s2c.release();
    w.run(1000);
    let a = w.a();
    assert_eq!(a.delivered + a.link.stats().rx_timeouts.get(), 1);
    assert!(matches!(a.state(), State::Ready | State::Waiting | State::Token | State::Dns | State::Connecting | State::Tls));
    w.b_bounded("A stalled exactly 5 s mid-record");
    w.end_checks();
}

/// The shared task sleeps until the earliest wait any link reports: an established relay with nothing to say reads as not busy and asks for no
/// polling (the C polled every 10 ms; the sans-IO link names its real deadlines instead).
#[test]
fn activity_gate_and_deadlines_of_an_idle_relay() {
    let mut w = World::new(0, 0);
    w.connect_both();
    w.run(2000);
    assert!(!w.a().link.is_busy());
    let sends_before = w.a().sends_total;
    let now = w.now;
    for _ in 0..100 {
        w.now += 10;
        let n = w.now;
        let f = w.mux.get_mut(w.a).unwrap();
        f.service(n, &mut w.neg);
        assert!(!f.link.is_busy());
    }
    assert_eq!(w.a().sends_total, sends_before, "100 idle polls move no frame");
    let d = {
        let n = w.now;
        w.a().link.next_deadline_ms(n)
    }
    .expect("a ready link has a stale deadline");
    assert!(d > 80_000, "idle relay: next wake {d} ms (stale watchdog), not a 10 ms poll");
    let _ = now;
    // every state: is_busy is true exactly while an attempt is in flight
    for (s, busy) in [
        (State::Idle, false),
        (State::Waiting, false),
        (State::Token, false),
        (State::Dns, true),
        (State::Connecting, true),
        (State::Tls, true),
        (State::Upgrade, true),
        (State::ServerKey, true),
        (State::ClientInfo, true),
        (State::ServerInfo, true),
        (State::Ready, false),
    ] {
        assert_eq!(s.is_connecting(), busy, "{s:?}");
    }
    w.end_checks();
}

#[test]
fn write_blocked_under_3s_is_backpressure_and_over_3s_is_a_dead_link() {
    let mut w = World::new(0, 0);
    w.connect_both();
    w.run(500);
    w.a().write_blocked = true; // the server stops reading: our send buffer fills
    let now = w.now;
    let mut neg = std::mem::take(&mut w.neg);
    for i in 0..20 {
        w.a().enqueue(now, 100 + i, 300, &mut neg).expect("queued");
    }
    w.neg = neg;
    let t0 = w.now;
    while w.now < t0 + 2900 {
        w.tick();
    }
    assert_eq!(w.a().state(), State::Ready, "backpressure under 3 s is not a dead link");
    while w.now < t0 + 3300 {
        w.tick();
    }
    let a = w.a();
    assert_eq!((a.link.stats().tx_stalls.get(), a.disconnected_events), (1, 1));
    assert_eq!(a.link.stats().tx_flushed.get(), 20, "the queued packets, the stalled one included, are counted, not silently lost");
    a.write_blocked = false;
    w.run(3000);
    assert_eq!(w.a().state(), State::Ready);
    w.b_bounded("A's writes blocked for 3 s");
    w.end_checks();
}

#[test]
fn a_tls_handshake_that_never_completes_costs_only_its_own_membership() {
    let mut w = World::new(0, 0);
    w.ev(w.b, Event::Connect);
    w.run(500);
    assert_eq!(w.b().state(), State::Ready);
    w.a().transport_hang = true;
    w.ev(w.a, Event::Connect);
    w.run(Timing::DEFAULT.connect_ms as u64 + 1500);
    let a = w.a();
    assert!(a.failed_events >= 1 && a.transports_closed >= 1);
    w.b_bounded("A's TLS handshake hung 30 s");
    w.a().transport_hang = false;
    w.run(30_000);
    assert_eq!(w.a().state(), State::Ready);
    w.end_checks();
}

#[test]
fn a_server_ignoring_the_http_upgrade() {
    let mut w = World::new(0, 0);
    w.ev(w.b, Event::Connect);
    w.run(500);
    w.a().http_silent = true;
    w.ev(w.a, Event::Connect);
    w.run(Timing::DEFAULT.phase_ms as u64 + 500);
    assert!(w.a().failed_events >= 1);
    w.b_bounded("A's server ignoring the HTTP upgrade");
    w.a().http_silent = false;
    w.run(60_000);
    assert_eq!(w.a().state(), State::Ready);
    w.end_checks();
}

/// The token is the one place a stalled member DOES delay another: only the other's join, never its steady-state relay.
#[test]
fn negotiation_token_serialises_joins_but_not_relay() {
    let mut w = World::new(0, 0);
    let mut c = Fake::new("C", 3);
    c.transport_delay_ms = 30;
    let sc = w.mux.attach(c).map_err(|_| ()).unwrap();
    w.ev(w.b, Event::Connect);
    w.run(500);
    w.a().transport_hang = true;
    w.ev(w.a, Event::Connect);
    w.run(100);
    w.ev(sc, Event::Connect);
    w.run(5000);
    assert_eq!(w.mux.get_mut(sc).unwrap().state(), State::Token, "C queued behind A's negotiation");
    assert_eq!(w.neg.holder, Some(1));
    w.run(Timing::DEFAULT.connect_ms as u64 - 5000 + 200); // A hits its connect deadline and releases
    w.a().transport_hang = false;
    w.run(3000);
    assert_eq!(w.mux.get_mut(sc).unwrap().state(), State::Ready, "...and C gets its turn");
    w.b_bounded("A hanging the negotiation token while C waited");
    w.ev(sc, Event::Close);
    assert!(w.mux.detach(sc).is_some());
    w.end_checks();
}

#[test]
fn pings_oversize_frames_and_budget_refusals() {
    let mut w = World::new(7, 5);
    w.connect_both();
    // server PING is answered with a PONG carrying the same bytes, while B relays
    w.a().s2c.push(&raw_frame(FrameType::PING, &[1, 2, 3, 4, 5, 6, 7, 8]));
    w.run(100);
    let a = w.a();
    assert_eq!((a.pongs_seen, a.link.stats().pings_answered.get()), (1, 1));
    // a frame larger than the protocol cap drops the link instead of being read
    w.a().s2c.push(&encode_hdr(FrameType::KEEP_ALIVE, 0x0010_0000));
    w.run(100);
    let a = w.a();
    assert_eq!((a.link.stats().oversize.get(), a.disconnected_events), (1, 1));
    w.run(3000);
    assert_eq!(w.a().state(), State::Ready);
    // A refusal by the heap budget (asked with the packet's size) is read off the wire and dropped, counted; connection and stream stay as they were
    fn refuse(_: usize) -> bool {
        false
    }
    fn admit(_: usize) -> bool {
        true
    }
    let now = w.now;
    w.a().server_send(now, 1, 300);
    w.run(50);
    assert_eq!(w.a().delivered, 1);
    w.a().link.set_rx_admit(Some(refuse));
    let now = w.now;
    w.a().server_send(now, 2, 400);
    w.run(50);
    let a = w.a();
    assert!(a.state() == State::Ready && a.link.stats().rx_refused.get() == 1 && a.delivered == 1);
    a.link.set_rx_admit(Some(admit));
    let now = w.now;
    w.a().server_send(now, 3, 400);
    w.run(50);
    let a = w.a();
    assert_eq!((a.delivered, a.delivered_bad), (2, 0), "the stream stayed in sync");
    w.b_bounded("A's ping, oversize frame and budget refusal");
    w.end_checks();
}

fn encode_hdr(t: FrameType, len: u32) -> [u8; 5] {
    tdongle_tailnet_derp::frame::encode_header(t, len)
}

/// Removing a member while its peers keep relaying: nobody touches it afterwards.
#[test]
fn detach_midstream() {
    let mut w = World::new(0, 0);
    w.connect_both();
    w.run(300);
    w.ev(w.a, Event::Close);
    let gone = w.mux.detach(w.a).unwrap();
    assert_eq!(gone.link.state(), State::Idle);
    w.run(500);
    assert_eq!(w.mux.count(), 1);
    assert!(w.mux.detach(w.a).is_none());
    w.b_bounded("A removed mid-stream");
    let b = w.b;
    let _ = w.mux.detach(b);
    assert_eq!(w.neg.holder, None);
}

/// Churn: a member that attaches, relays and detaches repeatedly while B runs.
#[test]
fn attach_detach_churn_does_not_disturb_a_relaying_member() {
    let mut w = World::new(0, 0);
    w.ev(w.b, Event::Connect);
    w.run(500);
    for round in 0..6u8 {
        let mut c = Fake::new("C", 3 + round as usize);
        c.transport_delay_ms = 20;
        let sc = w.mux.attach(c).map_err(|_| ()).unwrap();
        w.ev(sc, Event::Connect);
        w.run(300 + round as u64 * 37);
        w.ev(sc, Event::Close);
        assert!(w.mux.detach(sc).is_some());
        assert_eq!(w.neg.holder, None);
    }
    w.run(200);
    w.b_bounded("six attach/detach rounds");
    let a = w.a;
    w.mux.detach(a);
}

/// What the old per-membership owner test pinned, against the real state machine: both directions saturated, pongs never inside a frame.
#[test]
fn fair_duplex_and_serialised_pongs() {
    let mut w = World::new(0, 3); // three-byte writes: every frame is written in many pieces
    w.connect_both();
    w.run(100);
    let now = w.now;
    for i in 0..15u32 {
        let mut neg = std::mem::take(&mut w.neg);
        w.a().enqueue(now, 1000 + i, 300, &mut neg).expect("queued");
        w.neg = neg;
        w.a().server_send(now, 2000 + i, 300);
    }
    w.a().write_chunk = 3;
    // server pings arrive while frames are half written: the Pong must never land inside one
    for i in 0..20u8 {
        w.a().s2c.push(&raw_frame(FrameType::PING, &[1, 2, 3, 4, 5, 6, 7, i]));
        let now = w.now;
        let mut neg = std::mem::take(&mut w.neg);
        w.a().enqueue(now, 3000 + i as u32, 500, &mut neg).ok();
        w.neg = neg;
        w.run(20);
    }
    w.run(5000);
    let a = w.a();
    assert_eq!((a.server_bad, a.delivered_bad), (0, 0), "every frame the server parsed was whole");
    assert!(a.pongs_seen == a.link.stats().pings_answered.get() && a.pongs_seen >= 1);
    assert!(a.link.stats().pings_answered.get() + a.link.stats().pings_dropped.get() == 20);
    assert_eq!(a.delivered, 15);
    w.end_checks();
}

/// After a read failure the link makes no further call into the transport until it has redialled.
#[test]
fn no_io_after_failure() {
    let mut w = World::new(0, 0);
    w.connect_both();
    w.a().s2c.push(&encode_hdr(FrameType::KEEP_ALIVE, 0x0010_0000));
    w.tick();
    assert_eq!(w.a().state(), State::Waiting);
    assert_eq!(w.a().link.stats().oversize.get(), 1);
    let (sends, opened) = (w.a().sends_total, w.a().transports_opened);
    let closed = w.a().transports_closed;
    assert!(closed >= 1);
    // bytes the dead connection still held are not read: the transport is closed
    let now = w.now;
    w.a().server_send(now, 99, 100);
    for _ in 0..10 {
        w.now += 10; // inside the 200 ms redial delay
        let n = w.now;
        let f = w.mux.get_mut(w.a).unwrap();
        f.service(n, &mut w.neg);
    }
    let a = w.a();
    assert_eq!((a.sends_total, a.transports_opened), (sends, opened));
    assert_eq!(a.delivered, 0);
    w.end_checks();
}

/// The shared task sleeps until the earliest wait any link reports.
#[test]
fn wait_computation() {
    let mut w = World::new(0, 0);
    assert_eq!(
        {
            let n = w.now;
            w.a().link.next_deadline_ms(n)
        },
        None,
        "nothing wanted: sleep until woken"
    );
    w.ev(w.a, Event::ClockValid(true));
    w.ev(w.a, Event::Connect);
    assert_eq!(w.a().state(), State::Token, "first attempt is due now: the link asks for the token");
    assert_eq!(
        {
            let n = w.now;
            w.a().link.next_deadline_ms(n)
        },
        Some(50)
    );
    w.connect_both();
    w.a().s2c.push(&encode_hdr(FrameType::KEEP_ALIVE, 0x0010_0000));
    let n = w.now;
    let f = w.mux.get_mut(w.a).unwrap();
    f.service(n, &mut w.neg); // fails: redial in 200 ms, not at a tick
    let wait = {
        let n = w.now;
        w.a().link.next_deadline_ms(n)
    }
    .unwrap();
    assert!(wait > 100 && wait <= 200, "{wait}");
    w.now += 150;
    let wait = {
        let n = w.now;
        w.a().link.next_deadline_ms(n)
    }
    .unwrap();
    assert!(wait <= 50, "and it counts down: {wait}");
    w.end_checks();
}

/// Negative control: the old per-record behaviour (wait for the record, up to 5 s) run on the SHARED loop. The harness must see B starve;
/// otherwise the bounds asserted above would prove nothing.
#[test]
fn negative_control_a_blocking_wait_on_the_shared_loop_starves_b() {
    let mut w = World::new(0, 0);
    w.blocking_a = true;
    w.connect_both();
    w.run(500);
    let now = w.now;
    let frame = recv_frame(0xAA, &stamped(now, 3, 1000));
    let a = w.a();
    a.s2c.push(&frame[..100]);
    a.s2c.hold = true;
    a.s2c.push(&frame[100..]);
    // B has traffic waiting in both directions when A's pass starts to block
    w.b().server_send(now, 9999, 300);
    let mut neg = std::mem::take(&mut w.neg);
    w.b().enqueue(now, 9999, 300, &mut neg).unwrap();
    w.neg = neg;
    w.run(6000);
    let b = w.b();
    let (lat, dropped) = (b.max_rx_latency, b.disconnected_events);
    // the harness must see the starvation: B's frames wait the whole block, and its own pending write exceeds the 3 s stall limit (B is dropped)
    assert!(lat >= 3000 || dropped > 0, "a blocking wait on A really does starve B (worst latency {lat} ms, {dropped} drops)");
    std::println!("  negative control: B's worst latency {lat} ms, {dropped} drops -> the harness sees stalls");
    w.blocking_a = false;
    w.end_checks();
    let _ = w.mux.detach(Slot(3));
}
