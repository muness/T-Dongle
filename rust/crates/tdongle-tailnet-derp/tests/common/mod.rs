//! A scripted DERP world for host tests (the Rust form of `tests/derp_fake.h`): byte pipes with controllable stalls, a real server that speaks the
//! protocol (HTTP upgrade, ServerKey, ClientInfo opened with its secret, ServerInfo boxed to the client, data frames), a transport model (DNS, TCP,
//! TLS delays and hangs) and a negotiation token. Time is virtual: the test advances `now` and calls `service`.
#![allow(dead_code, missing_docs)]

use std::vec::Vec;
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_derp::frame::{FrameType, encode_header};
use tdongle_tailnet_derp::handshake::{CLIENT_INFO_BODY_LEN, CLIENT_INFO_JSON};
use tdongle_tailnet_derp::{Action, Event, Link, LinkEvent, MAGIC, State, Target, Timing};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;

pub const TXQ: usize = 8192;
pub type TestLink = Link<TXQ>;

#[derive(Default)]
pub struct Pipe {
    pub d: Vec<u8>,
    pub rd: usize,
    pub visible: usize,
    pub hold: bool,
}

impl Pipe {
    pub fn push(&mut self, data: &[u8]) {
        self.d.extend_from_slice(data);
        if !self.hold {
            self.visible = self.d.len();
        }
    }
    pub fn release(&mut self) {
        self.hold = false;
        self.visible = self.d.len();
    }
    pub fn avail(&self) -> usize {
        self.visible - self.rd
    }
    pub fn reset(&mut self) {
        self.d.clear();
        self.rd = 0;
        self.visible = 0;
        self.hold = false;
    }
}

/// The negotiation token (`ml_negotiation.h` reduced to what the link needs: one holder, FIFO waiters).
#[derive(Default)]
pub struct Neg {
    pub holder: Option<usize>,
    pub queue: Vec<usize>,
    pub grants: u32,
}

impl Neg {
    pub fn want(&mut self, id: usize) {
        if self.holder != Some(id) && !self.queue.contains(&id) {
            self.queue.push(id);
        }
    }
    pub fn try_grant(&mut self, id: usize) -> bool {
        if self.holder.is_none() && self.queue.first() == Some(&id) {
            self.queue.remove(0);
            self.holder = Some(id);
            self.grants += 1;
            true
        } else {
            false
        }
    }
    pub fn release(&mut self, id: usize) {
        if self.holder == Some(id) {
            self.holder = None;
        }
        self.queue.retain(|&q| q != id);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    Closed,
    Dns,
    Tcp,
    TlsAt(u64),
    Up,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sv {
    WaitReq,
    WaitCi,
    Ready,
}

pub struct Fake {
    pub name: &'static str,
    pub id: usize,
    pub link: TestLink,
    pub rng: TestRng,
    pub server_secret: Key32,
    pub server_pub: Key32,
    // knobs
    pub read_chunk: usize,
    pub write_chunk: usize,
    pub write_blocked: bool,
    pub http_silent: bool,
    pub no_server_info: bool,
    pub bad_server_info: bool,
    pub transport_delay_ms: u64,
    pub transport_hang: bool,
    pub clock_valid: bool,
    // transport + pipes
    pub transport: Transport,
    pub s2c: Pipe,
    pub c2s: Pipe,
    pub pending: Option<(Vec<u8>, usize)>,
    sv: Sv,
    parsed: usize,
    // server-side measurements
    pub note_preferred: u32,
    pub pongs_seen: u32,
    pub ci_seen: u32,
    pub server_saw: u32,
    pub server_bad: u32,
    pub max_tx_latency: u64,
    // client-side measurements
    pub delivered: u32,
    pub delivered_bad: u32,
    pub max_rx_latency: u64,
    pub connected_events: u32,
    pub disconnected_events: u32,
    pub failed_events: u32,
    pub deferred_events: u32,
    pub stale_events: u32,
    pub transports_opened: u32,
    pub transports_closed: u32,
    pub sends_total: u32,
    /// Every `Send` after the link was told to go down (for "no I/O after failure").
    pub restarting: Vec<(u32, u32)>,
    pub healths: Vec<Vec<u8>>,
    pub peer_gone: u32,
    pub actions: u32,
    pub last_action_failed_at: Option<u64>,
    now: u64,
}

fn key_from(seed: u8) -> Key32 {
    Key32(core::array::from_fn(|i| seed.wrapping_mul(29).wrapping_add(i as u8 * 3 + 7)))
}

pub fn stamped(ts: u64, seq: u32, len: usize) -> Vec<u8> {
    let mut v = std::vec![0u8; len.max(12)];
    v[..8].copy_from_slice(&ts.to_le_bytes());
    v[8..12].copy_from_slice(&seq.to_le_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(12) {
        *b = (seq.wrapping_mul(31) as u8).wrapping_add(i as u8);
    }
    v
}

fn check_stamped(p: &[u8]) -> Option<(u64, u32)> {
    if p.len() < 12 {
        return None;
    }
    let ts = u64::from_le_bytes(p[..8].try_into().unwrap());
    let seq = u32::from_le_bytes(p[8..12].try_into().unwrap());
    (12..p.len()).all(|i| p[i] == (seq.wrapping_mul(31) as u8).wrapping_add(i as u8)).then_some((ts, seq))
}

pub fn recv_frame(src: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = encode_header(FrameType::RECV_PACKET, (32 + payload.len()) as u32).to_vec();
    v.extend_from_slice(&[src; 32]);
    v.extend_from_slice(payload);
    v
}

pub fn raw_frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut v = encode_header(ty, body.len() as u32).to_vec();
    v.extend_from_slice(body);
    v
}

impl Fake {
    pub fn new(name: &'static str, id: usize) -> Fake {
        let server_secret = key_from(100 + id as u8);
        let server_pub = x25519::public(&server_secret);
        let secret = key_from(id as u8 + 1);
        let link = Link::new(secret, Target::new(id as u16 + 1, "derp.test", 443), Timing::DEFAULT);
        Fake {
            name,
            id,
            link,
            rng: TestRng(0x1234_5678 + id as u64),
            server_secret,
            server_pub,
            read_chunk: 0,
            write_chunk: 0,
            write_blocked: false,
            http_silent: false,
            no_server_info: false,
            bad_server_info: false,
            transport_delay_ms: 30,
            transport_hang: false,
            clock_valid: true,
            transport: Transport::Closed,
            s2c: Pipe::default(),
            c2s: Pipe::default(),
            pending: None,
            sv: Sv::WaitReq,
            parsed: 0,
            note_preferred: 0,
            pongs_seen: 0,
            ci_seen: 0,
            server_saw: 0,
            server_bad: 0,
            max_tx_latency: 0,
            delivered: 0,
            delivered_bad: 0,
            max_rx_latency: 0,
            connected_events: 0,
            disconnected_events: 0,
            failed_events: 0,
            deferred_events: 0,
            stale_events: 0,
            transports_opened: 0,
            transports_closed: 0,
            sends_total: 0,
            restarting: Vec::new(),
            healths: Vec::new(),
            peer_gone: 0,
            actions: 0,
            last_action_failed_at: None,
            now: 0,
        }
    }

    pub fn state(&self) -> State {
        self.link.state()
    }

    /// Feed one event to the link and carry out what it asks.
    pub fn step(&mut self, now: u64, ev: Event<'_>, neg: &mut Neg) {
        self.now = now;
        let mut out: Vec<Owned> = Vec::new();
        {
            let mut sink = |a: Action<'_>| out.push(Owned::from(a));
            self.link.handle(now, ev, &mut self.rng, &mut sink);
        }
        self.apply(now, out, neg);
    }

    pub fn enqueue(&mut self, now: u64, seq: u32, len: usize, neg: &mut Neg) -> Result<(), tdongle_tailnet_derp::TxDrop> {
        let payload = stamped(now, seq, len);
        let mut out: Vec<Owned> = Vec::new();
        let r = {
            let mut sink = |a: Action<'_>| out.push(Owned::from(a));
            self.link.send_packet(now, &[0xD0; 32], &payload, &mut sink)
        };
        self.apply(now, out, neg);
        r
    }

    fn apply(&mut self, now: u64, acts: Vec<Owned>, neg: &mut Neg) {
        for a in acts {
            self.actions += 1;
            match a {
                Owned::Notify(LinkEvent::Connected) => self.connected_events += 1,
                Owned::Notify(LinkEvent::Disconnected) => self.disconnected_events += 1,
                Owned::Notify(LinkEvent::ConnectFailed) => {
                    self.failed_events += 1;
                    self.last_action_failed_at = Some(now);
                }
                Owned::Notify(LinkEvent::RxStale) => self.stale_events += 1,
                Owned::Notify(LinkEvent::ClockDeferred) => self.deferred_events += 1,
                Owned::WantToken => neg.want(self.id),
                Owned::ReleaseToken => neg.release(self.id),
                Owned::Dial => {
                    self.transports_opened += 1;
                    self.s2c.reset();
                    self.c2s.reset();
                    self.sv = Sv::WaitReq;
                    self.parsed = 0;
                    self.pending = None;
                    self.transport = Transport::Dns;
                }
                Owned::StartTls => {
                    self.transport = Transport::TlsAt(now + self.transport_delay_ms);
                }
                Owned::Send(b) => {
                    assert!(self.pending.is_none(), "{}: a second send while one is outstanding", self.name);
                    assert!(self.transport != Transport::Closed, "{}: send on a closed transport", self.name);
                    self.sends_total += 1;
                    self.pending = Some((b, 0));
                }
                Owned::Close => {
                    self.transports_closed += 1;
                    self.transport = Transport::Closed;
                    self.pending = None;
                }
                Owned::Deliver { src, payload } => match check_stamped(&payload) {
                    Some((ts, _)) if src == [0xAA; 32] => {
                        self.delivered += 1;
                        self.max_rx_latency = self.max_rx_latency.max(now - ts);
                    }
                    _ => self.delivered_bad += 1,
                },
                Owned::PeerGone => self.peer_gone += 1,
                Owned::Health(h) => self.healths.push(h),
                Owned::Restarting(a, b) => self.restarting.push((a, b)),
            }
        }
    }

    /// One service pass of the driver for this member (what the shared task does per pass).
    pub fn service(&mut self, now: u64, neg: &mut Neg) {
        self.now = now;
        self.step(now, Event::ClockValid(self.clock_valid), neg);
        if self.link.want_token() && neg.try_grant(self.id) {
            self.step(now, Event::TokenGranted, neg);
        }
        match self.transport {
            Transport::Dns => {
                self.transport = Transport::Tcp;
                self.step(now, Event::Dns(true), neg);
            }
            Transport::Tcp => {
                self.transport = Transport::Up;
                // TCP is up; TLS is next and is the transport_delay stage
                self.step(now, Event::Connected(true), neg);
            }
            Transport::TlsAt(t) if now >= t && !self.transport_hang => {
                self.transport = Transport::Up;
                self.step(now, Event::TlsDone(true), neg);
            }
            _ => {}
        }
        // short writes: keep writing what the transport accepts this pass (a socket accepts as much as its buffer holds)
        for _ in 0..4096 {
            let Some((buf, off)) = self.pending.take() else { break };
            if self.write_blocked || self.transport == Transport::Closed {
                self.pending = Some((buf, off));
                break;
            }
            let rest = buf.len() - off;
            let n = if self.write_chunk == 0 { rest } else { rest.min(self.write_chunk) };
            self.c2s.push(&buf[off..off + n]);
            let off = off + n;
            if off == buf.len() {
                self.step(now, Event::TxProgress, neg);
                self.step(now, Event::TxDone, neg);
            } else {
                self.pending = Some((buf, off));
                self.step(now, Event::TxProgress, neg);
            }
        }
        if self.transport == Transport::Up || self.state() >= State::Upgrade {
            for _ in 0..8192 {
                let avail = self.s2c.avail();
                if avail == 0 || self.transport == Transport::Closed {
                    break;
                }
                let n = if self.read_chunk == 0 { avail } else { avail.min(self.read_chunk) };
                let chunk = self.s2c.d[self.s2c.rd..self.s2c.rd + n].to_vec();
                self.s2c.rd += n;
                self.step(now, Event::Bytes(&chunk), neg);
            }
        }
        self.step(now, Event::Timer, neg);
    }

    pub fn server_send(&mut self, ts: u64, seq: u32, plen: usize) {
        let f = recv_frame(0xAA, &stamped(ts, seq, plen));
        self.s2c.push(&f);
    }

    /// The server side: parse what the client wrote, answer.
    pub fn server_poll(&mut self, now: u64) {
        loop {
            let avail = self.c2s.d.len() - self.parsed;
            match self.sv {
                Sv::WaitReq => {
                    let d = &self.c2s.d;
                    let Some(end) = (self.parsed..d.len().saturating_sub(3)).find(|&i| &d[i..i + 4] == b"\r\n\r\n").map(|i| i + 4) else { return };
                    let req = std::str::from_utf8(&d[self.parsed..end]).unwrap();
                    assert!(req.starts_with("GET /derp HTTP/1.1\r\n"), "{req}");
                    assert!(req.contains("Upgrade: DERP\r\n") && req.contains("Connection: Upgrade\r\n"), "{req}");
                    assert!(req.contains("Host: derp.test\r\n"), "{req}");
                    self.parsed = end;
                    if self.http_silent {
                        return;
                    }
                    self.s2c.push(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n");
                    let mut body = MAGIC.to_vec();
                    body.extend_from_slice(&self.server_pub.0);
                    self.s2c.push(&raw_frame(FrameType::SERVER_KEY, &body));
                    self.sv = Sv::WaitCi;
                }
                Sv::WaitCi => {
                    if avail < 5 {
                        return;
                    }
                    let h = &self.c2s.d[self.parsed..];
                    let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
                    if avail < 5 + len {
                        return;
                    }
                    assert_eq!(h[0], FrameType::CLIENT_INFO.0);
                    assert_eq!(len, CLIENT_INFO_BODY_LEN);
                    let body = h[5..5 + len].to_vec();
                    self.parsed += 5 + len;
                    let client_pub = Key32(body[..32].try_into().unwrap());
                    assert_eq!(client_pub, self.link.public_key(), "ClientInfo names our node key");
                    let nonce: [u8; 24] = body[32..56].try_into().unwrap();
                    let mut boxed = body[56..].to_vec();
                    nacl::box_open(&self.server_secret, &client_pub, &nonce, &mut boxed).expect("the server opens the ClientInfo box");
                    assert_eq!(&boxed[16..], CLIENT_INFO_JSON);
                    self.ci_seen += 1;
                    if !self.no_server_info {
                        let json = br#"{"version":2,"TokenBucketBytesPerSecond":0}"#;
                        let nonce = [self.ci_seen as u8; 24];
                        let mut sb = std::vec![0u8; 24 + 16 + json.len()];
                        sb[..24].copy_from_slice(&nonce);
                        sb[40..].copy_from_slice(json);
                        nacl::box_seal(&self.server_secret, &client_pub, &nonce, &mut sb[24..]).unwrap();
                        if self.bad_server_info {
                            sb[30] ^= 0x55;
                        }
                        self.s2c.push(&raw_frame(FrameType::SERVER_INFO, &sb));
                    }
                    self.sv = Sv::Ready;
                }
                Sv::Ready => {
                    if avail < 5 {
                        return;
                    }
                    let h = &self.c2s.d[self.parsed..];
                    let ty = FrameType(h[0]);
                    let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
                    if avail < 5 + len {
                        return;
                    }
                    let body = h[5..5 + len].to_vec();
                    match ty {
                        FrameType::NOTE_PREFERRED => {
                            if body == [1] {
                                self.note_preferred += 1
                            } else {
                                self.server_bad += 1
                            }
                        }
                        FrameType::PONG => {
                            self.pongs_seen += 1;
                            if len != 8 {
                                self.server_bad += 1;
                            }
                        }
                        FrameType::SEND_PACKET => match (body.get(..32), body.get(32..).and_then(check_stamped)) {
                            (Some(d), Some((ts, _))) if d == [0xD0; 32] => {
                                self.server_saw += 1;
                                self.max_tx_latency = self.max_tx_latency.max(now - ts);
                            }
                            _ => self.server_bad += 1,
                        },
                        _ => self.server_bad += 1, // a frame type we never send: the stream is desynchronised
                    }
                    self.parsed += 5 + len;
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum Owned {
    Notify(LinkEvent),
    WantToken,
    ReleaseToken,
    Dial,
    StartTls,
    Send(Vec<u8>),
    Close,
    Deliver { src: [u8; 32], payload: Vec<u8> },
    PeerGone,
    Health(Vec<u8>),
    Restarting(u32, u32),
}

impl From<Action<'_>> for Owned {
    fn from(a: Action<'_>) -> Owned {
        match a {
            Action::Notify(e) => Owned::Notify(e),
            Action::WantToken => Owned::WantToken,
            Action::ReleaseToken => Owned::ReleaseToken,
            Action::Dial { host, port, .. } => {
                assert_eq!((host, port), ("derp.test", 443));
                Owned::Dial
            }
            Action::StartTls { host } => {
                assert_eq!(host, "derp.test");
                Owned::StartTls
            }
            Action::Send(b) => Owned::Send(b.to_vec()),
            Action::Close => Owned::Close,
            Action::DeliverPacket { src_key, payload } => Owned::Deliver { src: *src_key, payload: payload.to_vec() },
            Action::PeerGone { .. } => Owned::PeerGone,
            Action::Health(h) => Owned::Health(h.to_vec()),
            Action::ServerRestarting { reconnect_in_ms, try_for_ms } => Owned::Restarting(reconnect_in_ms, try_for_ms),
        }
    }
}
