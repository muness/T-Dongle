//! Shared harness: two WireGuard nodes in one process, a sequential index allocator, and a packet dispatcher that does what the runtime does.
#![allow(dead_code)]

use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_wg::cookie::{CookieChecker, Screen, screen};
use tdongle_tailnet_wg::msg::{CookieReply, Initiation, MsgType, Response, TransportHeader, classify, transport_len};
use tdongle_tailnet_wg::*;

/// Sequential indices, never 0.
pub struct Seq {
    pub next: u32,
    pub released: Vec<u32>,
    pub fail: bool,
}
impl Seq {
    pub fn new(start: u32) -> Self {
        Seq { next: start, released: Vec::new(), fail: false }
    }
}
impl IndexAllocator for Seq {
    fn allocate(&mut self) -> Option<u32> {
        if self.fail {
            return None;
        }
        self.next += 1;
        Some(self.next)
    }
    fn release(&mut self, i: u32) {
        self.released.push(i);
    }
}

pub fn private_key(seed: u8) -> Key32 {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(1);
    }
    Key32(k)
}

pub fn wall(now_ms: u64) -> WallClock {
    WallClock { unix_secs: 1_700_000_000 + now_ms / 1000, nanos: ((now_ms % 1000) * 1_000_000) as u32 }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Event {
    /// Datagram to send back.
    Reply(Vec<u8>),
    /// Payload delivered (the whole decrypted body, padding included).
    Payload(Vec<u8>),
    Keepalive,
    /// First datagram on a responder session (payload empty for a keepalive).
    Confirmed(Vec<u8>),
    Established,
    CookieStored,
    Dropped(Dropped),
}

pub struct Side {
    pub id: Identity,
    pub cold: PeerCold,
    pub hot: PeerHot,
    pub rng: TestRng,
    pub idx: Seq,
    pub checker: CookieChecker,
    pub drops: DropCounters,
    pub src: Vec<u8>,
}

impl Side {
    pub fn new(seed: u8, other_seed: u8, psk: Option<Key32>, idx_start: u32) -> Side {
        let id = Identity::new(&private_key(seed)).unwrap();
        let other = Identity::new(&private_key(other_seed)).unwrap();
        let cold = PeerCold::new(&id, other.public().clone(), psk).unwrap();
        Side {
            id,
            cold,
            hot: PeerHot::new(),
            rng: TestRng(0x1234_5678 + seed as u64),
            idx: Seq::new(idx_start),
            checker: CookieChecker::new(),
            drops: DropCounters::new(),
            src: vec![192, 0, 2, seed, 0x1f, 0x90],
        }
    }

    /// A side from explicit key material (the interoperability tests).
    pub fn with_keys(private: &Key32, other_public: &Key32, psk: Option<Key32>, idx_start: u32, rng_seed: u64) -> Side {
        let id = Identity::new(private).unwrap();
        let cold = PeerCold::new(&id, other_public.clone(), psk).unwrap();
        Side {
            id,
            cold,
            hot: PeerHot::new(),
            rng: TestRng(rng_seed),
            idx: Seq::new(idx_start),
            checker: CookieChecker::new(),
            drops: DropCounters::new(),
            src: vec![203, 0, 113, 7, 0xc3, 0x50],
        }
    }

    pub fn initiate(&mut self, now: u64) -> Result<[u8; 148], InitError> {
        self.hot.create_initiation(&self.id, &self.cold, now, wall(now), &mut self.rng, &mut self.idx)
    }

    /// Receive one datagram as the runtime would.
    pub fn on_packet(&mut self, pkt: &mut [u8], now: u64, under_load: bool, src: &[u8]) -> Event {
        let ev = self.on_packet_inner(pkt, now, under_load, src);
        if let Event::Dropped(d) = &ev {
            self.drops.bump(*d);
        }
        ev
    }

    fn on_packet_inner(&mut self, pkt: &mut [u8], now: u64, under_load: bool, src: &[u8]) -> Event {
        let t = match classify(pkt) {
            Ok(t) => t,
            Err(e) => return Event::Dropped(e.into()),
        };
        match t {
            MsgType::Initiation | MsgType::Response => {
                match screen(&self.id, &mut self.checker, pkt, src, under_load, now, &mut self.rng) {
                    Screen::Pass => {}
                    Screen::CookieReply(r) => return Event::Reply(r.to_vec()),
                    Screen::Drop(d) => return Event::Dropped(d),
                }
                if t == MsgType::Initiation {
                    let m = Initiation::parse(pkt).unwrap();
                    let st = match self.id.consume_initiation_stage1(&m) {
                        Ok(s) => s,
                        Err(d) => return Event::Dropped(d),
                    };
                    if st.peer_public() != self.cold.public() {
                        return Event::Dropped(Dropped::HsUnknownPeer);
                    }
                    if let Err(d) = self.hot.consume_initiation(&st, &self.cold, now) {
                        return Event::Dropped(d);
                    }
                    match self.hot.create_response(&self.id, &self.cold, now, &mut self.rng, &mut self.idx) {
                        Ok(r) => Event::Reply(r.to_vec()),
                        Err(_) => Event::Dropped(Dropped::HsNoHandshake),
                    }
                } else {
                    let m = Response::parse(pkt).unwrap();
                    match self.hot.consume_response(&self.id, &self.cold, &m, now) {
                        Ok(_) => Event::Established,
                        Err(d) => Event::Dropped(d),
                    }
                }
            }
            MsgType::CookieReply => {
                let m = CookieReply::parse(pkt).unwrap();
                match self.hot.consume_cookie_reply(&self.cold, &m, now) {
                    Ok(()) => Event::CookieStored,
                    Err(d) => Event::Dropped(d),
                }
            }
            MsgType::Transport => match self.hot.decrypt(pkt, now) {
                Ok(o) if o.keepalive => {
                    if o.confirmed {
                        Event::Confirmed(vec![])
                    } else {
                        Event::Keepalive
                    }
                }
                Ok(o) => {
                    let p = pkt[16..16 + o.plain_len].to_vec();
                    if o.confirmed { Event::Confirmed(p) } else { Event::Payload(p) }
                }
                Err(d) => Event::Dropped(d),
            },
        }
    }

    pub fn rx(&mut self, pkt: &[u8], now: u64) -> Event {
        let mut p = pkt.to_vec();
        let src = self.src.clone();
        self.on_packet(&mut p, now, false, &src)
    }

    /// Seal `payload` (empty = keepalive) with the one-call path.
    pub fn send(&mut self, payload: &[u8], now: u64) -> Result<Vec<u8>, TxError> {
        let mut buf = vec![0u8; transport_len(payload.len()) + 7];
        buf[16..16 + payload.len()].copy_from_slice(payload);
        let n = self.hot.encrypt(&mut buf, payload.len(), now)?;
        assert_eq!(n, transport_len(payload.len()));
        buf.truncate(n);
        Ok(buf)
    }

    pub fn keepalive(&mut self, now: u64) -> Result<Vec<u8>, TxError> {
        self.send(&[], now)
    }
}

pub fn pair(psk: Option<Key32>) -> (Side, Side) {
    // A is the initiator, B the responder; both know each other. Index ranges differ so a mix-up is visible.
    (Side::new(1, 2, psk.clone(), 0x1000), Side::new(2, 1, psk, 0x2000))
}

/// Run the full handshake A -> B -> A at `now`; afterwards A (initiator) can send, B is unconfirmed.
pub fn handshake(a: &mut Side, b: &mut Side, now: u64) {
    let init = a.initiate(now).unwrap();
    let Event::Reply(resp) = b.rx(&init, now) else { panic!("no response") };
    assert_eq!(a.rx(&resp, now), Event::Established);
}

/// Handshake plus the keepalive that confirms B's session.
pub fn handshake_confirmed(a: &mut Side, b: &mut Side, now: u64) {
    handshake(a, b, now);
    let ka = a.keepalive(now).unwrap();
    assert_eq!(b.rx(&ka, now), Event::Confirmed(vec![]));
}

pub fn header(p: &[u8]) -> TransportHeader {
    TransportHeader::parse(p).unwrap()
}
