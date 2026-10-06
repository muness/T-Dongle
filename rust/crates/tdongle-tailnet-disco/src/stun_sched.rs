//! The membership's STUN schedule: what `ml_stun.c` and the STUN half of `ml_coord.c` do, without sockets.
//!
//! **Sockets.** The C keeps no IPv4 STUN socket while the DISCO socket exists: IPv4 binding requests leave from the DISCO socket so that the NAT mapping
//! STUN reports is the mapping peers will hit (a separate socket would report a port nobody sends DISCO to). Only IPv6 gets a socket of its own, and the
//! C opens it whether or not the board has a global IPv6 address. [`SockKind`] says which socket a request leaves from and a response arrives on; the
//! firmware's socket budget is therefore **one UDP socket shared with DISCO** (plus [`SockKind::Stun6`], which research item R7 says to open only with a
//! global IPv6 address, plus the transient [`SockKind::Netcheck`] one, which can be the DISCO socket too: responses are told apart by transaction id).
//!
//! **Schedule** (constants from `microlink_internal.h`): the first request goes to the primary server (`derp9.tailscale.com:3478`, or the DERP home
//! region's STUN node), three attempts two seconds apart, then the same to the fallback (`stun.l.google.com:19302`); the first answer starts a NAT check
//! (one request to the fallback; mapped ports that differ mean the mapping varies by destination, direct connections are unlikely); everything repeats
//! every 23 s so the NAT mapping stays open and the endpoint stays fresh.
//!
//! **Matching.** The C kept one outstanding transaction id per address family and accepted *any* response while it had none (after the first answer).
//! Here every request has its own transaction id per role; a response matches exactly one outstanding request or is `Unmatched`. A request is forgotten
//! after [`StunConfig::response_timeout_ms`].

use crate::addr::Ep;
use crate::stun::{self, REQUEST_LEN, StunError, TxId};
use tdongle_tailnet_types::{Counter, Entropy, Millis};

/// Tailscale's primary STUN host (the DERP home region's node when the DERP map has one).
pub const PRIMARY_HOST: &str = "derp9.tailscale.com";
/// Its port.
pub const PRIMARY_PORT: u16 = 3478;
/// The fallback host.
pub const FALLBACK_HOST: &str = "stun.l.google.com";
/// Its port.
pub const FALLBACK_PORT: u16 = 19302;

/// Which socket a request leaves from (and a response arrives on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockKind {
    /// The DISCO UDP socket (IPv4). The default for IPv4 STUN, so the mapping reported is the DISCO one.
    Disco4,
    /// A dedicated IPv4 STUN socket, only when there is no DISCO socket.
    Stun4,
    /// The dedicated IPv6 STUN socket.
    Stun6,
    /// The netcheck probe socket (may be the DISCO socket).
    Netcheck,
}

/// A STUN request to transmit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunSend {
    /// From which socket.
    pub sock: SockKind,
    /// To where.
    pub to: Ep,
    /// The 40-byte request.
    pub packet: [u8; REQUEST_LEN],
}

/// Whom a request went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// The primary server over IPv4.
    Primary4 = 0,
    /// The fallback server over IPv4 (also the NAT-check peer).
    Fallback4 = 1,
    /// The primary server over IPv6.
    Primary6 = 2,
}

const ROLES: usize = 3;

/// The servers, resolved by the caller (DNS is not ours). Set what exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Servers {
    /// Primary, IPv4.
    pub primary4: Option<Ep>,
    /// Fallback, IPv4.
    pub fallback4: Option<Ep>,
    /// Primary, IPv6.
    pub primary6: Option<Ep>,
}

/// Timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunConfig {
    /// Gap between attempts at one server (`ML_STUN_RETRY_INTERVAL_MS`).
    pub retry_interval_ms: u64,
    /// Attempts per server (`ML_STUN_MAX_RETRIES`).
    pub max_retries: u8,
    /// A fresh sequence this often (`ML_STUN_RESTUN_INTERVAL_MS`).
    pub restun_interval_ms: u64,
    /// An unanswered request is forgotten after this long.
    pub response_timeout_ms: u64,
}

impl StunConfig {
    /// The C's values.
    pub const DEFAULT: StunConfig = StunConfig { retry_interval_ms: 2_000, max_retries: 3, restun_interval_ms: 23_000, response_timeout_ms: 5_000 };
}

impl Default for StunConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Counts of everything the schedule does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StunCounters {
    /// Requests handed out for IPv4.
    pub tx4: Counter,
    /// Requests handed out for IPv6.
    pub tx6: Counter,
    /// Retries (the second and third attempt at one server).
    pub retries: Counter,
    /// Times the schedule moved on to the fallback server.
    pub fallbacks: Counter,
    /// A sequence that had nobody to ask.
    pub no_server: Counter,
    /// Responses accepted.
    pub rx_ok: Counter,
    /// Datagrams that are not STUN.
    pub rx_not_stun: Counter,
    /// STUN datagrams that do not parse as a mapped-address response.
    pub rx_bad: Counter,
    /// Well-formed responses matching no outstanding request.
    pub rx_unmatched: Counter,
    /// Responses of the wrong address family for the request, or that changed nothing and needed no action.
    pub rx_ignored: Counter,
    /// Requests that were never answered.
    pub timeouts: Counter,
    /// NAT checks completed.
    pub nat_checks: Counter,
    /// Periodic re-probes started.
    pub periodic: Counter,
}

/// What a received datagram did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunEvent {
    /// Not STUN.
    NotStun,
    /// STUN, but not a usable binding response.
    Bad(StunError),
    /// A response to nothing we are waiting for.
    Unmatched,
    /// Our public IPv4 endpoint as the server saw it.
    Public4 {
        /// The endpoint.
        ep: Ep,
        /// It differs from the previous one: send the control plane an endpoint update.
        changed: bool,
    },
    /// Our public IPv6 endpoint.
    Public6 {
        /// The endpoint.
        ep: Ep,
        /// Differs from the previous one.
        changed: bool,
    },
    /// The NAT check finished.
    NatChecked {
        /// The mapped port depends on the destination: symmetric NAT, direct connections unlikely.
        varies: bool,
    },
    /// Matched, but of no use (wrong family, or a late answer from the other server).
    Ignored,
}

#[derive(Debug, Clone, Copy)]
struct Out {
    txid: TxId,
    sent: u64,
}

/// The schedule. About 150 bytes.
#[derive(Debug, Clone)]
pub struct StunScheduler {
    cfg: StunConfig,
    servers: Servers,
    v4_sock: SockKind,
    out: [Option<Out>; ROLES],
    last_probe: u64,
    last_restun: u64,
    public4: Option<Ep>,
    public6: Option<Ep>,
    secondary_port: u16,
    retry_count: u8,
    using_fallback: bool,
    active: bool,
    nat_checked: bool,
    nat_varies: bool,
    /// Counters.
    pub counters: StunCounters,
}

impl Default for StunScheduler {
    fn default() -> Self {
        Self::new(StunConfig::DEFAULT)
    }
}

impl StunScheduler {
    /// Bytes of state.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// Idle until [`begin`](StunScheduler::begin).
    pub const fn new(cfg: StunConfig) -> Self {
        StunScheduler {
            cfg,
            servers: Servers { primary4: None, fallback4: None, primary6: None },
            v4_sock: SockKind::Disco4,
            out: [None; ROLES],
            last_probe: 0,
            last_restun: 0,
            public4: None,
            public6: None,
            secondary_port: 0,
            retry_count: 0,
            using_fallback: false,
            active: false,
            nat_checked: false,
            nat_varies: false,
            counters: StunCounters {
                tx4: Counter(0),
                tx6: Counter(0),
                retries: Counter(0),
                fallbacks: Counter(0),
                no_server: Counter(0),
                rx_ok: Counter(0),
                rx_not_stun: Counter(0),
                rx_bad: Counter(0),
                rx_unmatched: Counter(0),
                rx_ignored: Counter(0),
                timeouts: Counter(0),
                nat_checks: Counter(0),
                periodic: Counter(0),
            },
        }
    }

    /// Replace the server set (after DNS, or when the DERP home region changes).
    pub fn set_servers(&mut self, s: Servers) {
        self.servers = s;
    }
    /// The IPv4 socket requests leave from (default [`SockKind::Disco4`]).
    pub fn set_v4_socket(&mut self, s: SockKind) {
        self.v4_sock = s;
    }
    /// Our public IPv4 endpoint, once a server told us.
    pub fn public4(&self) -> Option<Ep> {
        self.public4
    }
    /// Our public IPv6 endpoint.
    pub fn public6(&self) -> Option<Ep> {
        self.public6
    }
    /// `Some(true)` if the NAT mapping varies by destination; `None` until the check ran.
    pub fn mapping_varies(&self) -> Option<bool> {
        self.nat_checked.then_some(self.nat_varies)
    }
    /// The mapped port the NAT check's second server reported.
    pub fn secondary_port(&self) -> u16 {
        self.secondary_port
    }
    /// A retry sequence is running (no answer yet).
    pub fn retrying(&self) -> bool {
        self.retry_count > 0 && self.retry_count <= self.cfg.max_retries
    }
    /// Forget results and outstanding requests (the network changed: new IP, new NAT).
    pub fn reset(&mut self) {
        let (cfg, servers, sock, counters) = (self.cfg, self.servers, self.v4_sock, self.counters);
        *self = Self::new(cfg);
        self.servers = servers;
        self.v4_sock = sock;
        self.counters = counters;
    }

    fn send(&mut self, role: Role, now: Millis, rng: &mut dyn Entropy, out: &mut dyn FnMut(StunSend)) -> bool {
        let (to, sock) = match role {
            Role::Primary4 => (self.servers.primary4, self.v4_sock),
            Role::Fallback4 => (self.servers.fallback4, self.v4_sock),
            Role::Primary6 => (self.servers.primary6, SockKind::Stun6),
        };
        let Some(to) = to else {
            return false;
        };
        let mut txid = [0u8; stun::TXID_LEN];
        rng.fill(&mut txid);
        let mut packet = [0u8; REQUEST_LEN];
        stun::build_request(&txid, &mut packet);
        self.out[role as usize] = Some(Out { txid, sent: now });
        if role == Role::Primary6 {
            self.counters.tx6.bump()
        } else {
            self.counters.tx4.bump()
        }
        out(StunSend { sock, to, packet });
        true
    }

    /// Start a fresh sequence: primary (or fallback, if there is no primary), and IPv6 alongside.
    fn sequence(&mut self, now: Millis, rng: &mut dyn Entropy, out: &mut dyn FnMut(StunSend)) {
        self.active = true;
        self.retry_count = 1;
        self.using_fallback = false;
        self.last_probe = now;
        self.last_restun = now;
        let mut sent = false;
        if self.servers.primary4.is_some() {
            sent |= self.send(Role::Primary4, now, rng, out);
        } else if self.servers.fallback4.is_some() {
            self.using_fallback = true;
            sent |= self.send(Role::Fallback4, now, rng, out);
        }
        sent |= self.send(Role::Primary6, now, rng, out);
        if !sent {
            self.counters.no_server.bump();
        }
    }

    /// The coordination task reached its STUN step (`COORD_STUN_PROBE`): send the first requests.
    pub fn begin(&mut self, now: Millis, rng: &mut dyn Entropy, out: &mut dyn FnMut(StunSend)) {
        self.sequence(now, rng, out);
    }

    /// Run the retry and periodic timers. Call at least once a second.
    pub fn poll(&mut self, now: Millis, rng: &mut dyn Entropy, out: &mut dyn FnMut(StunSend)) {
        if !self.active {
            return;
        }
        for slot in &mut self.out {
            if slot.is_some_and(|o| now.saturating_sub(o.sent) > self.cfg.response_timeout_ms) {
                *slot = None;
                self.counters.timeouts.bump();
            }
        }
        // Three attempts a server, two seconds apart, then the fallback.
        if self.retrying() && now.saturating_sub(self.last_probe) > self.cfg.retry_interval_ms {
            if !self.using_fallback && self.servers.primary4.is_some() {
                self.send(Role::Primary4, now, rng, out);
            } else if self.servers.fallback4.is_some() {
                self.send(Role::Fallback4, now, rng, out);
            }
            self.last_probe = now;
            self.retry_count += 1;
            self.counters.retries.bump();
            if self.retry_count > self.cfg.max_retries && !self.using_fallback {
                self.using_fallback = true;
                self.retry_count = 1;
                self.counters.fallbacks.bump();
                if self.servers.fallback4.is_some() {
                    self.send(Role::Fallback4, now, rng, out);
                    self.last_probe = now;
                }
            }
        }
        // A fresh sequence every 23 s keeps the NAT mapping open and the endpoint fresh.
        if now.saturating_sub(self.last_restun) > self.cfg.restun_interval_ms {
            self.counters.periodic.bump();
            self.sequence(now, rng, out);
        }
    }

    /// A datagram arrived on a STUN socket (or on the DISCO socket and did not look like DISCO).
    pub fn on_datagram(&mut self, now: Millis, data: &[u8], rng: &mut dyn Entropy, out: &mut dyn FnMut(StunSend)) -> StunEvent {
        if !stun::is_stun(data) {
            self.counters.rx_not_stun.bump();
            return StunEvent::NotStun;
        }
        let r = match stun::parse_response(data) {
            Ok(r) => r,
            Err(e) => {
                self.counters.rx_bad.bump();
                return StunEvent::Bad(e);
            }
        };
        let Some(role) = [Role::Primary4, Role::Fallback4, Role::Primary6].into_iter().find(|&role| self.out[role as usize].is_some_and(|o| o.txid == r.txid))
        else {
            self.counters.rx_unmatched.bump();
            return StunEvent::Unmatched;
        };
        self.out[role as usize] = None;
        let ep = r.mapped;
        match role {
            Role::Primary6 | Role::Primary4 if ep.is_v4() == (role == Role::Primary6) => {
                // An IPv4 answer to an IPv6 request or the reverse: matched, but not an address of the family we asked about.
                self.counters.rx_ignored.bump();
                StunEvent::Ignored
            }
            Role::Primary6 => {
                self.counters.rx_ok.bump();
                let changed = self.public6 != Some(ep);
                self.public6 = Some(ep);
                self.retry_count = 0;
                StunEvent::Public6 { ep, changed }
            }
            Role::Primary4 => {
                self.counters.rx_ok.bump();
                let changed = self.public4 != Some(ep);
                self.public4 = Some(ep);
                self.retry_count = 0;
                // The first answer starts the NAT check: ask the fallback server too and compare the mapped ports.
                if !self.nat_checked && self.servers.fallback4.is_some() {
                    self.send(Role::Fallback4, now, rng, out);
                }
                StunEvent::Public4 { ep, changed }
            }
            Role::Fallback4 if !ep.is_v4() => {
                self.counters.rx_ignored.bump();
                StunEvent::Ignored
            }
            Role::Fallback4 => {
                self.counters.rx_ok.bump();
                if self.public4.is_none() || self.using_fallback {
                    // The primary is not answering: the fallback's answer is our endpoint (no NAT check is possible without two servers).
                    let changed = self.public4 != Some(ep);
                    self.public4 = Some(ep);
                    self.retry_count = 0;
                    StunEvent::Public4 { ep, changed }
                } else if !self.nat_checked {
                    self.secondary_port = ep.port();
                    self.nat_checked = true;
                    self.nat_varies = self.public4.is_some_and(|p| p.port() != ep.port());
                    self.counters.nat_checks.bump();
                    StunEvent::NatChecked { varies: self.nat_varies }
                } else {
                    self.counters.rx_ignored.bump();
                    StunEvent::Ignored
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tdongle_tailnet_types::test_util::TestRng;
    extern crate std;
    use std::vec::Vec;

    const P4: Ep = Ep::v4([1, 1, 1, 1], 3478);
    const F4: Ep = Ep::v4([2, 2, 2, 2], 19302);
    const P6: Ep = Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 3478);

    fn run(s: &mut StunScheduler, now: u64, rng: &mut TestRng) -> Vec<StunSend> {
        let mut v = Vec::new();
        s.poll(now, rng, &mut |x| v.push(x));
        v
    }
    fn answer(tx: &StunSend, mapped: Ep) -> Vec<u8> {
        let mut b = [0u8; 64];
        let txid: TxId = tx.packet[8..20].try_into().unwrap();
        let n = stun::build_response(&txid, &mapped, &mut b).unwrap();
        b[..n].to_vec()
    }

    #[test]
    fn first_requests_nat_check_and_periodic() {
        let mut rng = TestRng(5);
        let mut s = StunScheduler::default();
        s.set_servers(Servers { primary4: Some(P4), fallback4: Some(F4), primary6: Some(P6) });
        let mut sent = Vec::new();
        s.begin(1000, &mut rng, &mut |x| sent.push(x));
        assert_eq!(sent.len(), 2);
        assert_eq!((sent[0].sock, sent[0].to), (SockKind::Disco4, P4));
        assert_eq!((sent[1].sock, sent[1].to), (SockKind::Stun6, P6));
        assert!(stun::parse_binding_request(&sent[0].packet).is_ok());
        // primary answers: public endpoint and a NAT check request to the fallback
        let mut nat = Vec::new();
        let ev = s.on_datagram(1030, &answer(&sent[0], Ep::v4([9, 9, 9, 9], 40000)), &mut rng, &mut |x| nat.push(x));
        assert_eq!(ev, StunEvent::Public4 { ep: Ep::v4([9, 9, 9, 9], 40000), changed: true });
        assert_eq!(nat.len(), 1);
        assert_eq!(nat[0].to, F4);
        assert!(!s.retrying());
        // a replay of the same response matches nothing now
        assert_eq!(s.on_datagram(1031, &answer(&sent[0], Ep::v4([9, 9, 9, 9], 40000)), &mut rng, &mut |_| {}), StunEvent::Unmatched);
        // the fallback sees a different port: symmetric NAT
        let ev = s.on_datagram(1060, &answer(&nat[0], Ep::v4([9, 9, 9, 9], 40001)), &mut rng, &mut |_| {});
        assert_eq!(ev, StunEvent::NatChecked { varies: true });
        assert_eq!(s.mapping_varies(), Some(true));
        // v6 answer
        let m6 = Ep::v6([0x26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], 41641);
        assert_eq!(s.on_datagram(1070, &answer(&sent[1], m6), &mut rng, &mut |_| {}), StunEvent::Public6 { ep: m6, changed: true });
        // nothing until 23 s have passed, then a fresh sequence from the same sockets
        assert!(run(&mut s, 20_000, &mut rng).is_empty());
        let again = run(&mut s, 24_001, &mut rng);
        assert_eq!(again.len(), 2);
        assert_eq!(s.counters.periodic.get(), 1);
        // same mapping again: not a change
        assert_eq!(
            s.on_datagram(24_050, &answer(&again[0], Ep::v4([9, 9, 9, 9], 40000)), &mut rng, &mut |_| {}),
            StunEvent::Public4 { ep: Ep::v4([9, 9, 9, 9], 40000), changed: false }
        );
    }

    #[test]
    fn cone_nat() {
        let mut rng = TestRng(6);
        let mut s = StunScheduler::default();
        s.set_servers(Servers { primary4: Some(P4), fallback4: Some(F4), primary6: None });
        let mut sent = Vec::new();
        s.begin(0, &mut rng, &mut |x| sent.push(x));
        let mut nat = Vec::new();
        let pub4 = Ep::v4([9, 9, 9, 9], 40000);
        s.on_datagram(5, &answer(&sent[0], pub4), &mut rng, &mut |x| nat.push(x));
        assert_eq!(s.on_datagram(9, &answer(&nat[0], pub4), &mut rng, &mut |_| {}), StunEvent::NatChecked { varies: false });
        assert_eq!(s.secondary_port(), 40000);
    }

    /// Three attempts two seconds apart at the primary, then the fallback (ml_coord.c).
    #[test]
    fn retries_then_fallback() {
        let mut rng = TestRng(7);
        let mut s = StunScheduler::default();
        s.set_servers(Servers { primary4: Some(P4), fallback4: Some(F4), primary6: None });
        let mut first = Vec::new();
        s.begin(0, &mut rng, &mut |x| first.push(x));
        assert_eq!(first.len(), 1);
        assert!(run(&mut s, 2000, &mut rng).is_empty()); // not yet: strictly more than 2 s
        let r1 = run(&mut s, 2001, &mut rng);
        assert_eq!(r1.iter().map(|x| x.to).collect::<Vec<_>>(), [P4]);
        let r2 = run(&mut s, 4002, &mut rng);
        assert_eq!(r2.iter().map(|x| x.to).collect::<Vec<_>>(), [P4]);
        // third retry crosses MAX: it goes to the primary once more (count 4 > 3) and the fallback follows at once
        let r3 = run(&mut s, 6003, &mut rng);
        assert_eq!(r3.iter().map(|x| x.to).collect::<Vec<_>>(), [P4, F4]);
        assert_eq!(s.counters.fallbacks.get(), 1);
        // the fallback answers while the primary is dead: that is our endpoint
        let pub4 = Ep::v4([8, 8, 4, 4], 1234);
        assert_eq!(s.on_datagram(6020, &answer(&r3[1], pub4), &mut rng, &mut |_| {}), StunEvent::Public4 { ep: pub4, changed: true });
        assert!(!s.retrying());
        assert_eq!(s.mapping_varies(), None);
    }

    #[test]
    fn no_servers_and_bad_input() {
        let mut rng = TestRng(8);
        let mut s = StunScheduler::default();
        s.begin(0, &mut rng, &mut |_| panic!());
        assert_eq!(s.counters.no_server.get(), 1);
        assert_eq!(s.on_datagram(1, b"hello", &mut rng, &mut |_| {}), StunEvent::NotStun);
        let mut b = [0u8; 20];
        b[..2].copy_from_slice(&[1, 1]);
        b[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(s.on_datagram(1, &b, &mut rng, &mut |_| {}), StunEvent::Bad(StunError::MalformedAttrs));
        s.set_servers(Servers { primary4: Some(P4), fallback4: None, primary6: None });
        let mut sent = Vec::new();
        s.begin(10, &mut rng, &mut |x| sent.push(x));
        // a v6 mapped address in answer to a v4 request is not usable
        let v6 = Ep::v6([0x26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], 5);
        assert_eq!(s.on_datagram(11, &answer(&sent[0], v6), &mut rng, &mut |_| {}), StunEvent::Ignored);
        assert_eq!(s.public4(), None);
        // unanswered requests are forgotten
        let mut sent = Vec::new();
        s.begin(100, &mut rng, &mut |x| sent.push(x));
        run(&mut s, 5_200, &mut rng);
        assert_eq!(s.on_datagram(5_201, &answer(&sent[0], Ep::v4([1, 2, 3, 4], 5)), &mut rng, &mut |_| {}), StunEvent::Unmatched);
        assert!(s.counters.timeouts.get() >= 1);
    }
}
