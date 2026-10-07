//! A simulated network around real engines: a DERP relay model (forwards `DerpSend` as a `DerpPacket` by node key), a UDP network with configurable
//! loss, delay, cuts and address-restricted NAT filtering, a STUN server, and USB "hosts" that send and echo UDP datagrams through the alias NAT.
#![allow(dead_code, clippy::too_many_arguments)]

use std::collections::{BTreeMap, HashSet};
use std::string::String;
use std::vec::Vec;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::stun;
use tdongle_tailnet_dns::Client;
use tdongle_tailnet_engine::{DerpNote, Engine, Handled, Input, MemberConfig, NetmapEvent, Out, RamDirectory};
use tdongle_tailnet_map::DerpCert;
use tdongle_tailnet_map::types::{DerpMap, DerpNode, DerpRegion, Group, PeerAction, PeerRecord, SelfNode};
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_types::{FixedStr, Key32};

pub type Dir = RamDirectory<3, 16, 32>;
pub type Eng = Engine<Dir, 3, 8, 12, 64, 64, 24>;

pub const HOST_IP: u32 = 0xc0a8_4d02; // 192.168.77.2
pub const DERP_IP: [u8; 4] = [192, 0, 2, 1];
pub const STUN_IP: [u8; 4] = [192, 0, 2, 1];

#[derive(Clone)]
pub struct Keys {
    pub node_priv: Key32,
    pub node_pub: Key32,
    pub disco_priv: Key32,
    pub disco_pub: Key32,
}

pub fn keys(seed: u8) -> Keys {
    let mk = |s: u8| {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = s.wrapping_mul(31).wrapping_add(i as u8 * 7 + 3);
        }
        Key32(b)
    };
    let (np, dp) = (mk(seed), mk(seed ^ 0x80));
    Keys { node_pub: x25519::public(&np), disco_pub: x25519::public(&dp), node_priv: np, disco_priv: dp }
}

#[derive(Debug, Clone)]
pub enum Owned {
    Udp { dst: Ep, data: Vec<u8> },
    Stun { dst: Ep, data: Vec<u8> },
    Derp { dst: [u8; 32], data: Vec<u8> },
    Host(Vec<u8>),
    Dns(Vec<u8>),
    DnsForward(Vec<u8>),
    DerpConnect { region: u16, host: String, port: u16 },
    DerpClose,
    HomeDerp(u16),
    Endpoint(Ep),
    Ready(bool),
    Gone,
    Token(bool),
    Wake(Option<u64>),
}

pub fn own(o: Out<'_>) -> Owned {
    match o {
        Out::SendUdp { dst, data, .. } => Owned::Udp { dst, data: data.to_vec() },
        Out::SendStun { dst, data, .. } => Owned::Stun { dst, data: data.to_vec() },
        Out::DerpSend { dst, data, .. } => Owned::Derp { dst: *dst, data: data.to_vec() },
        Out::HostPacket { data } => Owned::Host(data.to_vec()),
        Out::DnsAnswer { data, .. } => Owned::Dns(data.to_vec()),
        Out::DnsForward { data, .. } => Owned::DnsForward(data.to_vec()),
        Out::DerpConnect { region, host, port, .. } => Owned::DerpConnect { region, host: host.into(), port },
        Out::DerpClose { .. } => Owned::DerpClose,
        Out::HomeDerp { region, .. } => Owned::HomeDerp(region),
        Out::EndpointLearned { ep, .. } => Owned::Endpoint(ep),
        Out::MemberReady { ready, .. } => Owned::Ready(ready),
        Out::MemberGone { .. } => Owned::Gone,
        Out::WantToken { .. } => Owned::Token(true),
        Out::ReleaseToken { .. } => Owned::Token(false),
        Out::Wake(w) => Owned::Wake(w),
    }
}

// ---- packets -------------------------------------------------------------------------------------------------------------------------------

fn sum(p: &[u8], mut s: u32) -> u32 {
    let mut i = 0;
    while i + 1 < p.len() {
        s += u32::from(p[i]) << 8 | u32::from(p[i + 1]);
        i += 2;
    }
    if i < p.len() {
        s += u32::from(p[i]) << 8;
    }
    s
}
fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

pub fn udp_packet(src: u32, dst: u32, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let n = 28 + payload.len();
    let mut p = std::vec![0u8; n];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(n as u16).to_be_bytes());
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.to_be_bytes());
    p[16..20].copy_from_slice(&dst.to_be_bytes());
    let c = fold(sum(&p[..20], 0));
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    let c = fold(sum(&p[20..], sum(&p[12..20], 17 + (8 + payload.len()) as u32)));
    p[26..28].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
    p
}

pub struct Udp<'a> {
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(p: &[u8]) -> Option<Udp<'_>> {
    if p.len() < 28 || p[0] != 0x45 || p[9] != 17 {
        return None;
    }
    Some(Udp {
        src: u32::from_be_bytes([p[12], p[13], p[14], p[15]]),
        dst: u32::from_be_bytes([p[16], p[17], p[18], p[19]]),
        sport: u16::from_be_bytes([p[20], p[21]]),
        dport: u16::from_be_bytes([p[22], p[23]]),
        payload: &p[28..],
    })
}

/// A DNS A query for `name`.
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = std::vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// The A record of a DNS answer (the last four bytes of a one-answer reply), `None` for no answer.
pub fn dns_answer_ip(a: &[u8]) -> Option<u32> {
    if a.len() < 12 || a[7] != 1 || (a[3] & 15) != 0 {
        return None;
    }
    let n = a.len();
    Some(u32::from_be_bytes([a[n - 4], a[n - 3], a[n - 2], a[n - 1]]))
}

// ---- netmap --------------------------------------------------------------------------------------------------------------------------------

pub fn derp_map() -> DerpMap {
    derp_map_of(&[(1, DERP_IP)])
}

/// A DERP map with these (region id, STUN/DERP node address) regions, at most four.
pub fn derp_map_of(regions: &[(u16, [u8; 4])]) -> DerpMap {
    let node = |host: &str, ip: [u8; 4]| {
        let mut h = FixedStr::new();
        h.set(host);
        DerpNode { hostname: h, ipv4: Some(ip), ipv6: None, stun_port: 3478, derp_port: 443, stun_only: false, can_port80: false, cert: DerpCert::Invalid }
    };
    let empty = || DerpNode {
        hostname: FixedStr::new(),
        ipv4: None,
        ipv6: None,
        stun_port: 0,
        derp_port: 0,
        stun_only: false,
        can_port80: false,
        cert: DerpCert::Invalid,
    };
    let region = |id: u16, ip: Option<[u8; 4]>| {
        let mut code = FixedStr::new();
        code.set("tst");
        let mut name = FixedStr::new();
        name.set("Test");
        let n0 = ip.map_or_else(empty, |ip| node(&std::format!("derp{id}.example"), ip));
        DerpRegion { region_id: id, code, name, nodes: [n0, empty()], node_count: u8::from(ip.is_some()), avoid: false }
    };
    let mut rs = [region(0, None), region(0, None), region(0, None), region(0, None)];
    for (i, (id, ip)) in regions.iter().take(4).enumerate() {
        rs[i] = region(*id, Some(*ip));
    }
    DerpMap { regions: rs, count: regions.len().min(4) as u8 }
}

pub fn peer_record(id: u64, ip: u32, k: &Keys, name: &str, endpoint: Option<Ep>) -> PeerRecord {
    let mut r = PeerRecord::new(PeerAction::Add, Group::Peers);
    r.node_id = Some(id);
    r.vpn_ip = ip;
    r.node_key = k.node_pub.clone();
    r.disco_key = k.disco_pub.clone();
    r.name.set(name);
    r.home_derp = 1;
    if let Some(e) = endpoint
        && let Some(ip) = e.v4_u32()
    {
        r.endpoints[0] = tdongle_tailnet_map::types::Endpoint { ip, port: e.port() };
        r.endpoint_count = 1;
    }
    r
}

// ---- the simulation ------------------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
enum Ev {
    Udp { to: usize, src: Ep, data: Vec<u8> },
    Derp { to: usize, src: [u8; 32], data: Vec<u8> },
    Tick { node: usize },
}

pub struct SimNode {
    pub eng: Box<Eng>,
    pub rng: TestRng,
    pub member: u32,
    pub keys: Keys,
    pub pub_ep: Ep,
    pub vpn_ip: u32,
    pub name: String,
    pub host_rx: Vec<Vec<u8>>,
    pub dns_rx: Vec<Vec<u8>>,
    pub nat_filter: bool,
    pub permit: HashSet<u32>,
    pub derp_up: bool,
    pub echo_to: Option<(u32, u16)>,
    pub scheduled: Option<u64>,
    pub last_wake: Option<u64>,
    pub outs: Vec<Owned>,
    pub echoes: u32,
    /// Everything this node sends is lost (until cleared).
    pub muted: bool,
}

pub struct Sim {
    pub now: u64,
    pub nodes: Vec<SimNode>,
    q: BTreeMap<(u64, u64), Ev>,
    seq: u64,
    pub udp_up: bool,
    pub loss_pct: u32,
    pub delay: u64,
    pub derp_delay: u64,
    lossrng: TestRng,
    pub nat_dropped: u32,
    pub udp_delivered: u32,
    pub derp_delivered: u32,
    pub ticks: u32,
    /// Drop every DISCO datagram (UDP and DERP): forces WireGuard-first traffic.
    pub drop_disco: bool,
    /// STUN servers by address, with their one-way delay.
    pub stun_servers: std::collections::HashMap<[u8; 4], u64>,
    /// The DERP regions every netmap carries.
    pub regions: Vec<(u16, [u8; 4])>,
    /// Persistent keepalive of nodes added from now on, seconds.
    pub keepalive_s: u16,
}

impl Sim {
    pub fn new(seed: u64) -> Sim {
        Sim {
            now: 1_000,
            nodes: Vec::new(),
            q: BTreeMap::new(),
            seq: 0,
            udp_up: true,
            loss_pct: 0,
            delay: 20,
            derp_delay: 40,
            lossrng: TestRng(seed | 1),
            nat_dropped: 0,
            udp_delivered: 0,
            derp_delivered: 0,
            ticks: 0,
            drop_disco: false,
            stun_servers: std::collections::HashMap::from([(STUN_IP, 40)]),
            regions: std::vec![(1, DERP_IP)],
            keepalive_s: 0,
        }
    }

    fn push(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.q.insert((at, self.seq), ev);
    }

    /// Add a dongle with one membership (id 1) and register it with the engine (not yet enabled).
    pub fn add_node(&mut self, name: &str, seed: u8, vpn_ip: u32, pub_ep: Ep) -> usize {
        let k = keys(seed);
        let eng = Box::new(Eng::new(Dir::new()));
        let mut n = SimNode {
            eng,
            rng: TestRng(0x1234_5678 + u64::from(seed)),
            member: 1,
            keys: k.clone(),
            pub_ep,
            vpn_ip,
            name: name.into(),
            host_rx: Vec::new(),
            dns_rx: Vec::new(),
            nat_filter: false,
            permit: HashSet::new(),
            derp_up: true,
            echo_to: None,
            scheduled: None,
            last_wake: None,
            outs: Vec::new(),
            echoes: 0,
            muted: false,
        };
        let mut label = FixedStr::new();
        label.set("net");
        let cfg = MemberConfig {
            id: 1,
            node_private: k.node_priv,
            disco_private: k.disco_priv,
            label,
            priority_peer_ip: 0,
            persistent_keepalive_s: self.keepalive_s,
            enabled: false,
        };
        let mut o = |o: Out<'_>| {
            n.outs.push(own(o));
            true
        };
        n.eng.handle(self.now, Input::MemberAdded(&cfg), &mut n.rng, &mut o);
        self.nodes.push(n);
        self.nodes.len() - 1
    }

    /// Feed one input to node `i` and process everything it emits.
    pub fn input(&mut self, i: usize, input: Input<'_>) -> Handled {
        let now = self.now;
        let (h, outs) = {
            let n = &mut self.nodes[i];
            let mut outs = Vec::new();
            let mut o = |o: Out<'_>| {
                outs.push(own(o));
                true
            };
            let h = n.eng.handle(now, input, &mut n.rng, &mut o);
            (h, outs)
        };
        for o in outs {
            self.dispatch(i, o);
        }
        h
    }

    fn dispatch(&mut self, i: usize, o: Owned) {
        if self.nodes[i].muted && matches!(o, Owned::Udp { .. } | Owned::Stun { .. } | Owned::Derp { .. }) {
            self.nodes[i].outs.push(o);
            return;
        }
        match o.clone() {
            Owned::Udp { dst, data } | Owned::Stun { dst, data } => self.route_udp(i, dst, data),
            Owned::Derp { dst, data } => self.route_derp(i, dst, data),
            Owned::Host(p) => self.nodes[i].host_rx.push(p),
            Owned::Dns(a) => self.nodes[i].dns_rx.push(a),
            Owned::Wake(w) => {
                self.nodes[i].last_wake = w;
                if let Some(t) = w {
                    let t = t.max(self.now);
                    if self.nodes[i].scheduled != Some(t) {
                        self.nodes[i].scheduled = Some(t);
                        self.push(t, Ev::Tick { node: i });
                    }
                }
            }
            _ => {}
        }
        self.nodes[i].outs.push(o);
    }

    fn route_udp(&mut self, from: usize, dst: Ep, data: Vec<u8>) {
        if !self.udp_up || (self.drop_disco && data.starts_with(&[0x54, 0x53])) {
            return;
        }
        if self.loss_pct > 0 {
            let mut b = [0u8; 1];
            tdongle_tailnet_types::Entropy::fill(&mut self.lossrng, &mut b);
            if u32::from(b[0]) * 100 / 256 < self.loss_pct {
                return;
            }
        }
        let src = self.nodes[from].pub_ep;
        if let Some(ip) = dst.v4_octets().map(u32::from_be_bytes) {
            self.nodes[from].permit.insert(ip);
        }
        // the STUN server (also the DERP host's STUN port)
        if let Some(d) = dst.v4_octets().and_then(|o| self.stun_servers.get(&o).copied()) {
            if let Ok(txid) = stun::parse_binding_request(&data) {
                let mut r = [0u8; 64];
                if let Ok(n) = stun::build_response(&txid, &src, &mut r) {
                    let at = self.now + d * 2;
                    self.push(at, Ev::Udp { to: from, src: dst, data: r[..n].to_vec() });
                }
            }
            return;
        }
        let Some(to) = self.nodes.iter().position(|n| n.pub_ep == dst) else { return };
        let src_ip = src.v4_octets().map(u32::from_be_bytes).unwrap_or(0);
        if self.nodes[to].nat_filter && !self.nodes[to].permit.contains(&src_ip) {
            self.nat_dropped += 1;
            return;
        }
        let at = self.now + self.delay;
        self.push(at, Ev::Udp { to, src, data });
    }

    fn route_derp(&mut self, from: usize, dst: [u8; 32], data: Vec<u8>) {
        if !self.nodes[from].derp_up || (self.drop_disco && data.starts_with(&[0x54, 0x53])) {
            return;
        }
        let Some(to) = self.nodes.iter().position(|n| n.keys.node_pub.0 == dst && n.derp_up) else { return };
        let src = self.nodes[from].keys.node_pub.0;
        let at = self.now + self.derp_delay;
        self.push(at, Ev::Derp { to, src, data });
    }

    /// Run until virtual time `until`, delivering events and ticks.
    pub fn run_until(&mut self, until: u64) {
        while let Some((&(t, s), _)) = self.q.iter().next() {
            if t > until {
                break;
            }
            let ev = self.q.remove(&(t, s)).unwrap();
            self.now = t.max(self.now);
            match ev {
                Ev::Udp { to, src, mut data } => {
                    let m = self.nodes[to].member;
                    self.udp_delivered += 1;
                    self.input(to, Input::Udp { member: m, src, data: &mut data });
                }
                Ev::Derp { to, src, mut data } => {
                    let m = self.nodes[to].member;
                    self.derp_delivered += 1;
                    self.input(to, Input::DerpPacket { member: m, src: &src, data: &mut data });
                }
                Ev::Tick { node } => {
                    if self.nodes[node].scheduled == Some(t) {
                        self.nodes[node].scheduled = None;
                    }
                    self.ticks += 1;
                    let before = self.now;
                    self.input(node, Input::Tick);
                    // the engine must make progress: its next wake is later than now (or nothing)
                    if let Some(w) = self.nodes[node].last_wake {
                        assert!(w > before, "wake {w} not after tick at {before}: the runtime would spin");
                    }
                }
            }
            self.pump_hosts();
        }
        self.now = until.max(self.now);
    }

    /// The USB hosts' echo behaviour: every packet that reaches a host is answered to the same alias with the roles swapped.
    pub fn pump_hosts(&mut self) {
        for i in 0..self.nodes.len() {
            if self.nodes[i].echo_to.is_none() {
                continue;
            }
            let pkts: Vec<Vec<u8>> = std::mem::take(&mut self.nodes[i].host_rx);
            for p in pkts {
                let Some(u) = parse_udp(&p) else { continue };
                let (alias, sport, dport, payload) = (u.src, u.dport, u.sport, u.payload.to_vec());
                self.nodes[i].echoes += 1;
                self.host_send_to(i, alias, sport, dport, &payload);
            }
        }
    }

    pub fn enable(&mut self, i: usize) {
        let m = self.nodes[i].member;
        self.input(i, Input::MemberEnabled { member: m });
        if self.nodes[i].derp_up {
            self.input(i, Input::DerpLinkEvent { member: m, event: DerpNote::Connected });
        }
    }

    /// Install a netmap: self, DERP map, domain and these peers, committed authoritatively.
    pub fn netmap(&mut self, i: usize, peers: &[PeerRecord]) {
        let m = self.nodes[i].member;
        let mut me = SelfNode::new();
        me.vpn_ip = Some(self.nodes[i].vpn_ip);
        let mut nm = FixedStr::new();
        nm.set(&std::format!("{}.net.ts.net", self.nodes[i].name));
        me.name = Some(nm);
        me.home_derp = 1;
        let mut dom = FixedStr::new();
        dom.set("net.ts.net");
        let evs: Vec<NetmapEvent> = [
            NetmapEvent::SelfNode(me),
            NetmapEvent::Derp(derp_map_of(&self.regions)),
            NetmapEvent::Domain(dom),
            NetmapEvent::ControlTime { secs: 1_800_000_000, nanos: 0 },
        ]
        .into_iter()
        .chain(peers.iter().cloned().map(NetmapEvent::Peer))
        .chain([NetmapEvent::Commit { authoritative: true, self_expired: false }])
        .collect();
        for e in &evs {
            assert_ne!(self.input(i, Input::Netmap { member: m, event: e }), Handled::Refused);
        }
    }

    /// The alias of `peer_name` as the host's resolver answers it.
    pub fn resolve(&mut self, i: usize, name: &str) -> Option<u32> {
        let q = dns_query(7, name);
        self.nodes[i].dns_rx.clear();
        self.input(i, Input::Dns { client: Client { addr: HOST_IP, port: 5353 }, data: &q });
        self.nodes[i].dns_rx.pop().and_then(|a| dns_answer_ip(&a))
    }

    /// The host of node `i` sends a UDP datagram to `alias`.
    pub fn host_send_to(&mut self, i: usize, alias: u32, sport: u16, dport: u16, payload: &[u8]) -> Handled {
        let p = udp_packet(HOST_IP, alias, sport, dport, payload);
        let mut buf = std::vec![0u8; 1500];
        buf[..p.len()].copy_from_slice(&p);
        self.input(i, Input::HostPacket { buf: &mut buf, len: p.len() })
    }

    pub fn check(&self) {
        for n in &self.nodes {
            n.eng.check_identities().unwrap_or_else(|e| panic!("{}: identity {e:?}\n{:#?}", n.name, n.eng.status(self.now)));
        }
    }
}

// ---- a single engine without a network -------------------------------------------------------------------------------------------------------

/// One engine with several memberships and a directory of fake peers, fed directly.
pub struct SoloA<const A: usize, D: tdongle_tailnet_engine::PeerDirectory = Dir> {
    pub eng: Box<Engine<D, 3, 8, 12, A, 64, 24>>,
    pub rng: TestRng,
    pub now: u64,
    pub outs: Vec<Owned>,
    pub host_rx: Vec<Vec<u8>>,
    pub wake: Option<u64>,
}

/// The usual configuration (64-entry alias cache).
pub type Solo = SoloA<64>;

impl<const A: usize> SoloA<A> {
    pub fn new(seed: u64) -> Self {
        Self::with_dir(seed, Dir::new())
    }
}

impl<const A: usize, D: tdongle_tailnet_engine::PeerDirectory> SoloA<A, D> {
    pub fn with_dir(seed: u64, dir: D) -> Self {
        SoloA { eng: Box::new(Engine::new(dir)), rng: TestRng(seed | 1), now: 1_000, outs: Vec::new(), host_rx: Vec::new(), wake: None }
    }

    pub fn input(&mut self, input: Input<'_>) -> Handled {
        let now = self.now;
        let mut outs = Vec::new();
        let mut o = |o: Out<'_>| {
            outs.push(own(o));
            true
        };
        let h = self.eng.handle(now, input, &mut self.rng, &mut o);
        for o in outs {
            match &o {
                Owned::Host(p) => self.host_rx.push(p.clone()),
                Owned::Wake(w) => self.wake = *w,
                _ => {}
            }
            self.outs.push(o);
        }
        h
    }

    /// Add membership `id` (label `m<id>`), start it, and give it a netmap of `n_peers` peers `p1..` at 100.64.<id>.<k>.
    pub fn member(&mut self, id: u32, n_peers: u32, priority_peer_ip: u32) {
        let k = keys(id as u8);
        let mut label = FixedStr::new();
        label.set(&std::format!("m{id}"));
        let cfg =
            MemberConfig { id, node_private: k.node_priv, disco_private: k.disco_priv, label, priority_peer_ip, persistent_keepalive_s: 0, enabled: false };
        self.input(Input::MemberAdded(&cfg));
        let mut me = SelfNode::new();
        me.vpn_ip = Some(Self::ip(id, 250));
        let mut nm = FixedStr::new();
        nm.set(&std::format!("me.m{id}.ts.net"));
        me.name = Some(nm);
        me.home_derp = 1;
        let mut evs = std::vec![NetmapEvent::SelfNode(me), NetmapEvent::Derp(derp_map())];
        for p in 1..=n_peers {
            evs.push(NetmapEvent::Peer(peer_record(
                u64::from(id) * 1000 + u64::from(p),
                Self::ip(id, p),
                &Self::peer_keys(id, p),
                &std::format!("p{p}.m{id}.ts.net"),
                None,
            )));
        }
        evs.push(NetmapEvent::Commit { authoritative: true, self_expired: false });
        for e in &evs {
            assert_ne!(self.input(Input::Netmap { member: id, event: e }), Handled::Refused);
        }
        self.input(Input::MemberEnabled { member: id });
        self.input(Input::DerpLinkEvent { member: id, event: DerpNote::Connected });
    }

    pub fn ip(member: u32, peer: u32) -> u32 {
        0x6400_0000 | (member << 8) | peer
    }
    pub fn peer_keys(member: u32, peer: u32) -> Keys {
        keys((member * 16 + peer + 100) as u8)
    }

    pub fn alias(&mut self, member: u32, peer: u32) -> u32 {
        let q = dns_query(9, &std::format!("p{peer}.m{member}.tailnet"));
        let before = self.outs.len();
        self.input(Input::Dns { client: Client { addr: HOST_IP, port: 5000 }, data: &q });
        let a = self.outs[before..].iter().find_map(|o| if let Owned::Dns(a) = o { dns_answer_ip(a) } else { None });
        a.unwrap_or_else(|| panic!("no alias for p{peer}.m{member}"))
    }

    pub fn send(&mut self, alias: u32, len: usize) -> Handled {
        let p = udp_packet(HOST_IP, alias, 5000 + (alias & 0xff) as u16, 7, &std::vec![0xaa; len]);
        let mut buf = std::vec![0u8; 1500];
        buf[..p.len()].copy_from_slice(&p);
        self.input(Input::HostPacket { buf: &mut buf, len: p.len() })
    }

    pub fn advance(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            let step = self.wake.map_or(end, |w| w.min(end)).max(self.now + 1).min(end);
            self.now = step;
            self.input(Input::Tick);
        }
    }

    pub fn derp_up(&mut self) {
        let ids: Vec<u32> = self.eng.members_ids().collect();
        for id in ids {
            self.input(Input::DerpLinkEvent { member: id, event: DerpNote::Connected });
        }
    }

    pub fn resident(&self, member: u32) -> usize {
        self.eng.member(member).map_or(0, |m| m.mship.table.len())
    }
}
