//! Entry points the libfuzzer targets (`rust/fuzz/fuzz_targets/tailnet_engine_*.rs`), the proptest and the in-crate mini-fuzz share: a pair of engines wired
//! back to back, driven by a byte script. Whatever the script does (malformed datagrams, replays, flipped bits, duplicated and dropped packets, member
//! churn, netmap churn, heap pressure, refused outputs, time jumps) the engine must not panic, every packet must end in one counted outcome, the pool
//! and receiver-index invariants must hold, and the wake deadline must make progress. A panic here is a finding. Not part of the firmware's API.
//!
//! Script format: a stream of operations, each an opcode byte (`% 14`) followed by the parameters it reads (missing bytes read as zero). See
//! [`Chaos::step`].

extern crate std;

use crate::dir::RamDirectory;
use crate::engine::{Engine, Handled};
use crate::io::{DerpNote, Input, MemberConfig, NetmapEvent, Out};
use std::boxed::Box;
use std::collections::VecDeque;
use std::vec::Vec;
use tdongle_tailnet_admission::heap::ML_HB_FLOOR;
use tdongle_tailnet_admission::probe::HeapSnapshot;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_dns::Client;
use tdongle_tailnet_map::DerpCert;
use tdongle_tailnet_map::types::{DerpMap, DerpNode, DerpRegion, Group, PeerAction, PeerRecord, SelfNode};
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_types::{FixedStr, Key32};

/// The directory type of the harness.
pub type ChaosDir = RamDirectory<3, 12, 24>;
/// The engine type of the harness: the firmware's configuration.
pub type ChaosEngine = Engine<ChaosDir, 3, 8, 12, 64, 64, 24>;

const HOST_IP: u32 = 0xc0a8_4d02;
const EXTRA_PEERS: u32 = 5;
const HISTORY: usize = 48;

fn keys(seed: u32) -> (Key32, Key32) {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (seed as u8).wrapping_mul(29).wrapping_add((seed >> 8) as u8).wrapping_add(i as u8 * 5 + 1);
    }
    let k = Key32(b);
    (x25519::public(&k), k)
}

fn node_keys(node: usize, member: u32) -> ((Key32, Key32), (Key32, Key32)) {
    (keys(1 + node as u32 * 16 + member), keys(0x80 + node as u32 * 16 + member))
}

fn derp_map() -> DerpMap {
    let mut h = FixedStr::new();
    h.set("derp1.example");
    let node = DerpNode {
        hostname: h,
        ipv4: Some([192, 0, 2, 1]),
        ipv6: None,
        stun_port: 3478,
        derp_port: 443,
        stun_only: false,
        can_port80: false,
        cert: DerpCert::Invalid,
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
    let mut code = FixedStr::new();
    code.set("t");
    let r1 = DerpRegion { region_id: 1, code, name: FixedStr::new(), nodes: [node, empty()], node_count: 1, avoid: false };
    let none = || DerpRegion { region_id: 0, code: FixedStr::new(), name: FixedStr::new(), nodes: [empty(), empty()], node_count: 0, avoid: false };
    DerpMap { regions: [r1, none(), none(), none()], count: 1 }
}

#[derive(Clone, Debug)]
struct Msg {
    to: usize,
    member: u32,
    derp: bool,
    src: [u8; 32],
    ep: Ep,
    data: Vec<u8>,
}

struct Node {
    eng: Box<ChaosEngine>,
    rng: TestRng,
    wake: Option<u64>,
    present: [bool; 3],
    refuse: bool,
    pub_ep: Ep,
}

/// Two engines back to back, with an adversarial network between them.
pub struct Chaos {
    nodes: [Node; 2],
    now: u64,
    net: VecDeque<Msg>,
    history: Vec<Msg>,
    steps: u64,
    rr: TestRng,
}

struct Rd<'a> {
    d: &'a [u8],
    p: usize,
}

impl Rd<'_> {
    fn u8(&mut self) -> u8 {
        let v = self.d.get(self.p).copied().unwrap_or(0);
        self.p += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        u16::from(self.u8()) << 8 | u16::from(self.u8())
    }
    fn done(&self) -> bool {
        self.p >= self.d.len()
    }
}

impl core::fmt::Debug for Chaos {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Chaos(step {}, now {})", self.steps, self.now)
    }
}

impl Default for Chaos {
    fn default() -> Self {
        Self::new()
    }
}

impl Chaos {
    /// Both nodes with three memberships each, every membership knowing the other node's same membership plus a few unreachable peers.
    #[inline(always)]
    pub fn new() -> Chaos {
        let mk = |n: usize| Node {
            eng: Box::new(ChaosEngine::new(ChaosDir::new())),
            rng: TestRng(0x9e37_79b9 + n as u64 * 77),
            wake: None,
            present: [false; 3],
            refuse: false,
            pub_ep: Ep::v4([203, 0, 113, 1 + n as u8], 41641),
        };
        let mut c = Chaos { nodes: [mk(0), mk(1)], now: 1_000, net: VecDeque::new(), history: Vec::new(), steps: 0, rr: TestRng(99) };
        for node in 0..2 {
            for m in 1..=3 {
                c.add_member(node, m);
                c.netmap(node, m, 0xff, true);
                c.input(node, Input::MemberEnabled { member: m });
                c.input(node, Input::DerpLinkEvent { member: m, event: DerpNote::Connected });
            }
        }
        c
    }

    fn add_member(&mut self, node: usize, m: u32) {
        let ((_, np), (_, dp)) = node_keys(node, m);
        let mut label = FixedStr::new();
        label.set(["m1", "m2", "m3"][m as usize - 1]);
        let cfg = MemberConfig { id: m, node_private: np, disco_private: dp, label, priority_peer_ip: 0, persistent_keepalive_s: 0, enabled: false };
        self.input(node, Input::MemberAdded(&cfg));
        self.nodes[node].present[m as usize - 1] = true;
    }

    fn peer_ip(node: usize, m: u32, k: u32) -> u32 {
        0x6400_0000 | (m << 16) | ((node as u32 + 1) << 8) | k
    }

    /// Install a netmap for `member` of `node`: the other node's same membership plus the extra peers selected by `mask`; `commit` false aborts.
    fn netmap(&mut self, node: usize, m: u32, mask: u8, commit: bool) {
        let other = 1 - node;
        let mut me = SelfNode::new();
        me.vpn_ip = Some(Self::peer_ip(node, m, 250));
        let mut nm = FixedStr::new();
        nm.set(["me.m1.ts.net", "me.m2.ts.net", "me.m3.ts.net"][m as usize - 1]);
        me.name = Some(nm);
        me.home_derp = 1;
        let mut evs: Vec<NetmapEvent> = std::vec![NetmapEvent::SelfNode(me), NetmapEvent::Derp(derp_map())];
        let mut dom = FixedStr::new();
        dom.set(["m1.ts.net", "m2.ts.net", "m3.ts.net"][m as usize - 1]);
        evs.push(NetmapEvent::Domain(dom));
        evs.push(NetmapEvent::ControlTime { secs: 1_800_000_000, nanos: 0 });
        for k in 0..=EXTRA_PEERS {
            if k > 0 && mask & (1 << (k - 1)) == 0 {
                continue;
            }
            if k == 0 && mask & 0x80 == 0 && mask != 0xff {
                continue;
            }
            let (pk, dk) = if k == 0 {
                let ((np, _), (dp, _)) = node_keys(other, m);
                (np, dp)
            } else {
                (keys(0x400 + m * 16 + k).0, keys(0x500 + m * 16 + k).0)
            };
            let mut r = PeerRecord::new(PeerAction::Add, Group::Peers);
            r.node_id = Some(u64::from(m) * 100 + u64::from(k));
            r.vpn_ip = Self::peer_ip(other, m, if k == 0 { 1 } else { 10 + k });
            r.node_key = pk;
            r.disco_key = dk;
            r.name.set(&std::format!("p{k}.m{m}.ts.net"));
            r.home_derp = 1;
            if k == 0 {
                let ep = self.nodes[other].pub_ep;
                if let Some(ip) = ep.v4_u32() {
                    r.endpoints[0] = tdongle_tailnet_map::types::Endpoint { ip, port: ep.port() };
                    r.endpoint_count = 1;
                }
            }
            evs.push(NetmapEvent::Peer(r));
        }
        evs.push(if commit { NetmapEvent::Commit { authoritative: true, self_expired: false } } else { NetmapEvent::Abort });
        for e in &evs {
            self.input(node, Input::Netmap { member: m, event: e });
        }
    }

    fn input(&mut self, node: usize, input: Input<'_>) -> Handled {
        let now = self.now;
        let n = &mut self.nodes[node];
        let refuse = n.refuse;
        let mut msgs: Vec<Msg> = Vec::new();
        let mut wake = None;
        let pub_ep = n.pub_ep;
        let src_key = |m: u32| node_keys(node, m).0.0.0;
        let mut o = |o: Out<'_>| {
            match o {
                Out::SendUdp { member, dst: _, data } => msgs.push(Msg { to: 1 - node, member, derp: false, src: [0; 32], ep: pub_ep, data: data.to_vec() }),
                Out::DerpSend { member, data, .. } => {
                    msgs.push(Msg { to: 1 - node, member, derp: true, src: src_key(member), ep: pub_ep, data: data.to_vec() })
                }
                Out::Wake(w) => wake = Some(w),
                _ => {}
            }
            !refuse
        };
        let h = n.eng.handle(now, input, &mut n.rng, &mut o);
        if let Some(w) = wake {
            n.wake = w;
        }
        for m in msgs {
            if self.history.len() >= HISTORY {
                self.history.remove(0);
            }
            self.history.push(m.clone());
            self.net.push_back(m);
        }
        h
    }

    fn deliver(&mut self, m: &Msg) {
        // only to a membership that exists on the receiver by id (otherwise the engine counts a NoMember drop, which is also fine)
        let mut data = m.data.clone();
        if m.derp {
            let src = m.src;
            self.input(m.to, Input::DerpPacket { member: m.member, src: &src, data: &mut data });
        } else {
            self.input(m.to, Input::Udp { member: m.member, src: m.ep, data: &mut data });
        }
    }

    /// Advance virtual time to `t`, ticking each engine at its wake. Panics if an engine asks to be woken at or before the time it was just woken.
    fn advance_to(&mut self, t: u64) {
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 20_000, "wake loop does not terminate");
            let next = self.nodes.iter().enumerate().filter_map(|(i, n)| n.wake.map(|w| (w.max(self.now), i))).min();
            match next {
                Some((w, i)) if w <= t => {
                    self.now = w;
                    self.input(i, Input::Tick);
                    if let Some(nw) = self.nodes[i].wake
                        && nw <= self.now
                    {
                        let mut why = std::vec::Vec::new();
                        self.nodes[i].eng.deadlines(self.now, &mut |n, v| why.push((n, v)));
                        panic!("engine {i} asked to be woken at {nw} right after a tick at {}: {why:?}", self.now);
                    }
                }
                _ => break,
            }
        }
        self.now = self.now.max(t);
    }

    fn corrupt(&mut self, r: &mut Rd<'_>, d: &mut Vec<u8>) {
        for _ in 0..r.u8() % 4 {
            if d.is_empty() {
                break;
            }
            let i = usize::from(r.u16()) % d.len();
            d[i] ^= 1 << (r.u8() % 8);
        }
        match r.u8() % 8 {
            0 if !d.is_empty() => {
                let n = usize::from(r.u16()) % d.len();
                d.truncate(n);
            }
            1 => d.extend_from_slice(&[r.u8(), r.u8()]),
            _ => {}
        }
    }

    fn alias(&mut self, node: usize, m: u32, k: u32) -> Option<u32> {
        let name = std::format!("p{k}.m{m}.tailnet");
        let mut q = std::vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut ans = None;
        let now = self.now;
        let n = &mut self.nodes[node];
        let mut o = |o: Out<'_>| {
            if let Out::DnsAnswer { data, .. } = o
                && data.len() >= 16
                && data[7] == 1
            {
                ans = Some(u32::from_be_bytes([data[data.len() - 4], data[data.len() - 3], data[data.len() - 2], data[data.len() - 1]]));
            }
            true
        };
        n.eng.handle(now, Input::Dns { client: Client { addr: HOST_IP, port: 5353 }, data: &q }, &mut n.rng, &mut o);
        ans
    }

    /// Check what must hold after every step.
    pub fn check(&self) {
        for (i, n) in self.nodes.iter().enumerate() {
            if let Err(e) = n.eng.check_identities() {
                panic!("node {i}: identity {e:?} after {} steps", self.steps);
            }
        }
    }

    /// Run one operation from the script reader.
    fn step(&mut self, r: &mut Rd<'_>) {
        self.steps += 1;
        let op = r.u8() % 14;
        let node = usize::from(r.u8() & 1);
        let m = u32::from(r.u8() % 3) + 1;
        match op {
            // a packet from the host to a peer's alias
            0 | 1 => {
                let k = u32::from(r.u8()) % (EXTRA_PEERS + 1);
                let len = usize::from(r.u16()) % 1500;
                let a = match self.alias(node, m, k) {
                    Some(a) if !r.u8().is_multiple_of(8) => a,
                    _ => 0xc612_0000 | u32::from(r.u16()), // an alias nobody allocated
                };
                let sport = 1024 + u16::from(r.u8());
                let dport = if r.u8().is_multiple_of(2) { 40000 } else { u16::from(r.u8()) };
                let proto = if r.u8().is_multiple_of(8) { 6 } else { 17 };
                let mut p = std::vec![0u8; len.max(28)];
                p[0] = 0x45;
                let n = p.len() as u16;
                p[2..4].copy_from_slice(&n.to_be_bytes());
                p[6] = 0x40;
                p[8] = 64;
                p[9] = proto;
                p[12..16].copy_from_slice(&HOST_IP.to_be_bytes());
                p[16..20].copy_from_slice(&a.to_be_bytes());
                p[20..22].copy_from_slice(&sport.to_be_bytes());
                p[22..24].copy_from_slice(&dport.to_be_bytes());
                p[24..26].copy_from_slice(&(n - 20).to_be_bytes());
                // header checksum
                let mut s = 0u32;
                for c in p[..20].chunks(2) {
                    s += u32::from(c[0]) << 8 | u32::from(c[1]);
                }
                while s >> 16 != 0 {
                    s = (s & 0xffff) + (s >> 16);
                }
                p[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
                if r.u8().is_multiple_of(16) {
                    let i = usize::from(r.u16()) % p.len();
                    p[i] ^= 0x40;
                }
                let l = p.len();
                p.resize(1500, 0);
                self.input(node, Input::HostPacket { buf: &mut p, len: l });
            }
            // deliver the next queued packet, possibly damaged, duplicated or dropped
            2 | 3 => {
                if let Some(mut msg) = self.net.pop_front() {
                    let fate = r.u8() % 6;
                    if fate == 0 {
                        return;
                    }
                    self.corrupt(r, &mut msg.data);
                    self.deliver(&msg);
                    if fate == 1 {
                        self.deliver(&msg);
                    }
                }
            }
            // deliver everything
            4 => {
                let n = self.net.len().min(64);
                for _ in 0..n {
                    if let Some(msg) = self.net.pop_front() {
                        self.deliver(&msg);
                    }
                }
            }
            // replay something old, to the right node or the wrong one, under the right membership or another
            5 => {
                if !self.history.is_empty() {
                    let mut msg = self.history[usize::from(r.u8()) % self.history.len()].clone();
                    if r.u8().is_multiple_of(4) {
                        msg.to = node;
                    }
                    if r.u8().is_multiple_of(4) {
                        msg.member = m;
                    }
                    self.corrupt(r, &mut msg.data);
                    self.deliver(&msg);
                }
            }
            // garbage straight from the script
            6 => {
                let len = usize::from(r.u16()) % 1600;
                let mut d: Vec<u8> = (0..len).map(|_| r.u8()).collect();
                if r.u8().is_multiple_of(2) && !d.is_empty() {
                    d[0] = 1 + r.u8() % 4; // WireGuard-looking
                    if d.len() > 3 {
                        d[1] = 0;
                        d[2] = 0;
                        d[3] = 0;
                    }
                }
                let msg = Msg { to: node, member: m, derp: r.u8().is_multiple_of(2), src: [r.u8(); 32], ep: Ep::v4([198, 51, 100, r.u8()], 41641), data: d };
                self.deliver(&msg);
            }
            // time passes: to the next wake, or by a jump
            7 => {
                let ms = u64::from(r.u8()) * 37 + 1;
                self.advance_to(self.now + ms);
            }
            8 => {
                let ms = u64::from(r.u8()) * 1_000;
                self.advance_to(self.now + ms);
            }
            // membership churn
            9 => {
                let id = m;
                match r.u8() % 5 {
                    0 if !self.nodes[node].present[id as usize - 1] => {
                        self.add_member(node, id);
                        self.netmap(node, id, 0xff, true);
                    }
                    1 => {
                        self.input(node, Input::MemberEnabled { member: id });
                        self.input(node, Input::DerpLinkEvent { member: id, event: DerpNote::Connected });
                    }
                    2 => {
                        self.input(node, Input::MemberDisabled { member: id });
                    }
                    3 => {
                        self.input(node, Input::MemberRemoved { member: id });
                        self.nodes[node].present[id as usize - 1] = false;
                    }
                    _ => {
                        self.input(node, Input::DerpLinkEvent { member: id, event: DerpNote::Disconnected });
                    }
                }
            }
            // netmap churn: a different peer set, or an aborted map
            10 => {
                let mask = r.u8();
                let commit = !r.u8().is_multiple_of(4);
                if self.nodes[node].present[m as usize - 1] {
                    self.netmap(node, m, mask, commit);
                }
            }
            // a DNS query with a real or a mangled name
            11 => {
                let k = u32::from(r.u8()) % (EXTRA_PEERS + 2);
                let _ = self.alias(node, m, k);
                let len = usize::from(r.u8()) % 80;
                let q: Vec<u8> = (0..len).map(|_| r.u8()).collect();
                let now = self.now;
                let n = &mut self.nodes[node];
                n.eng.handle(now, Input::Dns { client: Client { addr: HOST_IP, port: 1 }, data: &q }, &mut n.rng, &mut |_: Out<'_>| true);
            }
            // heap: plenty, at the floor, below it
            12 => {
                let free = match r.u8() % 4 {
                    0 => usize::MAX / 2,
                    1 => ML_HB_FLOOR + usize::from(r.u16()),
                    2 => ML_HB_FLOOR.saturating_sub(usize::from(r.u16())),
                    _ => usize::from(r.u16()) * 64,
                };
                self.nodes[node].eng.set_heap(HeapSnapshot { free, largest: free, minimum: free });
            }
            // the rest: output refusal, endpoints, USB detach, clock
            _ => match r.u8() % 5 {
                0 => self.nodes[node].refuse = !self.nodes[node].refuse,
                1 => {
                    let eps = [Ep::v4([192, 168, 1, r.u8()], 41641), self.nodes[node].pub_ep];
                    self.input(node, Input::EndpointsChanged { member: m, endpoints: &eps[..1 + usize::from(r.u8() % 2)] });
                }
                2 => {
                    self.input(node, Input::UsbDetach);
                }
                3 => {
                    let v = r.u8().is_multiple_of(2);
                    self.input(node, Input::ClockValid(v));
                }
                _ => {
                    self.input(node, Input::DnsUpstream(Some(0x0808_0808)));
                }
            },
        }
    }

    /// Run a whole script, checking the invariants after every step.
    pub fn run(&mut self, script: &[u8]) {
        let mut r = Rd { d: script, p: 0 };
        while !r.done() {
            self.step(&mut r);
            self.check();
            let _ = self.rr.0;
        }
    }

    /// The node's engine (inspection).
    pub fn engine(&self, node: usize) -> &ChaosEngine {
        &self.nodes[node].eng
    }
}

/// A fixed prefix that establishes sessions in both directions (host sends, deliveries, time), so that scripts reach the transport and keepalive paths.
pub const WARM_UP: &[u8] = &[
    0, 0, 0, 0, 0, 0, 1, 5, 0, 1, 1, // node 0's host sends to member 1's peer 0
    4, 0, 0, 4, 0, 0, // deliver what was sent: DISCO, the initiation, the response
    8, 0, 0, 1, 4, 0, 0, // a second passes, deliver
    0, 1, 0, 0, 0, 0, 1, 5, 0, 1, 1, // node 1's host sends back
    4, 0, 0, 4, 0, 0, 8, 0, 0, 1, 4, 0, 0, //
    0, 0, 0, 0, 0, 0, 1, 5, 0, 1, 1, 4, 0, 0, 8, 0, 0, 2, 4, 0, 0, //
];

/// Entry point: any bytes as a script after the warm-up prefix.
pub fn script(data: &[u8]) {
    let mut c = Chaos::new();
    c.run(WARM_UP);
    c.run(data);
}

/// Entry point for a single datagram on a membership's UDP socket (after a warm-up): the first byte picks node and membership.
pub fn udp(data: &[u8]) {
    let mut c = Chaos::new();
    c.run(WARM_UP);
    let Some((&h, rest)) = data.split_first() else { return };
    let msg = Msg {
        to: usize::from(h & 1),
        member: u32::from((h >> 1) % 3) + 1,
        derp: false,
        src: [0; 32],
        ep: Ep::v4([198, 51, 100, h], 41641),
        data: rest.to_vec(),
    };
    c.deliver(&msg);
    c.check();
}

/// Entry point for a single relayed packet: the first byte picks node and membership, the next 32 the claimed sender key (a real peer's when the first
/// bit is set).
pub fn derp(data: &[u8]) {
    let mut c = Chaos::new();
    c.run(WARM_UP);
    let Some((&h, rest)) = data.split_first() else { return };
    let node = usize::from(h & 1);
    let member = u32::from((h >> 1) % 3) + 1;
    let (src, body) = if h & 0x80 != 0 {
        (node_keys(1 - node, member).0.0.0, rest)
    } else if rest.len() >= 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&rest[..32]);
        (k, &rest[32..])
    } else {
        return;
    };
    let msg = Msg { to: node, member, derp: true, src, ep: Ep::NONE, data: body.to_vec() };
    c.deliver(&msg);
    c.check();
}
