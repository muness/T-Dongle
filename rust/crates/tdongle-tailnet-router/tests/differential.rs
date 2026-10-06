//! Differential test (port of test_router_differential.c): a naive reference router, written the way the C's frozen "old" router was (linear
//! scans, full checksum recomputation, unbounded alias map), and the real fast path receive the same random stream of packets and control
//! events. Everything either emits must agree: which packets are forwarded, to whom, with which rewritten addresses, ports, TTL and payload, valid
//! checksums, and the whole flow table slot for slot after every event.
#![allow(
    clippy::type_complexity,
    clippy::manual_div_ceil,
    clippy::assertions_on_constants,
    clippy::unnecessary_to_owned,
    clippy::manual_range_contains,
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::manual_range_patterns
)]
mod common;
use common::*;
use tdongle_tailnet_router::tables::AliasRecord;
use tdongle_tailnet_router::*;

const IDLE: u64 = 120_000;
const BASE: u32 = 40_000;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
struct Row {
    used: bool,
    id: u32,
    peer: u32,
    alias: u32,
    host: u32,
    local: u16,
    remote: u16,
    mapped: u16,
    proto: u8,
    epoch: u32,
    touched: u64,
}

#[derive(PartialEq, Debug, Clone)]
struct Emit {
    kind: u8, // 0 to tunnel, 1 to USB
    member: u32,
    next_hop: u32,
    bytes: Vec<u8>,
}

struct Naive {
    members: Vec<(u32, u32, bool)>,
    aliases: Vec<(u32, u32, u32)>,
    flows: [Row; 64],
    epoch: u32,
}

fn valid(b: &[u8]) -> Option<usize> {
    let n = b.len();
    if n < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let h = (b[0] & 15) as usize * 4;
    if h < 20 || h > n || rd16(b, 2) as usize != n || rd16(b, 6) & 0x3fff != 0 || (b[9] != 6 && b[9] != 17) {
        return None;
    }
    if n < h + if b[9] == 6 { 20 } else { 8 } {
        return None;
    }
    if b[9] == 6 {
        let o = (b[h + 12] >> 4) as usize * 4;
        if o < 20 || o > n - h {
            return None;
        }
    }
    if b[9] == 17 && rd16(b, h + 4) as usize != n - h {
        return None;
    }
    ip_ok(b).then_some(h)
}
fn clamp(b: &mut [u8], h: usize) -> bool {
    if b[9] != 6 || b[h + 13] & 2 == 0 {
        return true;
    }
    let end = h + (b[h + 12] >> 4) as usize * 4;
    if end > b.len() {
        return false;
    }
    let mut pos = h + 20;
    while pos < end {
        match b[pos] {
            0 => break,
            1 => pos += 1,
            k => {
                if pos + 2 > end || b[pos + 1] < 2 || pos + b[pos + 1] as usize > end {
                    return false;
                }
                if k == 2 {
                    if b[pos + 1] != 4 {
                        return false;
                    }
                    if rd16(b, pos + 2) > 1360 {
                        wr16(b, pos + 2, 1360);
                    }
                }
                pos += b[pos + 1] as usize;
            }
        }
    }
    true
}
/// Rewrite and recompute every checksum from scratch; a UDP datagram without checksum keeps none.
fn rewrite(b: &mut [u8], h: usize, src: u32, dst: u32, off: usize, port: u16, was_none: bool) {
    wr32(b, 12, src);
    wr32(b, 16, dst);
    wr16(b, h + off, port);
    fill_checksums(b, was_none);
}
fn none_udp(b: &[u8], h: usize) -> bool {
    b[9] == 17 && rd16(b, h + 6) == 0
}

impl Naive {
    fn new() -> Self {
        Naive { members: vec![], aliases: vec![], flows: [Row::default(); 64], epoch: 1 }
    }
    fn member(&self, id: u32) -> Option<(u32, u32, bool)> {
        self.members.iter().copied().find(|m| m.0 == id)
    }
    fn forget_flows(&mut self, id: u32) {
        for f in self.flows.iter_mut() {
            if f.used && f.id == id {
                *f = Row::default();
            }
        }
    }
    fn host(&mut self, pkt: &[u8], now: u64) -> Option<Emit> {
        let mut b = pkt.to_vec();
        let h = valid(&b)?;
        if !clamp(&mut b, h) || b[8] < 2 {
            return None;
        }
        // an MSS clamp changed bytes: recompute only if the packet was valid and we change nothing else (checksums are recomputed at rewrite)
        let host = rd32(&b, 12);
        if host & 0xffff_ff00 != 0xc0a8_4d00 || host == 0xc0a8_4d01 || host == 0xc0a8_4dff {
            return None;
        }
        let dest = rd32(&b, 16);
        let (local, remote, proto) = (rd16(&b, h), rd16(&b, h + 2), b[9]);
        let hit = self
            .flows
            .iter()
            .position(|f| f.used && f.epoch == self.epoch && f.alias == dest && f.host == host && f.local == local && f.remote == remote && f.proto == proto);
        let (id, peer) = match hit {
            Some(i) => (self.flows[i].id, self.flows[i].peer),
            None => {
                let a = self.aliases.iter().find(|a| a.2 == dest)?;
                (a.0, a.1)
            }
        };
        let (_, vpn, ready) = self.member(id)?;
        if !ready {
            return None;
        }
        let slot = match hit {
            Some(i) => i,
            None => {
                let i = (0..64).find(|&i| {
                    let s = &self.flows[i];
                    !(s.used && s.epoch == self.epoch && now.saturating_sub(s.touched) <= IDLE)
                })?;
                self.flows[i] = Row {
                    used: true,
                    id,
                    peer,
                    alias: dest,
                    host,
                    local,
                    remote,
                    mapped: (BASE + i as u32 + 64 * ((self.epoch - 1) % 300)) as u16,
                    proto,
                    epoch: self.epoch,
                    touched: now,
                };
                i
            }
        };
        if hit.is_some() {
            self.flows[slot].touched = now;
        }
        let none = none_udp(&b, h);
        rewrite(&mut b, h, vpn, peer, 0, self.flows[slot].mapped, none);
        b[8] -= 1;
        fill_checksums(&mut b, none);
        Some(Emit { kind: 0, member: id, next_hop: peer, bytes: b })
    }
    fn tunnel(&mut self, from: u32, pkt: &[u8], now: u64) -> Option<Emit> {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 || rd16(pkt, 2) as usize > pkt.len() || rd16(pkt, 2) < 20 {
            return None;
        }
        let mut b = pkt[..rd16(pkt, 2) as usize].to_vec();
        let h = valid(&b)?;
        if !clamp(&mut b, h) {
            return None;
        }
        let (_, vpn, _) = self.member(from)?;
        if vpn != rd32(&b, 16) {
            return None;
        }
        let mapped = rd16(&b, h + 2);
        if (mapped as u32) < BASE || mapped as u32 >= BASE + 64 * 300 {
            return None;
        }
        let f = &mut self.flows[(mapped as usize - BASE as usize) & 63];
        if !(f.used
            && f.epoch == self.epoch
            && f.id == from
            && f.peer == rd32(&b, 12)
            && f.remote == rd16(&b, h)
            && f.mapped == mapped
            && f.proto == b[9]
            && now.saturating_sub(f.touched) < IDLE)
        {
            return None;
        }
        f.touched = now;
        let f = *f;
        let none = none_udp(&b, h);
        rewrite(&mut b, h, f.alias, f.host, 2, f.local, none);
        Some(Emit { kind: 1, member: from, next_hop: f.host, bytes: b })
    }
}

fn zero_pair(a: u16, b: u16) -> bool {
    (a == 0 && b == 0xffff) || (a == 0xffff && b == 0)
}

struct Harness {
    rng: Rng,
    old: Naive,
    new: GatewayRouter,
    now: u64,
    live: Vec<u32>,
    next_id: u32,
    known: Vec<(u32, u32, u32)>,
    next_alias: u32,
    seen: Vec<(u32, u32, u32, u16, u16, u8)>, // id, peer, vpn, mapped, remote, proto
    stats: [u32; 3],
    zero_diffs: u32,
}

impl Harness {
    fn vpn(id: u32) -> u32 {
        0x6440_0000 + id
    }
    fn compare(&mut self, what: &str, a: Option<Emit>, b: Option<Emit>) {
        match (&a, &b) {
            (None, None) => self.stats[2] += 1,
            (Some(x), Some(y)) => {
                assert_eq!((x.kind, x.member, x.next_hop, x.bytes.len()), (y.kind, y.member, y.next_hop, y.bytes.len()), "{what}");
                let h = (x.bytes[0] & 15) as usize * 4;
                assert!(ip_ok(&x.bytes) && ip_ok(&y.bytes) && l4_valid(&x.bytes) && l4_valid(&y.bytes), "{what}: checksums");
                let off = h + if x.bytes[9] == 6 { 16 } else { 6 };
                let (cu, cv) = (rd16(&x.bytes, off), rd16(&y.bytes, off));
                if cu != cv {
                    assert!(zero_pair(cu, cv), "{what}: l4 checksum {cu:04x} vs {cv:04x}");
                    self.zero_diffs += 1;
                }
                let (mut u, mut v) = (x.bytes.clone(), y.bytes.clone());
                for p in [&mut u, &mut v] {
                    wr16(p, off, 0);
                    wr16(p, 10, 0);
                }
                assert_eq!(u, v, "{what}: bytes");
                if x.kind == 0 {
                    self.stats[0] += 1;
                    let b = &x.bytes;
                    self.seen.push((x.member, x.next_hop, rd32(b, 12), rd16(b, 20), rd16(b, 22), b[9]));
                    if self.seen.len() > 64 {
                        let k = self.rng.below(64) as usize;
                        self.seen.swap_remove(k);
                    }
                } else {
                    self.stats[1] += 1;
                }
            }
            _ => panic!("{what}: old {:?} new {:?}", a.as_ref().map(|e| e.kind), b.as_ref().map(|e| e.kind)),
        }
        // flow tables slot for slot
        for (i, s) in self.new.flows().slots().enumerate() {
            let o = &self.old.flows[i];
            match s {
                None => assert!(!o.used, "{what}: slot {i} used in old only"),
                Some((f, g, t)) => {
                    let n = Row {
                        used: true,
                        id: f.id,
                        peer: f.peer,
                        alias: f.alias,
                        host: f.host,
                        local: f.local,
                        remote: f.remote,
                        mapped: f.mapped,
                        proto: f.proto,
                        epoch: g,
                        touched: t,
                    };
                    assert_eq!(&n, o, "{what}: slot {i}");
                }
            }
        }
    }
    fn publish(&mut self) {
        let mut s = MemberSet::<16>::new();
        for m in &self.old.members {
            s.insert(Member { id: m.0, vpn_ip: m.1, ready: m.2 });
        }
        self.new.publish(s);
    }
    fn host_packet(&mut self) {
        let r = &mut self.rng;
        let dst = match r.below(100) {
            0..=74 if !self.known.is_empty() => self.known[r.below(self.known.len() as u32) as usize].2,
            0..=84 => ALIAS_BASE + r.below(80),
            _ => 0xc612_0000 + r.below(0x20000),
        };
        let mut src = 0xc0a8_4d02 + r.below(3);
        if r.below(40) == 0 {
            src = if r.below(2) == 0 { 0xc0a8_4d01 } else { 0xc0a8_0102 };
        }
        let proto = if r.below(5) != 0 {
            if r.below(3) != 0 { 6 } else { 17 }
        } else if r.below(2) == 0 {
            6
        } else {
            17
        };
        let (sport, dport) = (2000 + r.below(6) as u16, 80 + r.below(3) as u16);
        let payload = if r.below(8) != 0 { r.below(64) } else { r.below(1300) } as usize;
        let syn = proto == 6 && r.below(4) == 0;
        let none = proto == 17 && r.below(8) == 0;
        let mut b = build(r, src, dst, proto, sport, dport, payload, syn, none);
        match r.below(40) {
            0 => b[10] ^= 0x55,
            1 => b[6] |= 0x20,
            2 => {
                let k = r.below(8) as usize;
                b.truncate(b.len().saturating_sub(k).max(1));
            }
            3 => b[0] = 0x46,
            4 if proto == 6 && syn => b[20 + 21] = 255,
            _ => {}
        }
        if b[8] > 1 && r.below(25) == 0 {
            b[8] = 1; // TTL 1 sometimes, header checksum fixed
            if b.len() >= 20 {
                wr16(&mut b, 10, 0);
                let c = finish(sum(&b[..20], 0));
                wr16(&mut b, 10, c);
            }
        }
        let a = self.old.host(&b, self.now);
        let g = self.new.usb_generation();
        let mut nb = b.clone();
        let o = self.new.host_packet(&mut nb, self.now, g);
        let e = match o {
            HostOutcome::Forwarded { member, peer, len } => Some(Emit { kind: 0, member, next_hop: peer, bytes: nb[..len].to_vec() }),
            _ => None,
        };
        self.compare("host", a, e);
    }
    fn tunnel_packet(&mut self) {
        if self.seen.is_empty() {
            return;
        }
        let r = &mut self.rng;
        let (mut id, peer, vpn, mapped, remote, mut proto) = self.seen[r.below(self.seen.len() as u32) as usize];
        let (mut src, mut dst, mut sport, mut dport) = (peer, vpn, remote, mapped);
        match r.below(14) {
            0 => src ^= 1,
            1 => sport ^= 1,
            2 => dport = dport.wrapping_add(1),
            3 => proto ^= 6 ^ 17,
            4 if !self.live.is_empty() => id = self.live[r.below(self.live.len() as u32) as usize],
            5 => dst ^= 1,
            _ => {}
        }
        let payload = r.below(60) as usize + if r.below(10) == 0 { r.below(1200) as usize } else { 0 };
        let syn = proto == 6 && r.below(5) == 0;
        let none = proto == 17 && r.below(8) == 0;
        let mut b = build(r, src, dst, proto, sport, dport, payload, syn, none);
        b[8] = 1 + r.below(64) as u8;
        let none = proto == 17 && rd16(&b, 26) == 0;
        fill_checksums(&mut b, none);
        if r.below(3) == 0 {
            let padded = (b.len() + 15) & !15;
            b.resize(padded, 0);
        }
        if r.below(30) == 0 {
            b[10] ^= 0x33;
        }
        let a = self.old.tunnel(id, &b, self.now);
        let mut nb = b.clone();
        let o = self.new.tunnel_packet(id, &mut nb, self.now);
        let e = match o {
            TunnelOutcome::ToHost { host, len } => Some(Emit { kind: 1, member: id, next_hop: host, bytes: nb[..len].to_vec() }),
            _ => None,
        };
        self.compare("tunnel", a, e);
    }
    /// The background fill the usb_routes task performs when idle: records that do not exist (allocated-but-unrecorded addresses) are absent.
    fn fill(&mut self) {
        while let Some(a) = self.new.begin_fill(self.now) {
            let rec = self.old.aliases.iter().find(|x| x.2 == a).map(|x| AliasRecord { id: x.0, peer: x.1, alias: x.2 });
            self.new.fill_done(a, rec, self.now);
            self.now += FILL_SPACING_MS;
        }
        let mut out = [0u8; 1400];
        while let Some(o) = self.new.hold_service(self.now, &mut out) {
            assert!(!matches!(o, HostOutcome::Forwarded { .. }), "a held packet was released without a record");
        }
    }
}

fn run(seed: u64, ops: u32) -> (u32, u32, u32, u32) {
    let mut h = Harness {
        rng: Rng(88172645463325252 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        old: Naive::new(),
        new: GatewayRouter::new(),
        now: 1000,
        live: vec![],
        next_id: 1,
        known: vec![],
        next_alias: 0,
        seen: vec![],
        stats: [0; 3],
        zero_diffs: 0,
    };
    for op in 0..ops {
        let mut kind = h.rng.below(1000);
        if op < 40 && h.live.len() < 4 {
            kind = 0;
        } else if op < 120 && h.known.len() < 24 {
            kind = 30;
        }
        if kind < 6 && h.live.len() < 4 && h.next_id < 40 {
            let id = h.next_id;
            h.next_id += 1;
            h.old.members.push((id, Harness::vpn(id), true));
            h.live.push(id);
            h.publish();
        } else if kind < 40 && !h.live.is_empty() && h.next_alias < 60 {
            let id = h.live[h.rng.below(h.live.len() as u32) as usize];
            let peer = 0x6450_0001 + h.rng.below(6);
            let a = match h.known.iter().find(|k| k.0 == id && k.1 == peer) {
                Some(k) => k.2,
                None => {
                    let a = ALIAS_BASE + h.next_alias;
                    h.next_alias += 1;
                    h.known.push((id, peer, a));
                    h.old.aliases.push((id, peer, a));
                    a
                }
            };
            assert!(h.new.alias_insert(AliasRecord { id, peer, alias: a }));
        } else if kind < 44 && !h.live.is_empty() {
            let id = h.live[h.rng.below(h.live.len() as u32) as usize];
            h.old.members.retain(|m| m.0 != id);
            h.old.forget_flows(id);
            h.new.suspend(id);
            // a restarted membership is republished (same id, same state) by the next control event
            h.old.members.push((id, Harness::vpn(id), true));
            h.publish();
        } else if kind < 45 && !h.live.is_empty() {
            let i = h.rng.below(h.live.len() as u32) as usize;
            let id = h.live.swap_remove(i);
            h.old.members.retain(|m| m.0 != id);
            h.old.forget_flows(id);
            h.old.aliases.retain(|a| a.0 != id);
            h.known.retain(|k| k.0 != id);
            h.new.forget(id);
        } else if kind < 56 && !h.live.is_empty() {
            let id = h.live[h.rng.below(h.live.len() as u32) as usize];
            let ready = h.rng.below(4) != 0;
            for m in h.old.members.iter_mut() {
                if m.0 == id {
                    m.2 = ready;
                }
            }
            h.publish();
        } else if kind < 60 {
            h.old.epoch += 1;
            h.new.usb_detach();
        } else if kind < 90 {
            h.now += if h.rng.below(8) != 0 { h.rng.below(5_000) } else { h.rng.below(150_000) } as u64;
        } else if kind < 560 {
            h.host_packet();
        } else {
            h.tunnel_packet();
        }
        h.fill();
    }
    (h.stats[0], h.stats[1], h.stats[2], h.zero_diffs)
}

#[test]
fn fast_path_equals_naive_reference() {
    let mut out = 0;
    let mut inn = 0;
    for seed in 1..=24u64 {
        let (o, i, _d, _z) = run(seed, 6000);
        assert!(o > 50 && i > 20, "seed {seed}: {o} to tunnel, {i} to USB");
        out += o;
        inn += i;
    }
    println!("differential: {out} packets to tunnel, {inn} to USB across 24 seeds");
}
