//! Shared test support: the same xorshift64 as the C test, frame builders ported from it, and an independent reference classifier.
#![allow(dead_code, clippy::too_many_arguments)] // builders mirror the 8-argument C test helper

use tdongle_aqm::EcnClass;

/// xorshift64 with the C test's seed and `rnd(n)` semantics (`rng % n`).
pub struct Rng(pub u64);

impl Rng {
    pub fn new() -> Self {
        Self(88172645463325252)
    }
    pub fn raw(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// Uniform-ish value in `0..n` (like C `rnd`, which truncates the result to 32 bits).
    pub fn rnd(&mut self, n: u32) -> u32 {
        (self.raw() % u64::from(n)) as u32
    }
    pub fn byte(&mut self) -> u8 {
        self.rnd(256) as u8
    }
    pub fn usz(&mut self, n: usize) -> usize {
        self.rnd(n as u32) as usize
    }
}

pub type Buf = [u8; 1600];

/// Ones' complement checksum of `p` seeded with `init` (RFC 1071), from the bytes.
pub fn csum16(p: &[u8], init: u32) -> u16 {
    let mut sum = init;
    for c in p.chunks(2) {
        sum += if c.len() == 2 { u32::from(u16::from_be_bytes([c[0], c[1]])) } else { u32::from(c[0]) << 8 };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ip4_header_ok(f: &[u8]) -> bool {
    let ihl = usize::from(f[14] & 15) * 4;
    csum16(&f[14..14 + ihl], 0) == 0
}

/// TCP/UDP checksum over the pseudo header and segment: independent of the ECN field.
pub fn l4_checksum(f: &[u8], v6: bool) -> u16 {
    let ip = &f[14..];
    let mut sum = 0u32;
    let (l4off, l4len, proto);
    if !v6 {
        let ihl = usize::from(ip[0] & 15) * 4;
        proto = ip[9];
        l4off = 14 + ihl;
        l4len = usize::from(u16::from_be_bytes([ip[2], ip[3]])) - ihl;
        for i in (12..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([ip[i], ip[i + 1]]));
        }
    } else {
        proto = ip[6];
        l4off = 14 + 40;
        l4len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
        for i in (8..40).step_by(2) {
            sum += u32::from(u16::from_be_bytes([ip[i], ip[i + 1]]));
        }
    }
    sum += u32::from(proto) + l4len as u32;
    assert!(l4off + l4len <= f.len());
    csum16(&f[l4off..l4off + l4len], sum)
}

pub fn build4(r: &mut Rng, f: &mut Buf, tos: u32, proto: u32, ihl_words: u32, payload: u32, flags_frag: u32) -> usize {
    f.fill(0);
    for b in &mut f[..12] {
        *b = r.byte();
    }
    f[12] = 0x08;
    f[13] = 0x00;
    let ihl = (ihl_words * 4) as usize;
    let total = ihl as u32 + payload;
    f[14] = (0x40 | ihl_words) as u8;
    f[15] = tos as u8;
    f[16] = (total >> 8) as u8;
    f[17] = total as u8;
    f[18] = r.byte();
    f[19] = r.byte();
    f[20] = (flags_frag >> 8) as u8;
    f[21] = flags_frag as u8;
    f[22] = 64;
    f[23] = proto as u8;
    for b in &mut f[26..34] {
        *b = r.byte();
    }
    for b in &mut f[34..14 + ihl] {
        *b = r.byte(); // IP options
    }
    for b in &mut f[14 + ihl..14 + total as usize] {
        *b = r.byte();
    }
    if proto == 6 {
        f[14 + ihl + 13] = 0x10; // ACK: not SYN/FIN/RST
    }
    if proto == 17 {
        f[14 + ihl + 2] = 0x13;
        f[14 + ihl + 3] = 0x88;
        f[14 + ihl] = 0xc3;
        f[14 + ihl + 1] = 0x50;
    }
    let hc = csum16(&f[14..14 + ihl], 0);
    [f[24], f[25]] = hc.to_be_bytes();
    14 + total as usize
}

pub fn build6(r: &mut Rng, f: &mut Buf, tclass: u32, next: u32, payload: u32) -> usize {
    f.fill(0);
    for b in &mut f[..12] {
        *b = r.byte();
    }
    f[12] = 0x86;
    f[13] = 0xdd;
    f[14] = (0x60 | (tclass >> 4)) as u8;
    f[15] = (((tclass & 15) << 4) | r.rnd(16)) as u8;
    f[16] = r.byte();
    f[17] = r.byte();
    f[18] = (payload >> 8) as u8;
    f[19] = payload as u8;
    f[20] = next as u8;
    f[21] = 64;
    for b in &mut f[22..54 + payload as usize] {
        *b = r.byte();
    }
    if next == 6 {
        f[14 + 40 + 13] = 0x10;
    }
    54 + payload as usize
}

/// One extension header of a hand-built chain. `units` is the Hdr Ext Len field (8-byte units beyond the first) for 0/43/60, 4-byte units
/// beyond 2 for 51; a fragment header is always 8 bytes.
#[derive(Clone, Copy)]
pub struct Ext {
    pub ty: u8,
    pub units: u8,
}

pub const fn ext(ty: u8, units: u8) -> Ext {
    Ext { ty, units }
}

pub fn build6_chain(r: &mut Rng, f: &mut Buf, tclass: u32, chain: &[Ext], proto: u32, tcp_flags: u32, udp_dst: u32, frag_off: u32) -> usize {
    f.fill(0);
    for b in &mut f[..12] {
        *b = r.byte();
    }
    f[12] = 0x86;
    f[13] = 0xdd;
    f[14] = (0x60 | (tclass >> 4)) as u8;
    f[15] = ((tclass & 15) << 4) as u8;
    f[21] = 64;
    let mut o = 54usize;
    let next = chain.first().map_or(proto as u8, |e| e.ty);
    f[20] = next;
    for (i, e) in chain.iter().enumerate() {
        let after = chain.get(i + 1).map_or(proto as u8, |n| n.ty);
        let hl = match e.ty {
            44 => 8,
            51 => (usize::from(e.units) + 2) * 4,
            _ => (usize::from(e.units) + 1) * 8,
        };
        f[o] = after;
        if e.ty != 44 {
            f[o + 1] = e.units;
        } else {
            f[o + 2] = (frag_off >> 5) as u8;
            f[o + 3] = ((frag_off & 31) << 3) as u8;
        }
        o += hl;
    }
    if proto == 6 {
        f[o + 12] = 0x50;
        f[o + 13] = tcp_flags as u8;
    }
    if proto == 17 {
        f[o + 2] = (udp_dst >> 8) as u8;
        f[o + 3] = udp_dst as u8;
    }
    let total = o + 60;
    f[18] = ((total - 54) >> 8) as u8;
    f[19] = (total - 54) as u8;
    let from = o + if proto == 6 { 20 } else { 8 };
    for b in &mut f[from..total] {
        *b = r.byte();
    }
    total
}

/// Reference classification of the ECN field.
pub fn ecn_to_class(ecn: u8) -> EcnClass {
    match ecn & 3 {
        0 => EcnClass::NotEct,
        3 => EcnClass::Ce,
        _ => EcnClass::Capable,
    }
}

/// An independent reference classifier, written from the specification in the C comments with slices instead of index arithmetic: it never
/// shares a helper or a bounds expression with the code under test.
pub fn ref_classify(frame: &[u8]) -> EcnClass {
    if frame.len() < 14 {
        return EcnClass::NotIp;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let ip = &frame[14..];
    match ethertype {
        0x0800 if ip.len() >= 20 && ip[0] >> 4 == 4 => {
            let ihl = usize::from(ip[0] & 15) * 4;
            if ihl < 20 || ihl > ip.len() {
                return EcnClass::NotIp;
            }
            let proto = ip[9];
            let frag = u16::from_be_bytes([ip[6] & 0x1f, ip[7]]);
            let l4 = &ip[ihl..];
            if frag == 0 {
                if proto == 6 && l4.len() >= 14 && l4[13] & 0b111 != 0 {
                    return EcnClass::Exempt;
                }
                if proto == 17 && l4.len() >= 4 {
                    let (src, dst) = (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]));
                    if [src, dst].iter().any(|p| *p == 67 || *p == 68) {
                        return EcnClass::Exempt;
                    }
                }
            }
            ecn_to_class(ip[1])
        }
        0x86dd if ip.len() >= 40 && ip[0] >> 4 == 6 => {
            let Some((proto, l4)) = ref_walk6(ip) else {
                return EcnClass::NotIp;
            };
            match proto {
                58 => return EcnClass::Exempt,
                6 if l4.len() >= 14 && l4[13] & 0b111 != 0 => return EcnClass::Exempt,
                17 if l4.len() >= 4 && matches!(u16::from_be_bytes([l4[2], l4[3]]), 546 | 547) => {
                    return EcnClass::Exempt;
                }
                _ => {}
            }
            ecn_to_class(ip[1] >> 4)
        }
        _ => EcnClass::NotIp,
    }
}

/// Reference extension-header walk over the IPv6 packet (starting at the fixed header). `Some((proto, rest))`: `proto` 0xff and an empty rest
/// when there is no readable transport header.
pub fn ref_walk6(ip: &[u8]) -> Option<(u8, &[u8])> {
    let mut next = ip[6];
    let mut rest = &ip[40..];
    let mut seen = 0;
    while matches!(next, 0 | 43 | 44 | 51 | 60) {
        seen += 1;
        if seen > 6 || rest.len() < 8 {
            return None;
        }
        let len = match next {
            44 => {
                if u16::from_be_bytes([rest[2], rest[3] & 0xf8]) != 0 {
                    return Some((0xff, &[]));
                }
                8
            }
            51 => (usize::from(rest[1]) + 2) * 4,
            _ => (usize::from(rest[1]) + 1) * 8,
        };
        if len > rest.len() {
            return None;
        }
        next = rest[0];
        rest = &rest[len..];
    }
    if next == 50 || next == 59 {
        return Some((0xff, &[]));
    }
    Some((next, rest))
}
