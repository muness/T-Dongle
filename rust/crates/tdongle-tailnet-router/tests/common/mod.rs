//! Packet construction and independent verification shared by the router tests. Deliberately unrelated to the crate's own checksum code.
#![allow(dead_code, clippy::too_many_arguments, clippy::needless_range_loop)]

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as u32
    }
    pub fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

pub fn rd16(p: &[u8], i: usize) -> u16 {
    (p[i] as u16) << 8 | p[i + 1] as u16
}
pub fn rd32(p: &[u8], i: usize) -> u32 {
    (rd16(p, i) as u32) << 16 | rd16(p, i + 2) as u32
}
pub fn wr16(p: &mut [u8], i: usize, v: u16) {
    p[i] = (v >> 8) as u8;
    p[i + 1] = v as u8;
}
pub fn wr32(p: &mut [u8], i: usize, v: u32) {
    wr16(p, i, (v >> 16) as u16);
    wr16(p, i + 2, v as u16);
}
pub fn sum(p: &[u8], mut s: u32) -> u32 {
    let mut i = 0;
    while i + 1 < p.len() {
        s += rd16(p, i) as u32;
        i += 2;
    }
    if i < p.len() {
        s += (p[i] as u32) << 8;
    }
    s
}
pub fn finish(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}
pub fn ip_ok(b: &[u8]) -> bool {
    let h = (b[0] & 15) as usize * 4;
    finish(sum(&b[..h], 0)) == 0
}
pub fn l4_valid(b: &[u8]) -> bool {
    let h = (b[0] & 15) as usize * 4;
    if b[9] == 17 && rd16(b, h + 6) == 0 {
        return true;
    }
    finish(sum(&b[h..], sum(&b[12..20], 0) + b[9] as u32 + (b.len() - h) as u32)) == 0
}
pub fn packet_ok(b: &[u8]) -> bool {
    ip_ok(b) && l4_valid(b) && rd16(b, 2) as usize == b.len()
}
/// Recompute both checksums from scratch (what the router never does).
pub fn fill_checksums(b: &mut [u8], udp_none: bool) {
    let h = (b[0] & 15) as usize * 4;
    wr16(b, 10, 0);
    let c = finish(sum(&b[..h], 0));
    wr16(b, 10, c);
    let off = h + if b[9] == 6 { 16 } else { 6 };
    wr16(b, off, 0);
    if udp_none {
        return;
    }
    let c = finish(sum(&b[h..], sum(&b[12..20], 0) + b[9] as u32 + (b.len() - h) as u32));
    wr16(b, off, if c == 0 { 0xffff } else { c });
}

/// A valid IPv4 TCP/UDP packet; `syn` adds an MSS option (random).
pub fn build(rng: &mut Rng, src: u32, dst: u32, proto: u8, sport: u16, dport: u16, payload: usize, syn: bool, udp_none: bool) -> Vec<u8> {
    let tcp_h = if syn { 24 } else { 20 };
    let h = 20;
    let n = h + if proto == 6 { tcp_h } else { 8 } + payload;
    let mut b = vec![0u8; n];
    b[0] = 0x45;
    b[8] = 2 + rng.below(62) as u8;
    b[9] = proto;
    wr16(&mut b, 2, n as u16);
    wr16(&mut b, 4, rng.next() as u16);
    wr32(&mut b, 12, src);
    wr32(&mut b, 16, dst);
    wr16(&mut b, h, sport);
    wr16(&mut b, h + 2, dport);
    if proto == 6 {
        wr32(&mut b, h + 4, rng.next());
        wr32(&mut b, h + 8, rng.next());
        b[h + 12] = ((tcp_h / 4) as u8) << 4;
        b[h + 13] = if syn { 2 } else { 0x10 };
        wr16(&mut b, h + 14, rng.next() as u16);
        if syn {
            b[h + 20] = 2;
            b[h + 21] = 4;
            let mss = if rng.below(3) != 0 { 1460 } else { 536 + rng.below(900) as u16 };
            wr16(&mut b, h + 22, mss);
        }
    } else {
        wr16(&mut b, h + 4, (n - h) as u16);
    }
    for i in n - payload..n {
        b[i] = rng.next() as u8;
    }
    fill_checksums(&mut b, udp_none);
    b
}
