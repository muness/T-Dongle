//! Packet builders and an *independent* checksum oracle for the tests. Nothing here uses the crate's `csum` module: the oracle sums bytes of an
//! explicitly built pseudo header with a different folding strategy, so a bug shared by the code and its test is not possible.
#![allow(dead_code, clippy::too_many_arguments)]

use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_usbnet::napt::{Napt, NaptConfig, WifiAddr};

pub const HOST: u32 = 0xC0A8_4D02; // 192.168.77.2
pub const HOST2: u32 = 0xC0A8_4D03;
pub const WIFI: u32 = 0x0A00_0032; // 10.0.0.50
pub const REMOTE: u32 = 0x5DB8_D822; // 93.184.216.34
pub const REMOTE2: u32 = 0x0808_0808;

pub fn octets(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}

/// RFC 1071 checksum by summing in u64 with a late fold (a different shape than the crate's).
pub fn oracle_sum(bytes: &[u8]) -> u16 {
    let mut total: u64 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        total += (u64::from(bytes[i]) << 8) | u64::from(bytes[i + 1]);
        i += 2;
    }
    if i < bytes.len() {
        total += u64::from(bytes[i]) << 8;
    }
    while total > 0xffff {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

pub fn ip_header_checksum(h: &[u8]) -> u16 {
    let mut c = h.to_vec();
    c[10] = 0;
    c[11] = 0;
    oracle_sum(&c)
}

/// The checksum the L4 segment of `pkt` must carry (TCP/UDP: with the pseudo header; ICMP: plain). `None` for other protocols.
pub fn l4_expected(pkt: &[u8]) -> Option<u16> {
    let ihl = usize::from(pkt[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let proto = pkt[9];
    let mut seg = pkt[ihl..total].to_vec();
    let at = match proto {
        6 => 16,
        17 => 6,
        1 => 2,
        _ => return None,
    };
    if seg.len() < at + 2 {
        return None;
    }
    seg[at] = 0;
    seg[at + 1] = 0;
    let mut buf = Vec::new();
    if proto != 1 {
        buf.extend_from_slice(&pkt[12..20]);
        buf.push(0);
        buf.push(proto);
        buf.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    }
    buf.extend_from_slice(&seg);
    let c = oracle_sum(&buf);
    Some(if proto == 17 && c == 0 { 0xffff } else { c })
}

/// Assert the IP header checksum and (unless a UDP datagram carries none) the L4 checksum are right.
pub fn assert_valid(pkt: &[u8]) {
    let ihl = usize::from(pkt[0] & 15) * 4;
    assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), ip_header_checksum(&pkt[..ihl]), "IP header checksum");
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if let Some(want) = l4_expected(pkt) {
        let at = ihl
            + match pkt[9] {
                6 => 16,
                17 => 6,
                _ => 2,
            };
        let have = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
        if pkt[9] == 17 && have == 0 {
            return;
        }
        assert_eq!(have, want, "L4 checksum of proto {} len {}", pkt[9], total);
    }
}

pub struct Ip {
    pub src: u32,
    pub dst: u32,
    pub ttl: u8,
    pub df: bool,
    pub frag: u16, // flags+offset field bits other than DF
    pub opts: Vec<u8>,
}

impl Ip {
    pub fn new(src: u32, dst: u32) -> Ip {
        Ip { src, dst, ttl: 64, df: false, frag: 0, opts: vec![] }
    }
    pub fn ttl(mut self, t: u8) -> Ip {
        self.ttl = t;
        self
    }
    pub fn df(mut self) -> Ip {
        self.df = true;
        self
    }
    pub fn frag(mut self, f: u16) -> Ip {
        self.frag = f;
        self
    }
    pub fn opts(mut self, o: &[u8]) -> Ip {
        assert!(o.len().is_multiple_of(4));
        self.opts = o.to_vec();
        self
    }
    /// Wrap `l4` (checksum already right or fixed with `fix_l4`).
    pub fn wrap(&self, proto: u8, l4: &[u8]) -> Vec<u8> {
        let ihl = 20 + self.opts.len();
        let mut p = vec![0u8; ihl];
        p[0] = 0x40 | (ihl / 4) as u8;
        p[2..4].copy_from_slice(&((ihl + l4.len()) as u16).to_be_bytes());
        let ff = self.frag | if self.df { 0x4000 } else { 0 };
        p[6..8].copy_from_slice(&ff.to_be_bytes());
        p[8] = self.ttl;
        p[9] = proto;
        p[12..16].copy_from_slice(&octets(self.src));
        p[16..20].copy_from_slice(&octets(self.dst));
        p[20..].copy_from_slice(&self.opts);
        let c = ip_header_checksum(&p);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(l4);
        p
    }
}

pub const SYN: u8 = 2;
pub const ACK: u8 = 0x10;
pub const FIN: u8 = 1;
pub const RST: u8 = 4;

pub fn tcp_seg(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    t.extend_from_slice(payload);
    t
}

pub fn udp_dgram(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(payload);
    u
}

pub fn icmp_msg(ty: u8, code: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![ty, code, 0, 0];
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(payload);
    m
}

/// Build a packet with correct IP and L4 checksums.
pub fn packet(ip: &Ip, proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = ip.wrap(proto, l4);
    fix_l4(&mut p);
    p
}

/// Recompute the L4 checksum of `p` in place (for building test inputs).
pub fn fix_l4(p: &mut [u8]) {
    let ihl = usize::from(p[0] & 15) * 4;
    if let Some(c) = l4_expected(p) {
        let at = ihl
            + match p[9] {
                6 => 16,
                17 => 6,
                _ => 2,
            };
        p[at..at + 2].copy_from_slice(&c.to_be_bytes());
    }
}

pub fn tcp_pkt(src: u32, sport: u16, dst: u32, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    packet(&Ip::new(src, dst), 6, &tcp_seg(sport, dport, seq, ack, flags, payload))
}
pub fn udp_pkt(src: u32, sport: u16, dst: u32, dport: u16, payload: &[u8]) -> Vec<u8> {
    packet(&Ip::new(src, dst), 17, &udp_dgram(sport, dport, payload))
}
pub fn echo_pkt(src: u32, dst: u32, ty: u8, id: u16, seq: u16) -> Vec<u8> {
    packet(&Ip::new(src, dst), 1, &icmp_msg(ty, 0, id, seq, b"abcdefgh"))
}

pub fn new_napt<const N: usize>() -> Napt<N> {
    let mut n = Napt::<N>::new(NaptConfig::C, &mut TestRng(0x1234_5678_9abc_def1));
    n.set_wifi(Some(WifiAddr { ip: WIFI, mask: 0xffff_ff00 }));
    n
}

pub fn sport(p: &[u8]) -> u16 {
    let ihl = usize::from(p[0] & 15) * 4;
    u16::from_be_bytes([p[ihl], p[ihl + 1]])
}
pub fn dport(p: &[u8]) -> u16 {
    let ihl = usize::from(p[0] & 15) * 4;
    u16::from_be_bytes([p[ihl + 2], p[ihl + 3]])
}
pub fn src(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[12], p[13], p[14], p[15]])
}
pub fn dst(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[16], p[17], p[18], p[19]])
}
