//! Internet checksums: the full computation (validation, generated packets) and the RFC 1624 incremental update (every NAT rewrite).
//!
//! The incremental form is what lwIP's `checksumadjust` does (and what the router crate does); it is checked against the full computation by the
//! differential tests in `tests/napt_checksums.rs`, with a *separate* reference implementation so the two cannot share a bug.

use crate::wire::{rd16, wr16};

/// One's-complement running sum of `p` (an odd tail is padded with a zero byte), added to `s`. Not folded.
pub fn sum(p: &[u8], s: u32) -> u32 {
    let mut s = s;
    let (words, rest) = p.as_chunks::<2>();
    for c in words {
        s += u32::from(u16::from_be_bytes(*c));
    }
    if let [last] = rest {
        s += u32::from(*last) << 8;
    }
    s
}

/// Fold and complement a running sum.
pub fn finish(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// True when the IPv4 header `p[..h]` carries a correct checksum.
pub fn header_ok(p: &[u8], h: usize) -> bool {
    finish(sum(&p[..h], 0)) == 0
}

/// Sum of the IPv4 pseudo header for a segment of `len` bytes.
pub fn pseudo(src: u32, dst: u32, proto: u8, len: u16) -> u32 {
    (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + u32::from(proto) + u32::from(len)
}

/// The checksum a TCP/UDP segment `l4` (checksum field zeroed by the caller) must carry between `src` and `dst`.
pub fn l4_checksum(src: u32, dst: u32, proto: u8, l4: &[u8]) -> u16 {
    finish(sum(l4, pseudo(src, dst, proto, l4.len() as u16)))
}

/// RFC 1624 equation 3: `HC' = ~(~HC + ~m + m')`, for one 16-bit word changing from `old` to `new`.
#[inline]
pub fn adjust(csum: u16, old: u16, new: u16) -> u16 {
    let mut s = u32::from(!csum) + u32::from(!old) + u32::from(new);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    !(s as u16)
}

/// [`adjust`] for a 32-bit field (an address).
#[inline]
pub fn adjust32(csum: u16, old: u32, new: u32) -> u16 {
    adjust(adjust(csum, (old >> 16) as u16, (new >> 16) as u16), old as u16, new as u16)
}

/// Incrementally replace a 16-bit field in the checksum stored at `p[at..at + 2]`.
#[inline]
pub fn patch16(p: &mut [u8], at: usize, old: u16, new: u16) {
    let c = adjust(rd16(p, at), old, new);
    wr16(p, at, c);
}

/// Incrementally replace a 32-bit field in the checksum stored at `p[at..at + 2]`.
#[inline]
pub fn patch32(p: &mut [u8], at: usize, old: u32, new: u32) {
    let c = adjust32(rd16(p, at), old, new);
    wr16(p, at, c);
}

/// Fill the IPv4 header checksum of `p[..h]`.
pub fn fill_header(p: &mut [u8], h: usize) {
    wr16(p, 10, 0);
    let c = finish(sum(&p[..h], 0));
    wr16(p, 10, c);
}
