//! Internet checksum helpers: full computation (validation, ICMP generation) and RFC 1624 incremental update (every rewrite).

/// Big-endian `u16` at `p[i..i + 2]`. Callers have checked the bounds.
#[inline(always)]
pub fn rd16(p: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([p[i], p[i + 1]])
}
/// Big-endian `u32` at `p[i..i + 4]`.
#[inline(always)]
pub fn rd32(p: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]])
}
/// Store a big-endian `u16`.
#[inline(always)]
pub fn wr16(p: &mut [u8], i: usize, v: u16) {
    p[i..i + 2].copy_from_slice(&v.to_be_bytes());
}
/// Store a big-endian `u32`.
#[inline(always)]
pub fn wr32(p: &mut [u8], i: usize, v: u32) {
    p[i..i + 4].copy_from_slice(&v.to_be_bytes());
}

/// One's-complement running sum of `p` (odd tail padded with a zero byte), added to `s`.
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

/// RFC 1624 eqn. 3: `HC' = ~(~HC + ~m + m')`. Replacing a value with itself is a no-op.
#[inline]
pub fn adjust(csum: u16, old: u16, new: u16) -> u16 {
    let mut s = u32::from(!csum) + u32::from(!old) + u32::from(new);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    !(s as u16)
}

/// Incrementally replace a 16-bit field in the checksum stored at `p[at..at + 2]`.
#[inline]
pub fn replace16(p: &mut [u8], at: usize, old: u16, new: u16) {
    let c = adjust(rd16(p, at), old, new);
    wr16(p, at, c);
}

/// Incrementally replace a 32-bit field (two words) in the checksum at `p[at..at + 2]`.
#[inline]
pub fn replace32(p: &mut [u8], at: usize, old: u32, new: u32) {
    replace16(p, at, (old >> 16) as u16, (new >> 16) as u16);
    replace16(p, at, old as u16, new as u16);
}

/// TCP/UDP checksum of the segment `p[h..]` with the IPv4 pseudo header taken from `p[12..20]` and `p[9]` (verification and test helper: the
/// router itself only ever updates checksums incrementally).
pub fn l4_sum(p: &[u8], h: usize) -> u16 {
    let len = p.len() - h;
    finish(sum(&p[h..], sum(&p[12..20], 0) + u32::from(p[9]) + len as u32))
}
