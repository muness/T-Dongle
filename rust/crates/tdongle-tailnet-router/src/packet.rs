//! IPv4 TCP/UDP packet validation and in-place rewriting (NAT, TTL, MSS clamp), all with RFC 1624 incremental checksums.
//!
//! Policy carried over from the C router (`router.c`): only unfragmented IPv4 TCP and UDP is routed; the IPv4 header checksum is verified but the
//! TCP/UDP checksum is NOT (a packet with a bad L4 checksum leaves bad, a UDP datagram without a checksum stays without one, and an updated UDP
//! checksum is never emitted as 0). Nothing here allocates or panics on any input.

use crate::csum::{self, rd16, rd32, wr16, wr32};
use crate::{ALIAS_MASK, ALIAS_NET, MSS_CLAMP, USB_HOST_NET};

/// IP protocol number of TCP.
pub const TCP: u8 = 6;
/// IP protocol number of UDP.
pub const UDP: u8 = 17;

/// Validate `b` as a routable packet and return the IPv4 header length.
///
/// Accepts only: version 4, header at least 20 bytes and inside the packet, total length equal to `b.len()`, no fragmentation (MF or offset;
/// DF is fine), TCP (data offset sane) or UDP (length field equal to the payload) and a correct header checksum.
pub fn valid(b: &[u8]) -> Option<usize> {
    let n = b.len();
    if n < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let h = usize::from(b[0] & 15) * 4;
    if h < 20 || h > n || usize::from(rd16(b, 2)) != n || rd16(b, 6) & 0x3fff != 0 {
        return None;
    }
    let proto = b[9];
    if proto != TCP && proto != UDP {
        return None;
    }
    if n < h + if proto == TCP { 20 } else { 8 } {
        return None;
    }
    if proto == TCP {
        let off = usize::from(b[h + 12] >> 4) * 4;
        if !(20..=n - h).contains(&off) {
            return None;
        }
    } else if usize::from(rd16(b, h + 4)) != n - h {
        return None;
    }
    csum::header_ok(b, h).then_some(h)
}

/// Clamp the MSS option of a SYN (either direction) to [`MSS_CLAMP`], never enlarging a smaller offer. Non-SYN and non-TCP packets are
/// untouched (`true`); a malformed option list fails closed (`false`). The TCP checksum is adjusted incrementally, including the case of an MSS
/// value at an odd offset (after a NOP) where it straddles two checksum words. `b` must have passed [`valid`] with header length `h`.
pub fn clamp_mss(b: &mut [u8], h: usize) -> bool {
    if b[9] != TCP || b[h + 13] & 2 == 0 {
        return true;
    }
    let end = h + usize::from(b[h + 12] >> 4) * 4;
    if end > b.len() {
        return false;
    }
    let mut pos = h + 20;
    while pos < end {
        let kind = b[pos];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            pos += 1;
            continue;
        }
        if pos + 2 > end {
            return false;
        }
        let len = usize::from(b[pos + 1]);
        if len < 2 || pos + len > end {
            return false;
        }
        if kind == 2 {
            if len != 4 {
                return false;
            }
            let old = rd16(b, pos + 2);
            if old > MSS_CLAMP {
                wr16(b, pos + 2, MSS_CLAMP);
                if (pos - h) & 1 == 1 {
                    // pos + 4 < end here (end - h is even, the value ends at an odd offset), so the second word is inside the header.
                    let w0 = rd16(b, pos + 1);
                    let w1 = rd16(b, pos + 3);
                    csum::replace16(b, h + 16, (w0 & 0xff00) | (old >> 8), w0);
                    csum::replace16(b, h + 16, ((old & 0xff) << 8) | (w1 & 0xff), w1);
                } else {
                    csum::replace16(b, h + 16, old, MSS_CLAMP);
                }
            }
        }
        pos += len;
    }
    true
}

/// Source address and port of a packet's flow key as seen on the USB side: (source, destination, local port, remote port).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuple {
    /// IPv4 source.
    pub src: u32,
    /// IPv4 destination.
    pub dst: u32,
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// IP protocol.
    pub proto: u8,
}

/// Read the 5-tuple of a validated packet with header length `h`.
pub fn tuple(b: &[u8], h: usize) -> Tuple {
    Tuple { src: rd32(b, 12), dst: rd32(b, 16), sport: rd16(b, h), dport: rd16(b, h + 2), proto: b[9] }
}

/// NAT rewrite with RFC 1624 incremental updates: addresses touch the IP header and the L4 pseudo-header, the port only the L4 checksum.
/// `port_offset` is 0 to rewrite the source port, 2 for the destination port. A UDP datagram that carries no checksum keeps carrying none.
pub fn nat_rewrite(b: &mut [u8], h: usize, src: u32, dst: u32, port_offset: usize, port: u16) {
    let old_src = rd32(b, 12);
    let old_dst = rd32(b, 16);
    let old_port = rd16(b, h + port_offset);
    let l4 = h + if b[9] == TCP { 16 } else { 6 };
    csum::replace32(b, 10, old_src, src);
    csum::replace32(b, 10, old_dst, dst);
    if b[9] == TCP || (b[l4] | b[l4 + 1]) != 0 {
        csum::replace32(b, l4, old_src, src);
        csum::replace32(b, l4, old_dst, dst);
        csum::replace16(b, l4, old_port, port);
        if b[9] == UDP && (b[l4] | b[l4 + 1]) == 0 {
            b[l4] = 0xff;
            b[l4 + 1] = 0xff;
        }
    }
    wr32(b, 12, src);
    wr32(b, 16, dst);
    wr16(b, h + port_offset, port);
}

/// Decrement the TTL (the caller has checked it is at least 2) and fix the header checksum incrementally.
pub fn ttl_decrement(b: &mut [u8]) {
    let old = rd16(b, 8);
    b[8] = b[8].wrapping_sub(1);
    let new = rd16(b, 8);
    csum::replace16(b, 10, old, new);
}

/// True for an address in the alias range 198.18.0.0/15 (the addresses the USB host uses to reach peers).
#[inline]
pub fn is_alias(a: u32) -> bool {
    a & ALIAS_MASK == ALIAS_NET
}

/// True for a usable USB host address: inside 192.168.77.0/24 and neither the gateway (.1) nor broadcast (.255).
#[inline]
pub fn is_usb_host(a: u32) -> bool {
    a & 0xffff_ff00 == USB_HOST_NET && a != USB_HOST_NET + 1 && a != USB_HOST_NET + 255
}
