//! A reply as one Ethernet frame (what lwIP's `dhcps` puts on the wire).
//!
//! lwIP sends a unicast reply to the client's address through a temporary static ARP entry `yiaddr -> chaddr`, i.e. an Ethernet frame to the client's MAC with IPv4
//! destination `yiaddr`; a broadcast reply goes to ff:ff:ff:ff:ff:ff / 255.255.255.255. A TCP/IP stack that has no way to install such an entry cannot send the first
//! (the client does not answer ARP for an address it does not hold yet), so the firmware builds the frame here and hands it to the Wi-Fi driver. IPv4: TTL 255 (lwIP
//! `IP_DEFAULT_TTL`), no fragmentation, header checksum and UDP checksum computed.

use crate::{Dest, Reply};

/// Ethernet + IPv4 + UDP headers.
pub const HEADERS: usize = 14 + 20 + 8;

fn sum(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

/// Build the frame for `payload` (the reply bytes `out[..reply.len]`) from `server_ip` / `server_mac` to the destination of `reply`, UDP 67 to 68.
/// Returns the frame length, or `None` when `frame` is too small (`HEADERS + payload.len()`).
#[must_use]
pub fn build(reply: &Reply, payload: &[u8], server_ip: [u8; 4], server_mac: [u8; 6], frame: &mut [u8]) -> Option<usize> {
    let total = HEADERS + payload.len();
    if frame.len() < total || total - 14 > usize::from(u16::MAX) {
        return None;
    }
    let (dst_mac, dst_ip) = match reply.dest {
        Dest::Broadcast => ([0xff; 6], [255; 4]),
        Dest::Unicast { ip, mac } => (mac, ip),
    };
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&server_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    let ip_len = (total - 14) as u16;
    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
    frame[18..22].copy_from_slice(&[0, 0, 0, 0]); // id 0, no flags, no fragment
    frame[22] = 255;
    frame[23] = 17;
    frame[24..26].copy_from_slice(&[0, 0]);
    frame[26..30].copy_from_slice(&server_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let csum = fold(sum(&frame[14..34], 0));
    frame[24..26].copy_from_slice(&csum.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    frame[34..36].copy_from_slice(&67u16.to_be_bytes());
    frame[36..38].copy_from_slice(&68u16.to_be_bytes());
    frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
    frame[40..42].copy_from_slice(&[0, 0]);
    frame[42..total].copy_from_slice(payload);
    // UDP checksum over the pseudo header
    let mut acc = sum(&server_ip, 0);
    acc = sum(&dst_ip, acc);
    acc += 17 + u32::from(udp_len);
    acc = sum(&frame[34..total], acc);
    let mut u = fold(acc);
    if u == 0 {
        u = 0xFFFF;
    }
    frame[40..42].copy_from_slice(&u.to_be_bytes());
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReplyKind;

    fn reply(dest: Dest) -> Reply {
        Reply { len: 5, dest, kind: ReplyKind::Offer, yiaddr: [192, 168, 4, 2], mac: [2, 0, 0, 0, 0, 9], static_arp: true }
    }

    #[test]
    fn unicast_goes_to_the_client_mac_and_ip() {
        let r = reply(Dest::Unicast { ip: [192, 168, 4, 2], mac: [2, 0, 0, 0, 0, 9] });
        let mut f = [0u8; 100];
        let n = build(&r, b"hello", [192, 168, 4, 1], [0x10, 0x20, 0x30, 0x40, 0x50, 0x60], &mut f).unwrap();
        assert_eq!(n, HEADERS + 5);
        assert_eq!(&f[0..6], &[2, 0, 0, 0, 0, 9]);
        assert_eq!(&f[6..12], &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
        assert_eq!(&f[30..34], &[192, 168, 4, 2]);
        assert_eq!(&f[34..38], &[0, 67, 0, 68]);
        assert_eq!(&f[42..47], b"hello");
    }

    #[test]
    fn broadcast_goes_to_all_ones() {
        let mut f = [0u8; 100];
        build(&reply(Dest::Broadcast), b"x", [192, 168, 4, 1], [1; 6], &mut f).unwrap();
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[30..34], &[255; 4]);
    }

    #[test]
    fn checksums_verify() {
        for payload in [&b""[..], b"a", b"abc", &[0xffu8; 548][..], &[0x55u8; 547][..]] {
            let mut f = [0u8; 700];
            let n = build(&reply(Dest::Broadcast), payload, [192, 168, 4, 1], [1; 6], &mut f).unwrap();
            // IPv4 header: the folded sum of the whole header including the checksum is 0xFFFF
            assert_eq!(fold(sum(&f[14..34], 0)), 0);
            // UDP: pseudo header + segment verifies to 0
            let mut acc = sum(&f[26..30], 0);
            acc = sum(&f[30..34], acc);
            acc += 17 + (n - 34) as u32;
            acc = sum(&f[34..n], acc);
            assert_eq!(fold(acc), 0, "payload {}", payload.len());
        }
    }

    #[test]
    fn too_small_buffer_is_refused() {
        let mut f = [0u8; 43];
        assert!(build(&reply(Dest::Broadcast), b"xx", [1; 4], [1; 6], &mut f).is_none());
    }
}
