//! Byte-level helpers and the constants of the USB subnet (the C's `start_network`).

/// An Ethernet address.
pub type Mac = [u8; 6];
/// The Ethernet broadcast address.
pub const BROADCAST_MAC: Mac = [0xff; 6];

/// Pack four octets into the numeric form used throughout this crate (`192.168.77.1` is `0xC0A8_4D01`).
pub const fn ip4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}
/// The dongle on the USB netif (`IP4_ADDR(&ip.ip, 192, 168, 77, 1)`; also gateway and DNS).
pub const USB_IP: u32 = ip4(192, 168, 77, 1);
/// The USB subnet mask (255.255.255.0).
pub const USB_MASK: u32 = ip4(255, 255, 255, 0);
/// The alias range of the router, 198.18.0.0/15: `(dest & 0xfffe0000) == 0xc6120000` in `gateway_host_input`.
pub const ALIAS_NET: u32 = ip4(198, 18, 0, 0);
/// Mask of [`ALIAS_NET`].
pub const ALIAS_MASK: u32 = 0xfffe_0000;

/// True when `ip` is in the router's alias range (those packets are the router crate's, not NAPT's).
pub const fn is_alias(ip: u32) -> bool {
    ip & ALIAS_MASK == ALIAS_NET
}

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

/// True for an Ethernet group address (multicast or broadcast).
pub const fn mac_is_group(m: &Mac) -> bool {
    m[0] & 1 != 0
}

/// Write an Ethernet header; returns 14.
pub fn write_eth(out: &mut [u8], dst: Mac, src: Mac, ethertype: u16) -> usize {
    out[0..6].copy_from_slice(&dst);
    out[6..12].copy_from_slice(&src);
    wr16(out, 12, ethertype);
    14
}

/// EtherType of IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType of ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType of IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
