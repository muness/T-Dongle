//! A UDP endpoint in DISCO's wire form: 16 address bytes (IPv4 as `::ffff:a.b.c.d`) and a port, 18 bytes, no padding.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Bytes of one endpoint on the wire (16 address + 2 port, big endian), also its size in memory.
pub const EP_LEN: usize = 18;

/// `127.3.3.40`, Tailscale's magic "DERP" address. A pong that answers a ping received over DERP reports it as its source, with the DERP region
/// number as the port (`tailcfg.DerpMagicIPAddr`).
pub const DERP_MAGIC_V4: [u8; 4] = [127, 3, 3, 40];

/// IP address and port. IPv4 is always held IPv4-mapped, so `1.2.3.4:5` built from four bytes equals the same endpoint decoded from the wire and an
/// IPv4-mapped IPv6 address is the IPv4 address (Go's `Addr.Unmap`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ep {
    ip: [u8; 16],
    port: u16,
}

impl Ep {
    /// The all-zero endpoint (`[::]:0`): "none".
    pub const NONE: Ep = Ep { ip: [0; 16], port: 0 };

    /// An IPv4 endpoint from four octets.
    pub const fn v4(o: [u8; 4], port: u16) -> Ep {
        Ep { ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3]], port }
    }
    /// An IPv4 endpoint from a host-order `u32` (the C's `uint32_t ip`).
    pub const fn from_u32(ip: u32, port: u16) -> Ep {
        Ep::v4(ip.to_be_bytes(), port)
    }
    /// An endpoint from 16 address bytes (an IPv4-mapped address is an IPv4 endpoint).
    pub const fn v6(ip: [u8; 16], port: u16) -> Ep {
        Ep { ip, port }
    }
    /// The 16 address bytes.
    pub const fn ip16(&self) -> &[u8; 16] {
        &self.ip
    }
    /// The port.
    pub const fn port(&self) -> u16 {
        self.port
    }
    /// True for an IPv4 (IPv4-mapped) endpoint.
    pub fn is_v4(&self) -> bool {
        self.ip[..10] == [0; 10] && self.ip[10] == 0xff && self.ip[11] == 0xff
    }
    /// The four octets of an IPv4 endpoint.
    pub fn v4_octets(&self) -> Option<[u8; 4]> {
        if self.is_v4() { Some([self.ip[12], self.ip[13], self.ip[14], self.ip[15]]) } else { None }
    }
    /// The host-order `u32` of an IPv4 endpoint.
    pub fn v4_u32(&self) -> Option<u32> {
        self.v4_octets().map(u32::from_be_bytes)
    }
    /// A usable probe target: a non-zero port and a non-zero, non-multicast address.
    pub fn is_usable(&self) -> bool {
        if self.port == 0 {
            return false;
        }
        match self.v4_octets() {
            Some(o) => o != [0; 4] && o[0] < 224,
            None => self.ip != [0; 16] && self.ip[0] != 0xff,
        }
    }
    /// True for the DERP magic address.
    pub fn is_derp_magic(&self) -> bool {
        self.v4_octets() == Some(DERP_MAGIC_V4)
    }
    /// Loopback, link-local or private address (Go's `IsLoopback`, `IsLinkLocalUnicast`, `IsPrivate` rank).
    fn locality(&self) -> u8 {
        match self.v4_octets() {
            Some(o) if o[0] == 127 => 50,
            Some(o) if o[0] == 169 && o[1] == 254 => 30,
            Some(o) if o[0] == 10 || (o[0] == 172 && (16..32).contains(&o[1])) || (o[0] == 192 && o[1] == 168) => 20,
            Some(_) => 0,
            None if self.ip[..15] == [0; 15] && self.ip[15] == 1 => 50,
            None if self.ip[0] == 0xfe && self.ip[1] & 0xc0 == 0x80 => 30,
            None if self.ip[0] & 0xfe == 0xfc => 20,
            None => 0,
        }
    }
    /// Go's address preference points before latency (`betterAddr`): loopback 50, link-local 30, private 20, and IPv6 +10.
    pub(crate) fn preference_points(&self) -> u32 {
        u32::from(self.locality()) + if self.is_v4() { 0 } else { 10 }
    }
    /// Decode 18 wire bytes.
    pub fn from_wire(b: &[u8]) -> Option<Ep> {
        if b.len() < EP_LEN {
            return None;
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&b[..16]);
        Some(Ep { ip, port: u16::from_be_bytes([b[16], b[17]]) })
    }
    /// Encode into 18 wire bytes (`out` must hold at least 18; the shorter bound is respected).
    pub fn write_wire(&self, out: &mut [u8]) {
        if out.len() >= EP_LEN {
            out[..16].copy_from_slice(&self.ip);
            out[16..EP_LEN].copy_from_slice(&self.port.to_be_bytes());
        }
    }
    /// As a `core::net` socket address.
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self.v4_octets() {
            Some(o) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), self.port),
            None => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(self.ip)), self.port),
        }
    }
}

impl Default for Ep {
    fn default() -> Self {
        Ep::NONE
    }
}

impl From<SocketAddr> for Ep {
    fn from(a: SocketAddr) -> Ep {
        match a {
            SocketAddr::V4(v) => Ep::v4(v.ip().octets(), v.port()),
            SocketAddr::V6(v) => Ep::v6(v.ip().octets(), v.port()),
        }
    }
}

impl fmt::Debug for Ep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Ep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_socket_addr() {
            SocketAddr::V4(a) => write!(f, "{a}"),
            SocketAddr::V6(a) => write!(f, "{a}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_mapped_is_v4() {
        let a = Ep::v4([1, 2, 3, 4], 567);
        let mut w = [0u8; 18];
        a.write_wire(&mut w);
        assert_eq!(w, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4, 2, 0x37]);
        assert_eq!(Ep::from_wire(&w), Some(a));
        assert_eq!(Ep::v6(*a.ip16(), 567), a);
        assert_eq!(a.v4_u32(), Some(0x0102_0304));
        assert_eq!(Ep::from_u32(0x0102_0304, 567), a);
        assert!(a.is_v4() && a.is_usable());
    }

    #[test]
    fn usable_rules() {
        assert!(!Ep::NONE.is_usable());
        assert!(!Ep::v4([1, 2, 3, 4], 0).is_usable());
        assert!(!Ep::v4([0, 0, 0, 0], 5).is_usable());
        assert!(!Ep::v4([239, 1, 1, 1], 5).is_usable());
        assert!(Ep::v6([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x56], 789).is_usable());
        assert!(Ep::v4(DERP_MAGIC_V4, 4).is_derp_magic());
    }

    #[test]
    fn preference_points() {
        assert_eq!(Ep::v4([127, 0, 0, 1], 1).preference_points(), 50);
        assert_eq!(Ep::v4([169, 254, 1, 1], 1).preference_points(), 30);
        assert_eq!(Ep::v4([192, 168, 1, 1], 1).preference_points(), 20);
        assert_eq!(Ep::v4([172, 16, 0, 1], 1).preference_points(), 20);
        assert_eq!(Ep::v4([172, 32, 0, 1], 1).preference_points(), 0);
        assert_eq!(Ep::v4([8, 8, 8, 8], 1).preference_points(), 0);
        let v6 = Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 1);
        assert_eq!(v6.preference_points(), 10);
    }

    #[test]
    fn display() {
        extern crate std;
        use std::string::ToString;
        assert_eq!(Ep::v4([2, 3, 4, 5], 1234).to_string(), "2.3.4.5:1234");
        let v6 = Ep::v6([0xfe, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0, 0], 6666);
        assert_eq!(v6.to_string(), "[fed0::12:0]:6666");
        assert_eq!(core::mem::size_of::<Ep>(), 18);
    }
}
