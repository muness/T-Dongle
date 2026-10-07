//! The network the runtime runs on: a small abstraction over "TCP connect, UDP socket, DNS resolve, link facts".
//!
//! Two implementations exist: [`crate::net_embassy::EmbassyNet`] (`embassy_net::Stack`, feature `embassy-net`, the firmware) and `TokioNet` in
//! `tdongle-tailnet-host` (the host harness).
//!
//! # Persistent socket handles
//!
//! A socket is a long-lived **handle** that the runtime takes once per (role, membership slot) and keeps for the life of the program; it is connected,
//! closed and connected again. This is what lets the embassy-net implementation own its buffers as `&'static mut [u8]` ("caller-supplied static
//! buffers": the firmware hands the buffers to [`crate::net_embassy::EmbassyNet::new`] once) without any `unsafe` and without a self-referential
//! stream type: a `TcpSocket<'static>` is created once from the buffers of its slot and re-used with `abort()` + `connect()`, the idiom of embassy-net.
//! The sizes of those buffers are const generics of the buffer set ([`crate::net_embassy::NetBuffers`]) and are reported by [`crate::sizes`].
//!
//! # Cancel safety
//!
//! Every `async fn` here may be dropped at any `.await`: a dropped `connect` leaves the handle unconnected-or-aborting (call [`TcpConn::close`] before
//! reusing it), a dropped `read` / `recv_from` loses nothing (the data stays in the socket), a dropped `write` may have written a prefix of its
//! buffer (the runtime closes the connection after a write is cancelled; see `derp.rs`).

use embedded_io_async::{ErrorKind, Read, Write};
use tdongle_tailnet_disco::Ep;

/// Why a network operation failed. Every variant is also an `embedded_io` error kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// The name did not resolve (or resolved to no IPv4 address).
    Dns,
    /// The connection could not be made (refused, unreachable, timed out in the stack).
    Connect,
    /// The handle is not connected (or was closed under the operation).
    Closed,
    /// Any other failure of the socket.
    Io,
    /// The datagram does not fit.
    TooLarge,
    /// The UDP socket could not be bound (port in use, no free socket).
    Bind,
    /// No network (link down, no address).
    NoRoute,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for NetError {}

impl embedded_io_async::Error for NetError {
    fn kind(&self) -> ErrorKind {
        match self {
            NetError::Dns => ErrorKind::NotFound,
            NetError::Connect => ErrorKind::ConnectionRefused,
            NetError::Closed => ErrorKind::ConnectionAborted,
            NetError::TooLarge => ErrorKind::InvalidInput,
            NetError::NoRoute => ErrorKind::AddrNotAvailable,
            NetError::Io | NetError::Bind => ErrorKind::Other,
        }
    }
}

/// What a TCP handle is for. The buffer sizes differ per role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpRole {
    /// The control connection (`/key` fetch, then ts2021 over the same handle, one after the other).
    Control,
    /// The DERP relay connection (TLS inside).
    Derp,
}

/// What a UDP handle is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpRole {
    /// A membership's socket: DISCO, WireGuard and STUN share it (the C's disco socket doubles as the STUN socket).
    Member,
    /// The USB host's DNS forwarder (one for the whole gateway, slot 0).
    DnsUpstream,
}

/// A persistent TCP handle. Reading and writing are the `embedded-io-async` traits of the handle itself, valid while connected.
#[allow(async_fn_in_trait)]
pub trait TcpConn: Read + Write {
    /// Connect to `host:port` (a dotted IPv4 literal, or a name that is resolved first). Cancel-safe in the sense above. Any previous connection is
    /// aborted first.
    async fn connect(&mut self, host: &str, port: u16) -> Result<(), NetError>;
    /// Abort the connection (a reset, no lingering) and return the handle to the unconnected state. Idempotent, never blocks.
    fn close(&mut self);
}

/// A persistent UDP handle.
#[allow(async_fn_in_trait)]
pub trait UdpConn {
    /// Bind to `port` (0: any); returns the port actually bound. Closes a previous binding first.
    fn bind(&mut self, port: u16) -> Result<u16, NetError>;
    /// Close the socket (pending datagrams are dropped). Idempotent.
    fn close(&mut self);
    /// Wait for a datagram. Cancel-safe.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ep), NetError>;
    /// Send a datagram (waits for room in the socket's transmit buffer; datagrams the stack cannot route are dropped by it, not an error).
    async fn send_to(&self, buf: &[u8], dst: Ep) -> Result<(), NetError>;
    /// Wait until a datagram can be taken with [`UdpConn::try_recv_from`], without a buffer: the runtime keeps no receive buffer per socket (one shared
    /// scratch buffer serves every membership, taken only for the moment a datagram is copied out and handed on). Cancel-safe.
    async fn wait_readable(&self) -> Result<(), NetError>;
    /// Take a waiting datagram without waiting: `Ok(None)` if there is none.
    fn try_recv_from(&self, buf: &mut [u8]) -> Result<Option<(usize, Ep)>, NetError>;
    /// Wait until the transmit side may have room (a hint: [`UdpConn::try_send_to`] can still say no). Cancel-safe.
    async fn wait_writable(&self) -> Result<(), NetError>;
    /// Send a datagram without waiting: `Ok(true)` it was taken (or silently dropped as unroutable, as `send_to` does), `Ok(false)` there is no room now.
    fn try_send_to(&self, buf: &[u8], dst: Ep) -> Result<bool, NetError>;
}

/// The station's IPv4 configuration as the stack has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetV4 {
    /// Address.
    pub addr: [u8; 4],
    /// Prefix length.
    pub prefix: u8,
    /// Default gateway.
    pub gateway: Option<[u8; 4]>,
    /// The resolver the lease handed out (the USB host's DNS forwards to it).
    pub dns: Option<[u8; 4]>,
}

impl NetV4 {
    /// The netmask, host order.
    pub const fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else if self.prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix as u32)
        }
    }
    /// The address, host order.
    pub const fn addr_u32(&self) -> u32 {
        u32::from_be_bytes(self.addr)
    }
}

/// The network. All methods take `&self`: the handles are the only mutable state.
#[allow(async_fn_in_trait)]
pub trait Net {
    /// TCP handle.
    type Tcp: TcpConn;
    /// UDP handle.
    type Udp: UdpConn;
    /// Take the handle of a role for membership `slot` (0-based; slot 0 for gateway-wide roles). `None` if it was taken already or the
    /// implementation has no buffers for it. The runtime takes each handle exactly once.
    fn tcp(&self, role: TcpRole, slot: usize) -> Option<Self::Tcp>;
    /// As [`Net::tcp`] for UDP.
    fn udp(&self, role: UdpRole, slot: usize) -> Option<Self::Udp>;
    /// Resolve `host` to an IPv4 address. Cancel-safe.
    async fn resolve(&self, host: &str) -> Result<[u8; 4], NetError>;
    /// The station's IPv4 configuration, `None` while there is none (not associated, no lease).
    fn ipv4(&self) -> Option<NetV4>;
    /// True while the link is up (associated).
    fn link_up(&self) -> bool;
    /// A number that changes on every (re)association: sockets of an older generation are dead and every session is restarted.
    fn link_generation(&self) -> u32;
    /// Bytes of socket buffers this network keeps per membership slot (for the memory table and admission); 0 if it keeps none.
    fn member_buffer_bytes(&self) -> usize {
        0
    }
}

/// Parse a dotted IPv4 literal (`a.b.c.d`, decimal, no leading `+`), as `connect` does before it resolves a name.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[n] = part.parse::<u16>().ok().filter(|&v| v <= 255)? as u8;
        n += 1;
    }
    (n == 4).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_literals() {
        assert_eq!(parse_ipv4("127.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_ipv4("192.168.77.1"), Some([192, 168, 77, 1]));
        for bad in ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1..2.3", "derp1.tailscale.com", "1.2.3.-4"] {
            assert_eq!(parse_ipv4(bad), None, "{bad}");
        }
    }

    #[test]
    fn mask_of_prefix() {
        let c = |p| NetV4 { addr: [10, 0, 0, 2], prefix: p, gateway: None, dns: None }.mask();
        assert_eq!((c(0), c(24), c(32), c(40), c(25)), (0, 0xffff_ff00, u32::MAX, u32::MAX, 0xffff_ff80));
    }
}
