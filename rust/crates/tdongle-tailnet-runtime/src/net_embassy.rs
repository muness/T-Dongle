//! [`Net`] for `embassy_net::Stack` (feature `embassy-net`), with the socket windows **taken from the pool when a connection is made and given back when it
//! is closed** (ADR 0002, "RAM fit"; the C's lwIP does the same with pbufs, bounded by the one elastic floor of ADR 0022).
//!
//! # Buffers and what they cost
//!
//! A [`SockMem`] hands out zeroed windows as `&'static mut [u8]` (embassy-net's sockets want that; the firmware's implementation takes them from the heap
//! through the shared [`tdongle_tailnet_pool::Pool`], so a refusal is a counted [`NetError::NoMem`] and the caller backs off). Nothing is static: the
//! UDP sockets' packet *metadata* (4 entries each way, a few hundred bytes) is taken the same way. The window sizes follow the C where they matter and shrink them
//! where the C's lwIP windows were dynamic ([`Windows`]): the control connection carries a map stream (a few KiB at a time, `rx 4,096`); the DERP
//! connection's receive window is the relay's throughput (`rx 5,760`, the C's baseline `TCP_WND`; the C's 8,640 is `tcp_window::SDKCONFIG.tcp_wnd`); the
//! DERP transmit buffer holds one TLS record's worth (`2,048`) and the control transmit buffer `1,024` (its writes are single requests, a few hundred bytes
//! to about 1.5 KB, which a short buffer takes in pieces: at worst one extra round trip per request, nothing on the map stream, which only the server
//! writes); the UDP socket holds four datagrams on receive (`4 * 1,600`: bursts of DISCO and WireGuard arrive together) and two on transmit. Per membership
//! that is [`Windows::PER_MEMBER`] bytes, **held only while the membership's sockets exist**.
//!
//! # Port ranges
//!
//! `tdongle-tailnet-wifimux` documents that the NAT's mapped range (49152..=61439) must not collide with the stack's own client ports; the runtime binds its
//! UDP sockets itself (`udp_port_base + slot`, below 49152) and **TCP client ports are chosen by embassy-net** (ephemeral, sequential from a seeded start in
//! 1025..=65535). Until the stack can bind a TCP client to a chosen local port, firmware should call `wifimux`'s `reserve_local_port` for the ports its
//! `Stack` hands out, or move `NaptConfig::port_start`: an open point in the crate docs.

use crate::net::{Net, NetError, NetV4, TcpConn, TcpRole, UdpConn, UdpRole, parse_ipv4};
use crate::shared::MAX_RUN;
use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::{self, TcpSocket};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Stack};
use embassy_time::{Duration, Timer, with_timeout};
use embedded_io_async::{ErrorType, Read, Write};
use tdongle_tailnet_disco::Ep;

/// Where the association generation comes from: the firmware's `WifiLink::association_generation()` (or anything that changes on re-association).
pub trait LinkGen: Sync {
    /// A number that changes on every (re)association.
    fn generation(&self) -> u32;
}

/// Where socket windows come from. The firmware implements it over the heap and the shared pool (the only `unsafe` of the buffer path lives there: the
/// windows must be `&'static mut` for embassy-net, and are reclaimed by address when the socket is gone); a test implements it over leaked boxes.
pub trait SockMem: Sync {
    /// A zeroed window of exactly `len` bytes, admitted against the heap floor; `None`: refused (counted by the implementation).
    fn take(&self, len: usize) -> Option<&'static mut [u8]>;
    /// `n` empty packet-metadata entries for a UDP socket (small: a few dozen bytes each), admitted like a window; `None`: refused.
    fn take_meta(&self, n: usize) -> Option<&'static mut [PacketMetadata]>;
    /// Give metadata back (as [`SockMem::give`]).
    fn give_meta(&self, addr: usize, n: usize);
    /// Give a window back: `addr` is the address of the slice [`SockMem::take`] returned, `len` its length. Called only after the socket that held the slice
    /// has been dropped; an address that was not handed out (or already given back) is ignored by the implementation.
    fn give(&self, addr: usize, len: usize);
}

/// The window sizes of one membership's sockets, in bytes. `CTL_*` / `DERP_*` are TCP windows, `UDP_*` the UDP socket's rings, `UDP_PKTS` the datagrams it can
/// queue each way, `DNS_BYTES` the DNS forwarder's window each way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    /// Control receive window.
    pub ctl_rx: usize,
    /// Control transmit window.
    pub ctl_tx: usize,
    /// DERP receive window.
    pub derp_rx: usize,
    /// DERP transmit window.
    pub derp_tx: usize,
    /// UDP receive ring.
    pub udp_rx: usize,
    /// UDP transmit ring.
    pub udp_tx: usize,
    /// DNS forwarder ring, each way.
    pub dns: usize,
}

impl Windows {
    /// The sizes the firmware starts with.
    pub const GATEWAY: Windows = Windows { ctl_rx: 4096, ctl_tx: 1024, derp_rx: 5760, derp_tx: 2048, udp_rx: 6400, udp_tx: 3200, dns: 1536 };
    /// Bytes one membership's sockets hold (windows only: the packet metadata is static).
    pub const fn per_member(&self) -> usize {
        self.ctl_rx + self.ctl_tx + self.derp_rx + self.derp_tx + self.udp_rx + self.udp_tx
    }
    /// Bytes the gateway's DNS forwarder holds while it is bound.
    pub const fn gateway(&self) -> usize {
        2 * self.dns
    }
    /// [`Windows::per_member`] of [`Windows::GATEWAY`].
    pub const PER_MEMBER: usize = Self::GATEWAY.per_member();
}

/// Datagrams a UDP socket can queue each way.
pub const UDP_PKTS: usize = 4;

/// `Net` over an `embassy_net::Stack`.
pub struct EmbassyNet {
    stack: Stack<'static>,
    link: &'static dyn LinkGen,
    mem: &'static dyn SockMem,
    win: Windows,
}

impl core::fmt::Debug for EmbassyNet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmbassyNet")
    }
}

impl EmbassyNet {
    /// `stack` is the station's stack (its `Runner` must be running); `link` reports re-associations; `mem` supplies the socket windows.
    pub fn new(stack: Stack<'static>, link: &'static dyn LinkGen, mem: &'static dyn SockMem) -> Self {
        EmbassyNet { stack, link, mem, win: Windows::GATEWAY }
    }
}

fn ip4(a: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::new(a[0], a[1], a[2], a[3]))
}

async fn resolve(stack: Stack<'static>, host: &str) -> Result<[u8; 4], NetError> {
    if let Some(ip) = parse_ipv4(host) {
        return Ok(ip);
    }
    let addrs = stack.dns_query(host, DnsQueryType::A).await.map_err(|_| NetError::Dns)?;
    addrs.iter().map(|IpAddress::Ipv4(v)| v.octets()).next().ok_or(NetError::Dns)
}

impl Net for EmbassyNet {
    type Tcp = EmbTcp;
    type Udp = EmbUdp;

    fn tcp(&self, role: TcpRole, slot: usize) -> Option<EmbTcp> {
        if slot >= MAX_RUN {
            return None;
        }
        let (rx, tx) = match role {
            TcpRole::Control => (self.win.ctl_rx, self.win.ctl_tx),
            TcpRole::Derp => (self.win.derp_rx, self.win.derp_tx),
        };
        Some(EmbTcp { stack: self.stack, mem: self.mem, rx_len: rx, tx_len: tx, sock: None, held: [(0, 0); 2] })
    }

    fn udp(&self, role: UdpRole, slot: usize) -> Option<EmbUdp> {
        if matches!(role, UdpRole::Member) && slot >= MAX_RUN {
            return None;
        }
        let (rx_len, tx_len) = match role {
            UdpRole::Member => (self.win.udp_rx, self.win.udp_tx),
            UdpRole::DnsUpstream => (self.win.dns, self.win.dns),
        };
        Some(EmbUdp { stack: self.stack, mem: self.mem, rx_len, tx_len, sock: None, held: [(0, 0); 2], held_meta: [(0, 0); 2] })
    }

    async fn resolve(&self, host: &str) -> Result<[u8; 4], NetError> {
        resolve(self.stack, host).await
    }

    fn ipv4(&self) -> Option<NetV4> {
        let c = self.stack.config_v4()?;
        Some(NetV4 {
            addr: c.address.address().octets(),
            prefix: c.address.prefix_len(),
            gateway: c.gateway.map(|g| g.octets()),
            dns: c.dns_servers.first().map(|d| d.octets()),
        })
    }

    fn link_up(&self) -> bool {
        self.stack.is_link_up()
    }

    fn link_generation(&self) -> u32 {
        self.link.generation()
    }

    fn member_buffer_bytes(&self) -> usize {
        self.win.per_member()
    }
}

/// Take a window pair from `mem`, or take nothing (a pair is useless with one half).
fn take_pair(mem: &dyn SockMem, rx_len: usize, tx_len: usize) -> Option<(&'static mut [u8], &'static mut [u8])> {
    let rx = mem.take(rx_len)?;
    match mem.take(tx_len) {
        Some(tx) => Some((rx, tx)),
        None => {
            mem.give(rx.as_ptr() as usize, rx.len());
            None
        }
    }
}

/// A TCP handle: the socket and its windows exist from `connect` until the handle is released (or connects again); the windows come from the [`SockMem`].
pub struct EmbTcp {
    stack: Stack<'static>,
    mem: &'static dyn SockMem,
    rx_len: usize,
    tx_len: usize,
    sock: Option<TcpSocket<'static>>,
    /// Address and length of the two windows the socket holds (receive, transmit); `(0, 0)` when none.
    held: [(usize, usize); 2],
}

impl core::fmt::Debug for EmbTcp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmbTcp")
    }
}

fn tcp_err(_: tcp::Error) -> NetError {
    NetError::Closed
}

impl EmbTcp {
    /// Drop the socket (it must be closed: the stack has had its turn to send the reset) and give its windows back.
    fn drop_socket(&mut self) {
        if self.sock.take().is_some() {
            for (addr, len) in core::mem::replace(&mut self.held, [(0, 0); 2]) {
                if len != 0 {
                    self.mem.give(addr, len);
                }
            }
        }
    }
}

impl Drop for EmbTcp {
    fn drop(&mut self) {
        self.drop_socket();
    }
}

impl ErrorType for EmbTcp {
    type Error = NetError;
}

impl Read for EmbTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        match self.sock.as_mut() {
            Some(s) => s.read(buf).await.map_err(tcp_err),
            None => Err(NetError::Closed),
        }
    }
}

impl Write for EmbTcp {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        match self.sock.as_mut() {
            Some(s) => s.write(buf).await.map_err(tcp_err),
            None => Err(NetError::Closed),
        }
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        match self.sock.as_mut() {
            Some(s) => s.flush().await.map_err(tcp_err),
            None => Err(NetError::Closed),
        }
    }
}

impl TcpConn for EmbTcp {
    async fn connect(&mut self, host: &str, port: u16) -> Result<(), NetError> {
        self.release().await;
        let ip = resolve(self.stack, host).await?;
        // the windows are taken now, after the name resolved: a connection that cannot be made holds nothing
        let Some((rx, tx)) = take_pair(self.mem, self.rx_len, self.tx_len) else { return Err(NetError::NoMem) };
        self.held = [(rx.as_ptr() as usize, rx.len()), (tx.as_ptr() as usize, tx.len())];
        let mut sock = TcpSocket::new(self.stack, rx, tx);
        sock.set_timeout(Some(Duration::from_secs(30)));
        sock.set_nagle_enabled(false);
        let r = sock.connect(IpEndpoint::new(ip4(ip), port)).await.map_err(|e| match e {
            tcp::ConnectError::NoRoute => NetError::NoRoute,
            tcp::ConnectError::InvalidState => NetError::Closed,
            tcp::ConnectError::ConnectionReset => NetError::Io,
            tcp::ConnectError::TimedOut => NetError::Connect,
        });
        self.sock = Some(sock);
        if r.is_err() {
            // a socket that did not connect holds its windows for nothing
            self.release().await;
        }
        r
    }
    fn close(&mut self) {
        if let Some(s) = self.sock.as_mut() {
            s.abort();
        }
    }
    async fn release(&mut self) {
        if let Some(s) = self.sock.as_mut() {
            // `abort` only marks the socket closed: the reset reaches the peer when the stack next polls, and a socket removed first would never send it (the
            // peer would keep the connection for good). Give the stack its turn, then wait for the closed state.
            s.abort();
            Timer::after_millis(2).await;
            let _ = with_timeout(Duration::from_millis(500), async {
                while s.state() != tcp::State::Closed {
                    Timer::after_millis(1).await;
                }
            })
            .await;
        }
        self.drop_socket();
    }
}

/// A UDP handle: the socket and its two rings exist from `bind` until `close`.
pub struct EmbUdp {
    stack: Stack<'static>,
    mem: &'static dyn SockMem,
    rx_len: usize,
    tx_len: usize,
    sock: Option<UdpSocket<'static>>,
    held: [(usize, usize); 2],
    /// Address and entry count of the two metadata arrays (receive, transmit).
    held_meta: [(usize, usize); 2],
}

impl core::fmt::Debug for EmbUdp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmbUdp")
    }
}

impl EmbUdp {
    /// Give back whatever windows and metadata are held (the socket is already gone).
    fn give_all(&mut self) {
        for (addr, len) in core::mem::replace(&mut self.held, [(0, 0); 2]) {
            if len != 0 {
                self.mem.give(addr, len);
            }
        }
        for (addr, n) in core::mem::replace(&mut self.held_meta, [(0, 0); 2]) {
            if n != 0 {
                self.mem.give_meta(addr, n);
            }
        }
    }
}

impl Drop for EmbUdp {
    fn drop(&mut self) {
        self.close();
    }
}

impl UdpConn for EmbUdp {
    fn bind(&mut self, port: u16) -> Result<u16, NetError> {
        self.close();
        let Some((rx, tx)) = take_pair(self.mem, self.rx_len, self.tx_len) else { return Err(NetError::NoMem) };
        self.held = [(rx.as_ptr() as usize, rx.len()), (tx.as_ptr() as usize, tx.len())];
        let (Some(rx_meta), Some(tx_meta)) = (self.mem.take_meta(UDP_PKTS), self.mem.take_meta(UDP_PKTS)) else {
            // a refused metadata array (or one of two): give back what was taken
            self.give_all();
            return Err(NetError::NoMem);
        };
        self.held_meta = [(rx_meta.as_ptr() as usize, rx_meta.len()), (tx_meta.as_ptr() as usize, tx_meta.len())];
        let mut sock = UdpSocket::new(self.stack, rx_meta, rx, tx_meta, tx);
        match sock.bind(IpListenEndpoint { addr: None, port }) {
            Ok(()) => {
                let p = sock.endpoint().port;
                self.sock = Some(sock);
                Ok(p)
            }
            Err(_) => {
                drop(sock);
                self.give_all();
                Err(NetError::Bind)
            }
        }
    }
    fn close(&mut self) {
        if let Some(s) = self.sock.as_mut() {
            s.close();
        }
        self.sock = None;
        self.give_all();
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ep), NetError> {
        let Some(sock) = self.sock.as_ref() else { return Err(NetError::Closed) };
        let (n, meta) = sock.recv_from(buf).await.map_err(|_| NetError::TooLarge)?;
        // the stack is built without IPv6 (`proto-ipv4` only), so every source is IPv4
        let IpAddress::Ipv4(v) = meta.endpoint.addr;
        Ok((n, Ep::v4(v.octets(), meta.endpoint.port)))
    }
    async fn wait_readable(&self) -> Result<(), NetError> {
        let Some(sock) = self.sock.as_ref() else { return Err(NetError::Closed) };
        sock.wait_recv_ready().await;
        Ok(())
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> Result<Option<(usize, Ep)>, NetError> {
        let Some(sock) = self.sock.as_ref() else { return Err(NetError::Closed) };
        // one poll with a waker that does nothing: a datagram is there or it is not (the task's own wait registers the real waker)
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match sock.poll_recv_from(buf, &mut cx) {
            core::task::Poll::Pending => Ok(None),
            core::task::Poll::Ready(Err(_)) => Err(NetError::TooLarge),
            core::task::Poll::Ready(Ok((n, meta))) => {
                let IpAddress::Ipv4(v) = meta.endpoint.addr;
                Ok(Some((n, Ep::v4(v.octets(), meta.endpoint.port))))
            }
        }
    }
    async fn wait_writable(&self) -> Result<(), NetError> {
        let Some(sock) = self.sock.as_ref() else { return Err(NetError::Closed) };
        sock.wait_send_ready().await;
        Ok(())
    }
    fn try_send_to(&self, buf: &[u8], dst: Ep) -> Result<bool, NetError> {
        let Some(sock) = self.sock.as_ref() else { return Err(NetError::Closed) };
        let Some(o) = dst.v4_octets() else { return Ok(true) };
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match sock.poll_send_to(buf, IpEndpoint::new(ip4(o), dst.port()), &mut cx) {
            core::task::Poll::Pending => Ok(false),
            core::task::Poll::Ready(Ok(())) => Ok(true),
            core::task::Poll::Ready(Err(embassy_net::udp::SendError::NoRoute)) => Err(NetError::NoRoute),
            core::task::Poll::Ready(Err(embassy_net::udp::SendError::PacketTooLarge)) => Err(NetError::TooLarge),
            core::task::Poll::Ready(Err(_)) => Err(NetError::Io),
        }
    }
    async fn send_to(&self, buf: &[u8], dst: Ep) -> Result<(), NetError> {
        let Some(sock) = self.sock.as_ref() else { return Err(NetError::Closed) };
        let Some(o) = dst.v4_octets() else { return Ok(()) };
        match sock.send_to(buf, IpEndpoint::new(ip4(o), dst.port())).await {
            Ok(()) => Ok(()),
            // no route: the stack could not take the datagram (link down): dropped, counted by the caller as an error
            Err(embassy_net::udp::SendError::NoRoute) => Err(NetError::NoRoute),
            Err(embassy_net::udp::SendError::PacketTooLarge) => Err(NetError::TooLarge),
            Err(_) => Err(NetError::Io),
        }
    }
}
