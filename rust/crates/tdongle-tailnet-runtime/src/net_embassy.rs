//! [`Net`] for `embassy_net::Stack` (feature `embassy-net`), with the socket buffers supplied by the firmware as `&'static mut`.
//!
//! # Buffers and what they cost
//!
//! [`NetBuffers`] is one static (put it in a `StaticCell`); its const parameters are the buffer sizes, and [`NetBuffers::BYTES`] / [`NetBuffers::PER_MEMBER`] /
//! [`NetBuffers::GATEWAY`] report them. The defaults of [`GatewayBuffers`] follow the C's windows where they matter and shrink them where the C's lwIP
//! windows were dynamic: the control connection carries a map stream (a few KiB at a time, `rx 4,096`); the DERP connection's receive window is the
//! relay's throughput (`rx 5,760`, the C's baseline `TCP_WND`, and the figure `tdongle-tailnet-tls::lease` documents; the C's 8,640 is
//! `tcp_window::SDKCONFIG.tcp_wnd` and would be `DERP_RX = 8640`); transmit buffers hold one TLS record's worth (`2,048`); the UDP socket holds four
//! datagrams on receive (`4 * 1,600`: bursts of DISCO and WireGuard arrive together) and two on transmit (`2 * 1,600`: the stack drains it at once). Per membership that is [`GatewayBuffers::PER_MEMBER`] bytes; they are static, so they are **not** heap.
//!
//! # Port ranges
//!
//! `tdongle-tailnet-wifimux` documents that the NAT's mapped range (49152..=61439) must not collide with the stack's own client ports; the runtime binds its
//! UDP sockets itself (`udp_port_base + slot`, below 49152) and **TCP client ports are chosen by embassy-net** (ephemeral, sequential from a seeded start in
//! 1025..=65535). Until the stack can bind a TCP client to a chosen local port, firmware should call `wifimux`'s `reserve_local_port` for the ports its
//! `Stack` hands out, or move `NaptConfig::port_start`: an open point in the crate docs.

use crate::net::{Net, NetError, NetV4, TcpConn, TcpRole, UdpConn, UdpRole, parse_ipv4};
use crate::shared::MAX_RUN;
use core::cell::RefCell;
use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::{self, TcpSocket};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Stack};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Duration, Timer, with_timeout};
use embedded_io_async::{ErrorType, Read, Write};
use tdongle_tailnet_disco::Ep;

/// Where the association generation comes from: the firmware's `WifiLink::association_generation()` (or anything that changes on re-association).
pub trait LinkGen: Sync {
    /// A number that changes on every (re)association.
    fn generation(&self) -> u32;
}

/// The socket buffers, as `&'static mut` slices, in the form [`EmbassyNet`] takes them.
#[derive(Debug)]
pub struct Slots {
    ctl: [Option<TcpBufs>; MAX_RUN],
    derp: [Option<TcpBufs>; MAX_RUN],
    udp: [Option<UdpBufs>; MAX_RUN],
    dns: Option<UdpBufs>,
    member_bytes: usize,
}

#[derive(Debug)]
struct TcpBufs {
    rx: &'static mut [u8],
    tx: &'static mut [u8],
}

#[derive(Debug)]
struct UdpBufs {
    rx_meta: &'static mut [PacketMetadata],
    rx: &'static mut [u8],
    tx_meta: &'static mut [PacketMetadata],
    tx: &'static mut [u8],
}

/// All the socket buffers of the gateway. `CTL_*` / `DERP_*` are TCP window sizes in bytes, `UDP_PKTS` the datagrams a UDP socket can queue each way and
/// `UDP_RX_BYTES` / `UDP_TX_BYTES` its byte capacity each way, `DNS_BYTES` the DNS forwarder's.
#[derive(Debug)]
pub struct NetBuffers<
    const CTL_RX: usize,
    const CTL_TX: usize,
    const DERP_RX: usize,
    const DERP_TX: usize,
    const UDP_PKTS: usize,
    const UDP_RX_BYTES: usize,
    const UDP_TX_BYTES: usize,
    const DNS_BYTES: usize,
> {
    ctl_rx: [[u8; CTL_RX]; MAX_RUN],
    ctl_tx: [[u8; CTL_TX]; MAX_RUN],
    derp_rx: [[u8; DERP_RX]; MAX_RUN],
    derp_tx: [[u8; DERP_TX]; MAX_RUN],
    udp_rx_meta: [[PacketMetadata; UDP_PKTS]; MAX_RUN],
    udp_tx_meta: [[PacketMetadata; UDP_PKTS]; MAX_RUN],
    udp_rx: [[u8; UDP_RX_BYTES]; MAX_RUN],
    udp_tx: [[u8; UDP_TX_BYTES]; MAX_RUN],
    dns_rx_meta: [PacketMetadata; 4],
    dns_tx_meta: [PacketMetadata; 4],
    dns_rx: [u8; DNS_BYTES],
    dns_tx: [u8; DNS_BYTES],
}

/// The buffer sizes the firmware starts with.
pub type GatewayBuffers = NetBuffers<4096, 2048, 5760, 2048, 4, 6400, 3200, 2048>;

impl<
    const CTL_RX: usize,
    const CTL_TX: usize,
    const DERP_RX: usize,
    const DERP_TX: usize,
    const UDP_PKTS: usize,
    const UDP_RX_BYTES: usize,
    const UDP_TX_BYTES: usize,
    const DNS_BYTES: usize,
> NetBuffers<CTL_RX, CTL_TX, DERP_RX, DERP_TX, UDP_PKTS, UDP_RX_BYTES, UDP_TX_BYTES, DNS_BYTES>
{
    /// Bytes one membership slot's sockets hold: control + DERP windows, the UDP socket's rings and metadata.
    pub const PER_MEMBER: usize = CTL_RX + CTL_TX + DERP_RX + DERP_TX + UDP_RX_BYTES + UDP_TX_BYTES + 2 * UDP_PKTS * core::mem::size_of::<PacketMetadata>();
    /// Bytes shared by the gateway (the DNS forwarder's socket).
    pub const GATEWAY: usize = 2 * DNS_BYTES + 2 * 4 * core::mem::size_of::<PacketMetadata>();
    /// Every byte of the set.
    pub const BYTES: usize = MAX_RUN * Self::PER_MEMBER + Self::GATEWAY;

    /// All zero. `const`, so a `static` works.
    pub const fn new() -> Self {
        NetBuffers {
            ctl_rx: [[0; CTL_RX]; MAX_RUN],
            ctl_tx: [[0; CTL_TX]; MAX_RUN],
            derp_rx: [[0; DERP_RX]; MAX_RUN],
            derp_tx: [[0; DERP_TX]; MAX_RUN],
            udp_rx_meta: [[PacketMetadata::EMPTY; UDP_PKTS]; MAX_RUN],
            udp_tx_meta: [[PacketMetadata::EMPTY; UDP_PKTS]; MAX_RUN],
            udp_rx: [[0; UDP_RX_BYTES]; MAX_RUN],
            udp_tx: [[0; UDP_TX_BYTES]; MAX_RUN],
            dns_rx_meta: [PacketMetadata::EMPTY; 4],
            dns_tx_meta: [PacketMetadata::EMPTY; 4],
            dns_rx: [0; DNS_BYTES],
            dns_tx: [0; DNS_BYTES],
        }
    }

    /// Split into the slots [`EmbassyNet::new`] takes.
    pub fn slots(&'static mut self) -> Slots {
        let NetBuffers { ctl_rx, ctl_tx, derp_rx, derp_tx, udp_rx_meta, udp_tx_meta, udp_rx, udp_tx, dns_rx_meta, dns_tx_meta, dns_rx, dns_tx } = self;
        let mut ctl = ctl_rx.iter_mut().zip(ctl_tx.iter_mut()).map(|(rx, tx)| Some(TcpBufs { rx: &mut rx[..], tx: &mut tx[..] }));
        let mut derp = derp_rx.iter_mut().zip(derp_tx.iter_mut()).map(|(rx, tx)| Some(TcpBufs { rx: &mut rx[..], tx: &mut tx[..] }));
        let mut udp = udp_rx_meta
            .iter_mut()
            .zip(udp_tx_meta.iter_mut())
            .zip(udp_rx.iter_mut().zip(udp_tx.iter_mut()))
            .map(|((rm, tm), (rx, tx))| Some(UdpBufs { rx_meta: &mut rm[..], rx: &mut rx[..], tx_meta: &mut tm[..], tx: &mut tx[..] }));
        Slots {
            ctl: core::array::from_fn(|_| ctl.next().flatten()),
            derp: core::array::from_fn(|_| derp.next().flatten()),
            udp: core::array::from_fn(|_| udp.next().flatten()),
            dns: Some(UdpBufs { rx_meta: &mut dns_rx_meta[..], rx: &mut dns_rx[..], tx_meta: &mut dns_tx_meta[..], tx: &mut dns_tx[..] }),
            member_bytes: Self::PER_MEMBER,
        }
    }
}

impl<
    const CTL_RX: usize,
    const CTL_TX: usize,
    const DERP_RX: usize,
    const DERP_TX: usize,
    const UDP_PKTS: usize,
    const UDP_RX_BYTES: usize,
    const UDP_TX_BYTES: usize,
    const DNS_BYTES: usize,
> Default for NetBuffers<CTL_RX, CTL_TX, DERP_RX, DERP_TX, UDP_PKTS, UDP_RX_BYTES, UDP_TX_BYTES, DNS_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

/// `Net` over an `embassy_net::Stack`.
pub struct EmbassyNet {
    stack: Stack<'static>,
    link: &'static dyn LinkGen,
    slots: Mutex<CriticalSectionRawMutex, RefCell<Slots>>,
}

impl core::fmt::Debug for EmbassyNet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmbassyNet")
    }
}

impl EmbassyNet {
    /// `stack` is the station's stack (its `Runner` must be running); `link` reports re-associations; `slots` come from [`NetBuffers::slots`].
    pub fn new(stack: Stack<'static>, link: &'static dyn LinkGen, slots: Slots) -> Self {
        EmbassyNet { stack, link, slots: Mutex::new(RefCell::new(slots)) }
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
        let b = self.slots.lock(|s| {
            let mut s = s.borrow_mut();
            match role {
                TcpRole::Control => s.ctl.get_mut(slot)?.take(),
                TcpRole::Derp => s.derp.get_mut(slot)?.take(),
            }
        })?;
        let mut sock = TcpSocket::new(self.stack, b.rx, b.tx);
        sock.set_timeout(Some(Duration::from_secs(30)));
        sock.set_nagle_enabled(false);
        Some(EmbTcp { stack: self.stack, sock })
    }

    fn udp(&self, role: UdpRole, slot: usize) -> Option<EmbUdp> {
        let b = self.slots.lock(|s| {
            let mut s = s.borrow_mut();
            match role {
                UdpRole::Member => s.udp.get_mut(slot)?.take(),
                UdpRole::DnsUpstream => s.dns.take(),
            }
        })?;
        Some(EmbUdp { sock: UdpSocket::new(self.stack, b.rx_meta, b.rx, b.tx_meta, b.tx) })
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
        self.slots.lock(|s| s.borrow().member_bytes)
    }
}

/// A TCP handle over a persistent `TcpSocket`.
pub struct EmbTcp {
    stack: Stack<'static>,
    sock: TcpSocket<'static>,
}

impl core::fmt::Debug for EmbTcp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmbTcp")
    }
}

fn tcp_err(_: tcp::Error) -> NetError {
    NetError::Closed
}

impl ErrorType for EmbTcp {
    type Error = NetError;
}

impl Read for EmbTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.sock.read(buf).await.map_err(tcp_err)
    }
}

impl Write for EmbTcp {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        self.sock.write(buf).await.map_err(tcp_err)
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        self.sock.flush().await.map_err(tcp_err)
    }
}

impl TcpConn for EmbTcp {
    async fn connect(&mut self, host: &str, port: u16) -> Result<(), NetError> {
        self.close();
        // `abort` only marks the socket closed: the reset reaches the peer when the stack next polls, and a `connect` that comes first overwrites the
        // connection's tuple so the reset is never sent (the peer would keep the old connection for good). Give the stack its turn.
        Timer::after_millis(2).await;
        // a socket can only connect from the closed state
        let closed = with_timeout(Duration::from_millis(500), async {
            while self.sock.state() != tcp::State::Closed {
                Timer::after_millis(1).await;
            }
        })
        .await;
        if closed.is_err() {
            return Err(NetError::Closed);
        }
        let ip = resolve(self.stack, host).await?;
        self.sock.connect(IpEndpoint::new(ip4(ip), port)).await.map_err(|e| match e {
            tcp::ConnectError::NoRoute => NetError::NoRoute,
            tcp::ConnectError::InvalidState => NetError::Closed,
            tcp::ConnectError::ConnectionReset => NetError::Io,
            tcp::ConnectError::TimedOut => NetError::Connect,
        })
    }
    fn close(&mut self) {
        self.sock.abort();
    }
}

/// A UDP handle over a persistent `UdpSocket`.
pub struct EmbUdp {
    sock: UdpSocket<'static>,
}

impl core::fmt::Debug for EmbUdp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmbUdp")
    }
}

impl UdpConn for EmbUdp {
    fn bind(&mut self, port: u16) -> Result<u16, NetError> {
        self.sock.close();
        self.sock.bind(IpListenEndpoint { addr: None, port }).map_err(|_| NetError::Bind)?;
        Ok(self.sock.endpoint().port)
    }
    fn close(&mut self) {
        self.sock.close();
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ep), NetError> {
        let (n, meta) = self.sock.recv_from(buf).await.map_err(|_| NetError::TooLarge)?;
        // the stack is built without IPv6 (`proto-ipv4` only), so every source is IPv4
        let IpAddress::Ipv4(v) = meta.endpoint.addr;
        Ok((n, Ep::v4(v.octets(), meta.endpoint.port)))
    }
    async fn send_to(&self, buf: &[u8], dst: Ep) -> Result<(), NetError> {
        let Some(o) = dst.v4_octets() else { return Ok(()) };
        match self.sock.send_to(buf, IpEndpoint::new(ip4(o), dst.port())).await {
            Ok(()) => Ok(()),
            // no route: the stack could not take the datagram (link down): dropped, counted by the caller as an error
            Err(embassy_net::udp::SendError::NoRoute) => Err(NetError::NoRoute),
            Err(embassy_net::udp::SendError::PacketTooLarge) => Err(NetError::TooLarge),
            Err(_) => Err(NetError::Io),
        }
    }
}
