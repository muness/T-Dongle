//! `TokioNet`: the runtime's `Net` on tokio sockets, with the switches the harness needs (block UDP, bounce the Wi-Fi link, cut every TCP connection).

use embedded_io_async::{ErrorType, Read, Write};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_runtime::net::{Net, NetError, NetV4, TcpConn, TcpRole, UdpConn, UdpRole};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// State shared between the net, its handles and the test.
#[derive(Debug)]
pub struct NetControl {
    /// Drop every UDP datagram, both ways (the "DERP only" switch).
    pub udp_blocked: AtomicBool,
    /// The link generation: bumped by [`NetControl::bounce`]; sockets of an older generation fail.
    pub generation: AtomicU32,
    /// The link is up.
    pub link_up: AtomicBool,
    /// Every TCP handle fails and closes when this changes (a connection cut without a Wi-Fi bounce).
    pub tcp_epoch: AtomicU64,
    /// UDP datagrams sent / received / dropped by the block.
    pub udp_tx: AtomicU64,
    /// See `udp_tx`.
    pub udp_rx: AtomicU64,
    /// See `udp_tx`.
    pub udp_blocked_count: AtomicU64,
    /// TCP connections made.
    pub tcp_connects: AtomicU64,
    /// Where the control connection of slot `n` really goes (`host:port`), whatever name the runtime asked for: lets two memberships talk to two
    /// separate control servers although the runtime has one control host name, as on the device. Empty entries use the requested name.
    pub control_routes: Mutex<Vec<Option<SocketAddr>>>,
    /// Where the DNS forwarder's datagrams really go (the "resolver" the lease advertises is not listening on port 53 on the test host).
    pub dns_redirect: Mutex<Option<SocketAddr>>,
    /// Milliseconds a DERP connect takes before it is made (a slow start of the relay link, as after a move to another region: traffic arrives while it comes up).
    pub derp_connect_delay_ms: AtomicU32,
    /// Milliseconds every write to a DERP connection takes (a relay at about 1.4 KB per this many ms).
    pub derp_write_delay_ms: AtomicU32,
}

impl Default for NetControl {
    fn default() -> Self {
        NetControl {
            udp_blocked: AtomicBool::new(false),
            generation: AtomicU32::new(1),
            link_up: AtomicBool::new(true),
            tcp_epoch: AtomicU64::new(0),
            udp_tx: AtomicU64::new(0),
            udp_rx: AtomicU64::new(0),
            udp_blocked_count: AtomicU64::new(0),
            tcp_connects: AtomicU64::new(0),
            control_routes: Mutex::new(Vec::new()),
            dns_redirect: Mutex::new(None),
            derp_connect_delay_ms: AtomicU32::new(0),
            derp_write_delay_ms: AtomicU32::new(0),
        }
    }
}

impl NetControl {
    /// Send the control connections of slot `slot` to `addr`.
    pub fn route_control(&self, slot: usize, addr: SocketAddr) {
        let mut r = self.control_routes.lock().unwrap();
        if r.len() <= slot {
            r.resize(slot + 1, None);
        }
        r[slot] = Some(addr);
    }
    /// A Wi-Fi bounce: the link goes down and up again, the association generation changes, every socket of the old one fails.
    pub fn bounce(&self) {
        self.link_up.store(false, Ordering::SeqCst);
        self.tcp_epoch.fetch_add(1, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.link_up.store(true, Ordering::SeqCst);
    }
    /// Cut every TCP connection (the sockets fail on their next use).
    pub fn cut_tcp(&self) {
        self.tcp_epoch.fetch_add(1, Ordering::SeqCst);
    }
}

/// The network. `local_ip` is the address the runtime reports as the station's (and puts in its endpoints).
#[derive(Debug)]
pub struct TokioNet {
    /// Shared switches.
    pub ctl: Arc<NetControl>,
    /// The station address.
    pub local_ip: [u8; 4],
    /// The resolver the "lease" hands out.
    pub dns: Option<[u8; 4]>,
    taken: Mutex<HashSet<(u8, usize)>>,
}

impl TokioNet {
    /// A network on `local_ip` (use `127.0.0.1` for the all-loopback tests).
    pub fn new(ctl: Arc<NetControl>, local_ip: [u8; 4]) -> Self {
        TokioNet { ctl, local_ip, dns: None, taken: Mutex::new(HashSet::new()) }
    }
    fn take(&self, kind: u8, role: u8, slot: usize) -> bool {
        self.taken.lock().unwrap().insert((kind * 8 + role, slot))
    }
}

impl Net for TokioNet {
    type Tcp = TokioTcp;
    type Udp = TokioUdp;
    fn tcp(&self, role: TcpRole, slot: usize) -> Option<TokioTcp> {
        let r = match role {
            TcpRole::Control => 0,
            TcpRole::Derp => 1,
        };
        self.take(0, r, slot).then(|| TokioTcp {
            ctl: self.ctl.clone(),
            stream: None,
            epoch: 0,
            gen_: 0,
            route: (role == TcpRole::Control).then_some(slot),
            extra: role == TcpRole::Derp,
        })
    }
    fn udp(&self, role: UdpRole, slot: usize) -> Option<TokioUdp> {
        let r = match role {
            UdpRole::Member => 0,
            UdpRole::DnsUpstream => 1,
        };
        self.take(1, r, slot).then(|| TokioUdp { ctl: self.ctl.clone(), sock: None, dns: role == UdpRole::DnsUpstream })
    }
    async fn resolve(&self, host: &str) -> Result<[u8; 4], NetError> {
        resolve_v4(host, 0).await
    }
    fn ipv4(&self) -> Option<NetV4> {
        self.ctl.link_up.load(Ordering::SeqCst).then_some(NetV4 { addr: self.local_ip, prefix: 24, gateway: Some([127, 0, 0, 1]), dns: self.dns })
    }
    fn link_up(&self) -> bool {
        self.ctl.link_up.load(Ordering::SeqCst)
    }
    fn link_generation(&self) -> u32 {
        self.ctl.generation.load(Ordering::SeqCst)
    }
    fn member_buffer_bytes(&self) -> usize {
        // what the embassy-net implementation would hold per slot with its default buffers (the figure the memory table uses on the host)
        0
    }
}

async fn resolve_v4(host: &str, port: u16) -> Result<[u8; 4], NetError> {
    if let Some(ip) = tdongle_tailnet_runtime::net::parse_ipv4(host) {
        return Ok(ip);
    }
    let mut it = tokio::net::lookup_host((host, port)).await.map_err(|_| NetError::Dns)?;
    it.find_map(|a| match a {
        SocketAddr::V4(v) => Some(v.ip().octets()),
        SocketAddr::V6(_) => None,
    })
    .ok_or(NetError::Dns)
}

/// A TCP handle.
#[derive(Debug)]
pub struct TokioTcp {
    ctl: Arc<NetControl>,
    stream: Option<TcpStream>,
    epoch: u64,
    gen_: u32,
    route: Option<usize>,
    extra: bool,
}

impl TokioTcp {
    fn alive(&mut self) -> bool {
        if self.stream.is_some() && (self.ctl.tcp_epoch.load(Ordering::SeqCst) != self.epoch || self.ctl.generation.load(Ordering::SeqCst) != self.gen_) {
            self.stream = None;
        }
        self.stream.is_some()
    }
}

impl ErrorType for TokioTcp {
    type Error = NetError;
}

impl Read for TokioTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        if !self.alive() {
            return Err(NetError::Closed);
        }
        let epoch = self.epoch;
        let ctl = self.ctl.clone();
        let s = self.stream.as_mut().ok_or(NetError::Closed)?;
        // poll the cut switch while waiting: a cut socket must fail even when the peer is silent
        loop {
            tokio::select! {
                r = s.read(buf) => return r.map_err(|_| NetError::Io),
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                    if ctl.tcp_epoch.load(Ordering::SeqCst) != epoch {
                        self.stream = None;
                        return Err(NetError::Closed);
                    }
                }
            }
        }
    }
}

impl Write for TokioTcp {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        if !self.alive() {
            return Err(NetError::Closed);
        }
        let n = self.stream.as_mut().ok_or(NetError::Closed)?.write(buf).await.map_err(|_| NetError::Io)?;
        if self.extra {
            // a relay that takes its time (a round trip per window, a slow link): the writer is paced, the sender above it must be held back, not dropped
            let ms = self.ctl.derp_write_delay_ms.load(Ordering::Relaxed);
            if ms != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(u64::from(ms))).await;
            }
        }
        Ok(n)
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        if !self.alive() {
            return Err(NetError::Closed);
        }
        self.stream.as_mut().ok_or(NetError::Closed)?.flush().await.map_err(|_| NetError::Io)
    }
}

impl TcpConn for TokioTcp {
    async fn connect(&mut self, host: &str, port: u16) -> Result<(), NetError> {
        self.stream = None;
        if !self.ctl.link_up.load(Ordering::SeqCst) {
            return Err(NetError::NoRoute);
        }
        let routed = self.route.and_then(|slot| self.ctl.control_routes.lock().unwrap().get(slot).copied().flatten());
        let target = match routed {
            Some(a) => a,
            None => {
                let ip = resolve_v4(host, port).await?;
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
            }
        };
        if self.extra {
            let ms = self.ctl.derp_connect_delay_ms.load(Ordering::Relaxed);
            if ms != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(u64::from(ms))).await;
            }
        }
        let s = TcpStream::connect(target).await.map_err(|_| NetError::Connect)?;
        s.set_nodelay(true).ok();
        self.epoch = self.ctl.tcp_epoch.load(Ordering::SeqCst);
        self.gen_ = self.ctl.generation.load(Ordering::SeqCst);
        self.ctl.tcp_connects.fetch_add(1, Ordering::Relaxed);
        self.stream = Some(s);
        Ok(())
    }
    fn close(&mut self) {
        self.stream = None;
    }
}

/// A UDP handle.
#[derive(Debug)]
pub struct TokioUdp {
    ctl: Arc<NetControl>,
    sock: Option<UdpSocket>,
    dns: bool,
}

impl UdpConn for TokioUdp {
    fn bind(&mut self, port: u16) -> Result<u16, NetError> {
        self.sock = None;
        let std_sock = std::net::UdpSocket::bind(("0.0.0.0", port)).map_err(|_| NetError::Bind)?;
        std_sock.set_nonblocking(true).map_err(|_| NetError::Bind)?;
        let port = std_sock.local_addr().map_err(|_| NetError::Bind)?.port();
        self.sock = Some(UdpSocket::from_std(std_sock).map_err(|_| NetError::Bind)?);
        Ok(port)
    }
    fn close(&mut self) {
        self.sock = None;
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ep), NetError> {
        let s = self.sock.as_ref().ok_or(NetError::Closed)?;
        loop {
            let (n, from) = s.recv_from(buf).await.map_err(|_| NetError::Io)?;
            if self.ctl.udp_blocked.load(Ordering::Relaxed) {
                self.ctl.udp_blocked_count.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let SocketAddr::V4(v4) = from else { continue };
            self.ctl.udp_rx.fetch_add(1, Ordering::Relaxed);
            return Ok((n, Ep::v4(v4.ip().octets(), v4.port())));
        }
    }
    async fn wait_readable(&self) -> Result<(), NetError> {
        let s = self.sock.as_ref().ok_or(NetError::Closed)?;
        s.readable().await.map_err(|_| NetError::Io)
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> Result<Option<(usize, Ep)>, NetError> {
        let s = self.sock.as_ref().ok_or(NetError::Closed)?;
        loop {
            match s.try_recv_from(buf) {
                Ok((n, from)) => {
                    if self.ctl.udp_blocked.load(Ordering::Relaxed) {
                        self.ctl.udp_blocked_count.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let SocketAddr::V4(v4) = from else { continue };
                    self.ctl.udp_rx.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some((n, Ep::v4(v4.ip().octets(), v4.port()))));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(_) => return Err(NetError::Io),
            }
        }
    }
    async fn wait_writable(&self) -> Result<(), NetError> {
        let s = self.sock.as_ref().ok_or(NetError::Closed)?;
        s.writable().await.map_err(|_| NetError::Io)
    }
    fn try_send_to(&self, buf: &[u8], dst: Ep) -> Result<bool, NetError> {
        let s = self.sock.as_ref().ok_or(NetError::Closed)?;
        if self.ctl.udp_blocked.load(Ordering::Relaxed) {
            self.ctl.udp_blocked_count.fetch_add(1, Ordering::Relaxed);
            return Ok(true);
        }
        let Some(o) = dst.v4_octets() else { return Ok(true) };
        let redirect = if self.dns { *self.ctl.dns_redirect.lock().unwrap() } else { None };
        let to = redirect.unwrap_or(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(o), dst.port())));
        match s.try_send_to(buf, to) {
            Ok(_) => {
                self.ctl.udp_tx.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(_) => Err(NetError::Io),
        }
    }
    async fn send_to(&self, buf: &[u8], dst: Ep) -> Result<(), NetError> {
        let s = self.sock.as_ref().ok_or(NetError::Closed)?;
        if self.ctl.udp_blocked.load(Ordering::Relaxed) {
            self.ctl.udp_blocked_count.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let Some(o) = dst.v4_octets() else { return Ok(()) };
        self.ctl.udp_tx.fetch_add(1, Ordering::Relaxed);
        let redirect = if self.dns { *self.ctl.dns_redirect.lock().unwrap() } else { None };
        let to = redirect.unwrap_or(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(o), dst.port())));
        s.send_to(buf, to).await.map(|_| ()).map_err(|_| NetError::Io)
    }
}
