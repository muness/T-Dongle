//! A fake USB host: a smoltcp stack on a pair of channels, plugged into the runtime as its `UsbFrames`.
//!
//! The host behaves like a laptop on the NCM link: a DHCP client (against the runtime's DHCP server), a DNS client (asking 192.168.77.1:53), TCP clients
//! (an echo, an HTTP GET of `/bytes/N`, an upload to a byte sink). It runs on its own thread with its own tokio runtime; the test thread talks to it
//! through [`HostHandle`] (blocking calls with timeouts).

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, dns, tcp, udp};
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{DnsQueryType, EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use tdongle_tailnet_fw::UsbFrames;
use tokio::sync::{Notify, mpsc as tmpsc};

/// Counters the test reads.
#[derive(Debug, Default)]
pub struct UsbCounters {
    /// Frames the dongle sent to the host.
    pub to_host: AtomicU64,
    /// Frames the host sent to the dongle.
    pub from_host: AtomicU64,
    /// Frames the host dropped for lack of a... (none: unbounded) / frames refused by the simulated ring.
    pub refused: AtomicU64,
}

/// The dongle's end: the runtime's `UsbFrames`.
#[derive(Debug)]
pub struct FakeUsb {
    rx: tmpsc::UnboundedReceiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    /// The host has the data interface configured.
    pub ready: Arc<AtomicBool>,
    /// The link generation.
    pub generation: Arc<AtomicU32>,
    /// The carrier the runtime last set.
    pub carrier: Arc<AtomicBool>,
    /// Counters.
    pub counters: Arc<UsbCounters>,
}

impl UsbFrames for FakeUsb {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        loop {
            match self.rx.recv().await {
                Some(f) => {
                    let n = f.len().min(buf.len());
                    buf[..n].copy_from_slice(&f[..n]);
                    return n;
                }
                None => std::future::pending::<()>().await,
            }
        }
    }
    fn send(&mut self, frame: &[u8]) -> bool {
        self.counters.to_host.fetch_add(1, Ordering::Relaxed);
        self.tx.send(frame.to_vec()).is_ok()
    }
    fn host_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
    fn link_generation(&self) -> u32 {
        self.generation.load(Ordering::Relaxed)
    }
    fn set_carrier(&mut self, up: bool) {
        self.carrier.store(up, Ordering::Relaxed);
    }
}

/// What a test asks of the host.
enum Cmd {
    WaitDhcp(mpsc::Sender<Result<[u8; 4], String>>, Duration),
    Resolve(String, mpsc::Sender<Result<[u8; 4], String>>, Duration),
    Echo { addr: [u8; 4], port: u16, payload: Vec<u8>, reply: mpsc::Sender<Result<Vec<u8>, String>>, timeout: Duration },
    Get { addr: [u8; 4], port: u16, bytes: usize, reply: mpsc::Sender<Result<(usize, Duration), String>>, timeout: Duration },
    Upload { addr: [u8; 4], port: u16, bytes: usize, reply: mpsc::Sender<Result<(usize, Duration), String>>, timeout: Duration },
    EchoLoop { addr: [u8; 4], port: u16, payload: Vec<u8>, interval: Duration, stop: Arc<AtomicBool>, counts: (Arc<AtomicU32>, Arc<AtomicU32>), reply: mpsc::Sender<()> },
    UdpEcho { addr: [u8; 4], port: u16, payload: Vec<u8>, reply: mpsc::Sender<Result<Vec<u8>, String>>, timeout: Duration },
    Stop,
}

/// The test's handle on the host. Calls block the calling (test) thread until the host answers or the timeout passes.
#[derive(Debug)]
pub struct HostHandle {
    tx: tmpsc::UnboundedSender<Cmd>,
    join: Option<std::thread::JoinHandle<()>>,
    /// Counters.
    pub counters: Arc<UsbCounters>,
    /// USB state toggles shared with [`FakeUsb`].
    pub ready: Arc<AtomicBool>,
    /// See [`FakeUsb::generation`].
    pub generation: Arc<AtomicU32>,
    /// See [`FakeUsb::carrier`].
    pub carrier: Arc<AtomicBool>,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cmd")
    }
}

fn ask<T>(tx: &tmpsc::UnboundedSender<Cmd>, make: impl FnOnce(mpsc::Sender<T>) -> Cmd, wait: Duration) -> Result<T, String> {
    let (r_tx, r_rx) = mpsc::channel();
    tx.send(make(r_tx)).map_err(|_| "host stopped".to_string())?;
    r_rx.recv_timeout(wait + Duration::from_secs(2)).map_err(|_| "host did not answer".to_string())
}

impl HostHandle {
    /// Wait until DHCP bound; returns the host's address.
    pub fn wait_dhcp(&self, timeout: Duration) -> Result<[u8; 4], String> {
        ask(&self.tx, |r| Cmd::WaitDhcp(r, timeout), timeout)?
    }
    /// Resolve `name` (an A query to the resolver DHCP handed out: 192.168.77.1).
    pub fn resolve(&self, name: &str, timeout: Duration) -> Result<[u8; 4], String> {
        ask(&self.tx, |r| Cmd::Resolve(name.to_string(), r, timeout), timeout)?
    }
    /// Connect to `addr:port`, send `payload`, read the same number of bytes back, close. Returns what came back.
    pub fn echo(&self, addr: [u8; 4], port: u16, payload: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        ask(&self.tx, |r| Cmd::Echo { addr, port, payload: payload.to_vec(), reply: r, timeout }, timeout)?
    }
    /// `GET /bytes/<bytes>` over HTTP/1.0; returns the body bytes received and the time from connect to the last byte.
    pub fn get_bytes(&self, addr: [u8; 4], port: u16, bytes: usize, timeout: Duration) -> Result<(usize, Duration), String> {
        ask(&self.tx, |r| Cmd::Get { addr, port, bytes, reply: r, timeout }, timeout)?
    }
    /// Send `bytes` to the byte sink on `:9` and read its count back; returns the count the sink reports and the time.
    pub fn upload(&self, addr: [u8; 4], port: u16, bytes: usize, timeout: Duration) -> Result<(usize, Duration), String> {
        ask(&self.tx, |r| Cmd::Upload { addr, port, bytes, reply: r, timeout }, timeout)?
    }
    /// One long-lived TCP connection to `addr:port` that sends `payload` and reads it back every `interval` until `stop` is set (reconnecting after a
    /// failure). `counts` are bumped live: `(exchanges that worked, failures)`. Blocks the caller until `stop`.
    pub fn echo_loop(&self, addr: [u8; 4], port: u16, payload: &[u8], interval: Duration, stop: Arc<AtomicBool>, counts: (Arc<AtomicU32>, Arc<AtomicU32>)) {
        let (r_tx, r_rx) = mpsc::channel();
        if self.tx.send(Cmd::EchoLoop { addr, port, payload: payload.to_vec(), interval, stop, counts, reply: r_tx }).is_err() {
            return;
        }
        let _ = r_rx.recv();
    }
    /// Send one UDP datagram to `addr:port` (an Internet address: it goes through the NAT) and wait for the datagram that comes back.
    pub fn udp_echo(&self, addr: [u8; 4], port: u16, payload: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        ask(&self.tx, |r| Cmd::UdpEcho { addr, port, payload: payload.to_vec(), reply: r, timeout }, timeout)?
    }
    /// Simulate unplugging and replugging the cable: the link generation changes (the runtime tells the engine `UsbDetach`).
    pub fn replug(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Stop);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Create the pair: the dongle's `FakeUsb` and the running host.
pub fn spawn_host() -> (FakeUsb, HostHandle) {
    let (to_dongle_tx, to_dongle_rx) = tmpsc::unbounded_channel::<Vec<u8>>();
    let (from_dongle_tx, from_dongle_rx) = mpsc::channel::<Vec<u8>>();
    let counters = Arc::new(UsbCounters::default());
    let (ready, generation, carrier) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicU32::new(1)), Arc::new(AtomicBool::new(false)));
    let usb = FakeUsb {
        rx: to_dongle_rx,
        tx: from_dongle_tx,
        ready: ready.clone(),
        generation: generation.clone(),
        carrier: carrier.clone(),
        counters: counters.clone(),
    };
    let (cmd_tx, cmd_rx) = tmpsc::unbounded_channel::<Cmd>();
    let c2 = counters.clone();
    let join = std::thread::Builder::new()
        .name("fake-usb-host".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, host_main(to_dongle_tx, from_dongle_rx, cmd_rx, c2));
        })
        .unwrap();
    (usb, HostHandle { tx: cmd_tx, join: Some(join), counters, ready, generation, carrier })
}

// ---- the smoltcp device -------------------------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Chan {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct ChanDevice<'a>(&'a mut Chan);

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}
impl Device for ChanDevice<'_> {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: SInstant) -> Option<(Rx, Tx<'_>)> {
        let f = self.0.rx.pop_front()?;
        Some((Rx(f), Tx(&mut self.0.tx)))
    }
    fn transmit(&mut self, _: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.0.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = 1514;
        c
    }
}

struct Inner {
    iface: Interface,
    chan: Chan,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    dns: SocketHandle,
    ip: Option<Ipv4Cidr>,
    start: Instant,
    next_port: u16,
}

impl Inner {
    fn now(&self) -> SInstant {
        SInstant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    fn poll(&mut self) {
        let now = self.now();
        let mut dev = ChanDevice(&mut self.chan);
        self.iface.poll(now, &mut dev, &mut self.sockets);
        match self.sockets.get_mut::<dhcpv4::Socket<'_>>(self.dhcp).poll() {
            Some(dhcpv4::Event::Configured(cfg)) => {
                self.ip = Some(cfg.address);
                let (addr, router, dns) = (cfg.address, cfg.router, cfg.dns_servers.clone());
                self.iface.update_ip_addrs(|a| {
                    a.clear();
                    a.push(IpCidr::Ipv4(addr)).ok();
                });
                if let Some(r) = router {
                    self.iface.routes_mut().add_default_ipv4_route(r).ok();
                }
                let servers: Vec<IpAddress> = dns.iter().map(|d| IpAddress::Ipv4(*d)).collect();
                self.sockets.get_mut::<dns::Socket<'_>>(self.dns).update_servers(&servers);
            }
            Some(dhcpv4::Event::Deconfigured) => {
                self.ip = None;
                self.iface.update_ip_addrs(|a| a.clear());
            }
            None => {}
        }
    }

    fn new_tcp(&mut self) -> SocketHandle {
        let s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 60_000]), tcp::SocketBuffer::new(vec![0; 60_000]));
        self.sockets.add(s)
    }

    fn port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 60_000 { 40_000 } else { self.next_port + 1 };
        self.next_port
    }
}

async fn host_main(
    to_dongle: tmpsc::UnboundedSender<Vec<u8>>,
    from_dongle: mpsc::Receiver<Vec<u8>>,
    mut cmds: tmpsc::UnboundedReceiver<Cmd>,
    counters: Arc<UsbCounters>,
) {
    let mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x77, 0x02]);
    let mut chan = Chan::default();
    let mut cfg = Config::new(HardwareAddress::Ethernet(mac));
    cfg.random_seed = 0x1234_5678_9abc_def0;
    let iface = {
        let mut dev = ChanDevice(&mut chan);
        Interface::new(cfg, &mut dev, SInstant::from_millis(0))
    };
    let mut sockets = SocketSet::new(vec![]);
    let dhcp = sockets.add(dhcpv4::Socket::new());
    let dns = sockets.add(dns::Socket::new(&[], vec![None, None, None, None]));
    let inner = Rc::new(RefCell::new(Inner { iface, chan, sockets, dhcp, dns, ip: None, start: Instant::now(), next_port: 40_000 }));
    let notify = Rc::new(Notify::new());

    // frames from the dongle arrive on a std channel: bridge it into this runtime with a blocking reader thread
    let (frame_tx, mut frame_rx) = tmpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(f) = from_dongle.recv() {
            if frame_tx.send(f).is_err() {
                break;
            }
        }
    });

    let pump = {
        let (inner, notify, counters) = (inner.clone(), notify.clone(), counters.clone());
        async move {
            loop {
                let delay = {
                    let mut i = inner.borrow_mut();
                    i.poll();
                    for f in i.chan.tx.drain(..) {
                        counters.from_host.fetch_add(1, Ordering::Relaxed);
                        let _ = to_dongle.send(f);
                    }
                    let now = i.now();
                    let i = &mut *i;
                    let d = i.iface.poll_delay(now, &i.sockets);
                    d.map_or(Duration::from_millis(20), |d| Duration::from_micros(d.total_micros()).min(Duration::from_millis(20)))
                };
                tokio::select! {
                    f = frame_rx.recv() => {
                        let Some(f) = f else { return };
                        inner.borrow_mut().chan.rx.push_back(f);
                    }
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(delay.max(Duration::from_micros(200))) => {}
                }
            }
        }
    };
    tokio::task::spawn_local(pump);

    while let Some(c) = cmds.recv().await {
        match c {
            Cmd::Stop => return,
            c => {
                let (inner, notify) = (inner.clone(), notify.clone());
                tokio::task::spawn_local(async move { run_cmd(inner, notify, c).await });
            }
        }
    }
}

async fn wait_until(notify: &Notify, deadline: Instant, mut cond: impl FnMut() -> bool) -> bool {
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        notify.notify_one();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn run_cmd(inner: Rc<RefCell<Inner>>, notify: Rc<Notify>, c: Cmd) {
    match c {
        Cmd::Stop => {}
        Cmd::WaitDhcp(reply, timeout) => {
            let ok = wait_until(&notify, Instant::now() + timeout, || inner.borrow().ip.is_some()).await;
            let r = inner.borrow().ip.filter(|_| ok).map(|c| c.address().octets());
            let _ = reply.send(r.ok_or_else(|| "no DHCP lease".to_string()));
        }
        Cmd::Resolve(name, reply, timeout) => {
            let q = {
                let mut i = inner.borrow_mut();
                let Inner { iface, sockets, dns, .. } = &mut *i;
                let cx = iface.context();
                sockets.get_mut::<dns::Socket<'_>>(*dns).start_query(cx, &name, DnsQueryType::A)
            };
            let Ok(h) = q else {
                let _ = reply.send(Err("could not start the query".into()));
                return;
            };
            let mut out: Option<Result<[u8; 4], String>> = None;
            wait_until(&notify, Instant::now() + timeout, || {
                let mut i = inner.borrow_mut();
                let dns_h = i.dns;
                match i.sockets.get_mut::<dns::Socket<'_>>(dns_h).get_query_result(h) {
                    Ok(addrs) => {
                        out = Some(addrs.iter().map(|IpAddress::Ipv4(v)| v.octets()).next().ok_or_else(|| "no A record".to_string()));
                        true
                    }
                    Err(dns::GetQueryResultError::Pending) => false,
                    Err(e) => {
                        out = Some(Err(format!("{e:?}")));
                        true
                    }
                }
            })
            .await;
            let _ = reply.send(out.unwrap_or_else(|| Err("DNS timeout".into())));
        }
        Cmd::EchoLoop { addr, port, payload, interval, stop, counts, reply } => {
            let (ok, bad) = counts;
            while !stop.load(Ordering::SeqCst) {
                let h = {
                    let mut i = inner.borrow_mut();
                    let h = i.new_tcp();
                    let local = i.port();
                    let Inner { iface, sockets, .. } = &mut *i;
                    let cx = iface.context();
                    let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3])), port);
                    let _ = sockets.get_mut::<tcp::Socket<'_>>(h).connect(cx, remote, local);
                    h
                };
                let up = wait_until(&notify, Instant::now() + Duration::from_secs(15), || {
                    matches!(inner.borrow().sockets.get::<tcp::Socket<'_>>(h).state(), tcp::State::Established)
                })
                .await;
                if !up {
                    bad.fetch_add(1, Ordering::SeqCst);
                } else {
                    while !stop.load(Ordering::SeqCst) {
                        let sent = {
                            let mut i = inner.borrow_mut();
                            i.sockets.get_mut::<tcp::Socket<'_>>(h).send_slice(&payload).map(|n| n == payload.len()).unwrap_or(false)
                        };
                        let mut got = 0usize;
                        let mut buf = vec![0u8; payload.len()];
                        let done = sent
                            && wait_until(&notify, Instant::now() + Duration::from_secs(15), || {
                                let mut i = inner.borrow_mut();
                                let s = i.sockets.get_mut::<tcp::Socket<'_>>(h);
                                if let Ok(n) = s.recv_slice(&mut buf[got..]) {
                                    got += n;
                                }
                                got >= payload.len()
                            })
                            .await;
                        if done && buf == payload {
                            ok.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(interval).await;
                        } else {
                            bad.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                {
                    let mut i = inner.borrow_mut();
                    i.sockets.get_mut::<tcp::Socket<'_>>(h).abort();
                    i.sockets.remove(h);
                }
                notify.notify_one();
                if !stop.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            let _ = reply.send(());
        }
        Cmd::UdpEcho { addr, port, payload, reply, timeout } => {
            let (h, local) = {
                let mut i = inner.borrow_mut();
                let local = i.port();
                let s = udp::Socket::new(
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
                );
                (i.sockets.add(s), local)
            };
            let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3])), port);
            let sent = {
                let mut i = inner.borrow_mut();
                let s = i.sockets.get_mut::<udp::Socket<'_>>(h);
                s.bind(local).and_then(|()| s.send_slice(&payload, remote).map_err(|_| udp::BindError::Unaddressable)).map_err(|e| format!("{e:?}"))
            };
            let mut out: Option<Vec<u8>> = None;
            if sent.is_ok() {
                notify.notify_one();
                wait_until(&notify, Instant::now() + timeout, || {
                    let mut i = inner.borrow_mut();
                    let s = i.sockets.get_mut::<udp::Socket<'_>>(h);
                    let mut b = vec![0u8; 2048];
                    match s.recv_slice(&mut b) {
                        Ok((n, _)) => {
                            b.truncate(n);
                            out = Some(b);
                            true
                        }
                        Err(_) => false,
                    }
                })
                .await;
            }
            inner.borrow_mut().sockets.remove(h);
            let _ = reply.send(match (sent, out) {
                (Err(e), _) => Err(e),
                (Ok(()), Some(b)) => Ok(b),
                (Ok(()), None) => Err("no reply".to_string()),
            });
        }
        Cmd::Echo { addr, port, payload, reply, timeout } => {
            let r = tcp_exchange(&inner, &notify, addr, port, timeout, Exchange::Echo(payload)).await.map(|(b, _)| b);
            let _ = reply.send(r);
        }
        Cmd::Get { addr, port, bytes, reply, timeout } => {
            let r = tcp_exchange(&inner, &notify, addr, port, timeout, Exchange::Get(bytes)).await.map(|(b, d)| (b.len(), d));
            let _ = reply.send(r);
        }
        Cmd::Upload { addr, port, bytes, reply, timeout } => {
            let r = tcp_exchange(&inner, &notify, addr, port, timeout, Exchange::Upload(bytes)).await.and_then(|(b, d)| {
                String::from_utf8_lossy(&b).trim().parse::<usize>().map(|n| (n, d)).map_err(|_| format!("sink said {:?}", String::from_utf8_lossy(&b)))
            });
            let _ = reply.send(r);
        }
    }
}

enum Exchange {
    Echo(Vec<u8>),
    Get(usize),
    Upload(usize),
}

async fn tcp_exchange(
    inner: &Rc<RefCell<Inner>>,
    notify: &Notify,
    addr: [u8; 4],
    port: u16,
    timeout: Duration,
    ex: Exchange,
) -> Result<(Vec<u8>, Duration), String> {
    let deadline = Instant::now() + timeout;
    let t0 = Instant::now();
    let h = {
        let mut i = inner.borrow_mut();
        let h = i.new_tcp();
        let local = i.port();
        let Inner { iface, sockets, .. } = &mut *i;
        let cx = iface.context();
        let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3])), port);
        sockets.get_mut::<tcp::Socket<'_>>(h).connect(cx, remote, local).map_err(|e| format!("connect: {e:?}"))?;
        h
    };
    let result = tcp_run(inner, notify, h, deadline, ex, t0).await;
    let mut i = inner.borrow_mut();
    i.sockets.get_mut::<tcp::Socket<'_>>(h).abort();
    i.sockets.remove(h);
    drop(i);
    notify.notify_one();
    result
}

async fn tcp_run(
    inner: &Rc<RefCell<Inner>>,
    notify: &Notify,
    h: SocketHandle,
    deadline: Instant,
    ex: Exchange,
    t0: Instant,
) -> Result<(Vec<u8>, Duration), String> {
    let est = wait_until(notify, deadline, || {
        let i = inner.borrow();
        matches!(i.sockets.get::<tcp::Socket<'_>>(h).state(), tcp::State::Established | tcp::State::CloseWait)
    })
    .await;
    if !est {
        return Err(format!("TCP connect timed out (state {:?})", inner.borrow().sockets.get::<tcp::Socket<'_>>(h).state()));
    }
    let (to_send, want, request_len): (Vec<u8>, Option<usize>, usize) = match &ex {
        Exchange::Echo(p) => (p.clone(), Some(p.len()), p.len()),
        Exchange::Get(n) => (format!("GET /bytes/{n} HTTP/1.0\r\nHost: peer\r\n\r\n").into_bytes(), None, 0),
        Exchange::Upload(n) => ((0..*n).map(|i| (i % 251) as u8).collect(), None, *n),
    };
    let _ = request_len;
    let mut sent = 0usize;
    let mut got: Vec<u8> = Vec::new();
    let mut body_bytes = 0usize;
    let mut header_done = false;
    let mut closed_write = false;
    let mut tmp = vec![0u8; 16_384];
    let get_n = if let Exchange::Get(n) = ex { Some(n) } else { None };
    loop {
        let progressed = {
            let mut i = inner.borrow_mut();
            let s = i.sockets.get_mut::<tcp::Socket<'_>>(h);
            let mut did = false;
            while sent < to_send.len() && s.can_send() {
                match s.send_slice(&to_send[sent..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        sent += n;
                        did = true;
                    }
                }
            }
            if sent == to_send.len() && !closed_write && matches!(ex, Exchange::Upload(_)) {
                s.close();
                closed_write = true;
                did = true;
            }
            while s.can_recv() {
                match s.recv_slice(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        did = true;
                        if get_n.is_some() {
                            if header_done {
                                body_bytes += n;
                            } else {
                                got.extend_from_slice(&tmp[..n]);
                                if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                                    header_done = true;
                                    body_bytes += got.len() - (p + 4);
                                    got.clear();
                                }
                            }
                        } else {
                            got.extend_from_slice(&tmp[..n]);
                        }
                    }
                }
            }
            did
        };
        let (done, dead) = {
            let i = inner.borrow();
            let s = i.sockets.get::<tcp::Socket<'_>>(h);
            let finished = match (&want, get_n) {
                (Some(w), _) => got.len() >= *w,
                (None, Some(n)) => body_bytes >= n,
                (None, None) => !s.may_recv() && sent == to_send.len(),
            };
            (finished, matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) && !s.can_recv())
        };
        if done {
            return Ok((if get_n.is_some() { vec![0u8; body_bytes] } else { got }, t0.elapsed()));
        }
        if dead {
            return Err(format!("connection ended early: sent {sent}/{} got {}", to_send.len(), got.len().max(body_bytes)));
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out: sent {sent}/{} got {}", to_send.len(), got.len().max(body_bytes)));
        }
        if progressed {
            notify.notify_one();
            tokio::task::yield_now().await;
        } else {
            notify.notify_one();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}
