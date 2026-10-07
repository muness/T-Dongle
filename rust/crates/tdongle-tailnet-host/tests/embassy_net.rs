//! `EmbassyNet` (the device's `Net`) on the host: two embassy-net stacks joined by an in-memory Ethernet link, the runtime's handle API on one side and a
//! plain embassy-net echo server on the other. Checks the handle life cycle the runtime relies on (take once, connect, close, connect again on the same
//! socket, UDP bind / send / receive, link facts, the buffer accounting).

use core::task::Context;
use embassy_net::{Config, IpEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4};
use embassy_net_driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};
use embedded_io_async::{Read, Write};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;
use tdongle_tailnet_admission::heap::ML_HB_FLOOR;
use tdongle_tailnet_admission::probe::{FixedProbe, HeapSnapshot};
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_pool::{Mem, Pool};
use tdongle_tailnet_runtime::net::{Net, TcpConn, TcpRole, UdpConn, UdpRole};
use tdongle_tailnet_runtime::net_embassy::{EmbassyNet, LinkGen, Windows};
use tdongle_tailnet_sockmem::HeapSockMem;

#[derive(Default)]
struct Wire {
    a_to_b: VecDeque<Vec<u8>>,
    b_to_a: VecDeque<Vec<u8>>,
    wakers: [Option<core::task::Waker>; 2],
}

struct End {
    wire: Rc<RefCell<Wire>>,
    me: usize,
    mac: [u8; 6],
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a Rc<RefCell<Wire>>, usize);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        let mut b = self.0;
        f(&mut b)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        let mut w = self.0.borrow_mut();
        if self.1 == 0 {
            w.a_to_b.push_back(b);
        } else {
            w.b_to_a.push_back(b);
        }
        if let Some(wk) = w.wakers[1 - self.1].take() {
            wk.wake();
        }
        r
    }
}

impl Driver for End {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a>
    where
        Self: 'a;
    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(Rx, Tx<'_>)> {
        let mut w = self.wire.borrow_mut();
        let q = if self.me == 0 { &mut w.b_to_a } else { &mut w.a_to_b };
        match q.pop_front() {
            Some(f) => {
                drop(w);
                Some((Rx(f), Tx(&self.wire, self.me)))
            }
            None => {
                w.wakers[self.me] = Some(cx.waker().clone());
                None
            }
        }
    }
    fn transmit(&mut self, _: &mut Context<'_>) -> Option<Tx<'_>> {
        Some(Tx(&self.wire, self.me))
    }
    fn link_state(&mut self, _: &mut Context<'_>) -> LinkState {
        LinkState::Up
    }
    fn capabilities(&self) -> Capabilities {
        let mut c = Capabilities::default();
        c.max_transmission_unit = 1514;
        c
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(self.mac)
    }
}

struct Gen;
impl LinkGen for Gen {
    fn generation(&self) -> u32 {
        7
    }
}

fn stack(end: End, ip: [u8; 4], seed: u64) -> (Stack<'static>, embassy_net::Runner<'static, End>) {
    let res: &'static mut StackResources<8> = Box::leak(Box::new(StackResources::new()));
    let cfg = Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3]), 24),
        gateway: None,
        dns_servers: Default::default(),
    });
    embassy_net::new(end, cfg, res, seed)
}

#[test]
fn the_handle_life_cycle_over_a_real_embassy_stack() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let wire = Rc::new(RefCell::new(Wire::default()));
        let (sa, mut ra) = stack(End { wire: wire.clone(), me: 0, mac: [2, 0, 0, 0, 0, 1] }, [10, 0, 0, 1], 1);
        let (sb, mut rb) = stack(End { wire: wire.clone(), me: 1, mac: [2, 0, 0, 0, 0, 2] }, [10, 0, 0, 2], 2);
        tokio::task::spawn_local(async move { ra.run().await });
        tokio::task::spawn_local(async move { rb.run().await });

        sa.wait_link_up().await;
        sb.wait_link_up().await;
        sa.wait_config_up().await;
        sb.wait_config_up().await;
        // the server: a TCP echo on :7000 (any number of connections, one after the other) and a UDP echo on :6000
        let sbc = sb;
        tokio::task::spawn_local(async move {
            let (mut rx, mut tx) = ([0u8; 2048], [0u8; 2048]);
            loop {
                let mut s = embassy_net::tcp::TcpSocket::new(sbc, &mut rx, &mut tx);
                if let Err(e) = s.accept(7000).await {
                    eprintln!("accept: {e:?}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }

                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                s.abort();
                tokio::time::sleep(Duration::from_millis(10)).await; // the reset goes out with the stack's next poll; the socket is dropped (and removed) after it
            }
        });
        tokio::task::spawn_local(async move {
            let (mut rm, mut tm) = ([embassy_net::udp::PacketMetadata::EMPTY; 4], [embassy_net::udp::PacketMetadata::EMPTY; 4]);
            let (mut rb_, mut tb_) = ([0u8; 2048], [0u8; 2048]);
            let mut u = embassy_net::udp::UdpSocket::new(sbc, &mut rm, &mut rb_, &mut tm, &mut tb_);
            u.bind(6000).unwrap();
            let mut buf = [0u8; 256];
            loop {
                let (n, meta) = u.recv_from(&mut buf).await.unwrap();
                u.send_to(&buf[..n], meta.endpoint).await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await; // let the server tasks reach their first accept / recv
        let pool: &'static Pool = Box::leak(Box::new(Pool::new(1 << 20)));
        let free = ML_HB_FLOOR + (1 << 20);
        let probe: &'static FixedProbe = Box::leak(Box::new(FixedProbe(HeapSnapshot { free, largest: free, minimum: free })));
        let sockmem: &'static HeapSockMem = Box::leak(Box::new(HeapSockMem::new(Mem { pool, heap: probe })));
        let net = EmbassyNet::new(sa, &Gen, sockmem);
        // nothing is held until a socket is made
        assert_eq!(pool.in_use(), 0);
        assert_eq!(net.link_generation(), 7);
        assert!(net.link_up());
        let v4 = net.ipv4().expect("static configuration");
        assert_eq!((v4.addr, v4.prefix, v4.gateway, v4.dns), ([10, 0, 0, 1], 24, None, None));
        assert_eq!(net.member_buffer_bytes(), Windows::PER_MEMBER);
        assert_eq!(net.resolve("10.0.0.2").await, Ok([10, 0, 0, 2]), "a literal needs no resolver");

        // a handle is a few words; a slot the runtime does not have gets none
        let mut tcp = net.tcp(TcpRole::Control, 0).expect("control handle of slot 0");
        assert!(
            net.tcp(TcpRole::Control, tdongle_tailnet_runtime::shared::MAX_RUN).is_none()
                && net.udp(UdpRole::Member, tdongle_tailnet_runtime::shared::MAX_RUN).is_none()
        );
        assert!(net.tcp(TcpRole::Derp, 0).is_some() && net.udp(UdpRole::DnsUpstream, 0).is_some());
        assert_eq!(pool.in_use(), 0, "handles hold no memory");

        // connect, echo, close, connect again on the same socket, echo again
        for round in 0..3 {
            // the one-socket test server needs a moment between connections (it has no backlog): retry a refused connect
            let mut tries = 0;
            loop {
                match tokio::time::timeout(Duration::from_secs(5), tcp.connect("10.0.0.2", 7000)).await.expect("connect timed out") {
                    Ok(()) => break,
                    Err(e) if tries < 20 => {
                        eprintln!("round {round}: connect {e:?}, retrying");
                        tries += 1;
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    Err(e) => panic!("connect: {e:?}"),
                }
            }
            let msg = format!("round {round}");
            tcp.write_all(msg.as_bytes()).await.unwrap();
            tcp.flush().await.unwrap();
            let mut got = vec![0u8; msg.len()];
            tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut got)).await.expect("read timed out").unwrap();
            assert_eq!(got, msg.as_bytes());
            // connected: exactly the control windows are held
            let w = Windows::GATEWAY;
            assert_eq!(pool.in_use(), w.ctl_rx + w.ctl_tx, "round {round}");
            tcp.close();
        }
        // closed but not released: the socket still holds its windows until the handle is released (the reset needs the stack's turn first)
        assert_ne!(pool.in_use(), 0);
        tcp.release().await;
        assert_eq!((pool.in_use(), sockmem.out()), (0, 0), "release gives every byte back");
        // a connect to a port nobody listens on fails (reset), and the handle is still usable
        assert!(tokio::time::timeout(Duration::from_secs(5), tcp.connect("10.0.0.2", 7999)).await.expect("refused connect timed out").is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(pool.in_use(), 0, "a connection that failed holds nothing");
        tokio::time::timeout(Duration::from_secs(5), tcp.connect("10.0.0.2", 7000)).await.unwrap().expect("reconnect after a refused connect");
        tcp.release().await;
        assert_eq!(pool.in_use(), 0);

        // UDP: bind a chosen port, send, receive the reflection with the sender's endpoint
        let mut udp = net.udp(UdpRole::Member, 0).expect("udp handle");
        assert_eq!(udp.bind(5000), Ok(5000));
        let w = Windows::GATEWAY;
        assert_eq!(pool.in_use(), w.udp_rx + w.udp_tx + 2 * 8 * core::mem::size_of::<embassy_net::udp::PacketMetadata>());
        udp.send_to(b"disco?", Ep::v4([10, 0, 0, 2], 6000)).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await.expect("udp reply timed out").unwrap();
        assert_eq!((&buf[..n], from), (&b"disco?"[..], Ep::v4([10, 0, 0, 2], 6000)));
        // rebinding closes the old binding and takes another port (0: the stack's pick)
        let p = udp.bind(0).unwrap();
        assert_ne!(p, 0);
        udp.close();
        assert_eq!((pool.in_use(), sockmem.out(), sockmem.given_unknown()), (0, 0, 0), "closing the socket gives its rings and metadata back");
        let _ = IpEndpoint::new(embassy_net::IpAddress::v4(10, 0, 0, 2), 1);
    });
}

#[test]
fn a_pool_that_says_no_is_a_counted_refusal_not_a_panic() {
    // the heap floor is the elastic floor: with only 5,000 bytes of room above it, neither the DERP windows (5,760 + 2,048) nor the UDP rings (6,400 + 3,200) fit
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let wire = Rc::new(RefCell::new(Wire::default()));
        let (sa, mut ra) = stack(End { wire: wire.clone(), me: 0, mac: [2, 0, 0, 0, 0, 1] }, [10, 0, 0, 1], 1);
        tokio::task::spawn_local(async move { ra.run().await });
        sa.wait_config_up().await;
        let pool: &'static Pool = Box::leak(Box::new(Pool::new(1 << 20)));
        let free = ML_HB_FLOOR + 5_000;
        let probe: &'static FixedProbe = Box::leak(Box::new(FixedProbe(HeapSnapshot { free, largest: free, minimum: free })));
        let sockmem: &'static HeapSockMem = Box::leak(Box::new(HeapSockMem::new(Mem { pool, heap: probe })));
        let net = EmbassyNet::new(sa, &Gen, sockmem);
        let mut tcp = net.tcp(TcpRole::Derp, 0).unwrap();
        assert_eq!(tcp.connect("10.0.0.2", 7000).await, Err(tdongle_tailnet_runtime::net::NetError::NoMem));
        let mut udp = net.udp(UdpRole::Member, 0).unwrap();
        assert_eq!(udp.bind(5000), Err(tdongle_tailnet_runtime::net::NetError::NoMem));
        // nothing leaked by the refusals (a pair is taken whole or not at all), and a socket that does not exist answers with an error, not a panic
        assert_eq!((pool.in_use(), sockmem.out()), (0, 0));
        assert!(pool.stats().denied_floor >= 2, "{:?}", pool.stats());
        assert!(udp.try_send_to(b"x", Ep::v4([10, 0, 0, 2], 6000)).is_err());
        assert!(udp.wait_readable().await.is_err());
        let mut b = [0u8; 4];
        assert!(embedded_io_async::Read::read(&mut tcp, &mut b).await.is_err());
    });
}
