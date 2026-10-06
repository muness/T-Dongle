//! The mux under the real embassy-net stack: DHCP, TCP and UDP flows of the device's own, concurrently with NAT flows of the USB host, on a scripted radio.

mod common;

use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::rc::Rc;
use std::task::Poll;

use common::*;
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, Ipv4Address, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4};
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_usbnet::napt::{NaptConfig, Proto, Verdict};
use tdongle_tailnet_wifimux::{NaptTap, RawPort, SharedNapt, StackDriver, TxDrop, WifiMux};

const TXQ: usize = 8;
const RXQ: usize = 8;
type Mux = WifiMux<FakeRadio, NaptTap<'static, 64>, TXQ, RXQ>;
type Port = RawPort<'static, TXQ, RXQ>;

struct Sta {
    stack: Stack<'static>,
    port: Port,
    napt: &'static SharedNapt<64>,
    radio: RadioHandle,
}

async fn yield_now() {
    let mut y = false;
    poll_fn(|cx| {
        if y {
            Poll::Ready(())
        } else {
            y = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

fn leak<T>(t: T) -> &'static mut T {
    Box::leak(Box::new(t))
}

/// The station: mux + embassy-net with DHCP; tasks: the stack's runner and the config follower.
fn sta(lan: &mut Lan) -> Sta {
    let radio = lan.sta.clone();
    let napt: &'static SharedNapt<64> = leak(SharedNapt::new(NaptConfig::C, &mut TestRng(7)));
    let mux: &'static mut Mux = leak(WifiMux::new(FakeRadio { h: radio.clone(), mac: STA_MAC }, NaptTap::new(napt)).unwrap());
    let (drv, port) = mux.split();
    let res = leak(StackResources::<6>::new());
    let (stack, runner): (Stack<'static>, Runner<'static, StackDriver<'static, FakeRadio, NaptTap<'static, 64>, TXQ, RXQ>>) =
        embassy_net::new(drv, Config::dhcpv4(Default::default()), res, 0x5eed);
    lan.tasks.push(Box::pin(run(runner)));
    let info = port.info();
    lan.tasks.push(Box::pin(async move {
        loop {
            info.refresh(&stack);
            yield_now().await;
        }
    }));
    Sta { stack, port, napt, radio }
}

async fn run<D: embassy_net_driver::Driver + 'static>(mut r: Runner<'static, D>) {
    r.run().await
}

/// The LAN neighbour: static address, TCP echo on 7, UDP echo on 9.
fn peer(lan: &mut Lan) {
    let radio = RadioHandle::new();
    lan.peer = Some(radio.clone());
    let res = leak(StackResources::<4>::new());
    let cfg = Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 10), 24),
        gateway: Some(Ipv4Address::new(192, 168, 1, 1)),
        dns_servers: Default::default(),
    });
    let (stack, runner) = embassy_net::new(FakeRadio { h: radio, mac: PEER_MAC }, cfg, res, 0xbeef);
    lan.tasks.push(Box::pin(run(runner)));
    lan.tasks.push(Box::pin(async move {
        let (rx, tx) = (leak(vec![0u8; 4096]), leak(vec![0u8; 4096]));
        let mut s = TcpSocket::new(stack, rx, tx);
        loop {
            if s.accept(7).await.is_err() {
                continue;
            }
            let mut buf = [0u8; 512];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut off = 0;
                        while off < n {
                            match s.write(&buf[off..n]).await {
                                Ok(w) => off += w,
                                Err(_) => break,
                            }
                        }
                    }
                }
            }
            s.close();
            s.abort();
            let _ = s.flush().await;
        }
    }));
    lan.tasks.push(Box::pin(async move {
        let (rm, rb, tm, tb) = (leak([PacketMetadata::EMPTY; 4]), leak(vec![0u8; 2048]), leak([PacketMetadata::EMPTY; 4]), leak(vec![0u8; 2048]));
        let mut u = UdpSocket::new(stack, rm, rb, tm, tb);
        u.bind(9).unwrap();
        let mut buf = [0u8; 600];
        loop {
            if let Ok((n, meta)) = u.recv_from(&mut buf).await {
                let _ = u.send_to(&buf[..n], meta).await;
            }
        }
    }));
}

/// Run DHCP to completion and wait until the mux knows the address and the link.
fn bring_up(lan: &mut Lan, s: &Sta) {
    let stack = s.stack;
    assert!(lan.run_until(|_| stack.config_v4().is_some(), 20_000), "DHCP never bound");
    let port = s.port;
    assert!(lan.run_until(|_| port.info().config().is_some(), 100));
    for _ in 0..5 {
        lan.step();
    }
}

fn tcp_echo_task(s: &Sta, total: usize, done: Rc<Cell<usize>>) -> Task {
    let stack = s.stack;
    Box::pin(async move {
        let (rx, tx) = (leak(vec![0u8; 4096]), leak(vec![0u8; 4096]));
        let mut sock = TcpSocket::new(stack, rx, tx);
        sock.connect((Ipv4Address::new(192, 168, 1, 10), 7)).await.expect("connect");
        let data: Vec<u8> = (0..total).map(|i| (i * 7 % 251) as u8).collect();
        let mut sent = 0;
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while got.len() < total {
            if sent < total {
                let end = (sent + 400).min(total);
                match sock.write(&data[sent..end]).await {
                    Ok(n) => sent += n,
                    Err(e) => panic!("write {e:?}"),
                }
            }
            if sock.can_recv() {
                let n = sock.read(&mut buf).await.expect("read");
                got.extend_from_slice(&buf[..n]);
                done.set(got.len());
            } else {
                yield_now().await;
            }
        }
        assert_eq!(got, data, "echo corrupted");
        sock.close();
    })
}

fn host_udp(napt: &SharedNapt<64>, sport: u16, dst: u32, dport: u16, data: &[u8]) -> (Vec<u8>, Verdict) {
    let mut p = udp_packet(HOST_IP, dst, sport, dport, data);
    let v = napt.outbound(0, &mut p);
    (p, v)
}

#[test]
fn dhcp_then_stack_tcp_and_udp_and_nat_concurrently() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    peer(&mut lan);
    bring_up(&mut lan, &s);
    let cfg = s.stack.config_v4().unwrap();
    assert_eq!(cfg.address.address(), Ipv4Address::new(192, 168, 1, 50));
    assert_eq!(s.port.info().config().unwrap().gateway, Some(GW_IP));

    // the device's own TCP flow...
    let done = Rc::new(Cell::new(0));
    lan.tasks.push(tcp_echo_task(&s, 20_000, done.clone()));
    // ...and its own UDP flow
    let udp_ok = Rc::new(Cell::new(false));
    {
        let stack = s.stack;
        let ok = udp_ok.clone();
        lan.tasks.push(Box::pin(async move {
            let (rm, rb, tm, tb) = (leak([PacketMetadata::EMPTY; 4]), leak(vec![0u8; 2048]), leak([PacketMetadata::EMPTY; 4]), leak(vec![0u8; 2048]));
            let mut u = UdpSocket::new(stack, rm, rb, tm, tb);
            u.bind(40_000).unwrap();
            u.send_to(b"ping-stack", (Ipv4Address::new(192, 168, 1, 10), 9)).await.unwrap();
            let mut buf = [0u8; 64];
            let (n, _) = u.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping-stack");
            ok.set(true);
        }));
    }
    // the USB host's NAT flows, interleaved: 40 datagrams, replies by the "Internet"
    let napt = s.napt;
    let port = s.port;
    let replies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
    {
        let replies = replies.clone();
        lan.tasks.push(Box::pin(async move {
            let mut buf = [0u8; 1500];
            loop {
                let n = port.next_to_host(&mut buf).await;
                replies.borrow_mut().push(buf[..n].to_vec());
            }
        }));
        lan.tasks.push(Box::pin(async move {
            for i in 0..40u16 {
                let (p, v) = host_udp(napt, 5000 + i, ip(8, 8, 8, 8), 53, format!("q{i}").as_bytes());
                let Verdict::Forward { len, .. } = v else { panic!("{v:?}") };
                port.send(&p[..usize::from(len)]).await.unwrap();
                for _ in 0..5 {
                    yield_now().await;
                }
            }
        }));
    }
    let r2 = replies.clone();
    let (d2, u2) = (done.clone(), udp_ok.clone());
    assert!(
        lan.run_until(move |_| d2.get() == 20_000 && u2.get() && r2.borrow().len() == 40, 40_000),
        "tcp {} udp {} nat {}",
        done.get(),
        udp_ok.get(),
        replies.borrow().len()
    );

    // every reply is translated back for the host: dst = the host and its original port, src = the remote
    let mut ports: Vec<u16> = replies
        .borrow()
        .iter()
        .map(|r| {
            assert_eq!(ip_dst(r), HOST_IP);
            assert_eq!(ip_src(r), ip(8, 8, 8, 8));
            udp_ports(r).1
        })
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, (5000..5040).collect::<Vec<_>>());
    // the gateway saw NAT frames from the station MAC with the station's address, framed to its own MAC
    let st = s.port.stats();
    assert_eq!(st.tx_napt.get(), 40);
    assert_eq!(st.rx_to_host.get(), 40);
    assert!(st.tx_stack.get() > 20, "the stack's own traffic flowed: {st:?}");
    assert_eq!(st.tx_dropped.iter().map(|c| c.get()).sum::<u32>(), 0);
    for u in &lan.gw.internet_udp {
        assert_eq!(ip_src(u), STA_IP);
    }
    assert_eq!(lan.gw.internet_udp.len(), 40);
    assert_eq!(s.port.gateway_mac(), Some(GW_MAC));
    // nothing of the stack's own flows went to the host
    assert_eq!(st.rx_dropped.iter().map(|c| c.get()).sum::<u32>(), 0);
}

#[test]
fn gateway_mac_is_learned_by_snooping_without_asking() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    bring_up(&mut lan, &s);
    // forget what DHCP's ARP exchange taught: a bounce clears the table
    s.port.info().new_association();
    for _ in 0..5 {
        lan.step();
    }
    assert_eq!(s.port.gateway_mac(), None);
    let before = s.port.stats().tx_arp.get();
    // the gateway sends the station an IPv4 packet (an ICMP from .1 would do; UDP is as good)
    s.radio.push_rx(udp_frame(STA_MAC, GW_MAC, GW_IP, STA_IP, 123, 40_001, b"ntp"));
    for _ in 0..10 {
        lan.step();
    }
    assert_eq!(s.port.gateway_mac(), Some(GW_MAC));
    assert!(s.port.stats().snooped.get() >= 1);
    // a NAT packet now leaves at once, without an ARP request of ours
    let seen = lan.gw.arp_requests_seen;
    let (p, v) = host_udp(s.napt, 6000, ip(1, 1, 1, 1), 53, b"x");
    let Verdict::Forward { len, .. } = v else { panic!("{v:?}") };
    s.port.try_send(&p[..usize::from(len)]).unwrap();
    assert!(lan.run_until(|l| l.gw.internet_udp.len() == 1, 200));
    assert_eq!(s.port.stats().tx_arp.get(), before);
    assert_eq!(lan.gw.arp_requests_seen, seen);
}

#[test]
fn gateway_mac_is_learned_by_our_own_arp_request() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    bring_up(&mut lan, &s);
    s.port.info().new_association();
    for _ in 0..5 {
        lan.step();
    }
    assert_eq!(s.port.gateway_mac(), None);
    let seen = lan.gw.arp_requests_seen;
    let (p, v) = host_udp(s.napt, 6001, ip(1, 1, 1, 1), 53, b"y");
    let Verdict::Forward { len, .. } = v else { panic!("{v:?}") };
    s.port.try_send(&p[..usize::from(len)]).unwrap();
    assert!(lan.run_until(|l| l.gw.internet_udp.len() == 1, 2_000));
    assert!(lan.gw.arp_requests_seen > seen, "the mux asked");
    assert_eq!(s.port.gateway_mac(), Some(GW_MAC));
    // the reply it got from the gateway came back through the NAT to the host
    let mut buf = [0u8; 1500];
    assert!(lan.run_until(|_| s.port.queued().1 > 0, 200));
    let n = s.port.try_next_to_host(&mut buf).unwrap();
    assert_eq!((ip_dst(&buf[..n]), udp_ports(&buf[..n]).1), (HOST_IP, 6001));
}

#[test]
fn unanswered_arp_gives_up_and_counts() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    bring_up(&mut lan, &s);
    s.port.info().new_association();
    for _ in 0..5 {
        lan.step();
    }
    lan.gw.answer_arp = false;
    let (p, v) = host_udp(s.napt, 6002, ip(1, 1, 1, 1), 53, b"z");
    let Verdict::Forward { len, .. } = v else { panic!("{v:?}") };
    s.port.try_send(&p[..usize::from(len)]).unwrap();
    // five requests one second apart: ~5 s of real time (the mux uses the embassy-time clock)
    let start = std::time::Instant::now();
    assert!(lan.run_until(|_| s.port.stats().tx_dropped(TxDrop::ArpFailed) == 1, 100_000), "{:?}", s.port.stats());
    assert!(start.elapsed().as_millis() >= 4_000);
    assert!(lan.gw.arp_requests_seen >= 4 && lan.gw.internet_udp.is_empty());
    assert_eq!(s.port.queued().0, 0);
}

#[test]
fn reserved_ports_keep_nat_off_the_stacks_sockets() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    peer(&mut lan);
    bring_up(&mut lan, &s);
    // the stack's UDP socket on 50000 (inside the NAT's mapped range); the runtime reserves it
    assert!(s.napt.reserve_local_port(Proto::Udp, 50_000));
    let got = Rc::new(RefCell::new(Vec::<u8>::new()));
    {
        let stack = s.stack;
        let got = got.clone();
        lan.tasks.push(Box::pin(async move {
            let (rm, rb, tm, tb) = (leak([PacketMetadata::EMPTY; 4]), leak(vec![0u8; 2048]), leak([PacketMetadata::EMPTY; 4]), leak(vec![0u8; 2048]));
            let mut u = UdpSocket::new(stack, rm, rb, tm, tb);
            u.bind(50_000).unwrap();
            let mut buf = [0u8; 64];
            let (n, _) = u.recv_from(&mut buf).await.unwrap();
            got.borrow_mut().extend_from_slice(&buf[..n]);
        }));
    }
    // the host uses source port 50000 towards the same remote the stack talks to: the NAT must remap it
    let (p, v) = host_udp(s.napt, 50_000, ip(9, 9, 9, 9), 5353, b"host");
    let Verdict::Forward { len, mapped, .. } = v else { panic!("{v:?}") };
    assert_ne!(mapped, 50_000, "a reserved port was handed out as a mapped port");
    s.port.try_send(&p[..usize::from(len)]).unwrap();
    // the remote (9.9.9.9:5353) now sends to the station's port 50000: it is the stack's, not a flow
    for _ in 0..50 {
        lan.step();
    }
    s.radio.push_rx(udp_frame(STA_MAC, GW_MAC, ip(9, 9, 9, 9), STA_IP, 5353, 50_000, b"for-stack"));
    let g = got.clone();
    assert!(lan.run_until(move |_| !g.borrow().is_empty(), 2_000));
    assert_eq!(&*got.borrow(), b"for-stack");
    // and the mapped one is the host's
    s.radio.push_rx(udp_frame(STA_MAC, GW_MAC, ip(9, 9, 9, 9), STA_IP, 5353, mapped, b"for-host"));
    assert!(lan.run_until(|_| s.port.queued().1 > 0, 500));
    let mut buf = [0u8; 1500];
    let n = s.port.try_next_to_host(&mut buf).unwrap();
    // (the gateway also echoed the host's own datagram first, so drain until ours)
    let mut last = n;
    while let Some(m) = s.port.try_next_to_host(&mut buf) {
        last = m;
    }
    let _ = last;
    assert!(s.napt.with(|n| n.flows().all(|(_, _, _, _, _, m)| m != 50_000)));
}

#[test]
fn without_reservation_the_nat_steals_the_matching_reply() {
    // the negative control of the previous test: the failure the reservation exists to prevent
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    bring_up(&mut lan, &s);
    lan.gw.echo_internet = false;
    let (p, v) = host_udp(s.napt, 50_001, ip(9, 9, 9, 9), 5353, b"host");
    let Verdict::Forward { len, mapped, .. } = v else { panic!("{v:?}") };
    assert_eq!(mapped, 50_001, "the host's port is kept when free");
    s.port.try_send(&p[..usize::from(len)]).unwrap();
    for _ in 0..50 {
        lan.step();
    }
    s.radio.push_rx(udp_frame(STA_MAC, GW_MAC, ip(9, 9, 9, 9), STA_IP, 5353, 50_001, b"x"));
    assert!(lan.run_until(|_| s.port.queued().1 > 0, 500), "the NAT took a packet a stack socket on 50001 would have wanted");
}

#[test]
fn nat_flood_does_not_starve_the_stack_and_vice_versa() {
    flood(false);
}

/// The same on a radio that behaves like esp-radio's `Interface`: `receive` yields only while a TX credit is free.
#[test]
fn nat_flood_on_a_radio_whose_rx_is_coupled_to_tx_credit() {
    flood(true);
}

fn flood(coupled: bool) {
    let mut lan = Lan::new(RadioHandle::new());
    lan.sta.set_coupled(coupled);
    let s = sta(&mut lan);
    peer(&mut lan);
    lan.gw.echo_internet = false;
    bring_up(&mut lan, &s);
    // the radio can take one frame per step: tight enough that both sides contend for every token
    s.radio.set_credit(Some(0));
    let done = Rc::new(Cell::new(0));
    lan.tasks.push(tcp_echo_task(&s, 30_000, done.clone()));
    // a NAT producer that never stops: refills the queue every step
    let port = s.port;
    let napt = s.napt;
    let sent = Rc::new(Cell::new(0usize));
    {
        let sent = sent.clone();
        lan.tasks.push(Box::pin(async move {
            let mut i = 0u16;
            loop {
                let (p, v) = host_udp(napt, 10_000 + (i % 400), ip(8, 8, 4, 4), 53, &[0u8; 900]);
                if let Verdict::Forward { len, .. } = v
                    && port.try_send(&p[..usize::from(len)]).is_ok()
                {
                    sent.set(sent.get() + 1);
                }
                i = i.wrapping_add(1);
                yield_now().await;
            }
        }));
    }
    let radio = s.radio.clone();
    let d = done.clone();
    let mut steps = 0;
    let mut tx_seen_napt = 0;
    let finished = lan.run_until(
        |l| {
            steps += 1;
            radio.set_credit(Some(1));
            tx_seen_napt = l.gw.internet_udp.len();
            d.get() == 30_000
        },
        400_000,
    );
    assert!(finished, "the stack starved: echoed {} of 30000 after {steps} steps, {:?}", done.get(), s.port.stats());
    let st = s.port.stats();
    // with one radio credit per step and both queues never empty, the two sides share the tokens: neither is a rounding error of the other
    assert!(st.tx_napt.get() * 4 >= st.tx_stack.get(), "the NAT starved: {st:?}");
    assert!(st.tx_stack.get() * 4 >= st.tx_napt.get(), "the stack starved: {st:?}");
    assert!(st.tx_dropped(TxDrop::QueueFull) > 0, "the flood did exceed the queue: bounded, counted");
}

#[test]
fn hostile_frames_never_panic_and_are_counted() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    peer(&mut lan);
    bring_up(&mut lan, &s);
    let before = s.port.stats();
    let other: Mac = [2, 9, 9, 9, 9, 9];
    let mut frames: Vec<Vec<u8>> = vec![
        vec![],                                                // runt
        vec![0xff; 13],                                        // runt
        eth(STA_MAC, [1, 2, 3, 4, 5, 6], 0x0800, &[0x45; 40]), // group source
        udp_frame(other, GW_MAC, GW_IP, STA_IP, 1, 2, b"x"),   // for another station
        vec![0xAB; 1600],                                      // oversize
    ];
    // bad IP lengths
    let mut p = udp_packet(GW_IP, STA_IP, 1, 2, b"hello");
    p[2..4].copy_from_slice(&1000u16.to_be_bytes()); // total length beyond the frame
    frames.push(eth(STA_MAC, GW_MAC, 0x0800, &p));
    let mut p = udp_packet(GW_IP, STA_IP, 1, 2, b"hello");
    p[0] = 0x4f; // ihl 60 > total
    frames.push(eth(STA_MAC, GW_MAC, 0x0800, &p));
    let mut p = udp_packet(GW_IP, STA_IP, 1, 2, b"hello");
    p[0] = 0x65; // version 6
    frames.push(eth(STA_MAC, GW_MAC, 0x0800, &p));
    frames.push(eth(STA_MAC, GW_MAC, 0x0800, &[0x45, 0, 0, 5])); // truncated header
    // fragments (first, middle, last) to our address and to a NAT-looking address
    for off in [0x2000u16, 0x20b9, 0x00b9] {
        let mut p = udp_packet(ip(8, 8, 8, 8), STA_IP, 53, 40_000, &[7u8; 100]);
        p[6..8].copy_from_slice(&off.to_be_bytes());
        fill(&mut p);
        frames.push(eth(STA_MAC, GW_MAC, 0x0800, &p));
    }
    // other ethertypes, truncated ARP
    frames.push(eth(STA_MAC, GW_MAC, 0x86dd, &[0x60; 60]));
    frames.push(eth(STA_MAC, GW_MAC, 0x888e, &[1; 30]));
    frames.push(eth(BCAST, GW_MAC, 0x0806, &[0, 1, 8, 0, 6, 4, 0, 1]));
    for f in frames {
        s.radio.push_rx(f);
    }
    for _ in 0..200 {
        lan.step();
    }
    let st = s.port.stats();
    use tdongle_tailnet_wifimux::RxDrop::*;
    assert_eq!(st.rx_dropped(Runt) - before.rx_dropped(Runt), 2);
    assert_eq!(st.rx_dropped(BadSource) - before.rx_dropped(BadSource), 1);
    assert_eq!(st.rx_dropped(NotForUs) - before.rx_dropped(NotForUs), 1);
    assert_eq!(st.rx_dropped(Oversize) - before.rx_dropped(Oversize), 1);
    assert_eq!(st.rx_dropped(BadIpv4) - before.rx_dropped(BadIpv4), 4);
    assert_eq!(st.rx_fragments.get() - before.rx_fragments.get(), 3);
    // the stack is unharmed
    let done = Rc::new(Cell::new(0));
    lan.tasks.push(tcp_echo_task(&s, 1_000, done.clone()));
    let d = done.clone();
    assert!(lan.run_until(move |_| d.get() == 1_000, 20_000));
}

fn fill(p: &mut [u8]) {
    p[10] = 0;
    p[11] = 0;
    tdongle_tailnet_usbnet::csum::fill_header(p, 20);
}

#[test]
fn link_bounce_clears_neighbours_queue_and_flows() {
    let mut lan = Lan::new(RadioHandle::new());
    let s = sta(&mut lan);
    bring_up(&mut lan, &s);
    lan.gw.echo_internet = false;
    // a NAT flow exists and the gateway is known
    let (p, v) = host_udp(s.napt, 7000, ip(1, 1, 1, 1), 53, b"a");
    let Verdict::Forward { len, .. } = v else { panic!("{v:?}") };
    s.port.try_send(&p[..usize::from(len)]).unwrap();
    assert!(lan.run_until(|l| l.gw.internet_udp.len() == 1, 500));
    assert_eq!(s.napt.with(|n| n.active()), 1);
    assert!(s.port.gateway_mac().is_some());
    // queue packets that cannot leave (no credit), then drop the link
    s.radio.set_credit(Some(0));
    for i in 0..3 {
        let (p, v) = host_udp(s.napt, 7001 + i, ip(1, 1, 1, 1), 53, b"b");
        let Verdict::Forward { len, .. } = v else { panic!("{v:?}") };
        s.port.try_send(&p[..usize::from(len)]).unwrap();
    }
    for _ in 0..10 {
        lan.step();
    }
    assert!(s.port.queued().0 > 0);
    s.radio.set_link(false);
    for _ in 0..20 {
        lan.step();
    }
    let st = s.port.stats();
    assert_eq!(st.link_downs.get(), 1);
    assert_eq!(st.tx_dropped(TxDrop::Flushed), 3);
    assert_eq!(s.port.queued().0, 0);
    assert_eq!(s.port.gateway_mac(), None);
    assert_eq!(s.napt.with(|n| n.active()), 0, "the tap forgot the flows");
    // while down, the runtime's packets are refused, counted
    let (p, v) = host_udp(s.napt, 7100, ip(1, 1, 1, 1), 53, b"c");
    if let Verdict::Forward { len, .. } = v {
        assert_eq!(s.port.try_send(&p[..usize::from(len)]), Err(TxDrop::LinkDown));
    }
}

#[test]
fn wakes_the_runner_on_every_event_it_must_see() {
    // a bare mux driven with a counting waker, no embassy-net: the wake contract of Driver
    use embassy_net_driver::Driver;
    let radio = RadioHandle::new();
    let napt: &'static SharedNapt<64> = leak(SharedNapt::new(NaptConfig::C, &mut TestRng(1)));
    let mux: &'static mut Mux = leak(WifiMux::new(FakeRadio { h: radio.clone(), mac: STA_MAC }, NaptTap::new(napt)).unwrap());
    let (mut drv, port) = mux.split();
    let (cw, waker) = CountingWaker::new();
    let mut cx = std::task::Context::from_waker(&waker);
    let _ = drv.link_state(&mut cx);
    assert!(drv.receive(&mut cx).is_none());
    // 1. a frame arriving wakes it
    let n0 = cw.count();
    radio.push_rx(eth(BCAST, GW_MAC, 0x0806, &arp(1, GW_MAC, GW_IP, [0; 6], ip(10, 9, 9, 9))));
    assert!(cw.count() > n0, "rx wake");
    // 2. configuration from the runtime wakes it
    let _ = drv.link_state(&mut cx);
    let n1 = cw.count();
    port.info().set_config(Some(tdongle_tailnet_wifimux::Ipv4Cfg { addr: STA_IP, gateway: Some(GW_IP), prefix: 24 }));
    assert!(cw.count() > n1, "config wake");
    // 3. a packet to send wakes it
    let _ = drv.link_state(&mut cx);
    let n2 = cw.count();
    let p = udp_packet(STA_IP, ip(8, 8, 8, 8), 1, 2, b"x");
    port.try_send(&p).unwrap();
    assert!(cw.count() > n2, "tx wake");
    // 4. a new association wakes it
    let _ = drv.link_state(&mut cx);
    let n3 = cw.count();
    port.info().new_association();
    assert!(cw.count() > n3, "association wake");
    // 5. credit returning wakes it (the radio's own waker, registered with our cx)
    radio.set_credit(Some(0));
    assert!(drv.transmit(&mut cx).is_none());
    let n4 = cw.count();
    radio.set_credit(Some(2));
    assert!(cw.count() > n4, "credit wake");
}
