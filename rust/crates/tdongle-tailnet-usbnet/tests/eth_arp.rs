//! Ethernet filtering, ARP and the composed USB side.
mod common;
use common::*;
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_usbnet::arp::*;
use tdongle_tailnet_usbnet::eth::*;
use tdongle_tailnet_usbnet::napt::Verdict;
use tdongle_tailnet_usbnet::wire::{BROADCAST_MAC, USB_IP, USB_MASK};
use tdongle_tailnet_usbnet::{HostRx, UsbNet};

const US: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const HOST_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x54];

fn eth(dst: [u8; 6], src: [u8; 6], ty: u16, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ty.to_be_bytes());
    f.extend_from_slice(body);
    f
}

fn arp_body(op: u16, sha: [u8; 6], spa: u32, tha: [u8; 6], tpa: u32) -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4];
    a.extend_from_slice(&op.to_be_bytes());
    a.extend_from_slice(&sha);
    a.extend_from_slice(&spa.to_be_bytes());
    a.extend_from_slice(&tha);
    a.extend_from_slice(&tpa.to_be_bytes());
    a
}

fn who_has(sha: [u8; 6], spa: u32, tpa: u32) -> Vec<u8> {
    arp_body(1, sha, spa, [0; 6], tpa)
}

fn table() -> Neighbors<4> {
    Neighbors::new(ArpConfig { mac: US, ip: USB_IP, mask: USB_MASK })
}

#[test]
fn ethernet_dispatch_and_filter() {
    let mut e = EthIngress::new(US);
    let ip = vec![0x45u8; 20];
    // runts: 14 bytes or fewer are dropped (lwIP: p->len <= SIZEOF_ETH_HDR)
    assert_eq!(e.ingress(&[]), Rx::Dropped(EthDrop::Runt));
    assert_eq!(e.ingress(&eth(US, HOST_MAC, 0x0800, &[])), Rx::Dropped(EthDrop::Runt));
    assert!(matches!(e.ingress(&eth(US, HOST_MAC, 0x0800, &[1])), Rx::Ipv4 { cast: Cast::Unicast, .. }));
    assert!(matches!(e.ingress(&eth(BROADCAST_MAC, HOST_MAC, 0x0800, &ip)), Rx::Ipv4 { cast: Cast::Broadcast, .. }));
    assert!(matches!(e.ingress(&eth([1, 0, 0x5e, 0, 0, 0xfb], HOST_MAC, 0x0800, &ip)), Rx::Ipv4 { cast: Cast::Multicast, .. }));
    match e.ingress(&eth(US, HOST_MAC, 0x0800, &ip)) {
        Rx::Ipv4 { src, packet, .. } => {
            assert_eq!(src, HOST_MAC);
            assert_eq!(packet, &ip[..]);
        }
        o => panic!("{o:?}"),
    }
    assert!(matches!(e.ingress(&eth(BROADCAST_MAC, HOST_MAC, 0x0806, &[0; 28])), Rx::Arp { payload } if payload.len() == 28));
    assert_eq!(e.ingress(&eth([2, 9, 9, 9, 9, 9], HOST_MAC, 0x0800, &ip)), Rx::Dropped(EthDrop::NotForUs));
    assert_eq!(e.ingress(&eth(US, [1, 2, 3, 4, 5, 6], 0x0800, &ip)), Rx::Dropped(EthDrop::BadSource));
    assert_eq!(e.ingress(&eth(US, HOST_MAC, 0x86dd, &[0x60; 40])), Rx::Dropped(EthDrop::Ipv6));
    assert_eq!(e.ingress(&eth([0x33, 0x33, 0, 0, 0, 1], HOST_MAC, 0x86dd, &[0x60; 40])), Rx::Dropped(EthDrop::Ipv6));
    assert_eq!(e.ingress(&eth(US, HOST_MAC, 0x8100, &[0; 40])), Rx::Dropped(EthDrop::Vlan));
    assert_eq!(e.ingress(&eth(US, HOST_MAC, 0x88cc, &[0; 40])), Rx::Dropped(EthDrop::OtherType));
    let s = e.stats();
    assert_eq!(s.dropped(EthDrop::Ipv6), 2, "IPv6 is counted, not served");
    let passed = s.arp.get() + s.ipv4.iter().map(|c| c.get()).sum::<u32>();
    assert_eq!(s.frames.get(), passed + s.dropped.iter().map(|c| c.get()).sum::<u32>());
}

#[test]
fn arp_answers_who_has_for_the_dongle_and_learns_the_host() {
    let mut t = table();
    let mut out = [0u8; 64];
    let o = t.handle(10, &who_has(HOST_MAC, ip(2), USB_IP), &mut out);
    assert_eq!(o, ArpOutcome::Replied { len: 42 });
    let want = eth(HOST_MAC, US, 0x0806, &arp_body(2, US, USB_IP, HOST_MAC, ip(2)));
    assert_eq!(&out[..42], &want[..], "unicast reply with the dongle's address, to the requester");
    assert_eq!(t.peek(ip(2)), Some(HOST_MAC), "the requester is learned");
    assert_eq!(t.host(), Some((ip(2), HOST_MAC)));
}

fn ip(n: u8) -> u32 {
    0xC0A8_4D00 | u32::from(n)
}

#[test]
fn arp_never_answers_for_other_addresses_and_does_not_learn_strangers() {
    let mut t = table();
    let mut out = [0u8; 64];
    assert_eq!(t.handle(0, &who_has(HOST_MAC, ip(2), ip(77)), &mut out), ArpOutcome::Ignored(ArpIgnore::NotForUs));
    assert_eq!(t.peek(ip(2)), None, "a request for someone else teaches nothing new (FIND_ONLY)");
    // after it is known, a request for someone else refreshes (and may change) the entry
    let _ = t.handle(1, &who_has(HOST_MAC, ip(2), USB_IP), &mut out);
    let other = [0x02, 9, 9, 9, 9, 9];
    assert_eq!(t.handle(2, &who_has(other, ip(2), ip(77)), &mut out), ArpOutcome::Learned);
    assert_eq!(t.peek(ip(2)), Some(other));
}

#[test]
fn arp_probe_is_answered_and_teaches_nothing() {
    let mut t = table();
    let mut out = [0u8; 64];
    assert_eq!(t.handle(0, &who_has(HOST_MAC, 0, USB_IP), &mut out), ArpOutcome::Replied { len: 42 });
    assert_eq!(&out[0..6], &HOST_MAC);
    assert_eq!(&out[38..42], &[0, 0, 0, 0], "the probe's sender address 0.0.0.0 is the reply's target");
    assert_eq!(t.host(), None);
    assert_eq!(t.stats().learn_refused.get(), 1);
}

#[test]
fn arp_reply_to_us_is_learned_and_a_conflict_is_counted() {
    let mut t = table();
    let mut out = [0u8; 64];
    assert_eq!(t.handle(0, &arp_body(2, HOST_MAC, ip(2), US, USB_IP), &mut out), ArpOutcome::Learned);
    assert_eq!(t.peek(ip(2)), Some(HOST_MAC));
    // somebody claims 192.168.77.1
    assert_eq!(t.handle(1, &who_has(HOST_MAC, USB_IP, USB_IP), &mut out), ArpOutcome::Ignored(ArpIgnore::AddressConflict));
    assert_eq!(t.stats().ignored[ArpIgnore::AddressConflict.index()].get(), 1);
}

#[test]
fn arp_bad_packets() {
    let mut t = table();
    let mut out = [0u8; 64];
    let good = who_has(HOST_MAC, ip(2), USB_IP);
    assert_eq!(t.handle(0, &good[..27], &mut out), ArpOutcome::Ignored(ArpIgnore::Runt));
    for (at, v) in [(1usize, 6u8), (2, 0x86), (4, 8), (5, 6)] {
        let mut p = good.clone();
        p[at] = v;
        assert_eq!(t.handle(0, &p, &mut out), ArpOutcome::Ignored(ArpIgnore::BadHeader), "byte {at}");
    }
    for op in [0u16, 3, 4, 9, 0xffff] {
        let mut p = good.clone();
        p[6..8].copy_from_slice(&op.to_be_bytes());
        assert_eq!(t.handle(0, &p, &mut out), ArpOutcome::Ignored(ArpIgnore::BadOpcode));
    }
    // sender addresses that never enter the table
    for (mac, spa) in [([0x01, 0, 0x5e, 0, 0, 1], ip(2)), ([0; 6], ip(2)), (HOST_MAC, u32::MAX), (HOST_MAC, 0xE000_0001), (HOST_MAC, ip(255))] {
        let o = t.handle(0, &who_has(mac, spa, USB_IP), &mut out);
        assert!(matches!(o, ArpOutcome::Replied { .. }));
        assert_eq!(t.host(), None, "{mac:?} {spa:08x}");
    }
    // a too-small output buffer is not an excuse to panic
    let mut tiny = [0u8; 10];
    let o = t.handle(0, &good, &mut tiny);
    assert_eq!(o, ArpOutcome::Learned);
}

#[test]
fn resolve_requests_retries_and_gives_up_like_lwip() {
    let mut t = table();
    let mut out = [0u8; 64];
    let Resolve::Request { len } = t.resolve(0, ip(2), &mut out) else { panic!() };
    assert_eq!(&out[..len], &eth(BROADCAST_MAC, US, 0x0806, &who_has(US, USB_IP, ip(2)))[..]);
    assert_eq!(t.resolve(500, ip(2), &mut out), Resolve::Pending);
    for k in 1..5u64 {
        assert!(matches!(t.resolve(k * 1000, ip(2), &mut out), Resolve::Request { .. }), "retry {k}");
        assert_eq!(t.resolve(k * 1000 + 1, ip(2), &mut out), Resolve::Pending);
    }
    assert_eq!(t.resolve(5000, ip(2), &mut out), Resolve::Failed, "ARP_MAXPENDING requests, then give up");
    assert_eq!(t.stats().gave_up.get(), 1);
    assert!(matches!(t.resolve(5001, ip(2), &mut out), Resolve::Request { .. }), "the next attempt starts over");
    // an answer resolves
    let _ = t.handle(5100, &arp_body(2, HOST_MAC, ip(2), US, USB_IP), &mut out);
    assert_eq!(t.resolve(5200, ip(2), &mut out), Resolve::Hit(HOST_MAC));
}

#[test]
fn resolve_refreshes_before_expiry_and_expires_at_five_minutes() {
    let mut t = table();
    let mut out = [0u8; 64];
    let _ = t.handle(0, &who_has(HOST_MAC, ip(2), USB_IP), &mut out);
    assert_eq!(t.resolve(284_999, ip(2), &mut out), Resolve::Hit(HOST_MAC));
    assert!(matches!(t.resolve(285_000, ip(2), &mut out), Resolve::HitRefresh { mac: HOST_MAC, len: 42 }));
    assert_eq!(t.resolve(285_500, ip(2), &mut out), Resolve::Hit(HOST_MAC), "one refresh request a second");
    assert!(matches!(t.resolve(286_001, ip(2), &mut out), Resolve::HitRefresh { .. }));
    assert!(matches!(t.resolve(300_001, ip(2), &mut out), Resolve::Request { .. }), "past ARP_MAXAGE the entry is gone");
    assert_eq!(t.stats().expired.get(), 1);
    // an answer to a refresh keeps it alive
    let mut t = table();
    let _ = t.handle(0, &who_has(HOST_MAC, ip(2), USB_IP), &mut out);
    let _ = t.handle(290_000, &who_has(HOST_MAC, ip(2), USB_IP), &mut out);
    assert_eq!(t.resolve(500_000, ip(2), &mut out), Resolve::Hit(HOST_MAC));
}

#[test]
fn resolve_only_resolves_the_usb_subnet() {
    let mut t = table();
    let mut out = [0u8; 64];
    for a in [USB_IP, ip(255), u32::MAX, 0x0A00_0001, 0, 0xE000_0001, 0xC0A8_4C05] {
        assert_eq!(t.resolve(0, a, &mut out), Resolve::OffLink, "{a:08x}");
    }
    assert_eq!(t.resolve(0, ip(2), &mut out[..10]), Resolve::OffLink, "no room for the request");
}

#[test]
fn full_table_prefers_to_drop_pending_then_the_least_recently_used() {
    let mut t = Neighbors::<2>::new(ArpConfig { mac: US, ip: USB_IP, mask: USB_MASK });
    let mut out = [0u8; 64];
    let _ = t.handle(0, &who_has(HOST_MAC, ip(2), USB_IP), &mut out);
    let _ = t.handle(10, &who_has([2, 0, 0, 0, 0, 3], ip(3), USB_IP), &mut out);
    let _ = t.resolve(20, ip(2), &mut out); // touches .2: .3 is now the least recently used
    let _ = t.handle(30, &who_has([2, 0, 0, 0, 0, 4], ip(4), USB_IP), &mut out);
    assert!(t.peek(ip(2)).is_some() && t.peek(ip(4)).is_some());
    assert_eq!(t.peek(ip(3)), None);
    // a pending entry is sacrificed first
    let _ = t.resolve(40, ip(9), &mut out); // takes the LRU slot (.4 or .2 ...)
    let _ = t.handle(50, &who_has([2, 0, 0, 0, 0, 5], ip(5), USB_IP), &mut out);
    assert!(t.peek(ip(5)).is_some());
    assert!(matches!(t.resolve(51, ip(9), &mut out), Resolve::Request { len: 42 } | Resolve::Pending));
}

// ---- the composed USB side ----

fn usb() -> UsbNet<64, 8, 4> {
    let mut u = UsbNet::<64, 8, 4>::new(US, &mut TestRng(99));
    u.napt.set_wifi(Some(tdongle_tailnet_usbnet::napt::WifiAddr { ip: WIFI, mask: 0xffff_ff00 }));
    u
}

fn ipv4_frame(dst_mac: [u8; 6], pkt: &[u8]) -> Vec<u8> {
    eth(dst_mac, HOST_MAC, 0x0800, pkt)
}

#[test]
fn host_frame_dispatch_follows_gateway_host_input() {
    let mut u = usb();
    let mut reply = [0u8; 400];
    // ARP
    let mut f = eth(BROADCAST_MAC, HOST_MAC, 0x0806, &who_has(HOST_MAC, ip(2), USB_IP));
    assert_eq!(u.host_frame(0, &mut f, &mut reply), HostRx::Reply { len: 42 });
    // alias destination (198.18.0.0/15): the router's
    for alias in [0xC612_0001u32, 0xC613_FFFE] {
        let mut f = ipv4_frame(US, &tcp_pkt(HOST, 50000, alias, 443, 1, 0, SYN, b""));
        let before = f.clone();
        assert_eq!(u.host_frame(0, &mut f, &mut reply), HostRx::Router { offset: 14, len: 40 });
        assert_eq!(f, before, "the router sees the packet unmodified");
    }
    // the dongle itself: HTTP, DNS, ping
    for p in [
        tcp_pkt(HOST, 50000, USB_IP, 80, 1, 0, SYN, b""),
        udp_pkt(HOST, 50000, USB_IP, 53, b"q"),
        echo_pkt(HOST, USB_IP, 8, 1, 1),
        udp_pkt(HOST, 5353, 0xC0A8_4DFF, 5353, b"x"),
    ] {
        let mut f = ipv4_frame(US, &p);
        let o = u.host_frame(0, &mut f, &mut reply);
        assert!(matches!(o, HostRx::Local { offset: 14, .. }), "{o:?}");
    }
    // everything else is NATed
    let mut f = ipv4_frame(US, &tcp_pkt(HOST, 50000, REMOTE, 443, 1, 0, SYN, b""));
    let HostRx::Napt { offset, verdict: Verdict::Forward { len, mapped, .. } } = u.host_frame(0, &mut f, &mut reply) else { panic!() };
    assert_eq!((offset, len), (14, 40));
    assert_valid(&f[14..14 + 40]);
    assert_eq!(src(&f[14..]), WIFI);
    // and the reply comes back through wifi_packet
    let mut r = tcp_pkt(REMOTE, 443, WIFI, mapped, 9, 2, SYN | ACK, b"");
    assert!(matches!(u.wifi_packet(1, &mut r), Verdict::Forward { .. }));
    assert_eq!(dst(&r), HOST);
}

#[test]
fn host_frame_dhcp_end_to_end() {
    let mut u = usb();
    let mut reply = [0u8; 400];
    let mut b = vec![0u8; 240];
    b[0] = 1;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&[1, 2, 3, 4]);
    b[10] = 0x80;
    b[28..34].copy_from_slice(&HOST_MAC);
    b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    b.extend_from_slice(&[53, 1, 1, 255]);
    let mut p = packet(&Ip::new(0, u32::MAX), 17, &udp_dgram(68, 67, &b));
    fix_l4(&mut p);
    let mut f = eth(BROADCAST_MAC, HOST_MAC, 0x0800, &p);
    let HostRx::Reply { len } = u.host_frame(0, &mut f, &mut reply) else { panic!() };
    assert!(len >= 342);
    assert_eq!(&reply[6..12], &US);
    assert_eq!(u.dhcp.lease_of(&HOST_MAC), Some(ip(2)));
}

#[test]
fn host_frame_drops_are_named() {
    let mut u = usb();
    let mut reply = [0u8; 400];
    let mut f = eth(US, HOST_MAC, 0x86dd, &[0x60; 40]);
    assert_eq!(u.host_frame(0, &mut f, &mut reply), HostRx::EthDropped(EthDrop::Ipv6));
    let mut f = eth(US, HOST_MAC, 0x0800, &[0x45; 10]);
    assert_eq!(u.host_frame(0, &mut f, &mut reply), HostRx::BadIpv4);
    let mut f = eth(US, HOST_MAC, 0x0800, &[0x55; 30]); // total length 0x5555 > frame
    assert_eq!(u.host_frame(0, &mut f, &mut reply), HostRx::BadIpv4);
    let mut f = eth(US, HOST_MAC, 0x0806, &[0; 5]);
    assert_eq!(u.host_frame(0, &mut f, &mut reply), HostRx::ArpIgnored(ArpIgnore::Runt));
    // a DHCP-port datagram that is not a request
    let mut p = udp_pkt(HOST, 68, USB_IP, 67, &[0u8; 20]);
    fix_l4(&mut p);
    let mut f = ipv4_frame(US, &p);
    assert!(matches!(u.host_frame(0, &mut f, &mut reply), HostRx::DhcpSilent(_)));
}

#[test]
fn tick_runs_the_nat_timers_at_most_every_two_seconds() {
    let mut u = usb();
    let mut reply = [0u8; 400];
    let mut f = ipv4_frame(US, &udp_pkt(HOST, 50000, REMOTE, 53, b"q"));
    let _ = u.host_frame(10_000, &mut f, &mut reply);
    assert_eq!(u.tick(10_500), 0, "too soon after the first run? the first call runs, nothing is old enough");
    assert_eq!(u.tick(11_000), 0, "less than 2 s since the last run: skipped");
    assert_eq!(u.tick(13_000), 1);
    assert_eq!(u.napt.active(), 0);
}

#[test]
fn composed_state_size_for_the_adr() {
    std::println!("UsbNet<512,8,4> STATE_BYTES = {}", UsbNet::<512, 8, 4>::STATE_BYTES);
    std::println!("UsbNet<128,8,4> STATE_BYTES = {}", UsbNet::<128, 8, 4>::STATE_BYTES);
    std::println!("Neighbors<4> = {}", Neighbors::<4>::STATE_BYTES);
    std::println!("DhcpServer<8> = {}", tdongle_tailnet_usbnet::dhcp::DhcpServer::<8>::STATE_BYTES);
    const { assert!(UsbNet::<512, 8, 4>::STATE_BYTES < 22_000) };
}

#[test]
fn frame_fuzz_through_the_composed_path() {
    use tdongle_tailnet_types::Entropy;
    let mut rng = TestRng(0xabad_1dea_0000_0007);
    let mut next = move || {
        let mut b = [0u8; 4];
        rng.fill(&mut b);
        u32::from_le_bytes(b)
    };
    let mut u = usb();
    let mut reply = [0u8; 400];
    let seeds: Vec<Vec<u8>> = vec![
        ipv4_frame(US, &tcp_pkt(HOST, 50000, REMOTE, 443, 1, 0, SYN, b"x")),
        ipv4_frame(US, &udp_pkt(HOST, 50001, REMOTE, 53, b"q")),
        ipv4_frame(US, &echo_pkt(HOST, REMOTE, 8, 3, 1)),
        ipv4_frame(US, &udp_pkt(HOST, 68, USB_IP, 67, &[1; 300])),
        ipv4_frame(US, &tcp_pkt(HOST, 50002, 0xC612_0005, 80, 1, 0, SYN, b"")),
        eth(BROADCAST_MAC, HOST_MAC, 0x0806, &who_has(HOST_MAC, ip(2), USB_IP)),
        eth(US, HOST_MAC, 0x86dd, &[0x60; 60]),
    ];
    let mut now = 0u64;
    for _ in 0..60_000 {
        let mut f = seeds[(next() as usize) % seeds.len()].clone();
        for _ in 0..(next() % 5) {
            let i = (next() as usize) % f.len();
            match next() % 3 {
                0 => f[i] = next() as u8,
                1 => f[i] ^= 1 << (next() % 8),
                _ => f.truncate(i),
            }
            if f.is_empty() {
                break;
            }
        }
        now += u64::from(next() % 1500);
        let _ = u.host_frame(now, &mut f, &mut reply);
        let _ = u.tick(now);
    }
    u.napt.check_invariants().unwrap();
}
