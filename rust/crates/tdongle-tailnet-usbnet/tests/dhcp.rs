//! The DHCP server against the behaviour of ESP-IDF's `dhcpserver.c` (read in 5.5.5) and RFC 2131.
mod common;
use common::*;
use proptest::prelude::*;
use tdongle_tailnet_usbnet::dhcp::*;
use tdongle_tailnet_usbnet::wire::{BROADCAST_MAC, ip4};

const SERVER_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const SERVER: u32 = 0xC0A8_4D01;

fn mac(n: u8) -> [u8; 6] {
    [0x02, 0xaa, 0xbb, 0xcc, 0xdd, n]
}

#[derive(Clone)]
struct Req {
    mac: [u8; 6],
    kind: u8,
    ciaddr: u32,
    requested: u32,
    server_id: u32,
    broadcast_flag: bool,
    xid: u32,
    giaddr: u32,
}

fn req(m: u8, kind: u8) -> Req {
    Req { mac: mac(m), kind, ciaddr: 0, requested: 0, server_id: 0, broadcast_flag: true, xid: 0xdead_0000 + u32::from(m), giaddr: 0 }
}

fn bootp(r: &Req) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = 1;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&r.xid.to_be_bytes());
    if r.broadcast_flag {
        b[10] = 0x80;
    }
    b[12..16].copy_from_slice(&r.ciaddr.to_be_bytes());
    b[24..28].copy_from_slice(&r.giaddr.to_be_bytes());
    b[28..34].copy_from_slice(&r.mac);
    b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    b.extend_from_slice(&[53, 1, r.kind]);
    if r.requested != 0 {
        b.extend_from_slice(&[50, 4]);
        b.extend_from_slice(&r.requested.to_be_bytes());
    }
    if r.server_id != 0 {
        b.extend_from_slice(&[54, 4]);
        b.extend_from_slice(&r.server_id.to_be_bytes());
    }
    b.extend_from_slice(&[55, 3, 1, 3, 6, 255]);
    b
}

fn frame_of(r: &Req, payload: &[u8]) -> Vec<u8> {
    let (sip, dip, dmac) = if r.ciaddr != 0 { (r.ciaddr, SERVER, SERVER_MAC) } else { (0, u32::MAX, BROADCAST_MAC) };
    let l4 = udp_dgram(68, 67, payload);
    let ip = Ip::new(sip, dip).wrap(17, &l4);
    let mut f = Vec::new();
    f.extend_from_slice(&dmac);
    f.extend_from_slice(&r.mac);
    f.extend_from_slice(&[8, 0]);
    f.extend_from_slice(&ip);
    // fix the UDP checksum
    let c = l4_expected(&f[14..]).unwrap();
    f[14 + 20 + 6..14 + 20 + 8].copy_from_slice(&c.to_be_bytes());
    f
}

fn frame(r: &Req) -> Vec<u8> {
    frame_of(r, &bootp(r))
}

fn server() -> DhcpServer<8> {
    DhcpServer::new(DhcpConfig::c(SERVER_MAC))
}

struct Reply {
    kind: ReplyKind,
    eth_dst: [u8; 6],
    ip_dst: u32,
    yiaddr: u32,
    ciaddr: u32,
    xid: u32,
    flags: u16,
    options: Vec<(u8, Vec<u8>)>,
}

impl Reply {
    fn opt(&self, code: u8) -> Option<&[u8]> {
        self.options.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_slice())
    }
    fn codes(&self) -> Vec<u8> {
        self.options.iter().map(|(c, _)| *c).collect()
    }
}

fn parse_reply(out: &[u8], len: usize, kind: ReplyKind) -> Reply {
    let f = &out[..len];
    assert_eq!(&f[6..12], &SERVER_MAC);
    assert_eq!(&f[12..14], &[8, 0]);
    assert_valid(&f[14..]); // IP header and UDP checksum, by the independent oracle
    assert_eq!(src(&f[14..]), SERVER);
    assert_eq!((sport(&f[14..]), dport(&f[14..])), (67, 68));
    assert_eq!(f[14 + 8], 64, "ttl");
    let b = &f[14 + 28..];
    assert!(b.len() >= 300, "BOOTP minimum");
    assert_eq!((b[0], b[1], b[2], b[3]), (2, 1, 6, 0));
    assert_eq!(&b[236..240], &[0x63, 0x82, 0x53, 0x63]);
    let mut options = vec![];
    let mut i = 240;
    loop {
        match b[i] {
            255 => break,
            0 => i += 1,
            c => {
                let l = usize::from(b[i + 1]);
                options.push((c, b[i + 2..i + 2 + l].to_vec()));
                i += 2 + l;
            }
        }
    }
    assert!(b[i + 1..].iter().all(|&x| x == 0), "padding is zero");
    Reply {
        kind,
        eth_dst: [f[0], f[1], f[2], f[3], f[4], f[5]],
        ip_dst: dst(&f[14..]),
        yiaddr: u32::from_be_bytes([b[16], b[17], b[18], b[19]]),
        ciaddr: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        xid: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        flags: u16::from_be_bytes([b[10], b[11]]),
        options,
    }
}

fn talk(s: &mut DhcpServer<8>, now: u64, r: &Req) -> Result<Reply, Silent> {
    let mut out = [0u8; REPLY_BUF];
    match s.handle_frame(now, &frame(r), &mut out) {
        DhcpOutcome::Reply { len, kind } => Ok(parse_reply(&out, len, kind)),
        DhcpOutcome::Silent(why) => Err(why),
    }
}

fn msg_type(r: &Reply) -> u8 {
    r.opt(53).unwrap()[0]
}

#[test]
fn the_pool_is_what_dhcps_poll_set_derives() {
    // 192.168.77.1/24: the larger side above the server, cut to DHCPS_MAX_LEASE = 100 addresses
    assert_eq!(lwip_pool(ip4(192, 168, 77, 1), ip4(255, 255, 255, 0)), (ip4(192, 168, 77, 2), ip4(192, 168, 77, 101)));
    // a server near the top uses the lower side
    assert_eq!(lwip_pool(ip4(192, 168, 77, 200), ip4(255, 255, 255, 0)), (ip4(192, 168, 77, 1), ip4(192, 168, 77, 100)));
    // a small subnet is not cut
    assert_eq!(lwip_pool(ip4(10, 0, 0, 1), ip4(255, 255, 255, 240)), (ip4(10, 0, 0, 2), ip4(10, 0, 0, 14)));
    let c = DhcpConfig::c(SERVER_MAC);
    assert_eq!((c.lease_secs, c.mtu, c.dns, c.router), (7200, 1500, SERVER, Some(SERVER)));
    assert_eq!(C_HOLD_MS, 432_000_000, "7200 lease units counted per minute: the C's retention");
    assert_eq!(C_TABLE, 8);
}

#[test]
fn discover_gets_an_offer_with_the_cs_options_in_the_cs_order() {
    let mut s = server();
    let r = talk(&mut s, 0, &req(1, 1)).unwrap();
    assert_eq!(r.kind, ReplyKind::Offer);
    assert_eq!(msg_type(&r), 2);
    assert_eq!(r.yiaddr, ip4(192, 168, 77, 2));
    assert_eq!(r.xid, 0xdead_0001);
    assert_eq!(r.ciaddr, 0);
    // option order and bytes of add_offer_options
    assert_eq!(r.codes(), vec![53, 1, 51, 54, 3, 6, 28, 26, 31, 43]);
    assert_eq!(r.opt(1).unwrap(), &[255, 255, 255, 0]);
    assert_eq!(r.opt(51).unwrap(), &7200u32.to_be_bytes());
    assert_eq!(r.opt(54).unwrap(), &[192, 168, 77, 1]);
    assert_eq!(r.opt(3).unwrap(), &[192, 168, 77, 1]);
    assert_eq!(r.opt(6).unwrap(), &[192, 168, 77, 1]);
    assert_eq!(r.opt(28).unwrap(), &[192, 168, 77, 255]);
    assert_eq!(r.opt(26).unwrap(), &[0x05, 0xdc]);
    assert_eq!(r.opt(31).unwrap(), &[0]);
    assert_eq!(r.opt(43).unwrap(), &[1, 4, 0, 0, 0, 2]);
    assert!(r.opt(15).is_none(), "the C offers no domain name");
    // broadcast flag set: broadcast reply
    assert_eq!((r.eth_dst, r.ip_dst), (BROADCAST_MAC, u32::MAX));
    assert_eq!(r.flags & 0x8000, 0x8000, "the client's flags are echoed");
    assert_eq!(s.lease_of(&mac(1)), Some(ip4(192, 168, 77, 2)));
}

#[test]
fn offer_is_unicast_to_chaddr_and_yiaddr_when_the_client_did_not_ask_for_broadcast() {
    let mut s = server();
    let mut q = req(1, 1);
    q.broadcast_flag = false;
    let r = talk(&mut s, 0, &q).unwrap();
    assert_eq!((r.eth_dst, r.ip_dst), (mac(1), ip4(192, 168, 77, 2)));
}

#[test]
fn full_exchange_discover_request_ack_and_renewal() {
    let mut s = server();
    let offer = talk(&mut s, 0, &req(1, 1)).unwrap();
    let mut q = req(1, 3);
    q.requested = offer.yiaddr;
    q.server_id = SERVER;
    let ack = talk(&mut s, 10, &q).unwrap();
    assert_eq!(ack.kind, ReplyKind::Ack);
    assert_eq!(msg_type(&ack), 5);
    assert_eq!(ack.yiaddr, offer.yiaddr);
    assert_eq!(ack.opt(51).unwrap(), &7200u32.to_be_bytes());
    // renewal: ciaddr set, no requested-ip option, unicast to ciaddr
    let mut q = req(1, 3);
    q.ciaddr = offer.yiaddr;
    q.broadcast_flag = false;
    let ack2 = talk(&mut s, 3_600_000, &q).unwrap();
    assert_eq!(ack2.kind, ReplyKind::Ack);
    assert_eq!((ack2.eth_dst, ack2.ip_dst), (mac(1), offer.yiaddr));
    assert_eq!(s.lease_count(), 1);
}

#[test]
fn request_for_another_address_is_nakked_and_drops_the_lease() {
    let mut s = server();
    let _ = talk(&mut s, 0, &req(1, 1)).unwrap();
    let mut q = req(1, 3);
    q.requested = ip4(192, 168, 77, 50);
    let nak = talk(&mut s, 1, &q).unwrap();
    assert_eq!(nak.kind, ReplyKind::Nak);
    assert_eq!(msg_type(&nak), 6);
    assert_eq!(nak.yiaddr, 0);
    assert_eq!((nak.eth_dst, nak.ip_dst), (BROADCAST_MAC, u32::MAX), "a NAK is always broadcast");
    assert_eq!(nak.codes(), vec![53, 54]);
    assert_eq!(s.lease_count(), 0, "the C removes the client's entry on a NAK");
    // a request naming neither option is a NAK too
    let nak = talk(&mut s, 2, &req(2, 3)).unwrap();
    assert_eq!(nak.kind, ReplyKind::Nak);
}

#[test]
fn init_reboot_after_the_server_forgot_is_acked_when_the_address_is_free_and_in_the_pool() {
    let mut s = server();
    let mut q = req(7, 3);
    q.requested = ip4(192, 168, 77, 40);
    let ack = talk(&mut s, 0, &q).unwrap();
    assert_eq!(ack.kind, ReplyKind::Ack);
    assert_eq!(s.lease_of(&mac(7)), Some(ip4(192, 168, 77, 40)));
    // the same address for another client, an address outside the pool, and one outside the subnet: NAK
    let mut q2 = req(8, 3);
    q2.requested = ip4(192, 168, 77, 40);
    assert_eq!(talk(&mut s, 1, &q2).unwrap().kind, ReplyKind::Nak);
    for bad in [ip4(192, 168, 77, 150), ip4(192, 168, 77, 1), ip4(10, 0, 0, 5), ip4(192, 168, 77, 0)] {
        let mut q3 = req(9, 3);
        q3.requested = bad;
        assert_eq!(talk(&mut s, 2, &q3).unwrap().kind, ReplyKind::Nak, "{bad:08x}");
    }
}

#[test]
fn a_request_for_another_server_is_ignored() {
    let mut s = server();
    let mut q = req(1, 3);
    q.requested = ip4(192, 168, 77, 2);
    q.server_id = ip4(192, 168, 77, 99);
    assert_eq!(talk(&mut s, 0, &q).err(), Some(Silent::OtherServer));
    assert_eq!(s.lease_count(), 0);
}

#[test]
fn addresses_are_handed_out_in_order_and_a_returning_client_keeps_its_own() {
    let mut s = server();
    for i in 0..5u8 {
        let r = talk(&mut s, u64::from(i), &req(i + 1, 1)).unwrap();
        assert_eq!(r.yiaddr, ip4(192, 168, 77, 2 + i));
    }
    let again = talk(&mut s, 100, &req(3, 1)).unwrap();
    assert_eq!(again.yiaddr, ip4(192, 168, 77, 4));
    // release gives nothing back on the wire, and the next new client continues after the last one handed out
    let mut rel = req(2, 7);
    rel.ciaddr = ip4(192, 168, 77, 3);
    assert_eq!(talk(&mut s, 101, &rel).err(), Some(Silent::Released));
    assert_eq!(s.lease_of(&mac(2)), None);
    let r = talk(&mut s, 102, &req(9, 1)).unwrap();
    assert_eq!(r.yiaddr, ip4(192, 168, 77, 7));
    // the released client comes back and is given the lowest... the next in sequence, then keeps it
    let back = talk(&mut s, 103, &req(2, 1)).unwrap();
    assert_eq!(back.yiaddr, ip4(192, 168, 77, 8));
    assert_eq!(talk(&mut s, 104, &req(2, 1)).unwrap().yiaddr, ip4(192, 168, 77, 8));
}

#[test]
fn table_of_eight_evicts_the_least_recently_heard_client() {
    let mut s = server();
    for i in 0..8u8 {
        let _ = talk(&mut s, u64::from(i) * 10, &req(i + 1, 1)).unwrap();
    }
    assert_eq!(s.lease_count(), 8);
    // client 1 speaks again, so client 2 is the oldest
    let _ = talk(&mut s, 1_000, &req(1, 1)).unwrap();
    let r = talk(&mut s, 1_001, &req(20, 1)).unwrap();
    assert_eq!(r.yiaddr, ip4(192, 168, 77, 10));
    assert_eq!(s.lease_count(), 8);
    assert_eq!(s.lease_of(&mac(2)), None);
    assert!(s.lease_of(&mac(1)).is_some());
    assert_eq!(s.stats().leases_evicted.get(), 1);
}

#[test]
fn the_pool_can_run_out() {
    let mut cfg = DhcpConfig::c(SERVER_MAC);
    cfg.pool_end = cfg.pool_start + 1; // two addresses
    let mut s = DhcpServer::<8>::new(cfg);
    assert!(talk(&mut s, 0, &req(1, 1)).is_ok());
    assert!(talk(&mut s, 0, &req(2, 1)).is_ok());
    assert_eq!(talk(&mut s, 0, &req(3, 1)).err(), Some(Silent::PoolExhausted));
}

#[test]
fn leases_are_forgotten_after_the_cs_retention() {
    let mut s = server();
    let _ = talk(&mut s, 0, &req(1, 1)).unwrap();
    // silence for just under 7200 minutes, then any message: the lease is still there
    assert_eq!(talk(&mut s, C_HOLD_MS, &req(2, 1)).unwrap().yiaddr, ip4(192, 168, 77, 3));
    assert_eq!(s.lease_of(&mac(1)), Some(ip4(192, 168, 77, 2)));
    let _ = talk(&mut s, C_HOLD_MS + 1, &req(3, 1)).unwrap();
    assert_eq!(s.lease_of(&mac(1)), None);
    assert!(s.stats().leases_expired.get() >= 1);
}

#[test]
fn decline_drops_the_lease_and_the_address_is_skipped_once() {
    let mut s = server();
    let r = talk(&mut s, 0, &req(1, 1)).unwrap();
    let mut d = req(1, 4);
    d.requested = r.yiaddr;
    assert_eq!(talk(&mut s, 1, &d).err(), Some(Silent::Declined));
    assert_eq!(s.lease_count(), 0);
    // the next client does not get the declined address (the rotating pointer is past it anyway; wrap around the pool to check the skip)
    let mut cfg = DhcpConfig::c(SERVER_MAC);
    cfg.pool_end = cfg.pool_start + 1;
    let mut s = DhcpServer::<8>::new(cfg);
    let a = talk(&mut s, 0, &req(1, 1)).unwrap();
    let mut d = req(1, 4);
    d.requested = a.yiaddr;
    let _ = talk(&mut s, 1, &d);
    let b = talk(&mut s, 2, &req(2, 1)).unwrap();
    assert_ne!(b.yiaddr, a.yiaddr);
}

#[test]
fn inform_gets_configuration_but_no_lease() {
    let mut s = server();
    let mut q = req(5, 8);
    q.ciaddr = ip4(192, 168, 77, 60);
    q.broadcast_flag = false;
    let r = talk(&mut s, 0, &q).unwrap();
    assert_eq!(r.kind, ReplyKind::InformAck);
    assert_eq!(msg_type(&r), 5);
    assert_eq!(r.yiaddr, 0);
    assert_eq!(r.ciaddr, q.ciaddr);
    assert!(r.opt(51).is_none());
    assert_eq!(r.codes(), vec![53, 1, 54, 3, 6, 28, 26, 31, 43]);
    assert_eq!(r.ip_dst, q.ciaddr);
    assert_eq!(r.eth_dst, mac(5), "the frame's source address");
    assert_eq!(s.lease_count(), 0);
    // ciaddr 0, and an address outside the subnet: ignored
    assert_eq!(talk(&mut s, 0, &req(5, 8)).err(), Some(Silent::InformInvalid));
    let mut q = req(5, 8);
    q.ciaddr = ip4(10, 1, 1, 1);
    assert_eq!(talk(&mut s, 0, &q).err(), Some(Silent::InformInvalid));
}

#[test]
fn malformed_and_foreign_frames_get_no_answer() {
    let mut s = server();
    let mut out = [0u8; REPLY_BUF];
    let good = frame(&req(1, 1));
    let mut cases: Vec<(Vec<u8>, Silent)> = vec![];
    cases.push((vec![], Silent::BadFrame));
    cases.push((good[..30].to_vec(), Silent::BadFrame));
    cases.push((
        {
            let mut f = good.clone();
            f[12] = 0x08;
            f[13] = 0x06;
            f
        },
        Silent::BadFrame,
    ));
    cases.push((
        {
            let mut f = good.clone();
            f[24] ^= 0xff;
            f
        },
        Silent::BadFrame,
    )); // IP header checksum
    cases.push((
        {
            let mut f = good.clone();
            f[14 + 6] = 0x20;
            f[14 + 7] = 0;
            f
        },
        Silent::BadFrame,
    )); // fragment: checksum no longer fits first
    // fragment with a repaired checksum
    {
        let l4 = udp_dgram(68, 67, &bootp(&req(1, 1)));
        let ip = Ip::new(0, u32::MAX).frag(0x2000).wrap(17, &l4);
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&mac(1));
        f.extend_from_slice(&[8, 0]);
        f.extend_from_slice(&ip);
        cases.push((f, Silent::Fragment));
    }
    cases.push((
        {
            let mut f = good.clone();
            f[14 + 22] = 0;
            f[14 + 23] = 68;
            fix_udp(&mut f);
            f
        },
        Silent::NotDhcp,
    )); // to port 68
    cases.push((tcp_frame(), Silent::NotDhcp));
    cases.push((
        {
            let mut f = good.clone();
            f[14 + 20 + 6] ^= 1;
            f
        },
        Silent::BadUdp,
    ));
    cases.push((frame_of(&req(1, 1), &bootp(&req(1, 1))[..239]), Silent::TooShort));
    cases.push((frame_of(&req(1, 1), &[0u8; 1501]), Silent::TooLong));
    cases.push((
        {
            let mut b = bootp(&req(1, 1));
            b[0] = 2;
            frame_of(&req(1, 1), &b)
        },
        Silent::NotRequest,
    ));
    cases.push((
        {
            let mut b = bootp(&req(1, 1));
            b[1] = 6;
            frame_of(&req(1, 1), &b)
        },
        Silent::BadHardware,
    ));
    cases.push((
        {
            let mut b = bootp(&req(1, 1));
            b[2] = 8;
            frame_of(&req(1, 1), &b)
        },
        Silent::BadHardware,
    ));
    cases.push((
        {
            let mut b = bootp(&req(1, 1));
            b[236] = 0;
            frame_of(&req(1, 1), &b)
        },
        Silent::BadCookie,
    ));
    cases.push((
        {
            let mut r = req(1, 1);
            r.giaddr = ip4(10, 0, 0, 1);
            frame(&r)
        },
        Silent::Relayed,
    ));
    cases.push((
        {
            let mut b = bootp(&req(1, 1));
            b.truncate(240);
            frame_of(&req(1, 1), &b)
        },
        Silent::NoMessageType,
    ));
    // an option whose length runs past the end hides the message type that follows it
    cases.push((
        {
            let mut b = bootp(&req(1, 1));
            b.truncate(240);
            b.extend_from_slice(&[12, 200, 1, 2, 3, 53, 1, 1]);
            frame_of(&req(1, 1), &b)
        },
        Silent::NoMessageType,
    ));
    for k in [2u8, 5, 6, 9, 200] {
        cases.push((frame(&req(1, k)), Silent::UnexpectedType));
    }
    for (f, why) in cases {
        match s.handle_frame(0, &f, &mut out) {
            DhcpOutcome::Silent(got) => assert_eq!(got, why, "{why:?}"),
            DhcpOutcome::Reply { .. } => panic!("answered a frame that must be ignored: expected {why:?}"),
        }
    }
    assert_eq!(s.lease_count(), 0, "ignored frames create no lease (the C allocated one anyway)");
    let mut small = [0u8; REPLY_BUF - 1];
    assert_eq!(s.handle_frame(0, &good, &mut small), DhcpOutcome::Silent(Silent::OutputTooSmall));
    // the frame counters add up
    let st = s.stats();
    assert_eq!(st.frames.get(), st.silent.iter().map(|c| c.get()).sum::<u32>() + st.replies.iter().map(|c| c.get()).sum::<u32>());
}

fn fix_udp(f: &mut [u8]) {
    // only when the frame is still shaped like IPv4/UDP (the fuzzer may have broken it)
    if f.len() < 14 + 28 || f[14] != 0x45 || f[14 + 9] != 17 {
        return;
    }
    let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
    if total < 28 || 14 + total > f.len() {
        return;
    }
    f[14 + 26] = 0;
    f[14 + 27] = 0;
    if let Some(c) = l4_expected(&f[14..]) {
        f[14 + 26..14 + 28].copy_from_slice(&c.to_be_bytes());
    }
}

fn tcp_frame() -> Vec<u8> {
    let p = tcp_pkt(0, 68, u32::MAX, 67, 1, 0, SYN, b"");
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&mac(1));
    f.extend_from_slice(&[8, 0]);
    f.extend_from_slice(&p);
    f
}

#[test]
fn option_scan_tolerates_pads_and_unknown_options_and_takes_the_first_message_type() {
    let mut s = server();
    let mut b = bootp(&req(1, 1));
    b.truncate(240);
    b.extend_from_slice(&[0, 0, 12, 3, b'a', b'b', b'c', 61, 2, 1, 2, 53, 1, 1, 53, 1, 3, 255, 99, 99]);
    let mut out = [0u8; REPLY_BUF];
    let o = s.handle_frame(0, &frame_of(&req(1, 1), &b), &mut out);
    assert!(matches!(o, DhcpOutcome::Reply { kind: ReplyKind::Offer, .. }), "{o:?}");
}

#[test]
fn a_mutation_fuzz_never_panics_and_every_reply_is_a_valid_frame() {
    use tdongle_tailnet_types::Entropy;
    use tdongle_tailnet_types::test_util::TestRng;
    let mut rng = TestRng(0x0dd5_eed5_0000_0001);
    let mut next = move || {
        let mut b = [0u8; 4];
        rng.fill(&mut b);
        u32::from_le_bytes(b)
    };
    let mut s = server();
    let mut out = [0u8; REPLY_BUF];
    let mut replies = 0;
    for round in 0..40_000u32 {
        let mut r = req((next() % 12) as u8, [1u8, 3, 3, 4, 7, 8, 1][(next() % 7) as usize]);
        if next() % 3 == 0 {
            r.requested = ip4(192, 168, 77, (next() % 120) as u8);
        }
        if next() % 3 == 0 {
            r.ciaddr = ip4(192, 168, 77, (next() % 120) as u8);
        }
        if next() % 5 == 0 {
            r.server_id = SERVER;
        }
        r.broadcast_flag = next() % 2 == 0;
        let mut f = frame(&r);
        for _ in 0..(next() % 3) {
            let i = (next() as usize) % f.len();
            f[i] = next() as u8;
        }
        if next() % 2 == 0 && f.len() > 14 + 28 {
            fix_udp(&mut f); // reach the BOOTP parser with a valid UDP checksum
        }
        if let DhcpOutcome::Reply { len, kind } = s.handle_frame(u64::from(round) * 1000, &f, &mut out) {
            replies += 1;
            let _ = parse_reply(&out, len, kind);
        }
        assert!(s.lease_count() <= 8);
    }
    assert!(replies > 1000, "reached the reply paths ({replies})");
    let mut seen = std::collections::HashSet::new();
    let mut macs = std::collections::HashSet::new();
    for (m, ip) in s.leases() {
        assert!(seen.insert(ip) && macs.insert(m), "leases are unique by address and by hardware address");
        assert!((s.config().pool_start..=s.config().pool_end).contains(&ip));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]
    /// Any sequence of client messages from a handful of stations: the table stays unique and in the pool, and an ACK always agrees with the table.
    #[test]
    fn random_conversations_keep_the_lease_table_consistent(steps in proptest::collection::vec((0u8..10, prop::sample::select(vec![1u8, 3, 3, 4, 7, 8]), 0u8..130, any::<bool>()), 1..80)) {
        let mut s = server();
        let mut now = 0u64;
        for (m, kind, last, use_req) in steps {
            now += 1000;
            let mut q = req(m, kind);
            if use_req { q.requested = ip4(192, 168, 77, last); } else { q.ciaddr = ip4(192, 168, 77, last); }
            if let Ok(r) = talk(&mut s, now, &q) {
                prop_assert_eq!(r.xid, q.xid);
                if r.kind == ReplyKind::Ack { prop_assert_eq!(s.lease_of(&q.mac), Some(r.yiaddr)); }
                if r.kind == ReplyKind::Offer { prop_assert_eq!(s.lease_of(&q.mac), Some(r.yiaddr)); }
            }
            let mut ips = std::collections::HashSet::new();
            let mut macs = std::collections::HashSet::new();
            for (mm, ip) in s.leases() {
                prop_assert!(ips.insert(ip), "duplicate address");
                prop_assert!(macs.insert(mm), "duplicate station");
                prop_assert!((ip4(192, 168, 77, 2)..=ip4(192, 168, 77, 101)).contains(&ip));
            }
            prop_assert!(s.lease_count() <= 8);
        }
    }
}
