//! NAPT behaviour: ported from what `ip4_napt.c` does (read in ESP-IDF 5.5.5) and adversarial cases.
mod common;
use common::*;
use tdongle_tailnet_usbnet::napt::*;
use tdongle_tailnet_usbnet::reply::{IcmpKind, RST_LEN, build_icmp_error};

fn fwd(v: Verdict) -> (u16, u16, bool) {
    match v {
        Verdict::Forward { len, mapped, new_flow } => (len, mapped, new_flow),
        other => panic!("expected Forward, got {other:?}"),
    }
}

fn syn_out<const N: usize>(n: &mut Napt<N>, t: u64, sport: u16) -> (Vec<u8>, u16) {
    let mut p = tcp_pkt(HOST, sport, REMOTE, 443, 1000, 0, SYN, &[]);
    let (_, m, _) = fwd(n.outbound(t, &mut p));
    (p, m)
}

/// Full TCP handshake of host port `sport`; returns the mapped port.
fn establish<const N: usize>(n: &mut Napt<N>, t: u64, sport: u16) -> u16 {
    let (_, m) = syn_out(n, t, sport);
    let mut sa = tcp_pkt(REMOTE, 443, WIFI, m, 5000, 1001, SYN | ACK, &[]);
    let _ = fwd(n.inbound(t, &mut sa));
    let mut a = tcp_pkt(HOST, sport, REMOTE, 443, 1001, 5001, ACK, &[]);
    let _ = fwd(n.outbound(t, &mut a));
    m
}

#[test]
fn tcp_round_trip_rewrites_and_checksums() {
    let mut n = new_napt::<512>();
    let mut syn = tcp_pkt(HOST, 49200, REMOTE, 443, 1000, 0, SYN, &[]);
    let orig = syn.clone();
    let (len, mapped, new) = fwd(n.outbound(10, &mut syn));
    assert_eq!(usize::from(len), orig.len());
    assert!(new);
    assert_eq!(mapped, 49200, "a source port inside the range and free is kept (ip_napt_new_port)");
    assert_eq!(src(&syn), WIFI);
    assert_eq!(dst(&syn), REMOTE);
    assert_eq!(sport(&syn), 49200);
    assert_eq!(syn[8], 63, "TTL decremented");
    assert_valid(&syn);

    let mut sa = tcp_pkt(REMOTE, 443, WIFI, mapped, 5000, 1001, SYN | ACK, b"");
    let (_, m2, new2) = fwd(n.inbound(11, &mut sa));
    assert_eq!(m2, mapped);
    assert!(!new2);
    assert_eq!(dst(&sa), HOST);
    assert_eq!(dport(&sa), 49200);
    assert_eq!(src(&sa), REMOTE);
    assert_eq!(sa[8], 63);
    assert_valid(&sa);

    // data both ways keeps every checksum right
    for i in 0..20u32 {
        let payload: Vec<u8> = (0..(i * 37 % 200) as u8).collect();
        let mut d = tcp_pkt(HOST, 49200, REMOTE, 443, 1001 + i, 5001, ACK, &payload);
        let _ = fwd(n.outbound(12, &mut d));
        assert_valid(&d);
        assert_eq!(&d[40..], &payload[..], "payload untouched");
        let mut r = tcp_pkt(REMOTE, 443, WIFI, mapped, 5001 + i, 1001, ACK, &payload);
        let _ = fwd(n.inbound(13, &mut r));
        assert_valid(&r);
    }
    n.check_invariants().unwrap();
}

#[test]
fn source_port_outside_range_gets_a_random_mapped_port_in_range() {
    let mut n = new_napt::<512>();
    let mut seen = std::collections::HashSet::new();
    for sp in 40000..40050u16 {
        let (_, m) = syn_out(&mut n, 0, sp);
        assert!((49152..=61439).contains(&m), "mapped {m}");
        assert!(seen.insert(m), "mapped ports are unique per protocol");
    }
    n.check_invariants().unwrap();
}

#[test]
fn udp_round_trip_and_zero_checksum_stays_zero() {
    let mut n = new_napt::<512>();
    let mut q = udp_pkt(HOST, 5353 + 50000 - 5353, REMOTE2, 53, b"query");
    let (_, m, new) = fwd(n.outbound(0, &mut q));
    assert!(new);
    assert_valid(&q);
    assert_eq!(src(&q), WIFI);
    let mut a = udp_pkt(REMOTE2, 53, WIFI, m, b"answer!");
    let _ = fwd(n.inbound(1, &mut a));
    assert_eq!((dst(&a), dport(&a)), (HOST, 50000));
    assert_valid(&a);

    // a datagram without a checksum (0) is translated and stays without
    let mut z = udp_pkt(HOST, 50001, REMOTE2, 53, b"nocsum");
    z[26..28].copy_from_slice(&[0, 0]);
    let _ = fwd(n.outbound(2, &mut z));
    assert_eq!(&z[26..28], &[0, 0]);
    assert_eq!(src(&z), WIFI);
    let ihl_ok = tdongle_tailnet_usbnet::csum::header_ok(&z, 20);
    assert!(ihl_ok);
}

#[test]
fn icmp_echo_keeps_the_identifier_and_the_reply_finds_the_host() {
    let mut n = new_napt::<512>();
    let mut req = echo_pkt(HOST, REMOTE, 8, 0x1234, 1);
    let (_, m, new) = fwd(n.outbound(0, &mut req));
    assert!(new);
    assert_eq!(m, 0x1234, "lwIP keeps the identifier");
    assert_eq!(src(&req), WIFI);
    assert_valid(&req);
    let mut rep = echo_pkt(REMOTE, WIFI, 0, 0x1234, 1);
    let _ = fwd(n.inbound(1, &mut rep));
    assert_eq!(dst(&rep), HOST);
    assert_valid(&rep);
    // the next echo of the same ping reuses the flow
    let mut req2 = echo_pkt(HOST, REMOTE, 8, 0x1234, 2);
    let (_, _, new2) = fwd(n.outbound(500, &mut req2));
    assert!(!new2);
    assert_eq!(n.active_of(Proto::Icmp), 1);
}

#[test]
fn icmp_identifier_clash_is_remapped_and_replies_find_the_right_host() {
    let mut n = new_napt::<512>();
    let mut a = echo_pkt(HOST, REMOTE, 8, 77, 1);
    let (_, ma, _) = fwd(n.outbound(0, &mut a));
    let mut b = echo_pkt(HOST2, REMOTE, 8, 77, 1);
    let (_, mb, _) = fwd(n.outbound(0, &mut b));
    assert_eq!(ma, 77);
    assert_ne!(mb, 77, "the second host's identifier is remapped");
    assert_valid(&b);
    assert_eq!(u16::from_be_bytes([b[24], b[25]]), mb);
    let mut ra = echo_pkt(REMOTE, WIFI, 0, ma, 1);
    let _ = fwd(n.inbound(1, &mut ra));
    assert_eq!(dst(&ra), HOST);
    assert_eq!(u16::from_be_bytes([ra[24], ra[25]]), 77);
    assert_valid(&ra);
    let mut rb = echo_pkt(REMOTE, WIFI, 0, mb, 1);
    let _ = fwd(n.inbound(1, &mut rb));
    assert_eq!(dst(&rb), HOST2);
    assert_eq!(u16::from_be_bytes([rb[24], rb[25]]), 77, "restored for the host");
    assert_valid(&rb);
}

#[test]
fn ttl_handling() {
    let mut n = new_napt::<512>();
    for ttl in [0u8, 1] {
        let mut p = packet(&Ip::new(HOST, REMOTE).ttl(ttl), 6, &tcp_seg(49000, 80, 1, 0, SYN, &[]));
        let before = p.clone();
        match n.outbound(0, &mut p) {
            Verdict::Reject(r) => {
                assert_eq!(r.reason, RejectReason::TtlExpired);
                assert_eq!(r.icmp, IcmpKind::TimeExceeded);
            }
            v => panic!("{v:?}"),
        }
        assert_eq!(p, before, "a rejected packet is untouched");
        let mut e = packet(&Ip::new(HOST, REMOTE).ttl(ttl), 1, &icmp_msg(8, 0, 1, 1, b"x"));
        assert_eq!(n.outbound(0, &mut e), Verdict::Drop(DropReason::TtlExpiredIcmp), "no ICMP error about an ICMP packet");
    }
    let mut p = packet(&Ip::new(HOST, REMOTE).ttl(2), 6, &tcp_seg(49000, 80, 1, 0, SYN, &[]));
    let _ = fwd(n.outbound(0, &mut p));
    assert_eq!(p[8], 1);
    assert_valid(&p);
    assert_eq!(n.active(), 1, "refused packets create no flow");
}

#[test]
fn icmp_error_for_a_reject_is_well_formed() {
    let mut n = new_napt::<512>();
    let mut p = tcp_pkt(HOST, 49000, REMOTE, 80, 77, 0, ACK, b"hello");
    let v = n.outbound(0, &mut p);
    let Verdict::Reject(r) = v else { panic!("{v:?}") };
    assert_eq!((r.reason, r.icmp), (RejectReason::NoSession, IcmpKind::PortUnreachable));
    let mut out = [0u8; 96];
    let len = build_icmp_error(r.icmp, &p, 0xC0A8_4D01, &mut out).unwrap();
    let e = &out[..len];
    assert_eq!(src(e), 0xC0A8_4D01);
    assert_eq!(dst(e), HOST);
    assert_eq!((e[20], e[21]), (3, 3));
    assert_eq!(&e[28..28 + 28], &p[..28], "quotes the IP header and 8 bytes");
    assert_valid(e);
    // fragmentation needed carries the MTU
    let len = build_icmp_error(IcmpKind::FragNeeded { mtu: 1400 }, &p, 0xC0A8_4D01, &mut out).unwrap();
    assert_eq!(u16::from_be_bytes([out[26], out[27]]), 1400);
    assert_eq!((out[20], out[21]), (3, 4));
    assert_valid(&out[..len]);
    // never in answer to an ICMP error, a non-first fragment, or a bad source
    let err = packet(&Ip::new(HOST, REMOTE), 1, &icmp_msg(3, 3, 0, 0, b"zzzzzzzz"));
    assert!(build_icmp_error(IcmpKind::TimeExceeded, &err, 1, &mut out).is_none());
    let frag = packet(&Ip::new(HOST, REMOTE).frag(0x0008), 17, &udp_dgram(1, 2, b"x"));
    assert!(build_icmp_error(IcmpKind::TimeExceeded, &frag, 1, &mut out).is_none());
    let bcast = packet(&Ip::new(u32::MAX, REMOTE), 17, &udp_dgram(1, 2, b"x"));
    assert!(build_icmp_error(IcmpKind::TimeExceeded, &bcast, 1, &mut out).is_none());
    assert!(build_icmp_error(IcmpKind::TimeExceeded, &p, 1, &mut out[..50]).is_none());
}

#[test]
fn fragments_are_dropped_outbound_and_left_to_the_local_stack_inbound() {
    let mut n = new_napt::<512>();
    for f in [0x2000u16, 0x0001, 0x2001] {
        let mut p = packet(&Ip::new(HOST, REMOTE).frag(f), 17, &udp_dgram(50000, 53, b"frag"));
        assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::Fragment));
    }
    let mut i = packet(&Ip::new(REMOTE, WIFI).frag(0x2000), 17, &udp_dgram(53, 50000, b"frag"));
    assert_eq!(n.inbound(0, &mut i), Verdict::Local(LocalReason::Fragment));
    assert_eq!(n.active(), 0);
}

#[test]
fn ip_options_are_carried() {
    let mut n = new_napt::<512>();
    let mut p = packet(&Ip::new(HOST, REMOTE).opts(&[1, 1, 1, 0]), 6, &tcp_seg(49500, 443, 5, 0, SYN, b""));
    assert_eq!(p[0], 0x46);
    let (len, m, _) = fwd(n.outbound(0, &mut p));
    assert_eq!(usize::from(len), p.len());
    assert_eq!(&p[20..24], &[1, 1, 1, 0]);
    assert_valid(&p);
    let mut r = packet(&Ip::new(REMOTE, WIFI).opts(&[1, 1, 1, 0]), 6, &tcp_seg(443, m, 9, 6, SYN | ACK, b""));
    let _ = fwd(n.inbound(1, &mut r));
    assert_valid(&r);
    assert_eq!(dst(&r), HOST);
}

#[test]
fn malformed_headers_are_dropped_with_the_right_reason() {
    let mut n = new_napt::<512>();
    let good = tcp_pkt(HOST, 49000, REMOTE, 443, 1, 0, SYN, &[]);
    let cases: Vec<(Vec<u8>, DropReason)> = vec![
        (vec![], DropReason::Truncated),
        (good[..19].to_vec(), DropReason::Truncated),
        (
            {
                let mut p = good.clone();
                p[0] = 0x65;
                p
            },
            DropReason::BadVersion,
        ),
        (
            {
                let mut p = good.clone();
                p[0] = 0x44;
                p
            },
            DropReason::BadHeaderLen,
        ),
        (
            {
                let mut p = good.clone();
                p[0] = 0x4f;
                p
            },
            DropReason::Truncated,
        ),
        (
            {
                let mut p = good.clone();
                p[2] = 0;
                p[3] = 10;
                p
            },
            DropReason::BadTotalLen,
        ),
        (
            {
                let mut p = good.clone();
                p[2] = 1;
                p
            },
            DropReason::BadTotalLen,
        ),
        (
            {
                let mut p = good.clone();
                p[10] ^= 1;
                p
            },
            DropReason::BadIpChecksum,
        ),
        (good[..30].to_vec(), DropReason::BadTotalLen),
    ];
    for (mut p, why) in cases {
        assert_eq!(n.outbound(0, &mut p), Verdict::Drop(why), "{p:?}");
    }
    // transport headers
    let mut short = packet(&Ip::new(HOST, REMOTE), 6, &[0u8; 12]);
    assert_eq!(n.outbound(0, &mut short), Verdict::Drop(DropReason::L4Truncated));
    let mut off = tcp_seg(49000, 443, 1, 0, SYN, &[]);
    off[12] = 4 << 4;
    let mut p = packet(&Ip::new(HOST, REMOTE), 6, &off);
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::BadL4Header));
    let mut off = tcp_seg(49000, 443, 1, 0, SYN, &[]);
    off[12] = 15 << 4;
    let mut p = packet(&Ip::new(HOST, REMOTE), 6, &off);
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::BadL4Header));
    let mut u = udp_dgram(49000, 53, b"abc");
    u[4..6].copy_from_slice(&200u16.to_be_bytes());
    let mut p = packet(&Ip::new(HOST, REMOTE), 17, &u);
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::BadL4Header));
    u[4..6].copy_from_slice(&4u16.to_be_bytes());
    let mut p = packet(&Ip::new(HOST, REMOTE), 17, &u);
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::BadL4Header));
    let mut p = packet(&Ip::new(HOST, REMOTE), 17, &[0u8; 5]);
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::L4Truncated));
    assert_eq!(n.active(), 0);
}

#[test]
fn destination_and_source_policy() {
    let mut n = new_napt::<512>();
    let udp = |s: u32, d: u32| udp_pkt(s, 50000, d, 53, b"x");
    let cases = [
        (HOST, 0xE000_00FB, DropReason::Multicast),
        (HOST, 0xFFFF_FFFF, DropReason::Broadcast),
        (HOST, 0xF000_0001, DropReason::Broadcast),
        (HOST, 0x0A00_00FF, DropReason::Broadcast), // directed broadcast of the Wi-Fi /24
        (HOST, 0x7F00_0001, DropReason::ThisNetOrLoopback),
        (HOST, 0x0001_0203, DropReason::ThisNetOrLoopback),
        (HOST, 0xA9FE_0101, DropReason::LinkLocal),
        (HOST, 0xC0A8_4D09, DropReason::OnLinkDestination),
        (0x0A01_0101, REMOTE, DropReason::SpoofedSource),
        (0xC0A8_4D01, REMOTE, DropReason::SpoofedSource), // the dongle's own address
        (0xC0A8_4DFF, REMOTE, DropReason::SpoofedSource),
        (0xC0A8_4D00, REMOTE, DropReason::SpoofedSource),
        (0, REMOTE, DropReason::SpoofedSource),
    ];
    for (s, d, why) in cases {
        let mut p = udp(s, d);
        assert_eq!(n.outbound(0, &mut p), Verdict::Drop(why), "{s:08x} -> {d:08x}");
    }
    let mut p = udp(HOST, WIFI);
    assert_eq!(n.outbound(0, &mut p), Verdict::Local(LocalReason::ToWifiAddress));
    assert_eq!(n.active(), 0);
}

#[test]
fn protocols_and_icmp_types_other_than_echo_are_dropped_not_leaked() {
    let mut n = new_napt::<512>();
    let mut gre = packet(&Ip::new(HOST, REMOTE), 47, &[0u8; 16]);
    assert_eq!(n.outbound(0, &mut gre), Verdict::Drop(DropReason::UnsupportedProtocol));
    let mut esp = packet(&Ip::new(HOST, REMOTE), 50, &[0u8; 16]);
    assert_eq!(n.outbound(0, &mut esp), Verdict::Drop(DropReason::UnsupportedProtocol));
    for ty in [0u8, 3, 5, 11, 13, 17] {
        let mut p = packet(&Ip::new(HOST, REMOTE), 1, &icmp_msg(ty, 0, 5, 5, b"abcd"));
        assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::IcmpNotEcho), "type {ty}");
    }
    let mut short = packet(&Ip::new(HOST, REMOTE), 1, &[8, 0, 0, 0]);
    assert_eq!(n.outbound(0, &mut short), Verdict::Drop(DropReason::L4Truncated));
}

#[test]
fn flows_start_only_where_lwip_starts_them() {
    let mut n = new_napt::<512>();
    // TCP without a SYN: no flow, ICMP port unreachable (not a RST, not silence)
    let mut p = tcp_pkt(HOST, 49000, REMOTE, 80, 1, 1, ACK, b"x");
    assert!(matches!(n.outbound(0, &mut p), Verdict::Reject(Reject { reason: RejectReason::NoSession, icmp: IcmpKind::PortUnreachable })));
    // SYN+ACK from the host is not a new flow either
    let mut p = tcp_pkt(HOST, 49000, REMOTE, 80, 1, 1, SYN | ACK, b"");
    assert!(matches!(n.outbound(0, &mut p), Verdict::Reject(_)));
    // a SYN from a port below 1024, and a datagram from one
    let mut p = tcp_pkt(HOST, 1023, REMOTE, 80, 1, 0, SYN, b"");
    assert!(matches!(n.outbound(0, &mut p), Verdict::Reject(Reject { reason: RejectReason::NoSession, .. })));
    let mut p = udp_pkt(HOST, 1023, REMOTE, 53, b"x");
    assert!(matches!(n.outbound(0, &mut p), Verdict::Reject(Reject { reason: RejectReason::NoSession, .. })));
    let mut p = udp_pkt(HOST, 1024, REMOTE, 53, b"x");
    assert!(matches!(n.outbound(0, &mut p), Verdict::Forward { .. }));
    assert_eq!(n.active(), 1);
}

#[test]
fn inbound_that_is_not_ours_goes_to_the_local_stack() {
    let mut n = new_napt::<512>();
    let m = establish(&mut n, 0, 49300);
    let before = n.active();
    let cases: Vec<(Vec<u8>, LocalReason)> = vec![
        (tcp_pkt(REMOTE, 443, WIFI, m + 1, 1, 1, ACK, b""), LocalReason::NoMapping),
        (tcp_pkt(REMOTE2, 443, WIFI, m, 1, 1, ACK, b""), LocalReason::RemoteMismatch),
        (tcp_pkt(REMOTE, 444, WIFI, m, 1, 1, ACK, b""), LocalReason::RemoteMismatch),
        (tcp_pkt(REMOTE, 443, 0x0A00_0033, m, 1, 1, ACK, b""), LocalReason::NotWifiAddress),
        (udp_pkt(REMOTE, 443, WIFI, m, b"x"), LocalReason::NoMapping), // same port, other protocol
        (packet(&Ip::new(REMOTE, WIFI), 47, &[0; 8]), LocalReason::Protocol),
        (packet(&Ip::new(REMOTE, WIFI), 1, &icmp_msg(8, 0, 1, 1, b"ping")), LocalReason::IcmpNotEchoReply),
        (packet(&Ip::new(REMOTE, WIFI), 1, &icmp_msg(3, 3, 0, 0, &[0; 28])), LocalReason::IcmpNotEchoReply),
        (echo_pkt(REMOTE, WIFI, 0, 9999, 1), LocalReason::NoMapping),
    ];
    for (mut p, why) in cases {
        let before_bytes = p.clone();
        assert_eq!(n.inbound(1, &mut p), Verdict::Local(why));
        assert_eq!(p, before_bytes, "a packet handed to the local stack is untouched");
    }
    assert_eq!(n.active(), before);
}

#[test]
fn mtu_policy_both_ways() {
    let mut n = new_napt::<512>();
    let big = vec![7u8; 1500 - 28 + 1];
    let mut p = packet(&Ip::new(HOST, REMOTE).df(), 17, &udp_dgram(50000, 53, &big));
    assert_eq!(p.len(), 1501);
    let Verdict::Reject(r) = n.outbound(0, &mut p) else { panic!() };
    assert_eq!((r.reason, r.icmp), (RejectReason::TooBigDf, IcmpKind::FragNeeded { mtu: 1500 }));
    let mut p = packet(&Ip::new(HOST, REMOTE), 17, &udp_dgram(50000, 53, &big));
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::TooBigNoFragment));
    assert_eq!(n.active(), 0, "no state for a refused packet");
    let fits = vec![7u8; 1500 - 28];
    let mut p = packet(&Ip::new(HOST, REMOTE).df(), 17, &udp_dgram(50000, 53, &fits));
    let (_, m, _) = fwd(n.outbound(0, &mut p));
    assert_valid(&p);
    let mut r = packet(&Ip::new(REMOTE, WIFI).df(), 17, &udp_dgram(53, m, &big));
    assert!(matches!(n.inbound(1, &mut r), Verdict::Reject(Reject { reason: RejectReason::TooBigDf, .. })));
    // a smaller Wi-Fi MTU
    let mut cfg = NaptConfig::C;
    cfg.wifi_mtu = 1400;
    let mut n2 = Napt::<8>::new(cfg, &mut tdongle_tailnet_types::test_util::TestRng(1));
    n2.set_wifi(Some(WifiAddr { ip: WIFI, mask: 0xffff_ff00 }));
    let mut p = packet(&Ip::new(HOST, REMOTE).df(), 17, &udp_dgram(50000, 53, &vec![0u8; 1400]));
    let Verdict::Reject(r) = n2.outbound(0, &mut p) else { panic!() };
    assert_eq!(r.icmp, IcmpKind::FragNeeded { mtu: 1400 });
}

#[test]
fn wifi_address_changes_flush_and_no_address_means_no_nat() {
    let mut n = new_napt::<512>();
    let _ = establish(&mut n, 0, 49300);
    assert_eq!(n.active(), 1);
    n.set_wifi(Some(WifiAddr { ip: WIFI, mask: 0xffff_ff00 }));
    assert_eq!(n.active(), 1, "the same address keeps the table");
    n.set_wifi(Some(WifiAddr { ip: 0x0A00_0063, mask: 0xffff_ff00 }));
    assert_eq!(n.active(), 0);
    assert_eq!(n.stats().flushed.get(), 1);
    n.set_wifi(None);
    let mut p = tcp_pkt(HOST, 49000, REMOTE, 80, 1, 0, SYN, b"");
    assert_eq!(n.outbound(0, &mut p), Verdict::Drop(DropReason::NoWifiAddress));
    let mut i = tcp_pkt(REMOTE, 80, WIFI, 49000, 1, 0, SYN | ACK, b"");
    assert_eq!(n.inbound(0, &mut i), Verdict::Local(LocalReason::NoWifiAddress));
    n.check_invariants().unwrap();
}

#[test]
fn padding_after_the_ip_length_is_ignored_and_untouched() {
    let mut n = new_napt::<512>();
    let mut p = tcp_pkt(HOST, 49400, REMOTE, 80, 1, 0, SYN, b"");
    let real = p.len();
    p.extend_from_slice(&[0xaa; 6]); // Ethernet padding
    let (len, _, _) = fwd(n.outbound(0, &mut p));
    assert_eq!(usize::from(len), real);
    assert_eq!(&p[real..], &[0xaa; 6]);
    assert_valid(&p[..real]);
}

#[test]
fn only_the_expected_bytes_change() {
    let mut n = new_napt::<512>();
    let orig = tcp_pkt(HOST, 49500, REMOTE, 8080, 99, 0, SYN, b"payload!");
    let mut p = orig.clone();
    let (_, m, _) = fwd(n.outbound(0, &mut p));
    let changed: Vec<usize> = (0..p.len()).filter(|&i| p[i] != orig[i]).collect();
    // ttl(8), ip csum(10,11), src addr(12..16), tcp csum(36,37), and the source port only if it moved
    for i in changed {
        assert!(matches!(i, 8 | 10 | 11 | 12..=15 | 36 | 37) || (m != 49500 && matches!(i, 20 | 21)), "byte {i} changed");
    }
}

#[test]
fn counters_account_for_every_packet() {
    let mut n = new_napt::<64>();
    let mut sent = 0u32;
    let mut go = |n: &mut Napt<64>, mut p: Vec<u8>, out: bool| {
        sent += 1;
        let _ = if out { n.outbound(0, &mut p) } else { n.inbound(0, &mut p) };
    };
    go(&mut n, tcp_pkt(HOST, 49000, REMOTE, 80, 1, 0, SYN, b""), true);
    go(&mut n, tcp_pkt(HOST, 49000, REMOTE, 80, 2, 0, ACK, b""), true);
    go(&mut n, tcp_pkt(HOST, 49001, REMOTE, 80, 2, 0, ACK, b""), true);
    go(&mut n, udp_pkt(HOST, 1, REMOTE, 80, b""), true);
    go(&mut n, vec![1, 2, 3], true);
    go(&mut n, tcp_pkt(REMOTE, 80, WIFI, 49000, 1, 0, SYN | ACK, b""), false);
    go(&mut n, tcp_pkt(REMOTE, 80, WIFI, 1, 1, 0, SYN | ACK, b""), false);
    let s = n.stats();
    let accounted = |d: &DirStats| d.forwarded_total() + d.refused_total();
    assert_eq!(s.outbound.packets.get() + s.inbound.packets.get(), sent);
    assert_eq!(s.outbound.packets.get(), accounted(&s.outbound));
    assert_eq!(s.inbound.packets.get(), accounted(&s.inbound));
}

#[test]
fn state_sizes() {
    use std::mem::size_of;
    std::println!("Napt<512>::STATE_BYTES = {}", Napt::<512>::STATE_BYTES);
    std::println!("Napt<128>::STATE_BYTES = {}", Napt::<128>::STATE_BYTES);
    std::println!("Napt<64>::STATE_BYTES = {}", Napt::<64>::STATE_BYTES);
    std::println!("NaptStats = {}", size_of::<NaptStats>());
    std::println!("DhcpServer<8> = {}", tdongle_tailnet_usbnet::dhcp::DhcpServer::<8>::STATE_BYTES);
    std::println!("Neighbors<4> = {}", tdongle_tailnet_usbnet::arp::Neighbors::<4>::STATE_BYTES);
    std::println!("UsbNet<512,8,4> = {}", tdongle_tailnet_usbnet::UsbNet::<512, 8, 4>::STATE_BYTES);
    // within lwIP's own table (512 x 40 = 20,480 B)
    // the flows are on the heap, as they come: the table itself is the two bucket arrays and the bookkeeping
    const { assert!(Napt::<512>::STATE_BYTES < 4_000) };
}

#[test]
fn the_flows_take_heap_as_they_come_and_give_it_back_when_idle() {
    let mut n = new_napt::<512>();
    assert_eq!(n.heap_bytes(), 0, "an empty table holds nothing");
    for i in 0..40u16 {
        let _ = syn_out(&mut n, 1, 40_000 + i);
    }
    let forty = n.heap_bytes();
    assert!(forty > 0 && forty < 4_000, "forty flows take about two chunks: {forty}");
    for i in 40..512u16 {
        let _ = syn_out(&mut n, 1, 40_000 + i);
    }
    let full = n.heap_bytes();
    assert!((512 * 32..21_000).contains(&full), "a full table is within lwIP's own 20,480 B: {full}");
    assert_eq!(n.active(), 512);
    // a refusal of the heap evicts instead of growing (a table of 512 is full anyway: test the guard on a fresh one)
    let mut g = new_napt::<512>();
    g.set_grow_guard(|_| false);
    let mut p = tcp_pkt(HOST, 41_000, REMOTE, 443, 1000, 0, SYN, &[]);
    assert!(!matches!(g.outbound(1, &mut p), Verdict::Forward { .. }), "no heap and no flow to evict: no new flow");
    assert_eq!(g.heap_bytes(), 0, "a guard that says no grows nothing");
    // idle: everything expires and the memory goes back
    n.expire(10_000_000);
    assert_eq!(n.active(), 0);
    assert_eq!(n.heap_bytes(), 0, "an idle table holds nothing");
    n.check_invariants().unwrap();
}

// ---- timers ----

#[test]
fn udp_and_icmp_expire_after_two_seconds_idle() {
    let mut n = new_napt::<512>();
    let mut p = udp_pkt(HOST, 50000, REMOTE, 53, b"q");
    let _ = fwd(n.outbound(1_000, &mut p));
    let mut e = echo_pkt(HOST, REMOTE, 8, 5, 1);
    let _ = fwd(n.outbound(1_000, &mut e));
    assert_eq!(n.expire(3_000), 0, "age 2000 is not past the timeout");
    assert_eq!(n.expire(3_001), 2);
    assert_eq!(n.active(), 0);
    assert_eq!(n.stats().expired[Proto::Udp as usize].get(), 1);
    n.check_invariants().unwrap();
}

#[test]
fn traffic_in_either_direction_refreshes_a_flow() {
    let mut n = new_napt::<512>();
    let mut p = udp_pkt(HOST, 50000, REMOTE, 53, b"q");
    let (_, m, _) = fwd(n.outbound(0, &mut p));
    let mut r = udp_pkt(REMOTE, 53, WIFI, m, b"a");
    let _ = fwd(n.inbound(1_900, &mut r)); // refreshed by the reply
    assert_eq!(n.expire(3_800), 0);
    let mut p = udp_pkt(HOST, 50000, REMOTE, 53, b"q2");
    let _ = fwd(n.outbound(3_700, &mut p)); // refreshed by the host
    assert_eq!(n.expire(5_600), 0);
    assert_eq!(n.expire(5_701), 1);
}

#[test]
fn tcp_half_open_goes_after_msl_established_after_thirty_minutes() {
    let mut n = new_napt::<512>();
    let _ = syn_out(&mut n, 0, 49100); // no SYN-ACK ever
    let m = establish(&mut n, 0, 49200);
    assert_eq!(n.expire(60_000), 0);
    assert_eq!(n.expire(60_001), 1, "the half-open one");
    assert_eq!(n.active(), 1);
    assert!(n.pop_rst().is_none(), "a half-open flow owes nobody a RST");
    assert_eq!(n.expire(1_800_000), 0);
    assert_eq!(n.expire(1_800_001), 1, "established, idle 30 minutes");
    // the two RSTs for the dropped live connection
    let rst = n.pop_rst().expect("RST queued");
    assert!(n.pop_rst().is_none());
    assert_eq!((rst.host_ip, rst.host_port, rst.remote_ip, rst.remote_port, rst.mapped_port), (HOST, 49200, REMOTE, 443, m));
    assert_eq!(rst.host_seq, 1001, "next sequence number of the host: SYN consumed one");
    assert_eq!(rst.remote_seq, 5001);
    let mut a = [0u8; RST_LEN];
    rst.to_host(&mut a);
    assert_eq!((src(&a), dst(&a), sport(&a), dport(&a)), (REMOTE, HOST, 443, 49200));
    assert_eq!(u32::from_be_bytes([a[24], a[25], a[26], a[27]]), 5001);
    assert_eq!(u32::from_be_bytes([a[28], a[29], a[30], a[31]]), 1001);
    assert_eq!(a[33], 0x14);
    assert_valid(&a);
    let mut b = [0u8; RST_LEN];
    rst.to_remote(WIFI, &mut b);
    assert_eq!((src(&b), dst(&b), sport(&b), dport(&b)), (WIFI, REMOTE, m, 443), "built from the identity the Internet knows");
    assert_valid(&b);
    n.check_invariants().unwrap();
}

#[test]
fn closed_and_reset_connections_go_after_msl_with_no_rst() {
    // FIN both ways, each acknowledged
    let mut n = new_napt::<512>();
    let m = establish(&mut n, 0, 49200);
    let mut f = tcp_pkt(HOST, 49200, REMOTE, 443, 1001, 5001, FIN | ACK, b"");
    let _ = fwd(n.outbound(1, &mut f));
    let mut fa = tcp_pkt(REMOTE, 443, WIFI, m, 5001, 1002, FIN | ACK, b"");
    let _ = fwd(n.inbound(2, &mut fa));
    let mut last = tcp_pkt(HOST, 49200, REMOTE, 443, 1002, 5002, ACK, b"");
    let _ = fwd(n.outbound(3, &mut last));
    assert_eq!(n.expire(60_003), 0);
    assert_eq!(n.expire(60_004), 1);
    assert!(n.pop_rst().is_none());

    // RST from the Internet
    let m = establish(&mut n, 100_000, 49201);
    let mut r = tcp_pkt(REMOTE, 443, WIFI, m, 5001, 0, RST | ACK, b"");
    let (_, _, _) = fwd(n.inbound(100_010, &mut r));
    assert_eq!(n.expire(160_010), 0);
    assert_eq!(n.expire(160_011), 1);
    assert!(n.pop_rst().is_none());

    // RST from the host
    let m = establish(&mut n, 200_000, 49202);
    let mut r = tcp_pkt(HOST, 49202, REMOTE, 443, 1001, 0, RST, b"");
    let _ = fwd(n.outbound(200_010, &mut r));
    assert_eq!(n.expire(260_011), 1);
    let _ = m;
    assert!(n.pop_rst().is_none());
}

#[test]
fn a_fin_that_is_never_acknowledged_does_not_free_a_live_flow_early() {
    let mut n = new_napt::<512>();
    let m = establish(&mut n, 0, 49200);
    let mut fa = tcp_pkt(REMOTE, 443, WIFI, m, 5001, 1001, FIN | ACK, b"");
    let _ = fwd(n.inbound(1, &mut fa)); // remote FIN, host has not ACKed
    assert_eq!(n.expire(100_000), 0, "still waiting for the host's ACK: lwIP keeps it up to 30 minutes");
    let mut ack = tcp_pkt(HOST, 49200, REMOTE, 443, 1001, 5002, ACK, b"");
    let _ = fwd(n.outbound(100_001, &mut ack));
    assert_eq!(n.expire(160_002), 1, "the host's ACK of the FIN completes it");
}

// ---- table pressure ----

#[test]
fn full_table_evicts_an_expired_flow_before_a_live_one() {
    let mut n = new_napt::<4>();
    for (i, t) in [0u64, 10, 20, 30].into_iter().enumerate() {
        let mut p = udp_pkt(HOST, 50000 + i as u16, REMOTE, 53, b"x");
        let _ = fwd(n.outbound(t, &mut p));
    }
    assert_eq!(n.active(), 4);
    // at t=2500 the first (age 2500) and second (2490) are expired, the others (2480, 2470) too; take the first one found
    let mut p = udp_pkt(HOST, 51000, REMOTE, 53, b"x");
    let _ = fwd(n.outbound(2_015, &mut p)); // only the t=0 and t=10 flows are past 2000
    assert_eq!(n.stats().evicted_expired.get(), 1);
    assert_eq!(n.stats().evicted_live.get(), 0);
    assert_eq!(n.active(), 4);
    n.check_invariants().unwrap();
}

#[test]
fn full_table_of_live_flows_evicts_the_oldest_and_reports_tcp_with_rst() {
    let mut n = new_napt::<4>();
    let mut maps = vec![];
    for (i, t) in [100u64, 200, 300, 400].into_iter().enumerate() {
        let sp = 50000 + i as u16;
        let mut syn = tcp_pkt(HOST, sp, REMOTE, 443, 1000, 0, SYN, &[]);
        let (_, m, _) = fwd(n.outbound(t, &mut syn));
        let mut sa = tcp_pkt(REMOTE, 443, WIFI, m, 5000, 1001, SYN | ACK, &[]);
        let _ = fwd(n.inbound(t, &mut sa));
        maps.push((sp, m));
    }
    // a new flow at t=500: the oldest (t=100, port 50000) goes
    let mut p = udp_pkt(HOST, 52000, REMOTE, 53, b"x");
    let _ = fwd(n.outbound(500, &mut p));
    assert_eq!(n.stats().evicted_live.get(), 1);
    let rst = n.pop_rst().expect("the evicted connection was established");
    assert_eq!(rst.host_port, 50000);
    // its replies now find nothing; the others still work
    let mut r = tcp_pkt(REMOTE, 443, WIFI, maps[0].1, 5001, 1001, ACK, b"");
    assert_eq!(n.inbound(501, &mut r), Verdict::Local(LocalReason::NoMapping));
    let mut r = tcp_pkt(REMOTE, 443, WIFI, maps[1].1, 5001, 1001, ACK, b"");
    assert!(matches!(n.inbound(501, &mut r), Verdict::Forward { .. }));
    n.check_invariants().unwrap();
}

#[test]
fn rst_queue_is_bounded_and_counted() {
    let mut n = new_napt::<32>();
    for i in 0..32u16 {
        let sp = 50000 + i;
        let mut syn = tcp_pkt(HOST, sp, REMOTE, 443, 1000, 0, SYN, &[]);
        let (_, m, _) = fwd(n.outbound(u64::from(i), &mut syn));
        let mut sa = tcp_pkt(REMOTE, 443, WIFI, m, 5000, 1001, SYN | ACK, &[]);
        let _ = fwd(n.inbound(u64::from(i), &mut sa));
    }
    for i in 0..20u16 {
        let mut p = udp_pkt(HOST, 53000 + i, REMOTE, 53, b"x");
        let _ = fwd(n.outbound(100 + u64::from(i), &mut p));
    }
    // 20 live evictions of established connections (the UDP flows are younger, the first 20 TCP go), 8 fit in the queue
    assert_eq!(n.stats().rst_queued.get(), 8);
    assert_eq!(n.stats().rst_lost.get(), 12);
    let mut got = 0;
    while n.pop_rst().is_some() {
        got += 1;
    }
    assert_eq!(got, 8);
    n.check_invariants().unwrap();
}

#[test]
fn syn_flood_from_the_host_cannot_corrupt_the_table() {
    let mut n = new_napt::<16>();
    for i in 0..2000u32 {
        let mut p = tcp_pkt(HOST, 1024 + (i % 60000) as u16, REMOTE, (i % 7 + 80) as u16, i, 0, SYN, &[]);
        let _ = n.outbound(u64::from(i), &mut p);
        if i % 100 == 0 {
            n.check_invariants().unwrap();
        }
    }
    assert_eq!(n.active(), 16);
    assert!(n.stats().high_water <= 16);
    n.check_invariants().unwrap();
}

#[test]
fn ports_in_use_by_other_flows_or_local_sockets_are_not_reused() {
    let mut n = new_napt::<512>();
    // flow 1 keeps 50000; flow 2 from HOST2 with the same source port must get another one
    let mut a = udp_pkt(HOST, 50000, REMOTE, 53, b"a");
    let (_, ma, _) = fwd(n.outbound(0, &mut a));
    let mut b = udp_pkt(HOST2, 50000, REMOTE, 53, b"b");
    let (_, mb, _) = fwd(n.outbound(0, &mut b));
    assert_eq!(ma, 50000);
    assert_ne!(mb, 50000);
    // TCP and UDP port spaces are separate
    let (_, mt) = syn_out(&mut n, 0, 50000);
    assert_eq!(mt, 50000);
    // a local socket's port is left alone
    assert!(n.reserve_local_port(Proto::Udp, 50100));
    let mut c = udp_pkt(HOST, 50100, REMOTE, 53, b"c");
    let (_, mc, _) = fwd(n.outbound(0, &mut c));
    assert_ne!(mc, 50100);
    n.release_local_port(Proto::Udp, 50100);
    let mut d = udp_pkt(HOST, 50100, REMOTE2, 53, b"d");
    let (_, md, _) = fwd(n.outbound(0, &mut d));
    assert_eq!(md, 50100);
    for i in 0..RESERVED_PORTS as u16 {
        assert!(n.reserve_local_port(Proto::Tcp, 1 + i) || i as usize >= RESERVED_PORTS - 1);
    }
    assert!(!n.reserve_local_port(Proto::Tcp, 9999), "the reservation table is bounded");
    n.check_invariants().unwrap();
}

#[test]
fn one_socket_talking_to_two_peers_gets_two_flows_that_do_not_mix() {
    // lwIP keys on the source port alone, so the second destination silently took over the first's mapping.
    let mut n = new_napt::<512>();
    let mut a = udp_pkt(HOST, 50200, REMOTE, 3478, b"a");
    let (_, ma, _) = fwd(n.outbound(0, &mut a));
    let mut b = udp_pkt(HOST, 50200, REMOTE2, 3478, b"b");
    let (_, mb, _) = fwd(n.outbound(0, &mut b));
    assert_ne!(ma, mb);
    let mut ra = udp_pkt(REMOTE, 3478, WIFI, ma, b"ra");
    let _ = fwd(n.inbound(1, &mut ra));
    assert_eq!((dst(&ra), dport(&ra)), (HOST, 50200));
    let mut rb = udp_pkt(REMOTE2, 3478, WIFI, mb, b"rb");
    let _ = fwd(n.inbound(1, &mut rb));
    assert_eq!((dst(&rb), dport(&rb)), (HOST, 50200));
    // cross-talk is refused
    let mut x = udp_pkt(REMOTE2, 3478, WIFI, ma, b"x");
    assert_eq!(n.inbound(1, &mut x), Verdict::Local(LocalReason::RemoteMismatch));
}

#[test]
fn new_syn_on_a_known_tuple_restarts_the_connection_without_a_rst() {
    let mut n = new_napt::<512>();
    let m = establish(&mut n, 0, 49200);
    let mut r = tcp_pkt(REMOTE, 443, WIFI, m, 5001, 0, RST | ACK, b"");
    let _ = fwd(n.inbound(10, &mut r)); // connection reset by the peer
    let mut syn = tcp_pkt(HOST, 49200, REMOTE, 443, 7000, 0, SYN, &[]); // the host reuses the port
    let (_, m2, new) = fwd(n.outbound(20, &mut syn));
    assert_eq!(m2, m, "same flow, same mapped port");
    assert!(new);
    assert_eq!(n.active(), 1);
    assert!(n.pop_rst().is_none());
    assert_valid(&syn);
    // it is half open again: gone after MSL without a SYN-ACK
    assert_eq!(n.expire(60_021), 1);
    assert!(n.pop_rst().is_none());
}

#[test]
fn a_single_flow_survives_a_million_time_steps_of_expiry_calls() {
    let mut n = new_napt::<8>();
    let m = establish(&mut n, 0, 49200);
    let mut t = 0u64;
    for _ in 0..1000 {
        t += 1_700;
        let _ = n.expire(t);
        let mut d = tcp_pkt(HOST, 49200, REMOTE, 443, 1001, 5001, ACK, b"k");
        let _ = fwd(n.outbound(t, &mut d)); // keepalive inside the 30 minutes
        let mut r = tcp_pkt(REMOTE, 443, WIFI, m, 5001, 1002, ACK, b"");
        let _ = fwd(n.inbound(t, &mut r));
    }
    assert_eq!(n.active(), 1);
}

#[test]
fn clock_wrap_of_the_32_bit_timestamps_is_harmless() {
    let mut n = new_napt::<8>();
    let base = u64::from(u32::MAX) - 500;
    let mut p = udp_pkt(HOST, 50000, REMOTE, 53, b"q");
    let (_, m, _) = fwd(n.outbound(base, &mut p));
    let mut r = udp_pkt(REMOTE, 53, WIFI, m, b"a");
    let _ = fwd(n.inbound(base + 1_000, &mut r)); // across the 32-bit boundary
    assert_eq!(n.expire(base + 2_500), 0);
    assert_eq!(n.expire(base + 3_001), 1);
}

#[test]
fn every_outcome_enum_has_a_dense_unique_counter_index() {
    use DropReason::*;
    let drops = [
        Truncated,
        BadVersion,
        BadHeaderLen,
        BadTotalLen,
        BadIpChecksum,
        BadL4Header,
        L4Truncated,
        Fragment,
        SpoofedSource,
        Multicast,
        Broadcast,
        ThisNetOrLoopback,
        LinkLocal,
        OnLinkDestination,
        NoWifiAddress,
        UnsupportedProtocol,
        IcmpNotEcho,
        TtlExpiredIcmp,
        TooBigNoFragment,
        NoPort,
    ];
    let mut seen: Vec<usize> = drops.iter().map(|d| d.index()).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..DropReason::COUNT).collect::<Vec<_>>());
    let locals = [
        LocalReason::ToWifiAddress,
        LocalReason::NotWifiAddress,
        LocalReason::NoWifiAddress,
        LocalReason::Fragment,
        LocalReason::Protocol,
        LocalReason::NoMapping,
        LocalReason::RemoteMismatch,
        LocalReason::IcmpNotEchoReply,
    ];
    let mut seen: Vec<usize> = locals.iter().map(|d| d.index()).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..LocalReason::COUNT).collect::<Vec<_>>());
    let rejects = [RejectReason::TtlExpired, RejectReason::NoSession, RejectReason::NoPort, RejectReason::TooBigDf];
    let mut seen: Vec<usize> = rejects.iter().map(|d| d.index()).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..RejectReason::COUNT).collect::<Vec<_>>());
}
