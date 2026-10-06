//! Behaviour tests ported from the C suite: test_router.c, test_router_rx_reasons.c, test_router_hotpath.c, test_router_batch.c,
//! test_route_table.c, test_route_ingress.c.
#![allow(
    clippy::type_complexity,
    clippy::manual_div_ceil,
    clippy::assertions_on_constants,
    clippy::unnecessary_to_owned,
    clippy::manual_range_contains,
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::manual_range_patterns
)]
mod common;
use common::*;
use tdongle_tailnet_router::tables::{AliasCache, AliasRecord, Flow, FlowInReject, FlowTable};
use tdongle_tailnet_router::*;

const HOST: u32 = 0xc0a8_4d02;
const VPN1: u32 = 0x6440_0001;
const PEER: u32 = 0x6440_0002;

type R = GatewayRouter;

fn set(ids: &[(u32, u32)]) -> MemberSet<16> {
    let mut s = MemberSet::new();
    for &(id, vpn) in ids {
        assert!(s.insert(Member { id, vpn_ip: vpn, ready: true }));
    }
    s
}
fn stat(r: &R, s: Stat) -> u32 {
    r.stats().get(s)
}
/// Send a USB-host packet, return the outcome and the (possibly rewritten) bytes.
fn host(r: &mut R, b: &[u8], now: u64) -> (HostOutcome, Vec<u8>) {
    let mut v = b.to_vec();
    let g = r.usb_generation();
    let o = r.host_packet(&mut v, now, g);
    if let HostOutcome::Forwarded { len, .. } | HostOutcome::Reply { len, .. } = o {
        v.truncate(len);
    }
    (o, v)
}
fn tunnel(r: &mut R, from: u32, b: &[u8], now: u64) -> (TunnelOutcome, Vec<u8>) {
    let mut v = b.to_vec();
    let o = r.tunnel_packet(from, &mut v, now);
    if let TunnelOutcome::ToHost { len, .. } = o {
        v.truncate(len);
    }
    (o, v)
}
fn alias_for(r: &mut R, id: u32, peer: u32, n: u32) -> u32 {
    let a = ALIAS_BASE + n;
    assert!(r.alias_insert(AliasRecord { id, peer, alias: a }));
    a
}
/// A UDP packet like test_router.c's `packet()`.
fn small_udp(src: u32, dst: u32, sport: u16, dport: u16) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0] = 0x45;
    b[8] = 64;
    b[9] = 17;
    wr16(&mut b, 2, 32);
    wr32(&mut b, 12, src);
    wr32(&mut b, 16, dst);
    wr16(&mut b, 20, sport);
    wr16(&mut b, 22, dport);
    wr16(&mut b, 24, 12);
    b[28..].copy_from_slice(b"ping");
    fill_checksums(&mut b, false);
    b
}

#[test]
fn three_memberships_identical_peers() {
    let mut r = R::new();
    let (v1, v2, v3) = (0x6440_0001, 0x6440_0001, 0x6440_0001);
    r.publish(set(&[(1, v1), (2, v2), (3, v3)]));
    // unknown alias with no members consumed (no Internet forwarding)
    let mut r0 = R::new();
    let (o, _) = host(&mut r0, &small_udp(HOST, 0xc612_0001, 1234, 443), 0);
    assert!(matches!(o, HostOutcome::Held | HostOutcome::Dropped(_)), "never forwarded or passed to the Internet: {o:?}");
    let a = alias_for(&mut r, 1, PEER, 0);
    let b = alias_for(&mut r, 2, PEER, 1);
    let c = alias_for(&mut r, 3, PEER, 2);
    let (o, out) = host(&mut r, &small_udp(HOST, a, 1234, 443), 0);
    assert_eq!(o, HostOutcome::Forwarded { member: 1, peer: PEER, len: 32 });
    assert_eq!((rd32(&out, 12), rd32(&out, 16)), (v1, PEER));
    let port = rd16(&out, 20);
    assert!(packet_ok(&out));
    let (o, out2) = host(&mut r, &small_udp(HOST, b, 1234, 443), 0);
    assert!(matches!(o, HostOutcome::Forwarded { member: 2, .. }));
    assert_ne!(rd16(&out2, 20), port);
    assert!(matches!(host(&mut r, &small_udp(HOST, c, 1234, 443), 0).0, HostOutcome::Forwarded { member: 3, .. }));
    // identical IP/ports from a different identity cannot claim the flow
    let reply = small_udp(PEER, v1, 443, port);
    // membership 2 has its own flows only: the same tuple from its device finds no flow of ours
    let (o, _) = tunnel(&mut r, 2, &reply, 0);
    assert!(matches!(o, TunnelOutcome::Dropped(TunnelDrop::Flow(FlowInReject::Owner | FlowInReject::NoFlow))), "{o:?}");
    let (o, out) = tunnel(&mut r, 1, &reply, 0);
    assert_eq!(o, TunnelOutcome::ToHost { host: HOST, len: 32 });
    assert_eq!((rd32(&out, 12), rd32(&out, 16), rd16(&out, 22)), (a, HOST, 1234));
    assert!(packet_ok(&out));
}

#[test]
fn padded_replies_and_host_padding() {
    // Real WireGuard plaintext retains up to 15 bytes of padding: tolerated at tunnel ingress only.
    let mut r = R::new();
    r.publish(set(&[(42, VPN1)]));
    let alias = alias_for(&mut r, 42, PEER, 0);
    for proto in [6u8, 17] {
        for payload in 0..64usize {
            let inner = 20 + if proto == 6 { 20 } else { 8 } + payload;
            let mut b = vec![0u8; inner];
            b[0] = 0x45;
            b[8] = 64;
            b[9] = proto;
            wr16(&mut b, 2, inner as u16);
            wr32(&mut b, 12, HOST);
            wr32(&mut b, 16, alias);
            wr16(&mut b, 20, 1234);
            wr16(&mut b, 22, 8768);
            if proto == 6 {
                b[32] = 0x50;
                b[33] = 0x10;
            } else {
                wr16(&mut b, 24, (inner - 20) as u16);
            }
            fill_checksums(&mut b, false);
            let (o, sent) = host(&mut r, &b, 0);
            assert!(matches!(o, HostOutcome::Forwarded { .. }));
            let mapped = rd16(&sent, 20);
            let padded = (inner + 15) & !15;
            let mut reply = vec![0u8; padded];
            reply[..inner].copy_from_slice(&sent);
            wr32(&mut reply, 12, PEER);
            wr32(&mut reply, 16, VPN1);
            wr16(&mut reply, 20, 8768);
            wr16(&mut reply, 22, mapped);
            for i in inner - payload..inner {
                reply[i] = i as u8;
            }
            fill_checksums(&mut reply[..inner], false);
            // wrong member
            assert!(matches!(tunnel(&mut r, 7, &reply, 0).0, TunnelOutcome::Dropped(TunnelDrop::NoMember)));
            // truncated
            assert!(matches!(tunnel(&mut r, 42, &reply[..inner - 1], 0).0, TunnelOutcome::Dropped(_)));
            let (o, out) = tunnel(&mut r, 42, &reply, 0);
            assert_eq!(o, TunnelOutcome::ToHost { host: HOST, len: inner });
            assert_eq!(out.len(), inner);
            assert_eq!((rd32(&out, 12), rd32(&out, 16)), (alias, HOST));
            assert_eq!((rd16(&out, 20), rd16(&out, 22)), (8768, 1234));
            assert!(packet_ok(&out));
            for i in inner - payload..inner {
                assert_eq!(out[i], i as u8);
            }
            if inner != padded {
                // the USB side gets no padding tolerance
                let mut bad = vec![0u8; padded];
                bad[..inner].copy_from_slice(&out);
                wr32(&mut bad, 12, HOST);
                wr32(&mut bad, 16, alias);
                fill_checksums(&mut bad[..inner], false);
                let (o, _) = host(&mut r, &bad, 0);
                assert!(matches!(o, HostOutcome::Dropped(HostDrop::Invalid)));
            }
        }
    }
    r.forget(42);
}

#[test]
fn drops_and_lifecycle() {
    let mut r = R::new();
    r.publish(set(&[(1, VPN1), (2, VPN1), (3, VPN1)]));
    let a = alias_for(&mut r, 1, PEER, 0);
    let b = alias_for(&mut r, 2, PEER, 1);
    let (_, out) = host(&mut r, &small_udp(HOST, a, 1234, 443), 0);
    let port = rd16(&out, 20);
    // bad: fragment bit
    let mut bad = small_udp(HOST, a, 1234, 443);
    bad[6] = 0x20;
    assert!(matches!(host(&mut r, &bad, 0).0, HostOutcome::Dropped(HostDrop::Invalid)));
    // bad source
    assert!(matches!(host(&mut r, &small_udp(0xc0a8_0102, a, 1234, 443), 0).0, HostOutcome::Dropped(HostDrop::BadSource)));
    assert!(matches!(host(&mut r, &small_udp(0xc0a8_4d01, a, 1234, 443), 0).0, HostOutcome::Dropped(HostDrop::BadSource)));
    assert!(matches!(host(&mut r, &small_udp(0xc0a8_4dff, a, 1234, 443), 0).0, HostOutcome::Dropped(HostDrop::BadSource)));
    // suspend(2) keeps the alias; forget(1) drops flows and aliases
    r.suspend(2);
    assert_eq!(r.alias_find_key(2, PEER), Some(b));
    r.forget(1);
    let reply = small_udp(PEER, VPN1, 443, port);
    assert!(matches!(tunnel(&mut r, 1, &reply, 0).0, TunnelOutcome::Dropped(TunnelDrop::NoMember)));
    // idle expiry: a flow of membership 3
    let c = alias_for(&mut r, 3, PEER, 2);
    let (_, out) = host(&mut r, &small_udp(HOST, c, 1234, 443), 1000);
    let m = rd16(&out, 20);
    let reply = small_udp(PEER, VPN1, 443, m);
    assert!(matches!(tunnel(&mut r, 3, &reply, 1000 + 121_000).0, TunnelOutcome::Dropped(TunnelDrop::Flow(FlowInReject::Idle))));
    // detach: old flow cannot be claimed, new traffic gets another mapped port
    let (_, out) = host(&mut r, &small_udp(HOST, c, 1234, 443), 200_000);
    let m = rd16(&out, 20);
    r.usb_detach();
    let reply = small_udp(PEER, VPN1, 443, m);
    assert!(matches!(tunnel(&mut r, 3, &reply, 200_000).0, TunnelOutcome::Dropped(TunnelDrop::Flow(FlowInReject::Generation))));
    let (_, out) = host(&mut r, &small_udp(HOST, c, 1234, 443), 200_000);
    assert_ne!(rd16(&out, 20), m);
    // a packet queued before the detach is stale
    let mut v = small_udp(HOST, c, 1, 2);
    let old = r.usb_generation() - 1;
    assert_eq!(r.host_packet(&mut v, 0, old), HostOutcome::Dropped(HostDrop::StaleGeneration));
    assert_eq!(r.stats().extra(Extra::StaleGeneration), 1);
}

#[test]
fn member_down_and_no_member() {
    let mut r = R::new();
    let mut s = set(&[(1, VPN1)]);
    r.publish(s);
    let a = alias_for(&mut r, 1, PEER, 0);
    let a9 = alias_for(&mut r, 9, PEER, 1); // membership 9 not published
    assert!(matches!(host(&mut r, &small_udp(HOST, a9, 1, 2), 0).0, HostOutcome::Dropped(HostDrop::NoMember)));
    s.insert(Member { id: 1, vpn_ip: VPN1, ready: false });
    r.publish(s);
    assert!(matches!(host(&mut r, &small_udp(HOST, a, 1, 2), 0).0, HostOutcome::Dropped(HostDrop::MemberDown)));
    assert_eq!((stat(&r, Stat::NoMember), stat(&r, Stat::MemberDown)), (1, 1));
}

#[test]
fn mss_clamp() {
    let mut syn = vec![0u8; 44];
    syn[9] = 6;
    syn[32] = 0x60;
    syn[33] = 2;
    syn[40] = 2;
    syn[41] = 4;
    wr16(&mut syn, 42, 1460);
    assert!(packet::clamp_mss(&mut syn, 20));
    assert_eq!(rd16(&syn, 42), 1360);
    wr16(&mut syn, 42, 1200);
    assert!(packet::clamp_mss(&mut syn, 20));
    assert_eq!(rd16(&syn, 42), 1200);
    syn[41] = 255;
    assert!(!packet::clamp_mss(&mut syn, 20));
}

/// NOP before the MSS: the value straddles two checksum words, the checksum must stay valid.
#[test]
fn mss_clamp_odd_offset_keeps_checksums_valid() {
    let mut r = R::new();
    r.publish(set(&[(1, VPN1)]));
    let a = alias_for(&mut r, 1, 0x6450_0001, 0);
    let mut rng = Rng(7);
    for nops in 0..4usize {
        for old in (1361u32..=1500).step_by(139) {
            let hdr = 20 + 4 * ((20 + nops + 4 + 3) / 4);
            let mut b = vec![0u8; hdr];
            b[0] = 0x45;
            b[8] = 30;
            b[9] = 6;
            wr16(&mut b, 2, hdr as u16);
            wr32(&mut b, 12, 0xc0a8_4d02);
            wr32(&mut b, 16, a);
            wr16(&mut b, 20, 4100 + nops as u16);
            wr16(&mut b, 22, 80);
            wr32(&mut b, 24, rng.next());
            wr32(&mut b, 28, rng.next());
            b[32] = (((hdr - 20) / 4) as u8) << 4;
            b[33] = 2;
            wr16(&mut b, 34, rng.next() as u16);
            for i in 0..nops {
                b[40 + i] = 1;
            }
            b[40 + nops] = 2;
            b[41 + nops] = 4;
            wr16(&mut b, 42 + nops, old as u16);
            fill_checksums(&mut b, false);
            assert!(packet_ok(&b));
            let (o, sent) = host(&mut r, &b, 0);
            assert!(matches!(o, HostOutcome::Forwarded { .. }), "{o:?}");
            assert_eq!(sent.len(), hdr);
            assert!(packet_ok(&sent));
            assert_eq!(rd16(&sent, 42 + nops), 1360);
        }
    }
}

#[test]
fn rx_reasons_one_counter_each() {
    let mut r = R::new();
    r.publish(set(&[(1, VPN1)]));
    let a = alias_for(&mut r, 1, PEER, 0);
    let (_, sent) = host(&mut r, &small_udp(HOST, a, 1234, 8768), 0);
    let mapped = rd16(&sent, 20);
    let good = small_udp(PEER, VPN1, 8768, mapped);
    let snap = |r: &R| *r.stats().as_array();
    let expect = |r: &R, before: [u32; 30], first: Stat, second: Option<Stat>| {
        for s in Stat::ALL {
            let want = u32::from(s == first) + u32::from(Some(s) == second);
            assert_eq!(r.stats().get(s) - before[s as usize], want, "{first:?}: {s:?}");
        }
    };
    let before = snap(&r);
    assert!(matches!(tunnel(&mut r, 1, &good, 1).0, TunnelOutcome::ToHost { .. }));
    // good: forwarded_in is counted when the runtime reports the emit
    r.tx_result(Dir::ToHost, true);
    expect(&r, before, Stat::ForwardedIn, None);
    // short, v6, long, tiny
    for len in 0..20 {
        let before = snap(&r);
        let mut m = good.clone();
        assert!(matches!(tunnel(&mut r, 1, &m[..len].to_vec(), 1).0, TunnelOutcome::Dropped(TunnelDrop::Malformed)));
        expect(&r, before, Stat::TunnelMalformed, None);
        m[0] = 0;
    }
    for (what, f) in [
        ("v6", Box::new(|m: &mut Vec<u8>| m[0] = 0x65) as Box<dyn Fn(&mut Vec<u8>)>),
        ("long", Box::new(|m: &mut Vec<u8>| wr16(m, 2, 33))),
        ("tiny", Box::new(|m: &mut Vec<u8>| wr16(m, 2, 19))),
    ] {
        let before = snap(&r);
        let mut m = good.clone();
        f(&mut m);
        assert!(matches!(tunnel(&mut r, 1, &m, 1).0, TunnelOutcome::Dropped(TunnelDrop::Malformed)), "{what}");
        expect(&r, before, Stat::TunnelMalformed, None);
    }
    let cases: Vec<(&str, Box<dyn Fn(&mut Vec<u8>)>, u32, Stat, Option<Stat>)> = vec![
        ("csum", Box::new(|m| m[10] ^= 0xff), 1, Stat::BadPacket, None),
        ("no member", Box::new(|_| {}), 9, Stat::ReplyNoMember, Some(Stat::ReplyNomatch)),
        (
            "not us",
            Box::new(|m| {
                wr32(m, 16, 0x6440_0009);
                fill_checksums(m, false)
            }),
            1,
            Stat::ReplyNotUs,
            Some(Stat::ReplyNomatch),
        ),
        (
            "range low",
            Box::new(|m| {
                wr16(m, 22, 39999);
                fill_checksums(m, false)
            }),
            1,
            Stat::ReplyFlowRange,
            Some(Stat::ReplyNomatch),
        ),
        (
            "range high",
            Box::new(|m| {
                wr16(m, 22, 65535);
                fill_checksums(m, false)
            }),
            1,
            Stat::ReplyFlowRange,
            Some(Stat::ReplyNomatch),
        ),
        (
            "no flow",
            Box::new(move |m| {
                wr16(m, 22, mapped + 1);
                fill_checksums(m, false)
            }),
            1,
            Stat::ReplyNoFlow,
            Some(Stat::ReplyNomatch),
        ),
        (
            "owner remote port",
            Box::new(|m| {
                wr16(m, 20, 8769);
                fill_checksums(m, false)
            }),
            1,
            Stat::ReplyOwner,
            Some(Stat::ReplyNomatch),
        ),
        (
            "owner peer",
            Box::new(|m| {
                wr32(m, 12, 0x6440_0003);
                fill_checksums(m, false)
            }),
            1,
            Stat::ReplyOwner,
            Some(Stat::ReplyNomatch),
        ),
    ];
    for (what, f, from, first, second) in cases {
        let before = snap(&r);
        let mut m = good.clone();
        f(&mut m);
        assert!(matches!(tunnel(&mut r, from, &m, 1).0, TunnelOutcome::Dropped(_)), "{what}");
        expect(&r, before, first, second);
    }
    // owner: protocol (TCP segment on a UDP flow)
    let before = snap(&r);
    let mut rng = Rng(3);
    let t = build(&mut rng, PEER, VPN1, 6, 8768, mapped, 0, false, false);
    assert!(matches!(tunnel(&mut r, 1, &t, 1).0, TunnelOutcome::Dropped(TunnelDrop::Flow(FlowInReject::Owner))));
    expect(&r, before, Stat::ReplyOwner, Some(Stat::ReplyNomatch));
    // idle
    let before = snap(&r);
    assert!(matches!(tunnel(&mut r, 1, &good, 1 + 120_000).0, TunnelOutcome::Dropped(TunnelDrop::Flow(FlowInReject::Idle))));
    expect(&r, before, Stat::ReplyIdle, Some(Stat::ReplyNomatch));
    // generation
    r.usb_detach();
    let before = snap(&r);
    assert!(matches!(tunnel(&mut r, 1, &good, 2).0, TunnelOutcome::Dropped(TunnelDrop::Flow(FlowInReject::Generation))));
    expect(&r, before, Stat::ReplyGeneration, Some(Stat::ReplyNomatch));
    // tx failure
    let before = snap(&r);
    r.tx_result(Dir::ToHost, false);
    expect(&r, before, Stat::TxFail, None);
    // every counter has a unique, non-empty name; the order and count are the C's
    assert_eq!(Stat::ALL.len(), 30);
    for (i, s) in Stat::ALL.iter().enumerate() {
        assert_eq!(*s as usize, i);
        assert!(!s.name().is_empty());
        for t in &Stat::ALL[..i] {
            assert_ne!(s.name(), t.name());
        }
    }
    assert_eq!(Stat::ALL[0].name(), "forwarded_out");
    assert_eq!(Stat::ALL[29].name(), "usb_tx_err");
}

#[test]
fn checksum_integrity_never_repaired_or_invented() {
    let mut r = R::new();
    r.publish(set(&[(1, VPN1)]));
    let a = alias_for(&mut r, 1, 0x6450_0001, 0);
    let mut rng = Rng(11);
    for i in 0..20000u32 {
        let proto = if i & 1 == 1 { 6 } else { 17 };
        let syn = proto == 6 && i % 5 == 0;
        let payload = rng.below(1300) as usize;
        let none = proto == 17 && i % 11 == 0;
        let b = build(&mut rng, HOST + i % 2, a, proto, 1024 + (i % 10) as u16, 1 + (i % 2) as u16, payload, syn, none);
        let mss = if syn { rd16(&b, 42) } else { 0 };
        let (o, sent) = host(&mut r, &b, 0);
        assert!(matches!(o, HostOutcome::Forwarded { .. }));
        assert!(packet_ok(&sent));
        if none {
            assert_eq!(rd16(&sent, 26), 0);
        }
        if syn {
            assert_eq!(rd16(&sent, 42), mss.min(1360));
        }
        if !none && i % 7 == 0 {
            let mut broken = b.clone();
            broken[(if proto == 6 { 36 } else { 26 }) + (i & 1) as usize] ^= 0x10;
            let (o, sent) = host(&mut r, &broken, 0);
            assert!(matches!(o, HostOutcome::Forwarded { .. }));
            assert!(ip_ok(&sent) && !l4_valid(&sent), "a corrupted L4 checksum stays corrupted");
        }
    }
}

#[test]
fn oversize_icmp_and_rate_limit() {
    let mut r = R::new();
    r.publish(set(&[(1, VPN1)]));
    let a = alias_for(&mut r, 1, 0x6450_0001, 0);
    let mut rng = Rng(5);
    let mut big = build(&mut rng, 0xc0a8_4d05, a, 17, 5000, 9, 1400, false, false); // 1428
    assert!(big.len() > ROUTE_MTU);
    big[6] = 0x40;
    fill_checksums(&mut big, false);
    let (o, reply) = host(&mut r, &big, 1000);
    assert_eq!(o, HostOutcome::Reply { host: 0xc0a8_4d05, len: 56 });
    assert_eq!(stat(&r, Stat::OversizeIcmp), 1);
    assert_eq!((reply[9], reply[20], reply[21]), (1, 3, 4));
    assert_eq!(rd16(&reply, 26), ROUTE_MTU as u16);
    assert_eq!((rd32(&reply, 12), rd32(&reply, 16)), (a, 0xc0a8_4d05));
    assert!(ip_ok(&reply) && finish(sum(&reply[20..], 0)) == 0);
    assert_eq!(rd16(&reply, 2) as usize, reply.len());
    assert_eq!(reply.len(), 20 + 8 + 20 + 8);
    assert_eq!(&reply[28..], &big[..28]);
    assert_eq!((reply[6], reply[8]), (0x40, 64));
    // rate limited
    for _ in 0..100 {
        assert!(matches!(host(&mut r, &big, 1001).0, HostOutcome::Dropped(HostDrop::IcmpSuppressed)));
    }
    assert_eq!(stat(&r, Stat::IcmpSuppressed), 100);
    assert!(matches!(host(&mut r, &big, 1000 + ICMP_SPACING_MS).0, HostOutcome::Reply { .. }));
    // without DF: dropped
    big[6] = 0;
    fill_checksums(&mut big, false);
    assert!(matches!(host(&mut r, &big, 9000).0, HostOutcome::Dropped(HostDrop::OversizeNoDf)));
    assert_eq!(stat(&r, Stat::OversizeDrop), 1);
    // a bad source or checksum gets no answer
    big[6] = 0x40;
    wr32(&mut big, 12, 0xc0a8_0102);
    fill_checksums(&mut big, false);
    assert!(matches!(host(&mut r, &big, 20_000).0, HostOutcome::Dropped(HostDrop::OversizeInvalid)));
    wr32(&mut big, 12, 0xc0a8_4d05);
    fill_checksums(&mut big, false);
    big[10] ^= 1;
    assert!(matches!(host(&mut r, &big, 20_000).0, HostOutcome::Dropped(HostDrop::OversizeInvalid)));
    // the largest accepted packet is still forwarded
    let ok = build(&mut rng, 0xc0a8_4d05, a, 17, 5000, 9, ROUTE_MTU - 28, false, false);
    assert_eq!(ok.len(), ROUTE_MTU);
    assert!(matches!(host(&mut r, &ok, 30_000).0, HostOutcome::Forwarded { .. }));
    // IP options: the quote is header + 8
    let mut opt = build(&mut rng, 0xc0a8_4d05, a, 17, 5000, 9, 1500, false, false);
    opt.splice(20..20, [1u8, 1, 1, 1]);
    opt[0] = 0x46;
    let n = opt.len() as u16;
    wr16(&mut opt, 2, n);
    opt[6] = 0x40;
    fill_checksums(&mut opt, false);
    let (o, rep) = host(&mut r, &opt, 40_000);
    assert!(matches!(o, HostOutcome::Reply { len, .. } if len == 28 + 24 + 8), "{o:?}");
    assert!(ip_ok(&rep) && finish(sum(&rep[20..], 0)) == 0);
}

#[test]
fn alias_miss_fill_negative_and_unknown() {
    let mut r = R::new();
    r.publish(set(&[(1, VPN1)]));
    // an address at/after the limit is dropped without a fill request
    let mut rng = Rng(9);
    let far = build(&mut rng, HOST, ALIAS_BASE + 5000, 6, 4000, 80, 10, false, false);
    let (o, _) = host(&mut r, &far, 0);
    assert_eq!(o, HostOutcome::Dropped(HostDrop::AliasUnknown));
    assert!(!r.fill_pending());
    assert_eq!((stat(&r, Stat::AliasMiss), stat(&r, Stat::AliasUnknown)), (1, 1));
    // allocated but not cached: one request, deduplicated, packet held
    r.alias_limit_raise(ALIAS_BASE + 6000);
    let p = build(&mut rng, HOST, ALIAS_BASE + 5000, 6, 4000, 80, 10, true, false);
    assert_eq!(host(&mut r, &p, 0).0, HostOutcome::Held);
    assert!(r.fill_pending());
    assert_eq!(r.held_count(), 1);
    // the record is absent: a fill that finds nothing ends the hold at once, and is negative-cached
    let mut out = [0u8; ROUTE_MTU];
    assert_eq!(r.begin_fill(20), Some(ALIAS_BASE + 5000));
    r.fill_done(ALIAS_BASE + 5000, None, 20);
    assert!(r.hold_service(20, &mut out).is_none());
    assert_eq!((r.held_count(), r.held_bytes(), stat(&r, Stat::HeldDropped)), (0, 0, 1));
    for _ in 0..50 {
        let (o, _) = host(&mut r, &p, 30);
        assert_eq!(o, HostOutcome::Dropped(HostDrop::AliasMiss));
    }
    assert!(!r.fill_pending(), "negative cache: no new request");
    let (o, _) = host(&mut r, &p, 20 + FILL_NEGATIVE_MS + 1);
    assert_eq!(o, HostOutcome::Held);
    assert!(r.fill_pending(), "... until the entry expires");
}

#[test]
fn miss_hold_release_expiry_detach_budget() {
    let mut rng = Rng(21);
    // fill 100 aliases into a 64 entry cache so the first is evicted
    let setup = || {
        let mut r = R::new();
        r.publish(set(&[(1, VPN1)]));
        for i in 0..200 {
            r.alias_insert(AliasRecord { id: 1, peer: 0x6460_0000 + i, alias: ALIAS_BASE + i });
        }
        let missing = (0..200).map(|i| ALIAS_BASE + i).find(|&a| r.aliases().len() == 64 && !cached(&r, a)).unwrap();
        (r, missing)
    };
    fn cached(r: &R, a: u32) -> bool {
        let mut c = r.aliases().clone();
        c.find(a).is_some()
    }
    let (mut r, a) = setup();
    let n = build(&mut rng, HOST, a, 6, 4000, 80, 0, true, false);
    for i in 0..4 {
        let (o, _) = host(&mut r, &n, 0);
        assert_eq!(o, if i < 2 { HostOutcome::Held } else { HostOutcome::Dropped(HostDrop::HoldFull) });
    }
    assert_eq!((r.held_count(), r.held_bytes()), (2, 2 * n.len()));
    assert_eq!(r.stats().extra(Extra::HoldFull), 2);
    let mut out = [0u8; ROUTE_MTU];
    assert!(r.hold_service(0, &mut out).is_none(), "nothing to release before the fill");
    let fa = r.begin_fill(20).unwrap();
    assert_eq!(fa, a);
    r.fill_done(fa, Some(AliasRecord { id: 1, peer: 0x6460_0000 + (a - ALIAS_BASE), alias: a }), 20);
    let mut released = 0;
    while let Some(o) = r.hold_service(20, &mut out) {
        let HostOutcome::Forwarded { member: 1, len, .. } = o else { panic!("{o:?}") };
        assert!(packet_ok(&out[..len]) && rd16(&out, 22) == 80 && rd16(&out, 20) >= MAPPED_BASE);
        released += 1;
    }
    assert_eq!((released, r.held_count(), r.held_bytes(), stat(&r, Stat::HeldReleased)), (2, 0, 0, 2));
    assert_eq!(stat(&r, Stat::AliasFill), 1);

    // expiry
    let (mut r, a) = setup();
    let n = build(&mut rng, HOST, a, 6, 4001, 80, 0, true, false);
    assert_eq!(host(&mut r, &n, 1000).0, HostOutcome::Held);
    assert!(r.hold_service(1000 + HOLD_MS - 1, &mut out).is_none());
    assert_eq!(r.held_count(), 1);
    assert!(r.hold_service(1000 + HOLD_MS, &mut out).is_none());
    assert_eq!((r.held_count(), r.held_bytes(), stat(&r, Stat::HeldDropped)), (0, 0, 1));

    // USB detach discards held packets unforwarded
    let (mut r, a) = setup();
    let n = build(&mut rng, HOST, a, 6, 4004, 80, 0, true, false);
    assert_eq!(host(&mut r, &n, 0).0, HostOutcome::Held);
    let fa = r.begin_fill(20).unwrap();
    r.fill_done(fa, Some(AliasRecord { id: 1, peer: 0x6460_0000 + (a - ALIAS_BASE), alias: a }), 20);
    r.usb_detach();
    assert!(r.hold_service(20, &mut out).is_none());
    assert_eq!((r.held_count(), stat(&r, Stat::ForwardedOut)), (0, 0));

    // byte budget: a second full-size packet does not fit
    let (mut r, a) = setup();
    let big = build(&mut rng, HOST, a, 17, 4005, 53, ROUTE_MTU - 28, false, false);
    assert_eq!(big.len(), ROUTE_MTU);
    assert_eq!(host(&mut r, &big, 0).0, HostOutcome::Held);
    assert_eq!(host(&mut r, &big, 0).0, HostOutcome::Dropped(HostDrop::HoldFull));
    assert!(r.held_bytes() <= HOLD_BYTES);
    r.hold_flush();
    assert_eq!(r.held_bytes(), 0);

    // a flood of distinct uncached aliases cannot hold more than the slots
    let mut r = R::new();
    r.publish(set(&[(1, VPN1)]));
    r.alias_limit_raise(ALIAS_BASE + 400);
    for i in 0..64u32 {
        let n = build(&mut rng, HOST, ALIAS_BASE + 64 + (i * 7) % 100, 6, 5000 + i as u16, 80, 0, true, false);
        host(&mut r, &n, 0);
        assert!(r.held_count() <= HOLD_SLOTS && r.held_bytes() <= HOLD_BYTES);
    }
    assert!((0..FILL_SLOTS).count() == 4);
}

#[test]
fn queue_budget_and_gate() {
    assert_eq!(queue_budget(0, 20_000), QUEUE_BYTES_MIN);
    assert_eq!(queue_budget(6400, 20_000), QUEUE_BYTES_MIN);
    assert_eq!(queue_budget(20_000 + 5000, 20_000), 5000);
    assert_eq!(queue_budget(1 << 20, 20_000), QUEUE_BYTES);
    assert!(QUEUE_BYTES_MIN as usize >= 2 * ROUTE_MTU);
    let mut gate = IngressGate::new();
    let mut accepted = 0;
    for _ in 0..64 {
        if gate.admit(1400, 0) {
            accepted += 1;
        }
        assert!(gate.bytes() <= QUEUE_BYTES);
    }
    assert_eq!(accepted, (QUEUE_BYTES / 1400) as usize);
    gate.release(1400);
    gate.release(1400);
    assert!(gate.admit(1400, 0) && gate.admit(1400, 0) && !gate.admit(1400, 0));
    // held bytes share the budget
    let mut gate = IngressGate::new();
    assert!(gate.admit((QUEUE_BYTES - 2000) as usize, 2000));
    let mut gate = IngressGate::new();
    assert!(!gate.admit((QUEUE_BYTES - 2000 + 1) as usize, 2000));
    // the budget shrinks with the heap
    let mut gate = IngressGate::new();
    gate.set_budget(3000);
    assert!(gate.admit(1400, 0) && gate.admit(1400, 0) && !gate.admit(1400, 0));
    // depth bound: tiny packets stop at QUEUE_DEPTH
    let mut gate = IngressGate::new();
    let n = (0..100).filter(|_| gate.admit(60, 0)).count();
    assert_eq!(n as u32, QUEUE_DEPTH);
}

#[test]
fn ingress_hook_policy() {
    let mut r = R::new();
    let mut gate = IngressGate::new();
    let mk = |dest: u32, df: bool| {
        let mut f = [0u8; 20];
        f[0] = 0x45;
        f[6] = if df { 0x40 } else { 0 };
        wr32(&mut f, 16, dest);
        f
    };
    let alias = mk(ALIAS_BASE, true);
    let facts = |first: &[u8], len: usize, usb: bool| IngressFacts {
        first: Box::leak(first.to_vec().into_boxed_slice()),
        len,
        from_usb: usb,
        to_input_addr: false,
        dport: None,
    };
    assert_eq!(r.ingress(&mut gate, &facts(&alias, 100, true)), Ingress::Queue);
    // oversize: DF queues (for ICMP), no DF drops at ingress
    assert_eq!(r.ingress(&mut gate, &facts(&alias, 1401, true)), Ingress::Queue);
    let nodf = mk(ALIAS_BASE, false);
    assert_eq!(r.ingress(&mut gate, &facts(&nodf, 1401, true)), Ingress::Drop(IngressDrop::OversizeNoDf));
    assert_eq!(stat(&r, Stat::OversizeDrop), 1);
    // alias from another interface: consumed
    assert_eq!(r.ingress(&mut gate, &facts(&alias, 100, false)), Ingress::Drop(IngressDrop::ForeignAlias));
    // ordinary Internet stays on the IP stack
    let net = mk(0xc0a8_0101, false);
    assert_eq!(r.ingress(&mut gate, &facts(&net, 100, true)), Ingress::PassThrough);
    assert_eq!(r.ingress(&mut gate, &facts(&net[..10], 10, true)), Ingress::PassThrough);
    // management: 192.168.77.1 from a non-USB interface, and own-address port 80/53
    let mgmt = mk(0xc0a8_4d01, false);
    assert_eq!(r.ingress(&mut gate, &facts(&mgmt, 100, false)), Ingress::Drop(IngressDrop::Management));
    assert_eq!(r.ingress(&mut gate, &facts(&mgmt, 100, true)), Ingress::PassThrough);
    let own = mk(0xc0a8_0105, false);
    let mut f = facts(&own, 100, false);
    f.to_input_addr = true;
    f.dport = Some(53);
    assert_eq!(r.ingress(&mut gate, &f), Ingress::Drop(IngressDrop::Management));
    f.dport = Some(443);
    assert_eq!(r.ingress(&mut gate, &f), Ingress::PassThrough);
    // queue full is counted
    let mut gate = IngressGate::new();
    for _ in 0..QUEUE_DEPTH {
        assert_eq!(r.ingress(&mut gate, &facts(&alias, 60, true)), Ingress::Queue);
    }
    assert_eq!(r.ingress(&mut gate, &facts(&alias, 60, true)), Ingress::Drop(IngressDrop::QueueFull));
    assert_eq!(stat(&r, Stat::QueueFull), 1);
}

#[test]
fn tunnel_batch_equals_one_by_one_and_keeps_order() {
    let mut rng = Rng(77);
    let mk = || {
        let mut r = R::new();
        r.publish(set(&[(1, VPN1)]));
        r
    };
    let (mut ra, mut rb) = (mk(), mk());
    let mut replies = Vec::new();
    for i in 0..40u32 {
        let alias = alias_for(&mut ra, 1, PEER + i, i);
        alias_for(&mut rb, 1, PEER + i, i);
        let p = build(&mut rng, HOST, alias, 17, 2000 + i as u16, 53, 10, false, false);
        let (oa, sa) = host(&mut ra, &p, 0);
        let (ob, _) = host(&mut rb, &p, 0);
        assert_eq!(oa, ob);
        let mapped = rd16(&sa, 20);
        let mut rep = build(&mut rng, PEER + i, VPN1, 17, 53, mapped, 5 + i as usize, false, false);
        if i % 7 == 3 {
            rep[10] ^= 1; // bad
        }
        replies.push(rep);
    }
    let single: Vec<_> = replies.iter().map(|p| tunnel(&mut ra, 1, p, 5)).collect();
    let mut bufs = replies.clone();
    let mut outs = vec![TunnelOutcome::Dropped(TunnelDrop::Malformed); bufs.len()];
    let mut done = 0;
    for chunk in bufs.chunks_mut(TUNNEL_BATCH_MAX) {
        let len = chunk.len();
        let mut refs: Vec<&mut [u8]> = chunk.iter_mut().map(|v| v.as_mut_slice()).collect();
        let k = rb.tunnel_batch(1, &mut refs, 5, &mut outs[done..done + len]);
        assert_eq!(k, len);
        done += k;
    }
    for (i, (o, bytes)) in single.iter().enumerate() {
        assert_eq!(*o, outs[i]);
        if let TunnelOutcome::ToHost { len, .. } = o {
            assert_eq!(&bufs[i][..*len], &bytes[..]);
        }
    }
    assert_eq!(ra.stats(), rb.stats());
}

#[test]
fn alias_cache_semantics() {
    let mut t = AliasCache::<64>::new();
    for i in 0..64u32 {
        assert!(t.insert(AliasRecord { id: 1 + i / 8, peer: 0x6440_0000 + i, alias: ALIAS_BASE + i }));
    }
    for i in 0..64u32 {
        let r = t.find(ALIAS_BASE + i).unwrap();
        assert_eq!((r.id, r.peer), (1 + i / 8, 0x6440_0000 + i));
        assert_eq!(t.find_key(1 + i / 8, 0x6440_0000 + i), Some(ALIAS_BASE + i));
    }
    // idempotent; conflicts rejected; zero rejected
    assert!(t.insert(AliasRecord { id: 1, peer: 0x6440_0000, alias: ALIAS_BASE }));
    assert!(!t.insert(AliasRecord { id: 2, peer: 0x6440_0000, alias: ALIAS_BASE }));
    assert!(!t.insert(AliasRecord { id: 1, peer: 0x6440_0000, alias: ALIAS_BASE + 100 }));
    assert!(!t.insert(AliasRecord { id: 0, peer: 1, alias: ALIAS_BASE + 100 }));
    assert!(!t.insert(AliasRecord { id: 1, peer: 1, alias: 0 }));
    // beyond capacity: a hit is always exact; the hot alias survives CLOCK
    let hot = ALIAS_BASE + 5;
    let mut kept = 0;
    for i in 0..2000u32 {
        t.find(hot);
        t.insert(AliasRecord { id: 100 + i, peer: 0x6450_0000 + i, alias: ALIAS_BASE + 64 + i });
        if t.find(hot).is_some() {
            kept += 1;
        }
        assert_eq!(t.len(), 64);
        let a = ALIAS_BASE + 64 + i;
        let r = t.find(a).unwrap();
        assert_eq!((r.id, r.peer), (100 + i, 0x6450_0000 + i));
    }
    assert!(kept > 1000);
    let n = t.forget(100 + 1999);
    assert_eq!(n, 1);
    assert_eq!(t.len(), 63);
}

#[test]
fn flow_table_semantics() {
    let key = Flow { id: 7, peer: 0x6440_0009, alias: 0xc612_0007, host: HOST, local: 5555, remote: 443, mapped: 0, proto: 6 };
    let mut t = FlowTable::<64>::new();
    let f = t.create(&key, 1, 1000).unwrap();
    assert!((MAPPED_BASE..MAPPED_BASE + 64).contains(&f.mapped));
    let ok = t.lookup_in(7, 0x6440_0009, 443, f.mapped, 6, 1, 2000).unwrap();
    assert_eq!((ok.host, ok.local, ok.alias), (HOST, 5555, 0xc612_0007));
    use FlowInReject::*;
    assert_eq!(t.lookup_in(8, 0x6440_0009, 443, f.mapped, 6, 1, 2000), Err(Owner));
    assert_eq!(t.lookup_in(7, 0x6440_000a, 443, f.mapped, 6, 1, 2000), Err(Owner));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 444, f.mapped, 6, 1, 2000), Err(Owner));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, f.mapped, 17, 1, 2000), Err(Owner));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, f.mapped + 64, 6, 1, 2000), Err(Owner));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, f.mapped, 6, 2, 2000), Err(Generation));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, 39999, 6, 1, 2000), Err(Range));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, 65535, 6, 1, 2000), Err(Range));
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, f.mapped, 6, 1, 2000 + FLOW_IDLE_MS), Err(Idle));
    assert!(t.lookup_in(7, 0x6440_0009, 443, f.mapped, 6, 1, 3000).is_ok());
    let other = Flow { id: 8, local: 6666, ..key };
    let g = t.create(&other, 1, 3000).unwrap();
    assert_ne!(g.mapped, f.mapped);
    assert_eq!(t.forget(7), 1);
    assert_eq!(t.lookup_in(7, 0x6440_0009, 443, f.mapped, 6, 1, 3000), Err(NoFlow));
    assert!(t.lookup_out(0xc612_0007, HOST, 5555, 443, 6, 1).is_none());
    assert!(t.lookup_in(8, other.peer, 443, g.mapped, 6, 1, 3000).is_ok());
    // exhaustion and reclaim of idle flows
    let mut t = FlowTable::<64>::new();
    for i in 0..64 {
        assert!(t.create(&Flow { id: 1, peer: 2, alias: 3, host: HOST, local: 1000 + i, remote: 80, mapped: 0, proto: 6 }, 1, 1000).is_some());
    }
    let k = Flow { id: 1, peer: 2, alias: 3, host: HOST, local: 2000, remote: 80, mapped: 0, proto: 6 };
    assert!(t.create(&k, 1, 1000).is_none());
    assert!(t.create(&k, 1, 1000 + FLOW_IDLE_MS).is_none(), "exactly idle for 120 s is still live (<=)");
    assert!(t.create(&k, 1, 1000 + FLOW_IDLE_MS + 1).is_some());
    // mapped ports stay inside the range for every generation
    for generation in 1..2000u32 {
        let mut t = FlowTable::<64>::new();
        let f = t.create(&Flow { id: 1, peer: 2, alias: 3, host: 4, local: 5, remote: 6, mapped: 0, proto: 6 }, generation, 1).unwrap();
        assert!(f.mapped >= MAPPED_BASE && f.mapped < 60_000);
    }
    assert_eq!(FlowTable::<64>::GENERATIONS, 300);
    // a larger table still fits the port range
    assert!(MAPPED_BASE as u32 + 128 * FlowTable::<128>::GENERATIONS <= 65_536);
}

#[test]
fn state_sizes_are_reported() {
    // printed for the ADR; run with --nocapture
    println!("GatewayRouter  = {} B", GatewayRouter::STATE_BYTES);
    println!("AliasCache<64> = {} B", core::mem::size_of::<AliasCache<64>>());
    println!("FlowTable<64>  = {} B", core::mem::size_of::<FlowTable<64>>());
    println!("MemberSet<16>  = {} B", core::mem::size_of::<MemberSet<16>>());
    println!("Pool<16,1536>  = {} B", pool::Pool::<16, 1536>::BYTES);
    assert!(GatewayRouter::STATE_BYTES < 8 * 1024);
}

#[test]
fn pool_bounded_class_and_owner_caps() {
    use pool::*;
    let mut p = Pool::<8, 64, 4>::new(2, 4);
    let mut held = Vec::new();
    // owner cap 4 for data
    for _ in 0..4 {
        held.push(p.alloc(Class::Data, 1).unwrap());
    }
    assert_eq!(p.alloc(Class::Data, 1).unwrap_err(), PoolDrop::OwnerCap);
    // another owner takes data up to N - reserve
    held.push(p.alloc(Class::Data, 2).unwrap());
    held.push(p.alloc(Class::Data, 2).unwrap());
    assert_eq!(p.alloc(Class::Data, 2).unwrap_err(), PoolDrop::Reserved);
    // control may use the reserve
    held.push(p.alloc(Class::Ctrl, 3).unwrap());
    held.push(p.alloc(Class::Ctrl, 3).unwrap());
    assert_eq!(p.alloc(Class::Ctrl, 3).unwrap_err(), PoolDrop::Empty);
    assert_eq!(p.in_use(), 8);
    assert_eq!((p.stats().owner_cap, p.stats().reserved, p.stats().empty, p.stats().high_water), (1, 1, 1, 8));
    // slabs are distinct memory
    for (i, s) in held.iter().enumerate() {
        p.bytes(s)[0] = i as u8;
    }
    for (i, s) in held.iter().enumerate() {
        assert_eq!(p.bytes(s)[0], i as u8);
    }
    for s in held {
        p.free(s);
    }
    assert_eq!(p.in_use(), 0);
    assert!(p.alloc(Class::Data, 1).is_ok());
}
