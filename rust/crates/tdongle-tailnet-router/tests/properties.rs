//! Property tests and a deterministic mini-fuzz of the packet parsers and both routing directions: no input panics, every emitted packet is
//! well formed, rewrites keep both checksums as valid as they were, and the hold/queue invariants hold under any sequence.
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
use proptest::prelude::*;
use tdongle_tailnet_router::tables::AliasRecord;
use tdongle_tailnet_router::*;

fn router() -> GatewayRouter {
    let mut r = GatewayRouter::new();
    let mut s = MemberSet::<16>::new();
    s.insert(Member { id: 1, vpn_ip: 0x6440_0001, ready: true });
    s.insert(Member { id: 2, vpn_ip: 0x6440_0002, ready: true });
    r.publish(s);
    for i in 0..20u32 {
        r.alias_insert(AliasRecord { id: 1 + i % 2, peer: 0x6450_0000 + i, alias: ALIAS_BASE + i });
    }
    r
}

/// Run one input through both directions and check the invariants of whatever comes out.
fn exercise(r: &mut GatewayRouter, data: &[u8], now: u64) {
    let mut a = data.to_vec();
    let g = r.usb_generation();
    match r.host_packet(&mut a, now, g) {
        HostOutcome::Forwarded { len, member, peer } => {
            assert!(len == data.len() && len <= ROUTE_MTU && (member == 1 || member == 2));
            assert!(ip_ok(&a[..len]) && rd16(&a, 2) as usize == len);
            assert_eq!(rd32(&a, 16), peer);
            assert!(a[8] >= 1 && a[8] < data[8]);
            let h = (a[0] & 15) as usize * 4;
            assert!(rd16(&a, h) >= MAPPED_BASE && (a[9] == 6 || a[9] == 17));
        }
        HostOutcome::Reply { len, host } => {
            assert!(len >= 56 && len <= 96 && ip_ok(&a[..len]) && finish(sum(&a[20..len], 0)) == 0);
            assert_eq!(rd32(&a, 16), host);
            assert!(data.len() > ROUTE_MTU);
        }
        HostOutcome::Held => assert!(r.held_bytes() <= HOLD_BYTES && r.held_count() <= HOLD_SLOTS),
        HostOutcome::PassThrough | HostOutcome::Dropped(_) => {}
    }
    let mut b = data.to_vec();
    if let TunnelOutcome::ToHost { len, host } = r.tunnel_packet(1, &mut b, now) {
        assert!(len >= 20 && len <= data.len());
        assert!(ip_ok(&b[..len]) && rd16(&b, 2) as usize == len);
        assert_eq!(rd32(&b, 16), host);
    }
    let mut out = [0u8; ROUTE_MTU];
    while let Some(o) = r.hold_service(now, &mut out) {
        if let HostOutcome::Forwarded { len, .. } = o {
            assert!(ip_ok(&out[..len]));
        }
    }
    while let Some(al) = r.begin_fill(now) {
        r.fill_done(al, None, now);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1600), now in 0u64..10_000_000) {
        let mut r = router();
        exercise(&mut r, &data, now);
    }

    /// Bit-flipped valid packets exercise the deep paths past validation.
    #[test]
    fn mutated_valid_packets(seed in any::<u64>(), flips in proptest::collection::vec((0usize..1500, 0u8..8), 0..4), udp in any::<bool>(), syn in any::<bool>(), payload in 0usize..1340) {
        let mut rng = Rng(seed | 1);
        let alias = ALIAS_BASE + rng.below(24);
        let sport = 1000 + rng.below(50) as u16;
        let mut b = build(&mut rng, 0xc0a8_4d02, alias, if udp { 17 } else { 6 }, sport, 80, payload, syn && !udp, false);
        for (i, bit) in flips {
            if i < b.len() { b[i] ^= 1 << bit; }
        }
        let mut r = router();
        exercise(&mut r, &b, 5);
    }

    /// A valid packet always forwards and the result is valid: both checksums stay valid across the NAT, TTL and MSS rewrites.
    #[test]
    fn rewrite_preserves_checksums(seed in any::<u64>(), udp in any::<bool>(), syn in any::<bool>(), none in any::<bool>(), payload in 0usize..1340) {
        let mut rng = Rng(seed | 1);
        let alias = ALIAS_BASE + rng.below(20);
        let proto = if udp { 17 } else { 6 };
        let (src, sp, dp) = (0xc0a8_4d02 + rng.below(100), 1 + rng.next() as u16 % 60000, 1 + rng.next() as u16 % 60000);
        let b = build(&mut rng, src, alias, proto, sp, dp, payload, syn && !udp, none && udp);
        let mut r = router();
        let mut p = b.clone();
        let g = r.usb_generation();
        let HostOutcome::Forwarded { len, .. } = r.host_packet(&mut p, 5, g) else { panic!("valid packet must forward") };
        prop_assert!(packet_ok(&p[..len]));
        if none && udp { prop_assert_eq!(rd16(&p, 26), 0); }
        // and the reply path returns exactly what was sent, with the original ports
        let mapped = rd16(&p, 20);
        let (peer, vpn) = (rd32(&p, 16), rd32(&p, 12));
        let rport = rd16(&p, 22);
        let mut rep = build(&mut rng, peer, vpn, proto, rport, mapped, payload % 200, syn && !udp, none && udp);
        let id = if vpn == 0x6440_0001 { 1 } else { 2 };
        let TunnelOutcome::ToHost { len, host } = r.tunnel_packet(id, &mut rep, 6) else { panic!("reply must forward") };
        prop_assert!(packet_ok(&rep[..len]));
        prop_assert_eq!(host, rd32(&b, 12));
        prop_assert_eq!(rd32(&rep, 12), alias);
        prop_assert_eq!(rd16(&rep, 22), rd16(&b, 20));
    }

    /// RFC 1624: any sequence of incremental replacements equals recomputation.
    #[test]
    fn incremental_checksum_equals_recompute(words in proptest::collection::vec(any::<u16>(), 2..64), idx in any::<usize>(), new in any::<u16>()) {
        let mut buf: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let n = buf.len();
        buf[0] = 0; buf[1] = 0;
        let c = finish(sum(&buf, 0));
        wr16(&mut buf, 0, c);
        prop_assert_eq!(finish(sum(&buf, 0)), 0);
        let i = 2 + (idx % ((n - 2) / 2)) * 2;
        let old = rd16(&buf, i);
        wr16(&mut buf, i, new);
        let mut c = [buf[0], buf[1]];
        let adj = tdongle_tailnet_router::csum::adjust(u16::from_be_bytes(c), old, new);
        c = adj.to_be_bytes();
        buf[0] = c[0]; buf[1] = c[1];
        // equal as one's complement numbers (0x0000 and 0xffff are the same value)
        let s = finish(sum(&buf, 0));
        prop_assert!(s == 0 || s == 0xffff);
    }

    /// Any interleaving of packets, fills, hold service, detach and clock jumps keeps the bounds.
    #[test]
    fn hold_and_queue_bounds(ops in proptest::collection::vec((0u8..6, any::<u32>(), 0u64..300), 1..200)) {
        let mut r = GatewayRouter::new();
        let mut s = MemberSet::<16>::new();
        s.insert(Member { id: 1, vpn_ip: 0x6440_0001, ready: true });
        r.publish(s);
        r.alias_limit_raise(ALIAS_BASE + 500);
        let mut now = 0u64;
        let mut rng = Rng(1);
        let mut gate = IngressGate::new();
        let mut out = [0u8; ROUTE_MTU];
        for (op, x, dt) in ops {
            now += dt;
            match op {
                0 | 1 | 2 => {
                    let alias = ALIAS_BASE + (x % 500);
                    let payload = (x >> 9) as usize % 1372;
                    let b = build(&mut rng, 0xc0a8_4d02, alias, 17, 1000 + (x >> 20) as u16 % 8, 80, payload, false, false);
                    let mut p = b.clone();
                    let g = r.usb_generation();
                    let _ = r.host_packet(&mut p, now, g);
                    if gate.admit(b.len(), r.held_bytes()) { gate.release(b.len()); }
                }
                3 => { if let Some(a) = r.begin_fill(now) { let rec = (x % 3 != 0).then_some(AliasRecord { id: 1, peer: 0x6450_0000 + (a - ALIAS_BASE), alias: a }); r.fill_done(a, rec, now); } }
                4 => { while r.hold_service(now, &mut out).is_some() {} }
                _ => { if x % 4 == 0 { r.usb_detach(); } }
            }
            prop_assert!(r.held_count() <= HOLD_SLOTS && r.held_bytes() <= HOLD_BYTES);
            prop_assert!(r.flows().len() <= 64 && r.aliases().len() <= 64);
            prop_assert!(gate.packets() <= QUEUE_DEPTH && gate.bytes() <= QUEUE_BYTES);
        }
    }
}

/// Deterministic mini-fuzz that runs in plain `cargo test`: random and mutated inputs against a router that already has live flows.
#[test]
fn mini_fuzz() {
    let mut rng = Rng(0xdead_beef_1234_5678);
    let mut r = router();
    let mut sent = 0u32;
    for i in 0..60_000u32 {
        let len = if rng.below(4) == 0 { rng.below(1600) } else { 20 + rng.below(120) } as usize;
        let mut data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        match rng.below(4) {
            0 if len >= 20 => {
                // structured header with random body
                data[0] = 0x45;
                wr16(&mut data, 2, len as u16);
                data[9] = if rng.below(2) == 0 { 6 } else { 17 };
                wr32(&mut data, 12, 0xc0a8_4d02);
                wr32(&mut data, 16, ALIAS_BASE + rng.below(24));
                data[6] &= 0x40;
                if rng.below(2) == 0 {
                    wr16(&mut data, 10, 0);
                    let c = finish(sum(&data[..20], 0));
                    wr16(&mut data, 10, c);
                }
            }
            1 => {
                let (al, sp, pl, sy) = (ALIAS_BASE + rng.below(24), 1000 + rng.below(20) as u16, rng.below(100) as usize, rng.below(2) == 0);
                let seed_pkt = build(&mut rng, 0xc0a8_4d02, al, 6, sp, 80, pl, sy, false);
                data = seed_pkt;
                for _ in 0..rng.below(4) {
                    let k = rng.below(data.len() as u32) as usize;
                    data[k] ^= 1 << rng.below(8);
                }
            }
            _ => {}
        }
        exercise(&mut r, &data, u64::from(i) * 7);
        sent += 1;
    }
    assert_eq!(sent, 60_000);
    assert!(r.stats().get(Stat::BadPacket) > 0);
}
