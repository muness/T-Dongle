//! Property, differential and mini-fuzz tests of the NAT: the fast incremental checksum against a full recompute by an independent oracle,
//! round trips, table invariants under random operation sequences, and arbitrary bytes.
mod common;
use common::*;
use proptest::prelude::*;
use tdongle_tailnet_usbnet::csum::{adjust, adjust32};
use tdongle_tailnet_usbnet::napt::*;

fn same_checksum(a: u16, b: u16) -> bool {
    a == b || (a == 0 && b == 0xffff) || (a == 0xffff && b == 0)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// RFC 1624: patching one word equals recomputing the whole checksum (the two zeros of one's complement are the same value).
    #[test]
    fn adjust_equals_full_recompute(data in proptest::collection::vec(any::<u8>(), 2..80), at in any::<prop::sample::Index>(), new in any::<u16>()) {
        let mut data = data;
        if data.len() % 2 == 1 { data.push(0); }
        let before = oracle_sum(&data);
        let i = at.index(data.len() / 2) * 2;
        let old = u16::from_be_bytes([data[i], data[i + 1]]);
        data[i..i + 2].copy_from_slice(&new.to_be_bytes());
        let after = oracle_sum(&data);
        prop_assert!(same_checksum(adjust(before, old, new), after), "{:04x} {:04x} {:04x}", before, adjust(before, old, new), after);
    }

    #[test]
    fn adjust32_equals_full_recompute(mut data in proptest::collection::vec(any::<u8>(), 4..80), at in any::<prop::sample::Index>(), new in any::<u32>()) {
        while data.len() % 4 != 0 { data.push(0); }
        let before = oracle_sum(&data);
        let i = at.index(data.len() / 4) * 4;
        let old = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        data[i..i + 4].copy_from_slice(&new.to_be_bytes());
        prop_assert!(same_checksum(adjust32(before, old, new), oracle_sum(&data)));
    }

    /// Whatever the packet, a forwarded packet leaves with valid checksums, and the reply comes back to the host restored.
    #[test]
    fn tcp_udp_icmp_round_trip(
        proto in 0u8..3,
        host_port in 1024u16..65535,
        rport in 1u16..65535,
        ttl in 3u8..255,
        payload in proptest::collection::vec(any::<u8>(), 0..300),
        opts in 0usize..4,
        flags in prop::sample::select(vec![SYN, SYN | ACK, ACK, FIN | ACK]),
        host_last in 2u8..254,
        remote in 0x0100_0000u32..0xdfff_ffff,
    ) {
        let host = 0xC0A8_4D00 | u32::from(host_last);
        prop_assume!(remote != WIFI && remote >> 16 != 0xa9fe && remote >> 24 != 127 && remote >> 24 != 0 && (remote & 0xffff_ff00) != 0x0A00_0000);
        let mut n = new_napt::<64>();
        let ip = Ip::new(host, remote).ttl(ttl).opts(&vec![1u8; opts * 4]);
        let (p, flags_used) = match proto {
            0 => (packet(&ip, 6, &tcp_seg(host_port, rport, 1, 2, SYN, &payload)), SYN),
            1 => (packet(&ip, 17, &udp_dgram(host_port, rport, &payload)), 0),
            _ => (packet(&ip, 1, &icmp_msg(8, 0, host_port, 3, &payload)), 0),
        };
        let _ = flags_used;
        let orig = p.clone();
        let mut out = p;
        let Verdict::Forward { len, mapped, .. } = n.outbound(5, &mut out) else { return Err(TestCaseError::fail("not forwarded")) };
        prop_assert_eq!(usize::from(len), orig.len());
        assert_valid(&out);
        prop_assert_eq!(src(&out), WIFI);
        prop_assert_eq!(dst(&out), remote);
        prop_assert_eq!(out[8], ttl - 1);
        // the reply
        let rip = Ip::new(remote, WIFI).ttl(ttl).opts(&vec![1u8; opts * 4]);
        let mut reply = match proto {
            0 => packet(&rip, 6, &tcp_seg(rport, mapped, 9, 2, flags, &payload)),
            1 => packet(&rip, 17, &udp_dgram(rport, mapped, &payload)),
            _ => packet(&rip, 1, &icmp_msg(0, 0, mapped, 3, &payload)),
        };
        let v = n.inbound(6, &mut reply);
        prop_assert!(matches!(v, Verdict::Forward { .. }), "{:?}", v);
        assert_valid(&reply);
        prop_assert_eq!(dst(&reply), host);
        prop_assert_eq!(src(&reply), remote);
        if proto < 2 { prop_assert_eq!(dport(&reply), host_port); } else {
            let ihl = usize::from(reply[0] & 15) * 4;
            prop_assert_eq!(u16::from_be_bytes([reply[ihl + 4], reply[ihl + 5]]), host_port);
        }
        n.check_invariants().map_err(TestCaseError::fail)?;
    }
}

#[derive(Debug, Clone)]
enum Op {
    Out { proto: u8, host: u8, port: u16, remote: u8, rport: u16, flags: u8 },
    In { proto: u8, remote: u8, rport: u16, mport_pick: u16, flags: u8 },
    Tick(u32),
    Wifi,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0u8..3, 0u8..3, prop::sample::select(vec![1024u16, 50000, 50001, 50002, 60000, 61439, 61440, 40000]), 0u8..4, 0u16..4,
              prop::sample::select(vec![SYN, ACK, SYN | ACK, FIN | ACK, RST, ACK | RST]))
            .prop_map(|(proto, host, port, remote, rport, flags)| Op::Out { proto, host, port, remote, rport, flags }),
        5 => (0u8..3, 0u8..4, 0u16..4, any::<u16>(), prop::sample::select(vec![SYN | ACK, ACK, FIN | ACK, RST | ACK]))
            .prop_map(|(proto, remote, rport, mport_pick, flags)| Op::In { proto, remote, rport, mport_pick, flags }),
        2 => (0u32..40_000).prop_map(Op::Tick),
        1 => Just(Op::Wifi),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// A small table under a random mix of packets and time: invariants hold after every step, every forwarded packet carries valid
    /// checksums, a flow keeps its mapped port while it exists, and the counters account for every packet.
    #[test]
    fn random_operation_sequences_keep_the_table_sound(ops in proptest::collection::vec(op_strategy(), 1..120)) {
        let mut n = new_napt::<8>();
        let mut now = 0u64;
        let mut packets = 0u32;
        let remotes = [REMOTE, REMOTE2, 0x0101_0101, 0x0909_0909];
        for op in ops {
            let before: Vec<_> = n.flows().collect();
            match op {
                Op::Out { proto, host, port, remote, rport, flags } => {
                    let h = HOST + u32::from(host);
                    let r = remotes[usize::from(remote)];
                    let rp = 80 + rport;
                    let mut p = match proto {
                        0 => tcp_pkt(h, port, r, rp, 100, 0, flags, b"data"),
                        1 => udp_pkt(h, port, r, rp, b"data"),
                        _ => echo_pkt(h, r, 8, port, 1),
                    };
                    packets += 1;
                    if let Verdict::Forward { len, mapped, .. } = n.outbound(now, &mut p) {
                        assert_valid(&p[..usize::from(len)]);
                        let key = (match proto { 0 => Proto::Tcp, 1 => Proto::Udp, _ => Proto::Icmp }, h, port, r, if proto == 2 { 0 } else { rp });
                        if let Some(old) = before.iter().find(|f| (f.0, f.1, f.2, f.3, f.4) == key) {
                            prop_assert_eq!(old.5, mapped, "a live flow keeps its mapped port");
                        }
                    }
                }
                Op::In { proto, remote, rport, mport_pick, flags } => {
                    let r = remotes[usize::from(remote)];
                    let rp = 80 + rport;
                    // aim at a real mapped port half of the time
                    let m = if mport_pick % 2 == 0 && !before.is_empty() { before[usize::from(mport_pick / 2) % before.len()].5 } else { 49152 + mport_pick % 12288 };
                    let mut p = match proto {
                        0 => tcp_pkt(r, rp, WIFI, m, 100, 0, flags, b"reply"),
                        1 => udp_pkt(r, rp, WIFI, m, b"reply"),
                        _ => echo_pkt(r, WIFI, 0, m, 1),
                    };
                    packets += 1;
                    if let Verdict::Forward { len, .. } = n.inbound(now, &mut p) {
                        assert_valid(&p[..usize::from(len)]);
                        prop_assert!(dst(&p) & 0xffff_ff00 == 0xC0A8_4D00);
                    }
                }
                Op::Tick(ms) => {
                    now += u64::from(ms);
                    let _ = n.expire(now);
                }
                Op::Wifi => {
                    n.set_wifi(Some(WifiAddr { ip: WIFI, mask: 0xffff_ff00 }));
                }
            }
            n.check_invariants().map_err(TestCaseError::fail)?;
            prop_assert!(n.active() <= 8);
            while n.pop_rst().is_some() {}
        }
        let s = n.stats();
        let acc = |d: &DirStats| d.forwarded_total() + d.refused_total();
        prop_assert_eq!(s.outbound.packets.get() + s.inbound.packets.get(), packets);
        prop_assert_eq!(s.outbound.packets.get() + s.inbound.packets.get(), acc(&s.outbound) + acc(&s.inbound));
    }

    /// Arbitrary bytes, in either direction: never a panic, never a broken table, and a refused packet is untouched.
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..200)) {
        let mut n = new_napt::<8>();
        let mut a = data.clone();
        let v = n.outbound(1, &mut a);
        if !matches!(v, Verdict::Forward { .. }) { prop_assert_eq!(&a, &data); }
        let mut b = data.clone();
        let v = n.inbound(1, &mut b);
        if !matches!(v, Verdict::Forward { .. }) { prop_assert_eq!(&b, &data); }
        n.check_invariants().map_err(TestCaseError::fail)?;
    }
}

/// Deterministic mutation fuzz (also run by `cargo test`): valid packets with random bytes flipped, to reach deep into the parsers.
#[test]
fn mutated_packets_never_panic_and_never_break_the_table() {
    use tdongle_tailnet_types::Entropy;
    use tdongle_tailnet_types::test_util::TestRng;
    let mut rng = TestRng(0xfeed_f00d_dead_beef);
    let mut next = move || {
        let mut b = [0u8; 4];
        rng.fill(&mut b);
        u32::from_le_bytes(b)
    };
    let mut n = new_napt::<16>();
    let seeds = [
        tcp_pkt(HOST, 50000, REMOTE, 443, 1, 0, SYN, b"x"),
        tcp_pkt(REMOTE, 443, WIFI, 50000, 1, 2, SYN | ACK, b""),
        udp_pkt(HOST, 50001, REMOTE, 53, b"query"),
        udp_pkt(REMOTE, 53, WIFI, 50001, b"answer"),
        echo_pkt(HOST, REMOTE, 8, 7, 1),
        echo_pkt(REMOTE, WIFI, 0, 7, 1),
        packet(&Ip::new(HOST, REMOTE).opts(&[1, 1, 1, 0]), 6, &tcp_seg(50002, 80, 1, 0, SYN, b"")),
    ];
    let mut now = 0u64;
    let mut forwarded = 0;
    for round in 0..60_000u32 {
        let mut p = seeds[(next() as usize) % seeds.len()].clone();
        for _ in 0..(next() % 4) {
            let i = (next() as usize) % p.len();
            match next() % 3 {
                0 => p[i] = next() as u8,
                1 => p[i] ^= 1 << (next() % 8),
                _ => {
                    let cut = (next() as usize) % (p.len() + 1);
                    p.truncate(cut.max(1));
                    break;
                }
            }
        }
        // half of the time repair the IP header checksum so the L4 parsers are reached
        if p.len() >= 20 && next() % 2 == 0 && p[0] >> 4 == 4 {
            let ihl = usize::from(p[0] & 15) * 4;
            if ihl >= 20 && ihl <= p.len() {
                let c = ip_header_checksum(&p[..ihl]);
                p[10..12].copy_from_slice(&c.to_be_bytes());
            }
        }
        now += u64::from(next() % 700);
        let before = p.clone();
        let v = if next() % 2 == 0 { n.outbound(now, &mut p) } else { n.inbound(now, &mut p) };
        match v {
            Verdict::Forward { len, .. } => {
                forwarded += 1;
                assert!(usize::from(len) <= p.len());
                // header checksum must hold after any rewrite
                let ihl = usize::from(p[0] & 15) * 4;
                assert_eq!(u16::from_be_bytes([p[10], p[11]]), ip_header_checksum(&p[..ihl]));
            }
            _ => assert_eq!(p, before, "refused packets are untouched (round {round})"),
        }
        if round % 5 == 0 {
            let _ = n.expire(now);
            while n.pop_rst().is_some() {}
        }
        if round % 1000 == 0 {
            n.check_invariants().unwrap();
        }
    }
    n.check_invariants().unwrap();
    assert!(forwarded > 100, "the fuzzer reached the rewrite paths ({forwarded})");
}
