//! ECN marking and classification: port of test_ecn_ipv4, test_ecn_ipv6, test_exempt_and_foreign and test_ipv6_extension_headers from
//! `components/tdongle_runtime/tests/test_aqm.c`, plus direct tests of `tcp_ecn_syn` / `ip6_l4`. Checksums are recomputed from the bytes,
//! never from the incremental formula.

#![allow(clippy::needless_range_loop)] // index loops mirror the C tests and compare two buffers

mod common;

use common::*;
use tdongle_aqm::{EcnClass, TcpEcnSyn, classify, ip6_l4, mark_ce, tcp_ecn_syn};

fn class_of_ecn(ecn: u32) -> EcnClass {
    ecn_to_class(ecn as u8)
}

#[test]
fn ipv4_marking_keeps_checksums_valid() {
    let mut r = Rng::new();
    let (mut f, mut g) = ([0u8; 1600], [0u8; 1600]);
    let mut marked = 0;
    for _ in 0..200_000 {
        let proto = if r.rnd(3) == 0 {
            17
        } else if r.rnd(2) != 0 {
            6
        } else {
            1
        };
        let ihl_words = 5 + if r.rnd(4) == 0 { r.rnd(11) } else { 0 };
        let payload = 20 + r.rnd(400);
        let tos = r.rnd(256);
        let frag = if r.rnd(8) == 0 { 0x4000 } else { 0 };
        let len = build4(&mut r, &mut f, tos, proto, ihl_words, payload, frag);
        g[..len].copy_from_slice(&f[..len]);
        assert!(ip4_header_ok(&f));
        let cls = classify(&f[..len]);
        let ihl = (ihl_words * 4) as usize;
        if proto == 17 && u16::from_be_bytes([f[14 + ihl], f[14 + ihl + 1]]) == 67 {
            continue;
        }
        assert_eq!(cls, class_of_ecn(tos & 3));
        if cls != EcnClass::Capable {
            continue;
        }
        let l4_before = if proto == 6 || proto == 17 {
            l4_checksum(&f[..len], false)
        } else {
            0
        };
        mark_ce(&mut f[..len]);
        marked += 1;
        assert!(f[15] & 3 == 3 && f[15] & 0xfc == g[15] & 0xfc); // CE, DSCP untouched
        assert!(ip4_header_ok(&f)); // the checksum is valid, recomputed from the bytes
        for i in 0..len {
            if i != 15 && i != 24 && i != 25 {
                assert_eq!(f[i], g[i], "byte {i} changed"); // nothing else changed
            }
        }
        if proto == 6 || proto == 17 {
            assert_eq!(l4_checksum(&f[..len], false), l4_before); // the transport checksum does not cover the ECN field
        }
        assert_eq!(classify(&f[..len]), EcnClass::Ce);
    }
    assert!(marked > 20_000);
}

/// The classic checksum field values that give trouble: ones' complement zero, 0xffff, and a carry out of the incremental update.
#[test]
fn ipv4_checksum_edge_values() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    for tos in 1..3 {
        for a in (0..65536u32).step_by(7) {
            build4(&mut r, &mut f, tos, 6, 5, 40, 0);
            [f[18], f[19]] = (a as u16).to_be_bytes();
            [f[24], f[25]] = [0, 0];
            let hc = csum16(&f[14..34], 0);
            [f[24], f[25]] = hc.to_be_bytes();
            mark_ce(&mut f);
            assert!(ip4_header_ok(&f), "tos {tos} id {a:#x}");
        }
    }
}

/// Stronger than C: sweep every value of the identification word for header checksums at both ones' complement extremes, with and without carry.
#[test]
fn ipv4_checksum_exhaustive_id_and_tos_words() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    for tos in [1u32, 2, 0x01 | 0xfc, 0x02 | 0x80] {
        for a in 0..=65535u32 {
            build4(&mut r, &mut f, tos, 6, 5, 40, 0);
            [f[18], f[19]] = (a as u16).to_be_bytes();
            [f[24], f[25]] = [0, 0];
            let hc = csum16(&f[14..34], 0);
            [f[24], f[25]] = hc.to_be_bytes();
            mark_ce(&mut f);
            assert!(ip4_header_ok(&f), "tos {tos:#x} id {a:#x}");
        }
    }
}

#[test]
fn ipv6_marking_touches_one_byte() {
    let mut r = Rng::new();
    let (mut f, mut g) = ([0u8; 1600], [0u8; 1600]);
    for _ in 0..100_000 {
        let next = if r.rnd(3) == 0 { 17 } else { 6 };
        let payload = 20 + r.rnd(300);
        let tclass = r.rnd(256);
        let len = build6(&mut r, &mut f, tclass, next, payload);
        g[..len].copy_from_slice(&f[..len]);
        let cls = classify(&f[..len]);
        let dst = u16::from_be_bytes([f[14 + 40 + 2], f[14 + 40 + 3]]);
        if next == 17 && (dst == 546 || dst == 547) {
            continue;
        }
        assert_eq!(cls, class_of_ecn(tclass & 3));
        if cls != EcnClass::Capable {
            continue;
        }
        let l4_before = l4_checksum(&f[..len], true);
        mark_ce(&mut f[..len]);
        let after = ((f[14] & 15) << 4) | (f[15] >> 4);
        assert!(after & 3 == 3 && u32::from(after & 0xfc) == tclass & 0xfc); // traffic class: CE, DSCP untouched
        for i in 0..len {
            if i != 15 {
                assert_eq!(f[i], g[i]); // only the one byte
            }
        }
        assert_eq!(f[15] & 0x0f, g[15] & 0x0f); // the flow label's high nibble sits in the same byte
        assert_eq!(l4_checksum(&f[..len], true), l4_before); // the IPv6 pseudo header does not cover the traffic class
    }
}

#[test]
fn exempt_and_foreign_frames() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    // ARP and other ethertypes: never touched.
    f[..60].fill(0);
    f[12] = 0x08;
    f[13] = 0x06;
    assert_eq!(classify(&f[..60]), EcnClass::NotIp);
    [f[12], f[13]] = [0x88, 0x8e];
    assert_eq!(classify(&f[..60]), EcnClass::NotIp); // EAPOL
    [f[12], f[13]] = [0x81, 0x00];
    assert_eq!(classify(&f[..60]), EcnClass::NotIp); // VLAN tag: not parsed, so not touched
    // Truncated and malformed: not IP, not touched, no read past the end.
    let mut len = build4(&mut r, &mut f, 2, 6, 5, 40, 0);
    for n in 0..40 {
        let c = classify(&f[..n]);
        if n < 34 {
            assert_eq!(c, EcnClass::NotIp, "prefix {n}");
        }
    }
    f[14] = 0x44;
    assert_eq!(classify(&f[..len]), EcnClass::NotIp); // IHL below 5
    f[14] = 0x4f;
    assert_eq!(classify(&f[..40]), EcnClass::NotIp); // IHL beyond the frame
    f[14] = 0x65;
    assert_eq!(classify(&f[..len]), EcnClass::NotIp); // version 6 in an IPv4 ethertype
    len = build6(&mut r, &mut f, 2, 6, 40);
    f[14] = 0x40;
    assert_eq!(classify(&f[..len]), EcnClass::NotIp);
    // Exempt: SYN, FIN, RST, DHCP (both directions), ICMPv6, DHCPv6.
    for flag in [0x01u8, 0x02, 0x04] {
        len = build4(&mut r, &mut f, 2, 6, 5, 40, 0);
        f[14 + 20 + 13] = flag;
        assert_eq!(classify(&f[..len]), EcnClass::Exempt);
    }
    len = build4(&mut r, &mut f, 2, 6, 5, 40, 0);
    f[14 + 20 + 13] = 0x12;
    assert_eq!(classify(&f[..len]), EcnClass::Exempt); // SYN+ACK
    len = build4(&mut r, &mut f, 2, 17, 5, 40, 0);
    [f[14 + 20 + 2], f[14 + 20 + 3]] = [0, 68];
    assert_eq!(classify(&f[..len]), EcnClass::Exempt);
    len = build4(&mut r, &mut f, 2, 17, 5, 40, 0);
    [f[14 + 20], f[14 + 20 + 1]] = [0, 67];
    assert_eq!(classify(&f[..len]), EcnClass::Exempt);
    len = build6(&mut r, &mut f, 2, 58, 40);
    assert_eq!(classify(&f[..len]), EcnClass::Exempt);
    len = build6(&mut r, &mut f, 2, 17, 40);
    [f[14 + 40 + 2], f[14 + 40 + 3]] = [0x02, 0x22];
    assert_eq!(classify(&f[..len]), EcnClass::Exempt);
    len = build6(&mut r, &mut f, 2, 6, 40);
    f[14 + 40 + 13] = 0x04;
    assert_eq!(classify(&f[..len]), EcnClass::Exempt);
    // A non-first fragment has no transport header: its bytes are payload, so flag-looking bytes there must not exempt it.
    len = build4(&mut r, &mut f, 2, 6, 5, 80, 0x00b9);
    f[14 + 20 + 13] = 0x02;
    assert_eq!(classify(&f[..len]), EcnClass::Capable);
    // ICMP echo and ordinary data are eligible.
    len = build4(&mut r, &mut f, 0, 1, 5, 64, 0);
    assert_eq!(classify(&f[..len]), EcnClass::NotEct);
    len = build4(&mut r, &mut f, 1, 6, 5, 1000, 0);
    assert_eq!(classify(&f[..len]), EcnClass::Capable);
}

#[test]
fn ipv4_exemption_details() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    // UDP source 68 / destination 67; ports 66 and 69 are not DHCP.
    for (src, dst, want) in [
        (68u16, 5000u16, EcnClass::Exempt),
        (5000, 67, EcnClass::Exempt),
        (66, 5000, EcnClass::Capable),
        (5000, 69, EcnClass::Capable),
    ] {
        let len = build4(&mut r, &mut f, 1, 17, 5, 40, 0);
        [f[34], f[35]] = src.to_be_bytes();
        [f[36], f[37]] = dst.to_be_bytes();
        assert_eq!(classify(&f[..len]), want, "{src}->{dst}");
    }
    // DHCP in a non-first fragment is payload, not DHCP.
    let len = build4(&mut r, &mut f, 1, 17, 5, 40, 0x0010);
    [f[36], f[37]] = 67u16.to_be_bytes();
    assert_eq!(classify(&f[..len]), EcnClass::Capable);
    // TCP with ECE/CWR/PSH/URG/ACK only is not exempt; each of FIN/SYN/RST alone is, whatever else is set.
    for flags in [0x10u8, 0x18, 0x20, 0x40, 0x80, 0xf8] {
        let len = build4(&mut r, &mut f, 1, 6, 5, 40, 0);
        f[14 + 20 + 13] = flags;
        assert_eq!(classify(&f[..len]), EcnClass::Capable, "flags {flags:#x}");
    }
    for flags in [0xf9u8, 0xfa, 0xfc] {
        let len = build4(&mut r, &mut f, 1, 6, 5, 40, 0);
        f[14 + 20 + 13] = flags;
        assert_eq!(classify(&f[..len]), EcnClass::Exempt, "flags {flags:#x}");
    }
    // Header bytes of TCP/UDP that are cut off by the frame end: fall through to the ECN field.
    let len = build4(&mut r, &mut f, 1, 6, 5, 40, 0);
    f[14 + 20 + 13] = 0x02;
    assert_eq!(classify(&f[..14 + 20 + 13]), EcnClass::Capable);
    assert_eq!(classify(&f[..14 + 20 + 14]), EcnClass::Exempt);
    assert_eq!(classify(&f[..len]), EcnClass::Exempt);
}

#[test]
fn ipv6_extension_headers() {
    let mut r = Rng::new();
    let (mut f, mut g) = ([0u8; 1600], [0u8; 1600]);
    let (hbh, hbh2, dst, rt, frag, ah) = (
        ext(0, 0),
        ext(0, 2),
        ext(60, 1),
        ext(43, 1),
        ext(44, 0),
        ext(51, 1),
    );
    // MLD (ICMPv6) behind hop-by-hop: exempt, the case the review found being dropped.
    let mut n = build6_chain(&mut r, &mut f, 2, &[hbh], 58, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt);
    n = build6_chain(&mut r, &mut f, 0, &[hbh], 58, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt); // not-ECT too: never dropped
    // A SYN behind a destination-options header: exempt; data behind it: eligible and markable; the ECN field is where it always is.
    n = build6_chain(&mut r, &mut f, 2, &[dst], 6, 0x02, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt);
    n = build6_chain(&mut r, &mut f, 2, &[dst], 6, 0x10, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    g[..n].copy_from_slice(&f[..n]);
    mark_ce(&mut f[..n]);
    for i in 0..n {
        if i != 15 {
            assert_eq!(f[i], g[i]);
        }
    }
    assert_eq!(classify(&f[..n]), EcnClass::Ce);
    n = build6_chain(&mut r, &mut f, 0, &[dst], 6, 0x10, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::NotEct);
    // Chains: several headers, of every kind, in any order.
    let c = [hbh2, rt, dst, ah];
    n = build6_chain(&mut r, &mut f, 2, &c, 58, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt);
    n = build6_chain(&mut r, &mut f, 2, &c, 6, 0x04, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt); // RST
    n = build6_chain(&mut r, &mut f, 1, &c, 6, 0x18, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    n = build6_chain(&mut r, &mut f, 2, &c, 17, 0, 547, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt); // DHCPv6
    n = build6_chain(&mut r, &mut f, 2, &c, 17, 0, 5001, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    // A first fragment still carries the transport header; a later one does not (its bytes are payload: eligible, never exempt, whatever they look like).
    n = build6_chain(&mut r, &mut f, 2, &[frag], 6, 0x02, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt);
    n = build6_chain(&mut r, &mut f, 2, &[frag], 6, 0x02, 0, 185);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    n = build6_chain(&mut r, &mut f, 2, &[frag], 58, 0, 0, 185);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    // ESP and "no next header": opaque, eligible by their ECN field.
    n = build6_chain(&mut r, &mut f, 2, &[hbh], 50, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    n = build6_chain(&mut r, &mut f, 2, &[hbh], 59, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Capable);
    // Bounds: too many headers, a header that runs past the frame, a length field that points beyond it: not IP, never touched.
    let seven = [hbh; 7];
    n = build6_chain(&mut r, &mut f, 2, &seven[..6], 58, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::Exempt); // six is the limit
    n = build6_chain(&mut r, &mut f, 2, &seven, 58, 0, 0, 0);
    assert_eq!(classify(&f[..n]), EcnClass::NotIp);
    n = build6_chain(&mut r, &mut f, 2, &[hbh], 6, 0x10, 0, 0);
    for cut in 0..n {
        let _ = classify(&f[..cut]); // every truncation: no read past `cut`
    }
    f[54 + 1] = 200;
    assert_eq!(classify(&f[..n]), EcnClass::NotIp); // hop-by-hop length beyond the frame
    // The SYN/SYN-ACK negotiation helper walks the same chain.
    n = build6_chain(&mut r, &mut f, 0, &[hbh], 6, 0xc2, 0, 0);
    assert_eq!(tcp_ecn_syn(&f[..n]), TcpEcnSyn::SynEcnSetup);
    n = build6_chain(&mut r, &mut f, 0, &[dst], 6, 0x52, 0, 0);
    assert_eq!(tcp_ecn_syn(&f[..n]), TcpEcnSyn::SynAckEcnAccept);
    n = build6_chain(&mut r, &mut f, 0, &[frag], 6, 0xc2, 0, 185);
    assert_eq!(tcp_ecn_syn(&f[..n]), TcpEcnSyn::Other);
}

/// Random chains: classification never reads out of bounds (fuzz; the C test ran it under ASan). Stronger than C: asserts a hand-built frame
/// classifies like the independent reference, and that a truncated one agrees too.
#[test]
fn ipv6_random_extension_chains() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    const KINDS: [u8; 5] = [0, 43, 44, 51, 60];
    for _ in 0..200_000 {
        let k = r.usz(8);
        let mut c = [ext(0, 0); 8];
        for e in &mut c[..k] {
            *e = ext(KINDS[r.usz(5)], r.byte() % 4);
        }
        let proto = if r.rnd(5) == 0 {
            58
        } else if r.rnd(2) != 0 {
            6
        } else {
            17
        };
        let tclass = r.rnd(256);
        let tcp_flags = r.rnd(256);
        let udp_dst = if r.rnd(2) != 0 { 546 } else { r.rnd(65536) };
        let frag_off = if r.rnd(3) == 0 { r.rnd(8000) } else { 0 };
        let n = build6_chain(
            &mut r,
            &mut f,
            tclass,
            &c[..k],
            proto,
            tcp_flags,
            udp_dst,
            frag_off,
        );
        let cut = if r.rnd(4) == 0 { r.usz(n + 1) } else { n };
        assert_eq!(classify(&f[..cut]), ref_classify(&f[..cut]));
        let _ = tcp_ecn_syn(&f[..cut]);
    }
}

#[test]
fn ip6_l4_direct() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    let n = build6_chain(&mut r, &mut f, 0, &[], 6, 0x10, 0, 0);
    assert_eq!(ip6_l4(&f[..n]), Some((6, 54)));
    let n = build6_chain(&mut r, &mut f, 0, &[ext(0, 1), ext(60, 0)], 17, 0, 9, 0);
    assert_eq!(ip6_l4(&f[..n]), Some((17, 54 + 16 + 8)));
    let n = build6_chain(&mut r, &mut f, 0, &[ext(51, 1)], 6, 0, 0, 0);
    assert_eq!(ip6_l4(&f[..n]), Some((6, 54 + 12))); // AH: (units + 2) * 4
    let n = build6_chain(&mut r, &mut f, 0, &[ext(44, 0)], 6, 0, 0, 1);
    assert_eq!(ip6_l4(&f[..n]), Some((0xff, 54))); // non-first fragment
    let n = build6_chain(&mut r, &mut f, 0, &[ext(0, 0)], 50, 0, 0, 0);
    assert_eq!(ip6_l4(&f[..n]), Some((0xff, 62))); // ESP
    let n = build6_chain(&mut r, &mut f, 0, &[], 59, 0, 0, 0);
    assert_eq!(ip6_l4(&f[..n]), Some((0xff, 54))); // no next header
    // The transport header may start exactly at the end of the frame (the callers do their own length check).
    assert_eq!(ip6_l4(&f[..54]), Some((0xff, 54)));
    let n = build6_chain(&mut r, &mut f, 0, &[ext(0, 0)], 6, 0, 0, 0);
    assert_eq!(ip6_l4(&f[..62]), Some((6, 62)));
    assert_eq!(ip6_l4(&f[..61]), None); // header does not fit
    assert_eq!(ip6_l4(&f[..20]), None);
    assert_eq!(ip6_l4(&[]), None);
    assert!(n > 62);
}

#[test]
fn tcp_ecn_syn_ipv4() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    let flags_at = |ihl_words: u32| (14 + ihl_words * 4 + 13) as usize;
    for (flags, want) in [
        (0xc2u8, TcpEcnSyn::SynEcnSetup),
        (0xc3, TcpEcnSyn::SynEcnSetup), // FIN set as well: only SYN/ACK/ECE/CWR are tested
        (0x52, TcpEcnSyn::SynAckEcnAccept),
        (0xd2, TcpEcnSyn::Other), // SYN+ACK+ECE+CWR
        (0x82, TcpEcnSyn::Other), // SYN+CWR, no ECE
        (0x42, TcpEcnSyn::Other), // SYN+ECE, no CWR, no ACK
        (0x02, TcpEcnSyn::Other), // plain SYN
        (0xd0, TcpEcnSyn::Other), // no SYN
        (0x12, TcpEcnSyn::Other), // plain SYN+ACK
        (0x00, TcpEcnSyn::Other),
    ] {
        for ihl_words in [5u32, 7, 15] {
            let len = build4(&mut r, &mut f, 0, 6, ihl_words, 40, 0);
            f[flags_at(ihl_words)] = flags;
            assert_eq!(
                tcp_ecn_syn(&f[..len]),
                want,
                "flags {flags:#x} ihl {ihl_words}"
            );
        }
    }
    let len = build4(&mut r, &mut f, 0, 6, 5, 40, 0);
    f[flags_at(5)] = 0xc2;
    assert_eq!(tcp_ecn_syn(&f[..len]), TcpEcnSyn::SynEcnSetup);
    assert_eq!(tcp_ecn_syn(&f[..flags_at(5)]), TcpEcnSyn::Other); // truncated before the flags byte
    assert_eq!(tcp_ecn_syn(&f[..flags_at(5) + 1]), TcpEcnSyn::SynEcnSetup);
    f[20] = 0x00;
    f[21] = 0x01;
    assert_eq!(tcp_ecn_syn(&f[..len]), TcpEcnSyn::Other); // not the first fragment
    f[20] = 0x40; // DF only
    f[21] = 0;
    assert_eq!(tcp_ecn_syn(&f[..len]), TcpEcnSyn::SynEcnSetup);
    f[23] = 17;
    assert_eq!(tcp_ecn_syn(&f[..len]), TcpEcnSyn::Other); // UDP
    f[23] = 6;
    f[14] = 0x44;
    assert_eq!(tcp_ecn_syn(&f[..len]), TcpEcnSyn::Other); // IHL below 5
    assert_eq!(tcp_ecn_syn(&[]), TcpEcnSyn::Other);
    assert_eq!(TcpEcnSyn::Other as u8, 0);
    assert_eq!(TcpEcnSyn::SynEcnSetup as u8, 1);
    assert_eq!(TcpEcnSyn::SynAckEcnAccept as u8, 2);
}

#[test]
fn mark_ce_on_short_frames_is_a_no_op() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    let len = build4(&mut r, &mut f, 1, 6, 5, 40, 0);
    for n in 0..26 {
        let mut g = f[..n].to_vec();
        mark_ce(&mut g);
        assert_eq!(g, f[..n], "prefix {n}");
    }
    let len6 = build6(&mut r, &mut f, 1, 6, 40);
    for n in 0..16 {
        let mut g = f[..n].to_vec();
        mark_ce(&mut g);
        assert_eq!(g, f[..n]);
    }
    assert!(len > 26 && len6 > 16);
}
