//! Differential and robustness tests for the ECN code (additions to the C test suite): `classify` and `mark_ce` against an independent
//! reference written in `common`, every prefix of every generated frame, and a no-panic fuzz over arbitrary bytes.

mod common;

use common::*;
use tdongle_aqm::{EcnClass, classify, mark_ce, tcp_ecn_syn};

/// A random mix of valid and structurally hostile frames, `len` bytes of `f`.
fn gen_frame(r: &mut Rng, f: &mut Buf) -> usize {
    let mut len = match r.rnd(4) {
        0 => {
            let proto = [6, 17, 1, 47][r.usz(4)];
            let frag = [0, 0, 0x4000, 0x00b9, 0x2000, 1][r.usz(6)];
            let tos = r.rnd(256);
            let ihl_words = 5 + if r.rnd(3) == 0 { r.rnd(11) } else { 0 };
            let payload = 20 + r.rnd(200);
            build4(r, f, tos, proto, ihl_words, payload, frag)
        }
        1 => {
            let proto = [6, 17, 58, 50, 59, 1][r.usz(6)];
            let tclass = r.rnd(256);
            let payload = 20 + r.rnd(200);
            build6(r, f, tclass, proto, payload)
        }
        _ => {
            const KINDS: [u8; 5] = [0, 43, 44, 51, 60];
            let k = r.usz(8);
            let mut c = [ext(0, 0); 8];
            for e in &mut c[..k] {
                *e = ext(KINDS[r.usz(5)], r.byte() % 4);
            }
            let proto = [6, 17, 58, 50, 59][r.usz(5)];
            let udp_dst = [546, 547, 67, 5001][r.usz(4)];
            let frag_off = if r.rnd(3) == 0 { r.rnd(8000) } else { 0 };
            let tclass = r.rnd(256);
            let flags = r.rnd(256);
            build6_chain(r, f, tclass, &c[..k], proto, flags, udp_dst, frag_off)
        }
    };
    // Hostile mutations: flip header bytes, hit the flag/port bytes, truncate.
    for _ in 0..r.rnd(3) {
        let i = if r.rnd(2) != 0 { 12 + r.usz(60) } else { r.usz(len) };
        f[i] = if r.rnd(2) != 0 { r.byte() } else { [0x00, 0xff, 0x45, 0x60, 0x08, 0x86, 0xdd][r.usz(7)] };
    }
    if r.rnd(4) == 0 {
        len = r.usz(len + 1);
    }
    len
}

/// Reference marking: set the ECN bits, recompute the IPv4 header checksum from scratch.
fn ref_mark(f: &mut [u8]) {
    if u16::from_be_bytes([f[12], f[13]]) == 0x0800 {
        let ihl = usize::from(f[14] & 15) * 4;
        f[15] |= 3;
        f[24] = 0;
        f[25] = 0;
        let hc = csum16(&f[14..14 + ihl], 0);
        [f[24], f[25]] = hc.to_be_bytes();
    } else {
        f[15] |= 0x30;
    }
}

#[test]
fn classify_and_mark_ce_match_independent_reference() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    let mut seen = [0u32; 5];
    for _ in 0..300_000 {
        let len = gen_frame(&mut r, &mut f);
        let got = classify(&f[..len]);
        assert_eq!(got, ref_classify(&f[..len]), "frame {:02x?}", &f[..len.min(80)]);
        seen[got as usize] += 1;
        if got == EcnClass::Capable {
            let mut a = f[..len].to_vec();
            let mut b = f[..len].to_vec();
            let valid_before = u16::from_be_bytes([f[12], f[13]]) != 0x0800 || ip4_header_ok(&f);
            mark_ce(&mut a);
            ref_mark(&mut b);
            if valid_before {
                assert_eq!(a, b, "marked frame differs from recomputed-from-scratch reference");
            } else {
                // An invalid checksum stays invalid under the incremental update; everything but the checksum must still match.
                assert_eq!(a[..24], b[..24]);
                assert_eq!(a[26..], b[26..]);
            }
            assert_eq!(classify(&a), EcnClass::Ce);
        }
    }
    // every class reached, so the comparison is not vacuous
    assert!(seen.iter().all(|n| *n > 1000), "class coverage {seen:?}");
}

/// For every prefix of every generated frame `classify` and `tcp_ecn_syn` return without panicking, and agree with the reference.
#[test]
fn every_prefix_of_every_frame() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    for _ in 0..3000 {
        let len = gen_frame(&mut r, &mut f);
        for cut in 0..=len {
            let p = &f[..cut];
            let c = classify(p);
            assert_eq!(c, ref_classify(p), "prefix {cut} of {len}");
            let _ = tcp_ecn_syn(p);
            if cut < 14 {
                assert_eq!(c, EcnClass::NotIp);
            }
        }
    }
}

/// No panic on arbitrary bytes: random lengths 0..1600, ethertype forced to IPv4/IPv6 half the time (and a matching version nibble half of those).
#[test]
fn arbitrary_bytes_never_panic() {
    let mut r = Rng::new();
    let mut f = [0u8; 1600];
    for i in 0..400_000 {
        let len = r.usz(1600);
        for b in &mut f[..len] {
            *b = r.byte();
        }
        if len >= 15 && r.rnd(2) != 0 {
            let v6 = r.rnd(2) != 0;
            [f[12], f[13]] = if v6 { [0x86, 0xdd] } else { [0x08, 0x00] };
            if r.rnd(2) != 0 {
                f[14] = (f[14] & 0x0f) | if v6 { 0x60 } else { 0x40 };
            }
            if !v6 && r.rnd(2) != 0 {
                f[14] = 0x45 | (f[14] & 0x0a);
            }
            if v6 && len > 20 && r.rnd(2) != 0 {
                f[20] = [0, 43, 44, 51, 60, 6, 17, 58][r.usz(8)];
            }
        }
        let c = classify(&f[..len]);
        let _ = tcp_ecn_syn(&f[..len]);
        assert_eq!(c, ref_classify(&f[..len]), "iteration {i}");
        if c == EcnClass::Capable {
            mark_ce(&mut f[..len]);
            assert_eq!(classify(&f[..len]), EcnClass::Ce);
        }
    }
}
