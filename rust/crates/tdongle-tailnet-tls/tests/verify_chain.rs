#![cfg_attr(not(feature = "p384"), allow(dead_code, unused_macros))]
//! The trust policy against DER fixtures (tests/fixtures/gen.sh) and the real chain derp1.tailscale.com presented on 2026-10-06.
//! Ported from alternative/tailnet/tests/test_derp_tls.c: same scenarios, same expected verdicts.
use tdongle_tailnet_tls::verify::*;
use tdongle_tailnet_tls::{DerpCert, parse_cert_name};

const NOW: u64 = 1_791_244_800; // 2026-10-06T00:00:00Z

fn f(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}.der", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn run(chain: &[&str], host: &str, cert_name: Option<&str>, anchors: &[TrustAnchor<'_>]) -> Result<Accepted, Reject> {
    run_at(chain, host, cert_name, anchors, NOW)
}
fn run_at(chain: &[&str], host: &str, cert_name: Option<&str>, anchors: &[TrustAnchor<'_>], now: u64) -> Result<Accepted, Reject> {
    let ders: Vec<Vec<u8>> = chain.iter().map(|n| f(n)).collect();
    let refs: Vec<&[u8]> = ders.iter().map(|d| d.as_slice()).collect();
    let cert = parse_cert_name(Some(host), cert_name);
    verify_chain(&VerifyConfig { anchors, now_unix: now, cert: &cert, hostname: host }, &refs)
}

/// The test PKI's anchor: subject and SPKI of x2.der.
fn x2_anchor() -> (Vec<u8>, Vec<u8>) {
    anchor_of("x2")
}
fn anchor_of(name: &str) -> (Vec<u8>, Vec<u8>) {
    // Subject and SPKI by walking the DER with the same layout the verifier uses.
    let d = f(name);
    let (subject, spki) = tbs_fields(&d);
    (subject, spki)
}
fn tlv(b: &[u8]) -> (usize, usize) {
    let l = b[1] as usize;
    if l < 0x80 {
        (2, l)
    } else {
        let n = l & 0x7f;
        (2 + n, b[2..2 + n].iter().fold(0, |a, &x| a << 8 | x as usize))
    }
}
fn tbs_fields(d: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (h, _) = tlv(d);
    let cert = &d[h..];
    let (h, _) = tlv(cert);
    let mut c = &cert[h..];
    if c[0] == 0xa0 {
        let (h, l) = tlv(c);
        c = &c[h + l..];
    }
    let next = |c: &mut &[u8]| {
        let (h, l) = tlv(c);
        let t = c[..h + l].to_vec();
        *c = &c[h + l..];
        t
    };
    next(&mut c);
    next(&mut c);
    next(&mut c);
    next(&mut c);
    let subject = next(&mut c);
    let spki = next(&mut c);
    (subject, spki)
}

macro_rules! with_x2 {
    ($a:ident, $body:block) => {{
        let (s, k) = x2_anchor();
        let $a = [TrustAnchor { subject: &s, spki: &k }];
        $body
    }};
}

const H: &str = "derp1.test.example";

#[test]
#[cfg(feature = "p384")]
fn valid_chain_in_all_shapes() {
    with_x2!(a, {
        // leaf <- YE2 <- Root YE <- X2 cross-certificate (RSA signature on the cross cert is never examined)
        let r = run(&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, &a).unwrap();
        assert_eq!(r.trusted_by, TrustedBy::PresentedAnchor { anchor: 0 });
        assert_eq!(r.signature_verifies, 3, "leaf<-YE2, YE2<-YE, YE<-X2 (cross cert's RSA signature skipped)");
        // The cross-certificate not sent at all: Root YE is issued by an anchor that is not presented.
        let r = run(&["leaf_ok", "ye2", "ye"], H, None, &a).unwrap();
        assert_eq!(r.trusted_by, TrustedBy::IssuerAnchor { anchor: 0 });
        // Case-insensitive host, CertName == HostName, trailing dot.
        run(&["leaf_ok", "ye2", "ye"], "DERP1.Test.Example", None, &a).unwrap();
        run(&["leaf_ok", "ye2", "ye"], H, Some("derp1.test.example"), &a).unwrap();
        run(&["leaf_ok", "ye2", "ye"], "derp1.test.example.", None, &a).unwrap();
        // SHA-256 signature by a P-384 issuer, and an unrelated extra certificate in the list are fine.
        run(&["leaf_sha256sig", "ye2", "ye"], H, None, &a).unwrap();
        run(&["leaf_ok", "rogue_ye", "ye2", "ye", "x1"], H, None, &a).unwrap();
        // The Ed25519 derpkey meta certificate is skipped, wherever it is.
        run(&["leaf_ok", "ye2", "ye", "x2_cross", "derpkey"], H, None, &a).unwrap();
        run(&["leaf_ok", "derpkey", "ye2", "ye", "x2_cross"], H, None, &a).unwrap();
        assert_eq!(run(&["leaf_is_ca", "ye2", "ye"], H, None, &a), Err(Reject::KeyUsage), "a CA-only keyUsage cannot sign a TLS handshake");
    });
}

#[test]
#[cfg(feature = "p384")]
fn names() {
    with_x2!(a, {
        let nm = |l: &str, h: &str, cn: Option<&str>| run(&[l, "ye2", "ye", "x2_cross"], h, cn, &a);
        assert_eq!(nm("leaf_other", H, None), Err(Reject::NameMismatch));
        assert_eq!(nm("leaf_ok", "derp2.test.example", None), Err(Reject::NameMismatch));
        assert_eq!(nm("leaf_ok", "xderp1.test.example", None), Err(Reject::NameMismatch));
        assert_eq!(nm("leaf_cn_only", H, None), Err(Reject::NameMismatch), "SAN only, no CommonName fallback");
        // Wildcards: one label deep, whole left-most label.
        nm("leaf_wild", "a.wild.example", None).unwrap();
        assert_eq!(nm("leaf_wild", "a.b.wild.example", None), Err(Reject::NameMismatch));
        assert_eq!(nm("leaf_wild", "wild.example", None), Err(Reject::NameMismatch));
        // IP literals against iPAddress entries.
        nm("leaf_ip", "192.0.2.7", None).unwrap();
        assert_eq!(nm("leaf_ip", "192.0.2.8", None), Err(Reject::NameMismatch));
        assert_eq!(nm("leaf_ok", "192.0.2.7", None), Err(Reject::NameMismatch), "IP-only node, name cert: fail closed");
        nm("leaf_ip6", "2001:db8::7", None).unwrap();
        assert_eq!(nm("leaf_ip6", "2001:db8::8", None), Err(Reject::NameMismatch));
        // CertName (domain fronting): SNI is HostName, the chain must name CertName.
        nm("leaf_front", "front.example", Some("derp1.test.example")).unwrap();
        assert_eq!(nm("leaf_front", "front.example", Some("other.example")), Err(Reject::NameMismatch));
        assert_eq!(nm("leaf_front", H, Some("other.example")), Err(Reject::NameMismatch), "HostName alone no longer enough");
        // Malformed CertName: never connect.
        assert_eq!(nm("leaf_ok", H, Some("sha256-raw:00")), Err(Reject::InvalidCertName));
        assert_eq!(nm("leaf_ok", H, Some("bad name")), Err(Reject::InvalidCertName));
    });
}

#[test]
#[cfg(feature = "p384")]
fn untrusted() {
    with_x2!(a, {
        assert_eq!(run(&["leaf_rogue", "rogue_ye2", "rogue_ye"], H, None, &a), Err(Reject::NotTrusted));
        assert_eq!(run(&["leaf_ok"], H, None, &a), Err(Reject::NotTrusted), "intermediate absent");
        assert_eq!(run(&["leaf_ok", "ye2"], H, None, &a), Err(Reject::NotTrusted), "root YE absent and not an anchor");
        assert_eq!(run(&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, &[]), Err(Reject::NotTrusted), "no anchors at all");
        // Same subject DN as the anchor, different key: a self-made X2 issuing the whole chain.
        assert_eq!(run(&["leaf_fake", "fake_ye2", "fake_ye", "fake_x2"], H, None, &a), Err(Reject::NotTrusted));
        // The anchor's key under another subject DN: the key alone never matches.
        assert_eq!(run(&["leaf_ok", "ye2", "renamed_ye", "renamed_x2"], H, None, &a), Err(Reject::NotTrusted));
        // A chain that is cryptographically fine but the intermediate was signed by a different key than presented.
        assert_eq!(run(&["leaf_ok", "rogue_ye2", "ye", "x2_cross"], H, None, &a), Err(Reject::BadSignature));
    });
}

#[test]
#[cfg(feature = "p384")]
fn validity_and_extensions() {
    with_x2!(a, {
        assert_eq!(run(&["leaf_expired", "ye2", "ye", "x2_cross"], H, None, &a), Err(Reject::Expired));
        assert_eq!(run(&["leaf_future", "ye2", "ye", "x2_cross"], H, None, &a), Err(Reject::NotYetValid));
        assert_eq!(run(&["leaf_ok", "ye2_old", "ye", "x2_cross"], H, None, &a), Err(Reject::Expired), "expired intermediate");
        assert_eq!(run(&["leaf_ok", "ye2", "ye_expired", "x2_cross"], H, None, &a), Err(Reject::Expired), "expired root-level intermediate");
        assert_eq!(
            run(&["leaf_ok", "ye2", "ye", "x2_cross_old"], H, None, &a),
            Err(Reject::Expired),
            "expired presented anchor copy: validity of a presented certificate is still enforced"
        );
        assert_eq!(run(&["leaf_ok", "ye2", "ye", "x2_cross_new"], H, None, &a), Err(Reject::NotYetValid));
        // Clock rules: not set, and the boundary of validity.
        assert_eq!(run_at(&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, &a, 0), Err(Reject::ClockNotSet));
        assert_eq!(run_at(&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, &a, MIN_VALID_UNIX), Err(Reject::ClockNotSet));
        assert_eq!(run_at(&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, &a, MIN_VALID_UNIX + 1), Err(Reject::NotYetValid), "Nov 2023 is before the fixtures");
        assert!(run_at(&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, &a, 1_788_307_200).is_ok(), "2026-09-02 is valid");
        // Leaf and issuer constraints.
        assert_eq!(run(&["leaf_noeku", "ye2", "ye", "x2_cross"], H, None, &a), Err(Reject::KeyUsage));
        assert_eq!(run(&["leaf_under_noca", "ye2_noca", "ye", "x2_cross"], H, None, &a), Err(Reject::NotCa));
    });
}

#[test]
#[cfg(not(feature = "p384"))]
fn without_p384_the_ecdsa_chain_fails_closed() {
    let real = ["real_derp1_0", "real_derp1_1", "real_derp1_2", "real_derp1_3", "derpkey"];
    assert_eq!(run(&real, "derp1.tailscale.com", None, DEFAULT_ANCHORS), Err(Reject::UnsupportedAlgorithm));
}

fn sha256_hex(name: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(f(name)).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sha256_raw_pin() {
    let pin = |n: &str| format!("sha256-raw:{}", sha256_hex(n));
    let none: [TrustAnchor<'_>; 0] = [];
    // The pin needs no trust store; name, dates and "exactly one certificate" still count.
    assert!(run(&["pin"], "pin.example", Some(&pin("pin")), &none).is_ok());
    let r = run(&["pin"], "127.0.0.1", Some(&pin("pin")), &none).unwrap();
    assert_eq!((r.trusted_by, r.signature_verifies), (TrustedBy::Pin, 0));
    // The Tailscale meta certificate next to it is fine, any other second certificate is not.
    assert!(run(&["pin", "derpkey"], "pin.example", Some(&pin("pin")), &none).is_ok());
    assert_eq!(run(&["pin", "ye2"], "pin.example", Some(&pin("pin")), &none), Err(Reject::PinExtraCertificate));
    assert_eq!(run(&["pin", "derpkey", "ye2"], "pin.example", Some(&pin("pin")), &none), Err(Reject::PinExtraCertificate));
    assert_eq!(run(&["pin_other"], "pin.example", Some(&pin("pin")), &none), Err(Reject::PinMismatch), "different cert, same name");
    assert_eq!(run(&["leaf_ok", "ye2", "ye"], H, Some(&pin("pin")), &none), Err(Reject::PinExtraCertificate));
    assert_eq!(run(&["leaf_ok"], H, Some(&pin("pin")), &none), Err(Reject::PinMismatch), "a CA-valid cert is not the pinned one");
    assert_eq!(run(&["pin"], "other.example", Some(&pin("pin")), &none), Err(Reject::NameMismatch), "pinned, wrong name");
    assert_eq!(run(&["pin_expired"], "pin.example", Some(&pin("pin_expired")), &none), Err(Reject::Expired));
    assert_eq!(run(&["pin_wrong_name"], "pin.example", Some(&pin("pin_wrong_name")), &none), Err(Reject::NameMismatch));
    // Without a pin a self-signed certificate is untrusted.
    assert_eq!(run(&["pin"], "pin.example", None, &none), Err(Reject::NotTrusted));
    // Pin text in capitals works; malformed pins never connect.
    let up = pin("pin").replace(&sha256_hex("pin"), &sha256_hex("pin").to_uppercase());
    assert!(run(&["pin"], "pin.example", Some(&up), &none).is_ok());
    assert_eq!(run(&["pin"], "pin.example", Some("sha256-raw:abcd"), &none), Err(Reject::InvalidCertName));
}

/// What derp1.tailscale.com presented on 2026-10-06, verified with the anchors compiled into the crate.
#[test]
#[cfg(feature = "p384")]
fn real_derp_chain() {
    let host = "derp1.tailscale.com";
    let real = ["real_derp1_0", "real_derp1_1", "real_derp1_2", "real_derp1_3", "derpkey"];
    // ISRG Root X2 pinned by SPKI: the RSA-4096 cross-signature on the presented X2 is never verified.
    let r = run(&real, host, None, DEFAULT_ANCHORS).unwrap();
    assert_eq!(r.trusted_by, TrustedBy::PresentedAnchor { anchor: 0 });
    assert_eq!(r.signature_verifies, 3);
    assert_eq!(r.path_len, 4);
    // Root YE as an anchor too: the path ends one verification earlier.
    let both = [ISRG_ROOT_YE, ISRG_ROOT_X2];
    let r = run(&real, host, None, &both).unwrap();
    assert_eq!((r.trusted_by, r.signature_verifies), (TrustedBy::PresentedAnchor { anchor: 0 }, 2));
    // Without the cross-certificate X2 still anchors Root YE (the day Go stops sending it).
    let r = run(&real[..3], host, None, DEFAULT_ANCHORS).unwrap();
    assert_eq!(r.trusted_by, TrustedBy::IssuerAnchor { anchor: 0 });
    // Wrong host, no anchors, and a date before / after the leaf's validity (2026-09-24 .. 2026-12-23).
    assert_eq!(run(&real, "derp2.tailscale.com", None, DEFAULT_ANCHORS), Err(Reject::NameMismatch));
    assert_eq!(run(&real, host, None, &[]), Err(Reject::NotTrusted));
    assert_eq!(run_at(&real, host, None, DEFAULT_ANCHORS, 1_791_244_800 + 100 * 86_400), Err(Reject::Expired));
    assert_eq!(run_at(&real, host, None, DEFAULT_ANCHORS, 1_791_244_800 - 30 * 86_400), Err(Reject::NotYetValid));
    // Tampering with one byte of the leaf breaks the signature (or the parse).
    let mut leaf = f("real_derp1_0");
    leaf[300] ^= 1;
    let ders = [leaf, f("real_derp1_1"), f("real_derp1_2"), f("real_derp1_3")];
    let refs: Vec<&[u8]> = ders.iter().map(|d| d.as_slice()).collect();
    let cert = DerpCert::Hostname;
    let e = verify_chain(&VerifyConfig { anchors: DEFAULT_ANCHORS, now_unix: NOW, cert: &cert, hostname: host }, &refs).unwrap_err();
    assert!(matches!(e, Reject::BadSignature | Reject::Malformed | Reject::NotTrusted), "{e:?}");
}

/// What derp1.tailscale.com serves a TLS 1.3-only client (embedded-tls offers no TLS 1.2 ECDSA suite, so Go's autocert picks RSA): RSA-2048 leaf and
/// YR1, RSA-4096 Root YR cross-signed by ISRG Root X1.
#[test]
fn real_derp_rsa_chain() {
    let host = "derp1.tailscale.com";
    let real = ["real_derp1_rsa_0", "real_derp1_rsa_1", "real_derp1_rsa_2", "derpkey"];
    // X1 anchors Root YR (RSA-4096 signature verified), YR1 by Root YR (4096), leaf by YR1 (2048): three RSA public operations.
    let r = run(&real, host, None, DEFAULT_ANCHORS).unwrap();
    assert_eq!((r.trusted_by, r.signature_verifies), (TrustedBy::IssuerAnchor { anchor: 1 }, 3), "signature_verifies counts every signature check");
    // Root YR itself pinned as an anchor: its X1 signature is never verified.
    let r = run(&real, host, None, FAST_ANCHORS).unwrap();
    assert_eq!((r.trusted_by, r.signature_verifies), (TrustedBy::PresentedAnchor { anchor: 1 }, 2));
    // Only X2 trusted: the RSA chain has no path.
    assert_eq!(run(&real, host, None, &[ISRG_ROOT_X2]), Err(Reject::NotTrusted));
    assert_eq!(run(&real, "derp2.tailscale.com", None, DEFAULT_ANCHORS), Err(Reject::NameMismatch));
    // A flipped bit in the YR1 certificate's signature value breaks the leaf's path.
    let mut yr1 = f("real_derp1_rsa_1");
    let n = yr1.len();
    yr1[n - 5] ^= 1;
    let ders = [f("real_derp1_rsa_0"), yr1, f("real_derp1_rsa_2")];
    let refs: Vec<&[u8]> = ders.iter().map(|d| d.as_slice()).collect();
    let cert = DerpCert::Hostname;
    let e = verify_chain(&VerifyConfig { anchors: DEFAULT_ANCHORS, now_unix: NOW, cert: &cert, hostname: host }, &refs).unwrap_err();
    assert_eq!(e, Reject::BadSignature);
}

/// The compiled-in anchors are the real ISRG roots: X2 is what the real chain's cross-certificate carries.
#[test]
fn anchor_constants_match_the_real_certificates() {
    let (s, k) = tbs_fields(&f("real_derp1_3"));
    assert_eq!((ISRG_ROOT_X2.subject, ISRG_ROOT_X2.spki), (&s[..], &k[..]));
    let (s, k) = tbs_fields(&f("real_derp1_2"));
    assert_eq!((ISRG_ROOT_YE.subject, ISRG_ROOT_YE.spki), (&s[..], &k[..]));
    let (s, k) = tbs_fields(&f("real_derp1_rsa_2"));
    assert_eq!((ISRG_ROOT_YR.subject, ISRG_ROOT_YR.spki), (&s[..], &k[..]));
    let (s, k) = tbs_fields(&f("isrg_root_x1"));
    assert_eq!((ISRG_ROOT_X1.subject, ISRG_ROOT_X1.spki), (&s[..], &k[..]));
}

/// Mutated and truncated inputs never panic (the deterministic mini-fuzz; the libfuzzer target does the same with arbitrary bytes).
#[test]
fn mini_fuzz_never_panics() {
    let base: Vec<Vec<u8>> = ["real_derp1_0", "real_derp1_1", "real_derp1_2", "real_derp1_3", "derpkey"].iter().map(|n| f(n)).collect();
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let cert = DerpCert::Hostname;
    let mut accepted = 0;
    for _ in 0..3000 {
        let mut c = base.clone();
        for _ in 0..(rnd() % 4) {
            let i = (rnd() % c.len() as u64) as usize;
            if c[i].is_empty() {
                continue;
            }
            match rnd() % 4 {
                0 => {
                    let p = (rnd() % c[i].len() as u64) as usize;
                    c[i][p] ^= 1 << (rnd() % 8);
                }
                1 => {
                    let p = (rnd() % c[i].len() as u64) as usize;
                    c[i].truncate(p);
                }
                2 => {
                    let p = (rnd() % c[i].len() as u64) as usize;
                    c[i][p] = rnd() as u8;
                }
                _ => {
                    let p = (rnd() % c[i].len() as u64) as usize;
                    c[i].insert(p, rnd() as u8);
                }
            }
        }
        let refs: Vec<&[u8]> = c.iter().map(|d| d.as_slice()).collect();
        if verify_chain(&VerifyConfig { anchors: DEFAULT_ANCHORS, now_unix: NOW, cert: &cert, hostname: "derp1.tailscale.com" }, &refs).is_ok() {
            accepted += 1;
        }
    }
    // Mutations that only touch unused bytes (the meta certificate, the signature of the presented anchor copy) may still verify; most must not.
    assert!(accepted < 1500, "{accepted} of 3000 mutated chains accepted");
}
