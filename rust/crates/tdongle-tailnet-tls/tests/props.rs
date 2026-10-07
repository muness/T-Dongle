//! Property tests: nothing panics on arbitrary bytes, and the pin text round-trips.
use proptest::prelude::*;
use tdongle_tailnet_tls::transport::{Upgrade, UpgradeParser, upgrade_request};
use tdongle_tailnet_tls::{DEFAULT_ANCHORS, DerpCert, VerifyConfig, parse_cert_name, verify_chain};

proptest! {
    #[test]
    fn arbitrary_certificates_never_panic(parts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..700), 0..6), now in any::<u64>()) {
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let cert = DerpCert::Hostname;
        let r = verify_chain(&VerifyConfig { anchors: DEFAULT_ANCHORS, now_unix: now, cert: &cert, hostname: "derp1.tailscale.com" }, &refs);
        prop_assert!(r.is_err(), "random bytes must never verify");
    }

    #[test]
    fn pin_text_roundtrips(bytes in any::<[u8; 32]>(), upper in any::<bool>()) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let hex = if upper { hex.to_uppercase() } else { hex };
        prop_assert_eq!(parse_cert_name(Some("h"), Some(&format!("sha256-raw:{hex}"))), DerpCert::Pin(bytes));
    }

    #[test]
    fn cert_names_never_panic(host in "\\PC{0,80}", name in "\\PC{0,100}") {
        let _ = parse_cert_name(Some(&host), Some(&name));
        let _ = parse_cert_name(None, Some(&name));
    }

    #[test]
    fn upgrade_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1500)) {
        let mut p = UpgradeParser::new();
        let mut done = false;
        for b in data {
            let v = p.push(b);
            if done { continue; }
            done = v != Upgrade::Pending;
        }
    }

    #[test]
    fn upgrade_request_is_bounded(host in "[ -~]{0,100}", cap in 0usize..200) {
        let mut out = vec![0u8; cap];
        if let Some(n) = upgrade_request(&host, &mut out) {
            prop_assert!(n <= cap);
            prop_assert!(out[..n].starts_with(b"GET /derp HTTP/1.1\r\n") && out[..n].ends_with(b"\r\n\r\n"));
            prop_assert!(!host.contains(' '));
        }
    }
}
