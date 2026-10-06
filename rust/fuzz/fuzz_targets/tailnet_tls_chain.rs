//! The certificate chain a DERP server presents (and the CertName a control server sends) are attacker controlled bytes:
//! parse and verify them against the compiled-in anchors without panicking. The first input byte splits the rest into certificates.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_tls::{DEFAULT_ANCHORS, DerpCert, VerifyConfig, parse_cert_name, verify_chain};

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else { return };
    let n = (n as usize % 6) + 1;
    let step = rest.len() / n + 1;
    let certs: Vec<&[u8]> = rest.chunks(step).collect();
    let cert = DerpCert::Hostname;
    let _ = verify_chain(&VerifyConfig { anchors: DEFAULT_ANCHORS, now_unix: 1_791_244_800, cert: &cert, hostname: "derp1.tailscale.com" }, &certs);
    let pin = DerpCert::Pin([0u8; 32]);
    let _ = verify_chain(&VerifyConfig { anchors: DEFAULT_ANCHORS, now_unix: 1_791_244_800, cert: &pin, hostname: "x" }, &certs);
    if let Ok(s) = core::str::from_utf8(rest) {
        let _ = parse_cert_name(Some("derp1.tailscale.com"), Some(s));
    }
});
