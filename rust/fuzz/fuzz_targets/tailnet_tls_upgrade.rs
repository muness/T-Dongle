//! The HTTP response to `GET /derp` is read a byte at a time from the (already TLS-protected) server: no input may panic the parser.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_tls::transport::{Upgrade, UpgradeParser};

fuzz_target!(|data: &[u8]| {
    let mut p = UpgradeParser::new();
    for &b in data {
        if p.push(b) != Upgrade::Pending {
            break;
        }
    }
});
