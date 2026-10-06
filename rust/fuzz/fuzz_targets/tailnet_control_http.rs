//! The plaintext HTTP side on arbitrary bytes: the upgrade reader (any split), the `/key` response parser, the login-server URL parser and the early
//! payload reader.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_control::early::EarlyReader;
use tdongle_tailnet_control::http::{self, UpgradeReader};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, bytes)) = data.split_first() else { return };
    let mut u = UpgradeReader::new();
    let mut off = 0;
    while off < bytes.len() {
        let end = (off + 1 + sel as usize % 61).min(bytes.len());
        match u.push(&bytes[off..end]) {
            Ok((n, _)) => {
                assert!(n <= end - off);
                off += n.max(1);
            }
            Err(_) => break,
        }
    }
    let _ = http::parse_key_response(bytes);
    if let Ok(s) = core::str::from_utf8(bytes) {
        let _ = http::parse_host_port(s);
    }
    let mut json = [0u8; 1024];
    let mut e = EarlyReader::new(&mut json);
    for c in bytes.chunks(1 + sel as usize % 31) {
        if e.push(c).is_err() {
            break;
        }
    }
});
