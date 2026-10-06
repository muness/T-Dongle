//! The HPACK block decoder on arbitrary bytes: never panics, never loops (one byte in, bounded work out).
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_control::hpack::HpackDecoder;

fuzz_target!(|data: &[u8]| {
    let mut d = HpackDecoder::new(4096, 16384);
    d.start_block();
    for &b in data {
        if d.feed(b).is_err() {
            break;
        }
    }
    let _ = d.end_block();
});
