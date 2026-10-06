//! The captive DNS responder takes any UDP datagram a phone, or anyone on the open setup network, sends to port 53.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_setup::dns;

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; dns::REPLY_MAX];
    if let Some(n) = dns::serve(data, &mut out) {
        assert!(n <= dns::REPLY_MAX && n <= data.len().min(dns::QUERY_MAX) + 16);
        assert!(out[2] & 0x80 != 0);
    }
});
