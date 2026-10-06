//! STUN binding-response parser (and the STUN scheduler and netcheck handling of the same bytes): any bytes never panic; an accepted response carries the datagram's own transaction id and rebuilds to the same mapped endpoint.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_disco::fuzz::stun_response(data);
});
