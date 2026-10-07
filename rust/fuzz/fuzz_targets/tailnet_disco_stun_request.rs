//! STUN binding-request parser: any bytes never panic; an accepted request is a STUN message whose last attribute is a correct FINGERPRINT.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_disco::fuzz::stun_request(data);
});
