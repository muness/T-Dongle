//! Handshake messages come from the network: both directions' parsers must refuse garbage without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_noise::{Initiator, ResponseHeader, responder};
use tdongle_tailnet_types::Key32;

fuzz_target!(|data: &[u8]| {
    let cpriv = Key32([7; 32]);
    let mpriv = Key32([9; 32]);
    let cpub = x25519::public(&cpriv);
    let eph = Key32([3; 32]);
    let _ = responder::accept_with_ephemeral(&cpriv, data, eph.clone());
    if let Ok((init, _)) = Initiator::with_ephemeral(&mpriv, &cpub, 131, eph) {
        let _ = init.finish(data);
    }
    if data.len() >= 3 {
        let _ = ResponseHeader::parse(&[data[0], data[1], data[2]]);
    }
});
