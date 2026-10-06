#![no_main]
//! tdongle-tailnet-members: the settings decoder and the /command request parser over arbitrary bytes. Never panics; a decoded registry re-encodes.
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_members::{ENCODE_BUFFER, MemberRegistry, Origin, parse_request};

fuzz_target!(|data: &[u8]| {
    let mut reg = MemberRegistry::new();
    if reg.load(data).is_ok() {
        let mut buf = [0u8; ENCODE_BUFFER];
        let n = reg.encode(&mut buf).expect("an accepted registry fits");
        let mut again = MemberRegistry::new();
        again.load(&buf[..n]).expect("what we write we read");
    }
    let _ = parse_request(Origin::Usb, Some(b"application/json"), data.len().min(1024), data);
    let _ = parse_request(Origin::SetupAp, Some(b"application/json"), data.len().min(1024), data);
});
