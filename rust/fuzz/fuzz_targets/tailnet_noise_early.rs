//! The early payload header arrives from the control server after the handshake; any chunking must be safe and bounded.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_noise::early::{EarlyReader, EarlyState};

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else { return };
    let step = usize::from(chunk).max(1);
    let mut reader = EarlyReader::new();
    let mut pos = 0;
    while pos < rest.len() {
        let end = (pos + step).min(rest.len());
        match reader.feed(&rest[pos..end]) {
            Ok((used, EarlyState::NeedMore)) => pos += used,
            _ => return,
        }
    }
});
