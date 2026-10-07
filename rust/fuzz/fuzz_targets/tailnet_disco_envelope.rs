//! The DISCO receive pipeline. Odd first byte: the rest is sealed with the harness keys, so the box always opens and only the message parse may refuse it. Even: a raw datagram, which any counted reason may refuse; the counters see every datagram exactly once.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_disco::fuzz::envelope(data);
});
