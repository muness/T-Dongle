//! The HTTP/2 session on an arbitrary byte stream split at arbitrary points (the first input byte picks the chunk size): never panics, consumption never
//! exceeds the input, the outbox stays bounded, and a dead session stays dead.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_control::h2::{Config, Event, OUT_CAP, Session};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, bytes)) = data.split_first() else { return };
    let mut s = Session::new(Config::default());
    let mut sink = [0u8; 128];
    for chunk in bytes.chunks(1 + sel as usize % 97) {
        let mut rest = chunk;
        loop {
            let (n, ev) = s.on_input(rest);
            assert!(n <= rest.len());
            rest = &rest[n..];
            assert!(s.pending_output() <= OUT_CAP);
            let _ = s.poll_output(&mut sink);
            match ev {
                Event::Idle | Event::Closed => break,
                _ => {}
            }
        }
        if s.is_dead() {
            assert!(matches!(s.on_input(&[1]).1, Event::Closed));
        }
    }
});
