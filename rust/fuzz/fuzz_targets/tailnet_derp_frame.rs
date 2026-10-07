//! The DERP frame reader takes whatever a relay (or anyone on the path past TLS) sends: any chunking, any length field.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_derp::{FrameReader, Message, Poll};

fuzz_target!(|data: &[u8]| {
    // the first byte picks the chunk size so one input explores many cuts of the same stream
    let (cut, stream) = match data.split_first() {
        Some((&c, rest)) => (1 + c as usize % 97, rest),
        None => return,
    };
    let mut reader = FrameReader::new();
    for chunk in stream.chunks(cut) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let (n, poll) = reader.feed(rest);
            assert!(n <= rest.len());
            match poll {
                Poll::NeedMore => {}
                Poll::Frame(info) => {
                    let _ = Message::parse(info.ty, reader.body());
                }
                Poll::Error(_) => return,
            }
            rest = &rest[n..];
        }
    }
});
