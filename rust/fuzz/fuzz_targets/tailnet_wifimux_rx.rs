//! The Wi-Fi mux's receive classifier and bookkeeping take any frame: no panic, every frame accounted exactly once. Input: frames separated by a
//! 2-byte big-endian length; a frame whose first byte has the top bit set is also offered to the transmit side as an L3 packet.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_wifimux::fuzzing::Bench;
use tdongle_tailnet_wifimux::{FRAME_MAX, RxClass, RxDrop, classify_rx};

fuzz_target!(|data: &[u8]| {
    let mut b = Bench::new();
    let mut now = 0u64;
    let mut rest = data;
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let (frame, after) = rest[2..].split_at(n);
        match classify_rx(frame, &[2, 0, 0, 0, 0, 1]) {
            RxClass::Drop(RxDrop::Runt) => assert!(frame.len() < 14),
            RxClass::Drop(RxDrop::Oversize) => assert!(frame.len() > FRAME_MAX),
            _ => {}
        }
        let _ = b.rx(now, frame);
        if frame.first().is_some_and(|x| x & 0x80 != 0) && frame.len() > 14 {
            let _ = b.send(&frame[14..]);
            let _ = b.tx_step(now);
        }
        assert!(b.accounted());
        now += 997;
        rest = after;
    }
});
