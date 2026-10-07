//! The RFC 6479 replay window against an exact reference model, on counters drawn from the input (jumps, reordering, the 2^64 limit).
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use tdongle_tailnet_wg::consts::REJECT_AFTER_MESSAGES;
use tdongle_tailnet_wg::{ReplayVerdict, ReplayWindow};

fuzz_target!(|data: &[u8]| {
    let mut r = ReplayWindow::new();
    let mut seen = BTreeSet::new();
    let mut max = 0u64;
    let mut base = 0u64;
    for c in data.chunks(3) {
        let sel = c[0];
        let off = u16::from_le_bytes([c.get(1).copied().unwrap_or(0), c.get(2).copied().unwrap_or(0)]) as u64;
        // regimes: near the front, near the bottom, near the limit, absolute
        let v = match sel & 3 {
            0 => base.wrapping_add(off),
            1 => base.wrapping_sub(off % 1024),
            2 => REJECT_AFTER_MESSAGES.wrapping_sub(1 + off % 2048),
            _ => off | ((sel as u64) << 40),
        };
        if sel & 4 != 0 {
            base = max;
        }
        let want = if v >= REJECT_AFTER_MESSAGES {
            ReplayVerdict::Limit
        } else if v < max && max - v > ReplayWindow::WINDOW {
            ReplayVerdict::TooOld
        } else if seen.contains(&v) {
            ReplayVerdict::Duplicate
        } else {
            seen.insert(v);
            max = max.max(v);
            ReplayVerdict::Ok
        };
        let peek = r.peek(v);
        assert_eq!(r.check(v), want, "counter {v}");
        assert_eq!(peek, want);
    }
});
