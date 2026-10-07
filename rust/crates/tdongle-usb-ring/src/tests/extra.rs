//! Tests the C did not have: the counters the C comments promise but never assert, and the two contract guards of the Rust port.

use std::prelude::v1::*;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;

use super::world::{Rig, World, cfg_with};
use crate::{Ring, SendError};

/// "A stale (flushed) frame is not a cold start": only a frame handed to an NTB is measured.
#[test]
fn stale_frame_is_not_a_cold_start() {
    let r = Rig::new(cfg_with(3, 4));
    r.w().us.store(1000, SeqCst);
    assert!(r.send_len(300).is_ok());
    r.ring.flush();
    r.skip_to_next();
    r.w().us.store(9000, SeqCst);
    r.pump();
    let st = r.stats();
    assert!(st.cold_starts == 0 && st.cold_us_sum == 0 && st.flushed_link_down == 1 && st.sent_frames == 0);
    // The next edge is measured normally.
    r.w().us.store(20_000, SeqCst);
    assert!(r.send_len(300).is_ok());
    r.w().us.store(20_250, SeqCst);
    r.pump();
    let st = r.stats();
    assert!(st.cold_starts == 1 && st.cold_us_sum == 250 && st.cold_us_max == 250);
    // The microsecond clock wraps: the wait is a wrapping difference.
    r.w().us.store(u32::MAX - 100, SeqCst);
    assert!(r.send_len(300).is_ok());
    r.w().us.store(150, SeqCst);
    r.pump();
    assert_eq!(r.stats().cold_us_max, 251);
}

/// A second `send` that overlaps the first (a contract violation: single producer) is refused instead of racing on a slab.
#[test]
fn concurrent_send_is_refused() {
    let r = Rig::new(cfg_with(3, 4));
    let seen = Arc::new(std::sync::Mutex::new(None));
    let s = Arc::clone(&seen);
    *r.w().now_hook.lock().unwrap() = Some(Arc::new(move |ring: &Ring<World>| {
        // runs between reserve and commit of the outer send
        *s.lock().unwrap() = Some(ring.send(&[0u8; 100]));
    }));
    assert!(r.send_len(200).is_ok());
    assert_eq!(*seen.lock().unwrap(), Some(Err(SendError::Busy)));
    // Nothing was counted for the refused call, the outer frame is intact and the producer is usable again.
    assert!(r.send_len(201).is_ok());
    r.drain_all();
    let st = r.stats();
    assert!(st.enqueued_frames == 2 && r.delivered() == 2 && st.dropped_full == 0 && st.dropped_invalid == 0);
}

/// A drain that overlaps another (a contract violation: single consumer) returns at once; the frame is still delivered exactly once.
#[test]
fn overlapping_drain_is_a_no_op() {
    let r = Rig::new(cfg_with(3, 4));
    assert!(r.send_len(300).is_ok());
    assert!(r.send_len(301).is_ok());
    *r.w().pre_copy_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| {
        ring.drain(); // would re-peek the record being copied and hand it over twice
        ring.do_drain();
    }));
    r.ring.drain();
    *r.w().pre_copy_hook.lock().unwrap() = None;
    assert_eq!(r.delivered(), 2);
    assert_eq!(r.stats().sent_frames, 2);
    r.check_invariants();
}

/// `Config::bridge` is the firmware's ring: 8 permanent slabs, 10 chunks, 28 slabs.
#[test]
fn bridge_config() {
    let c = crate::Config::bridge(5, 29_884, 20_000);
    assert_eq!(c.validate(), Ok(()));
    assert!(c.base_frames == 8 && c.max_chunks == 10 && c.pm && c.idle_ms == 0 && c.work_priority == 0);
    let r = Rig::new(c);
    let s = r.stats();
    assert!(s.base_bytes == 8 * 1524 && s.max_bytes == 28 * 1524);
    // idle_ms 0 means the 2 s default.
    r.credit(0);
    for _ in 0..28 {
        assert!(r.send_len(1518).is_ok());
        r.step();
    }
    r.drain_all();
    r.advance_ms(1999);
    r.step();
    assert_eq!(r.stats().chunks, 10);
    r.advance_ms(1);
    r.step();
    assert_eq!(r.stats().chunks, 9);
}
