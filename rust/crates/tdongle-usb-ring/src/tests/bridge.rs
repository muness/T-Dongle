//! The ring-level scenarios of `alternative/tailnet/tests/test_bridge_path.c`: the transparent bridge's ring (8 permanent slabs, at most 10
//! chunks, so at most 28 slabs) under backpressure, a tight heap, Wi-Fi link flaps (`flush`), a USB detach (`link_down`) and the `bridgetune`
//! ring knob. The bridge, Wi-Fi budget and status code the C test also covers are other crates.

use std::prelude::v1::*;

use std::sync::atomic::Ordering::SeqCst;

use super::world::{FLOOR_LARGEST, Rig, cfg_with};
use crate::{BRIDGE_BASE_SLABS, BRIDGE_MAX_CHUNKS, BRIDGE_MAX_SLABS, Config, SLAB_BYTES, SendError};

/// `ML_HB_FLOOR` of `ml_heap_budget.h`: recovery reserve 16,384 + negotiation peak 13,500.
const ML_HB_FLOOR: usize = 29_884;

fn bridge_cfg(floor_free: usize) -> Config {
    Config { idle_ms: 2000, floor_free, floor_largest: FLOOR_LARGEST, ..Config::bridge(5, floor_free, FLOOR_LARGEST) }
}

#[test]
fn bridge_geometry() {
    let r = Rig::new(bridge_cfg(ML_HB_FLOOR));
    let s = r.stats();
    assert!(s.base_bytes as usize == BRIDGE_BASE_SLABS * SLAB_BYTES && s.max_bytes as usize == BRIDGE_MAX_SLABS * SLAB_BYTES && s.ring_bytes == s.base_bytes);
    assert_eq!(BRIDGE_MAX_SLABS, 28);
}

/// The USB side stops taking frames (every NTB in flight): the ring grows to its cap, then drops, counted, without ever blocking the Wi-Fi
/// task.
#[test]
fn ring_backpressure() {
    let r = Rig::new(bridge_cfg(ML_HB_FLOOR));
    r.credit(0);
    let mut accepted = 0;
    let mut full = 0;
    for _ in 0..200 {
        match r.send_len(1514) {
            Ok(()) => accepted += 1, // one frame per slab: the ring's capacity in frames is its slab count
            Err(e) => {
                assert_eq!(e, SendError::Full);
                full += 1;
            }
        }
        r.pump();
        r.check_invariants();
        r.check_pm();
    }
    let st = r.stats();
    assert!(accepted == BRIDGE_MAX_SLABS && full == 200 - BRIDGE_MAX_SLABS as u32); // a bounded standing queue: 12 frames = 21 ms of USB time, 8 permanent
    assert!(st.ring_bytes == st.max_bytes && st.dropped_full == 200 - BRIDGE_MAX_SLABS as u32);
    assert!(st.grow_events == BRIDGE_MAX_CHUNKS as u32 && st.grow_denied_heap == 0);
    assert_eq!(r.delivered(), 0);
    r.drain_all();
    r.check_invariants();
    assert!(r.delivered() as usize == BRIDGE_MAX_SLABS && r.stats().flushed_link_down == 0); // all of them, in order
    // The elastic part goes back to the heap when the burst is over; the permanent part stays.
    for _ in 0..40 {
        r.advance_ms(600);
        r.pump();
    }
    assert!(r.chunks_present() == 0 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert!(r.stats().shrink_events == BRIDGE_MAX_CHUNKS as u32 && r.stats().ring_bytes == st.base_bytes);
}

/// A tight heap: growth stops at the floor (counted), the ring drops instead, and the heap never goes below the floor.
#[test]
fn ring_tight_heap() {
    let w = super::world::World::new();
    w.heap_total.store((ML_HB_FLOOR + BRIDGE_BASE_SLABS * SLAB_BYTES + 4000) as i64, SeqCst);
    let r = Rig::with_world(bridge_cfg(ML_HB_FLOOR), w);
    r.credit(0);
    let mut accepted = 0;
    for _ in 0..100 {
        if r.send_len(1514).is_ok() {
            accepted += 1;
        }
        r.pump();
        r.check_invariants();
    }
    let st = r.stats();
    assert!(accepted == 10 && st.dropped_full == 90 && st.chunks == 1 && st.grow_denied_heap > 0);
    assert!(r.w().free_size() >= ML_HB_FLOOR);
    r.drain_all();
    assert_eq!(r.delivered(), 10);
}

/// Wi-Fi link changes: frames queued under the old association never reach the host (`flush`).
#[test]
fn wifi_link_flap() {
    let r = Rig::new(bridge_cfg(ML_HB_FLOOR));
    r.credit(0); // USB stalled: frames pile up in the ring
    for _ in 0..8 {
        assert!(r.send_len(600).is_ok());
        r.pump();
    }
    assert_eq!(r.queued(), 8);
    r.ring.flush(); // the association ends
    r.credit(-1);
    r.skip_to_next();
    r.pump();
    assert!(r.delivered() == 0 && r.stats().flushed_link_down == 8); // frames from the old association never reach the host
    r.check_invariants();
    r.check_pm();
    // Back up: frames work, and frames queued in the dark are gone.
    r.ring.flush();
    for _ in 0..3 {
        assert!(r.send_len(300).is_ok());
    }
    r.drain_all();
    assert_eq!(r.delivered(), 3);
    // A flap that comes and goes before the worker runs: what was queued under the first association is stale, whatever the link says now.
    r.credit(0);
    for _ in 0..5 {
        assert!(r.send_len(300).is_ok());
        r.pump();
    }
    r.ring.flush();
    r.ring.flush(); // disconnect, connect
    r.credit(-1);
    r.skip_to_next();
    r.drain_all();
    assert!(r.stats().flushed_link_down == 8 + 5 && r.delivered() == 3);
    assert!(r.send_len(300).is_ok());
    r.drain_all();
    assert_eq!(r.delivered(), 4);
}

/// A USB detach flushes the ring and releases the CPU-frequency hold; frames offered while USB is gone are counted, not queued.
#[test]
fn usb_detach() {
    let r = Rig::new(bridge_cfg(ML_HB_FLOOR));
    r.credit(0);
    for _ in 0..5 {
        assert!(r.send_len(400).is_ok());
        r.pump();
        r.check_pm();
    }
    assert_eq!(r.w().pm_held.load(SeqCst), 1); // queued frames hold the clock
    r.w().usb_ready.store(false, SeqCst); // cable pulled (usb_event: TINYUSB_EVENT_DETACHED)
    r.ring.link_down();
    r.pump();
    assert!(r.stats().flushed_link_down == 5 && r.w().pm_held.load(SeqCst) == 0); // flushed, and the clock released
    assert_eq!(r.send_len(400), Err(SendError::LinkDown));
    assert_eq!(r.send_len(400), Err(SendError::LinkDown));
    assert_eq!(r.stats().dropped_link_down, 2); // counted, not queued for a host that is gone
    r.w().usb_ready.store(true, SeqCst); // plugged back in
    r.credit(-1);
    r.skip_to_next();
    assert!(r.send_len(400).is_ok());
    r.drain_all();
    assert!(r.delivered() == 1 && r.stats().flushed_link_down == 5);
    r.check_pm();
}

/// `bridgetune ring=N`: the cap moves at run time and the knob bites (ring=0 is the 8 permanent frames).
#[test]
fn bridgetune_ring_knob() {
    let r = Rig::new(bridge_cfg(ML_HB_FLOOR));
    assert!(r.ring.set_max_chunks(3).is_ok() && r.ring.max_chunks() == 3);
    assert_eq!(r.stats().max_bytes as usize, (BRIDGE_BASE_SLABS + 3 * crate::CHUNK_SLABS) * SLAB_BYTES);
    assert!(r.ring.set_max_chunks(13).is_err() && r.ring.max_chunks() == 3); // a rejected value changes nothing
    assert!(r.ring.set_max_chunks(0).is_ok());
    r.credit(0);
    let mut accepted = 0;
    for _ in 0..40 {
        if r.send_len(1514).is_ok() {
            accepted += 1;
        }
        r.pump();
    }
    assert!(accepted == BRIDGE_BASE_SLABS && r.stats().max_bytes as usize == BRIDGE_BASE_SLABS * SLAB_BYTES);
    r.drain_all();
    let _ = cfg_with(3, 3);
}
