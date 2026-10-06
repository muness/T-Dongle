//! Port of `tests/mocks/net_ring_cases.c`, first half: lifecycle, the producer, capacity and packing, burst absorption, denied growth.

use std::prelude::v1::*;

use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;

use super::world::{FLOOR_FREE, FLOOR_LARGEST, Rig, World, cfg_with};
use crate::{CHUNK_BYTES, Config, ConfigError, Ring, RestartError, SLAB_BYTES, SendError, Wait, WORKER_STACK};

const SLAB: usize = SLAB_BYTES;

#[test]
fn lifecycle() {
    let f = [0u8; 100];
    let mut c = cfg_with(3, 10);
    // Configurations the start refuses (`ESP_ERR_INVALID_ARG`); the base memory is never touched on that path.
    c.base_frames = 1;
    assert_eq!(Ring::new(World::new(), c, &mut []).err(), Some(ConfigError::BaseFrames)); // below two frames
    c.base_frames = 9;
    assert_eq!(Ring::new(World::new(), c, &mut []).err(), Some(ConfigError::BaseFrames));
    c.base_frames = 3;
    c.max_chunks = 13;
    assert_eq!(Ring::new(World::new(), c, &mut []).err(), Some(ConfigError::MaxChunks));
    c.max_chunks = 10;
    assert_eq!(Ring::new(World::new(), c, &mut []).err(), Some(ConfigError::BaseTooSmall)); // Rust-only: the base is supplied
    assert_eq!(WORKER_STACK, 1536);

    let r = Rig::new(c);
    assert!(r.w().heap_live_blocks.load(SeqCst) == 1 && r.w().heap_live_bytes.load(SeqCst) == 3 * 1524);
    // Starting again with the same configuration is idempotent, another one is refused.
    assert_eq!(r.ring.restart(&c), Ok(()));
    let mut other = c;
    other.max_chunks = 9;
    assert_eq!(r.ring.restart(&other), Err(RestartError::Mismatch));
    other = c;
    other.floor_free += 1;
    assert_eq!(r.ring.restart(&other), Err(RestartError::Mismatch));
    other = c;
    other.pm = false;
    assert_eq!(r.ring.restart(&other), Err(RestartError::Mismatch));
    other.base_frames = 1;
    assert_eq!(r.ring.restart(&other), Err(RestartError::Invalid(ConfigError::BaseFrames)));
    // Invalid frames: empty (the C's NULL buffer), runt, oversize.
    assert_eq!(r.ring.send(&[]), Err(SendError::InvalidLength));
    assert_eq!(r.ring.send(&f[..13]), Err(SendError::InvalidLength));
    assert_eq!(r.ring.send(&[0u8; 1519]), Err(SendError::InvalidLength));
    r.w().usb_ready.store(false, SeqCst);
    assert_eq!(r.ring.send(&f), Err(SendError::LinkDown));
    r.w().usb_ready.store(true, SeqCst);
    let st = r.stats();
    assert!(st.ring_bytes == 3 * 1524 && st.base_bytes == 3 * 1524 && st.max_bytes == 23 * 1524);
    assert!(st.dropped_invalid == 3 && st.dropped_link_down == 1 && st.enqueued_frames == 0 && st.chunks == 0);
    assert!(st.worker_stack_free == 777 && st.elastic_held_bytes == 0);
    r.ring.deinit(); // stops accepting
    assert_eq!(r.ring.send(&f), Err(SendError::NotStarted));
    assert_eq!(r.ring.restart(&c), Ok(())); // the same ring is re-enabled, nothing reallocated
    assert_eq!(r.w().heap_live_blocks.load(SeqCst), 1);
    assert!(r.ring.send(&f).is_ok());

    // No PM hooks: the ring works and holds nothing.
    c = cfg_with(3, 4);
    c.pm = false;
    let r = Rig::new(c);
    assert!(r.send_len(300).is_ok());
    r.pump();
    assert!(r.w().pm_acquires.load(SeqCst) == 0 && r.stats().pm_acquired == 0 && r.delivered() == 1);
}

#[test]
fn basic_and_no_blocking() {
    let r = Rig::new(cfg_with(3, 0));
    let pend = r.w().pending();
    let crit0 = r.w().crit_total.load(SeqCst);
    for i in 0..3 {
        assert!(r.send_len(200 + i).is_ok());
    }
    // Producer: two short critical sections per frame (reserve, commit), nothing else shared.
    assert_eq!(r.w().crit_total.load(SeqCst) - crit0, 6);
    // The producer only notified the worker: it did not touch TinyUSB's queue and nothing ran yet.
    assert!(r.w().pending() == pend && r.delivered() == 0 && r.w().notify_count.load(SeqCst) == 3);
    assert_eq!(r.w().pm_acquires.load(SeqCst), 0); // the producer never takes the PM lock; the worker does
    r.check_invariants();
    r.step();
    assert!(r.w().pm_acquires.load(SeqCst) == 1 && r.w().pm_releases.load(SeqCst) == 0); // the producer woke the worker, which took the lock
    r.run_deferred();
    assert!(r.delivered() == 3 && r.queued() == 0 && !r.ring.is_blocked());
    r.check_invariants();
    r.step(); // the "queue emptied" wakeup
    r.check_pm();
    assert!(r.w().pm_acquires.load(SeqCst) == 1 && r.w().pm_releases.load(SeqCst) == 1);
    // With nothing queued and no elastic memory the worker sleeps indefinitely.
    r.w().notify_count.store(0, SeqCst);
    r.step();
    assert_eq!(r.last_wait.get(), Wait::Forever);
    let st = r.stats();
    assert!(st.enqueued_frames == 3 && st.sent_frames == 3 && st.sent_bytes == 200 + 201 + 202 && st.dropped_full == 0);
    // Idle worker with an empty ring does not queue a callback.
    r.w().notify_count.store(1, SeqCst);
    r.step();
    assert_eq!(r.w().pending(), 0);
}

/// A fixed ring (no elastic chunks) holds exactly its slabs of full frames, and many small frames per slab.
#[test]
fn fixed_capacity_and_packing() {
    let r = Rig::new(cfg_with(3, 0));
    r.credit(0); // every NTB is in flight: hold everything in the ring
    for _ in 0..3 {
        assert!(r.send_len(1518).is_ok());
    }
    assert!(r.send_len(1518) == Err(SendError::Full) && r.send_len(14) == Err(SendError::Full)); // no room even for a small one
    assert_eq!(r.stats().dropped_full, 2);
    r.check_invariants();
    r.drain_all();
    r.check_pm();
    assert_eq!(r.delivered(), 3);
    // 64-byte frames: 68-byte records, 22 per slab, 66 in three slabs.
    let r = Rig::new(cfg_with(3, 0));
    r.credit(0);
    let mut n = 0;
    while r.send_len(64).is_ok() {
        n += 1;
    }
    assert_eq!(n, 3 * (1524 / 68));
    // Records of 1004 and 520 bytes fill a slab to the last byte: three such pairs fill three slabs.
    r.drain_all();
    r.credit(0);
    for _ in 0..3 {
        assert!(r.send_len(1000).is_ok());
        assert!(r.send_len(516).is_ok());
    }
    assert_eq!(r.send_len(14), Err(SendError::Full));
    // Mid-size frames: 1280-byte tunnel frames, 1284-byte records: one per slab (240 B left over: a 200-byte frame fits).
    r.drain_all();
    r.credit(0);
    for _ in 0..3 {
        assert!(r.send_len(1280).is_ok());
    }
    assert!(r.send_len(200).is_ok()); // fits behind the newest 1280 in its slab: 1284 + 204 <= 1524
    assert_eq!(r.send_len(300), Err(SendError::Full));
    r.check_invariants();
    // Space returns the moment a slab is handed to USB, whatever the write position.
    r.credit(1);
    r.in_complete();
    r.check_invariants();
    assert!(r.send_len(1280).is_ok());
    assert_eq!(r.send_len(1280), Err(SendError::Full));
    r.drain_all();
    r.check_invariants();
    let st = r.stats();
    assert!(st.grow_events == 0 && st.chunks == 0 && st.ring_bytes == st.max_bytes);
    // Open slab restarts at offset 0 when the ring runs empty: a full frame fits again after small ones.
    for _ in 0..5 {
        assert!(r.send_len(100).is_ok());
    }
    r.drain_all();
    for _ in 0..3 {
        assert!(r.send_len(1518).is_ok());
    }
    r.drain_all();
}

/// The point of the change: a burst up to the cap is absorbed with no drop; beyond it, a counted drop.
#[test]
fn burst_absorption() {
    let r = Rig::new(cfg_with(3, 10)); // 3 + 10 x 2 = 23 frames
    r.credit(0);
    let free0 = r.w().free_size() as i64;
    for _ in 0..23 {
        assert!(r.send_len(1518).is_ok());
        r.step(); // the worker wakes on every enqueue, as in the product
        r.check_invariants();
    }
    let st = r.stats();
    assert!(st.dropped_full == 0 && st.chunks == 10 && st.grow_events == 10 && st.ring_bytes == st.max_bytes);
    assert!(st.high_water_slabs == 23 && st.high_water_bytes == 23 * 1524 && st.elastic_held_bytes == 10 * 3048);
    assert_eq!(free0 - r.w().free_size() as i64, 10 * 3048);
    r.w().notify_count.store(0, SeqCst);
    assert!(r.send_len(1518) == Err(SendError::Full) && r.stats().dropped_full == 1); // the cap
    assert_eq!(r.w().notify_count.load(SeqCst), 1); // a refusal still wakes the worker
    assert_eq!(r.send_len(14), Err(SendError::Full));
    let mc = r.w().malloc_calls.load(SeqCst);
    r.step();
    assert!(r.stats().grow_events == 10 && r.w().malloc_calls.load(SeqCst) == mc); // at the cap: no further growth, no attempt
    r.check_invariants();
    r.drain_all();
    assert_eq!(r.delivered(), 23);
    r.check_pm();
    // Growth keeps ahead of an ongoing burst only because the worker wakes: without it the ring is the base.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    for _ in 0..3 {
        assert!(r.send_len(1518).is_ok());
    }
    assert_eq!(r.send_len(1518), Err(SendError::Full)); // the producer never allocates
    assert_eq!(r.w().heap_live_blocks.load(SeqCst), 1);
    r.step(); // the drop asked for growth
    assert!(r.stats().chunks >= 1 && r.send_len(1518).is_ok());
    r.drain_all();
    // The producer's own critical sections stay at two per accepted frame while growing.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    for _ in 0..12 {
        let c0 = r.w().crit_total.load(SeqCst);
        assert!(r.send_len(1518).is_ok() && r.w().crit_total.load(SeqCst) - c0 == 2);
        r.step();
    }
    r.drain_all();
}

/// Get the ring to ask for growth without letting it succeed.
pub fn fill_pressure(r: &Rig, frames: usize) {
    r.credit(0);
    for _ in 0..frames {
        let _ = r.send_len(1518);
    }
}

#[test]
fn growth_denied() {
    // Free heap below the floor: no growth, counted, and the heap is untouched.
    let r = Rig::new(cfg_with(3, 10));
    let live = r.w().heap_live_bytes.load(SeqCst);
    r.w().heap_total.store(live + FLOOR_FREE as i64 + 3048 + 16 - 1, SeqCst); // one byte short
    fill_pressure(&r, 3);
    r.step();
    let st = r.stats();
    assert!(st.grow_events == 0 && st.grow_denied_heap == 1 && r.w().heap_live_blocks.load(SeqCst) == 1);
    // Denials are rate limited: a flood of pressure does not hammer the allocator.
    for _ in 0..50 {
        let _ = r.send_len(1518);
        r.step();
    }
    assert_eq!(r.stats().grow_denied_heap, 1);
    // After the retry interval, with the heap back, growth resumes.
    r.w().heap_total.store(200_000, SeqCst);
    r.advance_ms(100);
    let _ = r.send_len(1518);
    r.step();
    assert!(r.stats().grow_events >= 1);
    // Exactly at the floor is allowed: free after growth equals floor_free.
    let r = Rig::new(cfg_with(3, 10));
    let live = r.w().heap_live_bytes.load(SeqCst);
    r.w().heap_total.store(live + FLOOR_FREE as i64 + 3048 + 16, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    assert_eq!(r.stats().grow_events, 1);
    assert!(r.w().free_size() >= FLOOR_FREE);
    for _ in 0..20 {
        r.advance_ms(100);
        let _ = r.send_len(1518);
        r.step();
    }
    assert!(r.w().free_size() >= FLOOR_FREE); // a second chunk would go below the floor: refused
    assert!(r.stats().grow_events == 1 && r.stats().grow_denied_heap >= 1);
    r.drain_all();
    // Largest block already below the floor.
    let r = Rig::new(cfg_with(3, 10));
    r.w().mock_largest.store(FLOOR_LARGEST - 1, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    let st = r.stats();
    assert!(st.grow_events == 0 && st.grow_denied_largest == 1 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert_eq!(r.w().malloc_calls.load(SeqCst), 0); // the check came before any allocation (the C counted its own base allocation too: 1)
    // This allocation is the one that takes the largest block below the floor: undone.
    let r = Rig::new(cfg_with(3, 10));
    r.w().mock_largest.store(FLOOR_LARGEST + 1000, SeqCst);
    r.w().frag_next.store(FLOOR_LARGEST - 500, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    let st = r.stats();
    assert!(st.grow_events == 0 && st.grow_denied_largest == 1 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert_eq!(r.w().heap_live_bytes.load(SeqCst), 3 * 1524);
    // Allocator failure.
    let r = Rig::new(cfg_with(3, 10));
    r.w().malloc_fail.store(true, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    assert!(r.stats().grow_denied_nomem == 1 && r.stats().grow_events == 0);
    // Gate closed (a negotiation or admission is running): no growth.
    let r = Rig::new(cfg_with(3, 10));
    r.w().gate_busy.store(true, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    let st = r.stats();
    assert!(st.grow_denied_gate >= 1 && st.grow_events == 0 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert_eq!(r.w().malloc_calls.load(SeqCst), 0); // refused before allocating
    // The gate opens: growth after the retry interval.
    r.w().gate_busy.store(false, SeqCst);
    r.advance_ms(100);
    let _ = r.send_len(1518);
    r.step();
    assert!(r.stats().grow_events >= 1);
    r.drain_all();
    // A negotiation takes the token while the worker is allocating (after its gate check): the chunk is undone.
    let r = Rig::new(cfg_with(3, 10));
    *r.w().malloc_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| ring.env().gate_busy.store(true, SeqCst)));
    fill_pressure(&r, 3);
    r.step();
    let st = r.stats();
    assert!(st.grow_events == 0 && st.grow_denied_gate == 1 && r.w().heap_live_blocks.load(SeqCst) == 1 && r.w().malloc_calls.load(SeqCst) == 1);
    // No elastic chunks configured: pressure never allocates.
    let r = Rig::new(cfg_with(3, 0));
    fill_pressure(&r, 10);
    r.step();
    assert!(r.w().heap_live_blocks.load(SeqCst) == 1 && r.stats().grow_events == 0 && r.stats().grow_denied_heap == 0);
    r.drain_all();
    let _ = (SLAB, CHUNK_BYTES, Config::bridge(1, 0, 0));
}
