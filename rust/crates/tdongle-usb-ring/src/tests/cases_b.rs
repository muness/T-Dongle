//! Port of `tests/mocks/net_ring_cases.c`, second part: reclaim for admission, idle shrink, hardening.

use std::prelude::v1::*;

use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;

use super::cases_a::fill_pressure;
use super::world::{IDLE_MS, Rig, World, cfg_with};
use crate::{Ring, SendError, Wait};

fn grow_to(r: &Rig, frames: usize) {
    for _ in 0..frames {
        assert!(r.send_len(1518).is_ok());
        r.step();
    }
}

/// Admission needs the heap: idle chunks go at once, chunks with frames in them drain first, nothing in flight is lost.
#[test]
fn reclaim_for_admission() {
    let r = Rig::new(cfg_with(3, 10));
    let free0 = r.w().free_size() as i64;
    r.credit(0);
    grow_to(&r, 23);
    assert_eq!(r.stats().chunks, 10);
    // Admission: the token is held (gate), then reclaim, then the heap is measured.
    r.w().gate_busy.store(true, SeqCst);
    let held = r.ring.elastic_reclaim(0);
    let st = r.stats();
    assert!(held == 10 * 3048 && st.reclaim_events == 1 && st.chunks == 0 && st.reclaimed_chunks == 0); // all hold frames
    assert!(st.elastic_held_bytes == 10 * 3048 && st.ring_bytes == 3 * 1524);
    r.check_invariants();
    // No new frame goes into a retiring chunk, and nothing grows while the gate is closed.
    assert_eq!(r.send_len(1518), Err(SendError::Full));
    r.step();
    assert!(r.stats().chunks == 0 && r.w().heap_live_blocks.load(SeqCst) == 11);
    // The host takes the frames; each retiring chunk is freed when its last frame left.
    r.credit(-1);
    for _ in 0..40 {
        if r.queued() == 0 {
            break;
        }
        r.in_complete();
        r.check_invariants();
    }
    assert!(r.queued() == 0 && r.delivered() == 23);
    r.step(); // the consumer's wakeup: reap
    r.check_invariants();
    let st = r.stats();
    assert!(r.w().heap_live_blocks.load(SeqCst) == 1 && st.reclaimed_chunks == 10 && st.elastic_held_bytes == 0);
    assert_eq!(r.w().free_size() as i64, free0); // admission measures the heap with nothing borrowed
    r.check_pm();
    r.w().gate_busy.store(false, SeqCst);
    r.drain_all();

    // The wait form: reclaim sleeps while TinyUSB drains the chunks in the background.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.w().gate_busy.store(true, SeqCst);
    *r.w().delay_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| {
        ring.env().ntb_credit.store(-1, SeqCst); // the TinyUSB task alone
        ring.on_in_complete(64);
    }));
    assert_eq!(r.ring.elastic_reclaim(1000), 0);
    *r.w().delay_hook.lock().unwrap() = None;
    assert!(r.w().heap_live_blocks.load(SeqCst) == 1 && r.delivered() == 23 && r.stats().reclaimed_chunks == 10);
    // A reclaim that times out reports what it still holds.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.w().gate_busy.store(true, SeqCst);
    assert_eq!(r.ring.elastic_reclaim(5), 10 * 3048);
    r.drain_all();
    assert_eq!(r.w().heap_live_blocks.load(SeqCst), 1);

    // Idle chunks (no frames queued) are freed immediately.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.drain_all();
    assert_eq!(r.stats().chunks, 10);
    r.w().gate_busy.store(true, SeqCst);
    assert!(r.ring.elastic_reclaim(0) == 0 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert!(r.stats().reclaim_events == 1 && r.stats().reclaimed_chunks == 10);
    assert!(r.ring.elastic_reclaim(0) == 0 && r.stats().reclaim_events == 1); // nothing to retire: not an event

    // The consumer is in the middle of copying a frame out of an elastic chunk when admission reclaims. The copy must read live memory (the
    // mock poisons freed memory, so the observer's byte check would trip), and the frame is delivered intact.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.w().gate_busy.store(true, SeqCst);
    let reclaims = Arc::new(AtomicU32::new(0));
    let n = Arc::clone(&reclaims);
    *r.w().pre_copy_hook.lock().unwrap() = Some(Arc::new(move |ring: &Ring<World>| {
        if n.fetch_add(1, SeqCst) == 0 {
            let _ = ring.elastic_reclaim(0);
        }
    }));
    r.credit(-1);
    r.drain_all();
    *r.w().pre_copy_hook.lock().unwrap() = None;
    assert!(r.delivered() == 23 && r.w().heap_live_blocks.load(SeqCst) == 1 && r.stats().reclaimed_chunks == 10);

    // Teardown while the consumer is copying a frame out of a chunk (the 8th: slab 7, in an elastic chunk): the queue is flushed and the chunks
    // retired under it. The copy reads live memory, the chunk is freed only afterwards, and the consumer's advance finds the queue already flushed.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    let copies = Arc::new(AtomicU32::new(0));
    let n = Arc::clone(&copies);
    *r.w().pre_copy_hook.lock().unwrap() = Some(Arc::new(move |ring: &Ring<World>| {
        if n.fetch_add(1, SeqCst) + 1 == 8 {
            ring.deinit();
        }
    }));
    r.credit(-1);
    r.in_complete();
    *r.w().pre_copy_hook.lock().unwrap() = None;
    assert!(r.delivered() == 8 && r.queued() == 0 && r.stats().flushed_link_down == 15 && r.fifo_n() == 0);
    assert!(r.chunks_present() > 0); // the chunk holding the frame being copied outlived the teardown
    assert!(r.ring.probe().reap_pending); // the consumer's advance released the last slab: reap is due
    r.step();
    r.check_invariants();
    assert!(r.chunks_present() == 0 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert_eq!(r.ring.restart(&cfg_with(3, 10)), Ok(()));

    // A growth that allocated before admission started and publishes after it is discarded (epoch).
    let r = Rig::new(cfg_with(3, 10));
    fill_pressure(&r, 3);
    *r.w().malloc_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| {
        let _ = ring.elastic_reclaim(0);
    }));
    r.step();
    let s2 = r.stats();
    assert!(s2.grow_raced == 1 && s2.grow_events == 0 && r.w().heap_live_blocks.load(SeqCst) == 1 && s2.chunks == 0);
    r.drain_all();
}

/// Idle shrink is staged: each worker pass frees at most one chunk.
#[test]
fn idle_shrink() {
    let shrink_passes = |r: &Rig, n: usize| {
        for _ in 0..n {
            r.step();
        }
    };
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.drain_all();
    let st = r.stats();
    assert!(st.chunks == 10 && st.shrink_events == 0);
    // Chunks wait for the idle period, measured from the last frame they held.
    r.advance_ms(IDLE_MS - 1);
    r.step();
    assert!(r.stats().chunks == 10 && r.stats().shrink_events == 0);
    r.advance_ms(1);
    r.step();
    let st = r.stats();
    // Staged: one chunk per pass, the highest first, so a burst of frees never hits the heap at once.
    assert!(st.chunks == 9 && st.shrink_events == 1 && !r.chunk_present(9) && r.chunk_present(8));
    shrink_passes(&r, 9);
    let st = r.stats();
    assert!(st.chunks == 0 && st.shrink_events == 10 && r.w().heap_live_blocks.load(SeqCst) == 1 && st.ring_bytes == 3 * 1524);
    assert_eq!(st.reclaim_events, 0); // idle is not an admission reclaim
    r.check_invariants();
    r.step();
    assert_eq!(r.last_wait.get(), Wait::Forever); // nothing elastic left: no timer

    // Light load keeps only what it uses: four frames held (3 base + 1 chunk slab); the rest go.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.drain_all();
    r.credit(0);
    for _ in 0..4 {
        assert!(r.send_len(1518).is_ok());
    }
    r.advance_ms(IDLE_MS + 10);
    shrink_passes(&r, 12);
    let st = r.stats();
    assert!(st.chunks == 1 && st.shrink_events == 9 && r.chunk_present(0) && !r.chunk_present(1));
    // Frames in flight keep their chunk however long it has been.
    r.advance_ms(10 * IDLE_MS);
    r.step();
    assert_eq!(r.stats().chunks, 1);
    r.check_invariants();
    r.drain_all();
    // An empty open slab inside a chunk does not pin it.
    r.advance_ms(IDLE_MS + 10);
    shrink_passes(&r, 2);
    assert!(r.stats().chunks == 0 && r.w().heap_live_blocks.load(SeqCst) == 1);
    r.check_invariants();

    // Lowest slab first: a trickle of traffic never touches the chunks, so they all age out.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 23);
    r.drain_all();
    for round in 0..8 {
        r.advance_ms(400);
        assert!(r.send_len(500).is_ok());
        r.pump();
        assert!(round >= 4 || r.stats().shrink_events == 0); // before 2000 ticks idle nothing goes
    }
    shrink_passes(&r, 10);
    assert!(r.stats().chunks == 0 && r.stats().shrink_events == 10);
    // Growth after a shrink works (the slots are free again).
    r.credit(0);
    grow_to(&r, 23);
    assert!(r.stats().chunks == 10 && r.stats().dropped_full == 0);
    r.drain_all();

    // The worker's wait: a timer only while elastic memory exists.
    let r = Rig::new(cfg_with(3, 10));
    r.w().notify_count.store(0, SeqCst);
    r.step();
    assert_eq!(r.last_wait.get(), Wait::Forever);
    r.credit(0);
    grow_to(&r, 5);
    r.drain_all();
    r.w().notify_count.store(0, SeqCst);
    r.step();
    assert_eq!(r.last_wait.get(), Wait::Ms(500));

    // A negotiation starts (gate closes) with idle chunks and no traffic at all: a kick is enough.
    r.w().gate_busy.store(true, SeqCst);
    r.ring.elastic_kick();
    r.step();
    let st = r.stats();
    assert!(st.chunks == 0 && r.w().heap_live_blocks.load(SeqCst) == 1 && st.reclaim_events == 1 && st.shrink_events == 0);
    r.w().gate_busy.store(false, SeqCst);
}

/// Refusals back off exponentially, a growth resets it; teardown during growth; one PM mechanism; the heap is not cycled by bursts.
#[test]
fn hardening() {
    // Refusals back off exponentially, a growth resets it; the cheap O(1) free-size check runs before the heap walk.
    let r = Rig::new(cfg_with(3, 10));
    r.w().heap_total.store(r.w().heap_live_bytes.load(SeqCst) + super::world::FLOOR_FREE as i64, SeqCst); // far below the floor
    r.w().largest_calls.store(0, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    assert!(r.stats().grow_denied_heap == 1 && r.w().largest_calls.load(SeqCst) == 0); // no walk for a total that already fails
    let mut denied = 1;
    for wait in [100u32, 200, 400, 800, 1600, 1600] {
        r.advance_ms(wait - 1);
        let _ = r.send_len(1518);
        r.step();
        assert_eq!(r.stats().grow_denied_heap, denied); // one tick early: still backing off
        r.advance_ms(1);
        let _ = r.send_len(1518);
        r.step();
        denied += 1;
        assert_eq!(r.stats().grow_denied_heap, denied);
    }
    r.w().heap_total.store(200_000, SeqCst);
    r.advance_ms(1600);
    let _ = r.send_len(1518);
    r.step();
    assert!(r.stats().grow_events >= 1);
    r.drain_all();
    // after a growth the back-off starts again at 100 ms
    r.w().heap_total.store(r.w().heap_live_bytes.load(SeqCst) + super::world::FLOOR_FREE as i64, SeqCst);
    r.credit(0);
    for _ in 0..40 {
        let _ = r.send_len(1518); // fill whatever exists, then the next growth is refused
    }
    r.step();
    let d0 = r.stats().grow_denied_heap;
    r.advance_ms(100);
    let _ = r.send_len(1518);
    r.step();
    assert_eq!(r.stats().grow_denied_heap, d0 + 1);
    r.drain_all();

    // Largest-block floor: a walk happens (before and after the allocation) only when the total allows a growth.
    let r = Rig::new(cfg_with(3, 10));
    r.w().largest_calls.store(0, SeqCst);
    fill_pressure(&r, 3);
    r.step();
    assert!(r.stats().grow_events == 1 && r.w().largest_calls.load(SeqCst) == 2);
    r.drain_all();

    // Bursts every 5 s with a 10 s idle period: the chunks stay, the heap is not cycled (the 2 s default would free and re-allocate all ten
    // chunks per burst).
    let mut c = cfg_with(3, 10);
    c.idle_ms = 10_000;
    let r = Rig::new(c);
    r.credit(0);
    grow_to(&r, 23);
    r.drain_all();
    let mallocs = r.w().malloc_calls.load(SeqCst);
    for _ in 0..8 {
        r.advance_ms(5000);
        r.step();
        r.credit(0);
        grow_to(&r, 23);
        r.drain_all();
    }
    let st = r.stats();
    assert!(st.shrink_events == 0 && st.chunks == 10 && r.w().malloc_calls.load(SeqCst) == mallocs && st.dropped_full == 0);
    // a quiet spell longer than the idle period gives the memory back, one chunk per pass
    r.advance_ms(10_000);
    r.step();
    assert_eq!(r.stats().chunks, 9);
    for _ in 0..12 {
        r.step();
    }
    assert!(r.stats().chunks == 0 && r.stats().shrink_events == 10 && r.w().heap_live_blocks.load(SeqCst) == 1);
    r.check_invariants();

    // Teardown while a growth is allocating: the chunk is discarded, nothing is published after deinit.
    let r = Rig::new(cfg_with(3, 10));
    *r.w().malloc_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| ring.deinit()));
    fill_pressure(&r, 3);
    r.step();
    let st = r.stats();
    assert!(st.grow_events == 0 && st.grow_raced == 1 && st.chunks == 0 && r.w().heap_live_blocks.load(SeqCst) == 1);
    assert_eq!(r.ring.restart(&cfg_with(3, 10)), Ok(()));
    r.drain_all();

    // One PM mechanism: with hooks the ring takes no lock of its own and the hooks alternate begin/end.
    let hook = Arc::new(std::sync::Mutex::new((0u32, 0u32, false))); // begins, ends, open
    let r = Rig::new(cfg_with(3, 10));
    let h = Arc::clone(&hook);
    *r.w().pm_begin_hook.lock().unwrap() = Some(Arc::new(move || {
        let mut g = h.lock().unwrap();
        assert!(!g.2);
        g.2 = true;
        g.0 += 1;
    }));
    let h = Arc::clone(&hook);
    *r.w().pm_end_hook.lock().unwrap() = Some(Arc::new(move || {
        let mut g = h.lock().unwrap();
        assert!(g.2);
        g.2 = false;
        g.1 += 1;
    }));
    let read = || *hook.lock().unwrap();
    assert_eq!(r.w().pm_acquires.load(SeqCst), 0); // the caller's hooks, not the default ones, are in use
    r.credit(0);
    assert!(r.send_len(400).is_ok());
    r.pump();
    assert!(read().0 == 1 && read().1 == 0 && read().2);
    for _ in 0..6 {
        assert!(r.send_len(400).is_ok());
        r.step();
    }
    assert_eq!(read().0, 1); // one hold for the whole burst
    r.credit(-1);
    r.in_complete();
    r.step();
    assert!(read().0 == 1 && read().1 == 1 && !read().2 && r.stats().pm_held == 0 && r.stats().pm_acquired == 1);
    r.credit(0); // link loss with frames queued ends the hold too
    assert!(r.send_len(400).is_ok());
    r.pump();
    assert!(read().2);
    r.w().usb_ready.store(false, SeqCst);
    r.ring.link_down();
    r.step();
    r.run_deferred();
    r.step();
    assert!(!read().2 && read().0 == 2 && read().1 == 2);
    r.w().usb_ready.store(true, SeqCst);
    assert!(r.send_len(400).is_ok());
    r.pump(); // and teardown
    r.ring.deinit();
    r.step();
    assert!(!read().2 && read().0 == read().1);
    // the same hooks twice is a no-op restart, a different set is refused
    assert_eq!(r.ring.restart(&cfg_with(3, 10)), Ok(()));
    let mut other = cfg_with(3, 10);
    other.pm = false;
    assert!(r.ring.restart(&other).is_err());
}
