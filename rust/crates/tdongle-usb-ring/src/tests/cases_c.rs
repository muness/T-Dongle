//! Port of `tests/mocks/net_ring_cases.c`, third part: delivery triggers, link loss, producer flush, the elastic cap knob, drain evidence,
//! the CPU-frequency hold.

use std::prelude::v1::*;

use std::sync::atomic::Ordering::SeqCst;

use super::cases_a::fill_pressure;
use super::rng::Rng;
use super::world::{IDLE_MS, Rig, cfg_with};
use crate::{SLAB_BYTES, SendError, Wait};

fn grow_to(r: &Rig, frames: usize) {
    for _ in 0..frames {
        assert!(r.send_len(1518).is_ok());
        r.step();
    }
}

#[test]
fn exactly_once_and_triggers() {
    let r = Rig::new(cfg_with(3, 4));
    r.credit(0);
    for _ in 0..4 {
        assert!(r.send_len(1400).is_ok());
        r.step();
    }
    r.pump(); // drain stops, frames stay queued
    assert!(r.delivered() == 0 && r.ring.is_blocked() && r.stats().ntb_blocked >= 1);
    let ev = r.stats().ntb_blocked;
    // Nothing re-drains on a timer: with no new frame and no completion nothing moves.
    for _ in 0..20 {
        r.advance_ms(300);
        r.w().notify_count.store(0, SeqCst);
        r.step();
    }
    r.run_deferred();
    assert!(r.delivered() == 0 && r.stats().ntb_blocked == ev);
    r.check_pm();
    // The host takes one NTB: its completion event moves exactly one frame, in order.
    r.credit(1);
    r.in_complete();
    assert!(r.delivered() == 1 && r.ring.is_blocked() && r.w().pending() == 0);
    r.credit(-1);
    r.in_complete();
    assert!(r.delivered() == r.stats().enqueued_frames && !r.ring.is_blocked() && r.queued() == 0);
    r.check_invariants();

    // An IN completion drains with no worker and no deferred callback. (The C also checks that an OUT completion is not a transmit event and
    // that the real class driver ran first: both are the glue's business, the ring has no OUT entry point.)
    let r = Rig::new(cfg_with(3, 4));
    r.credit(0);
    assert!(r.send_len(300).is_ok());
    r.credit(-1);
    assert_eq!(r.delivered(), 0);
    let pend = r.w().pending();
    r.in_complete();
    assert!(r.delivered() == 1 && r.w().pending() == pend && r.stats().xfer_events >= 1);
    r.in_complete(); // empty ring: a cheap no-op
    assert_eq!(r.delivered(), 1);
    r.step();
    r.check_pm();

    // Duplicate and stale drain callbacks (timed-out wakeups, retries racing a drain) are harmless.
    let r = Rig::new(cfg_with(3, 4));
    for _ in 0..4 {
        assert!(r.send_len(300).is_ok());
    }
    r.pump();
    assert_eq!(r.delivered(), 4);
    for _ in 0..20 {
        r.ring.do_drain();
    }
    for _ in 0..20 {
        r.in_complete();
    }
    assert_eq!(r.delivered(), 4);
    assert!(r.send_len(300).is_ok());
    for _ in 0..5 {
        r.ring.do_drain(); // replay with a new frame queued: delivered once
    }
    assert_eq!(r.delivered(), 5);
    r.pump();
    assert!(r.w().pending() == 0 && r.delivered() == 5);
    // The worker defers once per outstanding request, not once per frame.
    for _ in 0..3 {
        assert!(r.send_len(300).is_ok());
    }
    r.step();
    r.step();
    r.step();
    assert_eq!(r.w().pending(), 1);
    r.run_deferred();
    assert_eq!(r.delivered(), 8);
    // Delayed callbacks: frames are committed, completions arrive late and in bursts, in any mix.
    let r = Rig::new(cfg_with(3, 10));
    let mut rng = Rng(88_172_645_463_325_252);
    r.credit(0);
    for i in 0..20 {
        assert!(r.send_len(1000 + i).is_ok());
        r.step();
    }
    for i in 0..100 {
        if r.queued() == 0 {
            break;
        }
        r.credit(rng.rnd(3) as i32);
        if rng.rnd(2) != 0 {
            r.in_complete();
        } else {
            r.step();
            r.run_deferred();
        }
        for _ in 0..rng.rnd(3) {
            r.ring.do_drain();
        }
        r.check_invariants();
        if i % 7 == 0 {
            r.credit(-1);
        }
    }
    r.drain_all();
    assert!(r.delivered() == 20 && r.stats().sent_frames == 20 && r.stats().flushed_link_down == 0);
}

#[test]
fn link_loss() {
    // Frames queued across the base and elastic chunks, cable pulled and replugged with no drain in between: the producer notices on its next
    // attempt and the stale frames never reach the new host.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 12);
    r.pump();
    assert!(r.ring.is_blocked() && r.delivered() == 0 && r.stats().chunks >= 4);
    r.check_pm();
    let flushed = r.stats().flushed_link_down;
    r.w().usb_ready.store(false, SeqCst);
    r.w().notify_count.store(0, SeqCst);
    assert_eq!(r.send_len(500), Err(SendError::LinkDown));
    assert_eq!(r.w().notify_count.load(SeqCst), 1); // stale frames are queued: the worker is woken to flush them
    assert_eq!(r.send_len(500), Err(SendError::LinkDown)); // one generation bump per outage
    assert_eq!(r.ring.generation(), 1);
    r.pump(); // the worker's drain discards them while the link is down
    assert!(r.stats().flushed_link_down == flushed + 12 && r.queued() == 0);
    r.check_pm(); // ... and the CPU-frequency lock is released
    r.check_invariants();
    r.w().usb_ready.store(true, SeqCst);
    r.credit(-1);
    r.skip_to_next(); // the stale frames are never observed
    assert!(r.send_len(500).is_ok());
    r.pump();
    assert!(r.delivered() == 1 && r.ring.generation() == 1);

    // The same, but replugged before anyone looked: the generation check on the producer side is what catches it.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 8);
    r.w().usb_ready.store(false, SeqCst);
    assert_eq!(r.send_len(500), Err(SendError::LinkDown));
    r.w().usb_ready.store(true, SeqCst);
    r.credit(-1);
    r.skip_to_next();
    assert!(r.send_len(500).is_ok());
    r.pump();
    r.in_complete();
    r.pump();
    assert!(r.delivered() == 1 && r.stats().flushed_link_down == 8 && r.queued() == 0);
    r.check_pm();
    r.check_invariants();

    // Silent loss: nobody sends, no event arrives. The worker's link check (it is polling because frames are queued) discards the frames and
    // lets go of the CPU-frequency lock.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 10);
    r.pump();
    r.w().usb_ready.store(false, SeqCst);
    r.w().notify_count.store(0, SeqCst);
    r.step(); // timed out, no notification
    assert_eq!(r.last_wait.get(), Wait::Ms(200));
    r.run_deferred();
    r.step();
    assert!(r.queued() == 0 && r.stats().flushed_link_down == 10 && r.ring.generation() == 1);
    r.check_pm();
    r.check_invariants();
    r.w().usb_ready.store(true, SeqCst);
    r.credit(-1);
    r.skip_to_next();
    assert!(r.send_len(300).is_ok());
    r.pump();
    assert!(r.delivered() == 1 && r.ring.generation() == 1);

    // The detach event (usb_event DETACHED) flushes without waiting for a poll.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 6);
    r.pump();
    r.w().usb_ready.store(false, SeqCst);
    r.ring.link_down();
    r.ring.link_down(); // idempotent
    assert_eq!(r.ring.generation(), 1);
    r.pump();
    assert!(r.queued() == 0 && r.stats().flushed_link_down == 6);
    r.check_pm();
    r.w().usb_ready.store(true, SeqCst);
    r.credit(-1);
    r.skip_to_next();
    // link_down on a ring that was never started or is stopped does nothing.
    r.ring.deinit();
    let gen_before = r.ring.generation();
    r.ring.link_down();
    assert_eq!(r.ring.generation(), gen_before);

    // A drain that finds USB down discards what is queued (no producer, no poll).
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 5);
    r.pump();
    let flushed = r.stats().flushed_link_down;
    r.w().usb_ready.store(false, SeqCst);
    r.in_complete(); // the consumer is the first to look: no generation bump yet
    assert!(r.stats().flushed_link_down == flushed + 5 && r.queued() == 0 && !r.ring.is_blocked() && r.ring.generation() == 0);
    r.w().usb_ready.store(true, SeqCst);
    r.credit(-1);
    r.skip_to_next();
    assert!(r.send_len(500).is_ok());
    r.pump();
    assert_eq!(r.delivered(), 1);
    r.check_invariants();
    r.check_pm();

    // Teardown with frames queued and chunks held: everything is discarded and given back, the lock is released.
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 15);
    r.pump();
    r.check_pm();
    assert_eq!(r.w().pm_held.load(SeqCst), 1);
    r.ring.deinit();
    assert!(r.queued() == 0 && r.w().heap_live_blocks.load(SeqCst) == 1 && r.stats().flushed_link_down == 15);
    r.step();
    r.check_pm();
    assert!(r.w().pm_held.load(SeqCst) == 0 && r.w().pm_acquires.load(SeqCst) == r.w().pm_releases.load(SeqCst));
    r.check_invariants();
    assert_eq!(r.ring.restart(&cfg_with(3, 10)), Ok(()));
    r.skip_to_next();
    r.credit(-1);
    assert!(r.send_len(300).is_ok());
    r.pump();
    assert_eq!(r.delivered(), 1);
}

/// `flush()`: the producer's own source changed (the transparent bridge's Wi-Fi link). Queued frames are stale, frames queued after the call
/// are not, and it never blocks.
#[test]
fn producer_flush() {
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    grow_to(&r, 6);
    r.pump();
    assert!(r.queued() == 6 && r.ring.generation() == 0);
    let flushed = r.stats().flushed_link_down;
    r.w().notify_count.store(0, SeqCst);
    super::world::as_producer(|| r.ring.flush()); // the bridge calls it from its event task: it must not wait or defer
    assert!(r.ring.generation() == 1 && r.w().notify_count.load(SeqCst) == 1); // the generation moved and the worker was woken to flush
    r.credit(-1);
    r.skip_to_next(); // the stale frames are never observed
    assert!(r.send_len(300).is_ok()); // a frame after the call carries the new generation
    r.pump();
    r.in_complete();
    r.pump();
    assert!(r.delivered() == 1 && r.stats().flushed_link_down == flushed + 6 && r.queued() == 0);
    r.check_pm();
    r.check_invariants();
    // On an empty ring it is harmless; frames after it are delivered.
    r.ring.flush();
    r.skip_to_next();
    assert!(r.send_len(300).is_ok());
    r.pump();
    r.in_complete();
    r.pump();
    assert!(r.delivered() == 2 && r.ring.generation() == 2 && r.stats().flushed_link_down == flushed + 6);
    // A stopped ring ignores it.
    r.ring.deinit();
    let gen_before = r.ring.generation();
    r.ring.flush();
    assert_eq!(r.ring.generation(), gen_before);
}

/// The elastic cap as a run-time knob: lowering retires the chunks above it (frames in them drain first), raising lets the worker grow again.
#[test]
fn set_max_chunks() {
    use crate::SetMaxChunksError;
    let r = Rig::new(cfg_with(3, 10));
    assert!(r.ring.max_chunks() == 10 && r.stats().max_bytes as usize == (3 + 10 * crate::CHUNK_SLABS) * SLAB_BYTES);
    r.credit(0);
    grow_to(&r, 14);
    r.pump();
    assert!(r.stats().chunks >= 5);
    assert_eq!(r.ring.set_max_chunks(13), Err(SetMaxChunksError::TooMany));
    assert!(r.ring.set_max_chunks(2).is_ok() && r.ring.max_chunks() == 2 && r.stats().max_bytes as usize == (3 + 2 * crate::CHUNK_SLABS) * SLAB_BYTES);
    r.check_invariants();
    assert_eq!(r.delivered(), 0); // nothing was dropped by lowering the cap
    r.credit(-1);
    r.drain_all();
    for _ in 0..10 {
        r.pump();
        r.advance_ms(IDLE_MS + 600);
    }
    assert!(r.chunks_present() <= 2 && r.ring.with_state(|st| st.chunks_live) <= 2 && r.stats().flushed_link_down == 0);
    r.check_invariants();
    r.credit(0);
    for _ in 0..40 {
        let _ = r.send_len(1500);
        r.pump(); // growth now stops at the new cap
    }
    assert!(r.stats().chunks <= 2);
    r.credit(-1);
    r.drain_all();
    assert!(r.ring.set_max_chunks(10).is_ok()); // ... and raising it lets the ring grow again
    r.credit(0);
    for _ in 0..40 {
        let _ = r.send_len(1500);
        r.pump();
    }
    assert!(r.stats().chunks > 2 && r.stats().chunks <= 10);
    r.credit(-1);
    r.drain_all();
    assert!(r.ring.set_max_chunks(0).is_ok() && r.ring.max_chunks() == 0);
    for _ in 0..10 {
        r.pump();
    }
    r.check_invariants();
    // A stopped ring refuses the knob.
    r.ring.deinit();
    assert_eq!(r.ring.set_max_chunks(3), Err(SetMaxChunksError::NotStarted));
}

/// The evidence counters (NTB size, frames per drain, completion gaps, cold-start latency) and the worker's priority split (relay high, heap
/// work low, only when there is heap work).
#[test]
fn drain_evidence_and_priority() {
    let mut c = cfg_with(3, 4);
    c.priority = 10;
    c.work_priority = 6;
    let r = Rig::new(c);
    // No elastic memory and no growth wanted: the relay pass never touches the priority.
    assert!(r.send_len(300).is_ok());
    r.w().us.store(1000, SeqCst);
    r.pump();
    assert!(r.w().prio_sets.load(SeqCst) == 0 && r.stats().worker_demotions == 0);
    r.drain_all();
    // Cold start: committed at t=5000 us, handed over by the consumer at t=5700 us.
    let r = Rig::new(c);
    r.w().us.store(5000, SeqCst);
    assert!(r.send_len(400).is_ok());
    assert!(r.send_len(500).is_ok()); // not a new edge: the queue was already non-empty
    r.w().us.store(5700, SeqCst);
    r.pump();
    let st = r.stats();
    assert!(st.cold_starts == 1 && st.cold_us_sum == 700 && st.cold_us_max == 700);
    assert!(st.drains_sent[1] == 1 && st.drains_sent[0] == 0); // both frames in one pass
    // A second edge after the queue emptied is measured again.
    r.w().us.store(9000, SeqCst);
    assert!(r.send_len(600).is_ok());
    r.w().us.store(9100, SeqCst);
    r.pump();
    let st = r.stats();
    assert!(st.cold_starts == 2 && st.cold_us_sum == 800 && st.cold_us_max == 700 && st.drains_sent[0] == 1);
    // Completions: sizes, a ZLP, and gaps counted only while frames are queued.
    let r = Rig::new(c);
    r.credit(0); // every NTB in flight: frames stay queued
    assert!(r.send_len(700).is_ok());
    r.pump();
    assert_eq!(r.queued(), 1);
    r.w().us.store(10_000, SeqCst);
    r.complete_bytes(3000); // first completion: no previous one
    r.w().us.store(10_900, SeqCst);
    r.complete_bytes(2500); // 0.9 ms
    r.w().us.store(13_000, SeqCst);
    r.complete_bytes(0); // 2.1 ms, a ZLP
    r.w().us.store(30_000, SeqCst);
    r.complete_bytes(64); // 17 ms
    let st = r.stats();
    assert!(st.ntb_xfers == 3 && st.ntb_zlp == 1 && st.ntb_bytes == 3000 + 2500 + 64 && st.ntb_max_bytes == 3000);
    assert!(st.gap_count == 3 && st.gap_us_sum == 900 + 2100 + 17_000 && st.gap_us_max == 17_000);
    assert!(st.gap_hist[0] == 1 && st.gap_hist[2] == 1 && st.gap_hist[4] == 1 && st.gap_hist[1] == 0);
    r.credit(-1);
    r.drain_all();
    // Idle completions (nothing queued) do not produce gaps.
    r.w().us.store(50_000, SeqCst);
    r.complete_bytes(64);
    r.w().us.store(90_000, SeqCst);
    r.complete_bytes(64);
    assert_eq!(r.stats().gap_count, 3);
    // Heap work: growth demotes the worker for the growth and restores the relay priority, once per pass.
    let r = Rig::new(c);
    fill_pressure(&r, 3);
    let before_prio = r.w().prio_sets.load(SeqCst);
    r.step();
    assert!(r.w().prio_sets.load(SeqCst) == before_prio + 2 && r.w().prio_cur.load(SeqCst) == 10); // down, then back up
    assert!(r.stats().worker_demotions >= 1);
    r.drain_all();
    // Housekeeping with an elastic chunk present but no growth wanted (an idle pass) is not demoted.
    let r = Rig::new(c);
    fill_pressure(&r, 3);
    r.step(); // grows a chunk
    r.drain_all();
    r.w().prio_sets.store(0, SeqCst);
    assert!(r.chunks_present() != 0 && !r.ring.probe().grow_wanted);
    r.step();
    assert!(r.w().prio_sets.load(SeqCst) == 0 && r.w().prio_cur.load(SeqCst) == 10);
    // Equal or unset work priority: never a call.
    c.work_priority = 0;
    let r = Rig::new(c);
    fill_pressure(&r, 3);
    r.step();
    assert_eq!(r.w().prio_sets.load(SeqCst), 0);
    c.work_priority = 10;
    let r = Rig::new(c);
    fill_pressure(&r, 3);
    r.step();
    assert_eq!(r.w().prio_sets.load(SeqCst), 0);
    r.drain_all();
}

/// The CPU-frequency lock follows the queue: acquired by the worker after the first frame, released by the worker after the last one left,
/// never doubled, and not touched by producer or consumer.
#[test]
fn pm_lock() {
    let r = Rig::new(cfg_with(3, 10));
    r.credit(0);
    assert!(r.send_len(400).is_ok());
    assert_eq!(r.w().pm_acquires.load(SeqCst), 0);
    r.step();
    assert!(r.w().pm_acquires.load(SeqCst) == 1 && r.w().pm_releases.load(SeqCst) == 0);
    r.step();
    assert_eq!(r.last_wait.get(), Wait::Ms(200)); // polling the link while queued
    for _ in 0..10 {
        assert!(r.send_len(400).is_ok());
        r.step();
    }
    assert_eq!(r.w().pm_acquires.load(SeqCst), 1); // one lock for the whole burst
    r.run_deferred();
    r.in_complete();
    assert_eq!(r.w().pm_releases.load(SeqCst), 0); // blocked: still queued, still held
    r.credit(-1);
    r.in_complete();
    assert!(r.queued() == 0 && r.w().pm_releases.load(SeqCst) == 0); // the consumer does not release: it wakes the worker
    assert!(r.w().notify_count.load(SeqCst) > 0);
    r.step();
    assert!(r.w().pm_acquires.load(SeqCst) == 1 && r.w().pm_releases.load(SeqCst) == 1 && r.w().pm_held.load(SeqCst) == 0);
    // The next burst takes it again.
    assert!(r.send_len(400).is_ok());
    r.pump();
    assert!(r.w().pm_acquires.load(SeqCst) == 2 && r.w().pm_releases.load(SeqCst) == 2);
    // Reclaim and elastic housekeeping never touch it.
    r.w().gate_busy.store(true, SeqCst);
    r.ring.elastic_reclaim(0);
    r.step();
    assert!(r.w().pm_acquires.load(SeqCst) == 2 && r.w().pm_releases.load(SeqCst) == 2);
    r.w().gate_busy.store(false, SeqCst);
}
