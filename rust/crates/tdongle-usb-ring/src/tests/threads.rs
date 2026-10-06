//! Port of `tests/mocks/net_ring_threads.c`: the elastic ring with real threads, as on the board: the lwIP core lock holder (producer), the
//! TinyUSB task (consumer: deferred drains and IN completions), the usb_txq worker (growth, idle shrink, CPU-frequency lock) and membership
//! admission (gate closes, reclaim, gate opens), all at once. Every accepted frame must be delivered once, in order, bytes intact; the mocks
//! assert that nothing allocates, frees, waits or calls a task inside the critical section or in the producer.
//!
//! `threads_with_link_flapper` adds a fifth thread that flaps the link (USB detach and re-attach, producer flush) while the rest run: frames
//! may then be flushed, so the check becomes exactly-once with gaps: no frame repeats or reorders, bytes intact, and every accepted frame is
//! either delivered or counted flushed.

use std::prelude::v1::*;

use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::thread::{sleep, yield_now};
use std::time::Duration;

use super::world::{FLOOR_FREE, FLOOR_LARGEST, Rig, World, as_producer, build_frame, cfg_with};
use crate::{Config, Ring};

fn xorshift(r: &mut u64) {
    *r ^= *r << 13;
    *r ^= *r >> 7;
    *r ^= *r << 17;
}

struct Totals {
    accepted: u64,
    admissions: u64,
    flaps: u64,
}

fn run(flapper: bool, frames: u32) -> Totals {
    let mut cfg: Config = cfg_with(3, 10);
    cfg.idle_ms = 5;
    cfg.floor_free = FLOOR_FREE;
    cfg.floor_largest = FLOOR_LARGEST;
    let rig = Rig::new(cfg);
    {
        let mut o = rig.w().obs.lock().unwrap();
        o.mul = 7;
        o.monotonic = flapper;
    }
    let ring: Arc<Ring<World>> = Arc::clone(&rig.ring);
    let producer_done = Arc::new(AtomicBool::new(false));
    let consumer_stop = Arc::new(AtomicBool::new(false));
    let gate_flag = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicU64::new(0));
    let admissions = Arc::new(AtomicU64::new(0));
    let flaps = Arc::new(AtomicU64::new(0));

    let producer = {
        let (ring, done, accepted) = (Arc::clone(&ring), Arc::clone(&producer_done), Arc::clone(&accepted));
        std::thread::spawn(move || {
            let mut r = 0x9e37_79b9_7f4a_7c15u64;
            let mut seq = 0u32;
            as_producer(|| {
                for _ in 0..frames {
                    xorshift(&mut r);
                    let mut n = if r & 3 == 0 { 14 + ((r >> 8) % 60) as usize } else { 14 + ((r >> 8) % 1505) as usize };
                    if (r >> 50) & 1 == 1 {
                        n = 1518 - ((r >> 12) & 7) as usize; // bursts of full-size frames
                    }
                    let f = build_frame(seq, 7, n);
                    if ring.send(&f).is_ok() {
                        seq += 1;
                        accepted.fetch_add(1, SeqCst);
                    } else if (r >> 40) & 1 == 1 {
                        yield_now();
                    }
                    if (r >> 20) & 63 == 0 {
                        for _ in 0..20 {
                            yield_now(); // a pause: the ring drains and chunks idle
                        }
                    }
                }
            });
            done.store(true, SeqCst);
        })
    };
    let consumer = {
        let (ring, stop) = (Arc::clone(&ring), Arc::clone(&consumer_stop));
        std::thread::spawn(move || {
            // the TinyUSB task
            let mut r = 0xdead_beef_cafe_f00du64;
            while !stop.load(SeqCst) {
                xorshift(&mut r);
                // USB drains slower than the producer fills: two frames per NTB, one NTB per wakeup, with periods of catching up.
                let credit = if r & 63 == 0 { -1 } else { ((r >> 8) % 3) as i32 };
                ring.env().ntb_credit.store(credit, SeqCst);
                while ring.env().take_pending() {
                    ring.do_drain();
                }
                if (r >> 20) & 1 == 1 {
                    ring.do_drain();
                } else {
                    ring.on_in_complete(64);
                }
                sleep(Duration::from_micros(30));
            }
        })
    };
    let worker = {
        let (ring, stop) = (Arc::clone(&ring), Arc::clone(&consumer_stop));
        std::thread::spawn(move || {
            // usb_txq (the mock take returns at once)
            while !stop.load(SeqCst) {
                ring.worker_step();
                ring.env().tick.fetch_add(1, SeqCst);
                yield_now();
            }
        })
    };
    let admission = {
        let (ring, done, gate, n) = (Arc::clone(&ring), Arc::clone(&producer_done), Arc::clone(&gate_flag), Arc::clone(&admissions));
        std::thread::spawn(move || {
            // a membership starts: token (gate), reclaim, measure, release
            *ring.env().delay_hook.lock().unwrap() = Some(Arc::new(|_: &Ring<World>| sleep(Duration::from_micros(200))));
            while !done.load(SeqCst) {
                gate.store(true, SeqCst);
                ring.env().gate_busy.store(true, SeqCst);
                let _ = ring.elastic_reclaim(20);
                n.fetch_add(1, SeqCst);
                sleep(Duration::from_micros(300));
                gate.store(false, SeqCst);
                ring.env().gate_busy.store(false, SeqCst);
                ring.elastic_kick();
                sleep(Duration::from_micros(2000));
            }
        })
    };
    let flap = flapper.then(|| {
        let (ring, done, n) = (Arc::clone(&ring), Arc::clone(&producer_done), Arc::clone(&flaps));
        std::thread::spawn(move || {
            let mut r = 0x0123_4567_89ab_cdefu64;
            while !done.load(SeqCst) {
                xorshift(&mut r);
                match r % 3 {
                    0 => ring.flush(), // the bridge's Wi-Fi association changed
                    1 => {
                        ring.env().usb_ready.store(false, SeqCst); // detach
                        ring.link_down();
                        sleep(Duration::from_micros(100 + r % 400));
                        ring.env().usb_ready.store(true, SeqCst); // attach again
                    }
                    _ => {}
                }
                n.fetch_add(1, SeqCst);
                sleep(Duration::from_micros(500 + (r >> 8) % 1500));
            }
        })
    });

    producer.join().unwrap();
    admission.join().unwrap();
    if let Some(f) = flap {
        f.join().unwrap();
    }
    ring.env().gate_busy.store(false, SeqCst);
    ring.env().usb_ready.store(true, SeqCst);
    *ring.env().delay_hook.lock().unwrap() = None;
    // the consumer finishes the queue
    for _ in 0..200_000 {
        let q = ring.stats();
        if q.sent_frames + q.flushed_link_down == q.enqueued_frames {
            break;
        }
        yield_now();
    }
    consumer_stop.store(true, SeqCst);
    consumer.join().unwrap();
    worker.join().unwrap();
    rig.credit(-1);
    ring.do_drain();
    rig.step();
    rig.step();
    assert_eq!(rig.queued(), 0);
    let st = ring.stats();
    let acc = accepted.load(SeqCst);
    let (delivered, gaps) = {
        let o = rig.w().obs.lock().unwrap();
        (u64::from(o.delivered_frames), o.gaps)
    };
    assert_eq!(u64::from(st.enqueued_frames), acc);
    assert_eq!(delivered, u64::from(st.sent_frames));
    assert_eq!(acc, u64::from(st.sent_frames) + u64::from(st.flushed_link_down)); // exactly once: delivered or flushed
    if flapper {
        assert!(gaps <= u64::from(st.flushed_link_down)); // a missing sequence number is a flushed frame, never a lost one
    } else {
        assert!(st.flushed_link_down == 0 && delivered == acc && gaps == 0);
    }
    assert!(acc > 10_000.min(u64::from(frames) / 30) && st.grow_events > 0 && st.reclaim_events > 0);
    assert_eq!(rig.w().pm_acquires.load(SeqCst), rig.w().pm_releases.load(SeqCst));
    assert!(rig.w().pm_held.load(SeqCst) == 0 && rig.w().pm_acquires.load(SeqCst) > 0);
    assert!(rig.w().heap_live_blocks.load(SeqCst) == 1 + i64::from(rig.chunks_present()) && st.chunks <= 10);
    rig.check_invariants();
    Totals { accepted: acc, admissions: admissions.load(SeqCst), flaps: flaps.load(SeqCst) }
}

#[test]
fn threads_four() {
    let t = run(false, 300_000);
    assert!(t.admissions > 5 && t.accepted > 10_000);
}

#[test]
fn threads_with_link_flapper() {
    let t = run(true, 200_000);
    assert!(t.flaps > 5 && t.admissions > 5);
}
