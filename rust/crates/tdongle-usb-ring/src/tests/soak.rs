//! The C soak: random everything, with the bookkeeping re-derived from the bytes after every operation.

use std::prelude::v1::*;

use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;

use super::rng::Rng;
use super::world::{FLOOR_FREE, FLOOR_LARGEST, IDLE_MS, Rig, World, cfg_with};
use crate::{CHUNK_SLABS, Ring, SendError};

/// Random everything: sizes, NTB availability, link flaps, gate, heap level, tick, reclaims, allocator failures, duplicate callbacks.
/// Invariant: accepted == delivered + flushed, in order, bytes intact; bookkeeping re-derived from the bytes after every operation.
fn soak_once(base: u32, chunks: u32, rounds: u32, seed: u64) {
    let r = Rig::new(cfg_with(base, chunks));
    let mut rng = Rng(seed);
    let (mut accepted, mut dropped) = (0u64, 0u64);
    let max_slabs = base + chunks * CHUNK_SLABS as u32;
    let w = r.w();
    for _ in 0..rounds {
        let op = rng.rnd(20);
        if op < 8 {
            let n = if rng.rnd(4) == 0 {
                14 + rng.rnd(60)
            } else if rng.rnd(3) == 0 {
                1200 + rng.rnd(319)
            } else {
                14 + rng.rnd(1505)
            };
            match r.send_len(n as usize) {
                Ok(()) => accepted += 1,
                Err(e) => {
                    assert_eq!(e, SendError::Full);
                    dropped += 1;
                }
            }
            if rng.rnd(2) != 0 {
                r.step();
            }
        } else if op < 10 {
            let mut credit = if rng.rnd(3) == 0 { 0 } else { rng.rnd(6) as i32 };
            if rng.rnd(4) == 0 {
                credit = -1;
            }
            r.credit(credit);
            r.pump();
        } else if op == 10 {
            r.ring.do_drain();
        } else if op < 13 {
            if rng.rnd(3) == 0 {
                r.credit(-1);
            }
            r.in_complete();
        } else if op == 13 {
            let ms = if rng.rnd(3) != 0 { rng.rnd(300) } else { IDLE_MS + rng.rnd(500) };
            r.advance_ms(ms);
            r.step();
        } else if op == 14 {
            w.gate_busy.store(rng.rnd(3) == 0, SeqCst);
            if rng.rnd(2) != 0 {
                r.ring.elastic_kick();
            }
            r.step();
        } else if op == 15 {
            let extra = if rng.rnd(3) != 0 { 200_000 } else { FLOOR_FREE as i64 + i64::from(rng.rnd(8000)) };
            w.heap_total.store(w.heap_live_bytes.load(SeqCst) + extra, SeqCst);
            let largest = if rng.rnd(4) != 0 { 100_000 } else { FLOOR_LARGEST - 1 + rng.rnd(3000) as usize };
            w.mock_largest.store(largest, SeqCst);
            w.malloc_fail.store(rng.rnd(10) == 0, SeqCst);
            if rng.rnd(8) == 0 {
                w.frag_next.store(FLOOR_LARGEST - 1 + rng.rnd(2) as usize, SeqCst);
            }
        } else if op == 16 {
            if rng.rnd(2) != 0 {
                w.gate_busy.store(true, SeqCst);
                let _ = r.ring.elastic_reclaim(0);
            } else {
                w.gate_busy.store(true, SeqCst);
                *w.delay_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| {
                    ring.env().ntb_credit.store(-1, SeqCst);
                    ring.on_in_complete(64);
                }));
                let _ = r.ring.elastic_reclaim(rng.rnd(60));
                *w.delay_hook.lock().unwrap() = None;
            }
            w.gate_busy.store(rng.rnd(2) != 0, SeqCst);
        } else if op == 17 {
            if rng.rnd(6) == 0 {
                // An outage: seen by the producer, by a drain, by the detach event, or by nobody until the poll.
                w.usb_ready.store(false, SeqCst);
                match rng.rnd(4) {
                    0 => {
                        let _ = r.send_len(100);
                    }
                    1 => r.pump(),
                    2 => {
                        r.ring.link_down();
                        r.pump();
                    }
                    _ => {
                        r.step();
                        r.run_deferred();
                    }
                }
                w.usb_ready.store(true, SeqCst);
                // Everything queued before the outage is stale or flushed; the host that comes back sees none of it.
                r.credit(-1);
                if rng.rnd(2) != 0 {
                    w.usb_ready.store(false, SeqCst);
                    r.in_complete();
                    w.usb_ready.store(true, SeqCst);
                }
                r.step();
                r.skip_to_next();
            }
        } else {
            r.ring.do_drain();
            r.in_complete();
        }
        if w.pending() > 4 {
            r.run_deferred(); // the TinyUSB task keeps up with its queue
        }
        r.check_invariants();
        assert!(r.capacity_slabs() <= max_slabs && r.fifo_n() <= max_slabs);
        assert!(w.free_size() < 1_000_000);
    }
    w.gate_busy.store(false, SeqCst);
    w.malloc_fail.store(false, SeqCst);
    w.frag_next.store(0, SeqCst);
    r.drain_all();
    r.check_invariants();
    r.check_pm();
    let st = r.stats();
    assert_eq!(accepted, u64::from(st.sent_frames + st.flushed_link_down)); // every accepted frame left the ring exactly once
    assert_eq!(u64::from(r.delivered()), u64::from(st.sent_frames));
    // Interpreter runs retain accounting/invariants; only the volume floor scales with their rounds.
    let min_sent = if cfg!(miri) { rounds / 40 } else { 500 };
    assert!(st.sent_frames > min_sent);
    assert!(st.high_water_slabs <= max_slabs);
    assert_eq!(u64::from(st.enqueued_frames), accepted);
    assert_eq!(u64::from(st.dropped_full), dropped);
}

// Each Miri geometry still runs hundreds of send/drain/outage operations and repeated queue wraps.
#[test]
fn soak_base3_chunks10() {
    soak_once(3, 10, if cfg!(miri) { 512 } else { 200_000 }, 88_172_645_463_325_252);
}

#[test]
fn soak_base2_chunks4() {
    soak_once(2, 4, if cfg!(miri) { 512 } else { 100_000 }, 0x9e37_79b9_7f4a_7c15);
}

#[test]
fn soak_base4_fixed() {
    soak_once(4, 0, if cfg!(miri) { 512 } else { 100_000 }, 0x2545_f491_4f6c_dd1d);
}

#[test]
fn soak_base8_chunks12() {
    soak_once(8, 12, if cfg!(miri) { 512 } else { 100_000 }, 0xd1b5_4a32_d192_ed03);
}
