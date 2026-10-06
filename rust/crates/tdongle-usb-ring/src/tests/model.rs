//! A randomized model-based test (new in the port; the C has the soak above and the bridge test's soak).
//!
//! The reference model is a `VecDeque` of the frames the ring accepted and has neither delivered nor flushed, with the generation and the
//! outage epoch each was accepted in. After every operation:
//!
//! * the identity `enq = sent + flushed + queued` holds in the counters;
//! * every frame the USB side received is the oldest model entry that was still legitimately in the ring: the entries ahead of it were flushed,
//!   and only a generation bump, an outage or a teardown since their acceptance may flush a frame;
//! * the frames the ring still holds, read back from its slab bytes, are exactly the model's remaining entries, in order;
//! * `flushed` equals the number of entries the model saw disappear, and the bookkeeping invariants of the C `check_invariants` hold.

use std::prelude::v1::*;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;

use super::rng::Rng;
use super::world::{FLOOR_FREE, FLOOR_LARGEST, IDLE_MS, Rig, World, build_frame, cfg_with};
use crate::{Ring, SendError};

struct Entry {
    seq: u32,
    gen_: u16,
    outage: u32,
}

#[derive(Default)]
struct Model {
    q: VecDeque<Entry>,
    /// Bumped whenever the test takes USB away or tears the ring down: the only events that may flush a frame without a generation bump.
    outage: u32,
    skipped: u64,
    delivered: u64,
}

impl Model {
    /// Pop entries ahead of `seq`: they were flushed, which is legal only if something that flushes happened since they were accepted.
    fn skip_to(&mut self, seq: u32, gen_now: u16) {
        while self.q.front().expect("a delivered frame was accepted").seq != seq {
            let e = self.q.pop_front().unwrap();
            assert!(e.gen_ != gen_now || e.outage != self.outage, "frame {} flushed with no outage or flush since it was accepted", e.seq);
            self.skipped += 1;
        }
    }
}

fn run(seed: u64, ops: u32, base: u32, chunks: u32) {
    let r = Rig::new(cfg_with(base, chunks));
    let w = r.w();
    {
        let mut o = w.obs.lock().unwrap();
        o.record = true;
    }
    let mut rng = Rng(seed);
    let mut m = Model::default();
    let mut next_seq = 0u32;
    for op_no in 0..ops {
        match rng.rnd(24) {
            0..=7 => {
                let n = match rng.rnd(5) {
                    0 => 14 + rng.rnd(60),
                    1 => 1200 + rng.rnd(319),
                    2 => 1518,
                    _ => 14 + rng.rnd(1505),
                } as usize;
                let f = build_frame(next_seq, 1, n);
                match super::world::as_producer(|| r.ring.send(&f)) {
                    Ok(()) => {
                        m.q.push_back(Entry { seq: next_seq, gen_: r.ring.generation(), outage: m.outage });
                        next_seq += 1;
                    }
                    Err(e) => assert!(matches!(e, SendError::Full | SendError::LinkDown | SendError::NotStarted), "{e:?}"),
                }
                if rng.rnd(2) != 0 {
                    r.step();
                }
            }
            8 | 9 => {
                r.credit(match rng.rnd(4) {
                    0 => 0,
                    1 => -1,
                    _ => rng.rnd(6) as i32,
                });
                r.pump();
            }
            10 => r.ring.do_drain(),
            11..=13 => {
                if rng.rnd(3) == 0 {
                    r.credit(-1);
                }
                r.in_complete();
            }
            14 => {
                r.advance_ms(if rng.rnd(3) != 0 { rng.rnd(300) } else { IDLE_MS + rng.rnd(500) });
                r.step();
            }
            15 => {
                w.gate_busy.store(rng.rnd(3) == 0, SeqCst);
                if rng.rnd(2) != 0 {
                    r.ring.elastic_kick();
                }
                r.step();
            }
            16 => {
                let extra = if rng.rnd(3) != 0 { 200_000 } else { FLOOR_FREE as i64 + i64::from(rng.rnd(8000)) };
                w.heap_total.store(w.heap_live_bytes.load(SeqCst) + extra, SeqCst);
                w.mock_largest.store(if rng.rnd(4) != 0 { 100_000 } else { FLOOR_LARGEST - 1 + rng.rnd(3000) as usize }, SeqCst);
                w.malloc_fail.store(rng.rnd(10) == 0, SeqCst);
            }
            17 => {
                w.gate_busy.store(true, SeqCst);
                if rng.rnd(2) != 0 {
                    let _ = r.ring.elastic_reclaim(0);
                } else {
                    *w.delay_hook.lock().unwrap() = Some(Arc::new(|ring: &Ring<World>| {
                        ring.env().ntb_credit.store(-1, SeqCst);
                        ring.on_in_complete(64);
                    }));
                    let _ = r.ring.elastic_reclaim(rng.rnd(40));
                    *w.delay_hook.lock().unwrap() = None;
                }
                w.gate_busy.store(rng.rnd(2) != 0, SeqCst);
            }
            18 => {
                let _ = r.ring.set_max_chunks(rng.rnd(chunks + 1));
                r.step();
            }
            19 => {
                // An outage seen by the producer, a drain, the detach event, or nobody until the poll.
                m.outage += 1;
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
            }
            20 => r.ring.flush(),
            21 => {
                // Teardown and restart: everything queued is discarded.
                m.outage += 1;
                r.ring.deinit();
                r.step();
                assert_eq!(r.ring.restart(&cfg_with(base, chunks)), Ok(()));
                let _ = r.ring.set_max_chunks(chunks);
            }
            _ => {
                r.ring.do_drain();
                r.in_complete();
            }
        }
        if w.pending() > 4 {
            r.run_deferred();
        }
        // The USB side: every delivered frame is the oldest legitimate model entry, bytes intact.
        let log = std::mem::take(&mut w.obs.lock().unwrap().log);
        for f in &log {
            let seq = u32::from_le_bytes([f[0], f[1], f[2], f[3]]);
            assert_eq!(f, &build_frame(seq, 1, f.len()), "bytes of frame {seq} (op {op_no})");
            m.skip_to(seq, r.ring.generation());
            let e = m.q.pop_front().unwrap();
            assert!(e.gen_ == r.ring.generation(), "frame {seq} of generation {} delivered in generation {}", e.gen_, r.ring.generation());
            m.delivered += 1;
        }
        // The ring's own bytes: what it still holds is the model's remainder; the rest was flushed.
        let held = r.queued_seqs();
        assert!(m.q.len() >= held.len(), "the ring holds more frames than were accepted and undelivered");
        for _ in 0..m.q.len() - held.len() {
            let e = m.q.pop_front().unwrap();
            assert!(e.gen_ != r.ring.generation() || e.outage != m.outage, "frame {} vanished with no outage or flush since it was accepted", e.seq);
            m.skipped += 1;
        }
        assert_eq!(m.q.iter().map(|e| e.seq).collect::<Vec<_>>(), held, "ring contents differ from the model (op {op_no})");
        // The counters.
        let st = r.stats();
        assert_eq!(u64::from(st.enqueued_frames), u64::from(next_seq));
        assert_eq!(st.enqueued_frames, st.sent_frames + st.flushed_link_down + r.queued(), "enq = sent + flushed + queued");
        assert_eq!(u64::from(st.sent_frames), m.delivered);
        assert_eq!(u64::from(st.flushed_link_down), m.skipped);
        r.check_invariants();
    }
    w.gate_busy.store(false, SeqCst);
    w.malloc_fail.store(false, SeqCst);
    r.drain_all();
    let st = r.stats();
    assert_eq!(st.enqueued_frames, st.sent_frames + st.flushed_link_down);
}

#[test]
fn model_seed_1() {
    run(0x9e37_79b9_7f4a_7c15, 40_000, 3, 10);
}
#[test]
fn model_seed_2() {
    run(0xd1b5_4a32_d192_ed03, 40_000, 2, 4);
}
#[test]
fn model_seed_3() {
    run(0x2545_f491_4f6c_dd1d, 40_000, 8, 12);
}
#[test]
fn model_seed_4() {
    run(0x1234_5678_9abc_def1, 40_000, 4, 0);
}
#[test]
fn model_seed_5() {
    run(0xfeed_face_cafe_beef, 40_000, 8, 10);
}
#[test]
fn model_seed_6() {
    run(88_172_645_463_325_252, 40_000, 5, 6);
}
