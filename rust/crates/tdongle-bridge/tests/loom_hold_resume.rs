//! A loom model of the host queue's hold/resume handshake (ADR 0023 amendment 2): the producer says HOLD at the queue limit and publishes a
//! `held` flag BEFORE it looks at the queue again; the worker releases a slot and then swaps the flag away and resumes. Every interleaving must end with
//! every offered frame taken, no datagram stranded behind a hold nobody will answer (the lost wake-up the C tests could only argue about).
//!
//! **Known limit, found by running it:** loom models `SeqCst` as acquire/release (its documentation says so), and this handshake is a store-buffering
//! (Dekker) pattern that is only correct under sequential consistency: the producer stores `held` then reads `tail`; the worker stores `tail` then
//! reads `held`. Loom therefore reports a deadlock in an execution that real SeqCst atomics (and the Xtensa `memw`-fenced code the compiler emits for
//! them) forbid. The test is kept, `#[ignore]`d, as the executable statement of the property; the property itself is checked by
//! `tests/sc_handshake.rs`, an exhaustive enumeration of every interleaving of the protocol's steps under sequential consistency, and the data-race
//! freedom of the slots is what `tdongle-spsc/tests/loom_spsc.rs` checks with loom proper.
//!
//! Run: `RUSTFLAGS="--cfg loom" cargo test -p tdongle-bridge --test loom_hold_resume --release`.
#![cfg(loom)]

use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;
use tdongle_bridge::{Bridge, Env, HostOutcome, RingSend, TaskContext, Tuning, TxError};

/// The two wake-ups the firmware has: the worker's task notification, and the class driver's "offer the held datagram again". Both are blocking
/// waits here, so loom reports a lost wake-up as a deadlock instead of letting a spin loop paper over it.
#[derive(Default)]
struct Signals {
    state: Mutex<State>,
    wake: Condvar,
}

#[derive(Default)]
struct State {
    work: u32,
    resumed: bool,
    done: bool,
    sent: u32,
}

impl Env for Signals {
    fn now_us(&self) -> u32 {
        1000
    }
    fn usb_ring_send(&self, _frame: &[u8]) -> RingSend {
        RingSend::Accepted
    }
    fn usb_ring_flush(&self) {}
    fn usb_link_state(&self, _up: bool) {}
    fn wifi_rx_register(&self, _on: bool) {}
    fn notify_worker(&self) {
        self.state.lock().unwrap().work += 1;
        self.wake.notify_all();
    }
    fn wifi_tx(&self, _frame: &[u8], _context: &TaskContext) -> Result<(), TxError> {
        self.state.lock().unwrap().sent += 1;
        Ok(())
    }
    fn wifi_room(&self) -> bool {
        true
    }
    fn wait_retry(&self, _context: &TaskContext) {}
    fn rx_resume(&self, _context: &TaskContext) {
        self.state.lock().unwrap().resumed = true;
        self.wake.notify_all();
    }
    fn note_activity(&self) {}
}

const MAC: [u8; 6] = [2, 1, 2, 3, 4, 5];

fn frame() -> [u8; 60] {
    let mut f = [0u8; 60];
    f[..6].copy_from_slice(&[0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
    f[6..12].copy_from_slice(&MAC);
    f
}

#[test]
#[ignore = "loom treats SeqCst as acquire/release and cannot express this store-buffering handshake; see the module documentation"]
fn a_held_datagram_is_always_offered_again() {
    // The bridge's queue (12 KB of slots) is built by value: give the model's first thread a stack that can hold it.
    loom::model(|| thread::Builder::new().stack_size(512 * 1024).spawn(scenario).unwrap().join().unwrap());
}

fn scenario() {
    {
        let bridge = Arc::new(Bridge::new(Signals::default(), MAC));
        // SAFETY: a test, which is a task that may block.
        let context = unsafe { TaskContext::assume() };
        bridge.link(true, &context);
        let tuning = Tuning { queue_limit: 2, resume_depth: 1, codel: false, ..bridge.tuning() };
        bridge.set_tuning(&tuning).unwrap();
        const FRAMES: u32 = 3;

        let producer = {
            let bridge = bridge.clone();
            thread::spawn(move || {
                let mut producer = bridge.producer().unwrap();
                for _ in 0..FRAMES {
                    loop {
                        match producer.host(&frame()) {
                            HostOutcome::Queued => break,
                            HostOutcome::Hold => {
                                // The class driver keeps the datagram and offers it again ONLY after a resume: it does not poll. A resume that
                                // never comes leaves this thread waiting for ever, which loom reports as a deadlock: the lost wake-up.
                                let env = bridge.env();
                                let mut state = env.state.lock().unwrap();
                                while !state.resumed {
                                    state = env.wake.wait(state).unwrap();
                                }
                                state.resumed = false;
                            }
                            other => panic!("unexpected {other:?}"),
                        }
                    }
                }
                bridge.env().state.lock().unwrap().done = true;
                bridge.env().wake.notify_all();
            })
        };
        let worker = {
            let bridge = bridge.clone();
            thread::spawn(move || {
                let mut worker = bridge.worker().unwrap();
                loop {
                    let finished = {
                        let env = bridge.env();
                        let mut state = env.state.lock().unwrap();
                        while state.work == 0 && !state.done {
                            state = env.wake.wait(state).unwrap();
                        }
                        state.work = 0;
                        state.done
                    };
                    worker.drain();
                    if finished {
                        break;
                    }
                }
            })
        };
        producer.join().unwrap();
        worker.join().unwrap();
        let stats = bridge.stats();
        assert_eq!(stats.check_identities(), Ok(()));
        assert_eq!((stats.h2w_queued, stats.h2w_sent, bridge.env().state.lock().unwrap().sent), (FRAMES, FRAMES, FRAMES));
    }
}
