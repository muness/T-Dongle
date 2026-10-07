//! Randomized operation sequences against the identities, and real threads (the Rust analogue of `test_bridge_path.c`'s six random seeds and
//! `test_bridge_threads.c`'s seven threads).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use super::*;

/// xorshift64, the generator the C tests use.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u32) -> u32 {
        (self.next() % u64::from(n)) as u32
    }
}

/// A random frame: ARP, IPv4 TCP/UDP with random ECN bits, IPv6, or noise; from the host (STA MAC source) or from the network.
fn random_frame(rng: &mut Rng, from_host: bool) -> Vec<u8> {
    let len = match rng.below(4) {
        0 => 14 + rng.below(60) as usize,
        1 => 60 + rng.below(200) as usize,
        2 => 1000 + rng.below(515) as usize, // up to 1514
        _ => rng.below(1700) as usize,       // includes runts and oversize
    };
    let mut f = vec![0u8; len];
    for byte in &mut f {
        *byte = rng.next() as u8;
    }
    if len >= 14 {
        let dst = if rng.below(8) == 0 { if rng.below(2) == 0 { BCAST } else { MCAST } } else { PEER };
        f[..6].copy_from_slice(&dst);
        let src = match rng.below(20) {
            0 => PEER, // foreign (host) / ordinary (network)
            _ => MAC,
        };
        let src = if from_host {
            src
        } else if rng.below(10) == 0 {
            MAC
        } else {
            PEER
        };
        f[6..12].copy_from_slice(&src);
        match rng.below(4) {
            0 => {
                f[12] = 0x08;
                f[13] = 0x06; // ARP
            }
            1 | 2 if len >= 54 => {
                f[12] = 0x08;
                f[13] = 0x00;
                f[14] = 0x45;
                f[15] = rng.next() as u8;
                f[23] = if rng.below(2) == 0 { 6 } else { 17 };
                f[20] &= 0x1f; // mostly unfragmented
                if rng.below(4) != 0 {
                    f[20] = 0;
                    f[21] = 0;
                }
            }
            _ if len >= 60 => {
                f[12] = 0x86;
                f[13] = 0xdd;
                f[14] = 0x60 | (rng.next() as u8 & 0x0f);
                f[20] = [6u8, 17, 58, 0, 43, 44, 60][rng.below(7) as usize];
            }
            _ => {}
        }
    }
    f
}

fn random_run(seed: u64, ops: u32, codel: bool) {
    let mut rng = Rng(seed | 1);
    let mut w = W::new();
    let t = Tuning { codel, ..Tuning::DEFAULT };
    assert_eq!(w.b.set_tuning(&t), Ok(()));
    let mut linked = false;
    for step in 0..ops {
        match rng.below(100) {
            0..=24 => {
                let f = random_frame(&mut rng, true);
                let outcome = w.host_in(&f);
                if outcome.is_hold() {
                    assert!(w.b.held.load(Ordering::SeqCst) || w.env().resumes.get() > 0 || w.stats().h2w_queue_depth > 0);
                }
            }
            25..=44 => w.wifi_in(&random_frame(&mut rng, false)),
            45..=69 => {
                w.pump();
            }
            70..=77 => w.advance_us(rng.below(30_000)),
            78..=80 => {
                linked = !linked;
                w.b.link(linked, &ctx());
            }
            81..=85 => w.env().room.set(rng.below(3) != 0),
            86..=89 => w.env().tx_default.set(match rng.below(4) {
                0 => Err(TxError::NoMem),
                1 => Err(TxError::Other(-1)),
                _ => Ok(()),
            }),
            90..=92 => w.env().ring_result.set(match rng.below(4) {
                0 => RingSend::Full,
                1 => RingSend::NotReady,
                2 => RingSend::Invalid,
                _ => RingSend::Accepted,
            }),
            93..=95 => {
                let t = Tuning {
                    queue_limit: 1 + rng.below(HOST_SLOTS as u32),
                    resume_depth: 0,
                    sojourn_ms: SOJOURN_MS_MIN + rng.below(SOJOURN_MS_MAX - SOJOURN_MS_MIN),
                    codel: rng.below(2) == 0,
                    codel_target_us: CODEL_TARGET_US_MIN + rng.below(10_000),
                    codel_interval_ms: CODEL_INTERVAL_MS_MIN + rng.below(300),
                };
                let t = Tuning { resume_depth: rng.below(t.queue_limit), ..t };
                assert_eq!(w.b.set_tuning(&t), Ok(()));
            }
            _ => {
                // A burst from the host as fast as it can go: exercises HOLD and resume.
                for _ in 0..10 {
                    let f = random_frame(&mut rng, true);
                    let _ = w.host_in(&f);
                }
            }
        }
        // Single-threaded: the system is at rest after every operation (pump drains to empty), so the identities must hold now.
        let s = w.stats();
        assert_eq!(s.check_identities(), Ok(()), "seed {seed} step {step}: {s:#?}");
        assert!(s.h2w_queue_depth <= HOST_SLOTS as u32, "seed {seed} step {step}: depth {}", s.h2w_queue_depth);
    }
    w.pump();
    w.check_identities();
}

#[test]
fn random_operations_keep_every_identity() {
    for (i, seed) in [88_172_645_463_325_252u64, 0x9e37_79b9_7f4a_7c15, 12_345, 777_777_777, 4_242_424_242, 99].into_iter().enumerate() {
        random_run(seed, 60_000, i % 3 != 0);
    }
}

// ---- real threads --------------------------------------------------------------------------------------------------------------------

/// A thread-safe world: counts what it was given and checks the bytes.
struct LiveEnv {
    start: Instant,
    ring_frames: AtomicU32,
    tx_frames: AtomicU32,
    tx_refuse_every: AtomicU32,
    tx_calls: AtomicU32,
    resume: AtomicBool,
    bad_bytes: AtomicU32,
    ring_flushes: AtomicU32,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl Env for LiveEnv {
    fn now_us(&self) -> u32 {
        self.start.elapsed().as_micros() as u32
    }
    fn usb_ring_send(&self, frame: &[u8]) -> RingSend {
        // Frames from the network carry a counter in bytes 12..16; every one must arrive intact.
        if frame.len() >= 16 && frame[12..16] != frame[frame.len() - 4..] {
            self.bad_bytes.fetch_add(1, Ordering::Relaxed);
        }
        self.ring_frames.fetch_add(1, Ordering::Relaxed);
        RingSend::Accepted
    }
    fn usb_ring_flush(&self) {
        self.ring_flushes.fetch_add(1, Ordering::Relaxed);
    }
    fn usb_link_state(&self, _up: bool) {}
    fn wifi_rx_register(&self, _on: bool) {}
    fn notify_worker(&self) {}
    fn wifi_tx(&self, frame: &[u8], _context: &TaskContext) -> Result<(), TxError> {
        let n = self.tx_calls.fetch_add(1, Ordering::Relaxed);
        let every = self.tx_refuse_every.load(Ordering::Relaxed);
        if every != 0 && n.is_multiple_of(every) {
            return Err(TxError::NoMem);
        }
        // Host frames carry the same counter at both ends: a torn slot (producer overwrote it under the worker) shows up as a mismatch.
        if frame[12..16] != frame[frame.len() - 4..] {
            self.bad_bytes.fetch_add(1, Ordering::Relaxed);
        }
        self.tx_frames.fetch_add(1, Ordering::Relaxed);
        self.sent.lock().unwrap().push(frame[12..16].to_vec());
        Ok(())
    }
    fn wifi_room(&self) -> bool {
        true
    }
    fn wait_retry(&self, _context: &TaskContext) {
        thread::sleep(Duration::from_micros(50));
    }
    fn rx_resume(&self, _context: &TaskContext) {
        self.resume.store(true, Ordering::SeqCst);
    }
    fn note_activity(&self) {}
}

fn counted_frame(n: u32, len: usize, from_host: bool) -> Vec<u8> {
    let mut f = frame(len, &PEER, if from_host { &MAC } else { &PEER }, 0);
    f[12..16].copy_from_slice(&n.to_be_bytes());
    let end = f.len();
    f[end - 4..].copy_from_slice(&n.to_be_bytes());
    f
}

/// The TinyUSB task (one producer), the worker, the Wi-Fi task and the event task (link flaps) run for real; at the end the system is quiesced
/// and every identity must hold, every host frame that reached `wifi_tx` must be intact and in order, and the producer must never be wedged
/// by a missed resume.
#[test]
fn threads_keep_identities_and_bytes() {
    let env = LiveEnv {
        start: Instant::now(),
        ring_frames: AtomicU32::new(0),
        tx_frames: AtomicU32::new(0),
        tx_refuse_every: AtomicU32::new(7),
        tx_calls: AtomicU32::new(0),
        resume: AtomicBool::new(false),
        bad_bytes: AtomicU32::new(0),
        ring_flushes: AtomicU32::new(0),
        sent: Mutex::new(Vec::new()),
    };
    let bridge: &'static Bridge<LiveEnv> = Box::leak(Box::new(Bridge::new(env, MAC)));
    bridge.link(true, &ctx());
    let stop = Arc::new(AtomicBool::new(false));
    let wifi_stop = stop.clone();
    let flap_stop = stop.clone();
    let worker_stop = stop.clone();
    let offered = Arc::new(AtomicU32::new(0));
    let offered_by_producer = offered.clone();

    let producer = thread::spawn(move || {
        let mut p = bridge.producer().unwrap();
        let mut n = 0u32;
        let deadline = Instant::now() + Duration::from_secs(30);
        while n < 150_000 {
            let f = counted_frame(n, 60 + (n as usize * 37) % 1400, true);
            loop {
                match p.host(&f) {
                    HostOutcome::Hold => {
                        // The class driver keeps the datagram and offers it again after a resume; a resume that never comes is a wedge.
                        bridge.env().resume.store(false, Ordering::SeqCst);
                        let waited = Instant::now();
                        while !bridge.env().resume.load(Ordering::SeqCst) {
                            // Resumes can also be missed legitimately only if the queue has room: re-offering finds it.
                            if bridge.stats().h2w_queue_depth < bridge.tuning().queue_limit {
                                break;
                            }
                            assert!(waited.elapsed() < Duration::from_secs(5) && Instant::now() < deadline, "the producer is wedged by a missed resume");
                            thread::yield_now();
                        }
                    }
                    HostOutcome::LinkDown => thread::yield_now(), // the link flapped: the host retries later
                    _ => break,
                }
            }
            n += 1;
            offered_by_producer.store(n, Ordering::Relaxed);
        }
    });
    let worker = thread::spawn(move || {
        let mut w = bridge.worker().unwrap();
        while !worker_stop.load(Ordering::Relaxed) || bridge.stats().h2w_queue_depth > 0 {
            if w.drain() == 0 {
                thread::yield_now();
            }
        }
    });
    let wifi = thread::spawn(move || {
        let mut n = 0u32;
        while !wifi_stop.load(Ordering::Relaxed) {
            let _ = bridge.wifi_rx(&counted_frame(n, 80 + (n as usize * 13) % 1400, false));
            n += 1;
            if n.is_multiple_of(64) {
                thread::yield_now();
            }
        }
    });
    let flapper = thread::spawn(move || {
        let mut up = true;
        while !flap_stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(3));
            up = !up;
            bridge.link(up, &ctx());
            if !up {
                thread::sleep(Duration::from_millis(1));
                bridge.link(true, &ctx());
                up = true;
            }
        }
    });

    producer.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    wifi.join().unwrap();
    flapper.join().unwrap();
    worker.join().unwrap();
    bridge.link(true, &ctx());

    let s = bridge.stats();
    assert_eq!(s.check_identities(), Ok(()), "{s:#?}");
    assert_eq!(bridge.env().bad_bytes.load(Ordering::Relaxed), 0, "a frame was torn or corrupted between the callback and the driver");
    assert_eq!(s.h2w_queue_depth, 0);
    assert_eq!(s.h2w_frames, offered.load(Ordering::Relaxed) + s.h2w_link_down, "every offered frame was taken exactly once (link-down refusals are retried)");
    // Order: the frames the driver accepted are a subsequence of the offered counters, strictly increasing.
    let sent = bridge.env().sent.lock().unwrap();
    let mut previous: Option<u32> = None;
    for counter in sent.iter() {
        let value = u32::from_be_bytes(counter[..4].try_into().unwrap());
        assert!(previous.is_none_or(|p| value > p), "frames were reordered: {previous:?} then {value}");
        previous = Some(value);
    }
    assert!(s.h2w_sent > 1000 && s.h2w_held > 0 && s.link_changes > 4, "the scenario did not exercise the paths: {s:#?}");
}
