//! Port of the C `tests/test_wg_replay.c` (unit, edge, limit, adversarial, exhaustive, differential and reorder tests against an exact reference model),
//! run at every ring size the C ran (64, 128, 512, 2048 and 8192 bits), plus proptest.

use super::*;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::vec::Vec;

const LIMIT: u64 = REJECT_AFTER_MESSAGES;

/// The specification: a counter is accepted iff it is below the reject limit, not more than WINDOW below the highest accepted counter, and not accepted before.
struct Model {
    seen: BTreeSet<u64>,
    max: u64,
    window: u64,
}
impl Model {
    fn new(window: u64) -> Self {
        Model { seen: BTreeSet::new(), max: 0, window }
    }
    fn check(&mut self, v: u64) -> ReplayVerdict {
        if v >= LIMIT {
            return ReplayVerdict::Limit;
        }
        if v < self.max && self.max - v > self.window {
            return ReplayVerdict::TooOld;
        }
        if self.seen.contains(&v) {
            return ReplayVerdict::Duplicate;
        }
        self.seen.insert(v);
        if v > self.max {
            self.max = v;
        }
        ReplayVerdict::Ok
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn same<const B: usize>(r: &mut ReplayRing<B>, m: &mut Model, v: u64) {
    let peeked = r.peek(v);
    let a = r.check(v);
    let b = m.check(v);
    assert_eq!(a, b, "counter={v} ring={} max={}", ReplayRing::<B>::RING_BITS, m.max);
    assert_eq!(peeked, a, "peek disagrees with check for {v}");
}

fn basics<const B: usize>() {
    let mut r = ReplayRing::<B>::new();
    assert_eq!(r.check(0), ReplayVerdict::Ok); // counters start at 0 and 0 is a valid one
    assert_eq!(r.check(0), ReplayVerdict::Duplicate);
    assert_eq!(r.check(1), ReplayVerdict::Ok);
    assert_eq!(r.check(1), ReplayVerdict::Duplicate);
    assert_eq!(r.check(0), ReplayVerdict::Duplicate);
    // a gap, then the gap filled out of order, each once
    assert_eq!(r.check(10), ReplayVerdict::Ok);
    for i in 2..10 {
        assert_eq!(r.check(i), ReplayVerdict::Ok);
    }
    for i in 0..=10 {
        assert_eq!(r.check(i), ReplayVerdict::Duplicate);
    }
    // a session that starts at a high counter (first packet lost)
    r.reset();
    assert_eq!(r.check(12345), ReplayVerdict::Ok);
    assert_eq!(r.check(12345), ReplayVerdict::Duplicate);
    assert_eq!(r.check(12344), ReplayVerdict::Ok); // unseen and inside the window
    assert_eq!(ReplayRing::<B>::BYTES, 8 + B * 4);
}

fn window_edges<const B: usize>() {
    let w = ReplayRing::<B>::WINDOW;
    let bits = ReplayRing::<B>::RING_BITS as u64;
    for top in (w + 1)..(w + 3 * bits) {
        let mut r = ReplayRing::<B>::new();
        assert_eq!(r.check(top), ReplayVerdict::Ok);
        assert_eq!(r.check(top - w - 1), ReplayVerdict::TooOld);
        assert_eq!(r.check(top - w), ReplayVerdict::Ok);
        assert_eq!(r.check(top - w), ReplayVerdict::Duplicate);
        assert_eq!(r.check(top - w + 1), ReplayVerdict::Ok);
        // advance by one: what was the edge is now too old, and an accepted one stays a duplicate
        assert_eq!(r.check(top + 1), ReplayVerdict::Ok);
        assert_eq!(r.check(top - w), ReplayVerdict::TooOld);
        assert_eq!(r.check(top - w + 1), ReplayVerdict::Duplicate);
        assert_eq!(r.check(top - w + 2), ReplayVerdict::Ok);
    }
    // Jumps of exactly one block, the window, the ring and beyond forget everything older, and nothing old comes back.
    let jumps = [1, 31, 32, 33, w - 1, w, w + 1, bits - 1, bits, bits + 1, 2 * bits, 1 << 20, 1 << 40, 1 << 62];
    for j in jumps {
        let mut r = ReplayRing::<B>::new();
        let mut m = Model::new(w);
        let base = 5000u64;
        for i in 0..40 {
            same(&mut r, &mut m, base + i * 2); // every other counter
        }
        for i in 0..40 {
            same(&mut r, &mut m, base + i * 2); // all duplicates
        }
        same(&mut r, &mut m, base + 78 + j);
        for i in 0..100 {
            same(&mut r, &mut m, base + 78 + j - i); // the neighbourhood, top down
        }
        for i in 0..80 {
            same(&mut r, &mut m, base + i); // the old region: must follow the model
        }
    }
}

fn limits<const B: usize>() {
    let w = ReplayRing::<B>::WINDOW;
    let mut r = ReplayRing::<B>::new();
    for v in [u64::MAX, u64::MAX - 1, LIMIT, LIMIT + 1] {
        assert_eq!(r.check(v), ReplayVerdict::Limit);
        assert_eq!(r.peek(v), ReplayVerdict::Limit);
    }
    assert_eq!(r.highest(), 0); // a refused counter changes nothing
    assert!(r.ring.iter().all(|&x| x == 0));
    assert_eq!(r.check(LIMIT - 1), ReplayVerdict::Ok);
    assert_eq!(r.check(LIMIT - 1), ReplayVerdict::Duplicate);
    assert_eq!(r.check(LIMIT), ReplayVerdict::Limit);
    assert_eq!(r.check(LIMIT - 1 - w), ReplayVerdict::Ok); // the window edge at the top of the number space: no wrap
    assert_eq!(r.check(LIMIT - 2 - w), ReplayVerdict::TooOld);
    assert_eq!(r.check(0), ReplayVerdict::TooOld); // a tiny counter must not wrap into the window
    assert_eq!(r.check(1), ReplayVerdict::TooOld);
    // The model agrees on a walk up to the limit in odd strides (stride 3 hits every block offset).
    let mut r = ReplayRing::<B>::new();
    let mut m = Model::new(w);
    let mut v = LIMIT - 400;
    while v < LIMIT + 5 {
        same(&mut r, &mut m, v);
        v += 3;
    }
    for v in (LIMIT - 400)..(LIMIT + 5) {
        same(&mut r, &mut m, v);
    }
    assert_eq!(LIMIT, 0xFFFF_FFFF_FFFF_FFFF - (1 << 13));
}

fn adversarial<const B: usize>() {
    let w = ReplayRing::<B>::WINDOW;
    // An attacker who can replay any captured authentic datagram, in any order, any number of times, must never get a counter accepted twice.
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut r = ReplayRing::<B>::new();
    let mut accepted: Vec<u64> = Vec::new();
    for c in 0..3000u64 {
        if r.check(c * 3) == ReplayVerdict::Ok {
            accepted.push(c * 3); // legitimate stream, gaps of 2
        }
        for _ in 0..4 {
            let v = accepted[(rng.next() % accepted.len() as u64) as usize];
            let verdict = r.check(v);
            assert!(matches!(verdict, ReplayVerdict::Duplicate | ReplayVerdict::TooOld));
        }
    }
    assert_eq!(accepted.len(), 3000);
    // replay of the very first and last packets after a long idle jump
    assert_eq!(r.check(3 * 3000 + (1 << 33)), ReplayVerdict::Ok);
    for v in &accepted {
        assert_eq!(r.check(*v), ReplayVerdict::TooOld);
    }
    // Fill the whole window with every other counter, then the odd ones in reverse: each exactly once.
    let mut r = ReplayRing::<B>::new();
    let top = 100_000u64;
    assert_eq!(r.check(top), ReplayVerdict::Ok);
    for d in (2..=w).step_by(2) {
        assert_eq!(r.check(top - d), ReplayVerdict::Ok);
    }
    for d in (1..=w).step_by(2) {
        assert_eq!(r.check(top - d), ReplayVerdict::Ok);
    }
    for d in 0..=w {
        assert_eq!(r.check(top - d), ReplayVerdict::Duplicate);
    }
    assert_eq!(r.check(top - w - 1), ReplayVerdict::TooOld);
}

/// Every sequence of `len` counters drawn from `[offset, offset + span)`: exhaustive against the model.
fn exhaust<const B: usize>(span: u64, len: u32, offset: u64) {
    let w = ReplayRing::<B>::WINDOW;
    let total = span.pow(len);
    for n in 0..total {
        let mut x = n;
        let mut r = ReplayRing::<B>::new();
        let mut m = Model::new(w);
        for _ in 0..len {
            same(&mut r, &mut m, offset + x % span);
            x /= span;
        }
    }
}

fn draw<const B: usize>(rng: &mut Rng, front: u64, mode: u32) -> u64 {
    let w = ReplayRing::<B>::WINDOW;
    let bits = ReplayRing::<B>::RING_BITS as u64;
    match mode {
        0 => front.wrapping_add(rng.next() % 8), // in order with jitter
        1 => {
            if front > w + 8 {
                front - rng.next() % (w + 8)
            } else {
                front
            }
        } // reordered around the window edge
        2 => front.wrapping_add(rng.next() % (3 * bits)), // jumps of a few rings
        3 => rng.next() % 64,                    // replays from the bottom
        4 => front - if front > 0 { rng.next() % (if front < 40 { front + 1 } else { 40 }) } else { 0 }, // recent duplicates
        5 => LIMIT - 1 - rng.next() % (2 * bits), // top of the number space
        _ => rng.next(),                         // anything, mostly >= LIMIT
    }
}

fn differential<const B: usize>(iterations: u64) {
    let w = ReplayRing::<B>::WINDOW;
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for it in 0..iterations {
        let mut r = ReplayRing::<B>::new();
        let mut m = Model::new(w);
        let mut front = match it & 3 {
            0 => 0,
            1 => rng.next() % 100_000,
            2 => (1u64 << 32) - 50 + rng.next() % 100,
            _ => LIMIT - 5000,
        };
        let len = 200 + rng.next() % 1800;
        for _ in 0..len {
            let m100 = rng.next() % 100;
            let mode = if m100 < 55 {
                0
            } else if m100 < 70 {
                1
            } else if m100 < 75 {
                2
            } else if m100 < 85 {
                3
            } else if m100 < 95 {
                4
            } else if m100 < 98 {
                5
            } else {
                6
            };
            let mut v = draw::<B>(&mut rng, front, mode);
            if (it & 3) == 3 && mode < 5 {
                v = front.wrapping_add(rng.next() % 16); // the near-limit runs advance towards the limit
            }
            same(&mut r, &mut m, v);
            if m.max > front && m.max < LIMIT {
                front = m.max;
            } else if (it & 3) == 3 && front + 4 < LIMIT {
                front += 3;
            }
        }
    }
}

/// The arrival patterns that motivated the ring: lateness within the window must lose nothing.
fn reorder<const B: usize>() {
    let w = ReplayRing::<B>::WINDOW;
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for depth in [2usize, 8, 32, 33, 64, 200, 400] {
        let total = 20_000usize;
        let mut order: Vec<u64> = (0..total as u64).collect();
        let mut base = 0;
        while base + depth <= total {
            for i in (1..depth).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                order.swap(base + i, base + j);
            }
            base += depth;
        }
        let mut r = ReplayRing::<B>::new();
        let ok = order.iter().filter(|&&c| r.check(c) == ReplayVerdict::Ok).count();
        if depth as u64 <= w {
            assert_eq!(ok, total, "no loss while the lateness ({depth}) fits the window ({w})");
        }
    }
    // One burst out of order by more than the window: exactly the packets beyond it are refused, as specified.
    let mut r = ReplayRing::<B>::new();
    assert_eq!(r.check(10_000), ReplayVerdict::Ok);
    let refused = (9000..10_000u64).filter(|&c| r.check(c) == ReplayVerdict::TooOld).count() as u64;
    assert_eq!(refused, 1000u64.saturating_sub(w));
}

fn suite<const B: usize>() {
    basics::<B>();
    window_edges::<B>();
    limits::<B>();
    adversarial::<B>();
    exhaust::<B>(48, 4, 0);
    exhaust::<B>(40, 4, 1000);
    exhaust::<B>(20, 5, 0xFFFF_FFFF - 8); // across the 32-bit counter boundary the legacy code truncated at
    exhaust::<B>(24, 4, LIMIT - 20); // against the reject limit
    differential::<B>(if cfg!(debug_assertions) { 300 } else { 3000 });
    reorder::<B>();
}

#[test]
fn ring_64_bits() {
    suite::<2>();
}
#[test]
fn ring_128_bits() {
    suite::<4>();
}
#[test]
fn ring_512_bits_firmware_size() {
    suite::<16>();
    assert_eq!(ReplayWindow::RING_BITS, 512);
    assert_eq!(ReplayWindow::WINDOW, 480);
    assert_eq!(ReplayWindow::BYTES, 72);
}
#[test]
fn ring_2048_bits() {
    suite::<64>();
}
#[test]
fn ring_8192_bits() {
    suite::<256>();
}

/// What the 32-bit RFC 2401 register this replaced lost: shows the 512-bit ring keeps reordering the register dropped.
#[test]
fn legacy_register_loses_what_the_ring_keeps() {
    fn legacy(bitmap: &mut u32, counter: &mut u64, seq: u64) -> bool {
        let seq = seq + 1;
        if seq > *counter {
            let diff = seq - *counter;
            if diff < 32 {
                *bitmap = (*bitmap << diff) | 1
            } else {
                *bitmap = 1
            }
            *counter = seq;
            true
        } else {
            let diff = *counter - seq;
            if diff < 32 && *bitmap & (1 << diff) == 0 {
                *bitmap |= 1 << diff;
                true
            } else {
                false
            }
        }
    }
    let mut rng = Rng(77);
    let depth = 200usize;
    let total = 20_000usize;
    let mut order: Vec<u64> = (0..total as u64).collect();
    for base in (0..total).step_by(depth) {
        for i in (1..depth).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            order.swap(base + i, base + j);
        }
    }
    let mut r = ReplayWindow::new();
    let (mut bm, mut c) = (0u32, 0u64);
    let ring_ok = order.iter().filter(|&&x| r.check(x) == ReplayVerdict::Ok).count();
    let legacy_ok = order.iter().filter(|&&x| legacy(&mut bm, &mut c, x)).count();
    assert_eq!(ring_ok, total);
    assert!(legacy_ok < total);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any sequence of counters, drawn from several regimes, agrees with the exact model; `peek` never disagrees with `check` and never mutates.
    #[test]
    fn matches_model(seq in proptest::collection::vec((0u8..4, any::<u64>()), 1..400)) {
        let mut r = ReplayWindow::new();
        let mut m = Model::new(ReplayWindow::WINDOW);
        let mut front = 0u64;
        for (mode, raw) in seq {
            let v = match mode {
                0 => front.saturating_add(raw % 700),
                1 => front.saturating_sub(raw % 700),
                2 => raw % 3000,
                _ => LIMIT.saturating_sub(raw % 3000),
            };
            let before = r.clone();
            let p = r.peek(v);
            prop_assert_eq!(&before, &r);
            let a = r.check(v);
            let b = m.check(v);
            prop_assert_eq!(a, b);
            prop_assert_eq!(p, a);
            if m.max < LIMIT { front = m.max; }
        }
    }

    /// Every counter is accepted at most once, whatever the order.
    #[test]
    fn accepted_at_most_once(seq in proptest::collection::vec(0u64..2000, 1..600)) {
        let mut r = ReplayWindow::new();
        let mut accepted = BTreeSet::new();
        for v in seq {
            if r.check(v) == ReplayVerdict::Ok {
                prop_assert!(accepted.insert(v), "{} accepted twice", v);
            }
        }
    }
}
