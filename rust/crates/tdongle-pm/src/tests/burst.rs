//! The burst cases of the C test: nesting, error paths, interrupt refusal, task exit, a reference model, threads.

use std::prelude::v1::*;
use std::sync::atomic::Ordering::SeqCst;

use super::{Fake, FakeBackend};
use crate::{BurstName, NAME_MAX, NoBackend, PmBurst};

fn burst(f: &Fake) -> PmBurst<FakeBackend<'_>> {
    PmBurst::new("t", FakeBackend(f))
}

#[test]
fn nesting() {
    let f = Fake::new();
    let b = burst(&f);
    b.begin();
    assert_eq!(f.held(), 1);
    b.begin();
    b.begin();
    assert!(f.held() == 1 && f.acquires() == 1); // nesting only counts
    b.end();
    b.end();
    assert_eq!(f.held(), 1); // outermost still open
    f.clock_us.fetch_add(250, SeqCst);
    b.end();
    assert!(f.held() == 0 && f.releases() == 1);
    let s = b.stats();
    assert!(s.acquires == 1 && s.releases == 1 && s.max_depth == 3 && s.depth == 0 && s.held_us == 250 && s.underflows == 0);
    for _ in 0..100 {
        b.begin();
        b.end();
    }
    let s = b.stats();
    assert!(s.acquires == 101 && s.releases == 101 && f.held() == 0);
}

#[test]
fn error_paths() {
    let f = Fake::new();
    let b = burst(&f);
    b.end(); // end without begin
    b.end();
    assert!(b.stats().underflows == 2 && f.releases() == 0 && f.held() == 0);
    b.begin();
    b.end();
    b.end(); // extra end after a pair
    assert!(b.stats().underflows == 3 && f.held() == 0 && b.stats().depth == 0);
    // the lock is refused: counted, depth still balances, nothing is held, and the object recovers
    f.refuse_acquire.store(true, SeqCst);
    b.begin();
    assert!(b.stats().backend_failures == 1 && f.held() == 0);
    b.end();
    assert_eq!(b.stats().depth, 0);
    f.below_zero.store(0, SeqCst);
    f.refuse_acquire.store(false, SeqCst);
    b.begin();
    assert_eq!(f.held(), 1);
    b.end();
    assert!(f.held() == 0 && f.below_zero() == 0);
    // no backend at all: counts, never crashes
    let none = PmBurst::new("n", NoBackend);
    none.begin();
    none.end();
    none.release_all();
    assert!(none.stats().acquires == 1 && none.stats().releases == 1);
}

#[test]
fn isr() {
    let f = Fake::new();
    let b = burst(&f);
    f.set_isr(true);
    b.begin();
    b.end();
    b.release_all();
    let s = b.stats();
    assert!(s.isr_rejects == 3 && s.acquires == 0 && s.depth == 0 && f.acquires() == 0 && f.releases() == 0);
    f.set_isr(false);
    b.begin();
    f.set_isr(true);
    b.end(); // an end from an interrupt must not release
    f.set_isr(false);
    assert!(f.held() == 1 && b.stats().depth == 1);
    b.end();
    assert_eq!(f.held(), 0);
}

#[test]
fn release_all() {
    let f = Fake::new();
    let b = burst(&f);
    b.release_all(); // idle: nothing
    assert!(f.releases() == 0 && b.stats().forced_releases == 0);
    b.begin();
    b.begin();
    b.begin();
    f.clock_us.fetch_add(40, SeqCst);
    b.release_all(); // the task exits mid-burst
    assert!(f.held() == 0 && f.releases() == 1);
    let s = b.stats();
    assert!(s.forced_releases == 1 && s.depth == 0 && s.held_us == 40 && s.releases == 1);
    b.end(); // a stray end afterwards is an underflow
    assert!(b.stats().underflows == 1 && f.held() == 0);
    b.begin();
    b.end();
    assert_eq!(f.held(), 0); // reusable
}

/// A reference model: the lock is held exactly while the model depth is above zero.
#[test]
fn model() {
    let f = Fake::new();
    let b = burst(&f);
    let mut x: u32 = 12345;
    let mut depth = 0u32;
    for _ in 0..200_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let op = x % 16;
        if op < 7 {
            b.begin();
            depth += 1;
        } else if op < 14 {
            b.end();
            depth = depth.saturating_sub(1);
        } else if op == 14 {
            b.release_all();
            depth = 0;
        } else {
            b.end();
            depth = depth.saturating_sub(1);
        }
        assert_eq!(f.held(), i32::from(depth > 0));
        assert_eq!(b.stats().depth, depth);
    }
    assert_eq!(f.below_zero(), 0);
    let s = b.stats();
    assert_eq!(s.acquires, s.releases + u32::from(depth != 0));
}

const THREADS: usize = 4;
const CYCLES: u32 = 50_000;

#[test]
fn threads() {
    let f = Fake::new();
    let shared = burst(&f);
    std::thread::scope(|sc| {
        for i in 0..THREADS {
            let shared = &shared;
            sc.spawn(move || {
                for c in 0..CYCLES {
                    shared.begin();
                    if c % 3 == 0 {
                        shared.begin();
                        shared.end();
                    }
                    shared.end();
                }
                if i == 0 {
                    shared.begin(); // ... task body fails here ...
                }
            });
        }
    });
    // thread 0 "exited" with its section open: the owner's exit path closes it. Only its own depth is left.
    assert!(shared.stats().depth == 1 && f.held() == 1);
    shared.release_all();
    let s = shared.stats();
    assert!(f.held() == 0 && s.depth == 0 && f.below_zero() == 0 && s.underflows == 0);
    assert!(s.acquires == s.releases && s.acquires == f.acquires() as u32);
}

#[test]
fn burst_names() {
    assert_eq!(BurstName::new("fwd_activity").as_str(), "fwd_activity");
    assert_eq!(BurstName::EMPTY.as_str(), "");
    let long = "0123456789012345678901234567890";
    assert_eq!(BurstName::new(long).as_str(), &long[..NAME_MAX]);
    // cut on a character boundary: 22 ASCII bytes then a 3-byte character that would straddle the limit
    let s = "0123456789012345678901\u{20ac}x";
    assert_eq!(BurstName::new(s).as_str(), "0123456789012345678901");
    let f = Fake::new();
    assert_eq!(burst(&f).stats().name.as_str(), "t");
}
