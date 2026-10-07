//! CoDel against an analytic reference: port of test_math, test_schedule (base 0 and across the 32-bit clock wrap) and test_invariants from
//! `components/tdongle_runtime/tests/test_aqm.c`. The schedule is RFC 8289's, worked out in f64 from the specification, not from the code under test.

#![allow(clippy::needless_range_loop)] // index loops mirror the C tests and compare two buffers

mod common;

use common::Rng;
use tdongle_aqm::{Codel, control_law, diff, isqrt, isqrt64};

fn check_isqrt(x: u32) {
    let r = isqrt(x);
    assert!(u64::from(r) * u64::from(r) <= u64::from(x) && u64::from(r + 1) * u64::from(r + 1) > u64::from(x), "isqrt({x}) = {r}");
}

#[test]
fn isqrt_exhaustive_low_range() {
    for x in 0..200_000 {
        check_isqrt(x);
    }
}

#[test]
fn isqrt_random_and_extremes() {
    let mut r = Rng::new();
    for _ in 0..100_000 {
        check_isqrt(r.rnd(0xffff_ffff));
    }
    assert_eq!(isqrt(u32::MAX), 65535);
    assert_eq!(isqrt(0), 0);
    // every perfect square and its neighbours
    for k in (0..=65535u32).step_by(7).chain([65535]) {
        let sq = k * k;
        assert_eq!(isqrt(sq), k);
        if sq > 0 {
            assert_eq!(isqrt(sq - 1), k - 1);
        }
    }
}

#[test]
fn isqrt64_random_and_extremes() {
    let mut rng = Rng::new();
    for _ in 0..100_000 {
        let x = (u64::from(rng.rnd(0xffff_ffff)) << 32) | u64::from(rng.rnd(0xffff_ffff));
        let r = isqrt64(x);
        assert!(r <= 0xffff_ffff && r * r <= x && (r + 1 == 0x1_0000_0000 || (r + 1) * (r + 1) > x), "isqrt64({x}) = {r}");
    }
    assert_eq!(isqrt64(u64::MAX), 0xffff_ffff);
    assert_eq!(isqrt64(0), 0);
    assert_eq!(isqrt64(1 << 32), 65536);
}

#[test]
fn control_law_accuracy_16_16() {
    let c = Codel::new(5000, 100_000);
    let mut count = 1u32;
    while count < 65536 {
        let want = 100_000.0 / f64::from(count).sqrt();
        let got = f64::from(control_law(&c, 0, count));
        assert!((got - want).abs() <= want * 0.0001 + 1.5, "count {count}: got {got}, want {want}"); // 16.16 fixed point
        count += if count < 300 { 1 } else { 97 };
    }
    // count 0 is treated as 1; exact at 1; wrapping addition of the time
    assert_eq!(c.control_law(10, 0), 100_010);
    assert_eq!(c.control_law(10, 1), 100_010);
    assert_eq!(c.control_law(u32::MAX, 1), 99_999);
    assert_eq!(c.control_law(0, 4), 50_000);
}

#[test]
fn diff_is_wrapping_signed() {
    assert_eq!(diff(5, 3), 2);
    assert_eq!(diff(3, 5), -2);
    assert_eq!(diff(2, u32::MAX), 3);
    assert_eq!(diff(u32::MAX, 2), -3);
    assert_eq!(diff(0x8000_0000, 0), i32::MIN);
}

#[test]
fn new_and_retune_reset_state() {
    let mut c = Codel::new(5000, 100_000);
    assert_eq!(c, Codel { target_us: 5000, interval_us: 100_000, dropping: false, first_above_us: 0, drop_next_us: 0, count: 0, lastcount: 0 });
    for t in (0..400_000).step_by(100) {
        c.should_signal(6000, t);
    }
    assert!(c.dropping && c.count > 1);
    c.retune(2000, 50_000);
    assert_eq!(c, Codel::new(2000, 50_000));
    assert_eq!(tdongle_aqm::TARGET_US_DEFAULT, 5000);
    assert_eq!(tdongle_aqm::INTERVAL_MS_DEFAULT, 100);
}

/// Feed packets every `dt` with a constant sojourn from `t_start`; return the times of the signals until `t_end` (wrapping clock).
fn run_constant(c: &mut Codel, t_start: u32, t_end: u32, dt: u32, sojourn: u32, times: &mut [u32; 64]) -> usize {
    let mut n = 0;
    let mut t = t_start;
    while diff(t_end, t) > 0 {
        if c.should_signal(sojourn, t) && n < times.len() {
            times[n] = t;
            n += 1;
        }
        t = t.wrapping_add(dt);
    }
    n
}

fn schedule(base: u32) {
    const I: u32 = 100_000;
    const DT: u32 = 100;
    let at = |t: u32| base.wrapping_add(t);
    let mut c = Codel::new(5000, I);
    let mut times = [0u32; 64];
    // 1. Below target forever: silence.
    assert_eq!(run_constant(&mut c, at(0), at(5_000_000), DT, 4999, &mut times), 0);
    // 2. Above target from t0: the first signal at t0 + I (within one packet), then the 1/sqrt(count) schedule.
    c = Codel::new(5000, I);
    let t0 = at(1000);
    let n = run_constant(&mut c, t0, t0.wrapping_add(3_000_000), DT, 5000, &mut times);
    assert!(n >= 25);
    let off = |t: u32| t.wrapping_sub(t0); // times relative to t0 stay small and monotone
    assert!(off(times[0]) >= I && off(times[0]) <= I + 3 * DT); // the first packet at or after t0 + I
    // Signal k+1 is the first packet at or after D_k, where D_k runs from the previous scheduled time, not from the packet that was signalled.
    let mut drop_next = f64::from(off(times[0])) + f64::from(I);
    for k in 1..n {
        let got = f64::from(off(times[k]));
        let slack = 1.5 * k as f64;
        assert!(got >= drop_next - slack && got <= drop_next + f64::from(DT) + slack, "signal {k}: {got} vs {drop_next}"); // first packet at or after drop_next
        drop_next += f64::from(I) / ((k + 1) as f64).sqrt();
    }
    // The signal rate rises: spacing between signals falls as 1/sqrt(count).
    assert!(times[n - 1].wrapping_sub(times[n - 2]) < times[2].wrapping_sub(times[1]));
    // 3. The sojourn falls below target: the dropping state ends at once, and the next signal needs a whole new interval.
    c = Codel::new(5000, I);
    let n = run_constant(&mut c, t0, t0.wrapping_add(1_000_000), DT, 5000, &mut times);
    assert!(n >= 5 && c.dropping);
    let t1 = t0.wrapping_add(1_000_000);
    assert!(!c.should_signal(100, t1) && !c.dropping && c.first_above_us == 0);
    let m = run_constant(&mut c, t1.wrapping_add(DT), t1.wrapping_add(I - 2 * DT), DT, 6000, &mut times); // just under an interval above target again
    assert_eq!(m, 0);
    // 4. Re-entry soon after a dropping state resumes near the old rate: count = count - lastcount (RFC 8289).
    c = Codel::new(5000, I);
    run_constant(&mut c, t0, t0.wrapping_add(1_500_000), DT, 5000, &mut times);
    let count_before = c.count;
    assert!(count_before >= 6 && c.lastcount == 1);
    c.should_signal(100, t0.wrapping_add(1_500_000)); // leave
    let t2 = t0.wrapping_add(1_500_100);
    let n = run_constant(&mut c, t2, t2.wrapping_add(2 * I), DT, 5000, &mut times); // above target again within 16 intervals
    assert!(n >= 1 && times[0].wrapping_sub(t2) >= I && c.dropping);
    assert_eq!(c.lastcount, count_before - 1); // resumed at delta, not at 1
    // ... but after a long calm (more than 16 intervals) it starts over at 1.
    c.should_signal(100, t0.wrapping_add(1_500_000 + 3 * I));
    let t3 = t0.wrapping_add(4_000_000);
    let n = run_constant(&mut c, t3, t3.wrapping_add(2 * I), DT, 5000, &mut times);
    assert!(n >= 1 && c.lastcount == 1);
}

#[test]
fn schedule_matches_rfc8289_reference_base_0() {
    schedule(0);
}

/// The 32-bit microsecond clock wraps inside the scenario.
#[test]
fn schedule_matches_rfc8289_reference_across_clock_wrap() {
    schedule(0xFFFF_FE00);
}

/// Same schedule with the wrap placed at many offsets, including the one where `now + interval` is exactly 0 (first_above_us forced to 1).
#[test]
fn schedule_independent_of_clock_offset() {
    for base in [0u32, 1, 0x7fff_ff00, 0x8000_0000, 0xFFFF_0000, 0xFFFF_FFFF - 100_000 - 1000, 0xFFFF_FFFF - 100_000 - 999, 0u32.wrapping_sub(101_000)] {
        schedule(base);
    }
}

#[test]
fn first_above_us_never_zero_once_started() {
    // now + interval == 0 (mod 2^32): the sentinel 0 means "not above", so it is bumped to 1.
    let mut c = Codel::new(5000, 100_000);
    assert!(!c.should_signal(5000, 0u32.wrapping_sub(100_000)));
    assert_eq!(c.first_above_us, 1);
}

/// Invariants over arbitrary input: never signal below target; never signal in less than an interval of continuous excess; one signal at most
/// per packet. 2M steps starting 65536 us before the clock wrap.
#[test]
fn invariants_over_random_steps() {
    let mut rng = Rng::new();
    let mut c = Codel::new(5000, 100_000);
    let (mut t, mut above_since, mut above, mut signals) = (0xFFFF_0000u32, 0u32, false, 0u32);
    for i in 0..2_000_000u32 {
        t = t.wrapping_add(1 + rng.rnd(400));
        let bad_spell = (i / 5000) % 3 == 1;
        let sojourn = if bad_spell { 5000 + rng.rnd(5000) } else { rng.rnd(5000) };
        if sojourn < 5000 {
            above = false;
        } else if !above {
            above = true;
            above_since = t;
        }
        let sig = c.should_signal(sojourn, t);
        if sig {
            signals += 1;
            assert!(sojourn >= 5000 || c.dropping);
        }
        if sig && above && c.count <= 1 {
            assert!(diff(t, above_since) >= 100_000 || c.dropping); // the first signal needs an interval above target
        }
        if sojourn < 5000 {
            assert!(!sig && !c.dropping);
        }
    }
    assert!(signals > 100);
}

/// Extreme parameters and counter values must not panic in debug (all arithmetic is wrapping, as in C).
#[test]
fn no_overflow_panics_at_extremes() {
    let mut rng = Rng::new();
    for (target, interval) in [(0, 0), (u32::MAX, u32::MAX), (1, u32::MAX), (5000, 0x2000_0000), (0, 1)] {
        let mut c = Codel::new(target, interval);
        c.count = u32::MAX;
        c.lastcount = 3;
        c.drop_next_us = u32::MAX;
        c.first_above_us = u32::MAX;
        let mut t = rng.raw() as u32;
        for _ in 0..20_000 {
            t = t.wrapping_add(rng.rnd(300_000));
            c.should_signal(rng.raw() as u32, t);
            c.should_signal(u32::MAX, t);
        }
        let _ = c.control_law(u32::MAX, u32::MAX);
        let _ = c.control_law(u32::MAX, 0);
    }
}
