//! The activity-hold cases of the C test.

use std::prelude::v1::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};

use super::{Fake, FakeBackend, FakeTimer};
use crate::{ActivityState, NoTimer, PmActivity, PmBurst};

fn setup(f: &Fake) -> (PmBurst<FakeBackend<'_>>, FakeTimer<'_>) {
    (PmBurst::new("fwd", FakeBackend(f)), FakeTimer(f))
}

#[test]
fn activity() {
    let f = Fake::new();
    let (b, t) = setup(&f);
    let a = PmActivity::new(&b, 200_000, t);
    a.tick(5000); // idle tick: nothing
    assert!(f.held() == 0 && f.arms() == 0);
    a.note(1000); // first packet: one acquire, one timer
    assert!(f.held() == 1 && f.arms() == 1 && f.last_arm_delay.load(SeqCst) == 200_000);
    let mut ts = 1100;
    while ts < 150_000 {
        a.note(ts); // a stream: no more acquires
        ts += 100;
    }
    assert!(f.acquires() == 1 && f.arms() == 1 && a.starts() == 1);
    a.tick(200_000); // last note 149,900: 50 ms in, 150 ms left
    assert!(f.held() == 1 && f.arms() == 2 && f.last_arm_delay.load(SeqCst) == 200_000 - (200_000 - 149_900));
    a.tick(349_899); // one us short
    assert!(f.held() == 1 && f.releases() == 0);
    a.tick(349_900); // hold_us since the last note: released
    assert!(f.held() == 0 && f.releases() == 1 && b.stats().depth == 0);
    a.tick(500_000); // idle again: nothing to do
    assert_eq!(f.releases(), 1);
    a.note(600_000); // and it restarts
    assert!(f.held() == 1 && a.starts() == 2 && f.arms() == 4);
    assert!(b.stats().acquires == 2 && b.stats().underflows == 0);
}

/// A tick that read the clock before a concurrent note (now < last) must treat the note as "just now".
#[test]
fn activity_stale_clock() {
    let f = Fake::new();
    let (b, t) = setup(&f);
    let a = PmActivity::new(&b, 200_000, t);
    a.note(1000);
    a.note(900_000);
    a.tick(800_000); // now is 100 ms older than the newest note
    assert!(f.held() == 1 && f.releases() == 0);
    // wrap: notes and ticks around the 2^32 us rollover
    let f = Fake::new();
    let (b, t) = setup(&f);
    let a = PmActivity::new(&b, 200_000, t);
    a.note(0xffff_ff00);
    a.tick(0x0000_0100 + 100_000); // 100 ms later across the wrap: still held
    assert_eq!(f.held(), 1);
    a.tick(0x0000_0100 + 250_000);
    assert_eq!(f.held(), 0);
}

#[test]
fn activity_isr() {
    let f = Fake::new();
    let (b, t) = setup(&f);
    let a = PmActivity::new(&b, 200_000, t);
    f.set_isr(true);
    a.note(1000);
    f.set_isr(false);
    assert!(f.held() == 0 && b.stats().isr_rejects == 1 && a.starts() == 0);
    a.note(2000); // the next task-context note works
    assert_eq!(f.held(), 1);
}

/// A tick that preempts a note between "the activity flag is set" and "the burst begins" (a real window: `note()` ran `activity_start`, which
/// published `held` before it took the lock) used to end a burst that had not begun: an underflow, and then the note's begin left the lock held
/// with the flag clear, so nothing would ever release it. The fake interrupt test hook runs at the start of every begin/end, which is exactly
/// that window, so the interleaving is forced here.
#[test]
fn activity_tick_inside_start() {
    let f: &'static Fake = Box::leak(Box::new(Fake::new()));
    let b: &'static PmBurst<FakeBackend<'static>> = Box::leak(Box::new(PmBurst::new("fwd", FakeBackend(f))));
    let a: &'static PmActivity<'static, NoTimer> = Box::leak(Box::new(PmActivity::new(b, 200_000, NoTimer)));
    a.note(1000); // take the lock once so `held` is set...
    a.tick(1000 + 250_000); // ...and let the quiet spell release it
    assert!(f.held() == 0 && b.stats().depth == 0);
    let armed = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicU32::new(0));
    let window_now = 1000 + 250_000 * 3; // the tick would find the spell long over
    {
        let (armed, calls) = (Arc::clone(&armed), Arc::clone(&calls));
        *f.isr_hook.lock().unwrap() = Some(Arc::new(move |_| {
            // call 1 is note() asking whether it runs in an interrupt; call 2 is the begin inside activity_start
            if armed.load(SeqCst) && calls.fetch_add(1, SeqCst) + 1 == 2 {
                armed.store(false, SeqCst);
                a.tick(window_now);
            }
        }));
    }
    armed.store(true, SeqCst);
    a.note(1000 + 250_000 * 2); // idle -> active, with the tick landing inside it
    armed.store(false, SeqCst);
    let s = b.stats();
    assert_eq!(s.underflows, 0); // no end without its begin
    // Whatever the tick decided, the flag and the lock must agree: held <=> one begin outstanding.
    assert!(s.depth == u32::from(a.held()) && f.held() == s.depth as i32);
    *f.isr_hook.lock().unwrap() = None;
    a.tick(1000 + 250_000 * 5); // a later tick releases it
    let s = b.stats();
    assert!(f.held() == 0 && s.depth == 0 && s.underflows == 0 && f.below_zero() == 0);
}

/// Producers note continuously while a timer thread ticks: the lock is never released under a live stream's feet for long, never leaked, and
/// always balanced.
#[test]
fn activity_threads() {
    let f = Fake::new();
    let (b, t) = setup(&f);
    let a = PmActivity::new(&b, 200_000, t);
    let stop = AtomicBool::new(false);
    let clock = AtomicU32::new(1000);
    std::thread::scope(|sc| {
        let mut producers = Vec::new();
        for _ in 0..3 {
            producers.push(sc.spawn(|| {
                for i in 0..100_000 {
                    a.note(clock.fetch_add(7, SeqCst));
                    if i % 1000 == 0 {
                        clock.fetch_add(300_000, SeqCst); // quiet spells: the ticker releases
                    }
                }
            }));
        }
        let ticker = sc.spawn(|| {
            while !stop.load(SeqCst) {
                a.tick(clock.load(SeqCst));
            }
        });
        for p in producers {
            p.join().unwrap();
        }
        stop.store(true, SeqCst);
        ticker.join().unwrap();
    });
    // drain: far in the future nothing is held any more, and the lock count matches the flag
    a.tick(clock.load(SeqCst).wrapping_add(1_000_000));
    let s = b.stats();
    assert!(f.held() == 0 && s.depth == 0 && s.underflows == 0 && f.below_zero() == 0);
    assert_eq!(s.acquires, s.releases); // every begin, including the one a losing note undoes, is matched by an end
}

#[test]
fn state_without_collaborators() {
    // `ActivityState` is the same logic with the burst and timer passed per call (what `Pm` uses).
    let f = Fake::new();
    let (b, t) = setup(&f);
    let st = ActivityState::new(1000);
    st.note(&b, &t, 10);
    assert!(st.held() && st.starts() == 1 && f.arms() == 1);
    st.tick(&b, &t, 20); // 10 us in: re-armed for what is left, but never for less than a millisecond
    assert!(st.held() && f.arms() == 2 && f.last_arm_delay.load(SeqCst) == 1000);
    st.tick(&b, &t, 2000);
    assert!(!st.held() && f.held() == 0);
}
