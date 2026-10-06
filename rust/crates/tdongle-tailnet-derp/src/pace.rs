//! When the link may try to connect again (`ml_derp_pace.h`).
//!
//! A connect attempt that fails for a reason of its own (refused, certificate not authenticated, handshake error) doubles the wait up to a ceiling. A
//! connect that cannot even be tried because the wall clock is not set (certificates cannot be judged) is not a failure of the relay: it neither raises
//! the wait nor counts as a retry, and the first attempt follows the clock at once.

use tdongle_tailnet_types::Millis;

/// The retry ladder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pace {
    /// The current wait.
    pub backoff_ms: u32,
    /// When the next attempt is due; 0 = not armed.
    pub next_ms: Millis,
    /// Times a connect was held back for the clock.
    pub deferrals: u32,
    /// True while held back for the clock.
    pub waiting_for_clock: bool,
}

impl Pace {
    /// A fresh ladder starting at `min_ms`.
    pub const fn new(min_ms: u32) -> Self {
        Self { backoff_ms: min_ms, next_ms: 0, deferrals: 0, waiting_for_clock: false }
    }

    /// Back to the first rung. The deferral count is kept (it is a statistic, not state).
    pub fn reset(&mut self, min_ms: u32) {
        self.backoff_ms = min_ms;
        self.next_ms = 0;
        self.waiting_for_clock = false;
    }

    /// True when a connect should be attempted now. The first call after a reset arms the timer and returns false.
    pub fn due(&mut self, now: Millis, clock_valid: bool, min_ms: u32) -> bool {
        if !clock_valid {
            if !self.waiting_for_clock {
                self.waiting_for_clock = true;
                self.deferrals = self.deferrals.saturating_add(1);
            }
            self.backoff_ms = min_ms;
            self.next_ms = 0;
            return false;
        }
        if self.waiting_for_clock {
            // the clock just arrived: connect now, not after the wait
            self.waiting_for_clock = false;
            self.next_ms = now;
            return true;
        }
        if self.next_ms == 0 {
            self.next_ms = now.saturating_add(self.backoff_ms as Millis);
            return false;
        }
        now >= self.next_ms
    }

    /// The attempt made after `due()` returned true failed: double the wait up to `max_ms`.
    pub fn failed(&mut self, now: Millis, max_ms: u32) {
        self.backoff_ms = if self.backoff_ms > max_ms / 2 { max_ms } else { self.backoff_ms * 2 };
        self.next_ms = now.saturating_add(self.backoff_ms as Millis);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u32 = 5000;
    const MAX: u32 = 60000;

    #[test]
    fn first_call_arms_then_fires_after_the_minimum() {
        let mut p = Pace::new(MIN);
        assert!(!p.due(1000, true, MIN));
        assert_eq!(p.next_ms, 6000);
        assert!(!p.due(5999, true, MIN));
        assert!(p.due(6000, true, MIN));
    }

    #[test]
    fn ladder_doubles_and_saturates_at_the_ceiling() {
        let mut p = Pace::new(MIN);
        let mut waits = std::vec::Vec::new();
        let mut now = 0;
        for _ in 0..7 {
            p.failed(now, MAX);
            waits.push(p.backoff_ms);
            now = p.next_ms;
        }
        assert_eq!(waits, [10000, 20000, 40000, 60000, 60000, 60000, 60000]);
    }

    #[test]
    fn no_clock_is_not_a_failure() {
        let mut p = Pace::new(MIN);
        p.failed(0, MAX); // backoff 10 s
        assert!(!p.due(100, false, MIN));
        assert!(!p.due(200, false, MIN));
        assert_eq!(p.deferrals, 1, "counted once per hold, not per poll");
        assert_eq!(p.backoff_ms, MIN, "the wait does not grow while the clock is unset");
        // the clock arrives: connect at once, no wait
        assert!(p.due(300, true, MIN));
        assert!(!p.waiting_for_clock);
        assert_eq!(p.next_ms, 300);
        assert!(p.due(301, true, MIN));
    }

    #[test]
    fn a_second_hold_counts_again() {
        let mut p = Pace::new(MIN);
        assert!(!p.due(0, false, MIN));
        assert!(p.due(1, true, MIN));
        assert!(!p.due(2, false, MIN));
        assert_eq!(p.deferrals, 2);
    }

    #[test]
    fn reset_keeps_the_statistic() {
        let mut p = Pace::new(MIN);
        p.due(0, false, MIN);
        p.failed(10, MAX);
        p.reset(MIN);
        assert_eq!((p.backoff_ms, p.next_ms, p.waiting_for_clock, p.deferrals), (MIN, 0, false, 1));
    }
}
