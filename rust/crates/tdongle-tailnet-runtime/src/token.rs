//! The global negotiation token (`ml_negotiation.h`), made `async`: one [`Negotiation`] behind a blocking mutex and the polling loop the module docs of
//! `tdongle_tailnet_admission::negotiation` describe.
//!
//! * Phase A (start allocations, Noise, registration, the initial map) is one holder key per membership ([`Phase::Start`] and [`Phase::Control`] share
//!   it); phase B (the DERP TLS handshake) is another, so the token is free between a membership's two phases (ADR 0013).
//! * A waiter must poll at least every `ML_NEG_STALE_MS` (2 s) or it is reaped; [`POLL_MS`] is far below that.
//! * A future dropped while waiting leaves the queue at once (the guard releases the key, which is idempotent).
//! * A holder that never releases loses the token after `ML_NEG_LEASE_MS` (counted in `lease_expired`); the supervisor calls [`Token::reap`] every
//!   tick so that a wedged holder is noticed even when nobody else asks.

use core::cell::RefCell;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Timer;
use tdongle_tailnet_admission::negotiation::{Grant, Key, Negotiation, Phase, Prio, Status};
use tdongle_tailnet_fw::Platform;
use tdongle_tailnet_types::Millis;

/// How often a waiter polls (the C polled every 10 ms with a tick; 25 ms keeps the executor quiet).
pub const POLL_MS: u64 = 25;

/// Why [`Token::acquire`] gave up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The wait exceeded its bound.
    TimedOut,
    /// The waiter queue is full (`ML_NEG_MAX_WAITERS`).
    QueueFull,
}

/// The token.
pub struct Token<R: RawMutex> {
    neg: Mutex<R, RefCell<Negotiation>>,
}

impl<R: RawMutex> core::fmt::Debug for Token<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token")
    }
}

impl<R: RawMutex> Default for Token<R> {
    fn default() -> Self {
        Self::new()
    }
}

struct Waiting<'a, R: RawMutex> {
    token: &'a Token<R>,
    key: Key,
    now: Millis,
    done: bool,
}

impl<R: RawMutex> Drop for Waiting<'_, R> {
    fn drop(&mut self) {
        if !self.done {
            self.token.neg.lock(|n| n.borrow_mut().release(self.now, self.key));
        }
    }
}

impl<R: RawMutex> Token<R> {
    /// A free token with the C's lease, stale and aging periods.
    pub const fn new() -> Self {
        Self { neg: Mutex::new(RefCell::new(Negotiation::new(0, 0, 0))) }
    }

    /// Non-blocking, idempotent request (`ml_neg_request`).
    pub fn request(&self, now: Millis, key: Key, prio: Prio, phase: Phase) -> Grant {
        self.neg.lock(|n| n.borrow_mut().request(now, key, prio, phase))
    }

    /// Wait for the token. `timeout_ms: None` waits for ever (a join may wait behind another membership's negotiation). Cancel-safe: dropping the
    /// future takes the key out of the queue. A holder asking again is granted at once (the phase-A hand-over by key).
    pub async fn acquire<P: Platform + ?Sized>(&self, p: &P, key: Key, prio: Prio, phase: Phase, timeout_ms: Option<u32>) -> Result<(), Refused> {
        let start = p.now_ms();
        let mut w = Waiting { token: self, key, now: start, done: false };
        loop {
            let now = p.now_ms();
            w.now = now;
            match self.request(now, key, prio, phase) {
                Grant::Granted => {
                    w.done = true;
                    return Ok(());
                }
                Grant::Full => {
                    w.done = true;
                    return Err(Refused::QueueFull);
                }
                Grant::Queued => {}
            }
            if timeout_ms.is_some_and(|t| now.saturating_sub(start) >= u64::from(t)) {
                // `w` drops here and takes the key out of the queue: the failure leaves no trace, as `Acquire::poll`'s abandon does
                return Err(Refused::TimedOut);
            }
            Timer::after_millis(POLL_MS).await;
        }
    }

    /// Give the token back or leave the queue (idempotent). True if this key was the holder.
    pub fn release(&self, now: Millis, key: Key) -> bool {
        self.neg.lock(|n| n.borrow_mut().release(now, key))
    }

    /// True if `key` holds the token now.
    pub fn holds(&self, key: Key) -> bool {
        self.neg.lock(|n| n.borrow().holds(key))
    }

    /// Run the lease and stale reaping without a request of its own.
    pub fn reap(&self, now: Millis) {
        self.neg.lock(|n| {
            let mut n = n.borrow_mut();
            // a request by a key nobody uses is the cheapest way to run the reaper: it queues, is checked, and is removed again
            let probe = Key::new(0x7fff_fff0, Phase::Start);
            let _ = n.request(now, probe, Prio::Start, Phase::None);
            let _ = n.release(now, probe);
        })
    }

    /// The counters and the holder.
    pub fn status(&self, now: Millis) -> Status {
        self.neg.lock(|n| n.borrow().status(now))
    }
}

/// Key of the phase-A hold of a membership (start allocations, Noise, registration, initial map).
pub fn key_control(member: u32) -> Key {
    Key::new(member, Phase::Control)
}

/// Key of the phase-B hold of a membership (the DERP TLS handshake).
pub fn key_derp(member: u32) -> Key {
    Key::new(member, Phase::Derp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use futures::executor::block_on;
    use std::time::Instant;
    use tdongle_tailnet_fw::HeapProbe;

    struct P(Instant);
    struct NoHeap;
    impl HeapProbe for NoHeap {
        fn free(&self) -> usize {
            0
        }
        fn largest_block(&self) -> usize {
            0
        }
        fn minimum_free(&self) -> usize {
            0
        }
    }
    impl Platform for P {
        fn now_ms(&self) -> Millis {
            self.0.elapsed().as_millis() as u64
        }
        fn unix_seconds(&self) -> Option<u64> {
            None
        }
        fn fill_random(&self, _: &mut [u8]) {}
        fn sta_mac(&self) -> [u8; 6] {
            [0; 6]
        }
        fn heap(&self) -> &dyn HeapProbe {
            &NoHeap
        }
        fn console_line(&self, _: &str) {}
    }

    #[test]
    fn second_waiter_gets_it_after_release_and_a_dropped_waiter_leaves_the_queue() {
        let t = Token::<NoopRawMutex>::new();
        let p = P(Instant::now());
        let (a, b) = (key_control(1), key_control(2));
        block_on(t.acquire(&p, a, Prio::Start, Phase::Control, Some(100))).unwrap();
        assert!(t.holds(a));
        // b waits and times out: no trace left
        assert_eq!(block_on(t.acquire(&p, b, Prio::Start, Phase::Control, Some(60))), Err(Refused::TimedOut));
        assert_eq!(t.status(p.now_ms()).waiting, 0);
        // b waits, a releases: b is granted
        let r = block_on(async {
            let waiter = t.acquire(&p, b, Prio::Start, Phase::Control, Some(2000));
            let releaser = async {
                Timer::after_millis(30).await;
                t.release(p.now_ms(), a);
            };
            futures::future::join(waiter, releaser).await.0
        });
        assert_eq!(r, Ok(()));
        assert!(t.holds(b));
        // the holder asking again is granted (hand-over by key)
        assert_eq!(block_on(t.acquire(&p, b, Prio::Rejoin, Phase::Control, Some(10))), Ok(()));
        // a future dropped mid-wait leaves the queue
        {
            let mut fut = std::pin::pin!(t.acquire(&p, a, Prio::Start, Phase::Control, None));
            let _ = futures::FutureExt::now_or_never(&mut fut);
            assert_eq!(t.status(p.now_ms()).waiting, 1);
        }
        assert_eq!(t.status(p.now_ms()).waiting, 0);
        assert!(t.release(p.now_ms(), b));
        assert!(!t.release(p.now_ms(), b));
    }
}
