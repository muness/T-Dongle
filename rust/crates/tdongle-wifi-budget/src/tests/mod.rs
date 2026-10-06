//! Port of `alternative/tailnet/tests/test_wifi_pin_budget.c`, plus tests of `room`, the TX limit and the `wifi_pins_tx` decision.

mod floor;
mod rules;
mod sim;
mod threads;
mod tx;

use std::cell::Cell;
use std::prelude::v1::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::{RawLock, WifiPins};

std::thread_local! {
    static HELD: Cell<bool> = const { Cell::new(false) };
}

/// A spin lock that asserts it is never nested and counts how often it was entered (the C test's mutex).
#[derive(Debug)]
pub struct TestLock {
    flag: AtomicBool,
    pub entered: AtomicUsize,
}

impl TestLock {
    pub const fn new() -> Self {
        Self { flag: AtomicBool::new(false), entered: AtomicUsize::new(0) }
    }
}

impl RawLock for TestLock {
    fn lock(&self) {
        while self.flag.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            std::thread::yield_now();
        }
        assert!(!HELD.with(Cell::get), "the critical section was nested");
        HELD.with(|h| h.set(true));
        self.entered.fetch_add(1, Ordering::Relaxed);
    }

    fn unlock(&self) {
        assert!(HELD.with(Cell::get));
        HELD.with(|h| h.set(false));
        self.flag.store(false, Ordering::Release);
    }
}

pub type Pins = WifiPins<TestLock>;

pub fn pins() -> Pins {
    WifiPins::new(TestLock::new())
}

/// The C test's generator: `(rs >> 11) % n` over xorshift64.
#[derive(Clone, Debug)]
pub struct Rs(pub u64);

impl Rs {
    pub fn rnd(&mut self, n: u32) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        ((self.0 >> 11) % u64::from(n)) as u32
    }
}

/// Quiescent: charged = released by any road + still outstanding (`conserved_tx`).
pub fn conserved_tx(b: &Pins) {
    let s = b.stats();
    assert_eq!(s.tx_charged, s.tx_done + s.tx_aborted + s.tx_flushed + s.tx_stale + s.tx_outstanding);
    assert!(s.tx_outstanding <= crate::GATEWAY_WIFI_TX_POOL as u32);
}

/// `conserved_rx`.
pub fn conserved_rx(b: &Pins) {
    let s = b.stats();
    assert_eq!(s.rx_band + s.rx_elastic, s.rx_released + s.rx_inflight);
}
