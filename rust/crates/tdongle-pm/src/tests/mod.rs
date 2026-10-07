//! Port of `components/tdongle_runtime/tests/test_pm_burst.c` (the C also runs it under ThreadSanitizer), plus tests of the registry.

mod activity;
mod burst;
mod registry;

use std::prelude::v1::*;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use crate::{ArmTimer, PmBackend};

/// A hook run inside `in_isr`, with the 1-based call number.
pub type IsrHook = Arc<dyn Fn(u32) + Send + Sync>;

/// The fake ESP lock of the C test: what it holds right now, how often it was called, whether it refuses, whether it "is in an interrupt".
pub struct Fake {
    pub held: AtomicI32,
    pub acquire_calls: AtomicI32,
    pub release_calls: AtomicI32,
    pub below_zero: AtomicI32,
    pub refuse_acquire: AtomicBool,
    pub isr: AtomicBool,
    pub clock_us: AtomicU32,
    pub arms: AtomicU32,
    pub last_arm_delay: AtomicU32,
    pub isr_calls: AtomicU32,
    /// Runs inside every `in_isr` query, with the call number (1-based): the "fake interrupt test hook" of the C window test.
    pub isr_hook: Mutex<Option<IsrHook>>,
}

impl Fake {
    pub fn new() -> Self {
        Self {
            held: AtomicI32::new(0),
            acquire_calls: AtomicI32::new(0),
            release_calls: AtomicI32::new(0),
            below_zero: AtomicI32::new(0),
            refuse_acquire: AtomicBool::new(false),
            isr: AtomicBool::new(false),
            clock_us: AtomicU32::new(1000),
            arms: AtomicU32::new(0),
            last_arm_delay: AtomicU32::new(0),
            isr_calls: AtomicU32::new(0),
            isr_hook: Mutex::new(None),
        }
    }

    pub fn held(&self) -> i32 {
        self.held.load(SeqCst)
    }
    pub fn acquires(&self) -> i32 {
        self.acquire_calls.load(SeqCst)
    }
    pub fn releases(&self) -> i32 {
        self.release_calls.load(SeqCst)
    }
    pub fn arms(&self) -> u32 {
        self.arms.load(SeqCst)
    }
    pub fn below_zero(&self) -> i32 {
        self.below_zero.load(SeqCst)
    }
    pub fn set_isr(&self, v: bool) {
        self.isr.store(v, SeqCst);
    }
}

#[derive(Clone, Copy)]
pub struct FakeBackend<'a>(pub &'a Fake);

impl PmBackend for FakeBackend<'_> {
    fn acquire(&self) -> bool {
        self.0.acquire_calls.fetch_add(1, SeqCst);
        if self.0.refuse_acquire.load(SeqCst) {
            return false;
        }
        self.0.held.fetch_add(1, SeqCst);
        true
    }

    fn release(&self) {
        self.0.release_calls.fetch_add(1, SeqCst);
        if self.0.held.fetch_sub(1, SeqCst) <= 0 {
            self.0.below_zero.fetch_add(1, SeqCst);
            self.0.held.store(0, SeqCst);
        }
    }

    fn now_us(&self) -> u32 {
        self.0.clock_us.load(SeqCst)
    }

    fn in_isr(&self) -> bool {
        let n = self.0.isr_calls.fetch_add(1, SeqCst) + 1;
        let hook = self.0.isr_hook.lock().unwrap().clone();
        if let Some(h) = hook {
            h(n);
        }
        self.0.isr.load(SeqCst)
    }
}

#[derive(Clone, Copy)]
pub struct FakeTimer<'a>(pub &'a Fake);

impl ArmTimer for FakeTimer<'_> {
    fn arm(&self, delay_us: u32) {
        self.0.arms.fetch_add(1, SeqCst);
        self.0.last_arm_delay.store(delay_us, SeqCst);
    }
}
