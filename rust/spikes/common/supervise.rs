//! Progress supervision and the rescue self-tests, shared by the esp-hal images. Included with `#[path = "../../common/supervise.rs"] mod supervise;`.
//!
//! Two executors (the console and USB device in an interrupt-mode one, everything else in the thread executor), a heartbeat in each, and a supervisor in the
//! higher-priority one that feeds the hardware watchdogs **only while both heartbeats advance** (`tdongle_boot_guard::watch`), calls the image healthy only after USB is
//! configured and everything has advanced for 30 s (`tdongle_rescue::HealthyTimer`), and names a stalled executor before resetting.
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_executor::SendSpawner;
use embassy_sync::once_lock::OnceLock;
use embassy_time::{Instant, Timer};
use tdongle_boot_guard::watch::{Verdict, Watch};
use tdongle_rescue::{HealthyTimer, Selftest};

use crate::guard;

/// Bumped by `thread_pulse_task` (thread executor) and by the console task's own loop (so a console that stops being polled stops it).
pub static PULSE_THREAD: AtomicU32 = AtomicU32::new(0);
pub static PULSE_CONSOLE: AtomicU32 = AtomicU32::new(0);
/// The host has configured the device (set by the USB handler's `configured`).
pub static USB_CONFIGURED: AtomicBool = AtomicBool::new(false);
/// `selftest console`: the console task stops being polled.
pub static CONSOLE_FROZEN: AtomicBool = AtomicBool::new(false);
/// A spawner of the thread executor, for `selftest spin`.
pub static THREAD_SPAWNER: OnceLock<SendSpawner> = OnceLock::new();

/// The supervisor's own counters (`boot-status` `sup`): a supervisor that stopped, or one that never feeds, shows here without a debugger.
pub static SUP_TICKS: AtomicU32 = AtomicU32::new(0);
pub static SUP_FEEDS: AtomicU32 = AtomicU32::new(0);

/// `[ticks, feeds, thread pulse, console pulse]`.
pub fn stats() -> [u32; 4] {
    [SUP_TICKS.load(Ordering::Relaxed), SUP_FEEDS.load(Ordering::Relaxed), PULSE_THREAD.load(Ordering::Relaxed), PULSE_CONSOLE.load(Ordering::Relaxed)]
}

/// The console task calls this at the top of its loop: it proves the console is polled, and `selftest console` parks it for good.
pub async fn console_alive() {
    PULSE_CONSOLE.fetch_add(1, Ordering::Relaxed);
    if CONSOLE_FROZEN.load(Ordering::Relaxed) {
        core::future::pending::<()>().await;
    }
}

#[embassy_executor::task]
pub async fn thread_pulse_task() -> ! {
    loop {
        PULSE_THREAD.fetch_add(1, Ordering::Relaxed);
        Timer::after_millis(500).await;
    }
}

#[embassy_executor::task]
async fn spin_task() -> ! {
    tdongle_rescue::spin()
}

/// Feeds the watchdogs while both executors make progress; otherwise records which one did not and resets. Marks the image healthy (bootloader) and the boot stable (guard) once
/// USB has been configured and everything advanced for `HEALTHY_AFTER_MS`. Runs in the interrupt executor: nothing in the thread executor can starve it.
#[embassy_executor::task]
pub async fn supervisor_task(mut dogs: guard::Dogs, safe_mode: bool) -> ! {
    // deadlines: the thread executor may be inside a long synchronous call (radio init takes seconds) but must come back well inside the 10 s hardware watchdog
    let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], Instant::now().as_millis());
    let mut healthy = HealthyTimer::new();
    let mut marked = false;
    loop {
        let now = Instant::now().as_millis();
        SUP_TICKS.fetch_add(1, Ordering::Relaxed);
        match watch.check(now, [PULSE_THREAD.load(Ordering::Relaxed), PULSE_CONSOLE.load(Ordering::Relaxed)]) {
            Verdict::Healthy => {
                dogs.feed();
                SUP_FEEDS.fetch_add(1, Ordering::Relaxed);
                if healthy.observe(now, USB_CONFIGURED.load(Ordering::Relaxed)) && !marked {
                    tdongle_rescue::mark_healthy();
                    guard::mark_stable(safe_mode);
                    marked = true;
                }
            }
            Verdict::Stalled(task) => {
                healthy.observe(now, false);
                guard::hang(task);
                esp_hal::system::software_reset()
            }
        }
        Timer::after_millis(500).await;
    }
}

/// `selftest NAME`: deliberately break the image so the rescue is proven on the board. Returns only for `console` (the console task parks itself at its next turn).
pub fn selftest(kind: Selftest) {
    tdongle_rescue::demote(); // count this reset against the image even if it had become healthy
    match kind {
        Selftest::Spin => {
            if let Some(spawner) = THREAD_SPAWNER.try_get() {
                if let Ok(token) = spin_task() {
                    spawner.spawn(token);
                }
            }
        }
        Selftest::IrqOff => tdongle_rescue::irqoff(),
        Selftest::Panic => panic!("selftest panic"),
        Selftest::Console => CONSOLE_FROZEN.store(true, Ordering::Relaxed),
    }
}
