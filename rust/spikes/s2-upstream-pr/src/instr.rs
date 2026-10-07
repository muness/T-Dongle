//! INSTRUMENTATION for the reset-loop investigation: a small record in RTC fast memory (survives the watchdog reset) written by the supervisor tick (interrupt executor) and by
//! the thread pulse (thread executor), plus the OTG interrupt handler's own timing from `esp_hal::usb::otg::isr_stats`. After a reset `boot-status` prints it as `previous_sup`.
//! The two writers use different executors on purpose: whichever one stops first is visible, and `hw` times come from the hardware timer, not from embassy-time, so a dead
//! embassy-time alarm shows as `embassy_ms` stopping while `hw_ms` keeps advancing.
#![allow(dead_code)]

use core::fmt::Write;
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use esp_hal::usb::otg::isr_stats;

const MAGIC: u32 = 0x1257_0001;
const WORDS: usize = 13;

#[esp_hal::ram(unstable(rtc_fast, persistent))]
static mut REC: [u32; WORDS] = [0; WORDS];

static PREVIOUS: embassy_sync::once_lock::OnceLock<[u32; WORDS]> = embassy_sync::once_lock::OnceLock::new();

fn put(i: usize, v: u32) {
    // SAFETY: plain word writes to a static only this module touches; a torn read after a reset is harmless (diagnostics).
    unsafe { addr_of_mut!(REC).cast::<u32>().add(i).write_volatile(v) }
}

fn hw_ms() -> u32 {
    esp_hal::time::Instant::now().duration_since_epoch().as_millis() as u32
}

/// Boot: keep what the previous boot left (if valid) for `boot-status`, then start a fresh record.
pub fn begin() {
    // SAFETY: as `put`.
    let rec = unsafe { addr_of_mut!(REC).read_volatile() };
    let _ = PREVIOUS.init(if rec[0] == MAGIC { rec } else { [0; WORDS] });
    for i in 1..WORDS {
        put(i, 0);
    }
    put(0, MAGIC);
}

fn isr(now_hw: u32) {
    put(10, isr_stats::COUNT.load(Ordering::Relaxed));
    put(11, isr_stats::MAX_US.load(Ordering::Relaxed));
    put(12, isr_stats::LAST_US.load(Ordering::Relaxed) / 1000);
    let _ = now_hw;
}

/// Supervisor tick (interrupt executor): `[ticks, embassy now ms, last feed ms, thread pulse, console pulse]`.
pub fn sup(ticks: u32, now_ms: u32, last_feed_ms: u32, thread: u32, console: u32) {
    put(1, ticks);
    put(2, now_ms);
    put(3, last_feed_ms);
    put(4, thread);
    put(5, console);
    let h = hw_ms();
    put(6, h);
    isr(h);
}

/// Thread pulse tick (thread executor).
pub fn thread(ticks: u32, now_ms: u32) {
    put(7, ticks);
    put(8, now_ms);
    let h = hw_ms();
    put(9, h);
    isr(h);
}

/// `previous_sup ...` for `boot-status`: what the previous boot's last supervisor tick, thread tick and OTG interrupt looked like.
pub fn write_previous(out: &mut impl Write) {
    let p = PREVIOUS.try_get().copied().unwrap_or([0; WORDS]);
    if p[0] != MAGIC {
        let _ = write!(out, " previous_sup=none");
        return;
    }
    let _ = write!(
        out,
        " previous_sup=[sup ticks={} embassy_ms={} hw_ms={} last_feed_ms={} pulse_thread={} pulse_console={}] [thread ticks={} embassy_ms={} hw_ms={}] [otg_irq n={} max_us={} last_hw_ms={}]",
        p[1], p[2], p[6], p[3], p[4], p[5], p[7], p[8], p[9], p[10], p[11], p[12]
    );
}

/// This boot's live values, same shape, for comparison.
pub fn write_now(out: &mut impl Write) {
    let _ = write!(
        out,
        " now_otg_irq=[n={} max_us={} last_hw_ms={}] hw_ms={}",
        isr_stats::COUNT.load(Ordering::Relaxed),
        isr_stats::MAX_US.load(Ordering::Relaxed),
        isr_stats::LAST_US.load(Ordering::Relaxed) / 1000,
        hw_ms()
    );
}
