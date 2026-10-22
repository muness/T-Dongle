//! C5 watchdog glue. Native USB Serial/JTAG stays recoverable; no S3 rescue-bootloader contract is claimed.
use core::cell::RefCell;
use critical_section::Mutex;
use esp_hal::rtc_cntl::{Rtc, Rwdt, RwdtStage};
pub use tdongle_rescue::{HealthyTimer, Selftest};
static WATCHDOG: Mutex<RefCell<Option<Rwdt>>> = Mutex::new(RefCell::new(None));
static HEALTHY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub fn arm() {
    // SAFETY: HAL init has dropped its RTC handle; this module owns the watchdog thereafter.
    let mut rtc = Rtc::new(unsafe { esp_hal::peripherals::RTC_TIMER::steal() });
    rtc.rwdt.set_timeout(RwdtStage::Stage0, esp_hal::time::Duration::from_secs(10));
    rtc.rwdt.enable();
    critical_section::with(|cs| *WATCHDOG.borrow_ref_mut(cs) = Some(rtc.rwdt));
}
pub fn feed() {
    critical_section::with(|cs| {
        if let Some(w) = WATCHDOG.borrow_ref_mut(cs).as_mut() {
            w.feed();
        }
    });
}
pub fn disarm() {
    critical_section::with(|cs| {
        if let Some(w) = WATCHDOG.borrow_ref_mut(cs).as_mut() {
            w.disable();
        }
    });
}
pub fn mark_healthy() {
    HEALTHY.store(true, core::sync::atomic::Ordering::Relaxed);
}
pub fn demote() {
    HEALTHY.store(false, core::sync::atomic::Ordering::Relaxed);
}
pub fn report() -> tdongle_rescue::Report {
    tdongle_rescue::Report { state: if HEALTHY.load(core::sync::atomic::Ordering::Relaxed) { "c5_healthy" } else { "c5_watchdog" }, count: 0 }
}
pub fn rwdt_snapshot() -> tdongle_rescue::rwdt::Snapshot {
    // No S3 register layout is read on C5. Zero means unavailable in the legacy report.
    tdongle_rescue::rwdt::Snapshot { config: [0; 5] }
}
pub fn deliberate_reset() -> ! {
    esp_hal::system::software_reset()
}
pub fn spin() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
pub fn irqoff() -> ! {
    critical_section::with(|_| spin())
}
