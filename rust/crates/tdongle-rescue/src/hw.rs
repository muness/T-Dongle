//! The hardware half: `RTC_CNTL_STORE0`, the RTC watchdog and the self-tests. The only unsafe code in the crate, each use with its reason.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use critical_section::Mutex;
use esp_hal::peripherals::RTC_TIMER;
use esp_hal::rtc_cntl::{Rtc, Rwdt, RwdtStage};
use esp_hal::time::Duration;

use crate::{ARMED, HEALTHY, Report, WATCHDOG_MS, armed_word, decode, rwdt, state_name, word};

/// `RTC_CNTL_STORE0_REG` of the ESP32-S3: `DR_REG_RTCCNTL_BASE (0x6000_8000) + 0x50`. esp-hal does not use it.
const STORE0: *mut u32 = 0x6000_8050 as *mut u32;

static RWDT: Mutex<RefCell<Option<Rwdt>>> = Mutex::new(RefCell::new(None));
/// The count the bootloader handed over (0 when the word was not ours), and the state byte now.
static HANDED_COUNT: AtomicU32 = AtomicU32::new(0);
static STATE: AtomicU8 = AtomicU8::new(0);

fn read() -> u32 {
    // SAFETY: a fixed, always-mapped RTC register (TRM RTC_CNTL_STORE0_REG); an aligned 32-bit volatile read.
    unsafe { STORE0.read_volatile() }
}

fn write(value: u32) {
    // SAFETY: as `read`; the register is plain storage, written only by this crate and the bootloader (never concurrently with the app).
    unsafe { STORE0.write_volatile(value) };
}

/// **Call this as the first statement after `esp_hal::init`** (a source check enforces it; `esp_hal::init` disables every watchdog, so nothing protects the image until
/// this runs). Keeps the count the bootloader handed over, writes [`ARMED`], and arms the RTC watchdog (reset the system, about [`WATCHDOG_MS`]). From here on the image
/// must call [`feed`] regularly, and only from a progress supervisor.
pub fn arm() {
    let handed = read();
    let count = decode(handed).map_or(0, |(_, c)| c);
    HANDED_COUNT.store(u32::from(count), Ordering::Relaxed);
    write(armed_word(handed));
    STATE.store(ARMED, Ordering::Relaxed);
    // The timeout through esp-hal (it converts with the calibrated slow clock and the eFuse multiplier); the CONFIGURATION through our own exact write. esp-hal's `enable()`
    // rewrites WDTCONFIG0 whole with stage 0 = 4 (reset the RTC domain too), so calling `set_stage_action(ResetCore)` before it, as the first two releases did, was undone by it:
    // `irqoff` kept ending in `SysRtcWdt` with the count wiped. Here WDTCONFIG0 is written last, once, with the value `rwdt::config0` (host-asserted).
    // SAFETY: `RTC_TIMER` is a zero-sized marker; `esp_hal::init` has finished with it and dropped its `Rtc`. Only `arm` creates this one.
    let mut rtc = Rtc::new(unsafe { RTC_TIMER::steal() });
    rtc.rwdt.set_timeout(RwdtStage::Stage0, Duration::from_millis(WATCHDOG_MS));
    write_config0(rwdt::config0(rwdt::Action::ResetDigital));
    critical_section::with(|cs| *RWDT.borrow_ref_mut(cs) = Some(rtc.rwdt));
}

fn reg(offset: usize) -> *mut u32 {
    (rwdt::RTC_CNTL_BASE + offset) as *mut u32
}

/// Write `WDTCONFIG0` behind the write-protect key.
fn write_config0(value: u32) {
    // SAFETY: fixed, always-mapped RTC_CNTL registers (TRM); the key unlocks the watchdog registers for these writes and 0 locks them again.
    unsafe {
        reg(rwdt::WDTWPROTECT).write_volatile(rwdt::WKEY);
        reg(rwdt::WDTCONFIG0).write_volatile(value);
        reg(rwdt::WDTWPROTECT).write_volatile(0);
    }
}

/// What the RTC watchdog actually has configured, read from `WDTCONFIG0..4`, for `boot-status`.
#[must_use]
pub fn rwdt_snapshot() -> rwdt::Snapshot {
    let mut config = [0u32; 5];
    for (i, c) in config.iter_mut().enumerate() {
        // SAFETY: as `write_config0`; plain reads.
        *c = unsafe { reg(rwdt::WDTCONFIG0 + 4 * i).read_volatile() };
    }
    rwdt::Snapshot { config }
}

/// Switch the RTC watchdog off before a deliberate entry into ROM download mode (`bootloader`): the ROM loader must not be reset by a watchdog armed for the app.
pub fn disarm() {
    critical_section::with(|cs| *RWDT.borrow_ref_mut(cs) = None);
    write_config0(0);
}

/// Feed the RTC watchdog. Only from the progress supervisor, and only when every heartbeat advanced.
pub fn feed() {
    critical_section::with(|cs| {
        if let Some(w) = RWDT.borrow_ref_mut(cs).as_mut() {
            w.feed();
        }
    });
}

/// The image proved itself (USB configured by the host and every heartbeat advancing for [`crate::HEALTHY_AFTER_MS`]): the bootloader stops counting.
pub fn mark_healthy() {
    write(word(HEALTHY, 0));
    STATE.store(HEALTHY, Ordering::Relaxed);
}

/// Before a self-test breaks the image: the bootloader must count the coming reset even if the image had become healthy ([`crate::demoted_word`]).
pub fn demote() {
    write(crate::demoted_word(HANDED_COUNT.load(Ordering::Relaxed) as u8));
    STATE.store(ARMED, Ordering::Relaxed);
}

/// A deliberate reset (`normal`, `reboot`): tell the bootloader this was not a failure, then reset. (`bootloader` needs no word: it sets the force-download flag.)
pub fn deliberate_reset() -> ! {
    write(word(HEALTHY, 0));
    esp_hal::system::software_reset()
}

/// For `boot-status`: the state now and the count handed at boot.
#[must_use]
pub fn report() -> Report {
    Report { state: state_name(STATE.load(Ordering::Relaxed)), count: HANDED_COUNT.load(Ordering::Relaxed) as u8 }
}

/// `selftest spin`: never returns, never yields (run it in a task of the thread executor).
pub fn spin() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// `selftest irqoff`: interrupts off, then spin. Nothing runs; only the hardware watchdog can end it.
pub fn irqoff() -> ! {
    critical_section::with(|_| {
        loop {
            core::hint::spin_loop();
        }
    })
}
