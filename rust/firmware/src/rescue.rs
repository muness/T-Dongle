//! The lockout rescue, app side, for the std image (`tdongle-rescue` is the protocol; ADR 0001 rule 13). The bootloader (`bootloader_components/tdongle_rescue`) counts boots
//! that never became healthy and enters ROM download mode at two. `arm` runs first in `main`, writes ARMED and arms the RTC watchdog (10 s, reset the system) through
//! the IDF's `rtc_wdt_*`; the **supervisor thread** feeds it only while the manager loop and the console task both make progress, and calls the image healthy only after
//! the host has configured USB and everything advanced for 30 s.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use esp_idf_svc::sys;
use tdongle_boot_guard::watch::{Verdict, Watch};
use tdongle_rescue::{ARMED, HEALTHY, HealthyTimer, Report, Selftest, WATCHDOG_MS, armed_word, decode, state_name, word};

/// `RTC_CNTL_STORE0_REG` (`DR_REG_RTCCNTL_BASE + 0x50`).
const STORE0: *mut u32 = 0x6000_8050 as *mut u32;

static HANDED_COUNT: AtomicU32 = AtomicU32::new(0);
static STATE: AtomicU32 = AtomicU32::new(0);
static PULSE_MAIN: AtomicU32 = AtomicU32::new(0);
static PULSE_CONSOLE: AtomicU32 = AtomicU32::new(0);
static SUP_TICKS: AtomicU32 = AtomicU32::new(0);
static SUP_FEEDS: AtomicU32 = AtomicU32::new(0);
static CONSOLE_FROZEN: AtomicBool = AtomicBool::new(false);

fn read() -> u32 {
    // SAFETY: a fixed, always-mapped RTC register; aligned 32-bit volatile read.
    unsafe { STORE0.read_volatile() }
}

fn write(value: u32) {
    // SAFETY: as `read`; plain storage shared only with the bootloader, which never runs concurrently with the app.
    unsafe { STORE0.write_volatile(value) };
}

/// **The first statement of `main`** (a source check enforces it). Keeps the handed count, writes ARMED, arms the RTC watchdog.
pub fn arm() {
    let handed = read();
    HANDED_COUNT.store(u32::from(decode(handed).map_or(0, |(_, c)| c)), Ordering::Relaxed);
    write(armed_word(handed));
    STATE.store(u32::from(ARMED), Ordering::Relaxed);
    with_rwdt(|ctx| {
        // SAFETY: the IDF HAL on the always-present RTC_CNTL block (as `esp_panic_handler_enable_rtc_wdt` does); write protection is lifted around the configuration.
        unsafe {
            sys::wdt_hal_init(ctx, sys::wdt_inst_t_WDT_RWDT, 0, false);
            let ticks = (WATCHDOG_MS * u64::from(sys::rtc_clk_slow_freq_get_hz()) / 1000) as u32;
            sys::wdt_hal_write_protect_disable(ctx);
            sys::wdt_hal_config_stage(
                ctx,
                sys::wdt_stage_t_WDT_STAGE0,
                ticks,
                sys::wdt_stage_action_t_WDT_STAGE_ACTION_RESET_SYSTEM, /* value 3: the digital system, not the RTC (RESET_RTC is 4); see tdongle_rescue::RWDT_RESET */
            );
            sys::wdt_hal_enable(ctx);
            sys::wdt_hal_write_protect_enable(ctx);
        }
    });
}

/// Switch the RTC watchdog off before a deliberate entry into ROM download mode: the loader must not be reset by a watchdog armed for the app.
pub fn disarm() {
    with_rwdt(|ctx| {
        // SAFETY: as in `arm`.
        unsafe {
            sys::wdt_hal_write_protect_disable(ctx);
            sys::wdt_hal_disable(ctx);
            sys::wdt_hal_write_protect_enable(ctx);
        }
    });
}

/// `RWDT_HAL_CONTEXT_DEFAULT()`: the RTC watchdog context.
fn with_rwdt(f: impl FnOnce(*mut sys::wdt_hal_context_t)) {
    // SAFETY: a zeroed context is initialised below to the RTC watchdog instance and the RTC_CNTL register block, exactly as the macro does.
    let mut ctx: sys::wdt_hal_context_t = unsafe { core::mem::zeroed() };
    ctx.inst = sys::wdt_inst_t_WDT_RWDT;
    // SAFETY: `RTCCNTL` is the IDF's always-mapped register block of the RTC controller.
    ctx.__bindgen_anon_1.rwdt_dev = core::ptr::addr_of_mut!(sys::RTCCNTL);
    f(&mut ctx);
}

fn feed() {
    with_rwdt(|ctx| {
        // SAFETY: as in `arm`.
        unsafe {
            sys::wdt_hal_write_protect_disable(ctx);
            sys::wdt_hal_feed(ctx);
            sys::wdt_hal_write_protect_enable(ctx);
        }
    });
}

/// What the RTC watchdog really has configured (`WDTCONFIG0..4`), for `boot-status`.
pub fn rwdt_snapshot() -> [u32; 5] {
    let mut config = [0u32; 5];
    for (i, c) in config.iter_mut().enumerate() {
        // SAFETY: fixed, always-mapped RTC_CNTL registers; plain volatile reads.
        *c = unsafe { ((tdongle_rescue::rwdt::RTC_CNTL_BASE + tdongle_rescue::rwdt::WDTCONFIG0 + 4 * i) as *const u32).read_volatile() };
    }
    config
}

/// `[ticks, feeds, main pulse, console pulse]` for `boot-status`.
pub fn supervisor_stats() -> [u32; 4] {
    [SUP_TICKS.load(Ordering::Relaxed), SUP_FEEDS.load(Ordering::Relaxed), PULSE_MAIN.load(Ordering::Relaxed), PULSE_CONSOLE.load(Ordering::Relaxed)]
}

/// The manager (main task) made progress.
pub fn pulse_main() {
    PULSE_MAIN.fetch_add(1, Ordering::Relaxed);
}

/// The console task made progress; `selftest console` parks it here for good.
pub fn console_alive() {
    PULSE_CONSOLE.fetch_add(1, Ordering::Relaxed);
    while CONSOLE_FROZEN.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Before a self-test breaks the image: the coming reset must count even if the image had become healthy.
fn demote() {
    write(tdongle_rescue::demoted_word(HANDED_COUNT.load(Ordering::Relaxed) as u8));
    STATE.store(u32::from(ARMED), Ordering::Relaxed);
}

/// A deliberate reset (`reboot`): not a failure.
pub fn deliberate_reset() -> ! {
    write(word(HEALTHY, 0));
    crate::sys::restart()
}

/// For `boot-status`.
pub fn report() -> Report {
    Report { state: state_name(STATE.load(Ordering::Relaxed) as u8), count: HANDED_COUNT.load(Ordering::Relaxed) as u8 }
}

/// Start the supervisor thread (above every working task, below the IDF system tasks).
///
/// # Errors
/// The thread could not be spawned.
pub fn start_supervisor() -> Result<(), &'static str> {
    ThreadSpawnConfiguration { name: Some(c"supervisor"), stack_size: 3072, priority: 20, ..Default::default() }
        .set()
        .map_err(|_| "supervisor configuration")?;
    let spawned = std::thread::Builder::new().name("supervisor".into()).stack_size(3072).spawn(supervise);
    crate::sys::reset_thread_spawn_defaults();
    spawned.map(|_| ()).map_err(|_| "supervisor spawn")
}

fn supervise() {
    // deadlines: the manager sleeps 10 s between turns and the startup stages can take seconds; the console task polls every few hundred milliseconds
    let mut watch = Watch::new(["main", "console"], [40_000, 5_000], u64::from(crate::sys::now_ms()));
    let mut healthy = HealthyTimer::new();
    let mut marked = false;
    loop {
        let now = u64::from(crate::sys::now_ms());
        SUP_TICKS.fetch_add(1, Ordering::Relaxed);
        match watch.check(now, [PULSE_MAIN.load(Ordering::Relaxed), PULSE_CONSOLE.load(Ordering::Relaxed)]) {
            Verdict::Healthy => {
                feed();
                SUP_FEEDS.fetch_add(1, Ordering::Relaxed);
                if healthy.observe(now, crate::usb::task::mounted()) && !marked {
                    write(word(HEALTHY, 0));
                    STATE.store(u32::from(HEALTHY), Ordering::Relaxed);
                    crate::guard::mark_stable();
                    marked = true;
                }
            }
            Verdict::Stalled(task) => {
                let _ = healthy.observe(now, false);
                crate::guard::hang(task);
                log::error!("{task} made no progress: resetting");
                crate::sys::restart();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// `selftest NAME`: break this image on purpose so the rescue is proven on the board.
pub fn selftest(kind: Selftest) {
    demote();
    match kind {
        Selftest::Spin => {
            // the scheduler stops: no task runs, the supervisor included; only the RTC watchdog is left
            let _ = std::thread::Builder::new().name("selftest".into()).stack_size(2048).spawn(|| {
                // SAFETY: deliberate: suspend the scheduler for ever.
                unsafe { sys::vTaskSuspendAll() };
                loop {
                    core::hint::spin_loop();
                }
            });
        }
        Selftest::IrqOff => {
            let _ = std::thread::Builder::new().name("selftest".into()).stack_size(2048).spawn(|| {
                let lock = crate::sys::critical::Mux::new();
                lock.lock(); // masks interrupts on this core, for ever
                loop {
                    core::hint::spin_loop();
                }
            });
        }
        Selftest::Panic => panic!("selftest panic"),
        Selftest::Console => CONSOLE_FROZEN.store(true, Ordering::Relaxed),
    }
}
