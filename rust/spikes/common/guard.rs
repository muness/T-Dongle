//! Boot guard glue for the no_std images (rules in `tdongle-boot-guard`): the RTC-memory record, the panic handler that fills it, the watchdogs and the
//! `boot-status` report. Included with `#[path = "../../common/guard.rs"] mod guard;`.
#![allow(dead_code)]

use core::fmt::Write;
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use esp_hal::time::Duration;
use tdongle_boot_guard::report::{BootStatus, write_boot_status};
use tdongle_boot_guard::{Boot, Record, Stage, WORDS};

/// The record's words. RTC fast memory keeps them over software and watchdog resets; a power-on boot zeroes them (which decodes as an empty record).
#[esp_hal::ram(unstable(rtc_fast, persistent))]
static mut RECORD: [u32; WORDS] = [0; WORDS];

fn load() -> Record {
    // SAFETY: `RECORD` is only touched from this module: from tasks on one core and from the panic handler (which never returns). A read racing a write can
    // only yield a torn record, which `Record::from_words` rejects or which is harmless; the type is valid for any bit pattern.
    let words = unsafe { addr_of_mut!(RECORD).read_volatile() };
    Record::from_words(&words)
}

fn store(rec: &Record) {
    // SAFETY: as in `load`.
    unsafe { addr_of_mut!(RECORD).write_volatile(rec.to_words()) };
}

/// Why the chip reset, from the ROM (`Debug` of the HAL's enum, or `unknown`).
pub fn reset_reason() -> heapless_str::Text {
    let mut t = heapless_str::Text::new();
    match esp_hal::system::reset_reason() {
        Some(r) => {
            let _ = write!(t, "{r:?}");
        }
        None => {
            let _ = t.write_str("unknown");
        }
    }
    t
}

/// What `begin` found and the boot's own state.
#[derive(Clone, Copy)]
pub struct State {
    /// The decision and what the previous boot left.
    pub boot: Boot,
    /// Reset reason of this boot.
    pub reset: heapless_str::Text,
}

/// First call of `main`: read the record, decide on safe mode, count this boot as unstable.
pub fn begin() -> State {
    let mut rec = load();
    let boot = rec.begin_boot();
    store(&rec);
    State { boot, reset: reset_reason() }
}

/// Record the step about to run.
pub fn stage(stage: Stage) {
    let mut rec = load();
    rec.note_stage(stage);
    store(&rec);
}

/// The step recorded last.
pub fn current_stage() -> Stage {
    load().stage().unwrap_or(Stage::Boot)
}

/// The boot stayed up long enough (call after `STABLE_AFTER_MS`).
pub fn mark_stable(safe_mode: bool) {
    let mut rec = load();
    rec.mark_stable(safe_mode);
    store(&rec);
}

/// Forget the failure history (console `normal`, and before a deliberate reset such as `bootloader`).
pub fn leave_safe_mode() {
    let mut rec = load();
    rec.leave_safe_mode();
    store(&rec);
}

/// The task watchdog (MWDT of TIMG1) and the RTC watchdog, both resetting the system; the heartbeat task feeds them. The timeouts are longer than any
/// single blocking step of the images (radio init, storage read) and far shorter than "the user must replug it".
pub struct Dogs {
    mwdt: esp_hal::timer::timg::Wdt<esp_hal::peripherals::TIMG1<'static>>,
    rwdt: esp_hal::rtc_cntl::Rwdt,
}

impl Dogs {
    /// Arm both watchdogs.
    pub fn arm(timg1: esp_hal::peripherals::TIMG1<'static>, rtc: esp_hal::peripherals::RTC_TIMER<'static>) -> Self {
        use esp_hal::rtc_cntl::{Rtc, RwdtStage, RwdtStageAction};
        use esp_hal::timer::timg::{MwdtStage, MwdtStageAction, TimerGroup};
        let mut mwdt = TimerGroup::new(timg1).wdt;
        mwdt.set_timeout(MwdtStage::Stage0, Duration::from_millis(10_000));
        mwdt.set_stage_action(MwdtStage::Stage0, MwdtStageAction::ResetSystem);
        mwdt.enable();
        let mut rwdt = Rtc::new(rtc).rwdt;
        rwdt.set_timeout(RwdtStage::Stage0, Duration::from_millis(20_000));
        rwdt.set_stage_action(RwdtStage::Stage0, RwdtStageAction::ResetSystem);
        rwdt.enable();
        Self { mwdt, rwdt }
    }

    /// Feed both. Called every 500 ms from a task on the same executor as everything else, so a blocked executor stops the feeding.
    pub fn feed(&mut self) {
        self.mwdt.feed();
        self.rwdt.feed();
    }
}

/// The `boot-status` line.
pub fn boot_status<W: Write>(w: &mut W, firmware: &str, elf: &[u8; 32], state: &State, up_ms: u64, free_heap: Option<u32>) {
    let prev_stage = state.boot.previous.stage.map_or("none", Stage::name);
    let _ = write_boot_status(
        w,
        &BootStatus {
            firmware,
            elf,
            reset_reason: state.reset.as_str(),
            stage: current_stage().name(),
            previous_stage: prev_stage,
            previous_panic: state.boot.previous.panic_text(),
            safe_mode: state.boot.safe_mode,
            unstable_boots: state.boot.previous.unstable_boots,
            uptime_ms: up_ms,
            free_heap,
        },
    );
}

/// Panic handler: keep the location and message in RTC memory, say so on the debug UART, reset. The next boot reports it in `boot-status` and counts toward
/// safe mode, so a panic at start-up cannot loop the device out of reach.
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let mut rec = load();
    match info.location() {
        Some(l) => rec.note_panic(format_args!("{}:{} {}", l.file(), l.line(), info.message())),
        None => rec.note_panic(format_args!("{}", info.message())),
    }
    store(&rec);
    esp_println::println!("PANIC: {}", info);
    esp_hal::system::software_reset()
}

/// A tiny fixed string that implements `Write` (no allocation: used before the heap is trusted).
pub mod heapless_str {
    /// 24 bytes of text, truncated.
    #[derive(Clone, Copy)]
    pub struct Text {
        buf: [u8; 24],
        len: usize,
    }

    impl Text {
        /// Empty.
        pub const fn new() -> Self {
            Self { buf: [0; 24], len: 0 }
        }
        /// The text.
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
        }
    }

    impl core::fmt::Write for Text {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
}
