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

/// Record the risky operation about to run (a driver call that can block); call `op("")` after it. A reset in between is reported as `previous_op` by the next boot.
pub fn op(tag: &str) {
    let mut rec = load();
    rec.note_op(tag);
    store(&rec);
}

/// A supervisor found `task` stalled: record it (the caller resets the chip right after).
pub fn hang(task: &str) {
    let mut rec = load();
    rec.note_hang(task);
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

/// The second hardware watchdog (MWDT of TIMG1, 10 s, reset the system) next to the RTC watchdog that `tdongle_rescue::arm` owns. Both are fed by the progress supervisor, and only
/// by it: `feed` is called once per check in which every heartbeat advanced.
pub struct Dogs {
    mwdt: esp_hal::timer::timg::Wdt<esp_hal::peripherals::TIMG1<'static>>,
}

impl Dogs {
    /// Arm the TIMG1 watchdog.
    pub fn arm(timg1: esp_hal::peripherals::TIMG1<'static>) -> Self {
        use esp_hal::timer::timg::{MwdtStage, MwdtStageAction, TimerGroup};
        let mut mwdt = TimerGroup::new(timg1).wdt;
        mwdt.set_timeout(MwdtStage::Stage0, Duration::from_millis(10_000));
        mwdt.set_stage_action(MwdtStage::Stage0, MwdtStageAction::ResetSystem);
        mwdt.enable();
        Self { mwdt }
    }

    /// Feed both watchdogs.
    pub fn feed(&mut self) {
        self.mwdt.feed();
        tdongle_rescue::feed();
    }
}

/// The `boot-status` line.
pub fn boot_status<W: Write>(w: &mut W, firmware: &str, elf: &[u8; 32], state: &State, up_ms: u64, free_heap: Option<u32>) {
    let prev_stage = state.boot.previous.stage.map_or("none", Stage::name);
    let rescue = tdongle_rescue::report();
    let _ = write_boot_status(
        w,
        &BootStatus {
            firmware,
            elf,
            reset_reason: state.reset.as_str(),
            stage: current_stage().name(),
            previous_stage: prev_stage,
            previous_panic: state.boot.previous.panic_text(),
            previous_hang: state.boot.previous.hang.as_str(),
            previous_op: state.boot.previous.op.as_str(),
            rescue_state: rescue.state,
            rescue_count: rescue.count,
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
    // No I/O here: a print that blocks (a full UART FIFO) would leave the reset to the watchdog. Record, then reset the digital core at once (the RTC domain survives).
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
