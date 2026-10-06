//! Boot guard (rule 13 of ADR 0001): the record of the step that was running, the panic text and the failed-boot count, kept in RTC memory over
//! software and watchdog resets (`.rtc_noinit`, the IDF's `RTC_NOINIT_ATTR`), and what the next boot does with them. The decisions are
//! `tdongle-boot-guard` (pure, tested on the host); this file is the storage and the panic hook.

use std::sync::OnceLock;

use tdongle_boot_guard::{Boot, Record, Stage, WORDS};

/// The record's words. `.rtc_noinit` is not initialised by the start-up code: after a power-on it holds whatever the RAM powered up with, which
/// `Record::from_words` rejects (magic, length, UTF-8), and it survives every reset except loss of power.
#[unsafe(link_section = ".rtc_noinit")]
static mut RECORD: [u32; WORDS] = [0; WORDS];

fn load() -> Record {
    // SAFETY: `RECORD` is only read and written here, by tasks and by the panic hook (which does not return to the panicking code). A torn read yields a
    // record that `from_words` rejects or that is harmless; every bit pattern is a valid `[u32; N]`.
    let words = unsafe { core::ptr::addr_of_mut!(RECORD).read_volatile() };
    Record::from_words(&words)
}

fn store(record: &Record) {
    // SAFETY: as in `load`.
    unsafe { core::ptr::addr_of_mut!(RECORD).write_volatile(record.to_words()) };
}

/// What this boot knows about the last one.
#[derive(Clone, Copy, Debug)]
pub struct State {
    /// Safe mode or not, and what the previous boot left.
    pub boot: Boot,
}

static STATE: OnceLock<State> = OnceLock::new();

/// First thing in `main`: read the record, decide on safe mode, count this boot as unstable until it has stayed up, and route panics into the record.
pub fn begin() -> &'static State {
    let mut record = load();
    let boot = record.begin_boot();
    store(&record);
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let mut record = load();
        match info.location() {
            Some(l) => record.note_panic(format_args!("{}:{} {}", l.file(), l.line(), info.payload_as_str().unwrap_or("panic"))),
            None => record.note_panic(format_args!("{}", info.payload_as_str().unwrap_or("panic"))),
        }
        store(&record);
        previous_hook(info);
    }));
    STATE.get_or_init(|| State { boot })
}

/// The state of this boot (`begin` has run in `main`).
pub fn state() -> Option<&'static State> {
    STATE.get()
}

/// Safe mode: console only, no saved settings, no Wi-Fi.
pub fn safe_mode() -> bool {
    state().is_some_and(|s| s.boot.safe_mode)
}

/// Record the step about to run and feed the task watchdog.
pub fn stage(stage: Stage) {
    let mut record = load();
    record.note_stage(stage);
    store(&record);
    crate::sys::watchdog_feed();
}

/// The step recorded last.
pub fn current_stage() -> Stage {
    load().stage().unwrap_or(Stage::Boot)
}

/// The boot stayed up for `STABLE_AFTER_MS`.
pub fn mark_stable() {
    let mut record = load();
    record.mark_stable(safe_mode());
    store(&record);
}

/// Forget the failure history (console `normal`; before a deliberate reset such as `bootloader`).
pub fn leave_safe_mode() {
    let mut record = load();
    record.leave_safe_mode();
    store(&record);
}
