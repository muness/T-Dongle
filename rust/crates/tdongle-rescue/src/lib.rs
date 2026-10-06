//! The lockout rescue, app side. The T-Dongle's only console is the app's own USB, so an app that hangs or reset-loops leaves no software way back into ROM download
//! mode. The second-stage bootloader (`bootloader_components/tdongle_rescue` in the release tree) breaks that, and this crate is the app's half of the protocol:
//!
//! * `RTC_CNTL_STORE0` holds `0xD0E5 << 16 | state << 8 | count`. After a reset that keeps the RTC domain, the bootloader counts one more boot that never became healthy
//!   (`state != HEALTHY`) and, when the count reaches [`LIMIT`], boots ROM download mode instead of the app. Power-on clears the word. It hands the count to the app as state 0.
//! * The app calls [`arm`] as the first thing after `esp_hal::init` (which disables every watchdog): it keeps the handed count, writes [`ARMED`] and arms the RTC
//!   watchdog (about 10 s, reset the system). The watchdog is fed only by the progress supervisor ([`feed`]), which needs heartbeats from both executors.
//! * The app calls [`mark_healthy`] only after USB is configured by the host **and** every heartbeat has advanced continuously for [`HEALTHY_AFTER_MS`] ([`HealthyTimer`]).
//!
//! The pure half (words, the health timer, the self-test commands and a model of the bootloader's decision) is host-tested; the `hal` feature adds the hardware half.

#![no_std]
#![cfg_attr(not(feature = "hal"), forbid(unsafe_code))]
#![deny(missing_docs)]

pub mod rwdt;

/// The marker in the top half of the word.
pub const MAGIC: u32 = 0xD0E5;
/// The app has started and has not yet proven itself.
pub const ARMED: u8 = 0xA5;
/// The app proved itself: USB configured and every heartbeat advancing for [`HEALTHY_AFTER_MS`].
pub const HEALTHY: u8 = 0x0C;
/// State the bootloader hands to the app.
pub const HANDED: u8 = 0;
/// Consecutive unhealthy boots after which the bootloader enters ROM download mode.
pub const LIMIT: u8 = 2;
/// How long every heartbeat must advance, with USB configured, before the app calls itself healthy.
pub const HEALTHY_AFTER_MS: u64 = 30_000;
/// The RTC watchdog timeout, approximately (the slow RTC clock is not calibrated to better than a few percent).
pub const WATCHDOG_MS: u64 = 10_000;

/// `MAGIC << 16 | state << 8 | count`.
#[must_use]
pub const fn word(state: u8, count: u8) -> u32 {
    (MAGIC << 16) | ((state as u32) << 8) | count as u32
}

/// `(state, count)` of a word that carries the magic.
#[must_use]
pub const fn decode(word: u32) -> Option<(u8, u8)> {
    if word >> 16 == MAGIC { Some(((word >> 8) as u8, word as u8)) } else { None }
}

/// What [`arm`] writes: the handed count (0 if the word is not ours) with state [`ARMED`].
#[must_use]
pub const fn armed_word(handed: u32) -> u32 {
    match decode(handed) {
        Some((_, count)) => word(ARMED, count),
        None => word(ARMED, 0),
    }
}

/// What the rescue reports in `boot-status`: the state names and the count handed at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// `"armed"` until [`mark_healthy`], then `"healthy"`; `"none"` if the image never armed.
    pub state: &'static str,
    /// Consecutive unhealthy boots before this one, as the bootloader counted them.
    pub count: u8,
}

/// The state name of a stored state byte.
#[must_use]
pub const fn state_name(state: u8) -> &'static str {
    match state {
        ARMED => "armed",
        HEALTHY => "healthy",
        HANDED => "handed",
        _ => "unknown",
    }
}

/// "Healthy" is a property of a stretch of time, not of a moment: [`observe`](Self::observe) is called at every supervisor check with whether everything is fine (USB
/// configured and every heartbeat advanced), and returns true once it has been fine continuously for [`HEALTHY_AFTER_MS`]. One bad check restarts the clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthyTimer {
    since: Option<u64>,
    done: bool,
}

impl HealthyTimer {
    /// A timer that has seen nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { since: None, done: false }
    }

    /// One supervisor check at `now_ms`. Stays true once reached.
    pub fn observe(&mut self, now_ms: u64, ok: bool) -> bool {
        if self.done {
            return true;
        }
        if !ok {
            self.since = None;
            return false;
        }
        let since = *self.since.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= HEALTHY_AFTER_MS {
            self.done = true;
        }
        self.done
    }
}

impl Default for HealthyTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// How far a reset reaches. The rescue count lives in `RTC_CNTL_STORE0`, which only survives a reset that leaves the RTC domain alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetScope {
    /// The digital core and its peripherals; the RTC domain, and so `STORE0`, survive.
    DigitalOnly,
    /// The RTC domain too: `STORE0` is wiped and the bootloader sees a fresh power-on.
    IncludingRtc,
}

/// Every way an image can end up reset, with the scope the hardware gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetPath {
    /// A software reset (`software_reset`, `esp_restart`): the panic handler, the supervisor's stall reset, a deliberate reset, the self-tests that panic.
    Software,
    /// The TIMG1 watchdog, stage action "reset system" (digital core only).
    TimerGroupWatchdog,
    /// The RTC watchdog with the action this crate configures ([`RWDT_RESET`]).
    RtcWatchdog,
    /// The RTC watchdog with the action esp-hal calls `ResetSystem`, which is the one that resets the RTC domain as well (the first release of the rescue used it).
    RtcWatchdogResetsRtc,
    /// Loss of power.
    PowerOn,
}

impl ResetPath {
    /// The scope of the reset (ESP32-S3 TRM, RTC_CNTL_WDTCONFIG0 stage actions: 2 reset CPU, 3 reset the main system without the RTC, 4 reset the main system and the RTC).
    #[must_use]
    pub const fn scope(self) -> ResetScope {
        match self {
            Self::Software | Self::TimerGroupWatchdog => ResetScope::DigitalOnly,
            Self::RtcWatchdog => match RWDT_RESET {
                ResetScope::DigitalOnly => ResetScope::DigitalOnly,
                ResetScope::IncludingRtc => ResetScope::IncludingRtc,
            },
            Self::RtcWatchdogResetsRtc | Self::PowerOn => ResetScope::IncludingRtc,
        }
    }
}

/// The paths an image takes on purpose or by its own watchdogs; every one must keep the RTC domain, or the bootloader cannot count the failed boot.
pub const IMAGE_RESET_PATHS: [ResetPath; 3] = [ResetPath::Software, ResetPath::TimerGroupWatchdog, ResetPath::RtcWatchdog];

/// The scope the RTC watchdog is configured with: digital core only. (esp-hal: `RwdtStageAction::ResetCore`, the value 3; IDF: `WDT_STAGE_ACTION_RESET_SYSTEM`. esp-hal's
/// `ResetSystem` is the value 4, RTC included, and wiped `STORE0` on the board: `irqoff` ended with count 0 and no ROM mode.)
pub const RWDT_RESET: ResetScope = ResetScope::DigitalOnly;

/// The console's deliberate-breakage commands (`selftest NAME`): each must end in a reset, and [`LIMIT`] of them in a row must end in ROM download mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selftest {
    /// The thread executor busy-loops forever (the supervisor sees its heartbeat stop).
    Spin,
    /// Interrupts are disabled and the core spins (nothing runs; only the hardware watchdog is left).
    IrqOff,
    /// A panic.
    Panic,
    /// The console executor stops polling the console (the supervisor sees its heartbeat stop).
    Console,
}

impl Selftest {
    /// The names `help` lists.
    pub const NAMES: &'static str = "selftest spin|irqoff|panic|console";

    /// Parse the part after `selftest `.
    #[must_use]
    pub fn parse(arg: &str) -> Option<Self> {
        match arg.trim() {
            "spin" => Some(Self::Spin),
            "irqoff" => Some(Self::IrqOff),
            "panic" => Some(Self::Panic),
            "console" => Some(Self::Console),
            _ => None,
        }
    }
}

/// What a self-test writes before it breaks the image: [`ARMED`] with the count the bootloader handed over. The bootloader then counts the reset against the image even if
/// the image had already proven itself ([`HEALTHY`]), so two self-tests in a row end in ROM download mode whenever they are issued.
#[must_use]
pub const fn demoted_word(handed_count: u8) -> u32 {
    word(ARMED, handed_count)
}

/// A model of `bootloader_after_init` of the release tree's `rescue.c`, for the host tests of the whole protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootDecision {
    /// Boot the app, with this word left in `STORE0`.
    App(u32),
    /// Enter ROM download mode (and the word is cleared).
    DownloadMode,
}

/// `power_on`: the reset reason is a power-on reset.
#[must_use]
pub fn bootloader_decision(store0: u32, power_on: bool) -> BootDecision {
    let Some((state, count)) = decode(store0) else { return BootDecision::App(store0) };
    if power_on {
        return BootDecision::App(0);
    }
    let count = if state == HEALTHY { 0 } else { count.saturating_add(1) };
    if count >= LIMIT {
        return BootDecision::DownloadMode;
    }
    BootDecision::App(word(HANDED, count))
}

#[cfg(feature = "hal")]
mod hw;
#[cfg(feature = "hal")]
pub use hw::{arm, deliberate_reset, demote, disarm, feed, irqoff, mark_healthy, report, rwdt_snapshot, spin};
