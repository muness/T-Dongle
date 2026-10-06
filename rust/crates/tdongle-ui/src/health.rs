//! Boot and crash tallies for the Health page ("Session boots / WDT / Panic"), and the recovery-mode policy that lights the ATTENTION LED.
//! Port of `main/health.{h,c}` (test: `tests/test_health.c`), `boot_policy.h` and the attention rule of `boot_health.c`.
//!
//! The tallies live in RTC memory (kept over a panic or watchdog reset, not over a power cycle). This is only a display: the crash-loop quarantine
//! is the recovery policy below.

/// Marks a valid RTC record.
pub const MAGIC: u32 = 0x4854_4c31;

/// Why the chip reset, as far as the tally cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetClass {
    /// Anything else (software reset, deep-sleep wake, ...).
    Other,
    /// Power on or brownout: a new session.
    Cold,
    /// Panic.
    Panic,
    /// Task or interrupt watchdog.
    Watchdog,
}

/// The RTC-resident record (`health_counters`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// [`MAGIC`] when valid.
    pub magic: u32,
    /// Boots this session.
    pub boots: u32,
    /// Watchdog resets this session.
    pub watchdogs: u32,
    /// Panics this session.
    pub panics: u32,
}

impl Counters {
    /// Count this boot. A cold start, or a record without the magic, starts the tally again.
    pub fn note_boot(&mut self, reset: ResetClass) {
        if reset == ResetClass::Cold || self.magic != MAGIC {
            *self = Counters { magic: MAGIC, boots: 0, watchdogs: 0, panics: 0 };
        }
        self.boots = self.boots.wrapping_add(1);
        match reset {
            ResetClass::Panic => self.panics = self.panics.wrapping_add(1),
            ResetClass::Watchdog => self.watchdogs = self.watchdogs.wrapping_add(1),
            _ => {}
        }
    }
}

/// `boot_should_recover`: a new binary gets one attempt; a failed attempt never auto-starts tailnets on the next boot.
pub fn should_recover(same_build: bool, unfinished: bool, crash: bool, latched: bool) -> bool {
    same_build && (unfinished || crash || latched)
}

/// Boot stages (persisted, append only).
pub mod stage {
    /// Number of stages including the unused 0.
    pub const COUNT: usize = 13;
    /// The display stage: its errors never count as "needs attention".
    pub const DISPLAY: usize = 11;
}

/// `gateway_boot_needs_attention`: recovery mode, or any boot stage (other than the display) that reported an error. This is the `recovery` field of
/// the LCD state that selects the RECOVERY screen and the ATTENTION LED.
pub fn needs_attention(recovery: bool, errors: &[i32; stage::COUNT]) -> bool {
    if recovery {
        return true;
    }
    errors.iter().enumerate().skip(1).any(|(i, &e)| i != stage::DISPLAY && e != 0)
}
