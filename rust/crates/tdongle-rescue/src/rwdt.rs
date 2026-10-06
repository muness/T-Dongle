//! The exact RTC watchdog register values (ESP32-S3 TRM, RTC_CNTL: `WDTCONFIG0..4`, `WDTFEED`, `WDTWPROTECT`), so the host can assert what the hardware half writes and what
//! `boot-status` reads back.
//!
//! `WDTCONFIG0` (offset 0x98): bit 31 `WDT_EN`; 30:28 `STG0`, 27:25 `STG1`, 24:22 `STG2`, 21:19 `STG3` (stage actions: 0 off, 1 interrupt, 2 reset CPU, 3 reset the main system
//! **keeping the RTC domain**, 4 reset the main system **and the RTC domain**); 18:16 `CPU_RESET_LENGTH`; 15:13 `SYS_RESET_LENGTH`; 12 `FLASHBOOT_MOD_EN`; 11 `PROCPU_RESET_EN`;
//! 10 `APPCPU_RESET_EN`; 9 `PAUSE_IN_SLP`; 8 `CHIP_RESET_EN`; 7:0 `CHIP_RESET_WIDTH`. `WDTCONFIG1..4` (0x9C..0xA8) are the hold times of stages 0 to 3, in slow-clock
//! ticks (halved by 2^(1 + the eFuse multiplier)). The registers are write-protected: write `0x50D8_3AA1` to `WDTWPROTECT` (0xB0) first and 0 after.

/// Base of `RTC_CNTL`.
pub const RTC_CNTL_BASE: usize = 0x6000_8000;
/// `RTC_CNTL_WDTCONFIG0_REG` offset.
pub const WDTCONFIG0: usize = 0x98;
/// `RTC_CNTL_WDTCONFIG1_REG` (stage 0 hold) offset.
pub const WDTCONFIG1: usize = 0x9C;
/// `RTC_CNTL_WDTFEED_REG` offset (write bit 31).
pub const WDTFEED: usize = 0xAC;
/// `RTC_CNTL_WDTWPROTECT_REG` offset.
pub const WDTWPROTECT: usize = 0xB0;
/// The unlock key.
pub const WKEY: u32 = 0x50D8_3AA1;
/// `RTC_CNTL_STORE0_REG` offset.
pub const STORE0: usize = 0x50;

/// A stage action as the hardware encodes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    /// 0.
    Off = 0,
    /// 1.
    Interrupt = 1,
    /// 2: reset the CPU core.
    ResetCpu = 2,
    /// 3: reset the main system; the RTC domain (and `STORE0`) survive. Reset reason `RTCWDT_SYS_RESET` (9). esp-hal calls this `ResetCore`, the IDF `WDT_STAGE_ACTION_RESET_SYSTEM`.
    ResetDigital = 3,
    /// 4: reset the main system **and the RTC domain**. Reset reason `RTCWDT_RTC_RESET` (16). esp-hal calls this `ResetSystem`, the IDF `WDT_STAGE_ACTION_RESET_RTC`.
    ResetIncludingRtc = 4,
}

impl Action {
    /// The ROM reset reason (`soc_reset_reason_t`) a stage-0 expiry with this action produces, if it resets.
    #[must_use]
    pub const fn reset_reason(self) -> Option<u8> {
        match self {
            Self::ResetCpu => Some(13),
            Self::ResetDigital => Some(9),
            Self::ResetIncludingRtc => Some(16),
            Self::Off | Self::Interrupt => None,
        }
    }

    /// Whether the reset leaves `STORE0` alone.
    #[must_use]
    pub const fn keeps_rtc(self) -> bool {
        !matches!(self, Self::ResetIncludingRtc)
    }

    /// The action in a `WDTCONFIG0` value, stage 0.
    #[must_use]
    pub const fn from_config0(cfg0: u32) -> Option<Self> {
        match (cfg0 >> 28) & 7 {
            0 => Some(Self::Off),
            1 => Some(Self::Interrupt),
            2 => Some(Self::ResetCpu),
            3 => Some(Self::ResetDigital),
            4 => Some(Self::ResetIncludingRtc),
            _ => None,
        }
    }
}

/// The reset signal length the IDF's `wdt_hal_init` uses (`WDT_RESET_SIG_LENGTH_3_2us`).
pub const RESET_LENGTH: u32 = 7;

/// The `WDTCONFIG0` value this crate writes: enabled, stage 0 = `action`, the other stages off, both reset lengths 7, flash-boot protection off, PRO and APP CPU reset enables on
/// and pause-in-sleep on (exactly what `wdt_hal_init` + `wdt_hal_config_stage` + `wdt_hal_enable` produce for the RWDT), `CHIP_RESET_EN` off.
#[must_use]
pub const fn config0(action: Action) -> u32 {
    (1 << 31) | ((action as u32) << 28) | (RESET_LENGTH << 16) | (RESET_LENGTH << 13) | (1 << 11) | (1 << 10) | (1 << 9)
}

/// What is armed, as read back from the registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// `WDTCONFIG0..4`.
    pub config: [u32; 5],
}

impl Snapshot {
    /// The watchdog is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.config[0] >> 31 != 0
    }

    /// The stage-0 action.
    #[must_use]
    pub const fn action(&self) -> Option<Action> {
        Action::from_config0(self.config[0])
    }

    /// The flash-boot protection bit (it must be off once the bootloader has run).
    #[must_use]
    pub const fn flashboot(&self) -> bool {
        (self.config[0] >> 12) & 1 != 0
    }

    /// What the watchdog will do at the end of stage 0 is a reset that keeps the RTC domain.
    #[must_use]
    pub const fn safe_for_rescue(&self) -> bool {
        match self.action() {
            Some(a) => self.enabled() && a.keeps_rtc() && a.reset_reason().is_some(),
            None => false,
        }
    }
}
