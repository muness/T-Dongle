//! The setup access point as a boot mode: port of `main/setup_boot.{h,c}` (test: `tests/test_setup_boot.c`).
//!
//! Setup is entered by RESTARTING the dongle (button menu, serial `setup`, the first boot with no saved network), never by starting an access point in a
//! running dongle. The request survives the restart in three RTC words (not cleared by a software reset, indeterminate after a power cycle: hence the magic).

use core::fmt::Write;

/// RTC magic.
pub const BOOT_MAGIC: u32 = 0x5444_4d31;
/// Length of a setup session.
pub const SESSION_MS: u32 = 600_000;
/// If the access point is still not up this long after the boot began, give up.
pub const AP_GRACE_MS: u32 = 30_000;
/// Saved-network slots.
pub const SLOTS: u32 = 8;

/// What the previous run asks of the next boot (`setup_request`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupRequest {
    /// No request.
    None = 0,
    /// Enter setup.
    Enter = 1,
    /// Leave setup for normal mode.
    Leave = 2,
}

/// The boot decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootDecision {
    /// Run this boot as the setup access point.
    pub setup: bool,
    /// Saved network (1 to 8) to preselect on the page, 0 for "add a new one".
    pub preselect: u32,
}

/// Decide this boot. A request counts only after a software reset with the magic intact. Without a request, setup starts only when no network is saved and
/// the store is readable (the first plug-in), and never after a LEAVE request.
pub fn decide(software_reset: bool, magic: u32, next: u32, slot: u32, networks_saved: bool, store_ok: bool) -> BootDecision {
    let request = if software_reset && magic == BOOT_MAGIC { next } else { SetupRequest::None as u32 };
    let mut d = BootDecision::default();
    if request == SetupRequest::Enter as u32 {
        d.setup = true;
        d.preselect = if (1..=SLOTS).contains(&slot) { slot } else { 0 };
    } else if request != SetupRequest::Leave as u32 {
        d.setup = !networks_saved && store_ok;
    }
    d
}

/// The RTC words `(magic, next, slot)` for the next boot.
pub fn request_words(request: SetupRequest, preselect: u32) -> (u32, u32, u32) {
    let slot = if request == SetupRequest::Enter && (1..=SLOTS).contains(&preselect) { preselect } else { 0 };
    (BOOT_MAGIC, request as u32, slot)
}

/// The 10 minute session. Times are 32 bit millisecond counts; comparisons are wrap safe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Session {
    started_ms: u32,
    active: bool,
}

impl Session {
    /// Not a setup boot.
    pub const fn inactive() -> Self {
        Session { started_ms: 0, active: false }
    }
    /// Start (when the boot decides to run setup, not when the access point comes up).
    pub fn start(now_ms: u32) -> Self {
        Session { started_ms: now_ms, active: true }
    }
    fn elapsed(&self, now_ms: u32) -> u32 {
        now_ms.wrapping_sub(self.started_ms)
    }
    /// The session is over.
    pub fn expired(&self, now_ms: u32) -> bool {
        self.active && self.elapsed(now_ms) >= SESSION_MS
    }
    /// Whole seconds left (rounded up), 0 when inactive or over.
    pub fn seconds_left(&self, now_ms: u32) -> u32 {
        if !self.active {
            return 0;
        }
        let e = self.elapsed(now_ms);
        if e >= SESSION_MS { 0 } else { (SESSION_MS - e).div_ceil(1000) }
    }
    /// Time to restart into normal mode? The session is over, or the access point is still not up [`AP_GRACE_MS`] after the boot began.
    pub fn should_end(&self, now_ms: u32, access_point_up: bool) -> bool {
        if !self.active {
            return false;
        }
        self.expired(now_ms) || (!access_point_up && self.elapsed(now_ms) >= AP_GRACE_MS)
    }
    /// The independent failsafe timer: milliseconds until the next moment setup could have to end, or 0 when it must end now.
    pub fn failsafe_delay_ms(&self, now_ms: u32, access_point_up: bool) -> u32 {
        if !self.active || self.should_end(now_ms, access_point_up) {
            return 0;
        }
        let e = self.elapsed(now_ms);
        let mut next = SESSION_MS - e;
        if !access_point_up && AP_GRACE_MS - e < next {
            next = AP_GRACE_MS - e;
        }
        if next == 0 { 1 } else { next }
    }
}

/// Access point name `TDongle-XXXXXX` (last three bytes of the station MAC, upper case hex): 14 characters.
pub fn ap_ssid(mac: [u8; 6]) -> crate::text::Text<14> {
    let mut t = crate::text::Text::new();
    let _ = write!(t, "TDongle-{:02X}{:02X}{:02X}", mac[3], mac[4], mac[5]);
    t
}
