//! The factory-reset flow, command layer (`gateway_serial_command`, `reset` and `confirm-reset`): step one arms a 10 s window, step two inside it erases the
//! saved networks and display settings and restarts into setup. The button menu runs the same two commands through [`crate::ui::Command`] (so a button
//! and a terminal cannot disagree); its own on-screen confirmation window ([`crate::menu::CONFIRM_MS`]) is the same 10 s and is independent of this one.

/// How long `reset` stays armed.
pub const ARM_MS: u32 = 10_000;

/// What the firmware must do for a `confirm-reset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Not armed, or expired: reply `ERR reset confirmation expired`.
    Expired,
    /// Erase (`wifi_factory_reset`) under the settings lock; on success reply `OK factory reset; restarting into setup`, wait 300 ms, restart with
    /// `SETUP_REQUEST_ENTER`; on failure reply `ERR Factory reset failed; storage could not be erased` and stay (disarmed).
    Erase,
}

/// The armed flag and its deadline (`factory_reset_armed`, `factory_reset_until_ms`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResetArm {
    armed: bool,
    until_ms: u32,
}

impl ResetArm {
    /// Disarmed.
    pub const fn new() -> Self {
        ResetArm { armed: false, until_ms: 0 }
    }
    /// `reset`: arm for [`ARM_MS`]; reply `Confirm within 10 seconds: confirm-reset`.
    pub fn reset(&mut self, now_ms: u32) {
        self.until_ms = now_ms.wrapping_add(ARM_MS);
        self.armed = true;
    }
    /// `confirm-reset`: always disarms.
    pub fn confirm(&mut self, now_ms: u32) -> Confirm {
        let ok = self.armed && (now_ms.wrapping_sub(self.until_ms) as i32) < 0;
        self.armed = false;
        if ok { Confirm::Erase } else { Confirm::Expired }
    }
    /// Armed and not yet expired.
    pub fn is_armed(&self, now_ms: u32) -> bool {
        self.armed && (now_ms.wrapping_sub(self.until_ms) as i32) < 0
    }
}
