//! Run-time tuning (the diagnostics build's `bridgetune`; not persisted). The compile-time constants are the defaults. Bounds are checked
//! as a whole: a rejected set changes nothing.

use crate::{
    CODEL_DEFAULT, CODEL_INTERVAL_MS_MAX, CODEL_INTERVAL_MS_MIN, CODEL_TARGET_US_MAX, CODEL_TARGET_US_MIN, HOST_QUEUE_LIMIT, HOST_RESUME_DEPTH, HOST_SLOTS,
    SOJOURN_MS, SOJOURN_MS_MAX, SOJOURN_MS_MIN,
};
use tdongle_aqm::{INTERVAL_MS_DEFAULT, TARGET_US_DEFAULT};

/// `tdongle_l2_tuning_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// `1..=HOST_SLOTS`: frames that may stand in the host queue before the host is held.
    pub queue_limit: u32,
    /// `0..queue_limit`: drain to this depth before the held datagram is offered again.
    pub resume_depth: u32,
    /// `SOJOURN_MS_MIN..=SOJOURN_MS_MAX`: age at which a frame is dropped.
    pub sojourn_ms: u32,
    /// CoDel/ECN on the ingress (ADR 0023 amendments 4 to 6): on by default at RFC 8289's 5 ms target and 100 ms interval.
    pub codel: bool,
    /// `CODEL_TARGET_US_MIN..=CODEL_TARGET_US_MAX`.
    pub codel_target_us: u32,
    /// `CODEL_INTERVAL_MS_MIN..=CODEL_INTERVAL_MS_MAX`.
    pub codel_interval_ms: u32,
}

impl Tuning {
    /// The defaults the release and diagnostics images both run.
    pub const DEFAULT: Self = Self {
        queue_limit: HOST_QUEUE_LIMIT,
        resume_depth: HOST_RESUME_DEPTH,
        sojourn_ms: SOJOURN_MS,
        codel: CODEL_DEFAULT,
        codel_target_us: TARGET_US_DEFAULT,
        codel_interval_ms: INTERVAL_MS_DEFAULT,
    };

    /// Whether every field is inside its bounds (`ESP_ERR_INVALID_ARG` otherwise in C).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.queue_limit >= 1
            && self.queue_limit <= HOST_SLOTS as u32
            && self.resume_depth < self.queue_limit
            && self.sojourn_ms >= SOJOURN_MS_MIN
            && self.sojourn_ms <= SOJOURN_MS_MAX
            && self.codel_target_us >= CODEL_TARGET_US_MIN
            && self.codel_target_us <= CODEL_TARGET_US_MAX
            && self.codel_interval_ms >= CODEL_INTERVAL_MS_MIN
            && self.codel_interval_ms <= CODEL_INTERVAL_MS_MAX
    }
}

impl Default for Tuning {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A tuning set was rejected: nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTuning;
