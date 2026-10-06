//! CoDel (RFC 8289) as a one-packet-at-a-time decision function. Port of the `tdongle_codel_*` half of `tdongle_aqm.h`.
//!
//! CoDel is given a "sojourn" in microseconds. The caller chooses the signal (in the C firmware: the larger of the packet's own time in the
//! dongle and the time the pipe has been continuously full); this module does not care. All times are `u32` microseconds on a clock that wraps
//! (about every 71.6 minutes), and every comparison is done on wrapping differences, exactly as in C.

/// Default CoDel target sojourn in microseconds (`TDONGLE_CODEL_TARGET_US_DEFAULT`).
pub const TARGET_US_DEFAULT: u32 = 5000;
/// Default CoDel interval in milliseconds (`TDONGLE_CODEL_INTERVAL_MS_DEFAULT`).
pub const INTERVAL_MS_DEFAULT: u32 = 100;

/// CoDel controller state (`tdongle_codel_t`). Fields are public because the firmware reads them for diagnostics and the tests assert on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Codel {
    /// Sojourn below which the queue is good, microseconds.
    pub target_us: u32,
    /// Window over which the sojourn must stay above target before signalling starts, microseconds.
    pub interval_us: u32,
    /// In the dropping (signalling) state.
    pub dropping: bool,
    /// Time at which the sojourn will have been above target for a full interval; 0: not above.
    pub first_above_us: u32,
    /// Time of the next scheduled signal while dropping.
    pub drop_next_us: u32,
    /// Signals in the current dropping state (drives the 1/sqrt(count) schedule).
    pub count: u32,
    /// `count` at the start of the previous dropping state (RFC 8289 `lastcount`).
    pub lastcount: u32,
}

impl Codel {
    /// A fresh controller (`tdongle_codel_init`).
    #[must_use]
    pub const fn new(target_us: u32, interval_us: u32) -> Self {
        Self {
            target_us,
            interval_us,
            dropping: false,
            first_above_us: 0,
            drop_next_us: 0,
            count: 0,
            lastcount: 0,
        }
    }

    /// Change the parameters and restart the controller: a state built under other numbers means nothing (`tdongle_codel_retune`).
    pub fn retune(&mut self, target_us: u32, interval_us: u32) {
        *self = Self::new(target_us, interval_us);
    }

    /// `t_us + interval / sqrt(count)`: the control law (`tdongle_codel_control_law`).
    ///
    /// The square root is in 16.16 fixed point (`isqrt64(count << 32) = 65536 sqrt(count)`): exact at count 1 and within 1e-5 relative at 65535,
    /// where a coarser root made the schedule drift by 50 us per step in the first few signals. A `count` of 0 is treated as 1. Wrapping addition.
    #[must_use]
    pub fn control_law(&self, t_us: u32, count: u32) -> u32 {
        let root = isqrt64(u64::from(if count == 0 { 1 } else { count }) << 32);
        // root >= 65536, so the quotient is at most interval_us and the narrowing is lossless (C: `(uint32_t)`).
        t_us.wrapping_add(((u64::from(self.interval_us) << 16) / root) as u32)
    }

    /// One packet leaves the queue with this sojourn at time `now_us`: should it be signalled (marked or dropped)?
    ///
    /// RFC 8289 section 5.5, one packet at a time (`tdongle_codel_should_signal`). The standard loop that drops several packets from one dequeue
    /// call is not needed: each packet is decided once, and a packet that finds `now` already past the next scheduled signal is signalled and the
    /// schedule advances, so the following packet is signalled too (the same sequence, packet by packet).
    ///
    /// Deliberate deviation from RFC 8289, as in C: the pseudocode guards entry to the dropping state with one more clause about the time since
    /// the last dropping state; what that protects is the choice of `count`, which is kept (see the resume rule below), not whether a standing queue
    /// is acted on, so entry here needs only a full interval above target.
    pub fn should_signal(&mut self, sojourn_us: u32, now_us: u32) -> bool {
        let mut ok_to_drop = false;
        if sojourn_us < self.target_us {
            self.first_above_us = 0; // good queue
        } else if self.first_above_us == 0 {
            self.first_above_us = now_us.wrapping_add(self.interval_us); // bad: start the clock of a full interval
            if self.first_above_us == 0 {
                self.first_above_us = 1;
            }
        } else if diff(now_us, self.first_above_us) >= 0 {
            ok_to_drop = true; // above target for a whole interval
        }
        if self.dropping {
            if !ok_to_drop {
                self.dropping = false; // leave the dropping state
                return false;
            }
            if diff(now_us, self.drop_next_us) >= 0 {
                self.count = self.count.wrapping_add(1);
                self.drop_next_us = self.control_law(self.drop_next_us, self.count);
                return true;
            }
            return false;
        }
        if ok_to_drop {
            // Entry: the sojourn has been above target for a whole interval (see the deviation note above).
            self.dropping = true;
            let delta = self.count.wrapping_sub(self.lastcount);
            // Resume near the previous rate if the last dropping state ended recently (RFC 8289: within 16 intervals).
            let recent = diff(now_us, self.drop_next_us) < self.interval_us.wrapping_mul(16) as i32;
            self.count = if delta > 1 && recent { delta } else { 1 };
            self.drop_next_us = self.control_law(now_us, self.count);
            self.lastcount = self.count;
            return true;
        }
        false
    }
}

/// `floor(sqrt(x))` for 32-bit `x`, by the bitwise method: no libm, no FPU (the S3 has none for double). Port of `tdongle_isqrt`.
#[must_use]
pub const fn isqrt(mut x: u32) -> u32 {
    let mut r: u32 = 0;
    let mut bit: u32 = 1 << 30;
    while bit > x {
        bit >>= 2;
    }
    while bit != 0 {
        if x >= r + bit {
            x -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    r
}

/// `floor(sqrt(x))` for 64-bit `x` (same method). Signals are rare (at most a few hundred a second), so 32 iterations are nothing.
/// Port of `tdongle_isqrt64`.
#[must_use]
pub const fn isqrt64(mut x: u64) -> u64 {
    let mut r: u64 = 0;
    let mut bit: u64 = 1 << 62;
    while bit > x {
        bit >>= 2;
    }
    while bit != 0 {
        if x >= r + bit {
            x -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    r
}

/// The wrapping difference `a - b` in microseconds as a signed quantity (`tdongle_codel_diff`): positive when `a` is later than `b` within
/// half the clock range (about 35.8 minutes).
#[must_use]
pub const fn diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

/// Control law as a free function: see [`Codel::control_law`].
#[must_use]
pub fn control_law(c: &Codel, t_us: u32, count: u32) -> u32 {
    c.control_law(t_us, count)
}
