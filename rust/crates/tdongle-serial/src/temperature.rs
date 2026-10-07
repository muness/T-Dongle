//! The chip temperature's sampling state: `components/tdongle_runtime/temperature.c`, line for line (the sensor itself is the firmware's).
//!
//! The gateway manager of the C calls `tdongle_temperature_sample()` every ten seconds; each call re-reads the sensor. `current` is that reading (tenths of a
//! degree, `lroundf(c * 10)`), `peak` the highest since boot, `changed_at` when `current` last differed from the sample before it. A failed read (the driver's
//! error, or a value that is not finite) clears `valid` and counts an error and leaves everything else as it was.

use crate::status::Temperature;

/// The seconds between samples in the C (`vTaskDelay(pdMS_TO_TICKS(10000))` in the manager loop).
pub const SAMPLE_PERIOD_MS: u32 = 10_000;

/// The state `temperature.c` keeps in a static.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tracker {
    state: Temperature,
}

impl Tracker {
    /// Nothing sampled yet.
    pub const fn new() -> Self {
        Self { state: Temperature { valid: false, current_tenths: 0, peak_tenths: 0, sampled_at_ms: 0, errors: 0, samples: 0, changed_at_ms: 0, age_ms: 0 } }
    }

    /// `tdongle_temperature_sample`: `reading` is the sensor's degrees C, `None` when the driver reported an error.
    pub fn sample(&mut self, now_ms: u32, reading: Option<f32>) {
        let s = &mut self.state;
        match reading.filter(|c| c.is_finite()) {
            Some(c) => {
                let tenths = c * 10.0;
                // `lroundf`: half away from zero
                let value = (if tenths >= 0.0 { tenths + 0.5 } else { tenths - 0.5 }) as i32;
                if s.samples == 0 || value > s.peak_tenths {
                    s.peak_tenths = value;
                }
                if s.samples == 0 || value != s.current_tenths {
                    s.changed_at_ms = now_ms;
                }
                s.valid = true;
                s.current_tenths = value;
                s.sampled_at_ms = now_ms;
                s.samples = s.samples.wrapping_add(1);
            }
            None => {
                s.valid = false;
                s.errors = s.errors.wrapping_add(1);
            }
        }
    }

    /// `tdongle_temperature_snapshot`: the state with `age_ms` filled in (`u32::MAX` before the first sample).
    pub fn snapshot(&self, now_ms: u32) -> Temperature {
        let mut t = self.state;
        t.age_ms = if t.samples != 0 { now_ms.wrapping_sub(t.sampled_at_ms) } else { u32::MAX };
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The assertions of `components/tdongle_runtime/tests/test_sensors.c`.
    #[test]
    fn it_follows_the_c_sensor_test() {
        let mut t = Tracker::new();
        t.sample(0, None);
        let s = t.snapshot(0);
        assert!(!s.valid && s.errors == 1 && s.age_ms == u32::MAX);
        t.sample(100, Some(55.25));
        let s = t.snapshot(100);
        assert!(s.valid && s.current_tenths == 553 && s.peak_tenths == 553, "55.25 rounds to 553 (half away from zero)");
        t.sample(200, Some(40.0));
        let s = t.snapshot(200);
        assert_eq!((s.peak_tenths, s.current_tenths, s.sampled_at_ms), (553, 400, 200));
        t.sample(300, Some(f32::NAN));
        let s = t.snapshot(300);
        assert!(!s.valid && s.sampled_at_ms == 200 && s.errors == 2, "a failed read keeps the last sample's time");
        t.sample(400, Some(60.0));
        let s = t.snapshot(400);
        assert!(s.valid && s.peak_tenths == 600);
    }

    #[test]
    fn age_and_change_time_follow_the_samples() {
        let mut t = Tracker::new();
        t.sample(1_000, Some(61.9));
        t.sample(11_000, Some(61.9));
        t.sample(21_000, Some(61.9));
        let s = t.snapshot(24_000);
        assert_eq!((s.current_tenths, s.samples, s.sampled_at_ms, s.age_ms, s.changed_at_ms, s.peak_tenths), (619, 3, 21_000, 3_000, 1_000, 619));
        t.sample(31_000, Some(45.1));
        let s = t.snapshot(31_000);
        assert_eq!((s.current_tenths, s.peak_tenths, s.changed_at_ms, s.age_ms, s.samples), (451, 619, 31_000, 0, 4));
        t.sample(41_000, Some(-3.25));
        assert_eq!(t.snapshot(41_000).current_tenths, -33, "negative values round away from zero too");
    }
}
