//! The chip temperature (`components/tdongle_runtime/temperature.c` over ESP-IDF's `esp_driver_tsens`), sampled the way the C's gateway manager does: every ten
//! seconds, the sensor switched on for the reading and off again, one fresh reading each time (never cached), the highest since boot kept as `peak`.
//!
//! What the IDF driver does for the ESP32-S3 and this repeats, with the driver's own constants (`soc/esp32s3/temperature_sensor_periph.c`, `esp_hw_support/
//! sar_periph_ctrl_common.c`, `esp_driver_tsens/src/temperature_sensor.c`):
//!
//! * the C installs the sensor for 20..100 degrees C: range 1 (DAC register 7, offset -1);
//! * a reading is `0.4386 * raw - 27.88 * offset - 20.52`, truncated to whole degrees; outside the range's limits the next range is selected (DAC register written,
//!   300 microseconds to settle) and the sensor is read again;
//! * the result is that integer minus the eFuse calibration (`TEMP_CALIB`, block 2, 9 bits, sign in bit 8, in tenths of a degree, used when the RTC calibration
//!   block is version 1): `tsens_raw - deltaT / 10`, so readings move in steps of one degree and repeat while the die stays inside one;
//! * a result below -40 or above 125 is an error.

use core::cell::RefCell;
use critical_section::Mutex;
use embassy_time::{Instant, Timer};
use esp_hal::peripherals::TSENS;
use esp_hal::tsens::{Config, TemperatureSensor};
use tdongle_serial::status::Temperature;
use tdongle_serial::temperature::{SAMPLE_PERIOD_MS, Tracker};

static TRACKER: Mutex<RefCell<Tracker>> = Mutex::new(RefCell::new(Tracker::new()));

/// The `tdongle_temperature_snapshot` of the C.
pub fn snapshot() -> Temperature {
    let now = Instant::now().as_millis() as u32;
    critical_section::with(|cs| TRACKER.borrow_ref(cs).snapshot(now))
}

/// `temperature_sensor_attributes`: `(offset, DAC register value, min, max)` of the five ranges.
const RANGES: [(i32, u8, i32, i32); 5] = [(-2, 5, 50, 125), (-1, 7, 20, 100), (0, 15, -10, 80), (1, 11, -30, 50), (2, 10, -40, 20)];
/// The range the C installs (20..100).
const START_RANGE: usize = 1;

/// The eFuse calibration in tenths of a degree (`esp_efuse_rtc_calib_get_tsens_val`): 0 when the block has no calibration.
fn calibration() -> f32 {
    if esp_hal::efuse::rtc_calib_version() != 1 {
        return 0.0;
    }
    let cal: u16 = esp_hal::efuse::read_field_le(esp_hal::efuse::TEMP_CALIB);
    // bit 8 is the sign; the magnitude is the low byte (the C negates the `uint8_t`)
    if cal & 0x100 != 0 { -f32::from(cal as u8) } else { f32::from(cal as u8) }
}

fn whole_degrees(raw: u8, range: usize) -> i32 {
    (0.4386 * f32::from(raw) - 27.88 * RANGES[range].0 as f32 - 20.52) as i32
}

/// `temp_sensor_get_raw_value`: the reading in whole degrees, choosing another range when this one's limits are passed.
async fn read_degrees(sensor: &TemperatureSensor<'_>, range: &mut usize) -> i32 {
    let mut degree = whole_degrees(sensor.get_temperature().raw_value, *range);
    let (_, _, min, max) = RANGES[*range];
    if degree >= min && degree <= max {
        return degree;
    }
    *range = if degree >= RANGES[1].3 {
        0
    } else if degree >= RANGES[2].3 && degree < RANGES[1].3 {
        1
    } else if degree <= RANGES[2].2 && degree > RANGES[3].2 {
        3
    } else if degree <= RANGES[3].2 {
        4
    } else {
        2
    };
    sensor.set_dac(RANGES[*range].1);
    Timer::after_millis(1).await;
    degree = whole_degrees(sensor.get_temperature().raw_value, *range);
    degree
}

/// One `tdongle_temperature_sample`: power the sensor, let it settle, read, power it down.
async fn sample(sensor: &TemperatureSensor<'_>, range: &mut usize, delta: f32) -> Option<f32> {
    sensor.power_up();
    sensor.set_dac(RANGES[*range].1);
    // the driver waits 300 microseconds after enabling; a millisecond tick is the shortest wait the executor offers
    Timer::after_millis(1).await;
    let degrees = read_degrees(sensor, range).await;
    sensor.power_down();
    let c = degrees as f32 - delta / 10.0;
    (-40.0..=125.0).contains(&c).then_some(c)
}

/// The sampling task: the first sample at once, then every ten seconds.
#[embassy_executor::task]
pub async fn task(tsens: TSENS<'static>) {
    let Ok(sensor) = TemperatureSensor::new(tsens, Config::default()) else {
        // the driver could not be installed: the C would count an error on every sample
        loop {
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).sample(Instant::now().as_millis() as u32, None));
            Timer::after_millis(u64::from(SAMPLE_PERIOD_MS)).await;
        }
    };
    sensor.power_down();
    let delta = calibration();
    let mut range = START_RANGE;
    loop {
        let r = sample(&sensor, &mut range, delta).await;
        critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).sample(Instant::now().as_millis() as u32, r));
        Timer::after_millis(u64::from(SAMPLE_PERIOD_MS)).await;
    }
}
