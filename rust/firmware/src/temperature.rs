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

// ---- the registers (`temperature_sensor_ll.h`, `regi2c_ctrl_ll.h`, ESP32-S3): esp-hal has no driver for this chip's sensor ----------------------------------------------

const SENS_BASE: usize = 0x6000_8800;
/// `SENS_SAR_TSENS_CTRL_REG`: DUMP_OUT 24, POWER_UP_FORCE 23, POWER_UP 22, READY 8, OUT 7:0.
const TSENS_CTRL: usize = SENS_BASE + 0x50;
/// `SENS_SAR_TSENS_CTRL2_REG`: XPD_FORCE 13:12.
const TSENS_CTRL2: usize = SENS_BASE + 0x54;
/// `SENS_SAR_PERI_CLK_GATE_CONF_REG`: TSENS_CLK_EN 29.
const CLK_GATE: usize = SENS_BASE + 0x104;
/// `SENS_SAR_PERI_RESET_CONF_REG`: TSENS_RESET 29.
const RESET_CONF: usize = SENS_BASE + 0x108;
/// `ANA_CONFIG_REG` (clear `I2C_SAR_M`, bit 18) and `ANA_CONFIG2_REG` (set `ANA_SAR_CFG2_M`, bit 16): the I2C bus to the SAR block, which the DAC register is on.
const ANA_CONFIG: usize = 0x6000_E044;
const ANA_CONFIG2: usize = 0x6000_E048;

unsafe extern "C" {
    fn rom_i2c_writeReg_Mask(block: u8, host_id: u8, reg_add: u8, msb: u8, lsb: u8, data: u8);
}

fn modify(addr: usize, clear: u32, set: u32) {
    // SAFETY: peripheral registers of the SENS and RTC_CNTL blocks; nothing else in the firmware uses the temperature sensor's bits.
    unsafe {
        let p = addr as *mut u32;
        p.write_volatile((p.read_volatile() & !clear) | set);
    }
}

fn read32(addr: usize) -> u32 {
    // SAFETY: as `modify`.
    unsafe { (addr as *const u32).read_volatile() }
}

/// `regi2c_saradc_enable` + the clock and reset of the module (once at start; the I2C bus stays enabled, the radio's calibration uses it too).
fn bus_on() {
    critical_section::with(|_| {
        modify(ANA_CONFIG, 1 << 18, 0);
        modify(ANA_CONFIG2, 0, 1 << 16);
        modify(CLK_GATE, 0, 1 << 29);
        modify(RESET_CONF, 0, 1 << 29);
        modify(RESET_CONF, 1 << 29, 0);
    });
}

/// `temperature_sensor_ll_enable`.
fn power(on: bool) {
    let b = u32::from(on);
    critical_section::with(|_| {
        modify(TSENS_CTRL, (1 << 23) | (1 << 22), (b << 23) | (b << 22));
        modify(TSENS_CTRL2, 3 << 12, b << 12);
    });
}

/// `temperature_sensor_ll_set_range`: the DAC register value, `I2C_SARADC_TSENS_DAC` (register 6 of the SAR block, bits 3..0).
fn set_range(reg_val: u8) {
    critical_section::with(|_| {
        // SAFETY: the ROM's I2C master routine, the one esp-hal and ESP-IDF call for this field.
        unsafe { rom_i2c_writeReg_Mask(0x69, 1, 6, 3, 0, reg_val) };
    });
}

/// `temperature_sensor_ll_get_raw_value`: dump the sensor's output and read it (`None` if it never says ready).
fn raw() -> Option<u8> {
    critical_section::with(|_| {
        modify(TSENS_CTRL, 0, 1 << 24);
        let mut n = 0u32;
        while read32(TSENS_CTRL) & (1 << 8) == 0 {
            n += 1;
            if n > 100_000 {
                modify(TSENS_CTRL, 1 << 24, 0);
                return None;
            }
        }
        modify(TSENS_CTRL, 1 << 24, 0);
        Some((read32(TSENS_CTRL) & 0xFF) as u8)
    })
}

/// `temp_sensor_get_raw_value`: the reading in whole degrees, choosing another range when this one's limits are passed.
async fn read_degrees(range: &mut usize) -> Option<i32> {
    let mut degree = whole_degrees(raw()?, *range);
    let (_, _, min, max) = RANGES[*range];
    if degree >= min && degree <= max {
        return Some(degree);
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
    set_range(RANGES[*range].1);
    Timer::after_millis(1).await;
    degree = whole_degrees(raw()?, *range);
    Some(degree)
}

/// One `tdongle_temperature_sample`: power the sensor, let it settle, read, power it down.
async fn sample(range: &mut usize, delta: f32) -> Option<f32> {
    power(true);
    set_range(RANGES[*range].1);
    // the driver waits 300 microseconds after enabling; a millisecond tick is the shortest wait the executor offers
    Timer::after_millis(1).await;
    let degrees = read_degrees(range).await;
    power(false);
    let c = degrees? as f32 - delta / 10.0;
    (-40.0..=125.0).contains(&c).then_some(c)
}

/// The sampling task: the first sample at once, then every ten seconds.
#[embassy_executor::task]
pub async fn task() {
    bus_on();
    let delta = calibration();
    let mut range = START_RANGE;
    loop {
        let r = sample(&mut range, delta).await;
        critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).sample(Instant::now().as_millis() as u32, r));
        Timer::after_millis(u64::from(SAMPLE_PERIOD_MS)).await;
    }
}
