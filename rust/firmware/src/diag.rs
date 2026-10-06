//! Evidence the serial `status` reports besides the bridge counters: the heap low-water records (`memory_pressure`) and the chip temperature.

use core::cell::UnsafeCell;

use esp_idf_svc::sys;
use tdongle_serial::memory_log::{MemoryLog, Record};
use tdongle_serial::status::Temperature;

use crate::sys::critical::Mux;
use crate::sys::{heap, now_ms};

pub use tdongle_serial::memory_log::{OP_TICK, OP_WIFI_PROFILES};

struct Guarded<T> {
    lock: Mux,
    value: UnsafeCell<T>,
}

// SAFETY: every access to `value` is inside `lock`.
unsafe impl<T: Send> Sync for Guarded<T> {}

impl<T> Guarded<T> {
    const fn new(value: T) -> Self {
        Self { lock: Mux::new(), value: UnsafeCell::new(value) }
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.lock.lock();
        // SAFETY: exclusive while the critical section is held.
        let result = f(unsafe { &mut *self.value.get() });
        self.lock.unlock();
        result
    }
}

static LOG: Guarded<MemoryLog> = Guarded::new(MemoryLog::new());

/// `tdongle_memory_note`: record the heap now (free, lowest ever, largest block). Low-water transitions and failures are kept; ordinary traffic
/// cannot evict them. The largest-block query walks the heap, so call it from housekeeping, never from the data path.
pub fn note_memory(operation: u32, requested: usize, failed: bool) {
    let record = Record {
        uptime_ms: now_ms(),
        operation,
        requested: requested as u32,
        free_bytes: heap::free_internal() as u32,
        minimum_bytes: heap::minimum_free_internal() as u32,
        largest_bytes: heap::largest_free_block() as u32,
        failed: u32::from(failed),
    };
    LOG.with(|log| {
        log.note(record, failed);
    });
}

/// The records, oldest first.
pub fn memory_records() -> ([Record; tdongle_serial::memory_log::CAPACITY], usize) {
    LOG.with(|log| {
        let mut out = [Record::default(); tdongle_serial::memory_log::CAPACITY];
        let mut n = 0;
        for (slot, record) in out.iter_mut().zip(log.iter()) {
            *slot = record;
            n += 1;
        }
        (out, n)
    })
}

/// The driver's sensor handle, usable from any task (the driver serialises its own state).
#[derive(Clone, Copy)]
struct SensorHandle(sys::temperature_sensor_handle_t);

// SAFETY: a handle is an opaque pointer the temperature driver accepts from any task; this file calls the driver from the manager task only.
unsafe impl Send for SensorHandle {}

struct Sensor {
    handle: SensorHandle,
    state: Temperature,
}

static SENSOR: Guarded<Sensor> = Guarded::new(Sensor {
    handle: SensorHandle(core::ptr::null_mut()),
    state: Temperature { valid: false, current_tenths: 0, peak_tenths: 0, sampled_at_ms: 0, errors: 0, samples: 0, changed_at_ms: 0, age_ms: 0 },
});

/// One sample of the chip temperature sensor (`tdongle_temperature_sample`): the manager calls it every ten seconds. On the ESP32-S3 the driver
/// reports whole degrees minus a calibration offset, so a repeated value is not evidence of a stale reading: `samples` and `age_ms` are.
pub fn sample_temperature() {
    // The driver calls take their own locks and may sleep: they run outside the critical section; only the result is stored inside it.
    let mut handle = SENSOR.with(|s| s.handle.0);
    let mut code = sys::ESP_OK;
    if handle.is_null() {
        let config = sys::temperature_sensor_config_t { range_min: 20, range_max: 100, clk_src: 0, flags: Default::default() };
        // SAFETY: `config` and `handle` are valid for the call.
        code = unsafe { sys::temperature_sensor_install(&config, &mut handle) };
        if code == sys::ESP_OK {
            SENSOR.with(|s| s.handle = SensorHandle(handle));
        }
    }
    let mut celsius = 0.0f32;
    if code == sys::ESP_OK {
        // SAFETY: `handle` came from a successful install; the sensor is enabled around the read and disabled again.
        unsafe {
            code = sys::temperature_sensor_enable(handle);
            if code == sys::ESP_OK {
                code = sys::temperature_sensor_get_celsius(handle, &mut celsius);
                sys::temperature_sensor_disable(handle);
            }
        }
    }
    let now = now_ms();
    SENSOR.with(|s| {
        let t = &mut s.state;
        if code == sys::ESP_OK && celsius.is_finite() {
            let value = (celsius * 10.0).round() as i32;
            if t.samples == 0 || value > t.peak_tenths {
                t.peak_tenths = value;
            }
            if t.samples == 0 || value != t.current_tenths {
                t.changed_at_ms = now;
            }
            t.valid = true;
            t.current_tenths = value;
            t.sampled_at_ms = now;
            t.samples += 1;
        } else {
            t.valid = false;
            t.errors += 1;
        }
    });
}

/// The latest sample, with its age (`tdongle_temperature_snapshot`). `now` is read inside the section: a sample taken between a clock read and the
/// copy would otherwise be newer than `now` and its age would wrap to about 49 days.
pub fn temperature() -> Temperature {
    SENSOR.with(|s| {
        let now = now_ms();
        let mut copy = s.state;
        copy.age_ms = if copy.samples != 0 { now.wrapping_sub(copy.sampled_at_ms) } else { u32::MAX };
        copy
    })
}
