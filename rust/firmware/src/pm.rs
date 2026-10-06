//! CPU frequency scaling (ADR 0016, ADR 0023 section 4): 240 MHz while forwarding work is pending, 80 MHz when idle, no light sleep.
//!
//! The counting and the activity-hold logic are `tdongle-pm` (host-tested); this file is the ESP-IDF half: `esp_pm_configure`, the
//! `ESP_PM_CPU_FREQ_MAX` locks and the one-shot timer that ends the forwarding-activity hold.

use core::ffi::CStr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use esp_idf_svc::sys;
use tdongle_pm::{BurstId, LockCreate, MAX_BURSTS, Pm, PmHardware, PmStatus};

use crate::sys::now_us;

/// The ESP-IDF half of [`Pm`].
#[derive(Debug)]
pub struct Hardware {
    locks: [AtomicPtr<sys::esp_pm_lock>; MAX_BURSTS],
    timer: AtomicPtr<sys::esp_timer>,
}

impl Hardware {
    const fn new() -> Self {
        Self { locks: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_BURSTS], timer: AtomicPtr::new(core::ptr::null_mut()) }
    }
}

extern "C" fn activity_fire(_argument: *mut core::ffi::c_void) {
    PM.activity_fire();
}

impl PmHardware for Hardware {
    fn configure(&self, max_mhz: u32, min_mhz: u32) -> Result<(), i32> {
        let config = sys::esp_pm_config_t { max_freq_mhz: max_mhz as i32, min_freq_mhz: min_mhz as i32, light_sleep_enable: false };
        // SAFETY: `config` is valid for the call; `esp_pm_configure` copies it.
        let code = unsafe { sys::esp_pm_configure((&raw const config).cast()) };
        if code == sys::ESP_OK { Ok(()) } else { Err(code) }
    }

    fn cpu_mhz(&self) -> u32 {
        // SAFETY: reads the current CPU clock configuration.
        (unsafe { sys::esp_clk_cpu_freq() } / 1_000_000) as u32
    }

    fn now_us(&self) -> u32 {
        now_us()
    }

    fn in_isr(&self) -> bool {
        // SAFETY: `xPortInIsrContext` only reads the interrupt nesting state.
        unsafe { sys::xPortInIsrContext() != 0 }
    }

    fn lock_create(&self, slot: usize, name: &str) -> LockCreate {
        let mut buffer = [0u8; 24];
        let n = name.len().min(buffer.len() - 1);
        buffer[..n].copy_from_slice(&name.as_bytes()[..n]);
        let Ok(c_name) = CStr::from_bytes_until_nul(&buffer) else {
            return LockCreate::Failed(sys::ESP_ERR_INVALID_ARG);
        };
        let mut handle: sys::esp_pm_lock_handle_t = core::ptr::null_mut();
        // SAFETY: `c_name` is NUL terminated (the driver keeps the pointer: the name lives in a `static` copy below); `handle` is a valid out pointer.
        // `esp_pm_lock_create` copies nothing of `c_name`, so leak a stable copy for the life of the firmware, as the C's string literals are.
        let stable: &'static CStr = Box::leak(c_name.to_owned().into_boxed_c_str());
        let code = unsafe { sys::esp_pm_lock_create(sys::esp_pm_lock_type_t_ESP_PM_CPU_FREQ_MAX, 0, stable.as_ptr(), &mut handle) };
        match code {
            sys::ESP_OK => {
                self.locks[slot].store(handle, Ordering::Release);
                LockCreate::Created
            }
            sys::ESP_ERR_NOT_SUPPORTED => LockCreate::NotSupported,
            other => LockCreate::Failed(other),
        }
    }

    fn lock_acquire(&self, slot: usize) -> bool {
        let handle = self.locks[slot].load(Ordering::Acquire);
        // SAFETY: a handle stored by `lock_create` is valid for ever (never deleted).
        !handle.is_null() && unsafe { sys::esp_pm_lock_acquire(handle) } == sys::ESP_OK
    }

    fn lock_release(&self, slot: usize) {
        let handle = self.locks[slot].load(Ordering::Acquire);
        if !handle.is_null() {
            // SAFETY: as `lock_acquire`.
            unsafe { sys::esp_pm_lock_release(handle) };
        }
    }

    fn timer_create(&self) -> bool {
        let args = sys::esp_timer_create_args_t {
            callback: Some(activity_fire),
            arg: core::ptr::null_mut(),
            dispatch_method: sys::esp_timer_dispatch_t_ESP_TIMER_TASK,
            name: c"pm_activity".as_ptr(),
            skip_unhandled_events: false,
        };
        let mut handle: sys::esp_timer_handle_t = core::ptr::null_mut();
        // SAFETY: `args` is valid for the call (the driver copies it; the name is a static C string); `handle` is a valid out pointer.
        let ok = unsafe { sys::esp_timer_create(&args, &mut handle) } == sys::ESP_OK;
        if ok {
            self.timer.store(handle, Ordering::Release);
        }
        ok
    }

    fn timer_start_once(&self, delay_us: u32) {
        let handle = self.timer.load(Ordering::Acquire);
        if !handle.is_null() {
            // SAFETY: a handle stored by `timer_create`, never deleted. Already armed: ESP_ERR_INVALID_STATE, nothing to do.
            unsafe { sys::esp_timer_start_once(handle, u64::from(delay_us)) };
        }
    }

    fn dump_locks(&self, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        buffer[0] = 0;
        // SAFETY: `fmemopen` over `buffer` for writing; `esp_pm_dump_locks` writes text into the stream; `fclose` flushes and NUL terminates when
        // there is room. The buffer outlives the stream (closed before return).
        unsafe {
            let stream = sys::fmemopen(buffer.as_mut_ptr().cast(), buffer.len(), c"w".as_ptr());
            if stream.is_null() {
                return 0;
            }
            sys::esp_pm_dump_locks(stream);
            sys::fclose(stream);
        }
        let last = buffer.len() - 1;
        buffer[last] = 0;
        buffer.iter().position(|&b| b == 0).unwrap_or(last)
    }
}

/// The one power-management registry of the image.
pub static PM: Pm<Hardware> = Pm::new(Hardware::new());

struct Bursts {
    usb_tx: Option<BurstId>,
}

static BURSTS: OnceLock<Bursts> = OnceLock::new();

/// Enable scaling (max 240, min 80 MHz, no light sleep) and register the transmit ring's burst. On failure the CPU stays at its boot frequency,
/// fixed at the maximum. Once, before the forwarding tasks start.
pub fn start() {
    match PM.start() {
        Ok(()) => log::info!("DFS {}..{} MHz, light sleep off", tdongle_pm::MIN_MHZ, tdongle_pm::MAX_MHZ),
        Err(code) => log::error!("esp_pm_configure failed ({code:#x}): running fixed at the boot frequency"),
    }
    let usb_tx = match PM.register_burst("usb_txq") {
        Ok(id) => Some(id),
        Err(error) => error.failed_id(),
    };
    if BURSTS.set(Bursts { usb_tx }).is_err() {
        log::warn!("power management started twice");
    }
}

/// The ring worker's CPU-max hold begins (`usb_tx_pm_begin`): worker only, strictly alternating with [`usb_tx_end`].
pub fn usb_tx_begin() {
    if let Some(Bursts { usb_tx: Some(id) }) = BURSTS.get() {
        PM.begin(*id);
    }
}

/// The ring worker's hold ends.
pub fn usb_tx_end() {
    if let Some(Bursts { usb_tx: Some(id) }) = BURSTS.get() {
        PM.end(*id);
    }
}

/// A packet is passing through a stage that has no queue of ours to wait on: the first call after a quiet spell raises the clock for every core
/// (`tdongle_pm_note_activity`). One atomic load while the hold is active.
#[inline]
pub fn note_activity() {
    PM.note_activity();
}

/// The `pm` command's data.
pub fn status() -> PmStatus {
    PM.status()
}

/// `esp_pm_dump_locks` into `buffer`; returns the length.
pub fn dump_locks(buffer: &mut [u8]) -> usize {
    PM.dump_locks(buffer)
}
