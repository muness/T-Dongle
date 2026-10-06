//! FreeRTOS task notifications and priorities: the bridge's wake-ups (`xTaskNotifyGive`, `ulTaskNotifyTake`).
//!
//! The C firmware's workers are FreeRTOS tasks that sleep on their notification value. The Rust firmware keeps exactly that mechanism: it is
//! the cheapest wake-up there is (no queue, no allocation), it is callable from the TinyUSB task and the Wi-Fi task without blocking, and
//! it coalesces, so a notification that arrives while the worker is busy is kept and no wake-up is lost.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use esp_idf_svc::sys;

/// A task a notification can be sent to, remembered by the task itself ([`Notified::for_current_task`]).
#[derive(Debug)]
pub struct Notified {
    handle: AtomicPtr<c_void>,
}

impl Notified {
    /// A target nobody listens on yet; notifications to it are ignored.
    pub const fn new() -> Self {
        Self { handle: AtomicPtr::new(core::ptr::null_mut()) }
    }

    /// Make the calling task the one that [`give`](Self::give) wakes. Call once, from the worker, before it first waits.
    pub fn register_current_task(&self) {
        // SAFETY: returns the calling task's own handle, valid for as long as the task lives (the workers never exit).
        let handle = unsafe { sys::xTaskGetCurrentTaskHandle() };
        self.handle.store(handle.cast(), Ordering::Release);
    }

    /// `xTaskNotifyGive`: never blocks, any context that may call FreeRTOS from a task. A no-op until a task registered.
    #[inline]
    pub fn give(&self) {
        let handle = self.handle.load(Ordering::Acquire);
        if !handle.is_null() {
            // SAFETY: the handle was stored by `register_current_task` and the task never exits; eIncrement on notification index 0 is what
            // the `xTaskNotifyGive` macro expands to.
            unsafe {
                sys::xTaskGenericNotify(handle.cast(), 0, 0, sys::eNotifyAction_eIncrement, core::ptr::null_mut());
            }
        }
    }
}

impl Notified {
    /// The registered task's stack high-water mark (bytes never used), 0 until a task registered.
    pub fn stack_free(&self) -> u32 {
        let handle = self.handle.load(Ordering::Acquire);
        if handle.is_null() {
            return 0;
        }
        // SAFETY: the handle was stored by `register_current_task` and the task never exits.
        unsafe { sys::uxTaskGetStackHighWaterMark(handle.cast()) }
    }
}

impl Default for Notified {
    fn default() -> Self {
        Self::new()
    }
}

/// `ulTaskNotifyTake(pdTRUE, ticks)`: clear the calling task's notification count and return what it was, waiting up to `ticks` for it to
/// become non-zero. Only the task that registered may call it.
pub fn notify_take(ticks: u32) -> u32 {
    // SAFETY: operates on the calling task's own notification state.
    unsafe { sys::ulTaskGenericNotifyTake(0, 1, ticks) }
}

/// `portMAX_DELAY`.
pub const WAIT_FOREVER: u32 = u32::MAX;

/// `pdMS_TO_TICKS` at the firmware's tick rate (`CONFIG_FREERTOS_HZ` = 100: 10 ms per tick; a 1 ms request rounds down to 0, which is why the
/// bridge never sleeps on the tick for sub-tick waits).
pub const fn ms_to_ticks(ms: u32) -> u32 {
    (ms as u64 * sys::configTICK_RATE_HZ as u64 / 1000) as u32
}

/// `vTaskPrioritySet(NULL, priority)`: the calling task's priority.
pub fn set_current_priority(priority: u32) {
    // SAFETY: a null handle means the calling task.
    unsafe { sys::vTaskPrioritySet(core::ptr::null_mut(), priority) }
}

/// `uxTaskGetStackHighWaterMark(NULL)`: bytes of the calling task's stack never used.
pub fn current_stack_free() -> u32 {
    // SAFETY: a null handle means the calling task.
    unsafe { sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) }
}
