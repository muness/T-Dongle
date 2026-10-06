//! The ESP-IDF critical section (a spinlock that also masks interrupts on the calling core): `portENTER_CRITICAL` / `portEXIT_CRITICAL`.

use core::cell::UnsafeCell;

use esp_idf_svc::sys;

/// A `portMUX_TYPE` with split `lock`/`unlock` calls, which is the shape the pure crates' environment traits ask for
/// (`tdongle_usb_ring::RingEnv::lock`).
///
/// Not reentrant on the same core in the sense the pure crates need ("never nested"), though the underlying IDF section does count nesting.
#[derive(Debug)]
pub struct Mux(UnsafeCell<sys::portMUX_TYPE>);

// SAFETY: the spinlock is the synchronisation primitive; it is designed to be shared between cores and with interrupt handlers.
unsafe impl Sync for Mux {}
// SAFETY: as above; the lock word is plain data that may live in any task.
unsafe impl Send for Mux {}

impl Mux {
    /// `portMUX_INITIALIZER_UNLOCKED`.
    pub const fn new() -> Self {
        Self(UnsafeCell::new(sys::portMUX_TYPE { owner: sys::portMUX_FREE_VAL, count: 0 }))
    }

    /// `portENTER_CRITICAL(mux)`: waits for the spinlock, forever.
    #[inline]
    pub fn lock(&self) {
        // SAFETY: the pointer is to a live, properly initialised portMUX_TYPE; SPINLOCK_WAIT_FOREVER is the documented "no timeout" value.
        unsafe {
            sys::xPortEnterCriticalTimeout(self.0.get(), sys::SPINLOCK_WAIT_FOREVER as _);
        }
    }

    /// `portEXIT_CRITICAL(mux)`. Must follow a [`lock`](Self::lock) by the same context.
    #[inline]
    pub fn unlock(&self) {
        // SAFETY: as `lock`; the caller upholds the pairing.
        unsafe { sys::vPortExitCritical(self.0.get()) }
    }
}

impl Default for Mux {
    fn default() -> Self {
        Self::new()
    }
}
