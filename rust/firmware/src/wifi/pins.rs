//! The Wi-Fi TX budget (ADR 0022 amendment 2, ADR 0023): every frame the bridge hands the driver is charged here first, the driver's tx-done
//! callback releases the charge, and a link change flushes them. The rules are `tdongle-wifi-budget`'s; this file is the three hooks
//! (`wifi_pins_tx`, the tx-done callback, `wifi_pins_link_changed`) that connect them to `esp_wifi_internal_tx` and the driver.

use core::sync::atomic::{AtomicBool, Ordering};

use esp_idf_svc::sys;
use tdongle_bridge::TxError;
use tdongle_wifi_budget::{RawLock, WifiPins, WifiPinsStats};

use crate::sys::critical::Mux;
use crate::sys::heap;

/// The TX FIFO's critical section. The pp task can run while the flash cache is off, so everything the tx-done path calls must be in IRAM
/// (`tx_done` below and what it inlines; see `tools/check_iram.py`).
#[derive(Debug)]
pub struct PinsLock(Mux);

impl RawLock for PinsLock {
    #[inline(always)]
    fn lock(&self) {
        self.0.lock();
    }

    #[inline(always)]
    fn unlock(&self) {
        self.0.unlock();
    }
}

/// `gateway_wifi_pins wifi_pins`.
pub static PINS: WifiPins<PinsLock> = WifiPins::new(PinsLock(Mux::new()));

/// `wifi_pins_tx_done_ok`: the tx-done callback is registered, so charges are released by the driver.
static TX_DONE_OK: AtomicBool = AtomicBool::new(false);

/// The pins' millisecond clock: FreeRTOS ticks times the tick period (`wifi_pins_now_ms`), wraps are fine.
fn now_ms() -> u32 {
    // SAFETY: reads the tick count.
    unsafe { sys::xTaskGetTickCount() }.wrapping_mul(1000 / sys::configTICK_RATE_HZ)
}

/// Send one frame on the STA interface, charged to the budget (`wifi_pins_tx`). `NoMem`: refused for buffers (the bridge retries it for a few
/// milliseconds). Worker only.
pub fn tx(frame: &[u8]) -> Result<(), TxError> {
    let length = frame.len() as u16;
    let sent = PINS.tx(TX_DONE_OK.load(Ordering::Relaxed), u32::from(length), heap::free_internal(), now_ms(), || {
        // SAFETY: `frame` is readable for `length` bytes; the driver copies it into its own buffer before returning.
        let code = unsafe { sys::esp_wifi_internal_tx(sys::wifi_interface_t_WIFI_IF_STA, frame.as_ptr().cast_mut().cast(), length) };
        if code == sys::ESP_OK { Ok(()) } else { Err(code) }
    });
    match sent {
        Ok(()) => Ok(()),
        Err(tdongle_wifi_budget::TxError::NoMem) => Err(TxError::NoMem),
        Err(tdongle_wifi_budget::TxError::Driver(code)) => Err(if code == sys::ESP_ERR_NO_MEM { TxError::NoMem } else { TxError::Other(code) }),
    }
}

/// Room for one more charge under the limit now (`wifi_pins_tx_room`): the bridge's worker waits instead of being refused every retry period.
pub fn room() -> bool {
    PINS.room(now_ms())
}

/// The most frames the radio is given at once in bridge mode (`wifi_pins_set_tx_limit`).
pub fn set_tx_limit(limit: u32) {
    PINS.set_tx_limit(limit);
}

/// The pp task: a frame completed (sent, or failed: either way the buffer is free). In IRAM: this task runs while the flash cache is off, so
/// it may call only IRAM code (`WifiPins::done` and the lock are `#[inline(always)]`).
#[unsafe(link_section = ".iram1.tdongle_tx_done")]
#[inline(never)]
extern "C" fn tx_done(_ifidx: u8, _data: *mut u8, _len: *mut u16, _tx_ok: bool) {
    PINS.done();
}

/// After `esp_wifi_start` (`wifi_pins_start`): register the tx-done callback. Failure leaves TX held to the heap floor with small frames exempt.
pub fn start() {
    // SAFETY: `tx_done` is a valid callback with the signature the driver expects.
    let code = unsafe { sys::esp_wifi_set_tx_done_cb(Some(tx_done)) };
    TX_DONE_OK.store(code == sys::ESP_OK, Ordering::Release);
    if code != sys::ESP_OK {
        log::warn!("tx-done callback not registered ({code:#x}): TX is held to the heap floor with small frames exempt");
    }
}

/// The driver clears its queues when the link drops or comes up, without completing the frames in them (`wifi_pins_link_changed`).
pub fn link_changed() {
    PINS.flush();
}

/// Whether the tx-done callback is registered (`bridge_wifi_tx tx_done_cb`).
pub fn tx_done_registered() -> bool {
    TX_DONE_OK.load(Ordering::Acquire)
}

/// The budget's counters.
pub fn stats() -> WifiPinsStats {
    PINS.stats()
}
