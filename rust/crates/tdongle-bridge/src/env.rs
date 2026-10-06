//! What the bridge needs from the world around it. Everything hardware- or RTOS-shaped is behind this trait, so the forwarding logic runs on
//! the host against a scripted world (`tests/`) and on the board against the real USB ring, Wi-Fi driver and clock (`firmware/src/bridge.rs`).
//!
//! The C original (`components/tdongle_runtime/l2.c`) reached these through link-time stubs; the rule the C tests enforce is kept: **none of
//! the methods called from the two receive callbacks may block, allocate or call into the Wi-Fi driver** (`wifi_tx` is called by the worker
//! only). A firmware implementation is audited against that list, a test implementation asserts it.

use tdongle_spsc::TaskContext;

/// The outcome of handing one frame to the Wi-Fi driver (`esp_wifi_internal_tx` behind the TX budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    /// Refused for buffers (the budget's, or the driver's pool): clears as frames leave the antenna, so the worker retries.
    NoMem,
    /// Any other driver error code (`esp_err_t`): final, never retried.
    Other(i32),
}

impl TxError {
    /// `ESP_ERR_NO_MEM`, the value the C stats report in `last_tx_error`.
    pub const ESP_ERR_NO_MEM: i32 = 0x101;

    /// The `esp_err_t` this error corresponds to (what `bridge_to_wifi last_tx_error` prints).
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::NoMem => Self::ESP_ERR_NO_MEM,
            Self::Other(code) => code,
        }
    }
}

/// What the USB transmit ring said about a frame (`tinyusb_net_tx_ring_send`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingSend {
    /// Accepted: it will be handed to USB exactly once or flushed on a link change.
    Accepted,
    /// No slab free, at the elastic cap: backpressure drop (`ESP_ERR_NO_MEM`).
    Full,
    /// USB not configured (cable out, host asleep) or the ring not started (`ESP_ERR_INVALID_STATE`).
    NotReady,
    /// The ring refused the frame itself (length outside its limits, `ESP_ERR_INVALID_ARG`).
    Invalid,
}

/// The bridge's neighbours. All methods take `&self`: implementations use interior mutability (atomics, critical sections) because the
/// receive callbacks, the worker and the event task call in from different tasks.
pub trait Env {
    /// The low 32 bits of the microsecond clock (`esp_timer_get_time`). Every use is wrapping arithmetic; the clock wraps every 71 minutes.
    fn now_us(&self) -> u32;

    // ---- Wi-Fi -> host (Wi-Fi task) -------------------------------------------------------------------------------------------------
    /// Copy one frame into the USB transmit ring. Never blocks.
    fn usb_ring_send(&self, frame: &[u8]) -> RingSend;
    /// Discard what the ring holds from the previous association (bumps the ring's link generation). Never blocks.
    fn usb_ring_flush(&self);
    /// Tell the host the carrier changed (`tud_network_link_state`).
    fn usb_link_state(&self, up: bool);
    /// Register (`true`) or unregister (`false`) the Wi-Fi RX callback for the STA interface (`esp_wifi_internal_reg_rxcb`).
    fn wifi_rx_register(&self, on: bool);

    // ---- host -> Wi-Fi ---------------------------------------------------------------------------------------------------------------
    /// Wake the worker (`xTaskNotifyGive`). Never blocks; called from the TinyUSB task.
    fn notify_worker(&self);
    /// Send one frame on the STA interface through the Wi-Fi TX budget. **Worker only.**
    ///
    /// # Errors
    /// [`TxError::NoMem`] when refused for buffers (retried until the frame's sojourn limit), anything else is final.
    fn wifi_tx(&self, frame: &[u8], context: &TaskContext) -> Result<(), TxError>;
    /// True when the radio can take another frame now (`wifi_pins_tx_room`). While it is false the worker waits instead of calling
    /// [`wifi_tx`](Self::wifi_tx) and being refused. Return `true` always when there is no allowance to respect.
    fn wifi_room(&self) -> bool;
    /// Wait for the next chance: arm a [`RETRY_US`](crate::RETRY_US) timer and sleep until it fires or the worker is notified (a new frame:
    /// the loop re-attempts at once, harmlessly), but for at most `SOJOURN_MS_MAX + 1` ms. **Worker only.**
    fn wait_retry(&self, context: &TaskContext);
    /// Ask the USB class driver to offer the held datagram again (`tinyusb_net_rx_resume`). **Worker only.**
    fn rx_resume(&self, context: &TaskContext);

    // ---- power management ------------------------------------------------------------------------------------------------------------
    /// Raise the CPU clock for forwarding work (`tdongle_pm_note_activity`): one atomic load while the hold is active.
    fn note_activity(&self);

    /// Bytes of the worker's stack never used (`uxTaskGetStackHighWaterMark`), for the `bridge_link` status line.
    fn worker_stack_free(&self) -> u32 {
        0
    }
}
