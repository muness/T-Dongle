//! The hardware-free decision of `wifi_pins_tx` (`alternative/tailnet/main/wifi_pins.inc`).
//!
//! `wifi_pins_tx` reads the free heap, asks the budget, calls `esp_wifi_internal_tx` and, if that fails, aborts the charge. Everything but the
//! two driver-facing steps (reading the heap, the driver call) is here, so the host tests exercise it and the firmware only supplies those.

use crate::heap_budget::hb_ok;
use crate::pins::{RawLock, TxVerdict, WifiPins, wtx_cost};

/// A frame no bigger than this is let through when the tx-done callback could not be registered (no counter to hold a band with): ACKs, ARP,
/// DHCP, DNS, keepalives (`WIFI_PINS_SMALL_FRAME`).
pub const WIFI_PINS_SMALL_FRAME: u32 = 256;

/// What [`WifiPins::tx_decision`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDecision {
    /// Refused for buffers: return `ESP_ERR_NO_MEM` (wlanif: `ERR_MEM`; `tcp_output` keeps the segment and retries, the bridge waits). The
    /// refusal is already counted. `by` says which rule refused (in degraded mode always [`TxVerdict::Heap`]).
    Refuse {
        /// The rule that refused.
        by: TxVerdict,
    },
    /// Charged to the budget: call the driver, and if it fails call [`WifiPins::abort`] (no driver buffer exists, so no tx-done will come).
    SendCharged {
        /// Band or elastic.
        by: TxVerdict,
    },
    /// Degraded mode (the tx-done callback is not registered) and the frame passed: call the driver; nothing is counted, nothing can leak.
    SendUncounted,
}

/// How [`WifiPins::tx`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError<E> {
    /// Refused for buffers (`ESP_ERR_NO_MEM`).
    NoMem,
    /// The driver call failed with `E`; the charge, if any, was aborted.
    Driver(E),
}

impl<L: RawLock, const POOL: usize> WifiPins<L, POOL> {
    /// The decision of `wifi_pins_tx` for a frame of `len` bytes, given the free internal heap and whether the tx-done callback is registered
    /// (`wifi_pins_tx_done_ok`).
    ///
    /// With the callback: admit through the budget; a refusal is counted by [`admit`](Self::admit). Without it (degraded): the heap floor
    /// alone, frames up to [`WIFI_PINS_SMALL_FRAME`] bytes exempt, and a refusal is counted in `tx_refused_heap`; nothing is charged.
    pub fn tx_decision(&self, tx_done_ok: bool, len: u32, free_internal: usize, now_ms: u32) -> TxDecision {
        if tx_done_ok {
            let by = self.admit(len, free_internal, now_ms);
            return if by.admitted() { TxDecision::SendCharged { by } } else { TxDecision::Refuse { by } };
        }
        if len > WIFI_PINS_SMALL_FRAME && !hb_ok(free_internal, wtx_cost(len)) {
            self.note_refused_heap();
            return TxDecision::Refuse { by: TxVerdict::Heap };
        }
        TxDecision::SendUncounted
    }

    /// The whole of `wifi_pins_tx`: decide, call `send` (the driver's `esp_wifi_internal_tx`) when the frame may go, and abort the charge when
    /// the driver refuses it.
    ///
    /// # Errors
    ///
    /// [`TxError::NoMem`] when refused for buffers, [`TxError::Driver`] with the driver's error.
    pub fn tx<E>(&self, tx_done_ok: bool, len: u32, free_internal: usize, now_ms: u32, send: impl FnOnce() -> Result<(), E>) -> Result<(), TxError<E>> {
        match self.tx_decision(tx_done_ok, len, free_internal, now_ms) {
            TxDecision::Refuse { .. } => Err(TxError::NoMem),
            TxDecision::SendUncounted => send().map_err(TxError::Driver),
            TxDecision::SendCharged { .. } => match send() {
                Ok(()) => Ok(()),
                Err(e) => {
                    self.abort(); // no driver buffer exists, so no tx-done will come
                    Err(TxError::Driver(e))
                }
            },
        }
    }
}
