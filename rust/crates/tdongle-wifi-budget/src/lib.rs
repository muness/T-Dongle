//! The Wi-Fi driver buffer budget of the T-Dongle firmware: pinned buffers counted at run time and held to the one heap floor (ADR 0022
//! amendment 2, ADR 0023), as a pure `no_std`, allocation-free, `unsafe`-free crate.
//!
//! Port of `alternative/tailnet/main/wifi_pin_budget.h` (the TX and RX halves), the heap-budget constants and checks of
//! `alternative/tailnet/components/microlink/include/ml_heap_budget.h` it needs, and the hardware-free decision of `wifi_pins_tx` in
//! `alternative/tailnet/main/wifi_pins.inc`. The C stays the specification; the long comment of `wifi_pin_budget.h` is the argument for the
//! rules and is carried into the documentation of [`WifiPins`].
//!
//! * [`heap_budget`]: `ML_HB_*` constants, [`hb_ok`], [`hb_rx_ok`].
//! * [`pins`]: [`WifiPins`], the joint TX/RX counter with the TX charge FIFO and the lease.
//! * [`tx`]: [`TxDecision`] and `WifiPins::tx_decision`/`WifiPins::tx`, the pure part of `wifi_pins_tx`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod heap_budget;
pub mod pins;
pub mod tx;

#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
mod tests;

pub use heap_budget::{
    ML_ADM_NEG_PEAK_BYTES, ML_ADM_RECOVERY_BYTES, ML_HB_FLOOR, ML_HB_PIN_BUF_BYTES, ML_HB_PIN_BUFFERS, ML_HB_PIN_BYTES, ML_HB_RESERVE,
    ML_HB_RX_SMALL_BYTES, ML_HB_SLACK_BYTES, hb_ok, hb_rx_ok,
};
pub use pins::{
    GATEWAY_WIFI_BAND_TOTAL, GATEWAY_WIFI_PIN_BAND_BYTES, GATEWAY_WIFI_RX_BAND_MAX, GATEWAY_WIFI_TX_BAND_MAX, GATEWAY_WIFI_TX_POOL, GW_WTX_LEASE_MS,
    GW_WTX_OVERHEAD, GW_WTX_RING, RawLock, TxVerdict, WifiPins, WifiPinsStats, wtx_cost,
};
pub use tx::{TxDecision, TxError, WIFI_PINS_SMALL_FRAME};
