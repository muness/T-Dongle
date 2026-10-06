//! The transparent Wi-Fi bridge's forwarding logic: the port of `components/tdongle_runtime/l2.c` and `include/tdongle_l2.h`, designed in
//! `alternative/tailnet/docs/adr/0023-bridge-mode-data-plane.md` (with its seven amendments) and kept bit-for-bit in behaviour.
//!
//! ```text
//!   Wi-Fi -> host   the Wi-Fi RX callback ([`Bridge::wifi_rx`]) copies the frame into the USB transmit ring and returns. It never waits.
//!   host -> Wi-Fi   the TinyUSB receive callback ([`Producer::host`]) copies the frame into a small fixed queue and returns; one worker
//!                   ([`Worker`]) sends it through the Wi-Fi TX budget. At the queue limit the callback answers HOLD: the USB class driver
//!                   keeps the datagram and NAKs the host (lossless backpressure); when the worker drains to the resume depth it asks for the
//!                   held datagram again. CoDel/ECN at the hand-to-radio keeps the host's own queue short (hold-evidenced busy period).
//! ```
//!
//! Every frame that enters either callback is counted exactly once, as forwarded or as one named drop ([`Stats`]), and the counter identities
//! hold at rest ([`Stats::check_identities`]).
//!
//! Hardware and RTOS facts are behind [`Env`]; this crate is `no_std`, allocation-free, and tested on the host.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
#[macro_use]
extern crate std;

mod bridge;
mod env;
mod queue;
mod stats;
#[cfg(test)]
mod tests;
mod tuning;

pub use bridge::{Bridge, HostOutcome, Producer, Worker};
pub use env::{Env, RingSend, TxError};
pub use stats::{IdentityFailure, Stats};
pub use tuning::{InvalidTuning, Tuning};

/// The largest Ethernet frame the bridge carries (1,500 byte MTU + header; no VLAN tag): anything else is dropped and counted.
pub const FRAME_MAX: usize = 1514;
/// Physical slots of the bulk queue (a power of two: the counters run free); [`Tuning::queue_limit`] may use up to all of them.
pub const HOST_SLOTS: usize = 8;
/// Default standing limit: frames that may stand in the host queue before the host is held (ADR 0023 amendment 2).
pub const HOST_QUEUE_LIMIT: u32 = 3;
/// Default resume depth: drain to this before the held datagram is offered again, so the pipe keeps a frame of runway.
pub const HOST_RESUME_DEPTH: u32 = 1;
/// The size one slot is budgeted at (ADR 0023: 1,524 B each).
pub const SLOT_BYTES: usize = 1524;
/// Default sojourn limit: a safety net for a stalled Wi-Fi link, not the steady-state mechanism (with backpressure it reads 0).
pub const SOJOURN_MS: u32 = 100;
/// Lower bound of [`Tuning::sojourn_ms`].
pub const SOJOURN_MS_MIN: u32 = 5;
/// Upper bound of [`Tuning::sojourn_ms`]: below the forwarding activity hold, asserted below.
pub const SOJOURN_MS_MAX: u32 = 190;
/// Lower bound of [`Tuning::codel_target_us`].
pub const CODEL_TARGET_US_MIN: u32 = 500;
/// Upper bound of [`Tuning::codel_target_us`].
pub const CODEL_TARGET_US_MAX: u32 = 50_000;
/// Lower bound of [`Tuning::codel_interval_ms`].
pub const CODEL_INTERVAL_MS_MIN: u32 = 20;
/// Upper bound of [`Tuning::codel_interval_ms`].
pub const CODEL_INTERVAL_MS_MAX: u32 = 1000;
/// CoDel is on by default (ADR 0023 amendment 6).
pub const CODEL_DEFAULT: bool = true;
/// A refusal for buffers clears as frames leave the antenna, about every 0.3 to 1 ms at the Wi-Fi rate, so the worker retries on a 500 us
/// timer, not on the RTOS tick (at `CONFIG_FREERTOS_HZ=100` a tick sleep is 10 ms, long enough for the whole 16-buffer pool to drain).
pub const RETRY_US: u32 = 500;
/// `TDONGLE_PM_ACTIVITY_HOLD_US`: the forwarding-activity hold of the clock. A frame waiting for Wi-Fi must be inside it.
pub const PM_ACTIVITY_HOLD_US: u32 = 200_000;

const _: () = assert!(SOJOURN_MS >= SOJOURN_MS_MIN && SOJOURN_MS <= SOJOURN_MS_MAX, "the default sojourn limit is inside its bounds");
const _: () = assert!(HOST_RESUME_DEPTH < HOST_QUEUE_LIMIT, "resume below the limit, or the pipe is released at the moment it is refused again");
const _: () = assert!(HOST_QUEUE_LIMIT >= 2 && HOST_QUEUE_LIMIT as usize <= HOST_SLOTS, "the standing-queue limit lives inside the slot array");
const _: () = assert!(
    (SOJOURN_MS_MAX as u64) * 1000 < PM_ACTIVITY_HOLD_US as u64,
    "a frame waiting for Wi-Fi must be inside the forwarding activity hold, or the clock drops under it"
);
const _: () = assert!(RETRY_US >= 100 && (RETRY_US as u64) * 4 <= (SOJOURN_MS_MIN as u64) * 1000, "a retry period is a fraction of the sojourn limit");
