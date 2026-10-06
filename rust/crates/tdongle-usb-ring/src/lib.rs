//! The Wi-Fi to host USB transmit ring of the T-Dongle firmware, as a pure `no_std`, allocation-free crate.
//!
//! Port of the "Non-blocking, elastic transmit ring" section of `components/esp_tinyusb/tinyusb_net.c` (with the constants and the statistics
//! struct of `components/esp_tinyusb/include/tinyusb_net.h`), which stays the specification. Everything that is hardware or operating
//! system in the C (the critical section, clocks, TinyUSB, the heap, task notification, the PM hold) is injected through [`RingEnv`], so
//! the whole ring, including its concurrency, runs on the host with std threads in the tests.
//!
//! The pieces: [`Ring`] is the object; [`Config`] the configuration; [`TxStats`] the counters (`tinyusb_net_tx_stats_t`); [`consts`] the
//! geometry with its compile-time assertions. `unsafe` is confined to the private `ring` module (calls into the private `mem` module, the only raw-memory accessors), each
//! block with a `SAFETY:` comment.
//!
//! The firmware's wiring, in terms of the C entry points:
//!
//! | C                                         | Rust                                              |
//! |-------------------------------------------|---------------------------------------------------|
//! | `tinyusb_net_tx_ring_start`               | [`Ring::new`], [`Ring::restart`]                  |
//! | `tx_worker` task                          | `loop { notify_take(wait); wait = ring.worker_step(); }` |
//! | `tinyusb_net_tx_ring_send`                | [`Ring::send`]                                    |
//! | `do_drain` (deferred into TinyUSB)        | [`Ring::do_drain`]                                |
//! | `__wrap_netd_xfer_cb`, IN endpoint        | [`Ring::on_in_complete`]                          |
//! | `tinyusb_net_tx_ring_link_down` / `_flush`| [`Ring::link_down`] / [`Ring::flush`]             |
//! | `tinyusb_net_tx_elastic_reclaim` / `_kick`| [`Ring::elastic_reclaim`] / [`Ring::elastic_kick`]|
//! | `tinyusb_net_tx_ring_set_max_chunks`      | [`Ring::set_max_chunks`] / [`Ring::max_chunks`]   |
//! | `tinyusb_net_tx_ring_stats`               | [`Ring::stats`]                                   |
//! | ring part of `tinyusb_net_deinit`         | [`Ring::deinit`]                                  |

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

mod config;
pub mod consts;
mod env;
mod mem;
mod ring;

#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
mod tests;

pub use config::{Config, ConfigError, RestartError, SendError, SetMaxChunksError, TxStats, Wait};
pub use consts::*;
pub use env::RingEnv;
pub use ring::Ring;
