//! Admission, heap budget, the negotiation token and the inbound-path budgets of the tailnet gateway.
//!
//! Everything here is pure: no clocks (time is a [`Millis`] argument), no allocator, no sockets, no
//! locks. The firmware wraps these types in whatever synchronisation it needs (an embassy `Mutex`, a
//! critical section) and supplies the measurements ([`HeapProbe`]).
//!
//! The C firmware is the specification. Each module names the C header it ports, keeps its
//! constants under the C names (in `SCREAMING_CASE`, so a grep for `ML_HB_FLOOR` finds both), and
//! reproduces the C's compile-time inequalities (`_Static_assert`) as `const` assertions so that a
//! change to one number that breaks another is a build error here too.
//!
//! * [`adm`]: what one more membership costs (`ml_admission.h`), with the C's arithmetic as
//!   [`adm::Params::c_reference`] and the Rust task model as [`adm::Params::rust`].
//! * [`heap`]: the one elastic heap floor (`ml_heap_budget.h`, ADR 0022) and the router queue bound.
//! * [`negotiation`]: the global negotiation token (`ml_negotiation.h`), sans-IO and pollable;
//!   [`coord_state`]: the control task's rule for holding it (`ml_coord_state.h`).
//! * [`wg_rx`]: the byte budget of datagrams waiting for the WireGuard task (`ml_wg_rx_budget.h`) and
//!   the run planner of `ml_wg_rx_batch.h`; [`net_io`]: the socket drain (`ml_net_io_drain.h`);
//!   [`rx_stats`]: the inbound counters (`ml_rx_stats.h`).
//! * [`usb_rx`], [`sockets`], [`tcp_window`]: `usb_rx_budget.h`, `socket_budget.{c,h}`,
//!   `tcp_window_budget.h`.
//! * [`ledger`]: the per-owner heap ledger (ADR 0001 rule 7) and [`probe::HeapProbe`].
//! * [`json`] and [`status`]: byte-identical `/status` and serial fragments.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod adm;
pub mod coord_state;
pub mod heap;
pub mod json;
pub mod ledger;
pub mod limits;
pub mod negotiation;
pub mod net_io;
pub mod probe;
pub mod rx_stats;
pub mod sockets;
pub mod status;
pub mod tcp_window;
pub mod usb_rx;
pub mod wg_rx;

pub use probe::HeapProbe;
pub use tdongle_tailnet_types::Millis;

// Layout guard, checked by `cargo +esp check --target xtensa-esp32s3-none-elf`: the 32-bit sizes of the state types (the counters and budgets have no
// pointer-sized fields, so they equal the host's; the negotiation token is 8 bytes smaller there, where a u64 aligns to 4).
#[cfg(target_arch = "xtensa")]
const _: () = {
    assert!(core::mem::size_of::<negotiation::Negotiation>() == 264);
    assert!(core::mem::size_of::<ledger::Ledger>() == 172);
    assert!(core::mem::size_of::<rx_stats::RxStats>() == 96);
    assert!(core::mem::size_of::<usb_rx::Budget>() == 24);
    assert!(core::mem::size_of::<wg_rx::Budget>() == 8);
};
