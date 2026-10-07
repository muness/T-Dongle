//! Active queue management for the transparent bridge's host to Wi-Fi ingress (ADR 0023, amendment 4): CoDel (RFC 8289) decides, ECN marking
//! (RFC 3168) or dropping acts.
//!
//! Port of `components/tdongle_runtime/include/tdongle_aqm.h`, which stays the specification: every constant, branch and wrapping-arithmetic
//! detail matches the C byte for byte. The crate is `no_std`, has no dependencies and no `unsafe`; every frame access is bounds-checked.
//!
//! Why it exists at all: with lossless USB backpressure the dongle's own queue is a few milliseconds, but the host's transmit queue sits behind
//! our NAKs and is FIFO, so the host's TCP grows its window until that queue is full. The only lever the dongle has is a congestion signal at
//! the point where it applies backpressure: mark (ECN) or drop the packets that cross it once the pipe has been saturated for longer than a
//! target, which is what CoDel is for. [`codel`] decides; [`ecn`] classifies frames and marks them.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod codel;
pub mod ecn;

pub use codel::{Codel, INTERVAL_MS_DEFAULT, TARGET_US_DEFAULT, control_law, diff, isqrt, isqrt64};
pub use ecn::{EcnClass, TcpEcnSyn, classify, ip6_l4, mark_ce, tcp_ecn_syn};
