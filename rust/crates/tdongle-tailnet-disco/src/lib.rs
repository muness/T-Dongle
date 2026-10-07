//! DISCO and STUN for the tailnet gateway: sans-IO, allocation free, in place on the caller's buffers.
//!
//! What the C spreads over `ml_stun.c`, `ml_netcheck.c`, `nacl_box.c` and the DISCO half of `ml_wg_mgr.c`, with Tailscale's `disco`, `net/stun` and
//! `wgengine/magicsock` as the authority on the wire and on timing.
//!
//! * [`msg`]: the three messages (ping, pong, call-me-maybe) as Go lays them out; parsing borrows the packet, encoding writes into a caller buffer.
//! * [`envelope`]: `TS💬 | sender key | nonce | NaCl box`; seal and open in place; [`envelope::process`] is the whole receive pipeline and every way it can
//!   end is a counted [`envelope::RxOutcome`].
//! * [`stun`]: binding request builder, response parser (`XOR-MAPPED-ADDRESS`, alternate, legacy), request parser, CRC-32 fingerprint.
//! * [`path`]: per-peer path state (candidate endpoints, outstanding pings, best path, trust, fallback to DERP, rate limits) as a machine that returns
//!   [`path::Action`]s; time and entropy are arguments.
//! * [`stun_sched`] and [`netcheck`]: the membership's STUN schedule (NAT mapping, symmetric-NAT check, 23 s refresh) and the DERP region latency probe.
//! * [`policy`]: the admission gate for activations on unauthenticated claims and the eviction choice of `ml_peer_policy.h`.
//!
//! No clock, socket or entropy source is read here; nothing allocates; every refusal is a variant and every drop is counted (ADR 0001 rule 2). The state
//! structs expose `STATE_BYTES` for the memory ledger; none of them holds a packet.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod addr;
pub mod envelope;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;
pub mod msg;
pub mod netcheck;
pub mod path;
pub mod policy;
pub mod stun;
pub mod stun_sched;

pub use addr::Ep;

#[cfg(test)]
extern crate std;

// State sizes measured on the host and on xtensa (identical: no field needs more than 4-byte alignment). A growth past these fails the build of
// every target, so the memory ledger and this crate cannot drift apart unnoticed.
const _: () = {
    assert!(core::mem::size_of::<path::PathState<8>>() <= 248);
    assert!(core::mem::size_of::<path::PathState<4>>() <= 176);
    assert!(path::ProbeTable::<16>::STATE_BYTES <= 320);
    assert!(core::mem::size_of::<path::PathCounters>() <= 128);
    assert!(stun_sched::StunScheduler::STATE_BYTES <= 304);
    assert!(netcheck::Netcheck::<8>::STATE_BYTES <= 464);
    assert!(core::mem::size_of::<policy::TrialGate>() <= 48);
    assert!(core::mem::size_of::<addr::Ep>() == 18);
};
