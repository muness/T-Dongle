//! WireGuard for the tailnet gateway: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, sans-IO and allocation free, over [`tdongle_tailnet_crypto`].
//!
//! The C firmware's equivalents: `wireguard.c` (handshake, sessions), `wireguardif.c` (timers and the packet path, minus the lwIP glue),
//! `wireguard_replay.h`, `wireguard_stats.h`. Protocol authority: the WireGuard whitepaper and wireguard-go, against which the tests in `tests/` are
//! cross-checked (`tests/fixtures/wireguard_go_*.txt` are transcripts produced by a real wireguard-go `device`).
//!
//! # Layout
//!
//! | piece | what | state |
//! |---|---|---|
//! | [`Identity`] | our static key pair, mac1 and cookie keys | one per membership, read only |
//! | [`PeerCold`] | a peer's public key, preshared key, precomputed static DH ([`PeerCold::BYTES`]) | one per configured peer |
//! | [`PeerHot`] | handshake, three [`Session`] slots, timers, cookie ([`PeerHot::BYTES`]) | one per *resident* peer: a pool serves many memberships |
//! | [`CookieChecker`] | the responder's cookie secret | one per membership |
//! | [`Session`], [`TxTicket`], [`RxTicket`] | keys, counters and [`ReplayWindow`] of one session; the lock-free packet path | inside `PeerHot`, or alone |
//!
//! # The packet path without a shared lock (ADR 0013 / 0018 of the C tree)
//!
//! ```text
//! send:    PeerHot::tx_prepare   (lock: counter + key copy)  ->  TxTicket::seal   (no lock: pad, header, ChaCha20-Poly1305 in place)
//! receive: PeerHot::rx_begin     (lock: lookup, expiry, replay peek, key copy)
//!          RxTicket::open        (no lock: authenticate and decrypt in place)
//!          PeerHot::rx_commit    (lock: record the counter, timers, promote a responder session)
//! ```
//!
//! # Handshake
//!
//! Receive side: [`cookie::screen`] (framing, mac1, mac2/cookie reply under load) ->
//! initiation: [`Identity::consume_initiation_stage1`] (names the peer) -> [`PeerHot::consume_initiation`] -> [`PeerHot::create_response`];
//! response: [`PeerHot::consume_response`]; cookie reply: [`PeerHot::consume_cookie_reply`].
//! Send side: [`PeerHot::create_initiation`] (or `initiation_begin` / [`InitiationJob::compute`] / `initiation_commit` to run the two X25519 outside a lock).
//! Time-driven work: [`PeerHot::poll`] and [`PeerHot::next_wake`].
//!
//! Receiver indices come from the caller ([`IndexAllocator`]), time is [`tdongle_tailnet_types::Millis`], entropy
//! [`tdongle_tailnet_types::Entropy`], the TAI64N source a [`WallClock`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod consts;
pub mod cookie;
pub mod error;
pub mod ident;
pub mod index;
pub mod msg;
pub mod peer;
pub mod replay;
pub mod session;

pub use cookie::{CookieChecker, Screen};
pub use error::{DropCounters, Dropped, InitError, SealError, TxError};
pub use ident::{Identity, PeerCold, WallClock};
pub use index::IndexAllocator;
pub use peer::{Actions, HsState, InitiationJob, InitiationStage1, PeerHot, RxOutcome, TxKind};
pub use replay::{ReplayRing, ReplayVerdict, ReplayWindow};
pub use session::{RxTicket, Session, TxTicket};

#[cfg(test)]
extern crate std;
