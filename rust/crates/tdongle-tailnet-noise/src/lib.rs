//! The Tailscale ts2021 control-plane transport: `Noise_IK_25519_ChaChaPoly_BLAKE2s` plus record framing, sans-IO and allocation free.
//!
//! The specification is Tailscale's `control/controlbase` (checked against v1.104.0) and the C `ml_noise.c` / `noise_send_owned` / `noise_recv_inplace`.
//!
//! Wire format
//! * msg1 (client to server, 101 bytes): `version(2 BE) | type 1 | len(2 BE) = 96 | e(32) | enc(s)(48) | tag(16)`.
//! * msg2 (server to client, 51 bytes): `type 2 | len(2 BE) = 48 | e(32) | tag(16)`. Type 3 is an unauthenticated error message.
//! * records: `type 4 | len(2 BE) | ciphertext+tag`, at most 4096 bytes on the wire (so 4077 plaintext bytes), a separate cipher state per direction, nonce = 4
//!   zero bytes then the **big-endian** 64-bit counter (Noise's own text says little-endian; Tailscale uses big-endian, [`session`] documents the consequence
//!   for the `snow` differential tests), empty associated data, `u64::MAX` is never used.
//! * the prologue is `"Tailscale Control Protocol v"` followed by the decimal version.
//!
//! Layers
//! * [`Initiator`] / [`responder`]: the handshake. The responder exists for tests and the host interop server; the device only initiates.
//! * [`Session`]: sealing and opening records **in place** (`HEADROOM` bytes before the plaintext, `TAILROOM` after it), counters for every refusal.
//! * [`RecordReader`]: feeds arbitrary TCP chunks, yields one decrypted record at a time out of its single 4096-byte buffer.
//! * [`early`]: the optional `\xff\xff\xffTS` early payload the server may send before the HTTP/2 preface (capped at 1024 bytes as in the C).
//!
//! Rekeying is not implemented (the protocol has none). Handshake temporaries on the stack are not all zeroized; keys held in state structs are.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod early;
mod handshake;
mod reader;
pub mod responder;
mod session;
mod symmetric;

pub use handshake::{HandshakeError, INITIATION_LEN, Initiator, RESPONSE_LEN, ResponseHeader};
pub use reader::{Feed, RecordReader};
pub use session::{HEADER_LEN, HEADROOM, MAX_CIPHERTEXT, MAX_PLAINTEXT, MAX_RECORD, OpenError, Role, SealError, Session, Stats, TAILROOM, wire_len};

/// `size_of` of the handshake state (host build: 64-bit pointers do not matter, there are none).
pub const INITIATOR_BYTES: usize = core::mem::size_of::<Initiator>();
/// `size_of` of a [`Session`].
pub const SESSION_BYTES: usize = core::mem::size_of::<Session>();
/// `size_of` of a [`RecordReader`] (dominated by its 4096-byte record buffer).
pub const READER_BYTES: usize = core::mem::size_of::<RecordReader>();
/// `size_of` of an [`early::EarlyReader`].
pub const EARLY_BYTES: usize = core::mem::size_of::<early::EarlyReader>();
