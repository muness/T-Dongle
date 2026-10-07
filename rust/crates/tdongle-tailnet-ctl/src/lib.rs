//! The control client driver.
//!
//! [`run_session`] is the C's whole control path (`ml_coord.c` `do_tcp_connect` .. `poll_map_update`, `gateway_handshake.inc`) as one async function over
//! an abstract byte stream:
//!
//! ```text
//! gate.begin_negotiation
//!   -> [GET /key on its own connection]      (when `control_pub` is None; the connection is closed before the next one opens)
//!   -> connect -> POST /ts2021 + base64(Noise msg1) -> 101 -> Noise msg2
//!   -> H2 preface -> early payload (node-key challenge) -> POST /machine/register (stream 1)
//!   -> POST /machine/map streaming (stream 5) -> gate.end_negotiation(true) after the first map is applied
//!   -> forever: map messages to the projector and the sink, PING every 5 s, lite endpoint updates (streams 7, 9, ...) when the caller has new endpoints
//! ```
//!
//! Every failure is a typed [`SessionEnd`] with the C's `noise_error` / `map_error` numbers; the negotiation gate is released with `false` on any failure
//! before the first map was applied.
//!
//! # Memory
//! The big buffers are a [`Bulk`]: the record reader (4 KiB), the sealed-record buffer (4 KiB), a request/response JSON buffer (the early payload passes
//! through its start) and the map projector. [`run_session_leased`] **leases** it from a [`BulkLease`] instead of owning it: it takes it after the TCP connect
//! (or for the `/key` fetch), keeps it while the session negotiates (the negotiation token is held for the same time), and once the first map is applied
//! keeps it only from the first byte of a record until the map message that record belongs to is applied; whenever the session waits for the server with no
//! record or message in progress it gives it back. A quiet long poll therefore holds nothing, and one `Bulk` serves every membership of a gateway. What a
//! membership keeps for its whole session is a [`SessionBuf`] (the TCP input buffer and the counters, about 1.1 KiB). A server that stalls while the lease is
//! held ends only its own session ([`SessionEnd::LeaseStall`], after [`Timeouts::lease_stall_ms`]); a write is bounded by the same figure.
//! [`run_session`] is the one-owner form (a [`Workspace`] = one `SessionBuf` + one `Bulk`) for tests and tools. The future of the session itself holds the
//! Noise session, the HTTP/2 session and a few counters (see [`sizes`]).
//!
//! # Cancellation
//! Dropping the future abandons the connection (the stream is dropped with it) but does not call the gate: the owner of the future releases its token.
//! Reads must be cancel safe (a timeout drops a pending read), which holds for tokio sockets and embassy-net.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// `SessionEnd` carries the AuthURL (384 bytes) by value: it is returned once per session and there is no allocator to box it with.
#![allow(clippy::result_large_err, clippy::large_enum_variant)]

mod driver;
mod end;
mod traits;

pub use driver::{Bulk, BulkLease, SessionBuf, SessionConfig, TX_BYTES, Timeouts, Workspace, fetch_control_key, run_session, run_session_leased};
pub use end::{IoFail, MapEnd, RegisterFailure, SessionEnd, SessionStats, Stage};
pub use traits::{Clock, Connect, EndpointSource, Gate, NoEndpoints, NoGate};

/// Sizes of the driver's memory on this target.
pub mod sizes {
    /// One session's buffers all in one owner ([`crate::Workspace`]).
    pub const WORKSPACE: usize = core::mem::size_of::<crate::Workspace>();
    /// The leased big buffers ([`crate::Bulk`]): one per gateway.
    pub const BULK: usize = core::mem::size_of::<crate::Bulk>();
    /// What a session keeps for its life ([`crate::SessionBuf`]): one per membership.
    pub const SESSION_BUF: usize = core::mem::size_of::<crate::SessionBuf>();
    /// The statistics block.
    pub const STATS: usize = core::mem::size_of::<crate::SessionStats>();
    /// The Noise transport session kept by a running session.
    pub const NOISE_SESSION: usize = tdongle_tailnet_noise::SESSION_BYTES;
    /// The HTTP/2 session kept by a running session.
    pub const H2_SESSION: usize = tdongle_tailnet_control::sizes::H2_SESSION;
    /// The map projector inside the workspace.
    pub const PROJECTOR: usize = tdongle_tailnet_map::PROJECTOR_STATE_BYTES;
}

#[cfg(test)]
extern crate std;
