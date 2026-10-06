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
//! Everything big lives in one [`Workspace`] the caller allocates (a `static`, `StaticCell` or `Box`): the record reader (4 KiB), the sealed-record
//! buffer (4 KiB), a request/response JSON buffer, the TCP input buffer and the map projector. **It is shared across memberships**: the negotiation
//! token serialises its users (ADR 0013), so two sessions never run `run_session` on the same workspace at the same time, and nothing in it survives
//! from one session to the next except the statistics. The future of `run_session` itself holds the Noise session, the HTTP/2 session and a few
//! counters (see [`sizes`]).
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

pub use driver::{SessionConfig, Timeouts, Workspace, fetch_control_key, run_session};
pub use end::{IoFail, MapEnd, RegisterFailure, SessionEnd, SessionStats, Stage};
pub use traits::{Clock, Connect, EndpointSource, Gate, NoEndpoints, NoGate};

/// Sizes of the driver's memory on this target.
pub mod sizes {
    /// The shared [`crate::Workspace`].
    pub const WORKSPACE: usize = core::mem::size_of::<crate::Workspace>();
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
