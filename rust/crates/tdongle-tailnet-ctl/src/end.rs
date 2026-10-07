//! How a session ended, and what it counted.

use embedded_io_async::ErrorKind;
use tdongle_tailnet_control::early::EarlyError;
use tdongle_tailnet_control::h2::{Counters as H2Counters, H2Error};
use tdongle_tailnet_control::http::{KeyError, UpgradeError};
use tdongle_tailnet_control::requests::{AUTH_URL_BYTES, ERROR_TEXT_BYTES, RegisterError};
use tdongle_tailnet_map::MapError;
use tdongle_tailnet_noise::{HandshakeError, OpenError, Stats as NoiseStats};
use tdongle_tailnet_types::FixedStr;

/// Where in the flow something happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// `GET /key`.
    KeyFetch,
    /// Opening the control connection.
    Connect,
    /// The HTTP upgrade request and its `101`.
    Upgrade,
    /// Noise message 2.
    Handshake,
    /// Early payload.
    Early,
    /// Register request and response.
    Register,
    /// The map stream.
    Map,
}

/// A failed transport operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoFail {
    /// The peer closed the connection.
    Eof,
    /// No progress within the stage's time budget.
    Timeout,
    /// The stream reported an error.
    Error(ErrorKind),
}

/// Why registration did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterFailure {
    /// Interactive login required: visit the URL, then run again with it as `followup`.
    AuthUrl(FixedStr<AUTH_URL_BYTES>),
    /// The control plane refused (`RegisterResponse.Error`).
    Refused(FixedStr<ERROR_TEXT_BYTES>),
    /// `NodeKeyExpired`: the node key must be replaced.
    NodeKeyExpired,
    /// The response was not a readable document.
    Malformed(RegisterError),
    /// The response is larger than the workspace's buffer.
    Overflow,
    /// The response's `:status` was not 200.
    HttpStatus(u16),
}

/// Why the map stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapEnd {
    /// The projector rejected a message (`map_error` 6, 8 or 9 in the C).
    Projector(MapError),
    /// A map message had length 0 or above 1 MiB (C 7).
    BadLength(u32),
    /// END_STREAM arrived: between messages (`clean`) or in the middle of one (C 12).
    StreamEnded {
        /// It ended on a message boundary.
        clean: bool,
    },
    /// The first map did not arrive within the initial deadline (C 12).
    Deadline,
}

/// How a session ended. Every variant is final: the caller backs off and runs again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// A connection could not be opened.
    Connect(Stage),
    /// A transport failure.
    Io {
        /// Where.
        stage: Stage,
        /// What.
        fail: IoFail,
    },
    /// The `/key` answer was refused.
    KeyFetch(KeyError),
    /// The upgrade answer was not `101`, or too long.
    Upgrade(UpgradeError),
    /// The Noise handshake failed. `AuthFailed` is what a wrong control key looks like.
    Handshake(HandshakeError),
    /// A Noise record failed to open (a tag failed, framing was lost).
    Record(OpenError),
    /// The early payload was refused.
    Early(EarlyError),
    /// An HTTP/2 connection error.
    H2(H2Error),
    /// The server sent GOAWAY.
    GoAway {
        /// HTTP/2 error code.
        code: u32,
        /// Sanitised debug text.
        debug: FixedStr<48>,
        /// Last stream the server processed.
        last_stream: u32,
    },
    /// The server reset a stream we were reading.
    Reset {
        /// Stream.
        stream: u32,
        /// HTTP/2 error code.
        code: u32,
    },
    /// Registration did not complete.
    Register(RegisterFailure),
    /// The map stream failed or ended.
    Map(MapEnd),
    /// A request would not fit one Noise record.
    RequestTooLarge,
    /// Nothing was heard for the idle timeout.
    Idle,
    /// The server went quiet in the middle of a record or message while the session held the leased buffers ([`crate::Timeouts::lease_stall_ms`]).
    LeaseStall,
}

impl SessionEnd {
    /// The C's `ml->noise_error`: 3 record exceeds capacity, 5 payload read failed, 6 authentication failed; 0 if not a Noise-level failure.
    pub fn noise_error(&self) -> u32 {
        match self {
            SessionEnd::Handshake(_) => 6,
            SessionEnd::Record(OpenError::AuthFailed) => 6,
            SessionEnd::Record(_) => 3,
            SessionEnd::Io { fail: IoFail::Eof, stage: Stage::Handshake | Stage::Early | Stage::Register | Stage::Map } => 5,
            _ => 0,
        }
    }

    /// The C's `ml->map_error`: 2 receive failed / closed, 3 no data, 4 padding, 6 capacity, 7 length, 8 malformed, 9 commit, 10 GOAWAY/RST, 12 deadline or
    /// mid-message end; 0 if the failure was before the map stream.
    pub fn map_error(&self) -> u32 {
        match self {
            SessionEnd::Map(MapEnd::Projector(e)) => e.code(),
            SessionEnd::Map(MapEnd::BadLength(_)) => 7,
            SessionEnd::Map(MapEnd::StreamEnded { clean: false }) | SessionEnd::Map(MapEnd::Deadline) => 12,
            SessionEnd::Map(MapEnd::StreamEnded { clean: true }) => 3,
            SessionEnd::GoAway { .. } | SessionEnd::Reset { .. } => 10,
            SessionEnd::H2(H2Error::BadPadding) => 4,
            SessionEnd::H2(_) => 3,
            SessionEnd::Io { stage: Stage::Map, .. } | SessionEnd::Idle | SessionEnd::LeaseStall | SessionEnd::Record(_) => 2,
            _ => 0,
        }
    }
}

/// What a session did, readable from the workspace after `run_session` returns (also after a failure).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Map messages applied (committed).
    pub maps: u32,
    /// Of those, keepalives.
    pub keepalives: u32,
    /// `Peer` events delivered to the sink.
    pub peer_events: u32,
    /// Map payload bytes.
    pub map_bytes: u64,
    /// The first map was applied.
    pub first_map_applied: bool,
    /// Bytes of the register response body.
    pub register_bytes: u32,
    /// `MachineAuthorized` from the register response.
    pub machine_authorized: bool,
    /// The server sent a node-key challenge.
    pub challenge_seen: bool,
    /// Lite endpoint updates sent.
    pub endpoint_updates: u32,
    /// Endpoint updates skipped because nothing changed.
    pub endpoint_updates_unchanged: u32,
    /// PINGs sent.
    pub pings_sent: u32,
    /// PING ACKs received.
    pub ping_acks: u32,
    /// Bytes read from / written to the control connection (ciphertext).
    pub bytes_in: u64,
    /// Bytes written.
    pub bytes_out: u64,
    /// Noise record counters.
    pub noise: NoiseStats,
    /// HTTP/2 counters.
    pub h2: H2Counters,
}
