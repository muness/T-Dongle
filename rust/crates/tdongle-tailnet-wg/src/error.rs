//! Outcomes. Every inbound datagram that does not become a delivered packet or a state change ends in exactly one [`Dropped`]; the runtime counts them with
//! [`DropCounters`] (ADR 0001 rule 2: no silent drops).

use crate::msg::ParseError;
use tdongle_tailnet_types::Counter;

macro_rules! drops {
    ($( $(#[$m:meta])* $name:ident => $s:literal, )*) => {
        /// Why an inbound datagram was refused.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum Dropped { $( $(#[$m])* $name, )* }
        impl Dropped {
            /// Every variant, in counter order.
            pub const ALL: [Dropped; Dropped::COUNT] = [ $( Dropped::$name, )* ];
            /// Number of variants.
            pub const COUNT: usize = [ $( $s, )* ].len();
            /// A short stable name (for status output).
            pub const fn name(self) -> &'static str { match self { $( Dropped::$name => $s, )* } }
        }
    };
}

drops! {
    /// Fewer than four bytes.
    ParseShort => "parse_short",
    /// Type byte not 1..=4.
    ParseType => "parse_type",
    /// Reserved bytes not zero.
    ParseReserved => "parse_reserved",
    /// Wrong length for the type.
    ParseLength => "parse_length",
    /// mac1 did not verify.
    BadMac1 => "bad_mac1",
    /// Under load, mac2 missing or wrong, and no cookie reply could be sent.
    BadMac2 => "bad_mac2",
    /// A transport message for a receiver index no session of this peer has.
    NoSession => "no_session",
    /// The session is `REJECT_AFTER_TIME` old.
    SessionExpired => "session_expired",
    /// Authenticated, counter already accepted.
    ReplayDuplicate => "replay_dup",
    /// Authenticated (or pre-checked), counter below the window.
    ReplayTooOld => "replay_old",
    /// Counter at or above `REJECT_AFTER_MESSAGES`.
    ReplayLimit => "replay_limit",
    /// The transport tag did not verify.
    AuthFail => "auth_fail",
    /// An X25519 result was all zero (a small-order key).
    DhZero => "dh_zero",
    /// The initiation's static key did not decrypt.
    HsAuthStatic => "hs_auth_static",
    /// The initiation's static key is not a configured peer.
    HsUnknownPeer => "hs_unknown_peer",
    /// The initiation's timestamp did not decrypt.
    HsAuthTimestamp => "hs_auth_timestamp",
    /// The initiation's timestamp is not newer than the greatest seen from this peer.
    HsTimestampReplay => "hs_timestamp_replay",
    /// Initiations from this peer arrive faster than `MIN_INITIATION_INTERVAL`.
    HsFlood => "hs_flood",
    /// A response with no initiation outstanding (or the wrong receiver index).
    HsNoHandshake => "hs_no_handshake",
    /// The response's empty payload did not authenticate.
    HsAuthResponse => "hs_auth_response",
    /// A cookie reply when no initiation (mac1) is outstanding.
    CookieUnexpected => "cookie_unexpected",
    /// A cookie reply that did not decrypt.
    CookieAuth => "cookie_auth",
}

impl From<ParseError> for Dropped {
    fn from(e: ParseError) -> Dropped {
        match e {
            ParseError::Short => Dropped::ParseShort,
            ParseError::BadType => Dropped::ParseType,
            ParseError::BadReserved => Dropped::ParseReserved,
            ParseError::BadLength => Dropped::ParseLength,
        }
    }
}

/// One saturating counter per [`Dropped`].
#[derive(Clone, Debug)]
pub struct DropCounters {
    c: [Counter; Dropped::COUNT],
}

impl Default for DropCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl DropCounters {
    /// All zero.
    pub const fn new() -> Self {
        Self { c: [Counter(0); Dropped::COUNT] }
    }
    /// Count one drop.
    pub fn bump(&mut self, d: Dropped) {
        self.c[d as usize].bump();
    }
    /// The count for one reason.
    pub fn get(&self, d: Dropped) -> u32 {
        self.c[d as usize].get()
    }
    /// The sum over all reasons.
    pub fn total(&self) -> u64 {
        self.c.iter().map(|c| c.get() as u64).sum()
    }
}

/// Why a datagram could not be prepared for sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    /// No usable session: the caller queues the packet, and calls `request_handshake`.
    NoSession,
    /// The current session reached `REJECT_AFTER_TIME`.
    Expired,
    /// The current session used `REJECT_AFTER_MESSAGES` counters.
    Exhausted,
    /// (`PeerHot::encrypt` only) the buffer cannot hold the datagram; a counter was spent on it (gaps are legal).
    BufferTooSmall,
}

/// Why sealing into a buffer failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The buffer cannot hold header, padded payload and tag, or the payload is longer than the buffer.
    BufferTooSmall,
}

/// Why a handshake message could not be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// An initiation was sent less than `REKEY_TIMEOUT` ago.
    TooSoon,
    /// The index allocator is exhausted.
    NoIndex,
    /// An X25519 result was all zero (a small-order key).
    DhZero,
    /// No initiation has been consumed from this peer (responses), or the handshake changed while a job ran (commit).
    BadState,
}
