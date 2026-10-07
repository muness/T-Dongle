//! Transport records, in place.
//!
//! A record on the wire is `4 | len(2 BE) | ciphertext | tag(16)`. The buffer a caller seals in must therefore be `HEADROOM` bytes of
//! headroom, the plaintext, and `TAILROOM` bytes of tailroom. [`Session::seal_record`] encrypts the plaintext where it lies and writes the
//! header and tag around it; [`Session::open_record`] decrypts a whole record where it lies and returns where the plaintext is. No copies.
//!
//! The nonce is Tailscale's: 4 zero bytes, then the counter as a **big-endian** `u64` (`controlbase.nonce`). Noise's own text and `snow`
//! use little-endian, so the two agree only for counter 0 (the handshake, and the first record of each direction). The crypto crate's AEAD takes
//! the counter as its little-endian value, so this module passes `counter.swap_bytes()`.

use core::ops::Range;
use tdongle_tailnet_crypto::aead;
use tdongle_tailnet_types::{Counter, Key32};

/// Bytes of record header (type, length).
pub const HEADER_LEN: usize = 3;
/// Bytes of headroom a caller leaves before the plaintext when sealing.
pub const HEADROOM: usize = HEADER_LEN;
/// Bytes of tailroom a caller leaves after the plaintext when sealing (the tag).
pub const TAILROOM: usize = aead::TAG_LEN;
/// Largest record on the wire, header included.
pub const MAX_RECORD: usize = 4096;
/// Largest ciphertext (plaintext plus tag) a record may carry.
pub const MAX_CIPHERTEXT: usize = MAX_RECORD - HEADER_LEN;
/// Largest plaintext a record may carry (4077).
pub const MAX_PLAINTEXT: usize = MAX_CIPHERTEXT - aead::TAG_LEN;

pub(crate) const MSG_RECORD: u8 = 4;
const EXHAUSTED: u64 = u64::MAX;

/// Wire length of a record that carries `plain_len` plaintext bytes.
pub const fn wire_len(plain_len: usize) -> usize {
    HEADER_LEN + plain_len + aead::TAG_LEN
}

/// Which end of the handshake this session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The client (the dongle).
    Initiator,
    /// The server (tests and the host interop server).
    Responder,
}

/// Why a record was not sealed. The session state is unchanged except for the counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// More plaintext than one record carries ([`MAX_PLAINTEXT`]).
    TooLong,
    /// The buffer is shorter than `HEADROOM + plain_len + TAILROOM`.
    BufferTooSmall,
    /// The send counter reached its last value; the session is finished.
    Exhausted,
}

/// Why a record was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Fewer than 3 bytes, or fewer bytes than the length field announces (only from [`Session::open_record`]; the reader waits instead).
    Truncated,
    /// The type byte is not 4.
    BadType(u8),
    /// The length field says more than a record may carry, or the slice is longer than a record.
    Oversize,
    /// The slice does not hold exactly the number of bytes the length field announces.
    LengthMismatch,
    /// A ciphertext shorter than its tag.
    TooShort,
    /// The tag did not verify. The receive direction is dead from here on, as in `controlbase`.
    AuthFailed,
    /// A previous failure killed the receive direction.
    Dead,
    /// The receive counter reached its last value.
    Exhausted,
}

/// Counters for every record outcome (ADR rule 2: nothing is dropped silently).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Records sealed.
    pub sealed: Counter,
    /// Records opened.
    pub opened: Counter,
    /// Tags that did not verify.
    pub auth_failures: Counter,
    /// Wrong type bytes.
    pub bad_type: Counter,
    /// Oversize records or plaintexts.
    pub oversize: Counter,
    /// Truncated, over-long or too-short framing.
    pub bad_framing: Counter,
    /// Seal calls with a buffer that was too small.
    pub buffer_too_small: Counter,
    /// Opens attempted after the receive side died.
    pub rx_dead: Counter,
    /// Counter exhaustions (either direction).
    pub exhausted: Counter,
}

impl Stats {
    /// All zero (`const`, so state built from it can live in a `static`).
    pub const fn new() -> Self {
        Self {
            sealed: Counter(0),
            opened: Counter(0),
            auth_failures: Counter(0),
            bad_type: Counter(0),
            oversize: Counter(0),
            bad_framing: Counter(0),
            buffer_too_small: Counter(0),
            rx_dead: Counter(0),
            exhausted: Counter(0),
        }
    }
}

/// An established transport: two cipher states and their counters. 8-byte aligned, about 160 bytes.
#[derive(Debug)]
pub struct Session {
    tx_key: Key32,
    rx_key: Key32,
    tx_nonce: u64,
    rx_nonce: u64,
    handshake_hash: [u8; 32],
    peer: Key32,
    version: u16,
    role: Role,
    rx_dead: bool,
    stats: Stats,
}

impl Session {
    pub(crate) fn new(role: Role, k1: Key32, k2: Key32, hash: [u8; 32], version: u16, peer: Key32) -> Session {
        let (tx_key, rx_key) = match role {
            Role::Initiator => (k1, k2),
            Role::Responder => (k2, k1),
        };
        Session { tx_key, rx_key, tx_nonce: 0, rx_nonce: 0, handshake_hash: hash, peer, version, role, rx_dead: false, stats: Stats::default() }
    }

    /// The Noise handshake hash (binds later messages to this connection, e.g. the `nodeKeyChallenge` flow).
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }
    /// The peer's static public key (the control key for an initiator, the machine key for a responder).
    pub fn peer(&self) -> &Key32 {
        &self.peer
    }
    /// The negotiated protocol version.
    pub fn version(&self) -> u16 {
        self.version
    }
    /// Which end this is.
    pub fn role(&self) -> Role {
        self.role
    }
    /// The outcome counters.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
    /// Next send counter (the C's `tx_nonce`).
    pub fn tx_nonce(&self) -> u64 {
        self.tx_nonce
    }
    /// Next receive counter (the C's `rx_nonce`).
    pub fn rx_nonce(&self) -> u64 {
        self.rx_nonce
    }
    /// True once a tag failed: no further record can be opened.
    pub fn rx_dead(&self) -> bool {
        self.rx_dead
    }

    /// The plaintext window inside a record buffer of `buf_len` bytes: `HEADROOM..buf_len - TAILROOM`, or empty when it does not fit.
    pub fn plaintext_window(buf_len: usize) -> Range<usize> {
        let end = buf_len.saturating_sub(TAILROOM).min(HEADROOM + MAX_PLAINTEXT);
        HEADROOM.min(end)..end
    }

    /// Seal the plaintext already in `buf[HEADROOM..HEADROOM + plain_len]` in place: writes the header before it and the tag after it.
    /// Returns the wire length (`buf[..n]` is the record). A failed call leaves the counter alone, except [`SealError::Exhausted`].
    pub fn seal_record(&mut self, buf: &mut [u8], plain_len: usize) -> Result<usize, SealError> {
        if plain_len > MAX_PLAINTEXT {
            self.stats.oversize.bump();
            return Err(SealError::TooLong);
        }
        let total = wire_len(plain_len);
        if buf.len() < total {
            self.stats.buffer_too_small.bump();
            return Err(SealError::BufferTooSmall);
        }
        if self.tx_nonce == EXHAUSTED {
            self.stats.exhausted.bump();
            return Err(SealError::Exhausted);
        }
        buf[0] = MSG_RECORD;
        buf[1..3].copy_from_slice(&((plain_len + aead::TAG_LEN) as u16).to_be_bytes());
        let tag = aead::seal_detached(self.tx_key.as_bytes(), self.tx_nonce.swap_bytes(), &[], &mut buf[HEADROOM..HEADROOM + plain_len]);
        buf[HEADROOM + plain_len..total].copy_from_slice(&tag);
        self.tx_nonce += 1;
        self.stats.sealed.bump();
        Ok(total)
    }

    /// Convenience over [`Session::seal_record`]: copy `plain` into `out` after the headroom and seal it. One copy.
    pub fn seal_into(&mut self, plain: &[u8], out: &mut [u8]) -> Result<usize, SealError> {
        if plain.len() > MAX_PLAINTEXT {
            self.stats.oversize.bump();
            return Err(SealError::TooLong);
        }
        if out.len() < wire_len(plain.len()) {
            self.stats.buffer_too_small.bump();
            return Err(SealError::BufferTooSmall);
        }
        out[HEADROOM..HEADROOM + plain.len()].copy_from_slice(plain);
        self.seal_record(out, plain.len())
    }

    /// Open exactly one whole record (`record` is the header plus the ciphertext, nothing else) in place. Returns the plaintext range within `record`.
    pub fn open_record(&mut self, record: &mut [u8]) -> Result<Range<usize>, OpenError> {
        if record.len() < HEADER_LEN {
            self.stats.bad_framing.bump();
            return Err(OpenError::Truncated);
        }
        if record[0] != MSG_RECORD {
            self.stats.bad_type.bump();
            return Err(OpenError::BadType(record[0]));
        }
        let len = usize::from(u16::from_be_bytes([record[1], record[2]]));
        if len > MAX_CIPHERTEXT || record.len() > MAX_RECORD {
            self.stats.oversize.bump();
            return Err(OpenError::Oversize);
        }
        if record.len() < HEADER_LEN + len {
            self.stats.bad_framing.bump();
            return Err(OpenError::Truncated);
        }
        if record.len() != HEADER_LEN + len {
            self.stats.bad_framing.bump();
            return Err(OpenError::LengthMismatch);
        }
        if len < aead::TAG_LEN {
            self.stats.bad_framing.bump();
            return Err(OpenError::TooShort);
        }
        self.open_checked(record)
    }

    /// Crypto half shared with the reader, which has already validated the framing.
    pub(crate) fn open_checked(&mut self, record: &mut [u8]) -> Result<Range<usize>, OpenError> {
        if self.rx_dead {
            self.stats.rx_dead.bump();
            return Err(OpenError::Dead);
        }
        if self.rx_nonce == EXHAUSTED {
            self.stats.exhausted.bump();
            return Err(OpenError::Exhausted);
        }
        let n = record.len() - HEADER_LEN - aead::TAG_LEN;
        let mut tag = [0u8; aead::TAG_LEN];
        tag.copy_from_slice(&record[HEADER_LEN + n..]);
        match aead::open_detached(self.rx_key.as_bytes(), self.rx_nonce.swap_bytes(), &[], &mut record[HEADER_LEN..HEADER_LEN + n], &tag) {
            Ok(()) => {
                self.rx_nonce += 1;
                self.stats.opened.bump();
                Ok(HEADER_LEN..HEADER_LEN + n)
            }
            Err(_) => {
                // Like the C's in-place decrypt: whatever the failed open left in the body is not for anyone to read.
                record[HEADER_LEN..HEADER_LEN + n].fill(0);
                self.rx_dead = true;
                self.stats.auth_failures.bump();
                Err(OpenError::AuthFailed)
            }
        }
    }

    /// Test hook: set both counters (the C tests start at nonce 7).
    #[doc(hidden)]
    pub fn set_nonces_for_test(&mut self, tx: u64, rx: u64) {
        self.tx_nonce = tx;
        self.rx_nonce = rx;
    }

    pub(crate) fn count_framing(&mut self, e: OpenError) {
        match e {
            OpenError::BadType(_) => self.stats.bad_type.bump(),
            OpenError::Oversize => self.stats.oversize.bump(),
            _ => self.stats.bad_framing.bump(),
        }
    }
}
