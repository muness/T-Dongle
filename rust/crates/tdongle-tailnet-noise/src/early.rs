//! The optional early payload (`tailcfg.EarlyNoise`).
//!
//! After the handshake the server's first plaintext bytes are either an HTTP/2 frame header (9 bytes) or, from servers that support it, the 5-byte
//! magic `ff ff ff 'T' 'S'` and a 4-byte big-endian length followed by that many bytes of JSON (it carries `nodeKeyChallenge`). The magic cannot start a valid
//! HTTP/2 frame (its length would be 0xffffff). The stream is plaintext spanning records, so this reader sits after the [`crate::RecordReader`].
//! The C caps the payload at 1024 bytes ([`MAX_EARLY`]); Tailscale itself allows 10 MiB.

/// The five magic bytes.
pub const MAGIC: [u8; 5] = [0xff, 0xff, 0xff, b'T', b'S'];
/// Size of the header that is either an early-payload header or an HTTP/2 frame header.
pub const HEADER_LEN: usize = 9;
/// Largest early payload accepted (the C's `length > 1024` check).
pub const MAX_EARLY: usize = 1024;

/// Why the early payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyError {
    /// Magic present but the announced length is zero (the C rejects it; JSON cannot be empty).
    Empty,
    /// The announced length exceeds [`MAX_EARLY`].
    TooLarge(u32),
    /// `feed` was called after the reader finished.
    Finished,
}

/// Where the reader is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyState {
    /// More plaintext needed.
    NeedMore,
    /// The payload is complete: read it with [`EarlyReader::payload`]. Plaintext after the consumed bytes belongs to HTTP/2.
    Payload,
    /// No magic: the nine bytes are the start of the HTTP/2 stream; replay them from [`EarlyReader::header`] before the rest.
    NotEarly,
}

/// Collects the first nine plaintext bytes and, when they announce an early payload, its body.
#[derive(Debug)]
pub struct EarlyReader {
    hdr: [u8; HEADER_LEN],
    hdr_used: usize,
    body: [u8; MAX_EARLY],
    body_used: usize,
    body_len: usize,
    done: bool,
}

impl Default for EarlyReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EarlyReader {
    /// A fresh reader (one per connection attempt; never share across identities).
    pub const fn new() -> EarlyReader {
        EarlyReader { hdr: [0; HEADER_LEN], hdr_used: 0, body: [0; MAX_EARLY], body_used: 0, body_len: 0, done: false }
    }

    /// Consume plaintext; returns how many bytes were used and the state. After `Payload` or `NotEarly` the rest of `plain` is the caller's.
    pub fn feed(&mut self, plain: &[u8]) -> Result<(usize, EarlyState), EarlyError> {
        if self.done {
            return Err(EarlyError::Finished);
        }
        let mut taken = 0;
        if self.hdr_used < HEADER_LEN {
            let n = (HEADER_LEN - self.hdr_used).min(plain.len());
            self.hdr[self.hdr_used..self.hdr_used + n].copy_from_slice(&plain[..n]);
            self.hdr_used += n;
            taken += n;
            // decide as early as the bytes allow: a mismatch with the magic ends it before nine bytes
            let seen = self.hdr_used.min(MAGIC.len());
            if self.hdr[..seen] != MAGIC[..seen] {
                if self.hdr_used < HEADER_LEN {
                    return Ok((taken, EarlyState::NeedMore)); // the caller must still get nine bytes to replay; keep collecting
                }
                self.done = true;
                return Ok((taken, EarlyState::NotEarly));
            }
            if self.hdr_used < HEADER_LEN {
                return Ok((taken, EarlyState::NeedMore));
            }
            let len = u32::from_be_bytes([self.hdr[5], self.hdr[6], self.hdr[7], self.hdr[8]]);
            if len == 0 {
                self.done = true;
                return Err(EarlyError::Empty);
            }
            if len as usize > MAX_EARLY {
                self.done = true;
                return Err(EarlyError::TooLarge(len));
            }
            self.body_len = len as usize;
        }
        if self.hdr[..MAGIC.len()] != MAGIC {
            self.done = true;
            return Ok((taken, EarlyState::NotEarly));
        }
        let n = (self.body_len - self.body_used).min(plain.len() - taken);
        self.body[self.body_used..self.body_used + n].copy_from_slice(&plain[taken..taken + n]);
        self.body_used += n;
        taken += n;
        if self.body_used == self.body_len {
            self.done = true;
            Ok((taken, EarlyState::Payload))
        } else {
            Ok((taken, EarlyState::NeedMore))
        }
    }

    /// The nine header bytes collected so far (the stream's first bytes when [`EarlyState::NotEarly`]).
    pub fn header(&self) -> &[u8] {
        &self.hdr[..self.hdr_used]
    }

    /// The JSON body once [`EarlyState::Payload`] was returned.
    pub fn payload(&self) -> &[u8] {
        &self.body[..self.body_used]
    }
}
