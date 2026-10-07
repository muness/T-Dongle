//! Incremental record reader: feed it whatever the socket returned, get decrypted records out of one 4096-byte buffer.

use crate::session::{HEADER_LEN, MAX_CIPHERTEXT, MAX_RECORD, MSG_RECORD, OpenError, Session};
use tdongle_tailnet_crypto::aead::TAG_LEN;

/// What one [`RecordReader::feed`] call produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Feed<'a> {
    /// All input was consumed (the returned count equals `data.len()`) and the record is still incomplete.
    NeedMore,
    /// One whole record, decrypted; the slice is its plaintext (possibly empty: the protocol allows zero-byte records). It lives in the reader's buffer
    /// until the next `feed`.
    Record(&'a [u8]),
    /// The stream is unusable (framing lost or a tag failed). Sticky: every later call returns [`OpenError::Dead`] without consuming.
    Error(OpenError),
}

/// Reassembles records from arbitrary chunks. Owns exactly one record buffer; bytes are copied into it once and decrypted there.
#[derive(Debug)]
pub struct RecordReader {
    buf: [u8; MAX_RECORD],
    used: usize,
    complete: bool,
    failed: bool,
}

impl Default for RecordReader {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordReader {
    /// An empty reader.
    pub const fn new() -> RecordReader {
        RecordReader { buf: [0; MAX_RECORD], used: 0, complete: false, failed: false }
    }

    /// Bytes of a partial record currently buffered.
    pub fn buffered(&self) -> usize {
        if self.complete { 0 } else { self.used }
    }

    /// True after a fatal error.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Consume bytes from `data` until one record is complete (or the data runs out) and return how many were consumed with the outcome.
    /// Call again with the rest (`&data[consumed..]`) until it returns [`Feed::NeedMore`]. Header problems are reported as soon as the three header
    /// bytes are in, without waiting for the body.
    pub fn feed<'a>(&'a mut self, session: &mut Session, data: &[u8]) -> (usize, Feed<'a>) {
        if self.failed {
            return (0, Feed::Error(OpenError::Dead));
        }
        if self.complete {
            self.used = 0;
            self.complete = false;
        }
        let mut taken = 0;
        loop {
            let want = if self.used < HEADER_LEN { HEADER_LEN - self.used } else { HEADER_LEN + self.body_len() - self.used };
            let n = want.min(data.len() - taken);
            self.buf[self.used..self.used + n].copy_from_slice(&data[taken..taken + n]);
            self.used += n;
            taken += n;
            if self.used < HEADER_LEN {
                return (taken, Feed::NeedMore);
            }
            if let Err(e) = self.check_header() {
                return (taken, self.fail(session, e));
            }
            let total = HEADER_LEN + self.body_len();
            if self.used < total {
                if taken == data.len() {
                    return (taken, Feed::NeedMore);
                }
                continue;
            }
            return match session.open_checked(&mut self.buf[..total]) {
                Ok(range) => {
                    self.complete = true;
                    (taken, Feed::Record(&self.buf[range]))
                }
                Err(e) => {
                    self.failed = true;
                    (taken, Feed::Error(e))
                }
            };
        }
    }

    fn body_len(&self) -> usize {
        usize::from(u16::from_be_bytes([self.buf[1], self.buf[2]]))
    }

    fn check_header(&self) -> Result<(), OpenError> {
        if self.buf[0] != MSG_RECORD {
            return Err(OpenError::BadType(self.buf[0]));
        }
        let len = self.body_len();
        if len > MAX_CIPHERTEXT {
            return Err(OpenError::Oversize);
        }
        if len < TAG_LEN {
            return Err(OpenError::TooShort);
        }
        Ok(())
    }

    fn fail<'a>(&mut self, session: &mut Session, e: OpenError) -> Feed<'a> {
        session.count_framing(e);
        self.failed = true;
        Feed::Error(e)
    }
}
