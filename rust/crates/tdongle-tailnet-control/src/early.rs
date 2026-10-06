//! The "early noise" payload: the first plaintext bytes after the Noise handshake (`\xff\xff\xffTS`, a big-endian u32 length, then JSON carrying the
//! `nodeKeyChallenge`). A control server that does not send it (a custom coordinator) goes straight to its HTTP/2 SETTINGS; the nine bytes read are then
//! handed back to be replayed into the HTTP/2 reader.

use crate::json::{self, JsonError, Value};
use tdongle_tailnet_types::Key32;

/// The five magic bytes.
pub const EARLY_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";
/// Largest early JSON accepted (the C: 1024).
pub const EARLY_JSON_MAX: usize = 1024;
/// Nesting allowed in the early JSON.
pub const EARLY_JSON_DEPTH: u32 = 8;

/// Why the early payload was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyError {
    /// The declared length is 0 or above [`EARLY_JSON_MAX`] (C `EMSGSIZE`).
    BadLength(u32),
    /// The caller's buffer is smaller than the declared length.
    BufferTooSmall,
    /// Not a JSON object (C `EPROTO`).
    BadJson,
    /// `nodeKeyChallenge` present but not `chalpub:` + 64 hex digits (C `EPROTO`).
    BadChallenge,
}

/// Progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EarlyStatus {
    /// Feed more.
    NeedMore,
    /// Not an early payload: these nine bytes belong to HTTP/2 and must be replayed into it.
    Absent {
        /// The nine bytes.
        replay: [u8; 9],
    },
    /// The payload was read; `challenge` is the node-key challenge if the server sent one.
    Present {
        /// `nodeKeyChallenge`.
        challenge: Option<Key32>,
    },
}

/// Streaming reader of the early payload into a caller buffer (1024 bytes is enough).
#[derive(Debug)]
pub struct EarlyReader<'a> {
    hdr: [u8; 9],
    used: u8,
    json: &'a mut [u8],
    want: usize,
    got: usize,
    done: bool,
}

impl<'a> EarlyReader<'a> {
    /// Collect the JSON into `json`.
    pub fn new(json: &'a mut [u8]) -> Self {
        Self { hdr: [0; 9], used: 0, json, want: 0, got: 0, done: false }
    }

    /// Consume from `data`; returns the bytes taken (the rest is HTTP/2) and the status.
    pub fn push(&mut self, data: &[u8]) -> Result<(usize, EarlyStatus), EarlyError> {
        if self.done {
            return Ok((0, EarlyStatus::NeedMore));
        }
        let mut n = 0;
        while self.used < 9 && n < data.len() {
            self.hdr[self.used as usize] = data[n];
            self.used += 1;
            n += 1;
        }
        if self.used < 9 {
            return Ok((n, EarlyStatus::NeedMore));
        }
        if self.want == 0 {
            if &self.hdr[..5] != EARLY_MAGIC {
                self.done = true;
                return Ok((n, EarlyStatus::Absent { replay: self.hdr }));
            }
            let len = u32::from_be_bytes([self.hdr[5], self.hdr[6], self.hdr[7], self.hdr[8]]);
            if len == 0 || len as usize > EARLY_JSON_MAX {
                self.done = true;
                return Err(EarlyError::BadLength(len));
            }
            if len as usize > self.json.len() {
                self.done = true;
                return Err(EarlyError::BufferTooSmall);
            }
            self.want = len as usize;
        }
        let take = (self.want - self.got).min(data.len() - n);
        self.json[self.got..self.got + take].copy_from_slice(&data[n..n + take]);
        self.got += take;
        n += take;
        if self.got < self.want {
            return Ok((n, EarlyStatus::NeedMore));
        }
        self.done = true;
        let mut v = [None; 1];
        json::scan_top(&self.json[..self.want], EARLY_JSON_DEPTH, false, &["nodeKeyChallenge"], &mut v).map_err(|_: JsonError| EarlyError::BadJson)?;
        let challenge = match v[0] {
            None => None,
            Some(Value::Str(s)) if s.len() == 72 && s.starts_with(b"chalpub:") => Some(Key32::from_hex(&s[8..]).ok_or(EarlyError::BadChallenge)?),
            Some(_) => return Err(EarlyError::BadChallenge),
        };
        Ok((n, EarlyStatus::Present { challenge }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    const JSON: &str = r#"{"nodeKeyChallenge":"chalpub:0101010101010101010101010101010101010101010101010101010101010101"}"#;
    const SETTINGS: [u8; 15] = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0];

    fn stream(json: &str) -> Vec<u8> {
        let mut v = vec![0xff, 0xff, 0xff, b'T', b'S', 0, 0, 0, json.len() as u8];
        v.extend_from_slice(json.as_bytes());
        v.extend_from_slice(&SETTINGS);
        v
    }

    fn run(bytes: &[u8], piece: usize) -> Result<(EarlyStatus, Vec<u8>), EarlyError> {
        let mut buf = [0u8; EARLY_JSON_MAX];
        let mut r = EarlyReader::new(&mut buf);
        let mut off = 0;
        while off < bytes.len() {
            let end = (off + piece).min(bytes.len());
            let (n, st) = r.push(&bytes[off..end])?;
            off += n;
            if st != EarlyStatus::NeedMore {
                return Ok((st, bytes[off..].to_vec()));
            }
        }
        Ok((EarlyStatus::NeedMore, vec![]))
    }

    #[test]
    fn every_split_leaves_the_settings_tail() {
        let b = stream(JSON);
        for piece in 1..b.len() {
            let (st, rest) = run(&b, piece).unwrap();
            assert_eq!(st, EarlyStatus::Present { challenge: Some(Key32([1; 32])) }, "{piece}");
            assert_eq!(rest, SETTINGS, "{piece}");
        }
    }

    #[test]
    fn absent_replays_nine_bytes() {
        let (st, rest) = run(&SETTINGS.repeat(3), 4).unwrap();
        let EarlyStatus::Absent { replay } = st else { panic!() };
        assert_eq!(&replay[..], &SETTINGS.repeat(3)[..9]);
        assert!(!rest.is_empty());
    }

    #[test]
    fn present_without_challenge_and_refusals() {
        assert_eq!(run(&stream("{}"), 3).unwrap().0, EarlyStatus::Present { challenge: None });
        assert_eq!(run(&stream("{\"other\":1}"), 3).unwrap().0, EarlyStatus::Present { challenge: None });
        for bad in [
            r#"{"nodeKeyChallenge":"chalpub:00"}"#,
            r#"{"nodeKeyChallenge":5}"#,
            r#"{"nodeKeyChallenge":"chalpux:0101010101010101010101010101010101010101010101010101010101010101"}"#,
            r#"{"nodeKeyChallenge":"chalpub:zz01010101010101010101010101010101010101010101010101010101010101"}"#,
        ] {
            assert_eq!(run(&stream(bad), 5), Err(EarlyError::BadChallenge), "{bad}");
        }
        assert_eq!(run(&stream("not json"), 5), Err(EarlyError::BadJson));
        // Length 0, and 0x401 (the C test's `huge`).
        let mut b = stream("{}");
        b[8] = 0;
        assert_eq!(run(&b, 4), Err(EarlyError::BadLength(0)));
        let huge = [255, 255, 255, b'T', b'S', 0, 0, 4, 1];
        assert_eq!(run(&huge, 9), Err(EarlyError::BadLength(1025)));
        let mut small = [0u8; 1];
        let mut r = EarlyReader::new(&mut small);
        assert_eq!(r.push(&stream("{}")), Err(EarlyError::BufferTooSmall));
    }
}
