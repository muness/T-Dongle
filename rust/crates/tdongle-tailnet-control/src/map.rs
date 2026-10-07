//! The map stream framing: each MapResponse is a 4-byte little-endian length and then that many bytes of JSON, carried as the payload of HTTP/2 DATA
//! frames on the map request's stream, split anywhere (a message can span many DATA frames, and a frame can hold several messages).

use crate::h2::{Event, H2Error};
use crate::json;
use tdongle_tailnet_types::Counter;

/// Largest map message the C accepts (`1024 * 1024`).
pub const MAX_MAP_MESSAGE: u32 = 1024 * 1024;
/// `ML_GATEWAY_PLAIN_BYTES`: the C's per-record plaintext workspace (one Noise record of HTTP/2 bytes).
pub const GATEWAY_PLAIN_BYTES: usize = 20480 + 16;
/// `ML_GATEWAY_JSON_BYTES`: the C's retained / projected JSON workspace; a raw (unprojected) message larger than this minus one cannot be handed to a consumer.
pub const GATEWAY_JSON_BYTES: usize = 16384;

/// A map length the stream must not carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// Length 0 or above the bound (C `map_error` 7).
    BadLength(u32),
}

/// A piece of the message stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapEvent<'a> {
    /// A message of `len` JSON bytes begins.
    Start {
        /// Declared length.
        len: u32,
    },
    /// The next bytes of the current message.
    Json(&'a [u8]),
    /// The current message is complete.
    End,
}

/// Splits the byte stream of one map stream into messages. 12 bytes of state, whatever the message size.
#[derive(Clone, Debug)]
pub struct MapFramer {
    prefix: [u8; 4],
    got: u8,
    len: u32,
    seen: u32,
    max: u32,
    end_pending: bool,
    /// Messages completed.
    pub messages: Counter,
}

impl MapFramer {
    /// A framer refusing messages above `max` bytes ([`MAX_MAP_MESSAGE`] for the C's rule).
    pub const fn new(max: u32) -> Self {
        Self { prefix: [0; 4], got: 0, len: 0, seen: 0, max, end_pending: false, messages: Counter(0) }
    }

    /// True between messages (no byte of a next message has been seen): the only place a stream may end.
    pub fn at_boundary(&self) -> bool {
        self.got == 0 && self.len == 0 && !self.end_pending
    }

    /// Bytes of the current message still to come (0 between messages).
    pub fn remaining(&self) -> u32 {
        self.len - self.seen
    }

    /// Forget a half-read message (after an error the stream is abandoned).
    pub fn reset(&mut self) {
        self.got = 0;
        self.len = 0;
        self.seen = 0;
        self.end_pending = false;
    }

    /// Consume bytes until an event is ready; call in a loop on the unconsumed tail. `(n, None)` means keep going; with empty input it flushes a pending
    /// [`MapEvent::End`].
    pub fn push<'a>(&mut self, data: &'a [u8]) -> Result<(usize, Option<MapEvent<'a>>), MapError> {
        if self.end_pending {
            self.end_pending = false;
            self.messages.bump();
            return Ok((0, Some(MapEvent::End)));
        }
        if self.len == 0 {
            let mut n = 0;
            while self.got < 4 && n < data.len() {
                self.prefix[self.got as usize] = data[n];
                self.got += 1;
                n += 1;
            }
            if self.got < 4 {
                return Ok((n, None));
            }
            let len = u32::from_le_bytes(self.prefix);
            self.got = 0;
            if len == 0 || len > self.max {
                return Err(MapError::BadLength(len));
            }
            self.len = len;
            self.seen = 0;
            return Ok((n, Some(MapEvent::Start { len })));
        }
        let take = ((self.len - self.seen) as usize).min(data.len());
        if take == 0 {
            return Ok((0, None));
        }
        self.seen += take as u32;
        if self.seen == self.len {
            self.len = 0;
            self.seen = 0;
            self.end_pending = true;
        }
        Ok((take, Some(MapEvent::Json(&data[..take]))))
    }
}

/// `{"KeepAlive":true}`, the map message the control plane sends to show it is alive (whitespace-insensitive, and no other key).
pub fn is_keepalive(json_bytes: &[u8]) -> bool {
    let mut v = [None; 1];
    if json::scan_top(json_bytes, 2, false, &["KeepAlive"], &mut v).is_err() || v[0] != Some(json::Value::Bool(true)) {
        return false;
    }
    // Only that key: count top-level members by checking the compact form.
    let mut compact = [0u8; 24];
    let mut n = 0;
    for &b in json_bytes {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if n == compact.len() {
            return false;
        }
        compact[n] = b;
        n += 1;
    }
    &compact[..n] == b"{\"KeepAlive\":true}"
}

/// How a map stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEnd {
    /// END_STREAM before any message in an initial fetch: an empty answer (Headscale answers the non-streaming fetch this way and delivers the netmap
    /// on the long-poll stream). The C returns 1.
    Empty,
    /// END_STREAM between messages after at least one was delivered.
    Clean,
    /// END_STREAM in the middle of a message (C `map_error` 12).
    MidMessage,
}

/// What ended a map read badly, with the C's `map_error` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapFailure {
    /// GOAWAY, or RST_STREAM on the map stream (code 10).
    Closed {
        /// HTTP/2 error code.
        h2_code: u32,
    },
    /// The HTTP/2 layer failed (padding is C code 4; everything else is reported as 3, "no data / connection returned").
    Connection(H2Error),
    /// Bad length prefix (code 7).
    Length(MapError),
    /// END_STREAM in the middle of a message (code 12).
    MidMessage,
}

impl MapFailure {
    /// The C's `ml->map_error` value.
    pub fn c_code(&self) -> u32 {
        match self {
            MapFailure::Closed { .. } => 10,
            MapFailure::Connection(H2Error::BadPadding) => 4,
            MapFailure::Connection(_) => 3,
            MapFailure::Length(_) => 7,
            MapFailure::MidMessage => 12,
        }
    }
}

/// The map stream of one connection: a [`MapFramer`] plus the stream-level decisions of `gateway_read_map`.
#[derive(Clone, Debug)]
pub struct MapStream {
    wanted: u32,
    /// Message framing.
    pub framer: MapFramer,
    applied: bool,
}

impl MapStream {
    /// Read messages from HTTP/2 stream `wanted` (3 for the initial fetch, 5 for the long poll).
    pub const fn new(wanted: u32) -> Self {
        Self { wanted, framer: MapFramer::new(MAX_MAP_MESSAGE), applied: false }
    }

    /// The stream.
    pub fn stream(&self) -> u32 {
        self.wanted
    }

    /// The consumer finished a whole message (the C's `applied`).
    pub fn mark_applied(&mut self) {
        self.applied = true;
    }

    /// Triage an HTTP/2 event: `Ok(Some(bytes))` for DATA of this stream to run through [`MapFramer::push`]; `Ok(None)` for anything to ignore;
    /// `Err` for a failure that abandons the stream. [`Event::StreamEnd`] on this stream is returned through `Ok(None)` after [`MapStream::on_end`].
    pub fn data<'a>(&self, ev: &Event<'a>) -> Result<Option<&'a [u8]>, MapFailure> {
        match *ev {
            Event::Data { stream, bytes } if stream == self.wanted => Ok(Some(bytes)),
            Event::GoAway { code, .. } => Err(MapFailure::Closed { h2_code: code }),
            Event::Reset { stream, code } if stream == self.wanted => Err(MapFailure::Closed { h2_code: code }),
            Event::Fatal(e) => Err(MapFailure::Connection(e)),
            _ => Ok(None),
        }
    }

    /// END_STREAM arrived on the map stream: how did it end?
    pub fn on_end(&self) -> StreamEnd {
        if !self.framer.at_boundary() {
            StreamEnd::MidMessage
        } else if self.applied {
            StreamEnd::Clean
        } else {
            StreamEnd::Empty
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    fn feed(f: &mut MapFramer, mut data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), MapError> {
        loop {
            let (n, ev) = f.push(data)?;
            data = &data[n..];
            match ev {
                Some(MapEvent::Start { .. }) => out.push(vec![]),
                Some(MapEvent::Json(b)) => out.last_mut().unwrap().extend_from_slice(b),
                Some(MapEvent::End) | None => {}
            }
            if ev.is_none() && n == 0 {
                return Ok(());
            }
        }
    }

    fn msg(json: &[u8]) -> Vec<u8> {
        let mut v = (json.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(json);
        v
    }

    #[test]
    fn go_harness_message() {
        let payload = br#"{"Node":{"Name":"fixture.ts.net","Addresses":["100.64.0.8/32"]},"Peers":[]}"#;
        let m = msg(payload);
        assert_eq!(&m[..4], &(payload.len() as u32).to_le_bytes());
        let mut f = MapFramer::new(MAX_MAP_MESSAGE);
        let mut out = vec![];
        feed(&mut f, &m, &mut out).unwrap();
        assert_eq!(out, [payload.to_vec()]);
        assert!(f.at_boundary() && f.messages.get() == 1);
    }

    #[test]
    fn every_split_and_coalescing() {
        let mut stream = msg(b"{\"a\":1}");
        stream.extend(msg(b"{\"KeepAlive\":true}"));
        stream.extend(msg(&[b'x'; 300]));
        for piece in 1..40 {
            let mut f = MapFramer::new(MAX_MAP_MESSAGE);
            let mut out = vec![];
            for c in stream.chunks(piece) {
                feed(&mut f, c, &mut out).unwrap();
            }
            assert_eq!(out.len(), 3, "{piece}");
            assert_eq!(out[0], b"{\"a\":1}");
            assert_eq!(out[2].len(), 300);
            assert!(f.at_boundary());
        }
        let mut f = MapFramer::new(MAX_MAP_MESSAGE);
        let mut out = vec![];
        feed(&mut f, &stream, &mut out).unwrap();
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn length_limits() {
        let mut f = MapFramer::new(MAX_MAP_MESSAGE);
        assert_eq!(f.push(&[0, 0, 0, 0]), Err(MapError::BadLength(0)));
        let mut f = MapFramer::new(MAX_MAP_MESSAGE);
        assert_eq!(f.push(&(MAX_MAP_MESSAGE + 1).to_le_bytes()), Err(MapError::BadLength(MAX_MAP_MESSAGE + 1)));
        let mut f = MapFramer::new(MAX_MAP_MESSAGE);
        assert_eq!(f.push(&MAX_MAP_MESSAGE.to_le_bytes()).unwrap().1, Some(MapEvent::Start { len: MAX_MAP_MESSAGE }));
    }

    #[test]
    fn keepalive() {
        assert!(is_keepalive(b"{\"KeepAlive\":true}"));
        assert!(is_keepalive(b" { \"KeepAlive\" : true } "));
        assert!(!is_keepalive(b"{\"KeepAlive\":false}"));
        assert!(!is_keepalive(b"{\"KeepAlive\":true,\"Node\":{}}"));
        assert!(!is_keepalive(b"{}") && !is_keepalive(b"nope"));
    }

    #[test]
    fn stream_end_classification() {
        let mut s = MapStream::new(5);
        assert_eq!(s.on_end(), StreamEnd::Empty);
        let mut out = vec![];
        feed(&mut s.framer, &msg(b"{}")[..5], &mut out).unwrap();
        assert_eq!(s.on_end(), StreamEnd::MidMessage);
        feed(&mut s.framer, &msg(b"{}")[5..], &mut out).unwrap();
        s.mark_applied();
        assert_eq!(s.on_end(), StreamEnd::Clean);
        let ev = Event::Data { stream: 5, bytes: b"x" };
        assert_eq!(s.data(&ev), Ok(Some(&b"x"[..])));
        assert_eq!(s.data(&Event::Data { stream: 3, bytes: b"x" }), Ok(None));
        assert_eq!(s.data(&Event::Reset { stream: 5, code: 8 }).unwrap_err().c_code(), 10);
        assert_eq!(s.data(&Event::Reset { stream: 3, code: 8 }), Ok(None));
        assert_eq!(MapFailure::Connection(H2Error::BadPadding).c_code(), 4);
    }
}
