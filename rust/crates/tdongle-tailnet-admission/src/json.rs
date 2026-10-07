//! The bounded JSON writer of the firmware (`json_writer.inc`): no allocation, no locks, a failure latch.
//!
//! The C's `jw_writer` stages 256 bytes and flushes through a sink callback; failure of the sink latches and every later call becomes a no-op
//! returning false. This writer writes straight into a [`Sink`] (a fixed buffer, or the firmware's chunked HTTP response) and has the same latch,
//! so a fragment produced here is byte-identical to the C's. Strings are escaped as the C does: `"` and `\` with a backslash, bytes below 0x20 as
//! `\u00xx` (lower-case hex), everything else raw.

/// Where bytes go. `false` means the sink failed (full buffer, closed connection).
pub trait Sink {
    /// Append `bytes`; false on failure (nothing is assumed written).
    fn write(&mut self, bytes: &[u8]) -> bool;
}

/// A sink over a caller-owned slice; refuses (without a partial write) what does not fit.
#[derive(Debug)]
pub struct SliceSink<'a> {
    buf: &'a mut [u8],
    used: usize,
}

impl<'a> SliceSink<'a> {
    /// Over `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, used: 0 }
    }
    /// The bytes written so far.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl Sink for SliceSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> bool {
        let end = self.used + bytes.len();
        if end > self.buf.len() {
            return false;
        }
        self.buf[self.used..end].copy_from_slice(bytes);
        self.used = end;
        true
    }
}

/// `jw_writer`.
#[derive(Debug)]
pub struct JsonWriter<S: Sink> {
    sink: S,
    failed: bool,
}

impl<S: Sink> JsonWriter<S> {
    /// A writer over `sink`.
    pub fn new(sink: S) -> Self {
        Self { sink, failed: false }
    }
    /// Whether any write failed (the latch).
    #[must_use]
    pub fn failed(&self) -> bool {
        self.failed
    }
    /// The sink back.
    pub fn into_sink(self) -> S {
        self.sink
    }
    /// The sink, borrowed.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    fn put(&mut self, bytes: &[u8]) -> bool {
        if self.failed {
            return false;
        }
        if !self.sink.write(bytes) {
            self.failed = true;
        }
        !self.failed
    }

    /// `jw_char`.
    pub fn ch(&mut self, c: u8) -> bool {
        self.put(&[c])
    }
    /// `jw_raw`.
    pub fn raw(&mut self, s: &str) -> bool {
        self.put(s.as_bytes())
    }
    /// `jw_string`: quoted and escaped.
    pub fn string(&mut self, s: &str) -> bool {
        if !self.ch(b'"') {
            return false;
        }
        for &c in s.as_bytes() {
            let ok = if c == b'"' || c == b'\\' {
                self.put(&[b'\\', c])
            } else if c < 32 {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                self.put(&[b'\\', b'u', b'0', b'0', HEX[usize::from(c >> 4)], HEX[usize::from(c & 15)]])
            } else {
                self.put(&[c])
            };
            if !ok {
                return false;
            }
        }
        self.ch(b'"')
    }
    /// `jw_key`: `"name":`.
    pub fn key(&mut self, name: &str) -> bool {
        self.string(name) && self.ch(b':')
    }
    /// `jw_number`: unsigned decimal.
    pub fn number(&mut self, mut v: u64) -> bool {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&buf[i..])
    }
    /// `jw_bool`.
    pub fn boolean(&mut self, v: bool) -> bool {
        self.raw(if v { "true" } else { "false" })
    }
    /// The `NUM`/`RNUM` macros of the C: `"name":value,`.
    pub fn num_field(&mut self, name: &str, v: u64) -> bool {
        self.key(name) && self.number(v) && self.ch(b',')
    }
    /// `report_field`: `,"name":value`.
    pub fn report_field(&mut self, name: &str, v: u64) -> bool {
        self.ch(b',') && self.key(name) && self.number(v)
    }
}
