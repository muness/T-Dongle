//! The bounded JSON serializer of `json_writer.inc` (`jw_*`): no allocation, a 256-byte staging buffer, and a caller sink that receives it in chunks.
//!
//! Byte-for-byte what the C writes, including its quirks: control characters below 0x20 are `\u00xx` (lower-case hex, never `\n`), only `"` and `\`
//! are backslash-escaped, bytes of 0x80 and above pass through, a string ends at its first NUL, and the first sink failure latches (`failed`): every
//! later call is a no-op that reports false, so the caller may keep writing and check once. The chunk boundaries are the C's too: the staging buffer is
//! handed to the sink when it is full and a further byte arrives, and once at the end ([`JsonWriter::flush`]).

/// Where the chunks go (`status_chunk` -> `httpd_resp_send_chunk`).
pub trait ChunkSink {
    /// Take one chunk of at most 256 bytes. `false` is the C's `< 0`: the client went away.
    fn chunk(&mut self, bytes: &[u8]) -> bool;
}

impl<F: FnMut(&[u8]) -> bool> ChunkSink for F {
    fn chunk(&mut self, bytes: &[u8]) -> bool {
        self(bytes)
    }
}

/// Staging capacity (`char bytes[256]`), also the largest chunk.
pub const CHUNK: usize = 256;

/// `jw_writer`.
pub struct JsonWriter<'a> {
    bytes: [u8; CHUNK],
    used: usize,
    failed: bool,
    sink: &'a mut dyn ChunkSink,
}

impl core::fmt::Debug for JsonWriter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JsonWriter").field("used", &self.used).field("failed", &self.failed).finish()
    }
}

impl<'a> JsonWriter<'a> {
    /// A writer over `sink`.
    pub fn new(sink: &'a mut dyn ChunkSink) -> Self {
        JsonWriter { bytes: [0; CHUNK], used: 0, failed: false, sink }
    }
    /// True once the sink refused a chunk.
    pub fn failed(&self) -> bool {
        self.failed
    }
    /// `jw_flush`: hand the staged bytes to the sink. False if the writer has failed.
    pub fn flush(&mut self) -> bool {
        if self.failed {
            return false;
        }
        if self.used > 0 && !self.sink.chunk(&self.bytes[..self.used]) {
            self.failed = true;
            return false;
        }
        self.used = 0;
        true
    }
    /// `jw_char`.
    pub fn ch(&mut self, c: u8) -> bool {
        if self.failed {
            return false;
        }
        if self.used == CHUNK && !self.flush() {
            return false;
        }
        self.bytes[self.used] = c;
        self.used += 1;
        true
    }
    /// `jw_raw`: bytes up to the first NUL.
    pub fn raw(&mut self, s: &[u8]) -> bool {
        for &c in s {
            if c == 0 {
                break;
            }
            if !self.ch(c) {
                return false;
            }
        }
        true
    }
    /// `jw_string`: quoted and escaped, up to the first NUL.
    pub fn string(&mut self, s: &[u8]) -> bool {
        if !self.ch(b'"') {
            return false;
        }
        for &c in s {
            if c == 0 {
                break;
            }
            let ok = if c == b'"' || c == b'\\' {
                self.ch(b'\\') && self.ch(c)
            } else if c < 32 {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                self.raw(b"\\u00") && self.ch(HEX[(c >> 4) as usize]) && self.ch(HEX[(c & 15) as usize])
            } else {
                self.ch(c)
            };
            if !ok {
                return false;
            }
        }
        self.ch(b'"')
    }
    /// `jw_key`: `"name":`.
    pub fn key(&mut self, name: &str) -> bool {
        self.string(name.as_bytes()) && self.ch(b':')
    }
    /// `jw_number`: an unsigned decimal.
    pub fn number(&mut self, v: u64) -> bool {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut v = v;
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.raw(&buf[i..])
    }
    /// `jw_bool`.
    pub fn boolean(&mut self, v: bool) -> bool {
        self.raw(if v { b"true" } else { b"false" })
    }

    // The status macros of gateway_main.c / runtime_status.inc, as methods.

    /// `NUM(name, value)`: `"name":value,`.
    pub fn num(&mut self, name: &str, v: u64) {
        self.key(name);
        self.number(v);
        self.ch(b',');
    }
    /// `NUM(name, value)` for a signed C value: it converts to `uint64_t`, so a negative one prints as 2^64 minus its magnitude.
    pub fn num_i32_wrapping(&mut self, name: &str, v: i32) {
        self.num(name, i64::from(v) as u64);
    }
    /// `STR(name, value)`: `"name":"value",`.
    pub fn str(&mut self, name: &str, v: &[u8]) {
        self.key(name);
        self.string(v);
        self.ch(b',');
    }
    /// `BOOL(name, value)`: `"name":true,`.
    pub fn bool(&mut self, name: &str, v: bool) {
        self.key(name);
        self.boolean(v);
        self.ch(b',');
    }
    /// `PSIGNED(name, value)` (power): `"name":-5,` with the magnitude truncated to 32 bits like `(uint32_t)v_`.
    pub fn signed(&mut self, name: &str, v: i32) {
        self.key(name);
        let mut m = i64::from(v);
        if m < 0 {
            self.ch(b'-');
            m = -m;
        }
        self.number(u64::from(m as u32));
        self.ch(b',');
    }
    /// `"name":value` or `"name":null` (UINT32_MAX = "not running") followed by `,` when `comma`.
    pub fn num_or_null(&mut self, name: &str, v: u32, null_at: u32, comma: bool) {
        self.key(name);
        if v == null_at {
            self.raw(b"null");
        } else {
            self.number(u64::from(v));
        }
        if comma {
            self.ch(b',');
        }
    }
}

/// `microlink_ip_to_str`: dotted quad of a host-order address, as `"%lu.%lu.%lu.%lu"`.
pub fn ip_to_str(ip: u32) -> ([u8; 15], usize) {
    let mut out = [0u8; 15];
    let mut n = 0;
    for shift in [24u32, 16, 8, 0] {
        let b = (ip >> shift) & 255;
        let digits = if b >= 100 {
            3
        } else if b >= 10 {
            2
        } else {
            1
        };
        let mut v = b;
        for i in (0..digits).rev() {
            out[n + i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        n += digits;
        if shift != 0 {
            out[n] = b'.';
            n += 1;
        }
    }
    (out, n)
}
