//! A byte sink writing what `cJSON_PrintUnformatted` writes, for the shapes the registry needs.

/// The output buffer is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// Appends into a caller buffer; never panics, never allocates.
#[derive(Debug)]
pub struct Sink<'a> {
    out: &'a mut [u8],
    len: usize,
    /// Bytes that did not fit (the length the full text would have had, beyond the buffer).
    pub overflow: usize,
}

impl<'a> Sink<'a> {
    /// A sink over `out`.
    pub fn new(out: &'a mut [u8]) -> Self {
        Sink { out, len: 0, overflow: 0 }
    }
    /// Bytes written.
    pub fn len(&self) -> usize {
        self.len
    }
    /// True when nothing was written.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Total length the text has (written plus what did not fit).
    pub fn total(&self) -> usize {
        self.len + self.overflow
    }
    /// Append bytes.
    pub fn raw(&mut self, b: &[u8]) {
        let room = self.out.len() - self.len;
        let n = room.min(b.len());
        self.out[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        self.overflow += b.len() - n;
    }
    /// An unsigned integer in decimal (`%u`; for integral doubles cJSON prints the same digits).
    pub fn number(&mut self, v: u64) {
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
        self.raw(&buf[i..]);
    }
    /// A string as `print_string_ptr` writes it: quotes, `\"` `\\` `\b` `\f` `\n` `\r` `\t`, other bytes below 0x20 as `\u00xx` (lower case), everything
    /// else (including 0x7f and bytes >= 0x80) raw.
    pub fn string(&mut self, s: &[u8]) {
        self.raw(b"\"");
        for &c in s {
            match c {
                b'"' => self.raw(b"\\\""),
                b'\\' => self.raw(b"\\\\"),
                8 => self.raw(b"\\b"),
                12 => self.raw(b"\\f"),
                b'\n' => self.raw(b"\\n"),
                b'\r' => self.raw(b"\\r"),
                b'\t' => self.raw(b"\\t"),
                0..=31 => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.raw(&[b'\\', b'u', b'0', b'0', HEX[(c >> 4) as usize], HEX[(c & 15) as usize]]);
                }
                _ => self.raw(&[c]),
            }
        }
        self.raw(b"\"");
    }
}
