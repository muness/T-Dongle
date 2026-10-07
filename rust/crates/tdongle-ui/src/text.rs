//! Fixed-capacity text, truncating like `snprintf` / `strlcpy` (never allocates, never panics).

use core::fmt;

/// A NUL-free byte string of at most `N` bytes; longer input is cut (at a byte, as C does).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text<const N: usize> {
    buf: [u8; N],
    len: u8,
}

impl<const N: usize> Text<N> {
    /// Empty.
    pub const fn new() -> Self {
        Text { buf: [0; N], len: 0 }
    }
    /// Copy at most `N` bytes of `s` (the C buffers are `N + 1` bytes with the NUL).
    pub fn from_str_truncated(s: &str) -> Self {
        let mut t = Self::new();
        t.push_bytes(s.as_bytes());
        t
    }
    /// Append bytes up to the capacity.
    pub fn push_bytes(&mut self, b: &[u8]) {
        for &c in b {
            if (self.len as usize) >= N || self.len == u8::MAX {
                break;
            }
            self.buf[self.len as usize] = c;
            self.len += 1;
        }
    }
    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
    /// The text; a cut in the middle of a multi-byte character yields the valid prefix.
    pub fn as_str(&self) -> &str {
        match core::str::from_utf8(self.as_bytes()) {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&self.as_bytes()[..e.valid_up_to()]).unwrap_or(""),
        }
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_bytes(s.as_bytes());
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

impl<const N: usize> fmt::Display for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
