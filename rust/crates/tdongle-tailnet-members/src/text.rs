//! A bounded C-string: bytes up to the first NUL, at most `CAP` of them.

use zeroize::Zeroize;

/// A C string held in `CAP` bytes (no terminator stored). Pushing a 0 byte ends the string (what `strlen` would see after cJSON decoded `\u0000`);
/// pushing past `CAP` sets [`CText::overflowed`] (the C string was longer than `CAP`) and keeps the first `CAP` bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CText<const CAP: usize> {
    bytes: [u8; CAP],
    len: usize,
    terminated: bool,
    overflow: bool,
}

impl<const CAP: usize> core::fmt::Debug for CText<CAP> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CText({:?}{})", core::str::from_utf8(self.as_bytes()).unwrap_or("<bytes>"), if self.overflow { "+" } else { "" })
    }
}

impl<const CAP: usize> Default for CText<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> CText<CAP> {
    /// The empty string.
    pub const fn new() -> Self {
        CText { bytes: [0; CAP], len: 0, terminated: false, overflow: false }
    }
    /// From bytes with C semantics (stops at the first NUL, flags overflow).
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut t = Self::new();
        for &c in b {
            t.push(c);
        }
        t
    }
    /// Append one byte with C semantics.
    pub fn push(&mut self, b: u8) {
        if self.terminated {
            return;
        }
        if b == 0 {
            self.terminated = true;
        } else if self.len < CAP {
            self.bytes[self.len] = b;
            self.len += 1;
        } else {
            self.overflow = true;
        }
    }
    /// The bytes held (at most `CAP`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    /// The text as `&str` when it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
    /// Held length.
    pub fn len(&self) -> usize {
        self.len
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// True when the C string was longer than `CAP` (the held bytes are only its prefix).
    pub fn overflowed(&self) -> bool {
        self.overflow
    }
    /// Empty it (zeroing the bytes).
    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
        self.terminated = false;
        self.overflow = false;
    }
    /// `strcasecmp(a, b) == 0` for the C locale (ASCII case folding). Both must not have overflowed to be meaningful; an overflowed text never equals.
    pub fn eq_ignore_case(&self, other: &[u8]) -> bool {
        !self.overflow && self.as_bytes().eq_ignore_ascii_case(other)
    }
}

impl<const CAP: usize> Zeroize for CText<CAP> {
    fn zeroize(&mut self) {
        self.clear();
    }
}
