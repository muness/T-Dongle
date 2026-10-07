//! Tiny helpers.

/// A fixed buffer that implements `core::fmt::Write` and truncates instead of failing.
#[derive(Clone, Debug)]
pub struct Buf<const N: usize> {
    b: [u8; N],
    n: usize,
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Buf<N> {
    /// Empty.
    pub const fn new() -> Self {
        Buf { b: [0; N], n: 0 }
    }
    /// The text so far.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.b[..self.n]).unwrap_or("")
    }
    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.n
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

impl<const N: usize> core::fmt::Write for Buf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = N - self.n;
        let mut k = s.len().min(room);
        while !s.is_char_boundary(k) {
            k -= 1;
        }
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    #[test]
    fn truncates_on_a_character_boundary() {
        let mut b = Buf::<8>::new();
        b.write_str("ab").unwrap();
        b.write_str("\u{e9}\u{e9}\u{e9}").unwrap();
        // "ab" + three 2-byte characters = 8 bytes: it just fits
        assert_eq!((b.as_str(), b.len()), ("ab\u{e9}\u{e9}\u{e9}", 8));
        let mut c = Buf::<4>::new();
        write!(c, "host:{}", 1234).unwrap();
        assert_eq!(c.as_str(), "host");
        let mut d = Buf::<4>::new();
        d.write_str("a\u{e9}\u{e9}").unwrap();
        assert_eq!(d.as_str(), "a\u{e9}", "never cuts a character in half");
        assert!(!d.is_empty());
    }
}
