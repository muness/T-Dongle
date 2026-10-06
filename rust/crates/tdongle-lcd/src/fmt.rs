//! A tiny `snprintf` for byte buffers with the C's truncation semantics: at most `len - 1` bytes are written, then one NUL; bytes after
//! the NUL are left alone (so overwriting a field leaves the same trailing bytes as the C does).

/// The bytes of a C string stored in `b`: up to the first NUL, or all of `b`.
#[must_use]
pub fn cstr(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(n) => &b[..n],
        None => b,
    }
}

/// Output cursor into a fixed buffer (C `snprintf(buf, sizeof buf, ...)`).
#[derive(Debug)]
pub struct Snp<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Snp<'_> {
    fn push(&mut self, c: u8) {
        if self.len + 1 < self.buf.len() {
            self.buf[self.len] = c;
        }
        // Count even when truncated, like snprintf's would-be length; the cap is applied in `push`.
        self.len += 1;
    }
    /// Literal text, or `%s`.
    pub fn s(&mut self, text: &str) -> &mut Self {
        self.b(text.as_bytes())
    }
    /// `%s` of a byte string (up to its first NUL).
    pub fn b(&mut self, text: &[u8]) -> &mut Self {
        for &c in cstr(text) {
            self.push(c);
        }
        self
    }
    /// `%.<n>s`.
    pub fn bn(&mut self, text: &[u8], n: usize) -> &mut Self {
        for &c in cstr(text).iter().take(n) {
            self.push(c);
        }
        self
    }
    /// `%u` / `%lu`.
    pub fn u(&mut self, mut v: u64) -> &mut Self {
        let mut d = [0u8; 20];
        let mut n = 0;
        loop {
            d[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.push(d[n]);
        }
        self
    }
    /// `%02u`.
    pub fn u02(&mut self, v: u32) -> &mut Self {
        if v < 10 {
            self.push(b'0');
        }
        self.u(u64::from(v))
    }
    /// `%d`.
    pub fn i(&mut self, v: i32) -> &mut Self {
        if v < 0 {
            self.push(b'-');
        }
        self.u(u64::from(v.unsigned_abs()))
    }
}

/// Run `f` as one `snprintf` into `buf` and terminate with a NUL (nothing is written for an empty `buf`).
pub fn snprintf(buf: &mut [u8], f: impl FnOnce(&mut Snp<'_>)) {
    let mut w = Snp { buf, len: 0 };
    f(&mut w);
    let cap = w.buf.len();
    if cap > 0 {
        let at = w.len.min(cap - 1);
        w.buf[at] = 0;
    }
}
