//! `snprintf`-faithful line assembly without allocation.
//!
//! The C firmware formats every report line into a fixed `char[N]` with `snprintf`, which silently truncates to `N - 1` bytes and returns
//! the length the full text would have had. A few callers test that return value (`n >= cap` means "did not fit"), the rest send whatever
//! landed in the buffer. [`Counting`] reproduces both behaviours: it keeps the first `N - 1` bytes and counts the rest.

use core::fmt::{self, Write};

/// A writer over a byte buffer that stores at most `buf.len() - 1` bytes (room for the C terminator) and counts everything offered.
#[derive(Debug)]
pub(crate) struct Counting<'a> {
    buf: &'a mut [u8],
    stored: usize,
    total: usize,
}

impl<'a> Counting<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, stored: 0, total: 0 }
    }

    /// The length the complete text has (C: `snprintf`'s return value).
    pub(crate) fn total(&self) -> usize {
        self.total
    }

    /// C `n >= cap` is false: the whole text was stored and the terminator fits.
    pub(crate) fn fits(&self) -> bool {
        self.total < self.buf.len()
    }

    /// Store the C terminator after the text (as `snprintf` always does when `cap > 0`). Only meaningful for a non-empty buffer.
    pub(crate) fn terminate(&mut self) {
        if let Some(slot) = self.buf.get_mut(self.stored) {
            *slot = 0;
        }
    }
}

impl Write for Counting<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.total = self.total.saturating_add(s.len());
        let room = self.buf.len().saturating_sub(1).saturating_sub(self.stored);
        let take = s.len().min(room);
        self.buf[self.stored..self.stored + take].copy_from_slice(&s.as_bytes()[..take]);
        self.stored += take;
        Ok(())
    }
}

/// Format `args` into `scratch` like `snprintf(scratch, scratch.len(), ...)` and return what a C caller would then send: the stored prefix.
///
/// Only ASCII input is expected (every report is). Should a cut ever land inside a multi-byte character, the dangling bytes are dropped
/// because a `&str` cannot carry them.
pub(crate) fn snprintf<'a>(scratch: &'a mut [u8], args: fmt::Arguments<'_>) -> &'a str {
    let mut out = Counting::new(&mut *scratch);
    // `Counting::write_str` never fails.
    let _ = out.write_fmt(args);
    let stored = out.stored;
    let bytes = &scratch[..stored];
    match core::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    }
}

/// `snprintf` into `scratch`, then one `write_str` of the result: the Rust form of `snprintf(reply, sizeof reply, ...); mgmt_write(reply);`.
pub(crate) fn emit<W: Write>(w: &mut W, scratch: &mut [u8], args: fmt::Arguments<'_>) -> fmt::Result {
    w.write_str(snprintf(scratch, args))
}

/// A fixed `[u8; N]` line that keeps at most `N - 1` bytes, for text that is not guaranteed to be UTF-8 (SSIDs are arbitrary bytes).
#[derive(Clone, Debug)]
pub(crate) struct ByteLine<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> ByteLine<N> {
    pub(crate) const fn new() -> Self {
        Self { buf: [0; N], len: 0 }
    }

    /// Append, dropping whatever does not fit in `N - 1` bytes (C `snprintf` truncation).
    pub(crate) fn put(&mut self, bytes: &[u8]) {
        let room = (N - 1) - self.len;
        let take = bytes.len().min(room);
        self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
        self.len += take;
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> Write for ByteLine<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.put(s.as_bytes());
        Ok(())
    }
}
