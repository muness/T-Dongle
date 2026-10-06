//! The serial line discipline of `console.c`: bytes from the CDC port in, command lines (or the console's own short replies) out.
//!
//! # `rx()` in C
//!
//! `rx` reads up to 64 bytes at a time and feeds every byte through one state machine over `line[512]` (`used`, `overflow`):
//!
//! | byte | effect |
//! |------|--------|
//! | CR or LF, `overflow` set | reply [`OVERFLOW_REPLY`], line discarded |
//! | CR or LF, `used > 0` | the line is submitted to the command queue |
//! | CR or LF, empty line | reply [`PROMPT`] |
//! | BS (8) or DEL (127) | erase the last character if there is one (also while `overflow` is set, which stays set) |
//! | printable (32..=126), room (`used < 511`) | append |
//! | printable, buffer full | `overflow` |
//! | anything else (tab, ESC, bytes >= 128, NUL, ...) | `overflow` |
//!
//! A CRLF pair is two terminators: the CR submits the line and the LF then finds an empty line and produces a prompt. Clients that send
//! CRLF therefore see `tdongle>` after every command; this port keeps that (it is what the Android app and the scripts are used to).
//!
//! # What this module does not model (documentation of the C transport)
//!
//! * `mgmt_write` cuts every reply into pieces of at most 127 bytes ([`mgmt_chunks`]) and queues each as one 128 byte slot of an
//!   8 slot queue; the writer task sends a slot with `tinyusb_cdcacm_write_queue`. The bytes on the wire are the same as the
//!   unchunked reply.
//! * Back pressure: a task other than `gateway_control` queues with a zero wait, so **a chunk is silently dropped when the queue is full**;
//!   `gateway_control` waits up to 300 ms per chunk. Replies are therefore not guaranteed delivered under load.
//! * The writer retries a short write at most 10 times: after each attempt it flushes (20 ms) and, while bytes remain, sleeps 10 ms. A host
//!   that stops reading loses the rest of that chunk.
//! * `console_printf` formats into a 512 byte buffer (truncating) and then goes through `mgmt_write`.
//! * The CDC DTR edge sends the greeting ([`write_greeting`]). Input is never echoed.

use core::fmt;

/// `sizeof(line)` in `console.c`: a line holds at most [`LINE_CHARS_MAX`] characters.
pub const LINE_MAX: usize = 512;
/// The longest line `rx` accepts (`sizeof(line) - 1`).
pub const LINE_CHARS_MAX: usize = LINE_MAX - 1;

/// Reply to an empty line (CR or LF with nothing typed).
pub const PROMPT: &str = "tdongle>\r\n";
/// Reply at the CR or LF that ends a line that was too long or contained a non printable byte.
pub const OVERFLOW_REPLY: &str = "ERR line too long/invalid; discarded\r\n";
/// Reply when `control_submit` refused the line (the 2 slot command queue was full or the line did not fit): firmware policy, not the reader's.
pub const QUEUE_FULL_REPLY: &str = "ERR command queue full\r\n";

/// What `mgmt_write` does with one reply: pieces of at most this many bytes (the queue slot is 128 bytes including the NUL).
pub const MGMT_CHUNK_MAX: usize = 127;

/// What one input byte caused. Borrows the reader (see [`LineReader::feed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A complete, non empty, valid line (1 to 511 printable ASCII characters, no terminator): submit it to the command queue.
    Line(&'a str),
    /// An empty line: reply with [`PROMPT`].
    Prompt,
    /// The line just ended was invalid: reply with [`OVERFLOW_REPLY`].
    Overflow,
}

impl Event<'_> {
    /// The console's own reply to this event, if it has one (`Line` goes to the command task instead).
    #[must_use]
    pub const fn reply(&self) -> Option<&'static str> {
        match self {
            Self::Line(_) => None,
            Self::Prompt => Some(PROMPT),
            Self::Overflow => Some(OVERFLOW_REPLY),
        }
    }
}

/// The line buffer and its state machine (`line`, `used`, `overflow` of `console.c`).
#[derive(Clone, Debug)]
pub struct LineReader {
    line: [u8; LINE_MAX],
    used: usize,
    overflow: bool,
}

impl Default for LineReader {
    fn default() -> Self {
        Self::new()
    }
}

impl LineReader {
    /// An empty reader.
    #[must_use]
    pub const fn new() -> Self {
        Self { line: [0; LINE_MAX], used: 0, overflow: false }
    }

    /// Feed one received byte.
    ///
    /// Returns `Some` only for CR or LF. The borrow of an [`Event::Line`] points into the reader's buffer, so it must end before the next
    /// call to `feed` (the borrow checker enforces that: `feed` takes `&mut self`). The reader is already reset when `Line` is returned;
    /// copy the text out (the firmware queues it) before feeding more bytes.
    pub fn feed(&mut self, byte: u8) -> Option<Event<'_>> {
        match byte {
            b'\r' | b'\n' => {
                let used = core::mem::take(&mut self.used);
                let overflow = core::mem::take(&mut self.overflow);
                if overflow {
                    Some(Event::Overflow)
                } else if used > 0 {
                    // Only bytes 32..=126 are ever stored, so this is always valid UTF-8; `Overflow` is the unreachable fallback.
                    Some(core::str::from_utf8(&self.line[..used]).map_or(Event::Overflow, Event::Line))
                } else {
                    Some(Event::Prompt)
                }
            }
            8 | 127 => {
                self.used = self.used.saturating_sub(1);
                None
            }
            32..=126 if !self.overflow => {
                if self.used < LINE_CHARS_MAX {
                    self.line[self.used] = byte;
                    self.used += 1;
                } else {
                    self.overflow = true;
                }
                None
            }
            _ => {
                self.overflow = true;
                None
            }
        }
    }

    /// Characters currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.used
    }

    /// Whether no character is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Whether the current line is already doomed (it will be discarded at its terminator).
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflow
    }
}

/// The pieces `mgmt_write` queues for `reply`: consecutive slices of at most [`MGMT_CHUNK_MAX`] bytes covering it exactly.
///
/// The cut is by byte, not by character (as in C); reports are ASCII. Concatenating the pieces gives back `reply`, so the chunking never
/// changes the bytes the host sees.
#[must_use]
pub const fn mgmt_chunks(reply: &[u8]) -> MgmtChunks<'_> {
    MgmtChunks { rest: reply }
}

/// Iterator returned by [`mgmt_chunks`].
#[derive(Clone, Debug)]
pub struct MgmtChunks<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for MgmtChunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        let (piece, rest) = self.rest.split_at(self.rest.len().min(MGMT_CHUNK_MAX));
        self.rest = rest;
        Some(piece)
    }
}

/// The greeting sent when the host raises DTR: `T-Dongle-S3 adapter <version>. Type help. Input is not echoed.\r\n`, or `tailnet` in place of
/// `adapter` in the gateway mode. (The bridge keeps the v0.1.x prefix `T-Dongle-S3 adapter`.)
///
/// # Errors
/// Whatever the sink returns.
pub fn write_greeting<W: fmt::Write>(w: &mut W, tailnet: bool, version: &str) -> fmt::Result {
    write!(w, "T-Dongle-S3 {} {version}. Type help. Input is not echoed.\r\n", if tailnet { "tailnet" } else { "adapter" })
}
