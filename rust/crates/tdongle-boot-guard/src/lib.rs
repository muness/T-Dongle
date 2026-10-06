//! What survives a hang or a panic, and what the next boot does about it.
//!
//! A board whose firmware hangs before USB is up cannot be reflashed without the BOOT button, so every Rust image follows three rules, and this crate holds the
//! pure part of them (the hardware part is a few lines of RTC memory, watchdog and panic-handler glue in each image):
//!
//! 1. **USB and the console come up first**, then everything that can block (storage, radio, scan, connect). The step being run is recorded as a [`Stage`].
//! 2. **Watchdogs are armed**; a reset caused by one is reported (`reset_reason`) together with the stage that was running (`previous_stage`).
//! 3. **A panic leaves its location and message in RTC memory** ([`Record::note_panic`]) and resets; the next `boot-status` reports it (`previous_panic`).
//!
//! If the last [`SAFE_MODE_AFTER`] boots each failed to stay up for the stable period (they reset without [`Record::mark_stable`]), the next boot is a
//! **safe mode** boot: console only, none of the steps that can hang. Safe mode is sticky until a power cycle or the console's `normal` command, so a bad
//! saved setting or a radio fault can never again make the device unreachable.
//!
//! Pure: `no_std`, no allocation, no unsafe code; the record is `[u32; WORDS]` so that it can live in RTC memory that is valid for any bit pattern.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt::{self, Write};

pub mod report;
pub mod watch;

#[cfg(test)]
extern crate std;

/// Consecutive unstable boots after which the next boot is a safe-mode boot.
pub const SAFE_MODE_AFTER: u8 = 2;
/// How long (ms) the firmware must stay up before the boot counts as stable.
pub const STABLE_AFTER_MS: u64 = 30_000;
/// Longest stored panic text, in bytes.
pub const MSG_MAX: usize = 96;
/// Longest stored hang culprit or operation tag, in bytes.
pub const TAG_MAX: usize = 24;
/// Size of the record in 32-bit words: header, panic text, two tags.
pub const WORDS: usize = 2 + MSG_MAX / 4 + 2 * (TAG_MAX / 4) + 2;

const MAGIC: u32 = 0x7d6c_b007;

/// The step of boot that was running. Stored as one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    /// Early init: heap, scheduler.
    Boot = 0,
    /// USB device and console.
    Usb = 1,
    /// Reading saved settings from flash.
    Settings = 2,
    /// Radio driver initialisation.
    RadioInit = 3,
    /// Scanning for saved networks.
    Scan = 4,
    /// Associating.
    Connect = 5,
    /// Everything started.
    Running = 6,
}

impl Stage {
    /// Every stage, in boot order.
    pub const ALL: [Self; 7] = [Self::Boot, Self::Usb, Self::Settings, Self::RadioInit, Self::Scan, Self::Connect, Self::Running];

    /// The name `boot-status` prints.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Usb => "usb",
            Self::Settings => "settings",
            Self::RadioInit => "radio_init",
            Self::Scan => "scan",
            Self::Connect => "connect",
            Self::Running => "running",
        }
    }

    /// The stage stored as `byte`, if it is one.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|s| *s as u8 == byte)
    }
}

/// The persistent record (lives in RTC memory across software and watchdog resets, not across power loss).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    magic: u32,
    unstable_boots: u8,
    stage: u8,
    panics: u8,
    msg_len: u8,
    msg: [u8; MSG_MAX],
    /// The task the supervisor found making no progress, recorded just before it reset the chip.
    hang: Tag,
    /// The risky operation in progress (a driver call, a long step) when the chip last reset: set before it, cleared after. A reset with this set names the call that never returned.
    op: Tag,
}

/// A short text that survives in RTC memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    len: u8,
    text: [u8; TAG_MAX],
}

impl Tag {
    /// No text.
    pub const EMPTY: Self = Self { len: 0, text: [0; TAG_MAX] };

    /// `s`, cut at a character boundary to [`TAG_MAX`] bytes.
    #[must_use]
    pub fn new(s: &str) -> Self {
        let mut n = s.len().min(TAG_MAX);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut text = [0; TAG_MAX];
        text[..n].copy_from_slice(&s.as_bytes()[..n]);
        Self { len: n as u8, text }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.text[..usize::from(self.len).min(TAG_MAX)]).unwrap_or("")
    }

    fn valid(&self) -> bool {
        usize::from(self.len) <= TAG_MAX && core::str::from_utf8(&self.text[..usize::from(self.len)]).is_ok()
    }
}

/// What the previous boot left behind, captured by [`Record::begin_boot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Previous {
    /// The stage that was running when the previous boot ended, if there was a previous boot.
    pub stage: Option<Stage>,
    /// Boots in a row that did not stay up for [`STABLE_AFTER_MS`], before this one.
    pub unstable_boots: u8,
    /// Panics recorded since the last stable boot.
    pub panics: u8,
    msg_len: u8,
    msg: [u8; MSG_MAX],
    /// The task a supervisor found stalled before the previous reset, or empty.
    pub hang: Tag,
    /// The operation that was in progress when the previous boot ended, or empty.
    pub op: Tag,
}

impl Previous {
    /// The previous panic's location and message; empty if the previous boot did not panic.
    #[must_use]
    pub fn panic_text(&self) -> &str {
        core::str::from_utf8(&self.msg[..usize::from(self.msg_len)]).unwrap_or("")
    }
}

/// The decision of [`Record::begin_boot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Boot {
    /// Run the console only: no storage, radio, scan or connect.
    pub safe_mode: bool,
    /// What the previous boot left.
    pub previous: Previous,
}

/// Truncating writer into a fixed buffer; cuts at a character boundary so the text stays UTF-8.
struct Fixed<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Write for Fixed<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

impl Record {
    /// A record with nothing in it (what a power-on boot starts from).
    pub const EMPTY: Self = Self { magic: MAGIC, unstable_boots: 0, stage: 0, panics: 0, msg_len: 0, msg: [0; MSG_MAX], hang: Tag::EMPTY, op: Tag::EMPTY };

    /// Decode RTC memory. Anything that is not a well-formed record (power-on garbage, a write cut short by a reset) is an empty record.
    #[must_use]
    pub fn from_words(words: &[u32; WORDS]) -> Self {
        let mut bytes = [0u8; WORDS * 4];
        for (i, word) in words.iter().enumerate() {
            bytes[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        let tag_at = |at: usize| {
            let mut text = [0u8; TAG_MAX];
            text.copy_from_slice(&bytes[at + 1..at + 1 + TAG_MAX]);
            Tag { len: bytes[at], text }
        };
        let mut msg = [0u8; MSG_MAX];
        msg.copy_from_slice(&bytes[8..8 + MSG_MAX]);
        let hang_at = 8 + MSG_MAX;
        let rec = Self {
            magic: words[0],
            unstable_boots: bytes[4],
            stage: bytes[5],
            panics: bytes[6],
            msg_len: bytes[7],
            msg,
            hang: tag_at(hang_at),
            op: tag_at(hang_at + 1 + TAG_MAX),
        };
        if rec.magic != MAGIC
            || usize::from(rec.msg_len) > MSG_MAX
            || core::str::from_utf8(&rec.msg[..usize::from(rec.msg_len)]).is_err()
            || !rec.hang.valid()
            || !rec.op.valid()
        {
            return Self::EMPTY;
        }
        rec
    }

    /// Encode for RTC memory.
    #[must_use]
    pub fn to_words(&self) -> [u32; WORDS] {
        let mut bytes = [0u8; WORDS * 4];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4] = self.unstable_boots;
        bytes[5] = self.stage;
        bytes[6] = self.panics;
        bytes[7] = self.msg_len;
        bytes[8..8 + MSG_MAX].copy_from_slice(&self.msg);
        let hang_at = 8 + MSG_MAX;
        bytes[hang_at] = self.hang.len;
        bytes[hang_at + 1..hang_at + 1 + TAG_MAX].copy_from_slice(&self.hang.text);
        let op_at = hang_at + 1 + TAG_MAX;
        bytes[op_at] = self.op.len;
        bytes[op_at + 1..op_at + 1 + TAG_MAX].copy_from_slice(&self.op.text);
        let mut words = [0u32; WORDS];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
        }
        words
    }

    /// Start a boot: capture what the previous boot left, count this boot as unstable until [`Self::mark_stable`], clear the stage, and decide on safe mode.
    pub fn begin_boot(&mut self) -> Boot {
        let previous = Previous {
            stage: Stage::from_byte(self.stage).filter(|_| self.unstable_boots > 0 || self.panics > 0 || self.stage != 0),
            unstable_boots: self.unstable_boots,
            panics: self.panics,
            msg_len: self.msg_len,
            msg: self.msg,
            hang: self.hang,
            op: self.op,
        };
        let safe_mode = self.unstable_boots >= SAFE_MODE_AFTER;
        self.unstable_boots = self.unstable_boots.saturating_add(1);
        self.stage = Stage::Boot as u8;
        self.op = Tag::EMPTY;
        // The previous panic text stays in the record until a stable boot clears it, so a second boot that is also cut short still reports it.
        Boot { safe_mode, previous }
    }

    /// Record the step about to run.
    pub fn note_stage(&mut self, stage: Stage) {
        self.stage = stage as u8;
    }

    /// Record the operation about to run (an empty `tag` when it is over). If the chip resets with this set, the next boot reports it as `previous_op`.
    pub fn note_op(&mut self, tag: &str) {
        self.op = Tag::new(tag);
    }

    /// Record the task a supervisor found stalled, just before it resets the chip.
    pub fn note_hang(&mut self, task: &str) {
        self.hang = Tag::new(task);
    }

    /// The step recorded last.
    #[must_use]
    pub fn stage(&self) -> Option<Stage> {
        Stage::from_byte(self.stage)
    }

    /// Record a panic: `file:line message`, truncated to [`MSG_MAX`] bytes.
    pub fn note_panic(&mut self, args: fmt::Arguments<'_>) {
        let mut w = Fixed { buf: &mut self.msg, len: 0 };
        // Writing to `Fixed` cannot fail; a failing `Display` impl just leaves the text it already wrote.
        let _ = w.write_fmt(args);
        self.msg_len = u8::try_from(w.len).unwrap_or(u8::MAX);
        self.panics = self.panics.saturating_add(1);
    }

    /// The firmware has stayed up for [`STABLE_AFTER_MS`]. In a safe-mode boot nothing changes: safe mode stays until a power cycle or [`Self::leave_safe_mode`].
    pub fn mark_stable(&mut self, safe_mode: bool) {
        if !safe_mode {
            self.clear();
        }
    }

    /// Clear the failure history (the console's `normal`, and before a deliberate reset such as `bootloader`).
    pub fn leave_safe_mode(&mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        self.unstable_boots = 0;
        self.panics = 0;
        self.msg_len = 0;
        self.msg = [0; MSG_MAX];
        self.hang = Tag::EMPTY;
    }
}

#[cfg(test)]
mod tests;
