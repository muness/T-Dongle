//! A bounded, push-style JSON tokenizer.
//!
//! The control plane sends a MapResponse of unbounded size (the C's tests feed 300 KB maps and the limit is 1 MiB) to a device with a few hundred bytes of
//! parser state to spare. So the tokenizer never holds a document: it consumes arbitrary-sized chunks ([`Tokenizer::feed`]), keeps a fixed-size state and
//! hands every token to a [`TokenSink`] as an [`Event`] the moment it is complete. What a sink does not keep is gone, which is how unknown fields are skipped.
//!
//! # Bounds (the C's, `gateway_project_stream.inc`)
//!
//! | Bound | Value | C |
//! |---|---|---|
//! | nesting | [`MAX_DEPTH`] = 32 containers (the 33rd is [`JsonError::Depth`]) | `gs_frame frames[32]`, `p->depth == 32` |
//! | key | [`MAX_KEY_RAW`] = 126 raw bytes between the quotes (128 with them) | `char key[128]` |
//! | number / literal | [`MAX_SCALAR`] = 95 bytes | `char scalar[96]` |
//! | string kept | [`MAX_STRING`] = 256 decoded bytes; longer strings are validated to their end but only a prefix is delivered, flagged [`text_flags::TRUNCATED`] | the C streams discarded strings of any size and caps retained records at 4 KiB |
//!
//! # Strings and the two policies
//!
//! The C is lenient in one place and strict in another: a *discarded* string only has to be well formed JSON (`gp_string`: no control byte, a legal escape,
//! four hex digits after `\u`), so a lone surrogate or invalid UTF-8 in an ignored field passes; a *retained* string is then decoded by `gr_string`, which
//! refuses an embedded NUL and a lone surrogate. The tokenizer therefore decodes every string and reports what it found as [`text_flags`] on the [`Text`]
//! ([`Policy::CCompat`], the default): the projector refuses the flagged text only where it keeps it. [`Policy::Strict`] turns the same findings into
//! errors, which makes the tokenizer agree with `serde_json::from_slice::<Value>` (the differential tests rely on that).
//!
//! `\u0000` is delivered as a real NUL byte in [`Text::bytes`] and flagged [`text_flags::HAS_NUL`]; a lone surrogate is replaced by U+FFFD and flagged.
//! Raw bytes >= 0x80 are validated as UTF-8 incrementally across chunk boundaries.

use core::fmt;

/// Maximum container nesting (objects plus arrays) the tokenizer accepts. The C's `gs_frame frames[32]`.
pub const MAX_DEPTH: usize = 32;
/// Decoded bytes of one string that are delivered; the rest is validated and dropped (flag [`text_flags::TRUNCATED`]).
pub const MAX_STRING: usize = 256;
/// Longest raw key (bytes between the quotes, escapes counted undecoded). The C's `char key[128]` holds the quotes too.
pub const MAX_KEY_RAW: usize = 126;
/// Longest number or literal token. The C's `char scalar[96]`.
pub const MAX_SCALAR: usize = 95;

/// Findings about one string, as bits of [`Text::flags`].
pub mod text_flags {
    /// More than [`super::MAX_STRING`] decoded bytes: [`super::Text::bytes`] is a prefix (it may end inside a UTF-8 sequence).
    pub const TRUNCATED: u8 = 1;
    /// An escape decoded to NUL (`\u0000`): the C's retained-string decoder refuses it ("cannot represent an identity/key").
    pub const HAS_NUL: u8 = 2;
    /// A lone surrogate escape; the byte stream contains U+FFFD in its place.
    pub const BAD_SURROGATE: u8 = 4;
    /// A raw byte sequence that is not UTF-8 (the C does not check this; the projector refuses it where it keeps text).
    pub const BAD_UTF8: u8 = 8;
    /// The three findings that make a string unusable as text.
    pub const UNCLEAN: u8 = HAS_NUL | BAD_SURROGATE | BAD_UTF8;
}

/// How strictly strings are judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// The C's: bad UTF-8, lone surrogates and NUL escapes are findings (see [`text_flags`]), never errors.
    CCompat,
    /// RFC 8259 plus UTF-8 validity: bad UTF-8 and lone surrogates are errors (NUL escapes are legal JSON and stay a flag). Agrees with `serde_json`.
    Strict,
}

/// One decoded string (a key or a value).
#[derive(Clone, Copy, Debug)]
pub struct Text<'a> {
    /// Decoded bytes, at most [`MAX_STRING`]; a prefix when [`text_flags::TRUNCATED`] is set.
    pub bytes: &'a [u8],
    /// [`text_flags`].
    pub flags: u8,
    /// Decoded length of the whole string, which can exceed `bytes.len()`.
    pub decoded_len: u32,
    /// Raw length in the document including both quotes (what the C's projected text spends on it).
    pub raw_len: u32,
}

impl<'a> Text<'a> {
    /// True when the string has no NUL, surrogate or UTF-8 finding.
    pub fn is_clean(&self) -> bool {
        self.flags & text_flags::UNCLEAN == 0
    }
    /// True when only a prefix is delivered.
    pub fn is_truncated(&self) -> bool {
        self.flags & text_flags::TRUNCATED != 0
    }
    /// The text, or `None` when it is not clean. A truncated string yields its longest valid prefix (check [`Text::is_truncated`]).
    pub fn as_str(&self) -> Option<&'a str> {
        if !self.is_clean() {
            return None;
        }
        match core::str::from_utf8(self.bytes) {
            Ok(s) => Some(s),
            Err(e) => core::str::from_utf8(&self.bytes[..e.valid_up_to()]).ok(),
        }
    }
    /// ASCII case-insensitive comparison with `key` of the whole decoded string (what `cJSON_GetObjectItem` and `gp_key` do). A truncated string never
    /// matches.
    pub fn eq_ignore_ascii_case(&self, key: &str) -> bool {
        !self.is_truncated() && self.flags & text_flags::UNCLEAN == 0 && self.bytes.eq_ignore_ascii_case(key.as_bytes())
    }
}

/// One token.
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    /// `{`
    StartObject,
    /// `}`
    EndObject,
    /// `[`
    StartArray,
    /// `]`
    EndArray,
    /// An object key (always followed by that member's value).
    Key(Text<'a>),
    /// A string value.
    Str(Text<'a>),
    /// A number, exactly as written (validated against the JSON grammar; use [`number_i64`] / [`number_f64`]).
    Number(&'a [u8]),
    /// `true` / `false`.
    Bool(bool),
    /// `null`.
    Null,
}

/// What is wrong with the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonError {
    /// More than [`MAX_DEPTH`] open containers.
    Depth,
    /// A key longer than [`MAX_KEY_RAW`].
    KeyTooLong,
    /// A number or literal longer than [`MAX_SCALAR`].
    ScalarTooLong,
    /// A token starting like a number that is not one (`01`, `1.`, `1e+`, `-`).
    BadNumber,
    /// A token starting like `true`/`false`/`null` that is not exactly one.
    BadLiteral,
    /// A backslash not followed by one of `"\/bfnrt` or `u` and four hex digits.
    BadEscape,
    /// A control byte (< 0x20) inside a string.
    ControlChar,
    /// Invalid UTF-8 in a string ([`Policy::Strict`] only; otherwise [`text_flags::BAD_UTF8`]).
    BadUtf8,
    /// A lone surrogate escape ([`Policy::Strict`] only; otherwise [`text_flags::BAD_SURROGATE`]).
    LoneSurrogate,
    /// A byte that cannot start or continue what the grammar expects here.
    Unexpected(u8),
    /// Non-whitespace after the root value was complete.
    TrailingData,
    /// [`Tokenizer::finish`] before the root value was complete.
    Incomplete,
    /// The tokenizer already failed (or its sink refused an event); it must be [`Tokenizer::reset`].
    Poisoned,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Failure of [`Tokenizer::feed`] / [`Tokenizer::finish`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError<E> {
    /// The document is not acceptable JSON.
    Json(JsonError),
    /// The sink refused an event; the tokenizer is poisoned.
    Sink(E),
}

/// Receives the tokens of a document in order.
pub trait TokenSink {
    /// What the sink refuses with.
    type Error;
    /// One token. Returning `Err` stops the parse.
    fn event(&mut self, event: Event<'_>) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    RootValue,
    RootDone,
    ObjFirst,
    ObjKey,
    ObjColon,
    ObjValue,
    ObjAfter,
    ArrFirst,
    ArrValue,
    ArrAfter,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lex {
    None,
    Str,
    Scalar,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Esc {
    Plain,
    Backslash,
    Hex,
}

/// The tokenizer. Fixed size ([`Tokenizer::STATE_BYTES`]), no allocation, `const`-constructible so it can live in a `static`.
#[derive(Clone, Debug)]
pub struct Tokenizer {
    policy: Policy,
    kinds: u32,
    depth: u8,
    phase: Phase,
    lex: Lex,
    esc: Esc,
    is_key: bool,
    hex_n: u8,
    utf8_need: u8,
    utf8_lo: u8,
    utf8_hi: u8,
    flags: u8,
    hi: u16,
    acc: u16,
    len: u16,
    raw: u32,
    decoded: u32,
    consumed: u64,
    failed: Option<JsonError>,
    buf: [u8; MAX_STRING],
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::new(Policy::CCompat)
    }
}

impl Tokenizer {
    /// `size_of::<Tokenizer>()` on the compiling target (the "ADR needs bytes" figure).
    pub const STATE_BYTES: usize = core::mem::size_of::<Tokenizer>();

    /// A tokenizer at the start of a document.
    pub const fn new(policy: Policy) -> Self {
        Self {
            policy,
            kinds: 0,
            depth: 0,
            phase: Phase::RootValue,
            lex: Lex::None,
            esc: Esc::Plain,
            is_key: false,
            hex_n: 0,
            utf8_need: 0,
            utf8_lo: 0x80,
            utf8_hi: 0xbf,
            flags: 0,
            hi: 0,
            acc: 0,
            len: 0,
            raw: 0,
            decoded: 0,
            consumed: 0,
            failed: None,
            buf: [0; MAX_STRING],
        }
    }

    /// Forget everything and start a new document (the policy is kept).
    pub fn reset(&mut self) {
        let policy = self.policy;
        *self = Self::new(policy);
    }

    /// Currently open containers.
    pub fn depth(&self) -> usize {
        self.depth as usize
    }

    /// True once the root value is complete (only whitespace may follow).
    pub fn is_complete(&self) -> bool {
        self.failed.is_none() && self.phase == Phase::RootDone && self.lex == Lex::None
    }

    /// Bytes consumed so far (counting the ones that made it fail).
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// The error the tokenizer failed with, if it did.
    pub fn failure(&self) -> Option<JsonError> {
        self.failed
    }

    /// Consume `chunk`. Chunk boundaries are invisible: any split of a document into chunks (including empty ones) produces the same events and the same
    /// result. After an error every later call returns [`JsonError::Poisoned`] until [`Tokenizer::reset`].
    pub fn feed<S: TokenSink>(&mut self, chunk: &[u8], sink: &mut S) -> Result<(), ParseError<S::Error>> {
        if self.failed.is_some() {
            return Err(ParseError::Json(JsonError::Poisoned));
        }
        let mut i = 0;
        while i < chunk.len() {
            if self.lex == Lex::Str && self.esc == Esc::Plain && self.utf8_need == 0 && self.hi == 0 {
                let n = self.plain_run(&chunk[i..]);
                i += n;
                self.consumed += n as u64;
                if self.is_key && self.raw as usize > MAX_KEY_RAW {
                    return Err(self.fail(JsonError::KeyTooLong));
                }
                if i == chunk.len() {
                    break;
                }
            }
            let b = chunk[i];
            i += 1;
            self.consumed += 1;
            if let Err(e) = self.step(b, sink) {
                if let ParseError::Sink(_) = e {
                    self.failed = Some(JsonError::Poisoned);
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// End of input: completes a trailing number/literal at the root and requires a complete document.
    pub fn finish<S: TokenSink>(&mut self, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        if self.failed.is_some() {
            return Err(ParseError::Json(JsonError::Poisoned));
        }
        if self.lex == Lex::Scalar
            && let Err(e) = self.end_scalar(sink)
        {
            if let ParseError::Sink(_) = e {
                self.failed = Some(JsonError::Poisoned);
            }
            return Err(e);
        }
        if self.lex != Lex::None || self.phase != Phase::RootDone {
            return Err(self.fail(JsonError::Incomplete));
        }
        Ok(())
    }

    fn fail<E>(&mut self, e: JsonError) -> ParseError<E> {
        self.failed = Some(e);
        ParseError::Json(e)
    }

    /// Consume a run of plain ASCII string bytes (the common case of a long string) without per-byte dispatch.
    fn plain_run(&mut self, bytes: &[u8]) -> usize {
        let mut n = 0;
        let mut room = MAX_STRING - self.len as usize;
        let truncated = self.flags & text_flags::TRUNCATED != 0;
        let mut at = self.len as usize;
        for &b in bytes {
            if !(0x20..=0x7f).contains(&b) || b == b'"' || b == b'\\' {
                break;
            }
            if !truncated && room > 0 {
                self.buf[at] = b;
                at += 1;
                room -= 1;
            } else {
                self.flags |= text_flags::TRUNCATED;
            }
            n += 1;
        }
        // `n` is bounded by the chunk length; the counters saturate rather than wrap.
        self.len = at as u16;
        self.raw = self.raw.saturating_add(n as u32);
        self.decoded = self.decoded.saturating_add(n as u32);
        n
    }

    fn step<S: TokenSink>(&mut self, b: u8, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        match self.lex {
            Lex::Str => {
                if self.string_byte(b).map_err(|e| self.fail::<S::Error>(e))? {
                    self.end_string(sink)?;
                }
                Ok(())
            }
            Lex::Scalar => {
                if matches!(b, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n') {
                    self.end_scalar(sink)?;
                    self.structural(b, sink)
                } else {
                    if self.len as usize >= MAX_SCALAR {
                        return Err(self.fail(JsonError::ScalarTooLong));
                    }
                    self.buf[self.len as usize] = b;
                    self.len += 1;
                    Ok(())
                }
            }
            Lex::None => self.structural(b, sink),
        }
    }

    fn after_value(&self) -> Phase {
        if self.depth == 0 {
            Phase::RootDone
        } else if (self.kinds >> (self.depth - 1)) & 1 == 1 {
            Phase::ObjAfter
        } else {
            Phase::ArrAfter
        }
    }

    fn push<S: TokenSink>(&mut self, object: bool, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        if self.depth as usize >= MAX_DEPTH {
            return Err(self.fail(JsonError::Depth));
        }
        if object {
            self.kinds |= 1 << self.depth;
        } else {
            self.kinds &= !(1 << self.depth);
        }
        self.depth += 1;
        self.phase = if object { Phase::ObjFirst } else { Phase::ArrFirst };
        sink.event(if object { Event::StartObject } else { Event::StartArray }).map_err(ParseError::Sink)
    }

    fn pop<S: TokenSink>(&mut self, object: bool, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        self.depth -= 1;
        self.phase = self.after_value();
        sink.event(if object { Event::EndObject } else { Event::EndArray }).map_err(ParseError::Sink)
    }

    fn begin_string(&mut self, key: bool) {
        self.lex = Lex::Str;
        self.is_key = key;
        self.esc = Esc::Plain;
        self.len = 0;
        self.flags = 0;
        self.raw = 0;
        self.decoded = 0;
        self.hi = 0;
        self.utf8_need = 0;
    }

    fn structural<S: TokenSink>(&mut self, b: u8, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            return Ok(());
        }
        match self.phase {
            Phase::RootDone => Err(self.fail(JsonError::TrailingData)),
            Phase::RootValue | Phase::ObjValue | Phase::ArrFirst | Phase::ArrValue => match b {
                b']' if self.phase == Phase::ArrFirst => self.pop(false, sink),
                b'{' => self.push(true, sink),
                b'[' => self.push(false, sink),
                b'"' => {
                    self.begin_string(false);
                    Ok(())
                }
                b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                    self.lex = Lex::Scalar;
                    self.buf[0] = b;
                    self.len = 1;
                    Ok(())
                }
                _ => Err(self.fail(JsonError::Unexpected(b))),
            },
            Phase::ObjFirst => match b {
                b'}' => self.pop(true, sink),
                b'"' => {
                    self.begin_string(true);
                    Ok(())
                }
                _ => Err(self.fail(JsonError::Unexpected(b))),
            },
            Phase::ObjKey => match b {
                b'"' => {
                    self.begin_string(true);
                    Ok(())
                }
                _ => Err(self.fail(JsonError::Unexpected(b))),
            },
            Phase::ObjColon => match b {
                b':' => {
                    self.phase = Phase::ObjValue;
                    Ok(())
                }
                _ => Err(self.fail(JsonError::Unexpected(b))),
            },
            Phase::ObjAfter => match b {
                b',' => {
                    self.phase = Phase::ObjKey;
                    Ok(())
                }
                b'}' => self.pop(true, sink),
                _ => Err(self.fail(JsonError::Unexpected(b))),
            },
            Phase::ArrAfter => match b {
                b',' => {
                    self.phase = Phase::ArrValue;
                    Ok(())
                }
                b']' => self.pop(false, sink),
                _ => Err(self.fail(JsonError::Unexpected(b))),
            },
        }
    }

    fn end_scalar<S: TokenSink>(&mut self, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        self.lex = Lex::None;
        let n = self.len as usize;
        let ev = match self.buf[0] {
            b't' | b'f' | b'n' => match &self.buf[..n] {
                b"true" => Event::Bool(true),
                b"false" => Event::Bool(false),
                b"null" => Event::Null,
                _ => return Err(self.fail(JsonError::BadLiteral)),
            },
            _ => {
                if !valid_number(&self.buf[..n]) {
                    return Err(self.fail(JsonError::BadNumber));
                }
                Event::Number(&self.buf[..n])
            }
        };
        self.phase = self.after_value();
        sink.event(ev).map_err(ParseError::Sink)
    }

    fn end_string<S: TokenSink>(&mut self, sink: &mut S) -> Result<(), ParseError<S::Error>> {
        self.lex = Lex::None;
        let t = Text { bytes: &self.buf[..self.len as usize], flags: self.flags, decoded_len: self.decoded, raw_len: self.raw.saturating_add(2) };
        if self.is_key {
            self.phase = Phase::ObjColon;
            sink.event(Event::Key(t)).map_err(ParseError::Sink)
        } else {
            self.phase = self.after_value();
            sink.event(Event::Str(t)).map_err(ParseError::Sink)
        }
    }

    // ---- strings ------------------------------------------------------------------------------------------------------------------------------------

    fn push_bytes(&mut self, s: &[u8]) {
        self.decoded = self.decoded.saturating_add(s.len() as u32);
        if self.flags & text_flags::TRUNCATED != 0 {
            return;
        }
        let room = MAX_STRING - self.len as usize;
        let n = s.len().min(room);
        self.buf[self.len as usize..self.len as usize + n].copy_from_slice(&s[..n]);
        self.len += n as u16;
        if n < s.len() {
            self.flags |= text_flags::TRUNCATED;
        }
    }

    fn push_scalar(&mut self, c: u32) {
        if c == 0 {
            self.flags |= text_flags::HAS_NUL;
        }
        let mut b = [0u8; 4];
        let n = char::from_u32(c).unwrap_or('\u{fffd}').encode_utf8(&mut b).len();
        self.push_bytes(&b[..n]);
    }

    fn lone_surrogate(&mut self) -> Result<(), JsonError> {
        if self.policy == Policy::Strict {
            return Err(JsonError::LoneSurrogate);
        }
        self.flags |= text_flags::BAD_SURROGATE;
        self.push_scalar(0xfffd);
        Ok(())
    }

    fn flush_hi(&mut self) -> Result<(), JsonError> {
        if self.hi != 0 {
            self.hi = 0;
            self.lone_surrogate()?;
        }
        Ok(())
    }

    fn unicode(&mut self, v: u16) -> Result<(), JsonError> {
        if self.hi != 0 {
            if (0xdc00..=0xdfff).contains(&v) {
                let c = 0x10000 + (((self.hi as u32) - 0xd800) << 10) + (v as u32 - 0xdc00);
                self.hi = 0;
                self.push_scalar(c);
                return Ok(());
            }
            self.flush_hi()?;
        }
        if (0xd800..=0xdbff).contains(&v) {
            self.hi = v;
        } else if (0xdc00..=0xdfff).contains(&v) {
            self.lone_surrogate()?;
        } else {
            self.push_scalar(v as u32);
        }
        Ok(())
    }

    fn bad_utf8(&mut self) -> Result<(), JsonError> {
        if self.policy == Policy::Strict {
            return Err(JsonError::BadUtf8);
        }
        self.flags |= text_flags::BAD_UTF8;
        self.utf8_need = 0;
        Ok(())
    }

    /// One byte inside a string. `Ok(true)` when it was the closing quote.
    fn string_byte(&mut self, b: u8) -> Result<bool, JsonError> {
        match self.esc {
            Esc::Hex => {
                let d = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => return Err(JsonError::BadEscape),
                };
                self.raw = self.raw.saturating_add(1);
                self.acc = (self.acc << 4) | d as u16;
                self.hex_n += 1;
                if self.hex_n == 4 {
                    self.esc = Esc::Plain;
                    let v = self.acc;
                    self.unicode(v)?;
                }
            }
            Esc::Backslash => {
                self.raw = self.raw.saturating_add(1);
                let c = match b {
                    b'u' => {
                        self.esc = Esc::Hex;
                        self.acc = 0;
                        self.hex_n = 0;
                        return self.key_len_ok();
                    }
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    _ => return Err(JsonError::BadEscape),
                };
                self.esc = Esc::Plain;
                self.flush_hi()?;
                self.push_bytes(&[c]);
            }
            Esc::Plain => {
                if self.utf8_need > 0 {
                    if (self.utf8_lo..=self.utf8_hi).contains(&b) {
                        self.raw = self.raw.saturating_add(1);
                        self.push_bytes(&[b]);
                        self.utf8_need -= 1;
                        self.utf8_lo = 0x80;
                        self.utf8_hi = 0xbf;
                        return self.key_len_ok();
                    }
                    self.bad_utf8()?;
                }
                match b {
                    b'"' => {
                        self.flush_hi()?;
                        return Ok(true);
                    }
                    b'\\' => {
                        self.raw = self.raw.saturating_add(1);
                        self.esc = Esc::Backslash;
                    }
                    0..=0x1f => return Err(JsonError::ControlChar),
                    0x20..=0x7f => {
                        self.flush_hi()?;
                        self.raw = self.raw.saturating_add(1);
                        self.push_bytes(&[b]);
                    }
                    _ => {
                        self.flush_hi()?;
                        self.raw = self.raw.saturating_add(1);
                        // Lead byte: how many continuation bytes follow and what the first may be (rejects overlongs, surrogates, > U+10FFFF).
                        let (need, lo, hi) = match b {
                            0xc2..=0xdf => (1, 0x80, 0xbf),
                            0xe0 => (2, 0xa0, 0xbf),
                            0xe1..=0xec | 0xee | 0xef => (2, 0x80, 0xbf),
                            0xed => (2, 0x80, 0x9f),
                            0xf0 => (3, 0x90, 0xbf),
                            0xf1..=0xf3 => (3, 0x80, 0xbf),
                            0xf4 => (3, 0x80, 0x8f),
                            _ => (0, 0, 0),
                        };
                        if need == 0 {
                            self.bad_utf8()?;
                        } else {
                            self.utf8_need = need;
                            self.utf8_lo = lo;
                            self.utf8_hi = hi;
                        }
                        self.push_bytes(&[b]);
                    }
                }
            }
        }
        self.key_len_ok()
    }

    fn key_len_ok(&self) -> Result<bool, JsonError> {
        if self.is_key && self.raw as usize > MAX_KEY_RAW { Err(JsonError::KeyTooLong) } else { Ok(false) }
    }
}

/// RFC 8259 number grammar: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
fn valid_number(s: &[u8]) -> bool {
    let mut i = 0;
    if s.get(i) == Some(&b'-') {
        i += 1;
    }
    match s.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while matches!(s.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        _ => return false,
    }
    if s.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while matches!(s.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(s.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while matches!(s.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    i == s.len()
}

/// The value of an integer literal that fits `i64` exactly (no fraction, no exponent); `None` otherwise.
pub fn number_i64(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, s),
    };
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v: i128 = 0;
    for d in digits {
        v = v * 10 + (d - b'0') as i128;
    }
    if neg {
        v = -v;
    }
    i64::try_from(v).ok()
}

/// The value of a number as `f64` (what the C's `valuedouble` holds; overflow gives infinity), `None` if `s` is not a number.
pub fn number_f64(s: &[u8]) -> Option<f64> {
    core::str::from_utf8(s).ok()?.parse::<f64>().ok()
}

/// The C's `json_nesting_within` (`ml_coord.c`): does the text stay within `max_depth` levels of `{`/`[` outside strings? Cheap pre-check for the small
/// control documents (`/key`: [`DEPTH_KEY`], RegisterResponse: [`DEPTH_REGISTER`]) that are parsed by a recursive parser.
pub fn nesting_within(text: &[u8], max_depth: u32) -> bool {
    let mut depth = 0u32;
    let mut in_string = false;
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        if in_string {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'{' || c == b'[' {
            depth += 1;
            if depth > max_depth {
                return false;
            }
        } else if (c == b'}' || c == b']') && depth > 0 {
            depth -= 1;
        }
        i += 1;
    }
    true
}

/// Depth bound of the `/key` response (`ML_JSON_DEPTH_KEY`).
pub const DEPTH_KEY: u32 = 4;
/// Depth bound of the RegisterResponse (`ML_JSON_DEPTH_REGISTER`).
pub const DEPTH_REGISTER: u32 = 16;
