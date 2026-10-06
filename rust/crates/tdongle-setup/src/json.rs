//! The `/command` body: what `cJSON_Parse` (cJSON 1.7.19, ESP-IDF v5.5.5) plus a few `cJSON_GetObjectItem` calls accept, without
//! allocating, and the JSON text the handlers answer with (`cJSON_PrintUnformatted` shapes).
//!
//! cJSON behaviours that decide what the portal accepts and are kept:
//! * the body is a C string: it ends at its first NUL byte; one UTF-8 BOM is skipped; whitespace is any byte up to `0x20`; text after
//!   the first complete value is **ignored** (`cJSON_Parse` does not require the end of the text);
//! * containers nest to at most 1000 levels;
//! * a number is the longest `strtod` prefix of a run of `0-9 + - e E .` (it may be shorter than the run: the rest is then a syntax error
//!   in a container, ignored at the top level);
//! * strings keep raw control and high bytes, decode `\" \\ \/ \b \f \n \r \t` and `\uXXXX` (with surrogate pairs; a lone surrogate is an
//!   error), and a decoded NUL ends the string for every later `strlen`;
//! * `cJSON_GetObjectItem` is **case-insensitive, the first match wins whatever its type**, and a field of the wrong type reads as absent
//!   to `cJSON_GetStringValue` / `cJSON_IsNumber`.

use core::str::FromStr;

/// The deepest container nesting cJSON accepts (`CJSON_NESTING_LIMIT`).
pub const NESTING_LIMIT: usize = 1000;
/// Room for every decoded string of a body of [`crate::http::MAX_BODY`] bytes.
const ARENA: usize = crate::http::MAX_BODY + 8;

/// One looked-up member.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Val {
    /// The key is not in the object.
    Absent,
    /// A string: range in the arena, already cut at the first NUL.
    Str(u16, u16),
    /// A number (`valuedouble`).
    Num(f64),
    /// `true`
    True,
    /// `false`
    False,
    /// `null`, an array or an object.
    Other,
}

/// The members `/command` reads.
#[derive(Clone, Debug)]
pub struct Fields {
    arena: [u8; ARENA],
    used: usize,
    /// `action`
    pub action: Val,
    /// `ssid`
    pub ssid: Val,
    /// `password`
    pub password: Val,
    /// `name`
    pub name: Val,
    /// `slot`
    pub slot: Val,
    /// `priority`
    pub priority: Val,
    /// `mode`
    pub mode: Val,
    /// `label`
    pub label: Val,
    /// `key`
    pub key: Val,
    /// `id`
    pub id: Val,
    /// `enabled`
    pub enabled: Val,
}

impl Fields {
    /// `cJSON_GetStringValue`: the string, or `None` for an absent or non-string member.
    #[must_use]
    pub fn string(&self, v: Val) -> Option<&[u8]> {
        if let Val::Str(a, n) = v { Some(&self.arena[usize::from(a)..usize::from(a) + usize::from(n)]) } else { None }
    }
}

const KEYS: [&[u8]; 11] = [b"action", b"ssid", b"password", b"name", b"slot", b"priority", b"mode", b"label", b"key", b"id", b"enabled"];

struct P<'a> {
    t: &'a [u8],
    at: usize,
}

impl P<'_> {
    fn peek(&self) -> u8 {
        self.t.get(self.at).copied().unwrap_or(0)
    }
    fn eof(&self) -> bool {
        self.at >= self.t.len()
    }
    fn ws(&mut self) {
        while !self.eof() && self.t[self.at] <= 32 {
            self.at += 1;
        }
    }
    fn lit(&mut self, s: &[u8]) -> bool {
        let hit = self.t[self.at..].starts_with(s);
        if hit {
            self.at += s.len();
        }
        hit
    }

    /// Decode a string into `out` (stores at most `out.len()` bytes); returns the decoded length, or `None` on a syntax error.
    fn string(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.eof() || self.t[self.at] != b'"' {
            return None;
        }
        self.at += 1;
        let mut n = 0;
        let mut put = |b: u8, n: &mut usize| {
            if let Some(d) = out.get_mut(*n) {
                *d = b;
            }
            *n += 1;
        };
        loop {
            if self.eof() {
                return None;
            }
            let b = self.t[self.at];
            self.at += 1;
            match b {
                b'"' => return Some(n),
                b'\\' => {
                    if self.eof() {
                        return None;
                    }
                    let e = self.t[self.at];
                    self.at += 1;
                    match e {
                        b'b' => put(8, &mut n),
                        b'f' => put(12, &mut n),
                        b'n' => put(b'\n', &mut n),
                        b'r' => put(b'\r', &mut n),
                        b't' => put(b'\t', &mut n),
                        b'"' | b'\\' | b'/' => put(e, &mut n),
                        b'u' => {
                            let first = self.hex4()?;
                            let cp = if (0xdc00..=0xdfff).contains(&first) {
                                return None;
                            } else if (0xd800..=0xdbff).contains(&first) {
                                if !self.t[self.at..].starts_with(b"\\u") {
                                    return None;
                                }
                                self.at += 2;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return None;
                                }
                                0x10000 + (((first & 0x3ff) << 10) | (second & 0x3ff))
                            } else {
                                first
                            };
                            let mut buf = [0u8; 4];
                            let s = char::from_u32(cp).unwrap_or('\u{fffd}').encode_utf8(&mut buf);
                            for &c in s.as_bytes() {
                                put(c, &mut n);
                            }
                        }
                        _ => return None,
                    }
                }
                _ => put(b, &mut n),
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let d = self.t.get(self.at..self.at + 4)?;
        let mut v = 0;
        for &c in d {
            v = v << 4 | char::from(c).to_digit(16)?;
        }
        self.at += 4;
        Some(v)
    }

    fn number(&mut self) -> Option<f64> {
        let rest = &self.t[self.at..];
        let run = rest.iter().take_while(|b| matches!(b, b'0'..=b'9' | b'+' | b'-' | b'e' | b'E' | b'.')).count();
        let used = strtod_prefix(&rest[..run]);
        if used == 0 {
            return None;
        }
        let v = f64::from_str(core::str::from_utf8(&rest[..used]).ok()?).ok()?;
        self.at += used;
        Some(v)
    }
}

/// Length of the longest prefix C `strtod` reads as a decimal number (see `tdongle_nvs_format::profile_json`).
fn strtod_prefix(s: &[u8]) -> usize {
    let digits = |from: usize| s[from.min(s.len())..].iter().take_while(|b| b.is_ascii_digit()).count();
    let mut i = usize::from(matches!(s.first(), Some(b'+' | b'-')));
    let int = digits(i);
    i += int;
    let mut frac = 0;
    if s.get(i) == Some(&b'.') {
        frac = digits(i + 1);
        if int > 0 || frac > 0 {
            i += 1 + frac;
        }
    }
    if int == 0 && frac == 0 {
        return 0;
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(s.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let exp = digits(j);
        if exp > 0 {
            i = j + exp;
        }
    }
    i
}

/// Validate one value iteratively (no recursion, at most [`NESTING_LIMIT`] levels in a bit stack), starting `base` levels deep.
fn skip(p: &mut P<'_>, base: usize) -> Option<()> {
    let mut stack = [0u8; NESTING_LIMIT.div_ceil(8)]; // bit set: object
    let mut depth = base;
    loop {
        // one value
        if p.eof() {
            return None;
        }
        match p.peek() {
            b'n' if p.lit(b"null") => {}
            b'f' if p.lit(b"false") => {}
            b't' if p.lit(b"true") => {}
            b'"' => {
                p.string(&mut [])?;
            }
            b'-' | b'0'..=b'9' => {
                p.number()?;
            }
            c @ (b'[' | b'{') => {
                if depth >= NESTING_LIMIT {
                    return None;
                }
                let obj = c == b'{';
                p.at += 1;
                p.ws();
                if !p.eof() && p.peek() == if obj { b'}' } else { b']' } {
                    p.at += 1;
                } else {
                    set_kind(&mut stack, depth, obj);
                    depth += 1;
                    if obj {
                        key(p)?;
                    }
                    continue;
                }
            }
            _ => return None,
        }
        // the value is complete: separators and closers
        loop {
            p.ws();
            if depth == base {
                return Some(());
            }
            let obj = is_obj(&stack, depth - 1);
            if p.eof() {
                return None;
            }
            match p.peek() {
                b',' => {
                    p.at += 1;
                    p.ws();
                    if obj {
                        key(p)?;
                    }
                    break;
                }
                b'}' if obj => {}
                b']' if !obj => {}
                _ => return None,
            }
            p.at += 1;
            depth -= 1;
        }
    }
}

/// `"key" :` of an object member, discarding the key.
fn key(p: &mut P<'_>) -> Option<()> {
    p.string(&mut [])?;
    p.ws();
    if p.eof() || p.peek() != b':' {
        return None;
    }
    p.at += 1;
    p.ws();
    Some(())
}

fn is_obj(stack: &[u8], d: usize) -> bool {
    stack[d / 8] >> (d % 8) & 1 == 1
}

fn set_kind(stack: &mut [u8], d: usize, obj: bool) {
    if obj {
        stack[d / 8] |= 1 << (d % 8);
    } else {
        stack[d / 8] &= !(1 << (d % 8));
    }
}

/// Parse a `/command` body. `None` is cJSON's failure (answered "Invalid JSON").
#[must_use]
pub fn parse(body: &[u8]) -> Option<Fields> {
    let text = body.split(|&b| b == 0).next().unwrap_or(&[]);
    let text = if text.len() + 1 >= 4 && text.starts_with(&[0xef, 0xbb, 0xbf]) { &text[3..] } else { text };
    let mut p = P { t: text, at: 0 };
    p.ws();
    let root = p.at;
    skip(&mut p, 0)?;
    let mut f = Fields {
        arena: [0; ARENA],
        used: 0,
        action: Val::Absent,
        ssid: Val::Absent,
        password: Val::Absent,
        name: Val::Absent,
        slot: Val::Absent,
        priority: Val::Absent,
        mode: Val::Absent,
        label: Val::Absent,
        key: Val::Absent,
        id: Val::Absent,
        enabled: Val::Absent,
    };
    // The document is valid: walk the root object's members.
    p.at = root;
    if p.peek() != b'{' {
        return Some(f);
    }
    p.at += 1;
    p.ws();
    if p.peek() == b'}' {
        return Some(f);
    }
    loop {
        let mut kb = [0u8; 16];
        let n = p.string(&mut kb)?;
        p.ws();
        p.at += 1; // ':'
        p.ws();
        let eff = kb[..n.min(16)].iter().position(|&b| b == 0).unwrap_or(n.min(16));
        let hit = if n > 16 && eff == 16 { None } else { KEYS.iter().position(|k| k.eq_ignore_ascii_case(&kb[..eff])) };
        let wanted = hit.filter(|&i| matches!(slot_of(&f, i), Val::Absent));
        let v = match (wanted, p.peek()) {
            (Some(_), b'"') => {
                let at = f.used;
                let n = p.string(&mut f.arena[at..])?;
                let eff = f.arena[at..at + n].iter().position(|&b| b == 0).unwrap_or(n);
                f.used = at + n;
                Val::Str(at as u16, eff as u16)
            }
            (Some(_), b'-' | b'0'..=b'9') => Val::Num(p.number()?),
            (Some(_), b't') if p.lit(b"true") => Val::True,
            (Some(_), b'f') if p.lit(b"false") => Val::False,
            _ => {
                skip(&mut p, 1)?;
                Val::Other
            }
        };
        if let Some(i) = wanted {
            store(&mut f, i, v);
        }
        p.ws();
        if p.peek() == b',' {
            p.at += 1;
            p.ws();
        } else {
            return Some(f);
        }
    }
}

fn slot_of(f: &Fields, i: usize) -> Val {
    [f.action, f.ssid, f.password, f.name, f.slot, f.priority, f.mode, f.label, f.key, f.id, f.enabled][i]
}

fn store(f: &mut Fields, i: usize, v: Val) {
    let dst = match i {
        0 => &mut f.action,
        1 => &mut f.ssid,
        2 => &mut f.password,
        3 => &mut f.name,
        4 => &mut f.slot,
        5 => &mut f.priority,
        6 => &mut f.mode,
        7 => &mut f.label,
        8 => &mut f.key,
        9 => &mut f.id,
        _ => &mut f.enabled,
    };
    *dst = v;
}

/// Writes JSON text into a fixed buffer, the way `cJSON_PrintUnformatted` would print the objects the handlers build. Overflow is
/// recorded ([`Json::overflowed`]) and nothing is written past the end.
#[derive(Debug)]
pub struct Json<'a> {
    out: &'a mut [u8],
    len: usize,
    over: bool,
}

impl<'a> Json<'a> {
    /// Start an empty document in `out`.
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0, over: false }
    }
    /// Append raw bytes.
    pub fn raw(&mut self, s: &[u8]) -> &mut Self {
        if self.len + s.len() > self.out.len() {
            self.over = true;
        } else {
            self.out[self.len..self.len + s.len()].copy_from_slice(s);
            self.len += s.len();
        }
        self
    }
    /// A string with cJSON's escaping: `"` `\\` and control characters (`\b \f \n \r \t`, others `\u00xx`); other bytes are raw.
    pub fn string(&mut self, s: &[u8]) -> &mut Self {
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
                    self.raw(&[b'\\', b'u', b'0', b'0', HEX[usize::from(c >> 4)], HEX[usize::from(c & 15)]])
                }
                _ => self.raw(&[c]),
            };
        }
        self.raw(b"\"")
    }
    /// A signed integer in decimal.
    pub fn int(&mut self, v: i64) -> &mut Self {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut n = v.unsigned_abs();
        loop {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        if v < 0 {
            self.raw(b"-");
        }
        self.raw(&buf[i..])
    }
    /// `true` or `false`.
    pub fn boolean(&mut self, v: bool) -> &mut Self {
        self.raw(if v { b"true" } else { b"false" })
    }
    /// The text so far.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.out[..self.len]
    }
    /// The buffer was too small (cJSON: out of memory).
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.over
    }
}
