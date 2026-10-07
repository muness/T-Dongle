//! Bounded JSON for the control documents: a writer into a caller buffer, the C's nesting pre-check, and a one-pass scanner that validates a document
//! and hands back chosen top-level fields. No allocation; a document the scanner accepts is well formed and no deeper than the bound.

use tdongle_tailnet_types::{Key32, hex_encode};

/// The writer ran out of room (the output is cut; nothing is partially valid, discard it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overflow;

/// A JSON writer into a caller slice. Errors are sticky: after the first overflow every call is a no-op and [`JsonWriter::finish`] reports it.
#[derive(Debug)]
pub struct JsonWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflow: bool,
    /// One bit per open container: has it got a member already?
    commas: u32,
    depth: u8,
    after_key: bool,
}

const MAX_WRITE_DEPTH: u8 = 31;

impl<'a> JsonWriter<'a> {
    /// Write into `buf` from the start.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0, overflow: false, commas: 0, depth: 0, after_key: false }
    }

    fn put(&mut self, b: &[u8]) {
        if self.overflow || self.buf.len() - self.len < b.len() {
            self.overflow = true;
            return;
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }

    /// Comma before a member or element (not after a key).
    fn sep(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        let bit = 1u32 << self.depth;
        if self.commas & bit != 0 {
            self.put(b",");
        }
        self.commas |= bit;
    }

    fn open(&mut self, c: &[u8]) {
        self.sep();
        self.put(c);
        if self.depth >= MAX_WRITE_DEPTH {
            self.overflow = true;
            return;
        }
        self.depth += 1;
        self.commas &= !(1u32 << self.depth);
    }

    fn close(&mut self, c: &[u8]) {
        self.depth = self.depth.saturating_sub(1);
        self.put(c);
    }

    /// `{`
    pub fn begin_object(&mut self) {
        self.open(b"{")
    }
    /// `}`
    pub fn end_object(&mut self) {
        self.close(b"}")
    }
    /// `[`
    pub fn begin_array(&mut self) {
        self.open(b"[")
    }
    /// `]`
    pub fn end_array(&mut self) {
        self.close(b"]")
    }

    fn string_body(&mut self, s: &str) {
        self.put(b"\"");
        let bytes = s.as_bytes();
        let mut start = 0;
        for (i, &c) in bytes.iter().enumerate() {
            let esc: Option<&[u8]> = match c {
                b'"' => Some(b"\\\""),
                b'\\' => Some(b"\\\\"),
                b'\n' => Some(b"\\n"),
                b'\r' => Some(b"\\r"),
                b'\t' => Some(b"\\t"),
                0x08 => Some(b"\\b"),
                0x0c => Some(b"\\f"),
                0..=0x1f => None,
                _ => continue,
            };
            self.put(&bytes[start..i]);
            match esc {
                Some(e) => self.put(e),
                None => {
                    let mut u = *b"\\u00__";
                    hex_encode(&[c], &mut u[4..6]);
                    self.put(&u);
                }
            }
            start = i + 1;
        }
        self.put(&bytes[start..]);
        self.put(b"\"");
    }

    /// An object key (`"k":`); the next call writes its value.
    pub fn key(&mut self, k: &str) {
        self.sep();
        self.string_body(k);
        self.put(b":");
        self.after_key = true;
    }

    /// A string value (escaped).
    pub fn string(&mut self, s: &str) {
        self.sep();
        self.string_body(s);
    }

    /// A string value `prefix` + lower-case hex of `key` (`nodekey:..`, `discokey:..`, `chalresp:..`).
    pub fn key_string(&mut self, prefix: &str, key: &Key32) {
        self.sep();
        let mut hex = [0u8; 64];
        key.to_hex(&mut hex);
        self.put(b"\"");
        self.put(prefix.as_bytes());
        self.put(&hex);
        self.put(b"\"");
    }

    /// An unsigned integer.
    pub fn number(&mut self, mut n: u64) {
        self.sep();
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.put(&tmp[i..]);
    }

    /// `true` / `false`.
    pub fn boolean(&mut self, v: bool) {
        self.sep();
        self.put(if v { b"true" } else { b"false" });
    }

    /// `"k":"v"`.
    pub fn field_str(&mut self, k: &str, v: &str) {
        self.key(k);
        self.string(v);
    }
    /// `"k":n`.
    pub fn field_num(&mut self, k: &str, v: u64) {
        self.key(k);
        self.number(v);
    }
    /// `"k":true|false`.
    pub fn field_bool(&mut self, k: &str, v: bool) {
        self.key(k);
        self.boolean(v);
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Nothing written yet?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The length of the finished document, or [`Overflow`].
    pub fn finish(self) -> Result<usize, Overflow> {
        if self.overflow || self.depth != 0 { Err(Overflow) } else { Ok(self.len) }
    }
}

/// The C's `json_nesting_within`: every `{`/`[` outside a string is a level; true if the first `length` bytes never exceed `max_depth` levels. It is a
/// pre-check that is at least as strict as any recursive parser's descent, and it never reads past `text`.
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

/// What the scanner found at a top-level key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// A string; the raw bytes between the quotes (escapes undecoded: use [`unescape`]).
    Str(&'a [u8]),
    /// `true` / `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// A number (raw text).
    Number(&'a [u8]),
    /// An object or array (skipped, but validated).
    Container,
}

/// Why a document was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonError {
    /// Not well-formed JSON, or not an object at the top.
    Malformed,
    /// Nested deeper than the bound.
    TooDeep,
    /// Bytes after the document and trailing data was not allowed.
    Trailing,
}

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn string(&mut self) -> Result<&'a [u8], JsonError> {
        if self.peek() != Some(b'"') {
            return Err(JsonError::Malformed);
        }
        self.i += 1;
        let start = self.i;
        loop {
            let c = *self.s.get(self.i).ok_or(JsonError::Malformed)?;
            match c {
                b'"' => {
                    let r = &self.s[start..self.i];
                    self.i += 1;
                    return Ok(r);
                }
                b'\\' => {
                    let e = *self.s.get(self.i + 1).ok_or(JsonError::Malformed)?;
                    match e {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.i += 2,
                        b'u' => {
                            let h = self.s.get(self.i + 2..self.i + 6).ok_or(JsonError::Malformed)?;
                            if !h.iter().all(u8::is_ascii_hexdigit) {
                                return Err(JsonError::Malformed);
                            }
                            self.i += 6;
                        }
                        _ => return Err(JsonError::Malformed),
                    }
                }
                0..=0x1f => return Err(JsonError::Malformed),
                _ => self.i += 1,
            }
        }
    }
    fn literal(&mut self, lit: &[u8]) -> Result<(), JsonError> {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(JsonError::Malformed)
        }
    }
    fn number(&mut self) -> Result<&'a [u8], JsonError> {
        let start = self.i;
        while self.i < self.s.len() && matches!(self.s[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
            self.i += 1;
        }
        if self.i == start { Err(JsonError::Malformed) } else { Ok(&self.s[start..self.i]) }
    }

    /// Validate one value without recursion (an explicit open-container bitset stack: bit set = object, clear = array).
    fn value(&mut self, depth_base: u32, max_depth: u32) -> Result<Value<'a>, JsonError> {
        let mut depth = depth_base;
        let mut kinds = 0u64; // bit per level above depth_base, relative
        let mut first = true;
        let mut result = Value::Container;
        loop {
            self.ws();
            // A value starts here.
            let c = self.peek().ok_or(JsonError::Malformed)?;
            match c {
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max_depth {
                        return Err(JsonError::TooDeep);
                    }
                    let rel = depth - depth_base - 1;
                    if rel >= 64 {
                        return Err(JsonError::TooDeep);
                    }
                    if c == b'{' {
                        kinds |= 1 << rel;
                    } else {
                        kinds &= !(1 << rel);
                    }
                    self.i += 1;
                    self.ws();
                    let close = if c == b'{' { b'}' } else { b']' };
                    if self.peek() == Some(close) {
                        self.i += 1;
                        depth -= 1;
                    } else {
                        if c == b'{' {
                            self.ws();
                            self.string()?;
                            self.ws();
                            if self.peek() != Some(b':') {
                                return Err(JsonError::Malformed);
                            }
                            self.i += 1;
                        }
                        first = false;
                        continue;
                    }
                }
                b'"' => {
                    let s = self.string()?;
                    if first {
                        result = Value::Str(s);
                    }
                }
                b't' => {
                    self.literal(b"true")?;
                    if first {
                        result = Value::Bool(true);
                    }
                }
                b'f' => {
                    self.literal(b"false")?;
                    if first {
                        result = Value::Bool(false);
                    }
                }
                b'n' => {
                    self.literal(b"null")?;
                    if first {
                        result = Value::Null;
                    }
                }
                _ => {
                    let n = self.number()?;
                    if first {
                        result = Value::Number(n);
                    }
                }
            }
            first = false;
            // A value just ended: close containers as far as the syntax says.
            loop {
                if depth == depth_base {
                    return Ok(result);
                }
                self.ws();
                let rel = depth - depth_base - 1;
                let in_object = kinds & (1 << rel) != 0;
                match self.peek().ok_or(JsonError::Malformed)? {
                    b',' => {
                        self.i += 1;
                        if in_object {
                            self.ws();
                            self.string()?;
                            ws_colon(self)?;
                        }
                        break;
                    }
                    b'}' if in_object => {
                        self.i += 1;
                        depth -= 1;
                    }
                    b']' if !in_object => {
                        self.i += 1;
                        depth -= 1;
                    }
                    _ => return Err(JsonError::Malformed),
                }
            }
        }
    }
}

fn ws_colon(c: &mut Cursor<'_>) -> Result<(), JsonError> {
    c.ws();
    if c.peek() != Some(b':') {
        return Err(JsonError::Malformed);
    }
    c.i += 1;
    Ok(())
}

/// Validate `json` as one object no deeper than `max_depth` (the top object is level 1) and record the first value of each key in `want` into `out`
/// (`out[i]` for `want[i]`; `out` must be at least as long as `want`). Keys are compared on their raw bytes. With `allow_trailing` bytes after the object
/// are ignored (what `cJSON_Parse` does); without it only whitespace may follow.
pub fn scan_top<'a>(json: &'a [u8], max_depth: u32, allow_trailing: bool, want: &[&str], out: &mut [Option<Value<'a>>]) -> Result<(), JsonError> {
    for o in out.iter_mut() {
        *o = None;
    }
    let mut c = Cursor { s: json, i: 0 };
    c.ws();
    if c.peek() != Some(b'{') {
        return Err(JsonError::Malformed);
    }
    if max_depth < 1 {
        return Err(JsonError::TooDeep);
    }
    c.i += 1;
    c.ws();
    if c.peek() == Some(b'}') {
        c.i += 1;
    } else {
        loop {
            c.ws();
            let key = c.string()?;
            ws_colon(&mut c)?;
            let v = c.value(1, max_depth)?;
            if let Some(idx) = want.iter().position(|w| w.as_bytes() == key)
                && idx < out.len()
                && out[idx].is_none()
            {
                out[idx] = Some(v);
            }
            c.ws();
            match c.peek().ok_or(JsonError::Malformed)? {
                b',' => c.i += 1,
                b'}' => {
                    c.i += 1;
                    break;
                }
                _ => return Err(JsonError::Malformed),
            }
        }
    }
    c.ws();
    if !allow_trailing && c.i != json.len() {
        return Err(JsonError::Trailing);
    }
    Ok(())
}

/// Decode a JSON string body (`raw` from [`Value::Str`]) into UTF-8 in `out`. `None` if it does not fit, is not valid UTF-8 or has a lone surrogate.
pub fn unescape(raw: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut o = 0;
    let mut i = 0;
    let put = |out: &mut [u8], o: &mut usize, b: &[u8]| -> Option<()> {
        if out.len() - *o < b.len() {
            return None;
        }
        out[*o..*o + b.len()].copy_from_slice(b);
        *o += b.len();
        Some(())
    };
    let hex4 = |s: &[u8]| -> Option<u32> {
        let mut v = 0u32;
        for &c in s.get(..4)? {
            v = (v << 4) | (c as char).to_digit(16)?;
        }
        Some(v)
    };
    while i < raw.len() {
        let c = raw[i];
        if c != b'\\' {
            put(out, &mut o, &[c])?;
            i += 1;
            continue;
        }
        let e = *raw.get(i + 1)?;
        i += 2;
        let simple = match e {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(8),
            b'f' => Some(12),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            _ => None,
        };
        if let Some(s) = simple {
            put(out, &mut o, &[s])?;
            continue;
        }
        if e != b'u' {
            return None;
        }
        let mut cp = hex4(raw.get(i..)?)?;
        i += 4;
        if (0xd800..0xdc00).contains(&cp) {
            if raw.get(i) != Some(&b'\\') || raw.get(i + 1) != Some(&b'u') {
                return None;
            }
            let lo = hex4(raw.get(i + 2..)?)?;
            if !(0xdc00..0xe000).contains(&lo) {
                return None;
            }
            i += 6;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        }
        let ch = char::from_u32(cp)?;
        let mut tmp = [0u8; 4];
        put(out, &mut o, ch.encode_utf8(&mut tmp).as_bytes())?;
    }
    core::str::from_utf8(&out[..o]).ok()?;
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    #[test]
    fn writer_basic_and_escapes() {
        let mut b = [0u8; 128];
        let mut w = JsonWriter::new(&mut b);
        w.begin_object();
        w.field_str("a", "x\"y\\z\n\u{1}é");
        w.key("arr");
        w.begin_array();
        w.number(1);
        w.string("s");
        w.boolean(false);
        w.begin_object();
        w.end_object();
        w.end_array();
        w.field_bool("t", true);
        w.field_num("n", 18446744073709551615);
        w.end_object();
        let n = w.finish().unwrap();
        assert_eq!(
            core::str::from_utf8(&b[..n]).unwrap(),
            "{\"a\":\"x\\\"y\\\\z\\n\\u0001é\",\"arr\":[1,\"s\",false,{}],\"t\":true,\"n\":18446744073709551615}"
        );
        let mut v = [None; 2];
        scan_top(&b[..n], 4, false, &["t", "n"], &mut v).unwrap();
        assert_eq!(v[0], Some(Value::Bool(true)));
    }

    #[test]
    fn writer_overflow_is_sticky() {
        for cap in 0..20 {
            let mut b = [0u8; 20];
            let mut w = JsonWriter::new(&mut b[..cap]);
            w.begin_object();
            w.field_str("abc", "defghijk");
            w.end_object();
            assert_eq!(w.finish().is_ok(), cap >= 18, "{cap}");
        }
    }

    #[test]
    fn nesting_check_matches_c_test() {
        assert!(nesting_within(b"", 0) && nesting_within(b"123", 0));
        assert!(nesting_within(b"{}", 1) && !nesting_within(b"{}", 0));
        let d = br#"{"a":[{"b":[1]}]}"#;
        assert!(nesting_within(d, 4) && !nesting_within(d, 3));
        let quoted = br#"{"k":"[[[[[[[[{{{{{{{{\"[[[["}"#;
        assert!(nesting_within(quoted, 1));
        let esc = br#"{"k":"\\"}[[[["#;
        assert!(!nesting_within(esc, 1));
        assert!(nesting_within(b"}}]]{", 1) && !nesting_within(b"}}]]{{", 1));
        assert!(nesting_within(&b"{{{{{{"[..1], 1));
    }

    const REG: &str = "{\"User\":{\"ID\":1,\"LoginName\":\"a@b.c\",\"DisplayName\":\"A [B] {C} \\\"D\\\"\",\"ProfilePicURL\":\"\",\"Logins\":[{\"ID\":2,\"Provider\":\"google\",\"LoginName\":\"a@b.c\"}],\"Created\":\"2026-01-01T00:00:00Z\"},\"Login\":{\"ID\":2,\"Provider\":\"google\",\"LoginName\":\"a@b.c\",\"DisplayName\":\"A\"},\"NodeKeyExpired\":false,\"MachineAuthorized\":true,\"AuthURL\":\"\",\"NodeKeySignature\":null,\"Error\":\"\"}";

    #[test]
    fn register_document_depth_four() {
        let mut v = [None; 5];
        let want = ["NodeKeyExpired", "MachineAuthorized", "AuthURL", "Error", "Login"];
        scan_top(REG.as_bytes(), 4, false, &want, &mut v).unwrap();
        assert_eq!(v[0], Some(Value::Bool(false)));
        assert_eq!(v[1], Some(Value::Bool(true)));
        assert_eq!(v[2], Some(Value::Str(b"")));
        assert_eq!(v[4], Some(Value::Container));
        assert_eq!(scan_top(REG.as_bytes(), 3, false, &want, &mut v), Err(JsonError::TooDeep));
        // The C test asserts 3 levels, but only after a `return 0;` that makes it dead code: with the Logins array of objects the document is 4 deep.
        assert!(nesting_within(REG.as_bytes(), 4) && !nesting_within(REG.as_bytes(), 3));
    }

    #[test]
    fn scanner_rejects_malformed() {
        let mut v = [None; 1];
        for bad in [
            "",
            "[]",
            "{",
            "{\"a\"}",
            "{\"a\":}",
            "{\"a\":1,}",
            "{\"a\":1 \"b\":2}",
            "{\"a\":tru}",
            "{\"a\":\"\\x\"}",
            "{\"a\":[1,]}",
            "{\"a\":\"\u{1}\"}",
            "{\"a\":1}x",
            "{\"a\":[1}",
        ] {
            assert!(scan_top(bad.as_bytes(), 8, false, &["a"], &mut v).is_err(), "{bad:?}");
        }
        assert!(scan_top(b"{\"a\":1}x", 8, true, &["a"], &mut v).is_ok());
        assert!(scan_top(b" {\"a\" : [ 1 , { } ] , \"b\":-1.5e+3 } ", 8, false, &["a"], &mut v).is_ok());
    }

    #[test]
    fn duplicate_keys_first_wins() {
        let mut v = [None; 1];
        scan_top(br#"{"a":"1","a":"2"}"#, 2, false, &["a"], &mut v).unwrap();
        assert_eq!(v[0], Some(Value::Str(b"1")));
    }

    #[test]
    fn unescape_cases() {
        let mut o = [0u8; 64];
        let n = unescape(br"https://x/?a=1\u0026b=2\n\ud83d\ude00\/", &mut o).unwrap();
        assert_eq!(core::str::from_utf8(&o[..n]).unwrap(), "https://x/?a=1&b=2\n\u{1f600}/");
        assert!(unescape(br"\ud83d", &mut o).is_none());
        assert!(unescape(br"\ude00", &mut o).is_none());
        assert!(unescape(&[0xff], &mut o).is_none());
        assert!(unescape(b"abcdef", &mut o[..3]).is_none());
    }
}
