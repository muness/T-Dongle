//! A bounded, allocation-free reader with the acceptance and rejection rules of the cJSON 1.7.19 `cJSON_Parse` the C firmware reads its settings and
//! its `/command` bodies with. It is deliberately not a standards-conforming JSON parser:
//!
//! * the input is a C string (it ends at the first NUL); a UTF-8 BOM and any bytes `<= 0x20` before a token are skipped;
//! * whatever follows the first complete value is ignored (`cJSON_Parse` does not require the end);
//! * nesting is limited to 1000 containers (`CJSON_NESTING_LIMIT`);
//! * strings may hold raw control characters and raw bytes `>= 0x80` (no UTF-8 check); `\u` escapes follow `utf16_literal_to_utf8` (an invalid hex digit
//!   reads as 0, a lone low surrogate or a high surrogate without its pair fails, `\u0000` ends the C string);
//! * numbers are the longest run of `[0-9+-eE.]`, of which `strtod` takes the longest valid prefix (so `01`, `1.`, `-.5` are numbers; `+1` and `.5` are
//!   not values), and the rest of the run stays in the input;
//! * the literals `null`, `true`, `false` are matched by prefix (`truex` is `true` followed by `x`);
//! * `GetObjectItem` is ASCII case-insensitive and returns the FIRST member with a matching name.
//!
//! Nothing is built: values are positions in the input, and containers are walked iteratively (a 1000-bit stack), so the cost is constant stack.

use crate::text::CText;

/// `v == (uint32_t)v` for a double in range: the integer it holds.
pub fn as_u32(v: f64) -> Option<u32> {
    if (0.0..=f64::from(u32::MAX)).contains(&v) {
        let u = v as u32;
        if f64::from(u) == v {
            return Some(u);
        }
    }
    None
}

/// The nesting limit of cJSON.
pub const NESTING_LIMIT: usize = 1000;

/// The parse failed (cJSON returned NULL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError;

/// A parsed value: scalars carry their value, strings the range of their raw (still escaped) content, containers their opening position.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Val {
    /// `null`
    Null,
    /// `false`
    False,
    /// `true`
    True,
    /// A number (`valuedouble`).
    Number(f64),
    /// A string: raw content `[start, end)` between the quotes.
    Str(usize, usize),
    /// An array opening at this position.
    Array(usize),
    /// An object opening at this position.
    Object(usize),
}

impl Val {
    /// `cJSON_IsTrue`.
    pub fn is_true(&self) -> bool {
        matches!(self, Val::True)
    }
    /// `cJSON_IsBool`.
    pub fn is_bool(&self) -> bool {
        matches!(self, Val::True | Val::False)
    }
}

/// A reader over one C string.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    s: &'a [u8],
}

fn hex4(b: &[u8]) -> u32 {
    let mut h = 0u32;
    for (i, &c) in b.iter().take(4).enumerate() {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => return 0,
        };
        h += u32::from(d);
        if i < 3 {
            h <<= 4;
        }
    }
    h
}

impl<'a> Reader<'a> {
    /// A reader over `input` up to its first NUL.
    pub fn new(input: &'a [u8]) -> Reader<'a> {
        let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
        Reader { s: &input[..end] }
    }
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }
    fn ws(&self, mut p: usize) -> usize {
        while p < self.s.len() && self.s[p] <= 32 {
            p += 1;
        }
        p
    }

    /// Parse the root value as `cJSON_Parse` does: BOM, whitespace, one value, the rest ignored. Returns the value and its position.
    pub fn root(&self) -> Result<(Val, usize), SyntaxError> {
        let mut p = 0;
        if self.s.len() >= 4 && self.s.starts_with(&[0xEF, 0xBB, 0xBF]) {
            p = 3;
        }
        let p = self.ws(p);
        let (v, _) = self.value(p)?;
        Ok((v, p))
    }

    /// Parse the value starting at `p` (no leading whitespace skipped). Returns it and the position after it.
    pub fn value(&self, p: usize) -> Result<(Val, usize), SyntaxError> {
        match self.at(p) {
            b'[' => Ok((Val::Array(p), self.container_end(p)?)),
            b'{' => Ok((Val::Object(p), self.container_end(p)?)),
            _ => self.scalar(p),
        }
    }

    fn scalar(&self, p: usize) -> Result<(Val, usize), SyntaxError> {
        let rest = self.s.get(p..).unwrap_or(&[]);
        if rest.starts_with(b"null") {
            return Ok((Val::Null, p + 4));
        }
        if rest.starts_with(b"false") {
            return Ok((Val::False, p + 5));
        }
        if rest.starts_with(b"true") {
            return Ok((Val::True, p + 4));
        }
        match self.at(p) {
            b'"' => {
                let (end, _) = self.string_scan(p, &mut |_| {})?;
                Ok((Val::Str(p + 1, end), end + 1))
            }
            b'-' | b'0'..=b'9' => {
                let (n, used) = self.number(p)?;
                Ok((Val::Number(n), p + used))
            }
            _ => Err(SyntaxError),
        }
    }

    /// Scan and decode the string whose opening quote is at `p`; every decoded byte goes to `sink`. Returns the index of the closing quote.
    fn string_scan(&self, p: usize, sink: &mut dyn FnMut(u8)) -> Result<(usize, ()), SyntaxError> {
        let mut e = p + 1;
        while e < self.s.len() && self.s[e] != b'"' {
            if self.s[e] == b'\\' {
                e += 1;
            }
            e += 1;
        }
        if e >= self.s.len() {
            return Err(SyntaxError);
        }
        self.decode(p + 1, e, sink)?;
        Ok((e, ()))
    }

    /// Decode the escaped content `[start, end)` of a string (as found by [`Val::Str`]) into `sink`.
    pub fn decode(&self, start: usize, end: usize, sink: &mut dyn FnMut(u8)) -> Result<(), SyntaxError> {
        let s = self.s;
        let mut q = start;
        while q < end {
            if s[q] != b'\\' {
                sink(s[q]);
                q += 1;
                continue;
            }
            let step = match s.get(q + 1).copied().unwrap_or(0) {
                b'b' => {
                    sink(8);
                    2
                }
                b'f' => {
                    sink(12);
                    2
                }
                b'n' => {
                    sink(b'\n');
                    2
                }
                b'r' => {
                    sink(b'\r');
                    2
                }
                b't' => {
                    sink(b'\t');
                    2
                }
                c @ (b'"' | b'\\' | b'/') => {
                    sink(c);
                    2
                }
                b'u' => self.utf16(q, end, sink)?,
                _ => return Err(SyntaxError),
            };
            q += step;
        }
        Ok(())
    }

    fn utf16(&self, q: usize, end: usize, sink: &mut dyn FnMut(u8)) -> Result<usize, SyntaxError> {
        if end - q < 6 {
            return Err(SyntaxError);
        }
        let first = hex4(&self.s[q + 2..q + 6]);
        if (0xDC00..=0xDFFF).contains(&first) {
            return Err(SyntaxError);
        }
        let (code, len) = if (0xD800..=0xDBFF).contains(&first) {
            let sec = q + 6;
            if end - sec < 6 || self.s[sec] != b'\\' || self.s[sec + 1] != b'u' {
                return Err(SyntaxError);
            }
            let second = hex4(&self.s[sec + 2..sec + 6]);
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(SyntaxError);
            }
            (0x10000 + (((first & 0x3FF) << 10) | (second & 0x3FF)), 12)
        } else {
            (first, 6)
        };
        if code < 0x80 {
            sink(code as u8 & 0x7F);
        } else if code < 0x800 {
            sink(0xC0 | (code >> 6) as u8);
            sink(0x80 | (code & 0x3F) as u8);
        } else if code < 0x10000 {
            sink(0xE0 | (code >> 12) as u8);
            sink(0x80 | ((code >> 6) & 0x3F) as u8);
            sink(0x80 | (code & 0x3F) as u8);
        } else {
            sink(0xF0 | (code >> 18) as u8);
            sink(0x80 | ((code >> 12) & 0x3F) as u8);
            sink(0x80 | ((code >> 6) & 0x3F) as u8);
            sink(0x80 | (code & 0x3F) as u8);
        }
        Ok(len)
    }

    /// `parse_number`: the run of number characters, the `strtod` prefix of it, its value and how many bytes it used.
    fn number(&self, p: usize) -> Result<(f64, usize), SyntaxError> {
        let run = self.s[p..].iter().take_while(|&&c| matches!(c, b'0'..=b'9' | b'+' | b'-' | b'e' | b'E' | b'.')).count();
        let r = &self.s[p..p + run];
        let mut i = 0;
        if matches!(r.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let digits = |from: usize| r[from..].iter().take_while(|c| c.is_ascii_digit()).count();
        let int = digits(i);
        i += int;
        let mut frac = 0;
        if r.get(i) == Some(&b'.') {
            frac = digits(i + 1);
            if int + frac > 0 {
                i += 1 + frac;
            }
        }
        if int + frac == 0 {
            return Err(SyntaxError);
        }
        if matches!(r.get(i), Some(b'e' | b'E')) {
            let mut j = i + 1;
            if matches!(r.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            let ed = digits(j);
            if ed > 0 {
                i = j + ed;
            }
        }
        let text = core::str::from_utf8(&r[..i]).map_err(|_| SyntaxError)?;
        let v: f64 = text.parse().map_err(|_| SyntaxError)?;
        Ok((v, i))
    }

    /// After a member name: parse the key string at `p`, then `:`; returns (key range, position of the value after whitespace).
    fn member_head(&self, p: usize) -> Result<((usize, usize), usize), SyntaxError> {
        if self.at(p) != b'"' {
            return Err(SyntaxError);
        }
        let (e, ()) = self.string_scan(p, &mut |_| {})?;
        let c = self.ws(e + 1);
        if self.at(c) != b':' {
            return Err(SyntaxError);
        }
        Ok(((p + 1, e), self.ws(c + 1)))
    }

    /// Validate the container opening at `p0` and return the position after it. Iterative: the nesting is a bit stack.
    fn container_end(&self, p0: usize) -> Result<usize, SyntaxError> {
        let mut stack = [0u32; NESTING_LIMIT.div_ceil(32)];
        let mut depth = 0usize;
        let mut p = p0;
        loop {
            p = self.ws(p);
            match self.at(p) {
                c @ (b'[' | b'{') => {
                    if depth >= NESTING_LIMIT {
                        return Err(SyntaxError);
                    }
                    let object = c == b'{';
                    if object {
                        stack[depth / 32] |= 1 << (depth % 32);
                    } else {
                        stack[depth / 32] &= !(1 << (depth % 32));
                    }
                    depth += 1;
                    p = self.ws(p + 1);
                    if self.at(p) == if object { b'}' } else { b']' } {
                        depth -= 1;
                        p += 1;
                    } else {
                        if object {
                            p = self.member_head(p)?.1;
                        }
                        continue;
                    }
                }
                _ => p = self.scalar(p)?.1,
            }
            // A value is complete at p: unwind.
            loop {
                if depth == 0 {
                    return Ok(p);
                }
                p = self.ws(p);
                let object = stack[(depth - 1) / 32] >> ((depth - 1) % 32) & 1 == 1;
                match self.at(p) {
                    b',' => {
                        p = self.ws(p + 1);
                        if object {
                            p = self.member_head(p)?.1;
                        }
                        break;
                    }
                    b']' if !object => {}
                    b'}' if object => {}
                    _ => return Err(SyntaxError),
                }
                depth -= 1;
                p += 1;
            }
        }
    }

    /// The members of the validated object opening at `p`.
    pub fn members(&self, p: usize) -> Members<'_, 'a> {
        Members { r: self, p: p + 1, first: true, done: false }
    }

    /// The elements of the validated array opening at `p`.
    pub fn elements(&self, p: usize) -> Elements<'_, 'a> {
        Elements { r: self, p: p + 1, first: true, done: false }
    }

    /// Decode a string value's raw content into a C string of capacity `CAP`.
    pub fn text<const CAP: usize>(&self, start: usize, end: usize) -> CText<CAP> {
        let mut t = CText::<CAP>::new();
        // A validated string cannot fail to decode; an unvalidated one yields what decoded before the fault.
        let _ = self.decode(start, end, &mut |b| t.push(b));
        t
    }

    /// `cJSON_GetObjectItem(object, name)`: the first member whose name equals `name` ignoring ASCII case. Walks (and so validates) the whole object.
    pub fn get(&self, object: usize, name: &str) -> Result<Option<Val>, SyntaxError> {
        let mut found = None;
        for m in self.members(object) {
            let m = m?;
            if found.is_none() && self.key_is(&m, name) {
                found = Some(m.val);
            }
        }
        Ok(found)
    }

    /// Whether member `m`'s decoded name equals `name` ignoring ASCII case (`name` at most 15 bytes).
    pub fn key_is(&self, m: &Member, name: &str) -> bool {
        let k = self.text::<15>(m.key.0, m.key.1);
        k.eq_ignore_case(name.as_bytes())
    }
}

/// One object member.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    /// Raw content range of the name.
    pub key: (usize, usize),
    /// The value.
    pub val: Val,
}

/// Iterator over an object's members. Yields `Err` once at a fault and then stops.
#[derive(Debug)]
pub struct Members<'r, 'a> {
    r: &'r Reader<'a>,
    p: usize,
    first: bool,
    done: bool,
}

impl Iterator for Members<'_, '_> {
    type Item = Result<Member, SyntaxError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let r = self.r;
        let mut p = r.ws(self.p);
        if self.first {
            self.first = false;
            if r.at(p) == b'}' {
                self.done = true;
                return None;
            }
        } else if r.at(p) == b',' {
            p = r.ws(p + 1);
        } else {
            self.done = true;
            return if r.at(p) == b'}' { None } else { Some(Err(SyntaxError)) };
        }
        let res = r.member_head(p).and_then(|(key, vp)| r.value(vp).map(|(val, end)| (Member { key, val }, end)));
        match res {
            Ok((m, end)) => {
                self.p = end;
                Some(Ok(m))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Iterator over an array's elements.
#[derive(Debug)]
pub struct Elements<'r, 'a> {
    r: &'r Reader<'a>,
    p: usize,
    first: bool,
    done: bool,
}

impl Iterator for Elements<'_, '_> {
    type Item = Result<Val, SyntaxError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let r = self.r;
        let mut p = r.ws(self.p);
        if self.first {
            self.first = false;
            if r.at(p) == b']' {
                self.done = true;
                return None;
            }
        } else if r.at(p) == b',' {
            p = r.ws(p + 1);
        } else {
            self.done = true;
            return if r.at(p) == b']' { None } else { Some(Err(SyntaxError)) };
        }
        match r.value(p) {
            Ok((v, end)) => {
                self.p = end;
                Some(Ok(v))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}
