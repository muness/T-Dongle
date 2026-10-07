//! Bounded DNS wire parsing: the question of a query (strict, no compression, as the C), a loop-proof general name reader that follows
//! compression pointers, and the question hash used to match upstream replies.

/// Size of the name buffer (the C's `name[256]`): a name of at most 255 text bytes plus a terminator.
pub const NAME_MAX: usize = 256;
/// DNS header length.
pub const HEADER: usize = 12;

/// Big-endian `u16` at `p[i..i+2]` (caller checks bounds).
#[inline]
pub fn rd16(p: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([p[i], p[i + 1]])
}
/// Store a big-endian `u16`.
#[inline]
pub fn wr16(p: &mut [u8], i: usize, v: u16) {
    p[i..i + 2].copy_from_slice(&v.to_be_bytes());
}

/// Why a name or question could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The message ends inside the name or question.
    Truncated,
    /// A label longer than 63 bytes, or a compression pointer where none is allowed.
    BadLabel,
    /// The name does not fit the name buffer.
    TooLong,
    /// A compression pointer that does not point strictly backwards (a loop or a forward reference).
    BadPointer,
    /// More compression pointers than a legal name can need.
    TooManyJumps,
}

/// The parsed question of a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Question {
    /// Length of the name in the caller's buffer (labels joined by `.`, no trailing dot).
    pub name_len: usize,
    /// QTYPE.
    pub qtype: u16,
    /// QCLASS.
    pub qclass: u16,
    /// Offset just past the question (header + name + 4): where the response's answer goes.
    pub end: usize,
}

/// Parse the single question of a query the way the C's `dns_task` does: labels of at most 63 bytes (so a compression pointer, whose first byte
/// is at least 0xC0, is invalid), at most 254 bytes of text, and four bytes of type and class after the root label. `name` receives the
/// labels joined by `.` (it must hold [`NAME_MAX`] bytes).
pub fn parse_question(msg: &[u8], name: &mut [u8; NAME_MAX]) -> Result<Question, ParseError> {
    let n = msg.len();
    let mut pos = HEADER;
    let mut len = 0usize;
    while pos < n && msg[pos] != 0 {
        let size = usize::from(msg[pos]);
        pos += 1;
        if size > 63 {
            return Err(ParseError::BadLabel);
        }
        if pos + size > n {
            return Err(ParseError::Truncated);
        }
        if len + size + 1 >= NAME_MAX {
            return Err(ParseError::TooLong);
        }
        if len > 0 {
            name[len] = b'.';
            len += 1;
        }
        name[len..len + size].copy_from_slice(&msg[pos..pos + size]);
        len += size;
        pos += size;
    }
    if pos + 5 > n {
        return Err(ParseError::Truncated);
    }
    pos += 1; // the root label
    let qtype = rd16(msg, pos);
    let qclass = rd16(msg, pos + 2);
    Ok(Question { name_len: len, qtype, qclass, end: pos + 4 })
}

/// Read a (possibly compressed) name starting at `start` into `out` as dot-joined labels. Returns the text length and the offset just past the
/// name *in the original position* (after the first pointer if one was followed). Loop-proof: a pointer must point strictly before the label it
/// was read at, so the walk is monotonic and ends; at most 128 labels/pointers are followed in any case. Never reads out of bounds.
pub fn read_name(msg: &[u8], start: usize, out: &mut [u8]) -> Result<(usize, usize), ParseError> {
    let mut pos = start;
    let mut len = 0usize;
    let mut next: Option<usize> = None;
    for _ in 0..128 {
        let Some(&b) = msg.get(pos) else { return Err(ParseError::Truncated) };
        match b {
            0 => return Ok((len, next.unwrap_or(pos + 1))),
            1..=63 => {
                let size = usize::from(b);
                if pos + 1 + size > msg.len() {
                    return Err(ParseError::Truncated);
                }
                let add = size + usize::from(len > 0);
                if len + add >= NAME_MAX || len + add > out.len() {
                    return Err(ParseError::TooLong);
                }
                if len > 0 {
                    out[len] = b'.';
                    len += 1;
                }
                out[len..len + size].copy_from_slice(&msg[pos + 1..pos + 1 + size]);
                len += size;
                pos += 1 + size;
            }
            0xc0..=0xff => {
                let Some(&lo) = msg.get(pos + 1) else { return Err(ParseError::Truncated) };
                let target = (usize::from(b & 0x3f) << 8) | usize::from(lo);
                if target >= pos {
                    return Err(ParseError::BadPointer);
                }
                next.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(ParseError::BadLabel), // 0x40..0xbf: reserved label types
        }
    }
    Err(ParseError::TooManyJumps)
}

/// FNV-1a over the uncompressed question (name, type and class) of `msg`, exactly the C's `dns_question_hash`: 0 when `msg` is not a
/// one-question message with an uncompressed question, never 0 for a valid one. Used to match an upstream reply to the query that was
/// forwarded, on top of the rewritten transaction ID.
pub fn question_hash(msg: &[u8]) -> u32 {
    let n = msg.len();
    if n < 17 || rd16(msg, 4) != 1 {
        return 0;
    }
    let mut pos = HEADER;
    while pos < n && msg[pos] != 0 {
        let len = usize::from(msg[pos]);
        pos += 1;
        if len > 63 || pos + len >= n {
            return 0;
        }
        pos += len;
    }
    if pos + 5 > n {
        return 0;
    }
    let mut h = 2_166_136_261u32;
    for &b in &msg[HEADER..pos + 5] {
        h = (h ^ u32::from(b)).wrapping_mul(16_777_619);
    }
    if h == 0 { 1 } else { h }
}
