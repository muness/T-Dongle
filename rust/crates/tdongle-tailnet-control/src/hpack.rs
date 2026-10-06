//! HPACK (RFC 7541), the part the control client needs.
//!
//! **Encoding** is literals only, never indexed into a dynamic table (so the peer's table stays empty and our memory is zero): `:method` and `:scheme` use
//! their static entries, the rest are "literal without indexing" with a static name.
//!
//! **Decoding** is a byte-at-a-time state machine with a few words of state. The C reads none of the server's headers (it only looks at frame flags); this
//! decoder additionally recovers the one thing worth knowing, the `:status`, and otherwise *skips* every field by length. It keeps no dynamic table: a field
//! reached through a dynamic index is counted ([`HeaderSummary::dynamic_refs`]), not resolved, and a Huffman string is skipped without decoding, except
//! that a Huffman-coded `:status` value is decoded (digits only; any other symbol leaves the status unknown). Size updates above the advertised table size
//! and every malformed integer or index are errors, so a hostile block can neither loop nor grow anything.

use crate::http::{BuildError, Out};

/// Static table entries 8..=14 are the `:status` values 200, 204, 206, 304, 400, 404, 500.
const STATUS_TABLE: [u16; 7] = [200, 204, 206, 304, 400, 404, 500];
/// Number of static table entries; indexes above it refer to the (unsupported) dynamic table.
const STATIC_LEN: u32 = 61;

/// Header table size the decoder accepts in a dynamic table size update (RFC 7540 default, which we never lower).
pub const DEFAULT_TABLE_SIZE: u32 = 4096;

/// A malformed header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpackError {
    /// Index 0, or an integer that overflows 32 bits.
    BadInteger,
    /// A dynamic table size update larger than the table size we advertised, or one that is not first in the block.
    BadSizeUpdate,
    /// The block ended inside a field.
    Truncated,
    /// The block is longer than the bound the caller set.
    TooLong,
}

/// What a finished header block contained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeaderSummary {
    /// The `:status` if it was a static index or a literal (raw or Huffman digits) that could be read.
    pub status: Option<u16>,
    /// Fields in the block.
    pub fields: u16,
    /// Fields that were references to the dynamic table (not resolved).
    pub dynamic_refs: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    /// At the first byte of a representation.
    Start,
    /// Continuing a prefix integer: when done, act on `kind`.
    Int { kind: IntKind, value: u32, shift: u8 },
    /// Skipping or collecting a string body.
    Body { left: u32, huff: bool, role: Role },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntKind {
    /// Indexed field (7-bit prefix).
    Indexed,
    /// Literal field name index (6- or 4-bit prefix).
    NameIndex,
    /// Size update (5-bit prefix).
    SizeUpdate,
    /// String length (7-bit prefix); Huffman flag held.
    StrLen { huff: bool, role: Role },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// New literal name: skip it, then a value follows.
    NewName,
    /// A value to skip.
    SkipValue,
    /// A `:status` value to read.
    ReadStatus,
}

/// The decoder. One per connection; call [`HpackDecoder::start_block`] at each HEADERS frame, [`HpackDecoder::feed`] for each fragment byte (HEADERS then
/// CONTINUATION) and [`HpackDecoder::end_block`] at END_HEADERS.
#[derive(Clone, Debug)]
pub struct HpackDecoder {
    st: St,
    max_table: u32,
    at_block_start: bool,
    block_bytes: u32,
    max_block: u32,
    status_buf: [u8; 4],
    status_len: u8,
    status_huff: bool,
    sum: HeaderSummary,
}

impl HpackDecoder {
    /// A decoder accepting size updates up to `max_table` and blocks up to `max_block` bytes.
    pub const fn new(max_table: u32, max_block: u32) -> Self {
        Self {
            st: St::Start,
            max_table,
            at_block_start: true,
            block_bytes: 0,
            max_block,
            status_buf: [0; 4],
            status_len: 0,
            status_huff: false,
            sum: HeaderSummary { status: None, fields: 0, dynamic_refs: 0 },
        }
    }

    /// Begin a new header block.
    pub fn start_block(&mut self) {
        self.st = St::Start;
        self.at_block_start = true;
        self.block_bytes = 0;
        self.sum = HeaderSummary::default();
    }

    fn field(&mut self) {
        self.sum.fields = self.sum.fields.saturating_add(1);
        self.at_block_start = false;
    }

    fn index_field(&mut self, idx: u32) -> Result<(), HpackError> {
        if idx == 0 {
            return Err(HpackError::BadInteger);
        }
        self.field();
        if (8..=14).contains(&idx) {
            self.sum.status = Some(STATUS_TABLE[(idx - 8) as usize]);
        } else if idx > STATIC_LEN {
            self.sum.dynamic_refs = self.sum.dynamic_refs.saturating_add(1);
        }
        Ok(())
    }

    fn after_integer(&mut self, kind: IntKind, v: u32) -> Result<(), HpackError> {
        match kind {
            IntKind::Indexed => {
                self.index_field(v)?;
                self.st = St::Start;
            }
            IntKind::NameIndex if v == 0 => {
                // New name: a name string then a value string.
                self.field();
                self.st = St::Int { kind: IntKind::StrLen { huff: false, role: Role::NewName }, value: 0, shift: 255 };
            }
            IntKind::NameIndex => {
                self.field();
                let role = if (8..=14).contains(&v) { Role::ReadStatus } else { Role::SkipValue };
                if v > STATIC_LEN {
                    self.sum.dynamic_refs = self.sum.dynamic_refs.saturating_add(1);
                }
                self.st = St::Int { kind: IntKind::StrLen { huff: false, role }, value: 0, shift: 255 };
            }
            IntKind::SizeUpdate => {
                if !self.at_block_start || v > self.max_table {
                    return Err(HpackError::BadSizeUpdate);
                }
                self.st = St::Start;
            }
            IntKind::StrLen { huff, role } => {
                if role == Role::ReadStatus {
                    self.status_len = 0;
                    self.status_huff = huff;
                }
                if v == 0 {
                    self.string_done(role)?;
                } else {
                    self.st = St::Body { left: v, huff, role };
                }
            }
        }
        Ok(())
    }

    fn string_done(&mut self, role: Role) -> Result<(), HpackError> {
        match role {
            Role::NewName => {
                self.st = St::Int { kind: IntKind::StrLen { huff: false, role: Role::SkipValue }, value: 0, shift: 255 };
            }
            Role::SkipValue => self.st = St::Start,
            Role::ReadStatus => {
                self.st = St::Start;
                if let Some(s) = self.decode_status() {
                    self.sum.status = Some(s);
                }
            }
        }
        Ok(())
    }

    fn decode_status(&self) -> Option<u16> {
        let n = self.status_len as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let raw = &self.status_buf[..n];
        let mut digits = [0u8; 3];
        if !self.status_huff {
            if n != 3 || !raw.iter().all(u8::is_ascii_digit) {
                return None;
            }
            digits.copy_from_slice(raw);
        } else {
            // Digits only: '0'..'2' are the 5-bit codes 00000..00010, '3'..'9' the 6-bit codes 011001..011111; anything else is not a status.
            let (mut acc, mut bits, mut got) = (0u32, 0u32, 0usize);
            for &b in raw {
                acc = (acc << 8) | b as u32;
                bits += 8;
                loop {
                    if bits >= 5 && (acc >> (bits - 5)) & 0x1f < 3 {
                        if got == 3 {
                            return None;
                        }
                        digits[got] = b'0' + ((acc >> (bits - 5)) & 0x1f) as u8;
                        got += 1;
                        bits -= 5;
                    } else if bits >= 6 && (0b011001..=0b011111).contains(&((acc >> (bits - 6)) & 0x3f)) {
                        if got == 3 {
                            return None;
                        }
                        digits[got] = b'0' + (((acc >> (bits - 6)) & 0x3f) - 0b011001 + 3) as u8;
                        got += 1;
                        bits -= 6;
                    } else {
                        break;
                    }
                    acc &= (1u32 << bits) - 1;
                }
                if bits >= 8 {
                    return None; // an undecodable symbol is left: not a status
                }
            }
            // What is left must be EOS padding (all ones, fewer than 8 bits).
            if got != 3 || bits >= 8 || acc != (1u32 << bits) - 1 {
                return None;
            }
        }
        Some((digits[0] - b'0') as u16 * 100 + (digits[1] - b'0') as u16 * 10 + (digits[2] - b'0') as u16)
    }

    /// Feed one byte of the block.
    pub fn feed(&mut self, b: u8) -> Result<(), HpackError> {
        self.block_bytes += 1;
        if self.block_bytes > self.max_block {
            return Err(HpackError::TooLong);
        }
        match self.st {
            St::Start => {
                // Prefix width and kind from the first bits.
                let (kind, prefix) = if b & 0x80 != 0 {
                    (IntKind::Indexed, 7)
                } else if b & 0x40 != 0 {
                    (IntKind::NameIndex, 6)
                } else if b & 0x20 != 0 {
                    (IntKind::SizeUpdate, 5)
                } else {
                    (IntKind::NameIndex, 4)
                };
                self.int_start(kind, prefix, b)
            }
            St::Int { kind, value, shift } => {
                if shift == 255 {
                    // First byte of a string length: H bit then 7-bit prefix.
                    let IntKind::StrLen { role, .. } = kind else { return Err(HpackError::BadInteger) };
                    return self.int_start(IntKind::StrLen { huff: b & 0x80 != 0, role }, 7, b);
                }
                let part = (b & 0x7f) as u32;
                if shift > 28 || (part << shift) >> shift != part {
                    return Err(HpackError::BadInteger);
                }
                let v = value.checked_add(part << shift).ok_or(HpackError::BadInteger)?;
                if b & 0x80 != 0 {
                    self.st = St::Int { kind, value: v, shift: shift + 7 };
                    Ok(())
                } else {
                    self.after_integer(kind, v)
                }
            }
            St::Body { left, huff, role } => {
                if role == Role::ReadStatus && (self.status_len as usize) < self.status_buf.len() {
                    self.status_buf[self.status_len as usize] = b;
                    self.status_len += 1;
                } else if role == Role::ReadStatus {
                    self.status_len = 5; // too long to be a status
                }
                if left == 1 {
                    self.string_done(role)
                } else {
                    self.st = St::Body { left: left - 1, huff, role };
                    Ok(())
                }
            }
        }
    }

    fn int_start(&mut self, kind: IntKind, prefix: u32, b: u8) -> Result<(), HpackError> {
        let max = (1u32 << prefix) - 1;
        let v = (b as u32) & max;
        if v < max {
            self.after_integer(kind, v)
        } else {
            self.st = St::Int { kind, value: max, shift: 0 };
            Ok(())
        }
    }

    /// The block is complete (END_HEADERS): it must end between fields.
    pub fn end_block(&mut self) -> Result<HeaderSummary, HpackError> {
        let s = self.sum;
        let clean = self.st == St::Start;
        self.start_block();
        if clean { Ok(s) } else { Err(HpackError::Truncated) }
    }
}

/// Write an HPACK integer with an `n`-bit prefix; `flags` are the high bits of the first byte.
pub(crate) fn put_int(o: &mut Out<'_>, flags: u8, prefix: u32, mut v: u32) -> Result<(), BuildError> {
    let max = (1u32 << prefix) - 1;
    if v < max {
        return o.put(&[flags | v as u8]);
    }
    o.put(&[flags | max as u8])?;
    v -= max;
    while v >= 128 {
        o.put(&[(v & 0x7f) as u8 | 0x80])?;
        v >>= 7;
    }
    o.put(&[v as u8])
}

/// A literal header field without indexing: a static name index plus a raw value.
pub(crate) fn put_literal_indexed_name(o: &mut Out<'_>, name_index: u32, value: &str) -> Result<(), BuildError> {
    put_int(o, 0x00, 4, name_index)?;
    put_int(o, 0x00, 7, value.len() as u32)?;
    o.put(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    fn decode(block: &[u8]) -> Result<HeaderSummary, HpackError> {
        let mut d = HpackDecoder::new(DEFAULT_TABLE_SIZE, 16384);
        d.start_block();
        for &b in block {
            d.feed(b)?;
        }
        d.end_block()
    }

    #[test]
    fn rfc7541_c4_huffman_request_is_skipped_and_counted() {
        // C.4.1 first request: :method GET, :scheme http, :path /, :authority www.example.com (Huffman).
        let b = [0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff];
        let s = decode(&b).unwrap();
        assert_eq!((s.fields, s.status, s.dynamic_refs), (4, None, 0));
        // C.3.1 without Huffman.
        let b = [0x82, 0x86, 0x84, 0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm'];
        assert_eq!(decode(&b).unwrap().fields, 4);
    }

    #[test]
    fn status_forms() {
        assert_eq!(decode(&[0x88]).unwrap().status, Some(200));
        assert_eq!(decode(&[0x8c]).unwrap().status, Some(400));
        assert_eq!(decode(&[0x8e]).unwrap().status, Some(500));
        // literal with indexing, name index 8, raw "403"
        assert_eq!(decode(&[0x48, 0x03, b'4', b'0', b'3']).unwrap().status, Some(403));
        // without indexing, raw "502"
        assert_eq!(decode(&[0x08, 0x03, b'5', b'0', b'2']).unwrap().status, Some(502));
        // Huffman "403": 011010 00000 011001 + 7 pad ones = 68 0c ff
        assert_eq!(decode(&[0x48, 0x83, 0x68, 0x0c, 0xff]).unwrap().status, Some(403));
        // Huffman "200": 00010 00000 00000 = 15 bits + 1 pad bit
        assert_eq!(decode(&[0x48, 0x82, 0x10, 0x01]).unwrap().status, Some(200));
        // Four undecodable bytes (found by the mini-fuzz: used to overflow a shift).
        assert_eq!(decode(&[0x48, 0x84, 0xff, 0xff, 0xff, 0xff]).unwrap().status, None);
        // Huffman with a non-digit symbol: status unknown, no error.
        assert_eq!(decode(&[0x48, 0x82, 0xff, 0xff]).unwrap().status, None);
    }

    #[test]
    fn dynamic_refs_are_counted_not_resolved() {
        let s = decode(&[0xbe, 0x88]).unwrap();
        assert_eq!((s.dynamic_refs, s.status, s.fields), (1, Some(200), 2));
        let s = decode(&[0x7e, 0x01, b'x']).unwrap(); // literal with indexing, dynamic name index 62
        assert_eq!(s.dynamic_refs, 1);
    }

    #[test]
    fn size_update_rules() {
        assert!(decode(&[0x3f, 0xe1, 0x1f]).is_ok()); // 4096
        assert_eq!(decode(&[0x3f, 0xe2, 0x1f]), Err(HpackError::BadSizeUpdate)); // 4097
        assert_eq!(decode(&[0x88, 0x20]), Err(HpackError::BadSizeUpdate)); // after a field
        assert!(decode(&[0x20, 0x20, 0x88]).is_ok()); // two updates first
    }

    #[test]
    fn malformed() {
        assert_eq!(decode(&[0x80]), Err(HpackError::BadInteger)); // index 0
        assert_eq!(decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Err(HpackError::BadInteger));
        assert_eq!(decode(&[0xff, 0x80, 0x80, 0x80, 0x80, 0x10]), Err(HpackError::BadInteger)); // overflow past 32 bits
        assert_eq!(decode(&[0x40, 0x03, b'a']), Err(HpackError::Truncated));
        assert_eq!(decode(&[0x40]), Err(HpackError::Truncated));
        assert_eq!(decode(&[0xff]), Err(HpackError::Truncated));
        let mut d = HpackDecoder::new(4096, 3);
        d.start_block();
        assert!(d.feed(0x88).is_ok() && d.feed(0x88).is_ok() && d.feed(0x88).is_ok());
        assert_eq!(d.feed(0x88), Err(HpackError::TooLong));
    }

    #[test]
    fn huge_string_length_is_just_a_skip_counter() {
        // A 2^28-ish string length followed by a few bytes: still mid-string at the end of the block.
        assert_eq!(decode(&[0x00, 0x01, b'a', 0x7f, 0xff, 0xff, 0xff, 0x7f, b'x']), Err(HpackError::Truncated));
    }

    #[test]
    fn integer_encoder_matches_rfc_c1() {
        let mut b = [0u8; 8];
        let mut o = Out::new(&mut b);
        put_int(&mut o, 0, 5, 10).unwrap();
        assert_eq!(o.len(), 1);
        let mut b2 = [0u8; 8];
        let mut o2 = Out::new(&mut b2);
        put_int(&mut o2, 0, 5, 1337).unwrap();
        assert_eq!(&b2[..3], &[0x1f, 0x9a, 0x0a]);
        let mut b3 = [0u8; 8];
        let mut o3 = Out::new(&mut b3);
        put_int(&mut o3, 0, 8, 42).unwrap();
        assert_eq!(b3[0], 42);
    }
}
