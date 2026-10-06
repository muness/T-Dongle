//! STUN as Tailscale uses it (`net/stun/stun.go`): RFC 5389 binding requests with the `SOFTWARE="tailnode"` and `FINGERPRINT` attributes the DERP STUN
//! servers insist on, and a binding-response parser that finds `XOR-MAPPED-ADDRESS` (or the alternate `0x8020`, or the legacy `MAPPED-ADDRESS`).
//!
//! Parsing follows Go: any attribute that does not fit makes the whole response malformed (the C stopped quietly; Go's reading is the safer one),
//! trailing bytes after the header's stated length are ignored, an IPv4-mapped IPv6 address is an IPv4 address, and the response's own `FINGERPRINT` is
//! *not* required (the transaction id is the check). [`check_fingerprint`] says what it is when you want to know. The number of attributes read is bounded.

use crate::addr::Ep;

/// STUN header length.
pub const HEADER_LEN: usize = 20;
/// Bytes of a transaction id.
pub const TXID_LEN: usize = 12;
/// Bytes of a request this crate builds: header, `SOFTWARE` (12) and `FINGERPRINT` (8).
pub const REQUEST_LEN: usize = 40;
/// Largest response this crate builds (`IPv6`).
pub const MAX_BUILT_RESPONSE: usize = HEADER_LEN + 4 + 20;
/// Attributes read from one message before it is called malformed (a real response has under ten).
pub const MAX_ATTRS: usize = 64;
/// A transaction id.
pub type TxId = [u8; TXID_LEN];

const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const SOFTWARE: &[u8; 8] = b"tailnode";
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_MAPPED: u16 = 0x0001;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_XOR_MAPPED_ALT: u16 = 0x8020;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Why a STUN message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunError {
    /// Not a STUN message (too short, top bits set, or no magic cookie).
    NotStun,
    /// A STUN message that is not a success response.
    NotSuccessResponse,
    /// An attribute runs past the message, a mapped address is too short or of an unknown family, there is no mapped address, or there are too many
    /// attributes.
    MalformedAttrs,
    /// A request that is not a binding request.
    NotBindingRequest,
    /// A request that does not carry `SOFTWARE="tailnode"`.
    WrongSoftware,
    /// A request whose last attribute is not `FINGERPRINT`.
    NoFingerprint,
    /// A request whose `FINGERPRINT` is wrong.
    WrongFingerprint,
    /// The output buffer is too small.
    BufferTooSmall,
}

/// Go's `stun.Is`: long enough for a header, top two bits zero, magic cookie in place.
pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= HEADER_LEN && b[0] & 0b1100_0000 == 0 && b[4..8] == MAGIC_COOKIE
}

/// CRC-32 (IEEE, reflected) over `data`, four bits at a time: 64 bytes of table rather than 1 KB.
pub fn crc32(data: &[u8]) -> u32 {
    const T: [u32; 16] = {
        let mut t = [0u32; 16];
        let mut i = 0;
        while i < 16 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 4 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        c = T[(c & 15) as usize] ^ (c >> 4);
        c = T[(c & 15) as usize] ^ (c >> 4);
    }
    !c
}

fn fingerprint(b: &[u8]) -> u32 {
    crc32(b) ^ FINGERPRINT_XOR
}

/// Build a binding request into `out` (40 bytes): header, `SOFTWARE="tailnode"`, `FINGERPRINT`.
pub fn build_request(txid: &TxId, out: &mut [u8; REQUEST_LEN]) {
    out[0..2].copy_from_slice(&[0x00, 0x01]);
    out[2..4].copy_from_slice(&20u16.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC_COOKIE);
    out[8..20].copy_from_slice(txid);
    out[20..22].copy_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    out[22..24].copy_from_slice(&8u16.to_be_bytes());
    out[24..32].copy_from_slice(SOFTWARE);
    let fp = fingerprint(&out[..32]);
    out[32..34].copy_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    out[34..36].copy_from_slice(&4u16.to_be_bytes());
    out[36..40].copy_from_slice(&fp.to_be_bytes());
}

/// Walk the attributes of `b` (the part after the header). `f(type, value)` is called per attribute and may stop the walk with an error.
fn for_each_attr(mut b: &[u8], mut f: impl FnMut(u16, &[u8]) -> Result<(), StunError>) -> Result<(), StunError> {
    let mut n = 0;
    while !b.is_empty() {
        if b.len() < 4 {
            return Err(StunError::MalformedAttrs);
        }
        n += 1;
        if n > MAX_ATTRS {
            return Err(StunError::MalformedAttrs);
        }
        let ty = u16::from_be_bytes([b[0], b[1]]);
        let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        let padded = (len + 3) & !3;
        b = &b[4..];
        if padded > b.len() {
            return Err(StunError::MalformedAttrs);
        }
        f(ty, &b[..len])?;
        b = &b[padded..];
    }
    Ok(())
}

/// Parse a binding request: it must be a Tailscale one (`SOFTWARE="tailnode"`, last attribute a correct `FINGERPRINT`). Returns its transaction id.
pub fn parse_binding_request(b: &[u8]) -> Result<TxId, StunError> {
    if !is_stun(b) {
        return Err(StunError::NotStun);
    }
    if b[..2] != [0x00, 0x01] {
        return Err(StunError::NotBindingRequest);
    }
    let mut txid = [0u8; TXID_LEN];
    txid.copy_from_slice(&b[8..20]);
    let (mut software_ok, mut last, mut got_fp) = (false, 0u16, 0u32);
    for_each_attr(&b[HEADER_LEN..], |ty, a| {
        last = ty;
        if ty == ATTR_SOFTWARE && a == SOFTWARE {
            software_ok = true;
        }
        if ty == ATTR_FINGERPRINT && a.len() == 4 {
            got_fp = u32::from_be_bytes([a[0], a[1], a[2], a[3]]);
        }
        Ok(())
    })?;
    if !software_ok {
        return Err(StunError::WrongSoftware);
    }
    if last != ATTR_FINGERPRINT {
        return Err(StunError::NoFingerprint);
    }
    if got_fp != fingerprint(&b[..b.len() - 8]) {
        return Err(StunError::WrongFingerprint);
    }
    Ok(txid)
}

/// What a message's `FINGERPRINT` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    /// No `FINGERPRINT` attribute (or the message is not well formed enough to find one).
    Absent,
    /// Present and correct.
    Valid,
    /// Present and wrong.
    Invalid,
}

/// Check the `FINGERPRINT` of a message whose last attribute it is (RFC 5389: it must be last). The header length field is not trusted: the CRC covers
/// the message up to the attribute, as the sender computed it with the length already including the attribute.
pub fn check_fingerprint(b: &[u8]) -> Fingerprint {
    if !is_stun(b) {
        return Fingerprint::Absent;
    }
    let attrs_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    let end = HEADER_LEN + attrs_len;
    if attrs_len < 8 || end > b.len() || attrs_len % 4 != 0 {
        return Fingerprint::Absent;
    }
    let at = end - 8;
    if b[at..at + 4] != [0x80, 0x28, 0x00, 0x04] {
        return Fingerprint::Absent;
    }
    let got = u32::from_be_bytes([b[at + 4], b[at + 5], b[at + 6], b[at + 7]]);
    if got == fingerprint(&b[..at]) { Fingerprint::Valid } else { Fingerprint::Invalid }
}

/// A parsed binding response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingResponse {
    /// The request's transaction id.
    pub txid: TxId,
    /// Our address as the server saw it.
    pub mapped: Ep,
    /// It came from an `XOR-MAPPED-ADDRESS` (false: the legacy `MAPPED-ADDRESS`).
    pub xor: bool,
}

fn family_len(f: u8) -> usize {
    match f {
        1 => 4,
        2 => 16,
        _ => 0,
    }
}

fn mapped_ep(a: &[u8], xor: Option<&TxId>) -> Result<Ep, StunError> {
    if a.len() < 4 {
        return Err(StunError::MalformedAttrs);
    }
    let n = family_len(a[1]);
    if n == 0 || a.len() < 4 + n {
        return Err(StunError::MalformedAttrs);
    }
    let mut port = u16::from_be_bytes([a[2], a[3]]);
    let mut ip = [0u8; 16];
    let src = &a[4..4 + n];
    for (i, &v) in src.iter().enumerate() {
        ip[16 - n + i] = match xor {
            Some(_) if i < 4 => v ^ MAGIC_COOKIE[i],
            Some(tx) => v ^ tx[i - 4],
            None => v,
        };
    }
    if xor.is_some() {
        port ^= 0x2112;
    }
    if n == 4 {
        ip[10] = 0xff;
        ip[11] = 0xff;
    }
    Ok(Ep::v6(ip, port))
}

/// Parse a binding success response. `XOR-MAPPED-ADDRESS` (or the alternate attribute number) wins over `MAPPED-ADDRESS`; with several, the last wins.
pub fn parse_response(b: &[u8]) -> Result<BindingResponse, StunError> {
    if !is_stun(b) {
        return Err(StunError::NotStun);
    }
    let mut txid = [0u8; TXID_LEN];
    txid.copy_from_slice(&b[8..20]);
    if b[0] != 0x01 || b[1] != 0x01 {
        return Err(StunError::NotSuccessResponse);
    }
    let attrs_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    let mut attrs = &b[HEADER_LEN..];
    if attrs_len > attrs.len() {
        return Err(StunError::MalformedAttrs);
    }
    attrs = &attrs[..attrs_len];
    let (mut xor, mut legacy): (Option<Ep>, Option<Ep>) = (None, None);
    for_each_attr(attrs, |ty, a| {
        match ty {
            ATTR_XOR_MAPPED | ATTR_XOR_MAPPED_ALT => xor = Some(mapped_ep(a, Some(&txid))?),
            ATTR_MAPPED => legacy = Some(mapped_ep(a, None)?),
            _ => {}
        }
        Ok(())
    })?;
    match (xor, legacy) {
        (Some(mapped), _) => Ok(BindingResponse { txid, mapped, xor: true }),
        (None, Some(mapped)) => Ok(BindingResponse { txid, mapped, xor: false }),
        (None, None) => Err(StunError::MalformedAttrs),
    }
}

/// Build a binding success response with one `XOR-MAPPED-ADDRESS` (Go's `stun.Response`): for tests and for a gateway that answers STUN itself.
pub fn build_response(txid: &TxId, ep: &Ep, out: &mut [u8]) -> Result<usize, StunError> {
    let (family, n) = if ep.is_v4() { (1u8, 4usize) } else { (2u8, 16usize) };
    let attrs_len = 8 + n;
    let total = HEADER_LEN + attrs_len;
    let out = out.get_mut(..total).ok_or(StunError::BufferTooSmall)?;
    out[0..2].copy_from_slice(&[0x01, 0x01]);
    out[2..4].copy_from_slice(&(attrs_len as u16).to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC_COOKIE);
    out[8..20].copy_from_slice(txid);
    out[20..22].copy_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
    out[22..24].copy_from_slice(&((4 + n) as u16).to_be_bytes());
    out[24] = 0;
    out[25] = family;
    out[26..28].copy_from_slice(&(ep.port() ^ 0x2112).to_be_bytes());
    let ip = ep.ip16();
    for i in 0..n {
        let v = ip[16 - n + i];
        out[28 + i] = if i < 4 { v ^ MAGIC_COOKIE[i] } else { v ^ txid[i - 4] };
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    /// Output of Go's `stun.Request` for txid 01..0c (generated with the Go package, see tests/go_vectors.rs for the rest).
    #[test]
    fn request_matches_go() {
        let tx: TxId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut out = [0u8; REQUEST_LEN];
        build_request(&tx, &mut out);
        assert_eq!(out, hex!("000100142112a4420102030405060708090a0b0c802200087461696c6e6f646580280004b32c370f"));
        assert_eq!(parse_binding_request(&out), Ok(tx));
        assert_eq!(check_fingerprint(&out), Fingerprint::Valid);
        // the order xdp DERP relies on (Go TestAttrOrderForXdpDERP)
        assert_eq!(&out[20..22], &[0x80, 0x22]);
        assert_eq!(&out[24..32], b"tailnode");
    }

    #[test]
    fn request_rejections() {
        let tx = [3u8; 12];
        let mut good = [0u8; REQUEST_LEN];
        build_request(&tx, &mut good);
        let mut b = good;
        b[37] ^= 1;
        assert_eq!(parse_binding_request(&b), Err(StunError::WrongFingerprint));
        assert_eq!(check_fingerprint(&b), Fingerprint::Invalid);
        let mut b = good;
        b[24] = b'T';
        assert_eq!(parse_binding_request(&b), Err(StunError::WrongSoftware));
        let mut b = good;
        b[1] = 2;
        assert_eq!(parse_binding_request(&b), Err(StunError::NotBindingRequest));
        let mut b = good;
        b[4] = 0;
        assert_eq!(parse_binding_request(&b), Err(StunError::NotStun));
        assert_eq!(parse_binding_request(&good[..39]), Err(StunError::MalformedAttrs));
        // software but no fingerprint at the end
        assert_eq!(parse_binding_request(&good[..32]), Err(StunError::NoFingerprint));
        assert_eq!(check_fingerprint(&good[..32]), Fingerprint::Absent);
    }

    #[test]
    fn is_matches_go_table() {
        let cookie = [0x21u8, 0x12, 0xa4, 0x42];
        let mk = |first: u8, tail: usize| {
            extern crate std;
            let mut v = std::vec![first, 0, 0, 0];
            v.extend_from_slice(&cookie);
            v.extend(core::iter::repeat_n(0u8, tail));
            v
        };
        assert!(!is_stun(b""));
        assert!(!is_stun(&[0u8; 20]));
        assert!(!is_stun(&mk(0, 11)));
        assert!(is_stun(&mk(0, 12)));
        let mut foo = mk(0, 12);
        foo.extend_from_slice(b"foo");
        assert!(is_stun(&foo));
        assert!(!is_stun(&mk(0xf0, 12)));
        assert!(!is_stun(&mk(0x40, 12)));
        assert!(is_stun(&mk(0x20, 12)));
    }

    #[test]
    fn response_builder_round_trips_and_matches_go() {
        let tx: TxId = core::array::from_fn(|i| 0xa0 + (i as u8) * 7);
        let v4 = Ep::v4([203, 0, 113, 9], 51820);
        let mut b = [0u8; 64];
        let n = build_response(&tx, &v4, &mut b).unwrap();
        assert_eq!(&b[..n], &hex!("0101000c2112a442a0a7aeb5bcc3cad1d8dfe6ed002000080001eb7eea12d54b")[..]);
        assert_eq!(parse_response(&b[..n]), Ok(BindingResponse { txid: tx, mapped: v4, xor: true }));
        let v6 = Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2], 41641);
        let n = build_response(&tx, &v6, &mut b).unwrap();
        assert_eq!(&b[..n], &hex!("010100182112a442a0a7aeb5bcc3cad1d8dfe6ed00200014000283bb0113a9faa0a7aeb5bcc3cad1d8dee6ef")[..]);
        assert_eq!(parse_response(&b[..n]).unwrap().mapped, v6);
        assert_eq!(build_response(&tx, &v6, &mut b[..43]), Err(StunError::BufferTooSmall));
    }

    #[test]
    fn rejections() {
        let tx = [5u8; 12];
        let mut b = [0u8; 64];
        let n = build_response(&tx, &Ep::v4([1, 2, 3, 4], 5), &mut b).unwrap();
        // type, truncation, bad family, short attribute
        let mut x = b;
        x[0] = 0x01;
        x[1] = 0x11;
        assert_eq!(parse_response(&x[..n]), Err(StunError::NotSuccessResponse));
        assert_eq!(parse_response(&b[..n - 1]), Err(StunError::MalformedAttrs));
        let mut x = b;
        x[25] = 3;
        assert_eq!(parse_response(&x[..n]), Err(StunError::MalformedAttrs));
        let mut x = b;
        x[23] = 3; // attribute length 3: shorter than a mapped address
        assert_eq!(parse_response(&x[..n]), Err(StunError::MalformedAttrs));
        assert_eq!(parse_response(&b[..19]), Err(StunError::NotStun));
        // no mapped address at all (only SOFTWARE)
        let mut only = [0u8; 28];
        only[..2].copy_from_slice(&[1, 1]);
        only[2..4].copy_from_slice(&8u16.to_be_bytes());
        only[4..8].copy_from_slice(&MAGIC_COOKIE);
        only[20..22].copy_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        only[23] = 4;
        assert_eq!(parse_response(&only), Err(StunError::MalformedAttrs));
    }

    #[test]
    fn too_many_attributes_are_malformed() {
        extern crate std;
        let mut v = std::vec![0u8; HEADER_LEN];
        v[..2].copy_from_slice(&[1, 1]);
        v[4..8].copy_from_slice(&MAGIC_COOKIE);
        for _ in 0..=MAX_ATTRS {
            v.extend_from_slice(&[0x80, 0x22, 0, 0]);
        }
        let l = (v.len() - HEADER_LEN) as u16;
        v[2..4].copy_from_slice(&l.to_be_bytes());
        assert_eq!(parse_response(&v), Err(StunError::MalformedAttrs));
    }
}
