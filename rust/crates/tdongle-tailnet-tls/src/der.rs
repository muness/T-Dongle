//! A bounds-checked, allocation-free X.509 certificate reader: just the fields the DERP trust policy needs.
//!
//! Every function returns `None` on anything it does not understand (indefinite lengths, truncation, trailing bytes where none are allowed);
//! nothing panics and nothing indexes without a check (see the mini-fuzz test in `verify`).

/// One DER element: its tag, content and the whole encoding (tag, length, content).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Read one element from the front of `buf`; return it and the rest. Single-byte tags, lengths up to 3 bytes (16 MiB).
pub(crate) fn read(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tag numbers do not occur in certificates
    }
    let first = *buf.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 {
            return None; // indefinite or absurd
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *buf.get(2 + i)? as usize;
        }
        if l < 0x80 {
            return None; // not minimal
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let raw = buf.get(..end)?;
    Some((Tlv { tag, content: &raw[hdr..], raw }, &buf[end..]))
}

/// Read one element and require `tag`.
pub(crate) fn read_tag(buf: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (t, rest) = read(buf)?;
    (t.tag == tag).then_some((t, rest))
}

pub(crate) const SEQ: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
pub(crate) const INT: u8 = 0x02;
pub(crate) const OID: u8 = 0x06;
pub(crate) const BITSTR: u8 = 0x03;
pub(crate) const OCTSTR: u8 = 0x04;
pub(crate) const BOOL: u8 = 0x01;

/// What kind of public key a certificate carries (only what this crate can use).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyKind {
    EcP256,
    EcP384,
    Ed25519,
    /// rsaEncryption; `point` is the DER `RSAPublicKey`.
    Rsa,
    Other,
}

/// Signature algorithms a certificate can be signed with that this crate verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigAlg {
    EcdsaSha256,
    EcdsaSha384,
    RsaSha256,
    RsaSha384,
    RsaSha512,
    Other,
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
// Extensions that may be critical and are understood or harmless: SKI, AKI, certificatePolicies, AIA, CRL DP, SCT list.
const NON_CRITICAL_OK: [&[u8]; 6] = [
    &[0x55, 0x1d, 0x0e],
    &[0x55, 0x1d, 0x23],
    &[0x55, 0x1d, 0x20],
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01],
    &[0x55, 0x1d, 0x1f],
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02],
];

/// Days since 1970-01-01 of a civil date (proleptic Gregorian; Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// UTCTime `YYMMDDHHMMSSZ` or GeneralizedTime `YYYYMMDDHHMMSSZ` as Unix seconds (RFC 5280 section 4.1.2.5; fractional seconds and offsets are refused).
fn parse_time(t: Tlv<'_>) -> Option<i64> {
    let s = t.content;
    let (y, rest) = match (t.tag, s.len()) {
        (0x17, 13) => {
            let yy = two(s, 0)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        (0x18, 15) => (two(s, 0)? * 100 + two(s, 2)?, &s[4..]),
        _ => return None,
    };
    if rest.len() != 11 || rest[10] != b'Z' {
        return None;
    }
    let (mo, d, h, mi, se) = (two(rest, 0)?, two(rest, 2)?, two(rest, 4)?, two(rest, 6)?, two(rest, 8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

fn two(s: &[u8], i: usize) -> Option<i64> {
    let (a, b) = (*s.get(i)?, *s.get(i + 1)?);
    (a.is_ascii_digit() && b.is_ascii_digit()).then(|| ((a - b'0') * 10 + (b - b'0')) as i64)
}

/// Split a SubjectPublicKeyInfo (whole TLV) into its key kind and key bits (an uncompressed EC point, or 32 Ed25519 bytes).
pub(crate) fn parse_spki(spki: &[u8]) -> Option<(KeyKind, &[u8])> {
    let (seq, rest) = read_tag(spki, SEQ)?;
    if !rest.is_empty() {
        return None;
    }
    let (alg, key_bits) = read_tag(seq.content, SEQ)?;
    let (key_bits, tail) = read_tag(key_bits, BITSTR)?;
    if !tail.is_empty() || key_bits.content.first() != Some(&0) {
        return None;
    }
    let point = &key_bits.content[1..];
    let (alg_oid, params) = read_tag(alg.content, OID)?;
    let key = match alg_oid.content {
        OID_EC_PUBLIC_KEY => match read_tag(params, OID) {
            Some((curve, _)) if curve.content == OID_P256 && point.len() == 65 => KeyKind::EcP256,
            Some((curve, _)) if curve.content == OID_P384 && point.len() == 97 => KeyKind::EcP384,
            _ => KeyKind::Other,
        },
        OID_ED25519 if point.len() == 32 => KeyKind::Ed25519,
        OID_RSA => KeyKind::Rsa,
        _ => KeyKind::Other,
    };
    Some((key, point))
}

/// The fields of one certificate that the trust policy reads. All slices point into the input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cert<'a> {
    /// The whole certificate (what the `sha256-raw:` pin hashes).
    pub raw: &'a [u8],
    /// `tbsCertificate`, the signed bytes (whole TLV).
    pub tbs: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// SubjectPublicKeyInfo, whole TLV (what an anchor pins).
    pub spki: &'a [u8],
    /// The subjectPublicKey bits (an uncompressed EC point or 32 Ed25519 bytes).
    pub point: &'a [u8],
    pub key: KeyKind,
    pub sig_alg: SigAlg,
    /// The signature value (BIT STRING content without the unused-bits byte).
    pub sig: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    /// `subjectAltName` extension value (the GeneralNames SEQUENCE content), if present.
    pub san: Option<&'a [u8]>,
    /// `basicConstraints`: `Some((cA, pathLen))` when the extension is present.
    pub basic: Option<(bool, Option<u32>)>,
    /// `keyUsage` bits, bit 0 = digitalSignature ... bit 5 = keyCertSign (RFC 5280 numbering from the MSB of the first byte).
    pub key_usage: Option<u16>,
    /// `extKeyUsage` permits server authentication (true when the extension is absent).
    pub eku_server_auth: bool,
    /// A critical extension this crate does not understand.
    pub unknown_critical: bool,
}

impl<'a> Cert<'a> {
    /// Parse a DER certificate. `None` for anything malformed or trailing garbage.
    pub fn parse(der: &'a [u8]) -> Option<Cert<'a>> {
        let (cert, rest) = read_tag(der, SEQ)?;
        if !rest.is_empty() {
            return None;
        }
        let (tbs, after_tbs) = read_tag(cert.content, SEQ)?;
        let (sigalg, after_alg) = read_tag(after_tbs, SEQ)?;
        let (sigbits, tail) = read_tag(after_alg, BITSTR)?;
        if !tail.is_empty() || sigbits.content.first() != Some(&0) {
            return None;
        }
        let sig = &sigbits.content[1..];
        let (alg_oid, _) = read_tag(sigalg.content, OID)?;
        let sig_alg = match alg_oid.content {
            OID_ECDSA_SHA256 => SigAlg::EcdsaSha256,
            OID_ECDSA_SHA384 => SigAlg::EcdsaSha384,
            OID_RSA_SHA256 => SigAlg::RsaSha256,
            OID_RSA_SHA384 => SigAlg::RsaSha384,
            OID_RSA_SHA512 => SigAlg::RsaSha512,
            _ => SigAlg::Other,
        };
        let mut c = tbs.content;
        if c.first() == Some(&0xa0) {
            let (v, r) = read(c)?;
            read_tag(v.content, INT)?;
            c = r;
        }
        let (_serial, c) = read_tag(c, INT)?;
        let (_inner_alg, c) = read_tag(c, SEQ)?;
        let (issuer, c) = read_tag(c, SEQ)?;
        let (validity, c) = read_tag(c, SEQ)?;
        let (nb, v_rest) = read(validity.content)?;
        let (na, v_tail) = read(v_rest)?;
        if !v_tail.is_empty() {
            return None;
        }
        let (subject, c) = read_tag(c, SEQ)?;
        let (spki, mut c) = read_tag(c, SEQ)?;
        let (key, point) = parse_spki(spki.raw)?;
        let mut out = Cert {
            raw: cert.raw,
            tbs: tbs.raw,
            issuer: issuer.raw,
            subject: subject.raw,
            spki: spki.raw,
            point,
            key,
            sig_alg,
            sig,
            not_before: parse_time(nb)?,
            not_after: parse_time(na)?,
            san: None,
            basic: None,
            key_usage: None,
            eku_server_auth: true,
            unknown_critical: false,
        };
        // Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3].
        while let Some(&tag) = c.first() {
            let (t, r) = read(c)?;
            c = r;
            match tag {
                0x81 | 0x82 => {}
                0xa3 => {
                    let (exts, tail) = read_tag(t.content, SEQ)?;
                    if !tail.is_empty() {
                        return None;
                    }
                    out.read_extensions(exts.content)?;
                }
                _ => return None,
            }
        }
        Some(out)
    }

    fn read_extensions(&mut self, mut e: &'a [u8]) -> Option<()> {
        while !e.is_empty() {
            let (ext, r) = read_tag(e, SEQ)?;
            e = r;
            let (id, mut rest) = read_tag(ext.content, OID)?;
            let mut critical = false;
            if rest.first() == Some(&BOOL) {
                let (b, r) = read(rest)?;
                critical = b.content.first().is_some_and(|&v| v != 0);
                rest = r;
            }
            let (val, tail) = read_tag(rest, OCTSTR)?;
            if !tail.is_empty() {
                return None;
            }
            match id.content {
                OID_BASIC_CONSTRAINTS => {
                    let (seq, _) = read_tag(val.content, SEQ)?;
                    let mut s = seq.content;
                    let mut ca = false;
                    if s.first() == Some(&BOOL) {
                        let (b, r) = read(s)?;
                        ca = b.content.first().is_some_and(|&v| v != 0);
                        s = r;
                    }
                    let mut path = None;
                    if s.first() == Some(&INT) {
                        let (n, _) = read(s)?;
                        if n.content.len() > 4 || n.content.is_empty() || n.content[0] & 0x80 != 0 {
                            return None;
                        }
                        path = Some(n.content.iter().fold(0u32, |a, &b| (a << 8) | b as u32));
                    }
                    self.basic = Some((ca, path));
                }
                OID_KEY_USAGE => {
                    let (bits, _) = read_tag(val.content, BITSTR)?;
                    let b = bits.content;
                    let hi = *b.get(1).unwrap_or(&0) as u16;
                    let lo = *b.get(2).unwrap_or(&0) as u16;
                    self.key_usage = Some(hi << 8 | lo);
                }
                OID_SAN => {
                    let (names, _) = read_tag(val.content, SEQ)?;
                    self.san = Some(names.content);
                }
                OID_EKU => {
                    let (seq, _) = read_tag(val.content, SEQ)?;
                    let mut s = seq.content;
                    let mut ok = false;
                    while !s.is_empty() {
                        let (o, r) = read_tag(s, OID)?;
                        s = r;
                        ok |= o.content == OID_SERVER_AUTH || o.content == OID_ANY_EKU;
                    }
                    self.eku_server_auth = ok;
                }
                other => {
                    if critical && !NON_CRITICAL_OK.contains(&other) {
                        self.unknown_critical = true;
                    }
                }
            }
        }
        Some(())
    }

    /// `keyUsage` contains the bit (0 = digitalSignature, 5 = keyCertSign); true when the extension is absent.
    pub fn key_usage_allows(&self, bit: u8) -> bool {
        match self.key_usage {
            None => true,
            Some(v) => v & (0x8000 >> bit) != 0,
        }
    }

    /// The subject's commonName (first one), for recognising Tailscale's `derpkey` meta certificate.
    pub fn subject_common_name(&self) -> Option<&'a [u8]> {
        let (name, _) = read_tag(self.subject, SEQ)?;
        let mut rdns = name.content;
        while !rdns.is_empty() {
            let (set, r) = read_tag(rdns, SET)?;
            rdns = r;
            let (atv, _) = read_tag(set.content, SEQ)?;
            let (oid, v) = read_tag(atv.content, OID)?;
            if oid.content == OID_COMMON_NAME {
                return read(v).map(|(s, _)| s.content);
            }
        }
        None
    }

    /// Iterate the SAN entries as `(tag, bytes)`; `0x82` is dNSName, `0x87` iPAddress.
    pub fn san_entries(&self) -> SanIter<'a> {
        SanIter { rest: self.san.unwrap_or(&[]) }
    }
}

/// Iterator over `subjectAltName` entries; stops at the first malformed one.
#[derive(Clone, Debug)]
pub(crate) struct SanIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SanIter<'a> {
    type Item = (u8, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match read(self.rest) {
            Some((t, r)) => {
                self.rest = r;
                Some((t.tag, t.content))
            }
            None => {
                self.rest = &[];
                None
            }
        }
    }
}

/// `true` when the SPKI is an Ed25519 key (used with the CN prefix to recognise the `derpkey` meta certificate).
pub(crate) fn is_ed25519(c: &Cert<'_>) -> bool {
    c.key == KeyKind::Ed25519
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_conversions() {
        // 2026-10-06T00:00:00Z
        let t = Tlv { tag: 0x17, content: b"261006000000Z", raw: &[] };
        assert_eq!(parse_time(t), Some(1_791_244_800));
        let g = Tlv { tag: 0x18, content: b"20261006000000Z", raw: &[] };
        assert_eq!(parse_time(g), Some(1_791_244_800));
        let y50 = Tlv { tag: 0x17, content: b"500101000000Z", raw: &[] };
        assert_eq!(parse_time(y50), Some(-631_152_000)); // 1950-01-01
        for bad in [&b"26100600000Z"[..], b"261306000000Z", b"261006000000+0100", b"26100600000AZ"] {
            assert_eq!(parse_time(Tlv { tag: 0x17, content: bad, raw: &[] }), None);
        }
    }

    #[test]
    fn length_rules() {
        assert!(read(&[0x30, 0x81, 0x05, 1, 2, 3, 4, 5]).is_none(), "non-minimal long form");
        assert!(read(&[0x30, 0x80]).is_none(), "indefinite");
        assert!(read(&[0x30, 0x05, 1]).is_none(), "truncated");
        assert!(read(&[0x1f, 0x05]).is_none(), "multi-byte tag");
        let long: std::vec::Vec<u8> = [0x30, 0x81, 0x80].iter().chain(&[0u8; 128]).chain(&[9]).copied().collect();
        let (t, rest) = read(&long).unwrap();
        assert_eq!((t.content.len(), rest), (128, &[9u8][..]));
    }
}
