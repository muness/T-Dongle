//! The DERP trust policy of the C (`ml_derp_tls.c`, ADR 0021), sans-IO: given the certificates a server presented, decide.
//!
//! * Trust anchors are `(subject DN, SubjectPublicKeyInfo)` pairs compared by bytes (no certificate, no signature, no validity period): a
//!   presented certificate equal to an anchor on both is that anchor and its own signature is never checked, so the RSA-4096 cross-signature
//!   on the `ISRG Root X2` that DERP sends costs nothing (and RSA is not even compiled in).
//! * Every presented certificate on the path must be inside its validity period, checked against a wall clock that must be set
//!   ([`MIN_VALID_UNIX`], the C's `ml_derp_clock_valid`).
//! * Host names: subjectAltName only (no CommonName fallback), a wildcard only as the whole left-most label and one label deep, IP literals
//!   against iPAddress entries.
//! * `sha256-raw:` pin: exactly one certificate besides Tailscale's Ed25519 `derpkey` meta certificate, equal to the pin; no chain, but
//!   dates and the name still count.
//! * Nothing is skipped: an unsupported algorithm, an unknown critical extension, a missing server name all fail closed.

use crate::cert_name::DerpCert;
use crate::der::{Cert, KeyKind, SigAlg, is_ed25519, parse_spki};
use crate::rsa::{self, Hash as RsaHash, PublicKey};
use core::net::IpAddr;
use core::str::FromStr;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
#[cfg(feature = "p384")]
use sha2::Sha384;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The C's `ml_derp_clock_valid`: a Unix time at or below this (Nov 2023) means the clock was never set.
pub const MIN_VALID_UNIX: u64 = 1_700_000_000;
/// Longest chain examined (entries beyond it are a refusal, not a truncation).
pub const MAX_CHAIN: usize = 16;
/// Deepest path from leaf to anchor.
pub const MAX_PATH: usize = 8;

/// A trust anchor: the subject DN and the SubjectPublicKeyInfo, both as raw DER (TLV) bytes, exactly as the ESP-IDF bundle stores them.
#[derive(Clone, Copy, Debug)]
pub struct TrustAnchor<'a> {
    /// Subject Name (whole DER SEQUENCE).
    pub subject: &'a [u8],
    /// SubjectPublicKeyInfo (whole DER SEQUENCE).
    pub spki: &'a [u8],
}

/// ISRG Root X2 (ECDSA P-384), the root of the Let's Encrypt ECDSA hierarchy that DERP serves.
pub const ISRG_ROOT_X2: TrustAnchor<'static> =
    TrustAnchor { subject: include_bytes!("../anchors/isrg_root_x2.subject.der"), spki: include_bytes!("../anchors/isrg_root_x2.spki.der") };
/// ISRG Root YE (ECDSA P-384, cross-signed by X2): anchoring it saves one P-384 verification per handshake. Not in the C's bundle; opt in.
pub const ISRG_ROOT_YE: TrustAnchor<'static> =
    TrustAnchor { subject: include_bytes!("../anchors/isrg_root_ye.subject.der"), spki: include_bytes!("../anchors/isrg_root_ye.spki.der") };
/// ISRG Root X1 (RSA-4096), the root of the RSA hierarchy; the Go derper serves the RSA chain `leaf <- YR1 <- Root YR` to a TLS 1.3-only client.
pub const ISRG_ROOT_X1: TrustAnchor<'static> =
    TrustAnchor { subject: include_bytes!("../anchors/isrg_root_x1.subject.der"), spki: include_bytes!("../anchors/isrg_root_x1.spki.der") };
/// ISRG Root YR (RSA-4096, cross-signed by X1): anchoring it saves the RSA-4096 verification of its own signature. Not in the C's bundle; opt in.
pub const ISRG_ROOT_YR: TrustAnchor<'static> =
    TrustAnchor { subject: include_bytes!("../anchors/isrg_root_yr.subject.der"), spki: include_bytes!("../anchors/isrg_root_yr.spki.der") };
/// Both ISRG hierarchies the DERP servers use, by the roots the C's ESP-IDF bundle holds: X2 (ECDSA) and X1 (RSA).
pub const DEFAULT_ANCHORS: &[TrustAnchor<'static>] = &[ISRG_ROOT_X2, ISRG_ROOT_X1];
/// The same plus the cross-signed generation Y roots: one signature fewer on either hierarchy.
pub const FAST_ANCHORS: &[TrustAnchor<'static>] = &[ISRG_ROOT_YE, ISRG_ROOT_YR, ISRG_ROOT_X2, ISRG_ROOT_X1];

/// Why a server was refused. Exhaustive: every failure path of the verifier is one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The wall clock is not set ([`MIN_VALID_UNIX`]); the handshake is not even attempted.
    ClockNotSet,
    /// CertName was unusable ([`DerpCert::Invalid`]).
    InvalidCertName,
    /// No server name was configured, so no host name could be checked.
    NoServerName,
    /// The server sent no certificate, or more than [`MAX_CHAIN`].
    BadChainLength,
    /// A certificate did not parse.
    Malformed,
    /// A presented certificate on the path is past `notAfter`.
    Expired,
    /// A presented certificate on the path is before `notBefore`.
    NotYetValid,
    /// No path to a trust anchor (unknown issuer, self-signed, anchor name with another key, path too deep).
    NotTrusted,
    /// A signature on the path did not verify.
    BadSignature,
    /// A signature or key algorithm that is not compiled in (RSA, EdDSA, other curves, other digests).
    UnsupportedAlgorithm,
    /// An issuer on the path is not a CA (basicConstraints) or may not sign certificates (keyUsage).
    NotCa,
    /// basicConstraints pathLenConstraint exceeded.
    PathLength,
    /// The leaf may not be used for TLS server authentication (keyUsage or extKeyUsage).
    KeyUsage,
    /// A critical extension this crate does not understand.
    UnknownCriticalExtension,
    /// The certificate does not name the host (subjectAltName only).
    NameMismatch,
    /// `sha256-raw:` pin: the certificate is not the pinned one.
    PinMismatch,
    /// `sha256-raw:` pin: a second certificate besides the `derpkey` meta certificate.
    PinExtraCertificate,
    /// CertificateVerify did not verify with the leaf's key, or used a scheme the key cannot.
    BadHandshakeSignature,
}

/// How the chain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedBy {
    /// `sha256-raw:` pin.
    Pin,
    /// A presented certificate was itself an anchor (subject and SPKI equal): the cross-certificate case. `anchor` indexes the anchor slice.
    PresentedAnchor {
        /// Index into the anchors given to [`verify_chain`].
        anchor: usize,
    },
    /// The last presented certificate was issued by an anchor that was not itself presented.
    IssuerAnchor {
        /// Index into the anchors given to [`verify_chain`].
        anchor: usize,
    },
}

/// Largest leaf key kept for CertificateVerify: an RSA-4096 `RSAPublicKey` is 526 bytes.
pub const LEAF_KEY_MAX: usize = 528;

/// The leaf's public key for CertificateVerify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafKey {
    pub(crate) kind: KeyKind,
    point: [u8; LEAF_KEY_MAX],
    len: u16,
}

impl LeafKey {
    pub(crate) fn point(&self) -> &[u8] {
        &self.point[..self.len as usize]
    }
}

/// A verified chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The leaf's key, for the CertificateVerify check.
    pub leaf_key: LeafKey,
    /// How trust was established.
    pub trusted_by: TrustedBy,
    /// Signature verifications done on the path, ECDSA or RSA (CPU cost accounting; the CertificateVerify one comes later).
    pub signature_verifies: u8,
    /// Certificates on the path, leaf included.
    pub path_len: u8,
}

/// Inputs of one verification.
#[derive(Clone, Copy, Debug)]
pub struct VerifyConfig<'a> {
    /// Trust anchors (flash resident).
    pub anchors: &'a [TrustAnchor<'a>],
    /// Unix time now.
    pub now_unix: u64,
    /// CertName semantics.
    pub cert: &'a DerpCert,
    /// The node's `HostName` (also the SNI); used as the name to match unless [`DerpCert::Name`] says otherwise.
    pub hostname: &'a str,
}

/// Does `now` look like a set clock (the C's `ml_derp_clock_valid`)?
pub const fn clock_valid(now_unix: u64) -> bool {
    now_unix > MIN_VALID_UNIX
}

fn trimmed(s: &[u8]) -> &[u8] {
    s.strip_suffix(b".").unwrap_or(s)
}

/// `pattern` is a dNSName from a certificate (`dns_pattern_matches` in the C).
fn dns_pattern_matches(pattern: &[u8], host: &str) -> bool {
    let host = trimmed(host.as_bytes());
    let p = trimmed(pattern);
    if p.is_empty() || host.is_empty() {
        return false;
    }
    if p.len() > 2 && p[0] == b'*' && p[1] == b'.' {
        // The wildcard is the whole left-most label and covers exactly one label.
        let Some(dot) = host.iter().position(|&c| c == b'.') else { return false };
        if dot == 0 {
            return false;
        }
        let rest = &host[dot..];
        return rest.len() == p.len() - 1 && rest.eq_ignore_ascii_case(&p[1..]) && !p[2..].contains(&b'*');
    }
    p.len() == host.len() && !p.contains(&b'*') && p.eq_ignore_ascii_case(host)
}

/// Does the certificate name `name` (a DNS name or an IP literal)? Go's `VerifyHostname`: subjectAltName only.
pub(crate) fn cert_names(c: &Cert<'_>, name: &str) -> bool {
    let ip = IpAddr::from_str(name).ok();
    c.san_entries().any(|(tag, v)| match (tag, ip) {
        (0x82, None) => dns_pattern_matches(v, name),
        (0x87, Some(IpAddr::V4(a))) => v == a.octets(),
        (0x87, Some(IpAddr::V6(a))) => v == a.octets(),
        _ => false,
    })
}

fn check_dates(c: &Cert<'_>, now: i64) -> Result<(), Reject> {
    if now < c.not_before {
        Err(Reject::NotYetValid)
    } else if now > c.not_after {
        Err(Reject::Expired)
    } else {
        Ok(())
    }
}

/// Verify a certificate signature `sig` over `tbs` with the issuer's key (`point` from its SubjectPublicKeyInfo), per the certificate's algorithm.
pub(crate) fn verify_signature(alg: SigAlg, key: KeyKind, point: &[u8], tbs: &[u8], sig: &[u8]) -> Result<(), Reject> {
    let rsa_hash = match alg {
        SigAlg::RsaSha256 => Some(RsaHash::Sha256),
        #[cfg(feature = "p384")]
        SigAlg::RsaSha384 => Some(RsaHash::Sha384),
        #[cfg(feature = "p384")]
        SigAlg::RsaSha512 => Some(RsaHash::Sha512),
        _ => None,
    };
    if let Some(h) = rsa_hash {
        if key != KeyKind::Rsa {
            return Err(Reject::BadSignature); // an RSA signature by a non-RSA key never verifies
        }
        let pk = PublicKey::parse(point).ok_or(Reject::UnsupportedAlgorithm)?;
        return if rsa::verify_pkcs1(&pk, h, tbs, sig) { Ok(()) } else { Err(Reject::BadSignature) };
    }
    let digest: [u8; 48];
    let h: &[u8] = match alg {
        SigAlg::EcdsaSha256 => {
            let d: [u8; 32] = Sha256::digest(tbs).into();
            let mut b = [0u8; 48];
            b[..32].copy_from_slice(&d);
            digest = b;
            &digest[..32]
        }
        #[cfg(feature = "p384")]
        SigAlg::EcdsaSha384 => {
            digest = Sha384::digest(tbs).into();
            &digest[..]
        }
        _ => return Err(Reject::UnsupportedAlgorithm),
    };
    match key {
        KeyKind::EcP256 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| Reject::Malformed)?;
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| Reject::BadSignature)?;
            vk.verify_prehash(h, &s).map_err(|_| Reject::BadSignature)
        }
        #[cfg(feature = "p384")]
        KeyKind::EcP384 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| Reject::Malformed)?;
            let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| Reject::BadSignature)?;
            vk.verify_prehash(h, &s).map_err(|_| Reject::BadSignature)
        }
        #[cfg(not(feature = "p384"))]
        KeyKind::EcP384 => Err(Reject::UnsupportedAlgorithm),
        KeyKind::Rsa | KeyKind::Ed25519 | KeyKind::Other => Err(Reject::BadSignature),
    }
}

fn is_meta(c: &Cert<'_>) -> bool {
    is_ed25519(c) && c.subject_common_name().is_some_and(|cn| cn.starts_with(b"derpkey"))
}

/// Verify the certificate list a server presented (leaf first), the whole trust policy of the C. See the module docs.
pub fn verify_chain(cfg: &VerifyConfig<'_>, entries: &[&[u8]]) -> Result<Accepted, Reject> {
    if !clock_valid(cfg.now_unix) {
        return Err(Reject::ClockNotSet);
    }
    let now = i64::try_from(cfg.now_unix).unwrap_or(i64::MAX);
    let name: &str = match cfg.cert {
        DerpCert::Invalid => return Err(Reject::InvalidCertName),
        DerpCert::Name(n) => n.as_str(),
        _ => cfg.hostname,
    };
    if name.is_empty() {
        return Err(Reject::NoServerName);
    }
    if entries.is_empty() || entries.len() > MAX_CHAIN {
        return Err(Reject::BadChainLength);
    }
    let mut certs: [Option<Cert<'_>>; MAX_CHAIN] = [None; MAX_CHAIN];
    let mut used = [false; MAX_CHAIN];
    let mut ecdsa = 0u8;
    for (i, der) in entries.iter().enumerate() {
        let c = Cert::parse(der).ok_or(Reject::Malformed)?;
        // Tailscale's derper appends an Ed25519 "derpkey" meta certificate after the real chain; Go skips it and mbedTLS cannot parse it.
        used[i] = i > 0 && is_meta(&c);
        certs[i] = Some(c);
    }
    let leaf = certs[0].ok_or(Reject::Malformed)?;
    if leaf.unknown_critical {
        return Err(Reject::UnknownCriticalExtension);
    }
    check_dates(&leaf, now)?;
    if !leaf.key_usage_allows(0) || !leaf.eku_server_auth {
        return Err(Reject::KeyUsage);
    }
    let leaf_key = {
        if leaf.point.len() > LEAF_KEY_MAX {
            return Err(Reject::Malformed);
        }
        let mut point = [0u8; LEAF_KEY_MAX];
        point[..leaf.point.len()].copy_from_slice(leaf.point);
        LeafKey { kind: leaf.key, point, len: leaf.point.len() as u16 }
    };
    let finish = |trusted_by, signature_verifies, path_len| -> Result<Accepted, Reject> {
        if !cert_names(&leaf, name) {
            return Err(Reject::NameMismatch);
        }
        Ok(Accepted { leaf_key: leaf_key.clone(), trusted_by, signature_verifies, path_len })
    };

    if let DerpCert::Pin(pin) = cfg.cert {
        // Exactly one certificate besides the meta certificate; it must be the pinned one.
        if (1..entries.len()).any(|i| !used[i]) {
            return Err(Reject::PinExtraCertificate);
        }
        let h: [u8; 32] = Sha256::digest(leaf.raw).into();
        if !bool::from(h.ct_eq(pin)) {
            return Err(Reject::PinMismatch);
        }
        return finish(TrustedBy::Pin, 0, 1);
    }

    used[0] = true;
    let mut cur = leaf;
    let mut depth = 1usize; // certificates on the path so far
    let mut unsupported = false;
    let mut bad_sig = false;
    loop {
        if depth > MAX_PATH {
            return Err(Reject::NotTrusted);
        }
        // 1. A presented certificate that issued `cur`.
        let mut next: Option<(usize, Cert<'_>)> = None;
        for j in 1..entries.len() {
            let Some(p) = certs[j] else { continue };
            if used[j] || p.subject != cur.issuer {
                continue;
            }
            match verify_signature(cur.sig_alg, p.key, p.point, cur.tbs, cur.sig) {
                Ok(()) => {
                    ecdsa = ecdsa.saturating_add(1);
                    next = Some((j, p));
                    break;
                }
                Err(Reject::UnsupportedAlgorithm) => unsupported = true,
                Err(_) => {
                    ecdsa = ecdsa.saturating_add(1);
                    bad_sig = true;
                }
            }
        }
        if let Some((j, p)) = next {
            used[j] = true;
            if p.unknown_critical {
                return Err(Reject::UnknownCriticalExtension);
            }
            check_dates(&p, now)?;
            // The presented issuer must be a CA allowed to sign (mbedTLS checks this for every parent, anchors included).
            match p.basic {
                Some((true, path)) => {
                    if path.is_some_and(|n| (depth as u32 - 1) > n) {
                        return Err(Reject::PathLength);
                    }
                }
                _ => return Err(Reject::NotCa),
            }
            if !p.key_usage_allows(5) {
                return Err(Reject::NotCa);
            }
            if let Some(a) = cfg.anchors.iter().position(|a| a.subject == p.subject && a.spki == p.spki) {
                // The presented certificate IS an anchor: its own signature adds nothing (RFC 5280 6.1.1(d)); never verified.
                return finish(TrustedBy::PresentedAnchor { anchor: a }, ecdsa, depth as u8 + 1);
            }
            if p.subject == p.issuer {
                return Err(Reject::NotTrusted); // self-signed and not ours
            }
            cur = p;
            depth += 1;
            continue;
        }
        // 2. An anchor that issued `cur` and was not presented.
        for (ai, a) in cfg.anchors.iter().enumerate() {
            if a.subject != cur.issuer {
                continue;
            }
            let Some((kind, point)) = parse_spki(a.spki) else { continue };
            match verify_signature(cur.sig_alg, kind, point, cur.tbs, cur.sig) {
                Ok(()) => return finish(TrustedBy::IssuerAnchor { anchor: ai }, ecdsa.saturating_add(1), depth as u8 + 1),
                Err(Reject::UnsupportedAlgorithm) => unsupported = true,
                Err(_) => {
                    ecdsa = ecdsa.saturating_add(1);
                    bad_sig = true;
                }
            }
        }
        return Err(if unsupported {
            Reject::UnsupportedAlgorithm
        } else if bad_sig {
            Reject::BadSignature
        } else {
            Reject::NotTrusted
        });
    }
}
