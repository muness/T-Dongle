//! How a DERP node's TLS server is authenticated, from `DERPNode.CertName` (the C's `ml_derp_cert.c`).

use tdongle_tailnet_types::FixedStr;

/// Prefix of a pinned leaf certificate: `sha256-raw:` followed by 64 hex digits of the SHA-256 of the DER.
pub const PIN_PREFIX: &str = "sha256-raw:";
/// `ML_DERP_CERT_NAME_MAX` (64 with the NUL): longest accepted certificate name is 63 bytes.
pub const CERT_NAME_MAX: usize = 63;

/// The authentication mode of a DERP node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerpCert {
    /// Verify against `HostName` (no `CertName`, or one equal to it).
    Hostname,
    /// Verify against this name; SNI stays `HostName`.
    Name(FixedStr<CERT_NAME_MAX>),
    /// The leaf certificate must hash to this SHA-256.
    Pin([u8; 32]),
    /// `CertName` present but unusable (bad pin, too long, not a host name, wrong type, or no whole `HostName`): never connect.
    Invalid,
}

fn trimmed(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// A DNS name or IP literal this module is willing to compare certificates with (`ml_derp_name_plausible`; no wildcard).
pub fn name_plausible(s: &str) -> bool {
    !s.is_empty() && s.len() <= CERT_NAME_MAX && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':'))
}

/// Interpret a node's `CertName` (`ml_derp_cert_parse`). `cert_name` `None` or empty is the default. A name equal to `hostname` (ignoring case and one
/// trailing dot) is the default too.
pub fn cert_parse(hostname: &str, cert_name: Option<&str>) -> DerpCert {
    let Some(name) = cert_name.filter(|n| !n.is_empty()) else {
        return DerpCert::Hostname;
    };
    if let Some(hex) = name.strip_prefix(PIN_PREFIX) {
        return match tdongle_tailnet_types::Key32::from_hex(hex.as_bytes()) {
            Some(k) => DerpCert::Pin(*k.as_bytes()),
            None => DerpCert::Invalid,
        };
    }
    if trimmed(hostname).eq_ignore_ascii_case(trimmed(name)) {
        return DerpCert::Hostname;
    }
    if !name_plausible(name) {
        return DerpCert::Invalid;
    }
    let mut s = FixedStr::new();
    s.set(name);
    DerpCert::Name(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::ToString};

    #[test]
    fn cert_name_rules() {
        assert_eq!(cert_parse("derp1.example.com", None), DerpCert::Hostname);
        assert_eq!(cert_parse("derp1.example.com", Some("")), DerpCert::Hostname);
        // equal to the host name, ignoring case and a trailing dot
        assert_eq!(cert_parse("derp1.example.com", Some("DERP1.example.com.")), DerpCert::Hostname);
        assert_eq!(cert_parse("derp1.example.com.", Some("derp1.example.com")), DerpCert::Hostname);
        match cert_parse("derp1.example.com", Some("front.example")) {
            DerpCert::Name(n) => assert_eq!(n.as_str(), "front.example"),
            o => panic!("{o:?}"),
        }
        let pin = format!("{PIN_PREFIX}{}", "ab".repeat(32));
        assert_eq!(cert_parse("10.0.0.1", Some(&pin)), DerpCert::Pin([0xab; 32]));
        for bad in [
            format!("{PIN_PREFIX}ab"),
            format!("{PIN_PREFIX}{}", "zz".repeat(32)),
            format!("{PIN_PREFIX}{}", "ab".repeat(33)),
            "*.example.com".to_string(),
            "has space".to_string(),
            "a".repeat(64),
            "über.example".to_string(),
        ] {
            assert_eq!(cert_parse("derp1.example.com", Some(&bad)), DerpCert::Invalid, "{bad}");
        }
        // the longest accepted name is 63 bytes
        assert!(matches!(cert_parse("h", Some(&"a".repeat(63))), DerpCert::Name(_)));
        assert!(name_plausible("2001:db8::1"));
        assert!(!name_plausible(""));
    }
}
