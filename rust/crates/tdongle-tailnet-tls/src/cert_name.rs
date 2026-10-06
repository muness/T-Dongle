//! `DERPNode.CertName`: how a DERP node's TLS server is authenticated (port of `ml_derp_cert.c`).

use tdongle_tailnet_types::FixedStr;

/// Longest CertName this crate keeps, in bytes (the C's `ML_DERP_CERT_NAME_MAX` 64 includes the NUL).
pub const CERT_NAME_MAX: usize = 63;
/// Prefix of a pinned CertName.
pub const PIN_PREFIX: &str = "sha256-raw:";

/// How to authenticate a node's certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerpCert {
    /// Verify the chain against the node's `HostName` (no CertName, or CertName equals it).
    Hostname,
    /// Verify the chain against this name instead; the SNI stays `HostName`.
    Name(FixedStr<CERT_NAME_MAX>),
    /// The leaf is pinned by the SHA-256 of its DER encoding (self-signed DERP servers).
    Pin([u8; 32]),
    /// CertName present but unusable: never connect.
    Invalid,
}

/// A DNS name or IP literal this crate is willing to compare certificates with (the C's `ml_derp_name_plausible`; no `*`).
pub fn name_plausible(s: &str) -> bool {
    !s.is_empty() && s.len() <= CERT_NAME_MAX && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':'))
}

fn trim_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// Equal ignoring ASCII case and one trailing dot.
pub fn same_name(a: &str, b: &str) -> bool {
    trim_dot(a).eq_ignore_ascii_case(trim_dot(b))
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Interpret a DERPNode's CertName (`ml_derp_cert_parse`). `cert_name` may be `None` or empty (default). A name equal to `hostname` (ignoring case
/// and a trailing dot) is the default. A malformed pin, a too long name or a non-hostname gives [`DerpCert::Invalid`].
pub fn parse_cert_name(hostname: Option<&str>, cert_name: Option<&str>) -> DerpCert {
    let Some(cn) = cert_name.filter(|s| !s.is_empty()) else {
        return DerpCert::Hostname;
    };
    if let Some(h) = cn.strip_prefix(PIN_PREFIX) {
        let b = h.as_bytes();
        if b.len() != 64 {
            return DerpCert::Invalid;
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            match (hex(b[2 * i]), hex(b[2 * i + 1])) {
                (Some(hi), Some(lo)) => *o = hi << 4 | lo,
                _ => return DerpCert::Invalid,
            }
        }
        return DerpCert::Pin(out);
    }
    if hostname.is_some_and(|h| same_name(h, cn)) {
        return DerpCert::Hostname;
    }
    if !name_plausible(cn) {
        return DerpCert::Invalid;
    }
    let mut n = FixedStr::new();
    n.set(cn);
    DerpCert::Name(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from tests/test_derp_tls.c (the 12 CertName parser cases).
    #[test]
    fn c_parser_cases() {
        let hex64: std::string::String = (0..32).map(|i| std::format!("{:02x}", if i == 31 { 0xff } else { 0 })).collect();
        assert_eq!(parse_cert_name(Some("derp1.example"), None), DerpCert::Hostname);
        assert_eq!(parse_cert_name(Some("derp1.example"), Some("")), DerpCert::Hostname);
        assert_eq!(parse_cert_name(Some("derp1.example"), Some("DERP1.example.")), DerpCert::Hostname);
        match parse_cert_name(Some("derp1.example"), Some("front.example")) {
            DerpCert::Name(n) => assert_eq!(n.as_str(), "front.example"),
            o => panic!("{o:?}"),
        }
        let text = std::format!("sha256-raw:{hex64}");
        match parse_cert_name(Some("10.0.0.1"), Some(&text)) {
            DerpCert::Pin(p) => assert!(p[0] == 0 && p[31] == 0xff),
            o => panic!("{o:?}"),
        }
        assert!(matches!(parse_cert_name(Some("h"), Some(&text.to_uppercase().replace("SHA256-RAW", "sha256-raw"))), DerpCert::Pin(_)));
        for bad in [
            std::format!("sha256-raw:{}", &hex64[..62]),
            std::format!("sha256-raw:{hex64}00"),
            std::format!("sha256-raw:{}g", &hex64[..63]),
            "sha256-raw:".into(),
            std::format!("{:a<64}", "x"), // 64 characters: too long for the 63 byte name
            "bad name".into(),
            "evil\r\nname".into(),
            "*.wild.example".into(),
        ] {
            assert_eq!(parse_cert_name(Some("h"), Some(&bad)), DerpCert::Invalid, "{bad:?}");
        }
        // 63 characters is the longest accepted name.
        assert!(matches!(parse_cert_name(Some("h"), Some(&std::format!("{:a<63}", "x"))), DerpCert::Name(_)));
    }

    #[test]
    fn plausible_names() {
        for ok in ["derp1.tailscale.com", "192.0.2.7", "2001:db8::7", "a_b-c.d"] {
            assert!(name_plausible(ok), "{ok}");
        }
        for bad in ["", "a b", "*.x", "a/b", "é.example"] {
            assert!(!name_plausible(bad), "{bad}");
        }
    }
}
