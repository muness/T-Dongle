//! The control server's address as the C parses it (`parse_host_port` in `ml_coord.c`, tested by `test_control_key.c`): `[http[s]://]host[:port][/path]`.
//!
//! **No scheme means `https`, port 443, TLS** (Tailscale's own default: the `/key` fetch and the ts2021 upgrade both go over a verified TLS connection, and the
//! SaaS answers a plaintext `/key` with a 302 to https). Only an explicit `http://` is plain HTTP (port 80), for a trusted LAN or a pinned key. An explicit
//! `:port` overrides the default. The `Host` header omits the scheme's default port.

use core::fmt::Write as _;

/// A parsed control address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlUrl<'a> {
    /// The bare host name.
    pub host: &'a str,
    /// The TCP port.
    pub port: u16,
    /// The connection is TLS (`https://` or no scheme).
    pub tls: bool,
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Parse `[http[s]://]host[:port][/path]`; `None` for an empty host, an empty, non-numeric or out-of-range port (the C: "host too long or empty", "non-numeric
/// port", port field of at most seven characters, and 99999999 is refused; here anything over 65535).
pub fn parse_control_url(input: &str) -> Option<ControlUrl<'_>> {
    let (rest, tls, default_port) = if starts_with_ignore_case(input, "http://") {
        (&input[7..], false, 80)
    } else if starts_with_ignore_case(input, "https://") {
        (&input[8..], true, 443)
    } else {
        (input, true, 443)
    };
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => {
            if p.is_empty() || p.len() > 7 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (h, p.parse::<u32>().ok().filter(|&n| n <= 65_535)? as u16)
        }
        None => (authority, default_port),
    };
    if host.is_empty() || host.len() >= 64 {
        return None;
    }
    Some(ControlUrl { host, port, tls })
}

impl ControlUrl<'_> {
    /// The `Host` header value: the host, with `:port` unless it is the scheme's default (80 for plain, 443 for TLS).
    pub fn host_header<const N: usize>(&self, out: &mut crate::util::Buf<N>) {
        let default = if self.tls { 443 } else { 80 };
        let _ = if self.port == default { write!(out, "{}", self.host) } else { write!(out, "{}:{}", self.host, self.port) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Buf;

    fn p(s: &str) -> Option<(&str, u16, bool)> {
        parse_control_url(s).map(|u| (u.host, u.port, u.tls))
    }

    #[test]
    fn scheme_handling_is_the_cs_https_and_bare_hosts_are_tls_only_http_is_plain() {
        assert_eq!(p("hs.example.com"), Some(("hs.example.com", 443, true)));
        assert_eq!(p("hs.example.com:8443"), Some(("hs.example.com", 8443, true)));
        assert_eq!(p("https://hs.example.com"), Some(("hs.example.com", 443, true)));
        assert_eq!(p("HTTPS://hs.example.com:9/x"), Some(("hs.example.com", 9, true)));
        assert_eq!(p("http://hs.lan"), Some(("hs.lan", 80, false)));
        assert_eq!(p("http://hs.lan:8080"), Some(("hs.lan", 8080, false)));
        assert_eq!(p("controlplane.tailscale.com"), Some(("controlplane.tailscale.com", 443, true)));
    }

    #[test]
    fn what_the_c_refuses_is_refused() {
        for bad in ["http://", "", "hs:99999999", "hs:80a", "hs:", "hs:65536", ":80", "https://:443"] {
            assert_eq!(p(bad), None, "{bad:?}");
        }
        assert_eq!(p("hs:65535"), Some(("hs", 65_535, true)));
    }

    #[test]
    fn the_host_header_omits_the_default_port_of_the_scheme() {
        let h = |s: &str| {
            let mut b = Buf::<96>::new();
            parse_control_url(s).unwrap().host_header(&mut b);
            std::string::String::from(b.as_str())
        };
        assert_eq!(h("hs.example.com"), "hs.example.com");
        assert_eq!(h("https://hs.example.com:443"), "hs.example.com");
        assert_eq!(h("hs.example.com:8443"), "hs.example.com:8443");
        assert_eq!(h("http://hs.lan"), "hs.lan");
        assert_eq!(h("http://hs.lan:443"), "hs.lan:443", "443 is the default only for TLS");
        assert_eq!(h("https://hs.lan:80"), "hs.lan:80", "and 80 only for plain HTTP");
    }
}
