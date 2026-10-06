//! Small text parsers the projector uses (the C's `sscanf` calls, made strict), allocation free.

/// Parse `a.b.c.d` (each part 1..=3 decimal digits, <= 255) from the start of `s`; returns the address (host order) and the rest.
pub fn ipv4_prefix(s: &[u8]) -> Option<(u32, &[u8])> {
    let mut ip = 0u32;
    let mut at = 0;
    for part in 0..4 {
        let start = at;
        let mut v = 0u32;
        while at < s.len() && s[at].is_ascii_digit() && at - start < 3 {
            v = v * 10 + (s[at] - b'0') as u32;
            at += 1;
        }
        if at == start || v > 255 {
            return None;
        }
        ip = (ip << 8) | v;
        if part < 3 {
            if s.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    Some((ip, &s[at..]))
}

/// Parse an unsigned decimal of at most `max_digits` digits that must be the whole of `s`.
pub fn decimal(s: &[u8], max: u32) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    if v > max as u64 { None } else { Some(v as u32) }
}

/// `Addresses[0]`: `a.b.c.d` optionally followed by `/len` (len <= 32). Returns the address.
pub fn address_v4(s: &[u8]) -> Option<u32> {
    let (ip, rest) = ipv4_prefix(s)?;
    match rest {
        [] => Some(ip),
        [b'/', len @ ..] => decimal(len, 32).map(|_| ip),
        _ => None,
    }
}

/// An endpoint `a.b.c.d:port` (port <= 65535).
pub fn endpoint_v4(s: &[u8]) -> Option<(u32, u16)> {
    let (ip, rest) = ipv4_prefix(s)?;
    let port = decimal(rest.strip_prefix(b":")?, 65535)?;
    Some((ip, port as u16))
}

/// An `AllowedIPs` entry `a.b.c.d/len` (len <= 32).
pub fn cidr_v4(s: &[u8]) -> Option<(u32, u8)> {
    let (ip, rest) = ipv4_prefix(s)?;
    let len = decimal(rest.strip_prefix(b"/")?, 32)?;
    Some((ip, len as u8))
}

/// The legacy `DERP` string `127.3.3.40:N`: the region number N (1..=65535).
pub fn legacy_derp(s: &[u8]) -> Option<u16> {
    let n = decimal(s.strip_prefix(b"127.3.3.40:")?, 65535)?;
    Some(n as u16)
}

/// Strip an optional `prefix` and parse 64 hex digits.
pub fn key_hex(s: &str, prefix: &str) -> Option<tdongle_tailnet_types::Key32> {
    tdongle_tailnet_types::Key32::from_hex(s.strip_prefix(prefix).unwrap_or(s).as_bytes())
}

/// Seconds since the Unix epoch of an RFC 3339 timestamp (`2026-10-06T12:00:00Z`, `...+02:00`, optional fraction), plus nanoseconds. Years before 1970 give
/// `None` (Go's zero time `0001-01-01T00:00:00Z` means "no value").
pub fn rfc3339(s: &[u8]) -> Option<(i64, u32)> {
    let num = |a: usize, n: usize| -> Option<i64> {
        let part = s.get(a..a + n)?;
        part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0i64, |v, c| v * 10 + (c - b'0') as i64))
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    if s.get(4) != Some(&b'-') || s.get(7) != Some(&b'-') || !matches!(s.get(10), Some(b'T' | b't' | b' ')) {
        return None;
    }
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if s.get(13) != Some(&b':') || s.get(16) != Some(&b':') {
        return None;
    }
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0u32;
    if s.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        let mut scale = 100_000_000u32;
        while at < s.len() && s[at].is_ascii_digit() {
            nanos += (s[at] - b'0') as u32 * scale;
            scale /= 10;
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    let offset = match s.get(at..)? {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), rest @ ..] if rest.len() == 5 && rest[2] == b':' => {
            let n = |i: usize| (rest[i] - b'0') as i64 * 10 + (rest[i + 1] - b'0') as i64;
            if !rest.iter().enumerate().all(|(i, c)| i == 2 || c.is_ascii_digit()) {
                return None;
            }
            let o = n(0) * 3600 + n(3) * 60;
            if *sign == b'-' { -o } else { o }
        }
        _ => return None,
    };
    if y < 1970 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + h * 3600 + mi * 60 + sec - offset, nanos))
}

/// An unsigned decimal that fits `u64`, nothing else (the key of `PeerSeenChange` / `OnlineChange`).
pub fn decimal_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 20 {
        return None;
    }
    let mut v: u128 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u128;
    }
    u64::try_from(v).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    #[test]
    fn ipv4_forms() {
        assert_eq!(address_v4(b"100.64.1.2/32"), Some(0x6440_0102));
        assert_eq!(address_v4(b"100.64.1.2"), Some(0x6440_0102));
        assert_eq!(address_v4(b"0.0.0.0"), Some(0));
        assert_eq!(address_v4(b"255.255.255.255/0"), Some(u32::MAX));
        for bad in [
            &b""[..],
            b"1.2.3",
            b"1.2.3.4.5",
            b"256.1.1.1",
            b"1.2.3.4/33",
            b"1.2.3.4/",
            b"1.2.3.4/x",
            b"1.2.3.4 ",
            b" 1.2.3.4",
            b"1..3.4",
            b"1.2.3.4abc",
            b"fd7a::1/128",
            b"+1.2.3.4",
            b"1.2.3.1234",
        ] {
            assert_eq!(address_v4(bad), None, "{:?}", core::str::from_utf8(bad));
        }
        assert_eq!(endpoint_v4(b"1.2.3.4:5"), Some((0x0102_0304, 5)));
        assert_eq!(endpoint_v4(b"1.2.3.4:65535"), Some((0x0102_0304, 65535)));
        assert_eq!(endpoint_v4(b"1.2.3.4:65536"), None);
        assert_eq!(endpoint_v4(b"1.2.3.4"), None);
        assert_eq!(endpoint_v4(b"1.2.3.4:"), None);
        assert_eq!(endpoint_v4(b"[::1]:80"), None);
        assert_eq!(cidr_v4(b"192.168.5.0/24"), Some((0xc0a8_0500, 24)));
        assert_eq!(cidr_v4(b"192.168.5.0"), None);
        assert_eq!(legacy_derp(b"127.3.3.40:7"), Some(7));
        assert_eq!(legacy_derp(b"127.3.3.40:0"), Some(0));
        assert_eq!(legacy_derp(b"127.3.3.41:7"), None);
        assert_eq!(legacy_derp(b"127.3.3.40:"), None);
        assert_eq!(decimal_u64(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(decimal_u64(b"18446744073709551616"), None);
        assert_eq!(decimal_u64(b""), None);
        assert_eq!(decimal_u64(b"-1"), None);
    }

    #[test]
    fn rfc3339_forms() {
        assert_eq!(rfc3339(b"1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(rfc3339(b"2000-02-29T12:00:00Z"), Some((951_825_600, 0)));
        assert_eq!(rfc3339(b"2026-10-06T12:34:56.789Z"), Some((1_791_290_096, 789_000_000)));
        assert_eq!(rfc3339(b"2026-10-06T12:34:56.123456789Z"), Some((1_791_290_096, 123_456_789)));
        assert_eq!(rfc3339(b"2026-10-06T14:34:56+02:00"), Some((1_791_290_096, 0)));
        assert_eq!(rfc3339(b"2026-10-06T07:04:56-05:30"), Some((1_791_290_096, 0)));
        assert_eq!(rfc3339(b"2027-03-14T15:09:26Z"), Some((1_805_036_966, 0)));
        // Go's zero time and anything before 1970 is "no value"
        assert_eq!(rfc3339(b"0001-01-01T00:00:00Z"), None);
        assert_eq!(rfc3339(b"1969-12-31T23:59:59Z"), None);
        for bad in [
            &b""[..],
            b"2026-10-06",
            b"2026-10-06T12:34:56",
            b"2026-13-06T12:34:56Z",
            b"2026-10-32T12:34:56Z",
            b"2026-10-06T24:00:00Z",
            b"2026/10/06T12:34:56Z",
            b"2026-10-06T12:34:56.Z",
            b"2026-10-06T12:34:56+0200",
            b"2026-10-06T12:34:56ZZ",
            b"x026-10-06T12:34:56Z",
        ] {
            assert_eq!(rfc3339(bad), None, "{:?}", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn key_forms() {
        let hex = "0f".repeat(32);
        assert!(key_hex(&hex, "nodekey:").is_some());
        assert!(key_hex(&format!("nodekey:{hex}"), "nodekey:").is_some());
        assert!(key_hex(&format!("NODEKEY:{hex}"), "nodekey:").is_none());
        assert!(key_hex(&hex.to_uppercase(), "nodekey:").is_some());
        assert!(key_hex(&hex[1..], "nodekey:").is_none());
        assert!(key_hex(&format!("{hex}00"), "nodekey:").is_none());
    }
}
