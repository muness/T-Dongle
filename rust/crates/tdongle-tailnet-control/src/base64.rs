//! Standard-alphabet, padded base64 (Go's `base64.StdEncoding`), for the `X-Tailscale-Handshake` header.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Bytes of base64 text for `n` input bytes.
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encode `src` into `out`; returns the length written, or `None` if `out` is too small.
pub fn encode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = encoded_len(src.len());
    if out.len() < need {
        return None;
    }
    let mut o = 0;
    for chunk in src.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out[o] = ALPHABET[(n >> 18) as usize & 63];
        out[o + 1] = ALPHABET[(n >> 12) as usize & 63];
        out[o + 2] = if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] } else { b'=' };
        out[o + 3] = if chunk.len() > 2 { ALPHABET[n as usize & 63] } else { b'=' };
        o += 4;
    }
    Some(o)
}

fn val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict decode (padding required, no whitespace). Returns the length written, or `None` on bad input or a small `out`.
pub fn decode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    if !src.len().is_multiple_of(4) {
        return None;
    }
    let mut o = 0;
    let groups = src.len() / 4;
    for (g, q) in src.chunks(4).enumerate() {
        let last = g + 1 == groups;
        let pad = if last { q.iter().rev().take_while(|&&c| c == b'=').count() } else { 0 };
        if pad > 2 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in q.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { val(c)? };
            n = (n << 6) | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let take = 3 - pad;
        if o + take > out.len() {
            return None;
        }
        out[o..o + take].copy_from_slice(&bytes[..take]);
        o += take;
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    #[test]
    fn rfc4648_vectors() {
        for (plain, enc) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            let mut o = [0u8; 16];
            let n = encode(plain.as_bytes(), &mut o).unwrap();
            assert_eq!(&o[..n], enc.as_bytes());
            let mut d = [0u8; 16];
            let n = decode(enc.as_bytes(), &mut d).unwrap();
            assert_eq!(&d[..n], plain.as_bytes());
        }
        assert!(decode(b"Zg=", &mut [0; 8]).is_none());
        assert!(decode(b"Z===", &mut [0; 8]).is_none());
        assert!(decode(b"Zm9v", &mut [0; 2]).is_none());
        assert!(encode(b"foo", &mut [0; 3]).is_none());
    }
}
