//! BLAKE2s-256, keyed BLAKE2s-128 (WireGuard's MAC), HMAC-BLAKE2s-256 and the Noise/WireGuard KDFs.
//!
//! `hmac` 0.13 does not accept `Blake2s256` (its core is not a plain block-level hash), so HMAC is written out here per RFC 2104 and checked against the
//! WireGuard reference construction and the Noise test vectors in the `tdongle-tailnet-noise` and `-wg` crates.

use blake2::digest::{Digest, KeyInit, Mac, typenum::U16};
use blake2::{Blake2s256, Blake2sMac};

const BLOCK: usize = 64;

/// BLAKE2s-256 of `data`.
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

/// BLAKE2s-256 of `a || b`.
pub fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// WireGuard's `Mac`: keyed BLAKE2s with a 16-byte output (`mac1`, `mac2`, cookies). `key` is 1 to 32 bytes.
pub fn mac128(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    // A key of the wrong length is a programming error in the callers (all keys are 32 bytes); fall back to a zero MAC rather than panic on the hot path.
    let Ok(mut m) = <Blake2sMac<U16> as KeyInit>::new_from_slice(key) else { return [0; 16] };
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HMAC-BLAKE2s-256.
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_parts(key, &[data])
}

fn hmac_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&hash(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let ih: [u8; 32] = inner.finalize().into();
    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(ih);
    let out = outer.finalize().into();
    zero(&mut k);
    zero(&mut ipad);
    zero(&mut opad);
    out
}

fn zero(b: &mut [u8]) {
    use zeroize::Zeroize;
    b.zeroize();
}

/// The Noise / WireGuard KDF, one output: `T0 = HMAC(chaining_key, input)`; `out = HMAC(T0, 0x01)`.
pub fn kdf1(ck: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut t0 = hmac(ck, input);
    let t1 = hmac(&t0, &[1]);
    zero(&mut t0);
    t1
}

/// Two outputs (`T1 = HMAC(T0, 0x01)`, `T2 = HMAC(T0, T1 || 0x02)`).
pub fn kdf2(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut t0 = hmac(ck, input);
    let t1 = hmac(&t0, &[1]);
    let t2 = hmac_parts(&t0, &[&t1, &[2]]);
    zero(&mut t0);
    (t1, t2)
}

/// Three outputs (`T3 = HMAC(T0, T2 || 0x03)`), used by WireGuard's `psk` mixing.
pub fn kdf3(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut t0 = hmac(ck, input);
    let t1 = hmac(&t0, &[1]);
    let t2 = hmac_parts(&t0, &[&t1, &[2]]);
    let t3 = hmac_parts(&t0, &[&t2, &[3]]);
    zero(&mut t0);
    (t1, t2, t3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 7693 appendix B: BLAKE2s-256("abc").
    #[test]
    fn blake2s_abc() {
        assert_eq!(hash(b"abc"), hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
        assert_eq!(hash2(b"a", b"bc"), hash(b"abc"));
    }

    /// RFC 2104 construction checked with an independent reference computed from the WireGuard reference implementation's `hmac` (blake2s_hmac in
    /// wireguard-go `device/noise-protocol.go` = the same two-pad construction): HMAC-BLAKE2s("key", "The quick brown fox jumps over the lazy dog").
    #[test]
    fn hmac_blake2s_known_answer() {
        // Cross-checked against Python: hmac.new(b"key", msg, lambda: hashlib.blake2s()).hexdigest()
        assert_eq!(hmac(b"key", b"The quick brown fox jumps over the lazy dog"), hex!("f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0"));
    }

    #[test]
    fn long_keys_are_hashed_first() {
        let long = [9u8; 100];
        assert_eq!(hmac(&long, b"m"), hmac(&hash(&long), b"m"));
    }

    #[test]
    fn kdf_prefixes_agree() {
        let ck = [3u8; 32];
        let (a, b) = kdf2(&ck, b"in");
        let (a3, b3, _c) = kdf3(&ck, b"in");
        assert_eq!(kdf1(&ck, b"in"), a);
        assert_eq!((a, b), (a3, b3));
    }

    #[test]
    fn mac128_known_answer() {
        // hashlib.blake2s(b"", key=b"\x01"*32, digest_size=16)
        assert_eq!(mac128(&[1u8; 32], &[]), hex!("32f81ebc48b5b95bd9acbfa8da93c081"));
    }

    #[test]
    fn mac128_keyed_differs_by_key_and_data() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_ne!(mac128(&k1, &[b"x"]), mac128(&k2, &[b"x"]));
        assert_ne!(mac128(&k1, &[b"x"]), mac128(&k1, &[b"y"]));
        assert_eq!(mac128(&k1, &[b"x", b"y"]), mac128(&k1, &[b"xy"]));
    }
}
