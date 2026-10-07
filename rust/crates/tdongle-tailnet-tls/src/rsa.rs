//! RSA public-key operations (RFC 8017 verification only) on fixed-size big integers: no allocation, a few KB of stack.
//!
//! Why this exists: a TLS 1.3-only ClientHello (`embedded-tls` offers no TLS 1.2 cipher suites) makes the Go `derper`'s autocert pick its **RSA**
//! certificate chain (`leaf RSA-2048 <- YR1 <- Root YR (RSA-4096) <- ISRG Root X1`), whose CertificateVerify is RSA-PSS. The C (mbedTLS, TLS 1.2
//! ECDHE-ECDSA suites) gets the ECDSA chain. Verification with a small public exponent is cheap (17 modular multiplications), so this is not a CPU
//! problem, only code to carry: [`verify_pkcs1`] for certificate signatures and [`verify_pss`] for CertificateVerify.

use sha2::{Digest, Sha256};
#[cfg(feature = "p384")]
use sha2::{Sha384, Sha512};
use subtle::ConstantTimeEq;

/// Hash of an RSA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    #[cfg(feature = "p384")]
    Sha384,
    #[cfg(feature = "p384")]
    Sha512,
}

impl Hash {
    fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            #[cfg(feature = "p384")]
            Hash::Sha384 => 48,
            #[cfg(feature = "p384")]
            Hash::Sha512 => 64,
        }
    }
    fn digest(self, parts: &[&[u8]], out: &mut [u8; 64]) {
        fn run<D: Digest>(parts: &[&[u8]], out: &mut [u8; 64]) {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            let r = d.finalize();
            out[..r.len()].copy_from_slice(&r);
        }
        match self {
            Hash::Sha256 => run::<Sha256>(parts, out),
            #[cfg(feature = "p384")]
            Hash::Sha384 => run::<Sha384>(parts, out),
            #[cfg(feature = "p384")]
            Hash::Sha512 => run::<Sha512>(parts, out),
        }
    }
    /// DigestInfo prefix of EMSA-PKCS1-v1_5.
    fn prefix(self) -> &'static [u8] {
        match self {
            Hash::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            #[cfg(feature = "p384")]
            Hash::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            #[cfg(feature = "p384")]
            Hash::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        }
    }
}

/// Largest modulus (bytes) and smallest, in bits. 2048..=4096 covers every public CA hierarchy; shorter keys are refused.
pub(crate) const MAX_MODULUS_BYTES: usize = 512;
const MIN_MODULUS_BITS: usize = 2048;

/// An RSA public key borrowed from its `RSAPublicKey` DER (`SEQUENCE { INTEGER n, INTEGER e }`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicKey<'a> {
    n: &'a [u8],
    e: u32,
}

impl<'a> PublicKey<'a> {
    pub fn parse(der: &'a [u8]) -> Option<Self> {
        use crate::der::{INT, SEQ, read_tag};
        let (seq, rest) = read_tag(der, SEQ)?;
        if !rest.is_empty() {
            return None;
        }
        let (n, r) = read_tag(seq.content, INT)?;
        let (e, tail) = read_tag(r, INT)?;
        if !tail.is_empty() {
            return None;
        }
        let n = match n.content {
            [0, rest @ ..] => rest, // a positive INTEGER's sign byte
            all => all,
        };
        if n.first().is_none_or(|&b| b == 0) || n.len() > MAX_MODULUS_BYTES || n.last()? & 1 == 0 {
            return None;
        }
        let bits = n.len() * 8 - n[0].leading_zeros() as usize;
        if bits < MIN_MODULUS_BITS {
            return None;
        }
        if e.content.is_empty() || e.content.len() > 4 || e.content[0] & 0x80 != 0 {
            return None;
        }
        let e = e.content.iter().fold(0u32, |a, &b| (a << 8) | b as u32);
        if e < 3 || e & 1 == 0 {
            return None;
        }
        Some(Self { n, e })
    }

    fn bits(&self) -> usize {
        self.n.len() * 8 - self.n[0].leading_zeros() as usize
    }
    fn k(&self) -> usize {
        self.n.len()
    }

    /// `sig^e mod n` into `out[..k]` (big-endian). `None` if `sig` is not exactly `k` bytes or not below `n`.
    fn public_op(&self, sig: &[u8], out: &mut [u8; MAX_MODULUS_BYTES]) -> Option<()> {
        if sig.len() != self.k() {
            return None;
        }
        let l = self.k().div_ceil(4);
        let mut n = [0u32; MAX_LIMBS];
        let mut s = [0u32; MAX_LIMBS];
        load_be(&mut n[..l], self.n);
        load_be(&mut s[..l], sig);
        let (n, s) = (&n[..l], &mut s[..l]);
        if cmp(s, n) != core::cmp::Ordering::Less {
            return None;
        }
        // n0inv = -n^-1 mod 2^32 (Newton iteration; n is odd).
        let mut inv = n[0];
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let n0inv = inv.wrapping_neg();
        // x = s * R mod n by 32*l doublings, so no R^2 is ever needed; then x^e by square and multiply in Montgomery form.
        let mut x = [0u32; MAX_LIMBS];
        x[..l].copy_from_slice(s);
        for _ in 0..32 * l {
            double_mod(&mut x[..l], n);
        }
        let mut acc = [0u32; MAX_LIMBS];
        acc[..l].copy_from_slice(&x[..l]);
        let mut t = [0u32; MAX_LIMBS + 2];
        let top = 31 - self.e.leading_zeros() as usize;
        for i in (0..top).rev() {
            let a = acc;
            mont_mul(&mut acc[..l], &a[..l], &a[..l], n, n0inv, &mut t);
            if (self.e >> i) & 1 == 1 {
                let a = acc;
                mont_mul(&mut acc[..l], &a[..l], &x[..l], n, n0inv, &mut t);
            }
        }
        // out of Montgomery form: acc * 1 * R^-1
        let mut one = [0u32; MAX_LIMBS];
        one[0] = 1;
        let a = acc;
        mont_mul(&mut acc[..l], &a[..l], &one[..l], n, n0inv, &mut t);
        store_be(&acc[..l], &mut out[..self.k()]);
        Some(())
    }
}

const MAX_LIMBS: usize = MAX_MODULUS_BYTES / 4;

fn load_be(out: &mut [u32], be: &[u8]) {
    for (i, limb) in out.iter_mut().enumerate() {
        let mut v = 0u32;
        for j in 0..4 {
            let idx = be.len() as isize - 1 - (4 * i + j) as isize;
            if idx >= 0 {
                v |= (be[idx as usize] as u32) << (8 * j);
            }
        }
        *limb = v;
    }
}

fn store_be(limbs: &[u32], out: &mut [u8]) {
    let n = out.len();
    for (i, o) in out.iter_mut().enumerate() {
        let from_end = n - 1 - i;
        *o = (limbs[from_end / 4] >> (8 * (from_end % 4))) as u8;
    }
}

fn cmp(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

fn sub_in_place(a: &mut [u32], b: &[u32]) {
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        a[i] = d as u32;
        borrow = (d < 0) as i64;
    }
}

/// x = 2x mod n for x < n.
fn double_mod(x: &mut [u32], n: &[u32]) {
    let mut carry = 0u32;
    for v in x.iter_mut() {
        let c = *v >> 31;
        *v = (*v << 1) | carry;
        carry = c;
    }
    if carry != 0 || cmp(x, n) != core::cmp::Ordering::Less {
        sub_in_place(x, n);
    }
}

/// out = a * b * R^-1 mod n (CIOS Montgomery multiplication, R = 2^(32 l)); a, b < n. `t` is scratch of l + 2 limbs.
fn mont_mul(out: &mut [u32], a: &[u32], b: &[u32], n: &[u32], n0inv: u32, t: &mut [u32; MAX_LIMBS + 2]) {
    let l = n.len();
    t[..l + 2].fill(0);
    for &bi in b.iter().take(l) {
        let mut c = 0u64;
        for j in 0..l {
            let v = t[j] as u64 + a[j] as u64 * bi as u64 + c;
            t[j] = v as u32;
            c = v >> 32;
        }
        let v = t[l] as u64 + c;
        t[l] = v as u32;
        t[l + 1] = (v >> 32) as u32;
        let m = t[0].wrapping_mul(n0inv);
        let mut c = (t[0] as u64 + m as u64 * n[0] as u64) >> 32;
        for j in 1..l {
            let v = t[j] as u64 + m as u64 * n[j] as u64 + c;
            t[j - 1] = v as u32;
            c = v >> 32;
        }
        let v = t[l] as u64 + c;
        t[l - 1] = v as u32;
        t[l] = t[l + 1] + (v >> 32) as u32;
    }
    out.copy_from_slice(&t[..l]);
    if t[l] != 0 || cmp(out, n) != core::cmp::Ordering::Less {
        sub_in_place(out, n);
    }
}

/// RSASSA-PKCS1-v1_5 verification (certificate signatures). `msg` is the signed data.
pub(crate) fn verify_pkcs1(key: &PublicKey<'_>, hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    let mut em = [0u8; MAX_MODULUS_BYTES];
    if key.public_op(sig, &mut em).is_none() {
        return false;
    }
    let k = key.k();
    let mut h = [0u8; 64];
    hash.digest(&[msg], &mut h);
    let (p, hl) = (hash.prefix(), hash.len());
    let t = p.len() + hl;
    if k < t + 11 {
        return false;
    }
    // 00 01 FF..FF 00 prefix hash, compared in full (no parsing of the padding: nothing to get wrong).
    let mut ok = em[0].ct_eq(&0x00) & em[1].ct_eq(&0x01);
    for &b in &em[2..k - t - 1] {
        ok &= b.ct_eq(&0xff);
    }
    ok &= em[k - t - 1].ct_eq(&0x00);
    ok &= em[k - t..k - hl].ct_eq(p);
    ok &= em[k - hl..k].ct_eq(&h[..hl]);
    bool::from(ok)
}

/// RSASSA-PSS verification with MGF1 of the same hash and salt length = hash length (TLS 1.3 `rsa_pss_rsae_*`). `msg` is hashed here.
pub(crate) fn verify_pss(key: &PublicKey<'_>, hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    let mut full = [0u8; MAX_MODULUS_BYTES];
    if key.public_op(sig, &mut full).is_none() {
        return false;
    }
    let hl = hash.len();
    let mod_bits = key.bits();
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let skip = key.k() - em_len; // 0 or 1 (the top byte is zero when modBits-1 is a multiple of 8)
    if full[..skip].iter().any(|&b| b != 0) {
        return false;
    }
    let em = &mut full[skip..key.k()];
    let mut m_hash = [0u8; 64];
    hash.digest(&[msg], &mut m_hash);
    let salt_len = hl;
    if em_len < hl + salt_len + 2 || em[em_len - 1] != 0xbc {
        return false;
    }
    let db_len = em_len - hl - 1;
    let (masked_db, rest) = em.split_at_mut(db_len);
    let h_bytes: &[u8] = &rest[..hl];
    let top_bits = 8 * em_len - em_bits;
    if top_bits != 0 && masked_db[0] >> (8 - top_bits) != 0 {
        return false;
    }
    // DB = maskedDB xor MGF1(H, dbLen)
    let mut counter = 0u32;
    let mut off = 0;
    while off < db_len {
        let mut d = [0u8; 64];
        hash.digest(&[h_bytes, &counter.to_be_bytes()], &mut d);
        for (a, b) in masked_db[off..].iter_mut().zip(&d[..hl]) {
            *a ^= b;
        }
        off += hl;
        counter += 1;
    }
    if top_bits != 0 {
        masked_db[0] &= 0xffu8 >> top_bits;
    }
    let pad = db_len - salt_len - 1;
    if masked_db[..pad].iter().any(|&b| b != 0) || masked_db[pad] != 0x01 {
        return false;
    }
    let salt = &masked_db[pad + 1..];
    let mut h2 = [0u8; 64];
    hash.digest(&[&[0u8; 8], &m_hash[..hl], salt], &mut h2);
    bool::from(h2[..hl].ct_eq(h_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn f(name: &str) -> Vec<u8> {
        std::fs::read(std::format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn hashes() -> Vec<(Hash, &'static str)> {
        #[allow(unused_mut)]
        let mut v = std::vec![(Hash::Sha256, "sha256")];
        #[cfg(feature = "p384")]
        v.push((Hash::Sha384, "sha384"));
        v
    }

    #[test]
    fn openssl_signatures_verify_at_2048_and_4096() {
        let msg = f("rsa_msg.bin");
        for bits in [2048, 4096] {
            let pub_der = f(&std::format!("rsa{bits}_pub.der"));
            let key = PublicKey::parse(&pub_der).unwrap();
            assert_eq!(key.k() * 8, bits);
            assert_eq!(key.e, 65537);
            for (h, name) in hashes() {
                let p1 = f(&std::format!("rsa{bits}_pkcs1_{name}.sig"));
                assert!(verify_pkcs1(&key, h, &msg, &p1), "pkcs1 {bits} {name}");
                let pss = f(&std::format!("rsa{bits}_pss_{name}.sig"));
                assert!(verify_pss(&key, h, &msg, &pss), "pss {bits} {name}");
                // Every wrong pairing and every single-bit change fails.
                assert!(!verify_pss(&key, h, &msg, &p1) && !verify_pkcs1(&key, h, &msg, &pss));
                assert!(!verify_pkcs1(&key, h, b"other", &p1) && !verify_pss(&key, h, b"other", &pss));
                for i in (0..pss.len()).step_by(37) {
                    let mut bad = pss.clone();
                    bad[i] ^= 0x40;
                    assert!(!verify_pss(&key, h, &msg, &bad));
                    let mut bad = p1.clone();
                    bad[i] ^= 0x01;
                    assert!(!verify_pkcs1(&key, h, &msg, &bad));
                }
            }
            // Wrong hash for the signature, truncated and over-long signatures, sig >= n.
            let p1 = f(&std::format!("rsa{bits}_pkcs1_sha256.sig"));
            #[cfg(feature = "p384")]
            assert!(!verify_pkcs1(&key, Hash::Sha384, &msg, &p1));
            assert!(!verify_pkcs1(&key, Hash::Sha256, &msg, &p1[1..]));
            assert!(!verify_pkcs1(&key, Hash::Sha256, &msg, &[&p1[..], &[0u8][..]].concat()));
            assert!(!verify_pkcs1(&key, Hash::Sha256, &msg, &std::vec![0xff; key.k()]));
            assert!(!verify_pkcs1(&key, Hash::Sha256, &msg, &std::vec![0; key.k()]));
        }
    }

    #[test]
    fn key_parsing_limits() {
        let good = f("rsa2048_pub.der");
        assert!(PublicKey::parse(&good).is_some());
        assert!(PublicKey::parse(&good[..good.len() - 1]).is_none());
        let mut small = std::vec![0x30, 0x0b, 0x02, 0x04, 0x00, 0xc0, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01];
        small[1] = (small.len() - 2) as u8;
        assert!(PublicKey::parse(&small).is_none(), "tiny modulus refused");
        for i in 0..good.len() {
            let _ = PublicKey::parse(&good[..i]); // never panics
        }
    }
}
