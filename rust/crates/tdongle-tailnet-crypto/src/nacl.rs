//! NaCl `crypto_box` (Curve25519 + HSalsa20 + XSalsa20-Poly1305), which DISCO uses. Layout is NaCl's: `tag (16) || ciphertext`.
//!
//! Built from `salsa20` and `poly1305` (the `crypto_box` crate is a pre-release); verified against the RustCrypto `crypto_box` crate as a test-only
//! oracle and against vectors produced by libsodium.

use crate::x25519;
use poly1305::{Poly1305, universal_hash::KeyInit};
use salsa20::cipher::{KeyIvInit, StreamCipher, typenum::U10};
use salsa20::{XSalsa20, hsalsa};
use subtle::ConstantTimeEq;
use tdongle_tailnet_types::Key32;
use zeroize::Zeroize;

/// Tag length of a box.
pub const TAG_LEN: usize = 16;
/// Nonce length.
pub const NONCE_LEN: usize = 24;

/// The box did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenError;

/// `crypto_box_beforenm`: HSalsa20 over the X25519 shared secret with a zero input. `None` for a small-order public key.
pub fn precompute(secret: &Key32, their_public: &Key32) -> Option<Key32> {
    let shared = x25519::shared(secret, their_public)?;
    let key: salsa20::Key = shared.0.into();
    let out = hsalsa::<U10>(&key, &[0u8; 16].into());
    Some(Key32(out.into()))
}

/// `crypto_secretbox` seal in place: `data[..plain_len]` becomes ciphertext, the tag goes **in front** (NaCl layout), so `data` must be
/// `16 + plain_len` long with the plaintext at `data[16..]`. Returns the total length.
pub fn secretbox_seal(key: &Key32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) -> Result<usize, OpenError> {
    if data.len() < TAG_LEN {
        return Err(OpenError);
    }
    let (tag, body) = data.split_at_mut(TAG_LEN);
    // Keystream block 0: its first 32 bytes are the Poly1305 key; the message is encrypted from offset 32 of the same stream.
    let mut c = XSalsa20::new((&key.0).into(), nonce.into());
    let mut pk = [0u8; 32];
    c.apply_keystream(&mut pk);
    let poly = Poly1305::new((&pk).into());
    pk.zeroize();
    c.apply_keystream(body);
    tag.copy_from_slice(&poly.compute_unpadded(body));
    Ok(TAG_LEN + body.len())
}

/// `crypto_secretbox` open in place: `data` is `tag || ciphertext`; on success the plaintext is `data[16..]`.
pub fn secretbox_open(key: &Key32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) -> Result<(), OpenError> {
    if data.len() < TAG_LEN {
        return Err(OpenError);
    }
    let (tag, body) = data.split_at_mut(TAG_LEN);
    let mut c = XSalsa20::new((&key.0).into(), nonce.into());
    let mut pk = [0u8; 32];
    c.apply_keystream(&mut pk);
    let poly = Poly1305::new((&pk).into());
    pk.zeroize();
    let computed = poly.compute_unpadded(body);
    if !bool::from(computed.as_slice().ct_eq(tag)) {
        return Err(OpenError);
    }
    c.apply_keystream(body);
    Ok(())
}

/// `crypto_box` seal: precompute with `(secret, their_public)`, then secretbox. Layout as [`secretbox_seal`].
pub fn box_seal(secret: &Key32, their_public: &Key32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) -> Result<usize, OpenError> {
    let k = precompute(secret, their_public).ok_or(OpenError)?;
    secretbox_seal(&k, nonce, data)
}

/// `crypto_box` open: `data` is `tag || ciphertext`; plaintext at `data[16..]` on success.
pub fn box_open(secret: &Key32, their_public: &Key32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) -> Result<(), OpenError> {
    let k = precompute(secret, their_public).ok_or(OpenError)?;
    secretbox_open(&k, nonce, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng_key(seed: u8) -> Key32 {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8 * 7);
        }
        Key32(k)
    }

    #[test]
    fn roundtrip_and_tamper() {
        let (a, b) = (rng_key(1), rng_key(2));
        let (ap, bp) = (x25519::public(&a), x25519::public(&b));
        let nonce = [9u8; 24];
        let mut buf = [0u8; 16 + 11];
        buf[16..].copy_from_slice(b"disco ping!");
        box_seal(&a, &bp, &nonce, &mut buf).unwrap();
        let mut c = buf;
        box_open(&b, &ap, &nonce, &mut c).unwrap();
        assert_eq!(&c[16..], b"disco ping!");
        let mut bad = buf;
        bad[20] ^= 1;
        assert!(box_open(&b, &ap, &nonce, &mut bad).is_err());
        let mut bad = buf;
        bad[0] ^= 1;
        assert!(box_open(&b, &ap, &nonce, &mut bad).is_err());
        assert!(box_open(&a, &ap, &nonce, &mut buf.clone()).is_err());
    }

    /// Differential against the RustCrypto `crypto_box` crate for many sizes (test-only dependency).
    #[test]
    fn matches_crypto_box_crate() {
        use crypto_box::aead::Aead;
        use crypto_box::{PublicKey, SalsaBox, SecretKey};
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 100, 255, 1400] {
            let (a, b) = (rng_key((len as u8).wrapping_add(3)), rng_key((len as u8).wrapping_add(77)));
            let bp = x25519::public(&b);
            let nonce = [len as u8; 24];
            let msg: std::vec::Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
            let mut mine = std::vec![0u8; 16 + len];
            mine[16..].copy_from_slice(&msg);
            box_seal(&a, &bp, &nonce, &mut mine).unwrap();
            let sb = SalsaBox::new(&PublicKey::from(bp.0), &SecretKey::from(a.0));
            let theirs = sb.encrypt((&nonce).into(), &msg[..]).unwrap();
            assert_eq!(mine, theirs, "len {len}");
        }
    }
}
