//! ChaCha20-Poly1305 (RFC 8439, 64-bit counter nonce as Noise and WireGuard use it) and XChaCha20-Poly1305 (WireGuard cookie replies).

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

/// Authentication tag length.
pub const TAG_LEN: usize = 16;

/// The ciphertext did not authenticate (or was too short). Carries no detail, on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

#[inline]
fn nonce12(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Encrypt `buf` in place and return the tag. `counter` is the Noise/WireGuard nonce.
pub fn seal_detached(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
    let c = ChaCha20Poly1305::new(key.into());
    let n = nonce12(counter);
    match c.encrypt_inout_detached((&n).into(), aad, buf.into()) {
        Ok(t) => t.into(),
        // Only reachable for a buffer beyond 2^38 bytes; the callers' buffers are at most a few KB.
        Err(_) => [0; TAG_LEN],
    }
}

/// Decrypt `buf` in place against `tag`. On failure `buf` content is unspecified (callers drop the packet).
pub fn open_detached(key: &[u8; 32], counter: u64, aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), AuthError> {
    let c = ChaCha20Poly1305::new(key.into());
    let n = nonce12(counter);
    c.decrypt_inout_detached((&n).into(), aad, buf.into(), tag.into()).map_err(|_| AuthError)
}

/// Encrypt `data[..plain_len]` in place and write the tag after it; `data` must have room for `plain_len + 16`. Returns the sealed length.
pub fn seal_in_place(key: &[u8; 32], counter: u64, aad: &[u8], data: &mut [u8], plain_len: usize) -> Result<usize, AuthError> {
    if data.len() < plain_len + TAG_LEN {
        return Err(AuthError);
    }
    let (body, rest) = data.split_at_mut(plain_len);
    let tag = seal_detached(key, counter, aad, body);
    rest[..TAG_LEN].copy_from_slice(&tag);
    Ok(plain_len + TAG_LEN)
}

/// Decrypt `data` (ciphertext followed by the tag) in place; returns the plaintext length.
pub fn open_in_place(key: &[u8; 32], counter: u64, aad: &[u8], data: &mut [u8]) -> Result<usize, AuthError> {
    let n = data.len().checked_sub(TAG_LEN).ok_or(AuthError)?;
    let (body, tag) = data.split_at_mut(n);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(tag);
    open_detached(key, counter, aad, body, &t)?;
    Ok(n)
}

/// XChaCha20-Poly1305 seal (24-byte nonce), in place, tag returned.
pub fn xseal_detached(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
    let c = XChaCha20Poly1305::new(key.into());
    match c.encrypt_inout_detached(nonce.into(), aad, buf.into()) {
        Ok(t) => t.into(),
        Err(_) => [0; TAG_LEN],
    }
}

/// XChaCha20-Poly1305 open, in place.
pub fn xopen_detached(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), AuthError> {
    let c = XChaCha20Poly1305::new(key.into());
    c.decrypt_inout_detached(nonce.into(), aad, buf.into(), tag.into()).map_err(|_| AuthError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 8439 section 2.8.2 (the AEAD test vector); its nonce is 07 00 00 00 40 41 42 43 44 45 46 47, which is not our 4-zero-bytes form, so it
    /// is checked through the raw cipher below; here we check our nonce layout against an independent computation.
    #[test]
    fn nonce_layout_is_four_zero_bytes_then_le_counter() {
        assert_eq!(nonce12(0x0102030405060708), hex!("00000000 0807060504030201"));
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let mut buf = [0u8; 48];
        buf[..32].copy_from_slice(b"attack at dawn, bring the dongle");
        let n = seal_in_place(&key, 5, b"aad", &mut buf, 32).unwrap();
        assert_eq!(n, 48);
        let mut c = buf;
        assert_eq!(open_in_place(&key, 5, b"aad", &mut c).unwrap(), 32);
        assert_eq!(&c[..32], b"attack at dawn, bring the dongle");
        let mut bad = buf;
        bad[3] ^= 1;
        assert!(open_in_place(&key, 5, b"aad", &mut bad).is_err());
        let mut wrong_ctr = buf;
        assert!(open_in_place(&key, 6, b"aad", &mut wrong_ctr).is_err());
        let mut wrong_aad = buf;
        assert!(open_in_place(&key, 5, b"aae", &mut wrong_aad).is_err());
        assert!(open_in_place(&key, 5, b"aad", &mut [0u8; 15]).is_err());
    }

    /// RFC 8439 section 2.8.2 with its 96-bit nonce, driven through the underlying crate to pin the library to the RFC (so the layout test above
    /// is the only thing this module adds).
    #[test]
    fn rfc8439_2_8_2_vector() {
        use chacha20poly1305::aead::{AeadInOut, KeyInit};
        let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("070000004041424344454647");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = *pt;
        let tag = ChaCha20Poly1305::new((&key).into()).encrypt_inout_detached((&nonce).into(), &aad, (&mut buf[..]).into()).unwrap();
        assert_eq!(&buf[..16], &hex!("d31a8d34648e60db7b86afbc53ef7ec2"));
        assert_eq!(tag.as_slice(), &hex!("1ae10b594f09e26a7e902ecbd0600691"));
    }
}
