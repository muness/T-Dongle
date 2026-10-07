//! The Noise SymmetricState for this one protocol (BLAKE2s, ChaChaPoly, X25519), as `controlbase/handshake.go` does it.

use crate::handshake::HandshakeError;
use tdongle_tailnet_crypto::{aead, blake, x25519};
use tdongle_tailnet_types::Key32;
use zeroize::{Zeroize, ZeroizeOnDrop};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &[u8] = b"Tailscale Control Protocol v";

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Symmetric {
    pub(crate) h: [u8; 32],
    ck: [u8; 32],
}

impl Symmetric {
    /// Initialize, mix the version prologue and the responder's static key (the IK pre-message `<- s`).
    pub(crate) fn new(version: u16, responder_static: &Key32) -> Symmetric {
        let h = blake::hash(PROTOCOL_NAME);
        let mut s = Symmetric { h, ck: h };
        let mut pro = [0u8; 40];
        pro[..PROLOGUE_PREFIX.len()].copy_from_slice(PROLOGUE_PREFIX);
        let mut n = PROLOGUE_PREFIX.len();
        let mut digits = [0u8; 5];
        let mut d = 0;
        let mut v = version;
        loop {
            digits[d] = b'0' + (v % 10) as u8;
            d += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while d > 0 {
            d -= 1;
            pro[n] = digits[d];
            n += 1;
        }
        s.mix_hash(&pro[..n]);
        s.mix_hash(responder_static.as_bytes());
        s
    }

    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake::hash2(&self.h, data);
    }

    /// `MixKey(DH(sk, pk))`: updates the chaining key, returns the one-shot cipher key.
    pub(crate) fn mix_dh(&mut self, sk: &Key32, pk: &Key32) -> Result<Key32, HandshakeError> {
        let dh = x25519::shared(sk, pk).ok_or(HandshakeError::LowOrderPoint)?;
        let (ck, k) = blake::kdf2(&self.ck, dh.as_bytes());
        self.ck = ck;
        Ok(Key32(k))
    }

    /// Encrypt `out[..plain_len]` in place with the nonce-0 key, append the tag at `out[plain_len..plain_len + 16]`, mix `ciphertext || tag`.
    pub(crate) fn encrypt_and_hash(&mut self, k: &Key32, out: &mut [u8], plain_len: usize) {
        let (body, rest) = out.split_at_mut(plain_len);
        let tag = aead::seal_detached(k.as_bytes(), 0, &self.h, body);
        rest[..aead::TAG_LEN].copy_from_slice(&tag);
        self.mix_hash(&out[..plain_len + aead::TAG_LEN]);
    }

    /// Decrypt `buf` (ciphertext then tag) in place; on success mix the original ciphertext (re-read from `orig`).
    pub(crate) fn decrypt_and_hash(&mut self, k: &Key32, orig: &[u8], plain: &mut [u8]) -> Result<(), HandshakeError> {
        let n = orig.len().checked_sub(aead::TAG_LEN).ok_or(HandshakeError::AuthFailed)?;
        if plain.len() != n {
            return Err(HandshakeError::AuthFailed);
        }
        plain.copy_from_slice(&orig[..n]);
        let mut tag = [0u8; aead::TAG_LEN];
        tag.copy_from_slice(&orig[n..]);
        aead::open_detached(k.as_bytes(), 0, &self.h, plain, &tag).map_err(|_| HandshakeError::AuthFailed)?;
        self.mix_hash(orig);
        Ok(())
    }

    /// `Split()`: `(k1, k2)` where the initiator sends with `k1` and receives with `k2`.
    pub(crate) fn split(&self) -> (Key32, Key32) {
        let (a, b) = blake::kdf2(&self.ck, &[]);
        (Key32(a), Key32(b))
    }
}
