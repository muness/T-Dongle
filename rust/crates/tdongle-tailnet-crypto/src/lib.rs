//! Crypto for the tailnet gateway: the primitives Noise (ts2021), WireGuard, DISCO and DERP need, over RustCrypto.
//!
//! One crate, so the whole device has one place where a primitive is chosen, bounded, zeroized and measured (ADR 0001 rule 10). No allocation, no
//! `unsafe`; every secret comparison is [`subtle`]-based. The C firmware's equivalents: `wireguard_lwip/src/crypto/refc/*` (BLAKE2s, ChaCha20-Poly1305,
//! X25519), `ml_x25519.c`, `ml_noise.c`'s AEAD, `nacl_box.c`.
//!
//! Conventions that both Noise and WireGuard use are encoded here once: the ChaCha20-Poly1305 nonce is four zero bytes then the 64-bit counter,
//! little-endian; the KDF is HKDF over HMAC-BLAKE2s-256 with the Noise chaining-key arrangement ([`kdf1`], [`kdf2`], [`kdf3`]).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aead;
pub mod blake;
pub mod nacl;
pub mod x25519;


pub use aead::{AuthError, TAG_LEN};
pub use blake::{hash, hash2, hmac, kdf1, kdf2, kdf3, mac128};

#[cfg(test)]
extern crate std;
