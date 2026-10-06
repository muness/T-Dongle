use alloc::boxed::Box;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::types::{Cipher, Dh, Hash, Random};

/// Deterministic RNG (ChaCha8, seeded). Deterministic so a host-recorded server transcript replays byte-exactly.
pub struct Det(pub ChaCha8Rng);
impl Det {
    pub fn new(seed: u64) -> Self {
        Det(ChaCha8Rng::seed_from_u64(seed))
    }
}
impl Random for Det {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

/// snow resolver = snow's DefaultResolver (RustCrypto primitives) with our RNG (no getrandom on xtensa-none).
pub struct DetResolver(pub u64);
impl CryptoResolver for DetResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(Det::new(self.0)))
    }
    fn resolve_dh(&self, c: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(c)
    }
    fn resolve_hash(&self, c: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(c)
    }
    fn resolve_cipher(&self, c: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(c)
    }
}
