//! The C cases' xorshift generator (`rnd`), as a value so every test owns its stream.

use std::prelude::v1::*;

#[derive(Clone, Debug)]
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// `rnd(n)`: uniform enough in `0..n`.
    pub fn rnd(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n)) as u32
    }
}
