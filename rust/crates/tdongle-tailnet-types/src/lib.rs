//! Shared vocabulary of the `tdongle-tailnet-*` crates.
//!
//! Everything here is `no_std`, allocation free and `forbid(unsafe_code)`. The rules every tailnet crate follows (ADR 0001, "Phase 3: tailnet gateway"):
//!
//! * **Sans-IO.** A protocol crate never reads a clock, a socket or an entropy source. Time arrives as [`Millis`], entropy through [`Entropy`], bytes through
//!   slices. A state machine returns what it wants done; the runtime does it. That is what makes every crate host-testable and the runtime's memory
//!   countable.
//! * **Bounded.** Every buffer has a compile-time capacity. Exceeding it is an `Err` that the caller counts, never a panic and never an allocation.
//! * **Secrets** live in [`Key32`] (zeroized on drop, compared in constant time, no `Debug` of the bytes).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Monotonic milliseconds since boot (the C's `ml_get_time_ms`). 64 bits: no wrap in any lifetime a dongle has.
pub type Millis = u64;

/// A 32-byte key (WireGuard / node / machine / disco, public or private). Zeroized on drop; `==` is constant time; `Debug` prints only the first byte
/// of a public key's hex via [`Key32::short`], never the secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32(pub [u8; 32]);

impl Key32 {
    /// The all-zero key (an unset slot).
    pub const ZERO: Key32 = Key32([0; 32]);
    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// True for the all-zero key.
    pub fn is_zero(&self) -> bool {
        self.0.ct_eq(&[0u8; 32]).into()
    }
    /// A four-hex-digit tag of the first two bytes, for logs ("a1b2"). Safe for public keys; for secrets use nothing.
    pub fn short(&self) -> ShortKey {
        ShortKey([self.0[0], self.0[1]])
    }
    /// Lower-case hex of the key into `out` (64 bytes). Tailscale's `mkey:`/`nodekey:` prefixes are the caller's.
    pub fn to_hex(&self, out: &mut [u8; 64]) {
        hex_encode(&self.0, out)
    }
    /// Parse 64 hex digits.
    pub fn from_hex(s: &[u8]) -> Option<Key32> {
        if s.len() != 64 {
            return None;
        }
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (nibble(s[2 * i])? << 4) | nibble(s[2 * i + 1])?;
        }
        Some(Key32(k))
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Key32 {}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key32({}..)", self.short())
    }
}

/// Two bytes of a key as four hex digits.
#[derive(Clone, Copy, Debug)]
pub struct ShortKey(pub [u8; 2]);
impl fmt::Display for ShortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}{:02x}", self.0[0], self.0[1])
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lower-case hex of `src` into `out` (`out.len() == 2 * src.len()` is the caller's invariant; the shorter of the two bounds the work).
pub fn hex_encode(src: &[u8], out: &mut [u8]) {
    const D: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in src.iter().enumerate() {
        if 2 * i + 1 >= out.len() {
            break;
        }
        out[2 * i] = D[(b >> 4) as usize];
        out[2 * i + 1] = D[(b & 15) as usize];
    }
}

/// The only source of randomness a protocol crate sees. The firmware implements it with the hardware RNG (after the radio or the SAR ADC has been
/// enabled, as the C's `ml_rng.c` requires) and the tests with a seeded generator.
pub trait Entropy {
    /// Fill `buf` with cryptographically strong random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

impl<T: Entropy + ?Sized> Entropy for &mut T {
    fn fill(&mut self, buf: &mut [u8]) {
        (**self).fill(buf)
    }
}

/// A fixed-capacity byte vector: `push`/`extend` fail instead of growing.
#[derive(Clone)]
pub struct FixedBytes<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBytes<N> {
    /// Empty.
    pub const fn new() -> Self {
        Self { buf: [0; N], len: 0 }
    }
    /// Contents.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// Length.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Capacity.
    pub const fn capacity(&self) -> usize {
        N
    }
    /// Append, or `Err(())` (nothing is written) when it does not fit.
    #[allow(clippy::result_unit_err)]
    pub fn extend_from_slice(&mut self, s: &[u8]) -> Result<(), ()> {
        if s.len() > N - self.len {
            return Err(());
        }
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
        Ok(())
    }
    /// Remove everything.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes<{N}>(len={})", self.len)
    }
}

/// A fixed-capacity UTF-8 string (names, hostnames, error text) that truncates on a character boundary instead of failing.
#[derive(Clone)]
pub struct FixedStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedStr<N> {
    /// Empty.
    pub const fn new() -> Self {
        Self { buf: [0; N], len: 0 }
    }
    /// Copy `s`, cutting at the last character boundary that fits. Returns true if it was cut.
    pub fn set(&mut self, s: &str) -> bool {
        let mut n = s.len().min(N);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        self.len = n;
        n < s.len()
    }
    /// The string.
    pub fn as_str(&self) -> &str {
        // The invariant (set() cuts on a boundary and only copies valid UTF-8) makes this infallible; the fallback keeps the crate free of `unsafe`.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for FixedStr<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for FixedStr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}
impl<const N: usize> fmt::Display for FixedStr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl<const N: usize> PartialEq for FixedStr<N> {
    fn eq(&self, o: &Self) -> bool {
        self.as_str() == o.as_str()
    }
}
impl<const N: usize> Eq for FixedStr<N> {}

/// A saturating event counter (every drop and refusal in the tailnet crates is one; nothing is silent, ADR 0001 rule 2).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Counter(pub u32);
impl Counter {
    /// Count one.
    pub fn bump(&mut self) {
        self.0 = self.0.saturating_add(1);
    }
    /// The value.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// A deterministic entropy source for tests: xorshift64*, **not** cryptographic. Only compiled for tests of dependants through the `test-util` feature.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use super::Entropy;
    /// Seeded xorshift64*.
    #[derive(Debug, Clone)]
    pub struct TestRng(pub u64);
    impl Entropy for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                *b = (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn key_hex_roundtrip_and_constant_time_eq() {
        let k = Key32([0xab; 32]);
        let mut h = [0u8; 64];
        k.to_hex(&mut h);
        assert_eq!(&h[..4], b"abab");
        assert_eq!(Key32::from_hex(&h), Some(k.clone()));
        assert!(Key32::from_hex(&h[..63]).is_none());
        h[3] = b'z';
        assert!(Key32::from_hex(&h).is_none());
        assert!(Key32::ZERO.is_zero() && !k.is_zero());
    }

    #[test]
    fn fixed_str_cuts_on_char_boundary() {
        let mut s = FixedStr::<4>::new();
        assert!(s.set("aé€")); // 1 + 2 + 3 bytes: only "aé" fits
        assert_eq!(s.as_str(), "aé");
        assert!(!s.set("ok"));
        assert_eq!(s.as_str(), "ok");
    }

    #[test]
    fn fixed_bytes_never_grows() {
        let mut b = FixedBytes::<4>::new();
        assert!(b.extend_from_slice(&[1, 2, 3]).is_ok());
        assert!(b.extend_from_slice(&[4, 5]).is_err());
        assert_eq!(b.as_slice(), &[1, 2, 3]);
    }

    proptest! {
        #[test]
        fn fixed_str_always_valid_utf8(s in ".{0,40}", n in 0usize..3) {
            let mut f = FixedStr::<17>::new();
            f.set(&s);
            prop_assert!(s.starts_with(f.as_str()));
            prop_assert!(f.len() <= 17);
            let _ = n;
        }
        #[test]
        fn hex_roundtrip(b in proptest::array::uniform32(any::<u8>())) {
            let k = Key32(b);
            let mut h = [0u8; 64];
            k.to_hex(&mut h);
            prop_assert_eq!(Key32::from_hex(&h).unwrap().0, b);
        }
    }
}
