//! The published self name (the C's `ml_published_name_t`): a short text one task rewrites and others read.
//!
//! The C needs a seqlock because tasks on two cores touch it without a lock. In the Rust runtime the owner wraps this value in a mutex or a
//! `Signal`/`Watch` (a value type cannot be torn through safe code), so only the *semantics* are kept: a name of 128 bytes or more is refused and the old
//! value survives, and the sequence counter is even when stable and advances by 2 per successful write.

/// `ML_PUBLISHED_NAME_MAX`: the capacity including the NUL, so names up to 127 bytes fit.
pub const PUBLISHED_NAME_MAX: usize = 128;

/// A bounded, replaceable text value.
#[derive(Clone, Debug)]
pub struct PublishedName {
    seq: u32,
    len: u8,
    text: [u8; PUBLISHED_NAME_MAX],
}

impl Default for PublishedName {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishedName {
    /// `size_of::<PublishedName>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<PublishedName>();

    /// Empty (the unset name).
    pub const fn new() -> Self {
        Self { seq: 0, len: 0, text: [0; PUBLISHED_NAME_MAX] }
    }

    /// Replace the value. `false`, leaving the old value untouched, when the new one (with its NUL) does not fit.
    pub fn set(&mut self, value: &str) -> bool {
        let b = value.as_bytes();
        if b.len() >= PUBLISHED_NAME_MAX || b.contains(&0) {
            return false;
        }
        self.text[..b.len()].copy_from_slice(b);
        self.text[b.len()..].fill(0);
        self.len = b.len() as u8;
        self.seq = self.seq.wrapping_add(2);
        true
    }

    /// The value (empty before the first `set`).
    pub fn get(&self) -> &str {
        core::str::from_utf8(&self.text[..self.len as usize]).unwrap_or("")
    }

    /// Writes so far times two (even = stable).
    pub fn seq(&self) -> u32 {
        self.seq
    }
}
