//! The anti-replay window: a sliding bitmap kept as a ring of 32-bit blocks (RFC 6479; the algorithm of the Linux kernel's `counter_validate()`,
//! wireguard-go's `replay.Filter` and the C `wireguard_replay.h`, which this is a port of).
//!
//! Semantics, identical to the C and checked against an exact reference model:
//!
//! * a counter at or above [`REJECT_AFTER_MESSAGES`] is refused outright (the session is finished);
//! * a counter more than [`ReplayRing::WINDOW`] below the highest accepted counter is [`ReplayVerdict::TooOld`];
//! * a counter inside the window that was accepted before is a [`ReplayVerdict::Duplicate`]; every counter is accepted at most once;
//! * a counter above the highest slides the window forward, forgetting what falls out of it.
//!
//! Nothing may be recorded unless the packet authenticated: [`ReplayRing::peek`] is the cheap pre-check before the AEAD (no state change),
//! [`ReplayRing::check`] the test-and-record after it.

use crate::consts::REJECT_AFTER_MESSAGES;

/// The verdict on one counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Fresh: accepted (and recorded by [`ReplayRing::check`]).
    Ok,
    /// Inside the window, already accepted.
    Duplicate,
    /// Below the window.
    TooOld,
    /// At or above `REJECT_AFTER_MESSAGES`.
    Limit,
}

/// A window of `BLOCKS * 32` counters of which `BLOCKS * 32 - 32` are usable. `BLOCKS` must be a power of two between 2 and 256 (so the counter plus the
/// window can never wrap below the reject limit's 2^13 of slack).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayRing<const BLOCKS: usize> {
    counter: u64,
    ring: [u32; BLOCKS],
}

/// The firmware's window: 512 bits (window 480), 72 bytes per keypair (ADR 0019 of the C tree).
pub type ReplayWindow = ReplayRing<16>;

const BLOCK_BITS: u64 = 32;
const BLOCK_LOG: u32 = 5;

impl<const BLOCKS: usize> Default for ReplayRing<BLOCKS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCKS: usize> ReplayRing<BLOCKS> {
    const VALID: () = assert!(BLOCKS >= 2 && BLOCKS.is_power_of_two() && BLOCKS <= 256, "replay ring: power of two blocks, 2..=256");
    /// Ring size in bits.
    pub const RING_BITS: usize = BLOCKS * 32;
    /// The oldest accepted counter is `WINDOW` below the highest (the newest block may be only partly the window, so one block is redundant).
    pub const WINDOW: u64 = (BLOCKS as u64) * BLOCK_BITS - BLOCK_BITS;
    /// `size_of::<Self>()`.
    pub const BYTES: usize = core::mem::size_of::<Self>();

    /// An empty window (counter 0 is acceptable).
    pub const fn new() -> Self {
        let () = Self::VALID;
        Self { counter: 0, ring: [0; BLOCKS] }
    }

    /// Forget everything (a new session).
    pub fn reset(&mut self) {
        self.counter = 0;
        self.ring = [0; BLOCKS];
    }

    /// The highest counter accepted so far (0 before the first packet).
    pub fn highest(&self) -> u64 {
        self.counter
    }

    /// What [`check`](Self::check) would answer, changing nothing. Exact: `peek(c) == Ok` implies the next `check(c)` is `Ok` unless another counter was
    /// recorded in between.
    pub fn peek(&self, their: u64) -> ReplayVerdict {
        if their >= REJECT_AFTER_MESSAGES {
            return ReplayVerdict::Limit;
        }
        if their > self.counter {
            return ReplayVerdict::Ok;
        }
        if their + Self::WINDOW < self.counter {
            return ReplayVerdict::TooOld; // cannot wrap: their < LIMIT and the window is below 2^13
        }
        let word = self.ring[((their >> BLOCK_LOG) as usize) & (BLOCKS - 1)];
        if word & (1u32 << (their & (BLOCK_BITS - 1))) != 0 { ReplayVerdict::Duplicate } else { ReplayVerdict::Ok }
    }

    /// Test and, if acceptable, record `their` in one step. Call only after the packet authenticated.
    pub fn check(&mut self, their: u64) -> ReplayVerdict {
        if their >= REJECT_AFTER_MESSAGES {
            return ReplayVerdict::Limit;
        }
        let block = their >> BLOCK_LOG;
        if their > self.counter {
            // Forward: clear every block the window slides over (at most the whole ring); the current block keeps its older bits, which stay in the window.
            let current = self.counter >> BLOCK_LOG;
            let advance = (block - current).min(BLOCKS as u64);
            for i in 1..=advance {
                self.ring[((current + i) as usize) & (BLOCKS - 1)] = 0;
            }
            self.counter = their;
        } else if their + Self::WINDOW < self.counter {
            return ReplayVerdict::TooOld;
        }
        let word = &mut self.ring[(block as usize) & (BLOCKS - 1)];
        let bit = 1u32 << (their & (BLOCK_BITS - 1));
        if *word & bit != 0 {
            return ReplayVerdict::Duplicate;
        }
        *word |= bit;
        ReplayVerdict::Ok
    }
}

#[cfg(test)]
mod tests;
