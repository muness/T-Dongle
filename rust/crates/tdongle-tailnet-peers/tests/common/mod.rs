//! A stand-in for the WireGuard crate's slot payload and scripted entropy.
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};
use tdongle_tailnet_admission::HeapProbe;
use tdongle_tailnet_peers::Entropy;
use tdongle_tailnet_peers::pool::{Gate, GateRefusal, SlotMeta};

/// Counts [`TestSlot::wipe`] calls that found secret bytes.
pub static WIPES_WITH_SECRET: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keypair {
    pub valid: bool,
    pub local_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestSlot {
    pub valid: bool,
    pub public_key: [u8; 32],
    pub secret: [u8; 32],
    pub curr: Keypair,
    pub prev: Keypair,
    pub next: Keypair,
    pub hs_valid: bool,
    pub hs_initiator: bool,
    pub hs_index: u32,
}

const KP: Keypair = Keypair { valid: false, local_index: 0 };

impl SlotMeta for TestSlot {
    const ZEROED: Self =
        TestSlot { valid: false, public_key: [0; 32], secret: [0; 32], curr: KP, prev: KP, next: KP, hs_valid: false, hs_initiator: false, hs_index: 0 };
    fn wipe(&mut self) {
        if self.secret.iter().any(|b| *b != 0) {
            WIPES_WITH_SECRET.fetch_add(1, Ordering::Relaxed);
        }
        self.secret = [0; 32];
    }
    fn reserved_indices(&self) -> [u32; 4] {
        [self.curr.local_index, self.prev.local_index, self.next.local_index, self.hs_index]
    }
    fn is_valid(&self) -> bool {
        self.valid
    }
    fn session_has_index(&self, i: u32) -> bool {
        (self.curr.valid && self.curr.local_index == i) || (self.next.valid && self.next.local_index == i) || (self.prev.valid && self.prev.local_index == i)
    }
    fn handshake_has_index(&self, i: u32) -> bool {
        self.hs_valid && self.hs_initiator && self.hs_index == i
    }
    fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    fn handshake_state(&self) -> (bool, u32) {
        (self.hs_valid, self.hs_index)
    }
}

impl TestSlot {
    pub fn peer(seed: u8) -> TestSlot {
        let mut s = TestSlot::ZEROED;
        s.valid = true;
        s.public_key = [seed; 32];
        s.secret = [seed | 0x80; 32];
        s
    }
}

/// Entropy that plays a script of 32-bit values first (little endian, as the C's `wireguard_random_bytes` stub), then xorshift.
pub struct Script {
    pub values: std::vec::Vec<u32>,
    pub pos: usize,
    pub draws: usize,
    pub state: u64,
}
impl Script {
    pub fn new(values: &[u32]) -> Self {
        Script { values: values.to_vec(), pos: 0, draws: 0, state: 0x9E37_79B9_7F4A_7C15 }
    }
}
impl Entropy for Script {
    fn fill(&mut self, buf: &mut [u8]) {
        if buf.len() == 4 {
            self.draws += 1;
            if self.pos < self.values.len() {
                buf.copy_from_slice(&self.values[self.pos].to_le_bytes());
                self.pos += 1;
                return;
            }
        }
        for b in buf {
            self.state = self.state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            *b = (self.state >> 56) as u8;
        }
    }
}

/// A gate that refuses after a number of admissions, with a chosen reason.
pub struct FailAfter {
    pub left: Option<u32>,
    pub why: GateRefusal,
}
impl Gate for FailAfter {
    fn admit(&mut self, _live: u32, _bytes: usize) -> Result<Option<usize>, GateRefusal> {
        match &mut self.left {
            Some(0) => Err(self.why),
            Some(n) => {
                *n -= 1;
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

pub struct Probe(pub usize, pub usize, pub usize);
impl HeapProbe for Probe {
    fn free(&self) -> usize {
        self.0
    }
    fn largest_block(&self) -> usize {
        self.1
    }
    fn minimum_free(&self) -> usize {
        self.2
    }
}
