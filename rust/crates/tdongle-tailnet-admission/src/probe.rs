//! The heap measurements the firmware supplies. Nothing in this crate reads a heap itself.

use crate::adm::{Budget, Verdict};

/// What the platform can say about its internal heap (`heap_caps_get_*_size(MALLOC_CAP_INTERNAL)` on the device).
pub trait HeapProbe: Sync {
    /// Free internal heap now, bytes.
    fn free(&self) -> usize;
    /// The largest single free block, bytes.
    fn largest_block(&self) -> usize;
    /// The lowest the free heap has been since boot.
    fn minimum_free(&self) -> usize;

    /// One reading of all three (the three calls are not atomic on the device; this is the order admission reads them in).
    fn snapshot(&self) -> HeapSnapshot {
        HeapSnapshot { free: self.free(), largest: self.largest_block(), minimum: self.minimum_free() }
    }

    /// `ml_adm_decide` on a fresh reading.
    fn admit(&self, budget: &Budget) -> Verdict {
        let s = self.snapshot();
        budget.decide(s.free, s.largest)
    }
}

/// One reading of a [`HeapProbe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeapSnapshot {
    /// Free internal heap.
    pub free: usize,
    /// Largest free block.
    pub largest: usize,
    /// Minimum free since boot.
    pub minimum: usize,
}

/// A probe with fixed readings: the host-test double.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FixedProbe(pub HeapSnapshot);

impl HeapProbe for FixedProbe {
    fn free(&self) -> usize {
        self.0.free
    }
    fn largest_block(&self) -> usize {
        self.0.largest
    }
    fn minimum_free(&self) -> usize {
        self.0.minimum
    }
}
