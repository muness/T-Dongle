//! The heap low-water recorder: the port of `components/tdongle_runtime/memory.c` and `include/tdongle_memory.h` (record ring of 16).
//!
//! Pure over an injected record: the firmware fills the heap numbers (`free`, `minimum`, `largest` of the internal heap) and the uptime,
//! and takes its critical section around the calls (C: `portENTER_CRITICAL`). The ring keeps *low-water transitions* and *failures*:
//! a record is stored when the ring is empty, when the operation failed, or when its `minimum_bytes` is below that of the newest stored
//! record. Ordinary traffic at an unchanged minimum is dropped.
//!
//! Oddity kept from C: once the ring is full, every stored record overwrites the *oldest* one, whatever it was. The comment in `memory.c`
//! ("ordinary traffic cannot evict them") holds for ordinary traffic, but sixteen further low-water steps or failures do evict an old failure.

use core::fmt;

/// Capacity of the ring.
pub const CAPACITY: usize = 16;

/// `tdongle_memory_record`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// Uptime of the note, ms.
    pub uptime_ms: u32,
    /// What was being done (`TDONGLE_MEMORY_OP_*`; `TDONGLE_MEMORY_OP_PHASE + phase` for a join-phase boundary).
    pub operation: u32,
    /// Bytes the operation asked for.
    pub requested: u32,
    /// Free internal heap now.
    pub free_bytes: u32,
    /// Lowest free internal heap since boot.
    pub minimum_bytes: u32,
    /// Largest free internal block now.
    pub largest_bytes: u32,
    /// 1 when the operation failed, else 0 (C: `!!failed`).
    pub failed: u32,
}

/// `TDONGLE_MEMORY_OP_TICK`.
pub const OP_TICK: u32 = 0;
/// `TDONGLE_MEMORY_OP_CONTROL_BUFFER`.
pub const OP_CONTROL_BUFFER: u32 = 1;
/// `TDONGLE_MEMORY_OP_DIAG_WRITE`.
pub const OP_DIAG_WRITE: u32 = 2;
/// `TDONGLE_MEMORY_OP_JOURNAL`.
pub const OP_JOURNAL: u32 = 3;
/// `TDONGLE_MEMORY_OP_STATUS_SNAPSHOT`.
pub const OP_STATUS_SNAPSHOT: u32 = 4;
/// `TDONGLE_MEMORY_OP_WIFI_PROFILES`.
pub const OP_WIFI_PROFILES: u32 = 5;
/// `TDONGLE_MEMORY_OP_PHASE`: plus the `tdongle_phase` of a join-phase boundary.
pub const OP_PHASE: u32 = 16;

/// Something `status` can read the records from, oldest first (`tdongle_memory_count` / `tdongle_memory_get`). The firmware's
/// implementation takes its lock per call, as C does, so `status` never writes to the console while holding it.
pub trait RecordSource: fmt::Debug {
    /// Number of records held.
    fn count(&self) -> usize;
    /// Record `offset` (0 oldest), `None` beyond the end.
    fn get(&self, offset: usize) -> Option<Record>;
}

impl RecordSource for &[Record] {
    fn count(&self) -> usize {
        self.len()
    }

    fn get(&self, offset: usize) -> Option<Record> {
        <[Record]>::get(self, offset).copied()
    }
}

impl<const N: usize> RecordSource for [Record; N] {
    fn count(&self) -> usize {
        N
    }

    fn get(&self, offset: usize) -> Option<Record> {
        <[Record]>::get(self, offset).copied()
    }
}

/// The ring (`entries`, `count`, `next`).
#[derive(Clone, Debug)]
pub struct MemoryLog {
    entries: [Record; CAPACITY],
    count: usize,
    next: usize,
}

impl Default for MemoryLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryLog {
    /// An empty ring.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [Record { uptime_ms: 0, operation: 0, requested: 0, free_bytes: 0, minimum_bytes: 0, largest_bytes: 0, failed: 0 }; CAPACITY],
            count: 0,
            next: 0,
        }
    }

    /// `tdongle_memory_note`: `record` is what the firmware measured now (its `failed` field is overwritten from `failed`). Returns whether
    /// it was stored.
    pub fn note(&mut self, mut record: Record, failed: bool) -> bool {
        record.failed = u32::from(failed);
        let newest_minimum = self.entries[(self.next + CAPACITY - 1) % CAPACITY].minimum_bytes;
        if self.count == 0 || failed || record.minimum_bytes < newest_minimum {
            self.entries[self.next] = record;
            self.next = (self.next + 1) % CAPACITY;
            if self.count < CAPACITY {
                self.count += 1;
            }
            true
        } else {
            false
        }
    }

    /// `tdongle_memory_count`.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// `tdongle_memory_get`: record `offset`, 0 the oldest. C returns an all-zero record beyond the end; this returns `None`.
    #[must_use]
    pub fn get(&self, offset: usize) -> Option<Record> {
        (offset < self.count).then(|| self.entries[(self.next + CAPACITY - self.count + offset) % CAPACITY])
    }

    /// The records, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = Record> + '_ {
        (0..self.count).filter_map(|i| self.get(i))
    }
}

impl RecordSource for MemoryLog {
    fn count(&self) -> usize {
        self.count
    }

    fn get(&self, offset: usize) -> Option<Record> {
        Self::get(self, offset)
    }
}
