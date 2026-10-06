//! The growth and shrink policy of the Wi-Fi to host frame ring (ADR 0023, the C elastic ring): a small permanent base, growth in chunks by a task that may allocate (never by
//! the producer in the Wi-Fi task), and release when idle. Pure, so the table of cases is tested on the host; the firmware applies the answers.

/// Permanent slots (C `BRIDGE_BASE_SLABS`).
pub const BASE_SLOTS: usize = 8;
/// Slots per elastic chunk (C `CHUNK_SLABS`).
pub const CHUNK_SLOTS: usize = 2;
/// Chunks at most (C `BRIDGE_MAX_CHUNKS`): 8 + 10 * 2 = 28 slots.
pub const MAX_CHUNKS: usize = 10;
/// The most slots: 28 (ADR 0023).
pub const MAX_SLOTS: usize = BASE_SLOTS + MAX_CHUNKS * CHUNK_SLOTS;
/// Free internal heap that must remain after a growth, bytes (`ML_HB_FLOOR`: 16,384 recovery + 13,500 negotiation peak).
pub const FLOOR_FREE: usize = 29_884;
/// Grow when no more than this many slots are free (C `GROW_HEADROOM`).
pub const GROW_HEADROOM: usize = 1;
/// A chunk unused this long is freed, one per housekeeping pass.
pub const IDLE_MS: u32 = 2_000;

/// What the housekeeping task should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing.
    None,
    /// Allocate one chunk.
    Grow,
    /// Free one chunk.
    Shrink,
    /// Growth is wanted but the heap would fall below the floor.
    DeniedHeap,
}

/// `used`: frames queued now; `slots`: capacity now; `chunk_bytes`: heap a chunk costs; `free_heap`: free internal heap now; `idle_ms`: how long the ring has been at most
/// `slots - CHUNK_SLOTS - GROW_HEADROOM` full (a shrink must leave the headroom, or the next frame would grow it again).
#[must_use]
pub const fn step(used: usize, slots: usize, chunk_bytes: usize, free_heap: usize, idle_ms: u32) -> Step {
    let free_slots = slots - used;
    if free_slots <= GROW_HEADROOM && slots < MAX_SLOTS {
        return if free_heap >= FLOOR_FREE + chunk_bytes { Step::Grow } else { Step::DeniedHeap };
    }
    if slots > BASE_SLOTS && idle_ms >= IDLE_MS && used + CHUNK_SLOTS + GROW_HEADROOM < slots {
        return Step::Shrink;
    }
    Step::None
}
