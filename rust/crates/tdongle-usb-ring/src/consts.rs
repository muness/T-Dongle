//! Geometry and timing constants of the ring.
//!
//! C origin: `components/esp_tinyusb/include/tinyusb_net.h` (`TINYUSB_NET_TX_*`) and the `TX_*` block at the top of the ring section of
//! `components/esp_tinyusb/tinyusb_net.c`. The two `_Static_assert`s of the C become the `const` assertions at the bottom of this file, which
//! also pin the arithmetic the rest of the crate relies on (a slab holds exactly one maximum record, the bookkeeping fits 32-bit masks).

/// Bytes of the per-record header: `[len: u16][gen: u16]` (`TX_REC_HDR`).
pub const REC_HDR: usize = 4;
/// Smallest frame the ring accepts (`TX_FRAME_MIN`): an Ethernet header.
pub const FRAME_MIN: usize = 14;
/// Largest frame the ring accepts (`TX_FRAME_MAX`): 1500 byte MTU + Ethernet header + VLAN tag.
pub const FRAME_MAX: usize = 1518;

/// Round `n` up to a multiple of four (`TX_ALIGN4`).
#[must_use]
pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Size of the largest record: header plus the padded maximum frame (`TX_REC_MAX`), 1524.
pub const REC_MAX: usize = REC_HDR + align4(FRAME_MAX);
/// One slab holds exactly one maximum record (`TINYUSB_NET_TX_SLAB_BYTES`), 1524 bytes.
pub const SLAB_BYTES: usize = 1524;
/// Slabs per elastic chunk (`TINYUSB_NET_TX_CHUNK_SLABS`).
pub const CHUNK_SLABS: usize = 2;
/// Bytes of one elastic chunk, one heap block (`TINYUSB_NET_TX_CHUNK_BYTES`), 3048.
pub const CHUNK_BYTES: usize = CHUNK_SLABS * SLAB_BYTES;
/// Largest number of permanent base slabs (`TINYUSB_NET_TX_MAX_BASE_SLABS`).
pub const MAX_BASE_SLABS: usize = 8;
/// Largest number of elastic chunks (`TINYUSB_NET_TX_MAX_CHUNKS`).
pub const MAX_CHUNKS: usize = 12;
/// Largest number of slabs, permanent plus every chunk (`TX_MAX_SLABS`): the width of the allocation mask and the FIFO.
pub const MAX_SLABS: usize = MAX_BASE_SLABS + MAX_CHUNKS * CHUNK_SLABS;
/// Mask for FIFO indices (`TX_FIFO_MASK`).
pub const FIFO_MASK: usize = MAX_SLABS - 1;
/// Grow when this many free slabs or fewer remain (`TX_GROW_HEADROOM`). The pressure test is written for exactly one.
pub const GROW_HEADROOM: u32 = 1;
/// Stack of the worker task the firmware spawns (`TX_WORKER_STACK`), bytes.
pub const WORKER_STACK: usize = 1536;
/// While frames are queued the worker wakes this often to notice a link that went away silently (`TX_LINK_POLL_MS`).
pub const LINK_POLL_MS: u32 = 200;
/// While elastic chunks exist the worker wakes this often for the idle check (`TX_HOUSEKEEP_MS`).
pub const HOUSEKEEP_MS: u32 = 500;
/// First back-off after a refused growth; doubles per consecutive refusal (`TX_GROW_RETRY_MS`).
pub const GROW_RETRY_MS: u32 = 100;
/// Longest back-off (`TX_GROW_RETRY_MAX_MS`).
pub const GROW_RETRY_MAX_MS: u32 = 1600;
/// Idle period used when `Config::idle_ms` is 0 (`TX_IDLE_DEFAULT_MS`).
pub const IDLE_DEFAULT_MS: u32 = 2000;
/// Allocator header charged against the floor when deciding a growth (`TX_HEAP_BLOCK_SLACK`).
pub const HEAP_BLOCK_SLACK: usize = 16;

/// Permanent slabs the transparent bridge configures (ADR 0023; `BRIDGE_RING_BASE` in the C tests).
pub const BRIDGE_BASE_SLABS: usize = 8;
/// Elastic chunk cap the transparent bridge configures (`BRIDGE_RING_CHUNKS`).
pub const BRIDGE_MAX_CHUNKS: usize = 10;
/// Slabs of the bridge's ring with every chunk present (`BRIDGE_RING_FRAMES`): 28.
pub const BRIDGE_MAX_SLABS: usize = BRIDGE_BASE_SLABS + BRIDGE_MAX_CHUNKS * CHUNK_SLABS;

// `_Static_assert(TX_REC_MAX == TX_SLAB_BYTES, "a slab holds exactly one maximum record")`
const _: () = assert!(REC_MAX == SLAB_BYTES, "a slab holds exactly one maximum record");
// `_Static_assert(TX_MAX_SLABS == 32u, "slab bookkeeping uses a 32-bit mask and a 32-entry FIFO")`
const _: () = assert!(MAX_SLABS == 32, "slab bookkeeping uses a 32-bit mask and a 32-entry FIFO");
const _: () = assert!(MAX_SLABS.is_power_of_two() && FIFO_MASK == MAX_SLABS - 1, "the FIFO index wraps with a mask");
const _: () = assert!(CHUNK_BYTES == 3048 && CHUNK_BYTES == 2 * SLAB_BYTES, "a chunk is two slabs, one 3,048 byte heap block");
const _: () = assert!(GROW_HEADROOM == 1, "the pressure test is written for one free slab");
// Slab offsets (`fill`, `rd`, `resv`) are stored as u16 and the chunk index in a u8 `used`/FIFO entry.
const _: () = assert!(SLAB_BYTES <= u16::MAX as usize && MAX_SLABS <= u8::MAX as usize + 1);
// A chunk's slab bits must stay inside the 32-bit allocation mask even for the highest chunk.
const _: () = assert!(MAX_BASE_SLABS + MAX_CHUNKS * CHUNK_SLABS <= u32::BITS as usize);
const _: () = assert!(FRAME_MIN <= FRAME_MAX && REC_HDR + align4(FRAME_MIN) <= SLAB_BYTES);
const _: () = assert!(BRIDGE_BASE_SLABS >= 2 && BRIDGE_BASE_SLABS <= MAX_BASE_SLABS && BRIDGE_MAX_CHUNKS <= MAX_CHUNKS);
const _: () = assert!(BRIDGE_MAX_SLABS == 28 && BRIDGE_MAX_SLABS <= MAX_SLABS);
const _: () = assert!(GROW_RETRY_MS * 16 == GROW_RETRY_MAX_MS, "100, 200, 400, 800, 1600: five doublings reach the cap");
