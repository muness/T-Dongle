//! The host -> Wi-Fi hand-off queue: a single-producer, single-consumer array of fixed slots with two free-running 32-bit counters (no lock).
//!
//! This is the only `unsafe` in the crate. The protocol that makes it sound (the same one `l2.c` documents):
//!
//! * `head` is advanced only by the producer (the TinyUSB task), `tail` only by the consumer (the worker); both only grow and wrap at 2^32,
//!   so the slot count divides 2^32 (asserted) and `head - tail` is the depth whatever the interleaving, provided `tail` is read first;
//! * the producer writes slot `head & MASK` only while `head - tail < limit <= SLOTS`, i.e. while the consumer has already released it, and
//!   publishes it with a release store of `head + 1`;
//! * the consumer reads/modifies slot `tail & MASK` only while `tail != head`, i.e. after the producer published it (acquire load of `head`),
//!   and releases it with a store of `tail + 1`.
//!
//! The type system enforces "one producer, one consumer": the access methods are `unsafe` and are only called from
//! [`crate::Producer`] and [`crate::Worker`], each of which can be created once per bridge and takes `&mut self`.

use core::cell::UnsafeCell;

use crate::{FRAME_MAX, HOST_SLOTS, SLOT_BYTES};

/// One queued frame: where it came from in time, and under which association.
#[derive(Debug)]
pub(crate) struct Slot {
    pub(crate) len: u16,
    /// The link epoch at the time the frame was queued.
    pub(crate) epoch: u16,
    /// The microsecond clock when the callback queued it.
    pub(crate) enq_us: u32,
    pub(crate) bytes: [u8; FRAME_MAX],
}

// `TDONGLE_L2_SLOT_BYTES` is the size the heap budget is written with (ADR 0023): a slot must not grow past it.
const _: () = assert!(size_of::<Slot>() <= SLOT_BYTES);
// The counters run free: the slot count must divide 2^32.
const _: () = assert!(HOST_SLOTS.is_power_of_two());

pub(crate) const MASK: u32 = HOST_SLOTS as u32 - 1;

/// The slot array, shared between exactly one producer and one consumer.
#[derive(Debug)]
pub(crate) struct Slots {
    cells: [UnsafeCell<Slot>; HOST_SLOTS],
}

// SAFETY: access to each cell is exclusive by the SPSC protocol in the module documentation: the producer and the consumer never touch the
// same slot at the same time, and the hand-over is a release/acquire pair on `head` (and `tail`) in `Bridge`.
unsafe impl Sync for Slots {}

impl Slots {
    pub(crate) const fn new() -> Self {
        Self { cells: [const { UnsafeCell::new(Slot { len: 0, epoch: 0, enq_us: 0, bytes: [0; FRAME_MAX] }) }; HOST_SLOTS] }
    }

    /// Exclusive access to the slot for counter value `counter`.
    ///
    /// # Safety
    /// The caller must hold the slot under the protocol above: the producer for `head` when `head - tail < SLOTS`, the consumer for `tail`
    /// when `tail != head`, and no other reference to that slot may exist.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn slot(&self, counter: u32) -> &mut Slot {
        // SAFETY: forwarded to the caller; the index is in range because of the mask.
        unsafe { &mut *self.cells[(counter & MASK) as usize].get() }
    }
}
