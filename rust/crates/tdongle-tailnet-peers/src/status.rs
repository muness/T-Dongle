//! The `"wg_pool":{...},` fragment of `/status` (`runtime_status.inc`, `ml_wg_pool_status_t`), byte-identical to the C.

use crate::arbiter::ArbiterStats;
use crate::pool::PoolStats;
use tdongle_tailnet_admission::json::{JsonWriter, Sink};

/// `ml_wg_pool_status_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStatus {
    /// Pool capacity.
    pub capacity: u32,
    /// Live slots.
    pub used: u32,
    /// High-water mark.
    pub peak: u32,
    /// Refused: pool full.
    pub refused_full: u32,
    /// Refused: allocator failure.
    pub refused_nomem: u32,
    /// Evictions of the requester's own peers.
    pub evictions_own: u32,
    /// Evictions of other memberships' peers.
    pub evictions_other: u32,
    /// Activations rejected for want of a victim.
    pub rejected: u32,
    /// Slots refused by the largest-block guard.
    pub refused_largest: u32,
    /// Slots refused by the heap floor.
    pub refused_heap: u32,
    /// Smallest largest-free-block seen after a slot allocation (`u32::MAX`: none yet).
    pub largest_low: u32,
    /// Bytes per slot.
    pub slot_bytes: u32,
    /// Bytes of one WireGuard device.
    pub device_bytes: u32,
}

impl PoolStatus {
    /// `ml_wg_pool_status`: the pool's counters, the arbiter's, and the two sizes.
    #[must_use]
    pub fn compose(pool: &PoolStats, arbiter: &ArbiterStats, slot_bytes: u32, device_bytes: u32) -> Self {
        Self {
            capacity: pool.capacity,
            used: pool.used,
            peak: pool.peak_used,
            refused_full: pool.refused_full,
            refused_nomem: pool.refused_nomem,
            evictions_own: arbiter.evictions_own,
            evictions_other: arbiter.evictions_other,
            rejected: arbiter.refused,
            refused_largest: pool.refused_largest,
            refused_heap: pool.refused_heap,
            largest_low: pool.largest_low,
            slot_bytes,
            device_bytes,
        }
    }
}

/// `"wg_pool":{...},`
pub fn write_wg_pool<S: Sink>(w: &mut JsonWriter<S>, p: &PoolStatus) {
    w.raw("\"wg_pool\":{");
    w.num_field("capacity", u64::from(p.capacity));
    w.num_field("used", u64::from(p.used));
    w.num_field("peak", u64::from(p.peak));
    w.num_field("refused_full", u64::from(p.refused_full));
    w.num_field("refused_nomem", u64::from(p.refused_nomem));
    w.num_field("evictions_own", u64::from(p.evictions_own));
    w.num_field("evictions_other", u64::from(p.evictions_other));
    w.num_field("rejected", u64::from(p.rejected));
    w.num_field("refused_largest", u64::from(p.refused_largest));
    w.num_field("refused_heap", u64::from(p.refused_heap));
    w.key("largest_low");
    if p.largest_low == u32::MAX {
        w.raw("null");
    } else {
        w.number(u64::from(p.largest_low));
    }
    w.ch(b',');
    w.num_field("slot_bytes", u64::from(p.slot_bytes));
    w.key("device_bytes");
    w.number(u64::from(p.device_bytes));
    w.raw("},");
}
