//! Receiver indices. They must be unique across every session and handshake of every membership that shares a slot pool (an index that two memberships
//! share would attribute one membership's datagram to the other's session), so they come from the pool, not from this crate.

/// A source of receiver indices, implemented by the pool (crate `tdongle-tailnet-peers`).
pub trait IndexAllocator {
    /// A fresh index: not 0 or `0xFFFF_FFFF`, and not in use by any live session or handshake in the pool (the pool finds those through
    /// [`PeerHot::for_each_index`](crate::peer::PeerHot::for_each_index)). It stays reserved until it shows up in a `PeerHot` or [`release`](Self::release)
    /// is called. `None` when the pool cannot provide one.
    fn allocate(&mut self) -> Option<u32>;

    /// An index handed out by [`allocate`](Self::allocate) will not be used (a discarded initiation job, a failed commit).
    fn release(&mut self, _index: u32) {}
}

impl<T: IndexAllocator + ?Sized> IndexAllocator for &mut T {
    fn allocate(&mut self) -> Option<u32> {
        (**self).allocate()
    }
    fn release(&mut self, index: u32) {
        (**self).release(index)
    }
}
