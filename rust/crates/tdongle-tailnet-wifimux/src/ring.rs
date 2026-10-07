//! A bounded FIFO of byte packets. Each packet is a heap block of exactly its length (an ACK is 40 bytes, not 1,500): the C holds the same packets in lwIP pbufs.
//! The slots are `Option`s, so the ring itself is a few words; the caller decides whether the heap may take a packet ([`Ring::push`]'s `room`), so the queue
//! respects the one elastic floor of ADR 0022 and a refusal is a counted drop, never a panic.

extern crate alloc;

use crate::L3_MAX;
use alloc::vec::Vec;

#[derive(Debug)]
pub(crate) struct Ring<const N: usize> {
    slots: [Option<Vec<u8>>; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Ring<N> {
    pub(crate) const fn new() -> Self {
        const { assert!(N > 0) };
        Ring { slots: [const { None }; N], head: 0, len: 0 }
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) fn is_full(&self) -> bool {
        self.len == N
    }
    /// Append a copy of `data` (at most [`L3_MAX`] bytes); false when full, too long, `room` is false (the heap's elastic floor) or the allocator has no block.
    pub(crate) fn push(&mut self, data: &[u8], room: bool) -> bool {
        if self.is_full() || data.len() > L3_MAX || !room {
            return false;
        }
        let mut v: Vec<u8> = Vec::new();
        if v.try_reserve_exact(data.len()).is_err() {
            return false;
        }
        v.extend_from_slice(data);
        let i = (self.head + self.len) % N;
        self.slots[i] = Some(v);
        self.len += 1;
        true
    }
    pub(crate) fn front(&self) -> Option<&[u8]> {
        if self.len == 0 { None } else { self.slots[self.head].as_deref() }
    }
    pub(crate) fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.slots[self.head] = None;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        true
    }
    pub(crate) fn clear(&mut self) -> usize {
        let n = self.len;
        self.slots.fill(None);
        self.head = 0;
        self.len = 0;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_is_a_block_of_its_own_length_and_comes_back_intact() {
        let mut r = Ring::<3>::new();
        assert!(r.push(&[1; 40], true));
        assert!(r.push(&[2; 1500], true));
        assert_eq!(r.front().map(<[u8]>::len), Some(40));
        assert!(r.pop());
        assert_eq!(r.front(), Some(&[2u8; 1500][..]));
        // the memory is what is queued, not three 1,500 byte slots
        assert!(r.slots.iter().flatten().map(Vec::capacity).sum::<usize>() <= 1500);
    }

    #[test]
    fn a_heap_at_the_floor_refuses_the_packet_and_leaves_the_queue_as_it_was() {
        let mut r = Ring::<2>::new();
        assert!(r.push(&[7; 100], true));
        assert!(!r.push(&[8; 100], false), "no room: refused, not queued, not a panic");
        assert_eq!(r.len(), 1);
        assert_eq!(r.front(), Some(&[7u8; 100][..]));
        // too long is refused whatever the heap says
        assert!(!r.push(&[0; L3_MAX + 1], true));
    }

    #[test]
    fn clear_gives_every_block_back() {
        let mut r = Ring::<4>::new();
        for i in 0..4 {
            assert!(r.push(&[i; 10], true));
        }
        assert!(r.is_full());
        assert_eq!(r.clear(), 4);
        assert!(r.is_empty() && r.slots.iter().all(Option::is_none));
    }
}
