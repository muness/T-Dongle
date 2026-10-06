//! A bounded FIFO of byte packets in fixed slots (no allocation).

use crate::L3_MAX;

#[derive(Debug)]
pub(crate) struct Ring<const N: usize> {
    buf: [[u8; L3_MAX]; N],
    lens: [u16; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Ring<N> {
    pub(crate) const fn new() -> Self {
        const { assert!(N > 0) };
        Ring { buf: [[0; L3_MAX]; N], lens: [0; N], head: 0, len: 0 }
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
    /// Append a copy of `data` (at most [`L3_MAX`] bytes); false when full or too long.
    pub(crate) fn push(&mut self, data: &[u8]) -> bool {
        if self.is_full() || data.len() > L3_MAX {
            return false;
        }
        let i = (self.head + self.len) % N;
        self.buf[i][..data.len()].copy_from_slice(data);
        self.lens[i] = data.len() as u16;
        self.len += 1;
        true
    }
    pub(crate) fn front(&self) -> Option<&[u8]> {
        if self.len == 0 { None } else { Some(&self.buf[self.head][..usize::from(self.lens[self.head])]) }
    }
    pub(crate) fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.head = (self.head + 1) % N;
        self.len -= 1;
        true
    }
    pub(crate) fn clear(&mut self) -> usize {
        let n = self.len;
        self.head = 0;
        self.len = 0;
        n
    }
}
