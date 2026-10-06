//! The alias book: which USB-side alias (198.18.0.0/15) stands for which (membership, peer), allocated on demand from a persistent counter and never
//! reassigned (`ml_directory_alias_*`, ADR 0013).
//!
//! The DNS responder looks aliases up through a shared `&` view while it resolves a name, and allocates the first time it needs one, so the book has
//! interior mutability (`Cell`): one owner, one thread, nothing re-entrant. The router's alias cache ([`tdongle_tailnet_router::AliasCache`]) is a
//! cache of this book: a miss starts a fill that the engine answers from here.
//!
//! The firmware persists the entries ([`AliasBook::entry`] / [`AliasBook::restore`]) in the directory's alias log; the counter is derived from them.

use core::cell::Cell;
use tdongle_tailnet_router::ALIAS_BASE;

/// Aliases the book holds (the C's flash log holds more; 128 covers the 64-alias cache twice over).
pub const ALIAS_BOOK: usize = 128;

/// One entry: (membership id, peer address, alias).
pub type AliasEntry = (u32, u32, u32);

/// The book.
#[derive(Debug)]
pub struct AliasBook {
    entries: [Cell<AliasEntry>; ALIAS_BOOK],
    n: Cell<usize>,
    next: Cell<u32>,
}

impl Default for AliasBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AliasBook {
    /// Bytes of the book.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Empty; the first alias is 198.18.0.1.
    pub const fn new() -> Self {
        Self { entries: [const { Cell::new((0, 0, 0)) }; ALIAS_BOOK], n: Cell::new(0), next: Cell::new(ALIAS_BASE) }
    }
    /// Entries held.
    pub fn len(&self) -> usize {
        self.n.get()
    }
    /// No entries?
    pub fn is_empty(&self) -> bool {
        self.n.get() == 0
    }
    /// Entry `i` (persistence).
    pub fn entry(&self, i: usize) -> Option<AliasEntry> {
        (i < self.n.get()).then(|| self.entries[i].get())
    }
    /// Load an entry from the persistent log (boot). `false` when full or conflicting.
    pub fn restore(&self, e: AliasEntry) -> bool {
        if self.find(e.0, e.1).is_some() || self.owner(e.2).is_some() || self.n.get() >= ALIAS_BOOK || e.2 < ALIAS_BASE {
            return false;
        }
        self.entries[self.n.get()].set(e);
        self.n.set(self.n.get() + 1);
        if e.2 >= self.next.get() {
            self.next.set(e.2 + 1);
        }
        true
    }
    /// The alias of (`member_id`, `peer_ip`).
    pub fn find(&self, member_id: u32, peer_ip: u32) -> Option<u32> {
        (0..self.n.get()).map(|i| self.entries[i].get()).find(|e| e.0 == member_id && e.1 == peer_ip).map(|e| e.2)
    }
    /// The (membership id, peer address) an alias belongs to.
    pub fn owner(&self, alias: u32) -> Option<(u32, u32)> {
        (0..self.n.get()).map(|i| self.entries[i].get()).find(|e| e.2 == alias).map(|e| (e.0, e.1))
    }
    /// The alias of (`member_id`, `peer_ip`), allocated now if it has none. `None` when the book is full.
    pub fn alloc(&self, member_id: u32, peer_ip: u32) -> Option<u32> {
        if let Some(a) = self.find(member_id, peer_ip) {
            return Some(a);
        }
        let n = self.n.get();
        if n >= ALIAS_BOOK {
            return None;
        }
        let a = self.next.get();
        self.entries[n].set((member_id, peer_ip, a));
        self.n.set(n + 1);
        self.next.set(a + 1);
        Some(a)
    }
    /// The next alias that would be allocated.
    pub fn next_alias(&self) -> u32 {
        self.next.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_unique_and_restorable() {
        let b = AliasBook::new();
        let a = b.alloc(1, 0x64400002).unwrap();
        assert_eq!(a, ALIAS_BASE);
        assert_eq!(b.alloc(1, 0x64400002), Some(a));
        let c = b.alloc(2, 0x64400002).unwrap();
        assert_ne!(a, c);
        assert_eq!(b.owner(c), Some((2, 0x64400002)));
        let r = AliasBook::new();
        for i in 0..b.len() {
            assert!(r.restore(b.entry(i).unwrap()));
        }
        assert!(!r.restore((1, 0x64400002, a + 5)), "conflicting key refused");
        assert_eq!(r.alloc(3, 9), Some(c + 1), "the counter resumes after the restored entries");
    }

    #[test]
    fn full_book_refuses() {
        let b = AliasBook::new();
        for i in 0..ALIAS_BOOK as u32 {
            assert!(b.alloc(1, 1000 + i).is_some());
        }
        assert_eq!(b.alloc(1, 5), None);
    }
}
