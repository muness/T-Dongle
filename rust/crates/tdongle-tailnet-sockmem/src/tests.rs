//! What the adapter must guarantee, because the runtime relies on it without being able to check: admitted, counted, reclaimed exactly once.

use super::*;
use tdongle_tailnet_admission::heap::ML_HB_FLOOR;
use tdongle_tailnet_admission::probe::HeapProbe;
use tdongle_tailnet_pool::Pool;

/// A heap whose free bytes the test sets (the pool's own accounting is separate from what the allocator reports, as on the device).
struct Heap(core::sync::atomic::AtomicUsize);

impl HeapProbe for Heap {
    fn free(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    fn largest_block(&self) -> usize {
        self.free()
    }
    fn minimum_free(&self) -> usize {
        self.free()
    }
}

fn setup(room: usize, cap: usize) -> (&'static Pool, &'static Heap, HeapSockMem) {
    let pool: &'static Pool = std::boxed::Box::leak(std::boxed::Box::new(Pool::new(cap)));
    let probe: &'static Heap = std::boxed::Box::leak(std::boxed::Box::new(Heap(core::sync::atomic::AtomicUsize::new(ML_HB_FLOOR + room))));
    (pool, probe, HeapSockMem::new(Mem { pool, heap: probe }))
}

#[test]
fn a_window_is_zeroed_counted_and_given_back_by_address() {
    let (pool, _h, m) = setup(1 << 20, 1 << 20);
    let w = m.take(4096).unwrap();
    assert_eq!((w.len(), w.iter().all(|&b| b == 0), pool.in_use(), m.out()), (4096, true, 4096, 1));
    w[0] = 1;
    let (addr, len) = (w.as_ptr() as usize, w.len());
    m.give(addr, len);
    assert_eq!((pool.in_use(), m.out(), m.given_unknown()), (0, 0, 0));
}

#[test]
fn a_window_that_would_cross_the_heap_floor_is_refused_and_leaves_nothing_counted() {
    let (pool, heap, m) = setup(5000, 1 << 20);
    assert!(m.take(5000).is_some());
    // the allocator now has exactly the floor left (the real heap shrank by what was taken)
    heap.0.store(ML_HB_FLOOR, Ordering::Relaxed);
    assert!(m.take(1).is_none());
    assert_eq!(pool.stats().denied_floor, 1);
    assert_eq!(pool.in_use(), 5000);
}

#[test]
fn giving_back_something_that_was_not_handed_out_is_ignored_not_freed() {
    let (pool, _h, m) = setup(1 << 20, 1 << 20);
    let w = m.take(100).unwrap();
    let (addr, len) = (w.as_ptr() as usize, w.len());
    // a wrong length, a wrong address, a window of the other kind: all ignored; the real block is untouched
    m.give(addr, len - 1);
    m.give(addr + 1, len);
    m.give_meta(addr, len);
    assert_eq!((m.given_unknown(), m.out(), pool.in_use()), (3, 1, 100));
    m.give(addr, len);
    // and a double give of the right one is also ignored
    m.give(addr, len);
    assert_eq!((m.given_unknown(), m.out(), pool.in_use()), (4, 0, 0));
}

#[test]
fn metadata_arrays_follow_the_same_rules() {
    let (pool, _h, m) = setup(1 << 20, 1 << 20);
    let a = m.take_meta(4).unwrap();
    assert_eq!(a.len(), 4);
    assert_eq!(pool.in_use(), 4 * core::mem::size_of::<PacketMetadata>());
    let (addr, n) = (a.as_ptr() as usize, a.len());
    m.give_meta(addr, n);
    assert_eq!((pool.in_use(), m.out()), (0, 0));
}

#[test]
fn a_full_table_refuses_instead_of_handing_out_a_block_it_could_not_reclaim() {
    let (pool, _h, m) = setup(1 << 20, 1 << 20);
    let mut v = std::vec::Vec::new();
    for _ in 0..TABLE {
        let w = m.take(16).unwrap();
        v.push((w.as_ptr() as usize, w.len()));
    }
    assert!(m.take(16).is_none());
    assert_eq!(pool.in_use(), TABLE * 16, "the refused block was refunded");
    for (a, l) in v {
        m.give(a, l);
    }
    assert_eq!((pool.in_use(), m.out()), (0, 0));
}
