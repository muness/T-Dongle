//! What the pool must do under pressure (each of these is a way the runtime would otherwise panic, leak or starve).

use super::*;
use tdongle_tailnet_admission::probe::{FixedProbe, HeapSnapshot};

fn heap(free: usize) -> FixedProbe {
    FixedProbe(HeapSnapshot { free, largest: free, minimum: free })
}

#[test]
fn a_taken_buffer_is_zeroed_counted_and_given_back_on_drop() {
    let pool = Pool::new(100_000);
    let h = heap(ML_HB_FLOOR + 50_000);
    let mut b = pool.alloc(&h, Class::Socket, 4096).unwrap();
    assert_eq!((b.len(), b.iter().all(|&x| x == 0), pool.in_use()), (4096, true, 4096));
    b[0] = 7;
    drop(b);
    let s = pool.stats();
    assert_eq!((s.in_use, s.high_water, s.takes[0]), (0, 4096, 1));
}

#[test]
fn the_floor_is_the_c_elastic_floor_not_a_number_of_our_own() {
    let pool = Pool::new(1 << 20);
    // exactly `ml_hb_ok`: after taking `len` the free heap must still be FLOOR
    let h = heap(ML_HB_FLOOR + 4096);
    assert!(pool.alloc(&h, Class::Socket, 4096).is_ok());
    assert_eq!(pool.alloc(&h, Class::Socket, 4097).unwrap_err(), Denied::Floor);
    assert_eq!(pool.alloc(&h, Class::Record, 4097).unwrap_err(), Denied::Floor);
    // a refusal leaves nothing counted
    assert_eq!(pool.stats().denied_floor, 2);
}

#[test]
fn a_negotiation_may_use_the_floor_down_to_the_recovery_reserve_and_no_further() {
    // the negotiation peak is what ML_HB_FLOOR leaves free above the recovery reserve: it must be admitted there, and nothing else may
    let pool = Pool::new(1 << 20);
    let free = ML_HB_FLOOR + 100; // an elastic consumer would be refused anything over 100 bytes
    let h = heap(free);
    assert_eq!(pool.alloc(&h, Class::Socket, 17_744).unwrap_err(), Denied::Floor);
    let b = pool.alloc(&h, Class::Negotiation, free - ML_ADM_RECOVERY_BYTES).unwrap();
    assert_eq!(b.len(), free - ML_ADM_RECOVERY_BYTES);
    assert_eq!(pool.alloc(&h, Class::Negotiation, free - ML_ADM_RECOVERY_BYTES + 1).unwrap_err(), Denied::Floor);
}

#[test]
fn the_cap_bounds_the_pool_whatever_the_heap_says() {
    let pool = Pool::new(10_000);
    let h = heap(1 << 20);
    let a = pool.alloc(&h, Class::Socket, 6_000).unwrap();
    assert_eq!(pool.alloc(&h, Class::Socket, 4_001).unwrap_err(), Denied::Cap);
    let b = pool.alloc(&h, Class::Socket, 4_000).unwrap();
    assert_eq!(pool.in_use(), 10_000);
    drop(a);
    assert!(pool.alloc(&h, Class::Socket, 6_000).is_ok());
    drop(b);
    assert_eq!(pool.stats().denied_cap, 1);
}

#[test]
fn a_length_that_does_not_fit_u32_is_a_refusal_not_a_wrap() {
    let pool = Pool::new(usize::MAX);
    let h = heap(usize::MAX / 2);
    assert_eq!(pool.charge(&h, Class::Socket, usize::MAX).unwrap_err(), Denied::Cap);
    assert_eq!(pool.in_use(), 0);
}

#[test]
fn a_double_refund_does_not_wrap_the_counter() {
    let pool = Pool::new(1000);
    let h = heap(1 << 20);
    pool.charge(&h, Class::Socket, 100).unwrap();
    pool.refund(100);
    pool.refund(100);
    assert_eq!(pool.in_use(), 0);
    assert!(pool.alloc(&h, Class::Socket, 1000).is_ok());
}

#[test]
fn a_waiter_is_woken_by_a_refund_and_then_gets_its_buffer() {
    use futures::FutureExt;
    let pool = Pool::new(8_000);
    let h = heap(1 << 20);
    let held = pool.alloc(&h, Class::Socket, 6_000).unwrap();
    let mut waiting = std::boxed::Box::pin(pool.alloc_wait(&h, Class::Socket, 6_000));
    assert!(waiting.as_mut().now_or_never().is_none(), "the pool is full: the caller waits");
    assert_eq!(pool.stats().waits, 1);
    drop(held);
    let got = futures::executor::block_on(waiting);
    assert_eq!(got.len(), 6_000);
}
