//! Loom model of the slot queue: every interleaving of one producer and one consumer, with loom's `UnsafeCell` tracking so that any concurrent or
//! unsynchronised access to a slot (a data race, a torn read, a slot reused before it was released) fails the run. Rule 5 of ADR 0001.
//!
//! Run: `RUSTFLAGS="--cfg loom" cargo test -p tdongle-spsc --test loom_spsc --release`.
#![cfg(loom)]

use loom::sync::Arc;
use loom::thread;
use tdongle_spsc::Spsc;
use tdongle_spsc::sync::UnsafeCell;

type Queue = Spsc<[u32; 4], 2>;

fn queue() -> Queue {
    Spsc::from_cells(core::array::from_fn(|_| UnsafeCell::new([0; 4])))
}

#[test]
fn slots_are_never_shared_and_arrive_in_order_whole() {
    loom::model(|| {
        let q = Arc::new(queue());
        let producer = {
            let q = q.clone();
            thread::spawn(move || {
                let mut p = q.producer().unwrap();
                for n in 1..=4u32 {
                    // At most 2 standing (the slot count), so a slot is reused while the consumer may still be reading its neighbour.
                    while let Err(_full) = p.reserve(2).map(|r| r.publish(|slot| *slot = [n; 4])) {
                        thread::yield_now();
                    }
                }
            })
        };
        let mut c = q.consumer().unwrap();
        let mut next = 1;
        while next <= 4 {
            match c.claim() {
                Some(mut lease) => {
                    let value = lease.with(|slot| *slot);
                    assert_eq!(value, [next; 4], "a torn or reordered slot");
                    next += 1;
                }
                None => thread::yield_now(),
            }
        }
        producer.join().unwrap();
    });
}
