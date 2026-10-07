//! Section 3 of the C test: submitters, the pp task's done, the event task's flush and RX admit/release against one budget, with real
//! threads (the C runs it under ThreadSanitizer too; here the counters and the identities are asserted at the end).

use std::prelude::v1::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use super::{Pins, conserved_rx, conserved_tx, pins};
use crate::GATEWAY_WIFI_TX_POOL;

fn xorshift32(r: &mut u32) {
    *r ^= *r << 13;
    *r ^= *r >> 17;
    *r ^= *r << 5;
}

#[test]
fn threads() {
    let shared: Arc<Pins> = Arc::new(pins());
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for i in 1u32..=2 {
        let (b, stop) = (Arc::clone(&shared), Arc::clone(&stop));
        handles.push(thread::spawn(move || {
            let mut r = i.wrapping_mul(2_654_435_761).wrapping_add(1);
            let mut now = 0u32;
            while !stop.load(Ordering::Relaxed) {
                xorshift32(&mut r);
                let heap = if r & 1 != 0 { 1usize << 30 } else { 0 };
                if b.admit(1 + r % 1514, heap, now).admitted() && r % 5 == 0 {
                    b.abort();
                }
                assert!(b.tx_outstanding() <= GATEWAY_WIFI_TX_POOL as u32);
                now = now.wrapping_add(1);
            }
        }));
    }
    {
        let (b, stop) = (Arc::clone(&shared), Arc::clone(&stop)); // the pp task
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                b.done();
            }
        }));
    }
    {
        let (b, stop) = (Arc::clone(&shared), Arc::clone(&stop)); // the event task
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                b.flush();
                for _ in 0..2000 {
                    std::hint::spin_loop();
                }
            }
        }));
    }
    for i in 1u32..=3 {
        let (b, stop) = (Arc::clone(&shared), Arc::clone(&stop)); // RX users
        handles.push(thread::spawn(move || {
            let mut r = i.wrapping_mul(2_246_822_519).wrapping_add(7);
            let mut mine = 0u32;
            while !stop.load(Ordering::Relaxed) {
                xorshift32(&mut r);
                if r & 1 != 0 {
                    if b.rx_admit(if r & 2 != 0 { 1 << 30 } else { 0 }) {
                        mine += 1;
                    }
                } else if mine != 0 {
                    b.rx_release();
                    mine -= 1;
                }
                assert!(b.rx_inflight() <= 255);
            }
            while mine != 0 {
                b.rx_release();
                mine -= 1;
            }
        }));
    }
    thread::sleep(Duration::from_millis(400));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    conserved_tx(&shared);
    assert!(shared.rx_inflight() == 0 && shared.stats().rx_unmatched == 0);
    conserved_rx(&shared);
    let s = shared.stats();
    assert!(s.tx_charged > 1000 && s.rx_band + s.rx_elastic > 1000, "the threads made progress: {s:?}");
}
