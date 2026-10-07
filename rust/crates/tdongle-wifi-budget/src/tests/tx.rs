//! The `wifi_pins_tx` decision (`wifi_pins.inc`), with the driver call injected: the charged path, the abort on a driver failure, the degraded
//! path with small frames exempt.

use std::prelude::v1::*;

use super::{conserved_tx, pins};
use crate::heap_budget::*;
use crate::pins::*;
use crate::tx::*;

const F: usize = ML_HB_FLOOR;

#[test]
fn charged_path_and_driver_failure() {
    let b = pins();
    // Callback registered: the budget decides; a charged frame whose driver call fails is aborted, so no charge leaks.
    let mut sent = 0;
    assert_eq!(
        b.tx::<()>(true, 1514, 0, 10, || {
            sent += 1;
            Ok(())
        }),
        Ok(())
    );
    assert!(sent == 1 && b.tx_outstanding() == 1);
    assert_eq!(b.tx(true, 1514, 0, 10, || Err(7)), Err(TxError::Driver(7)));
    assert!(b.tx_outstanding() == 1 && b.stats().tx_aborted == 1 && b.stats().tx_charged == 2);
    // Fill the band, then a frame past it is refused for the heap without calling the driver.
    for _ in 0..3 {
        assert!(b.tx::<()>(true, 1514, 0, 10, || Ok(())).is_ok());
    }
    let mut called = false;
    let r = b.tx::<()>(true, 1514, F, 10, || {
        called = true;
        Ok(())
    });
    assert!(r == Err(TxError::NoMem) && !called && b.stats().tx_refused_heap == 1);
    assert_eq!(b.tx_decision(true, 1514, F, 10), TxDecision::Refuse { by: TxVerdict::Heap });
    assert_eq!(b.tx_decision(true, 1514, F + ML_HB_PIN_BUF_BYTES, 10), TxDecision::SendCharged { by: TxVerdict::Elastic });
    b.abort();
    conserved_tx(&b);
}

#[test]
fn degraded_path_small_frames_exempt() {
    let b = pins();
    // The callback could not be registered: nothing is charged, the heap floor alone decides, small frames are exempt.
    assert_eq!(WIFI_PINS_SMALL_FRAME, 256);
    assert_eq!(b.tx_decision(false, 256, 0, 0), TxDecision::SendUncounted); // exempt at the limit, whatever the heap
    assert_eq!(b.tx_decision(false, 257, 0, 0), TxDecision::Refuse { by: TxVerdict::Heap });
    assert_eq!(b.stats().tx_refused_heap, 1);
    let cost = wtx_cost(257);
    assert_eq!(b.tx_decision(false, 257, F + cost - 1, 0), TxDecision::Refuse { by: TxVerdict::Heap });
    assert_eq!(b.tx_decision(false, 257, F + cost, 0), TxDecision::SendUncounted);
    assert_eq!(b.tx_decision(false, 1514, F + ML_HB_PIN_BUF_BYTES, 0), TxDecision::SendUncounted);
    assert_eq!(b.stats().tx_refused_heap, 2);
    // Nothing was charged, so a driver failure has nothing to abort: tx() must not touch the counters.
    assert_eq!(b.tx(false, 100, 0, 0, || Err("driver")), Err(TxError::Driver("driver")));
    assert!(b.stats().tx_aborted == 0 && b.stats().tx_unmatched == 0 && b.stats().tx_charged == 0 && b.tx_outstanding() == 0);
    assert_eq!(b.tx::<()>(false, 1514, 0, 0, || Ok(())), Err(TxError::NoMem));
    assert_eq!(b.stats().tx_refused_heap, 3);
}

#[test]
fn tx_limit_in_the_decision() {
    // The bridge sets the limit to 6: the seventh frame is refused by the pool rule even with an enormous heap.
    let b = pins();
    b.set_tx_limit(6);
    for _ in 0..6 {
        assert!(matches!(b.tx_decision(true, 1000, 1 << 30, 0), TxDecision::SendCharged { .. }));
    }
    assert_eq!(b.tx_decision(true, 1000, 1 << 30, 0), TxDecision::Refuse { by: TxVerdict::Pool });
    assert_eq!(b.stats().tx_refused_pool, 1);
}
