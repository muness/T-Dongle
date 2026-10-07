//! Sections 1 and 2 of the C test: the rules (band, elastic floor, pool, lease), done/abort/flush, unmatched events, and exactly-once under
//! random event orders against a reference model.

use std::prelude::v1::*;

use super::{Rs, conserved_rx, conserved_tx, pins};
use crate::TxVerdict::{Band, Elastic, Heap, Pool};
use crate::heap_budget::*;
use crate::pins::*;

const F: usize = ML_HB_FLOOR;

#[test]
fn constants() {
    // The inequality the header asserts, restated with numbers: reserve + (the shared band + the RX frame under check) buffers + the racing
    // slack fit under the elastic floor, and the TX pool and the FIFO agree.
    const { assert!(GATEWAY_WIFI_BAND_TOTAL == 5 && GATEWAY_WIFI_TX_POOL == 16 && GW_WTX_RING == 16) };
    assert_eq!(GATEWAY_WIFI_PIN_BAND_BYTES, 6 * 1664);
    const { assert!(ML_HB_RESERVE + GATEWAY_WIFI_PIN_BAND_BYTES + ML_HB_SLACK_BYTES == 29_696 && 29_696 <= ML_HB_FLOOR) };
    // ml_heap_budget.h values, one by one.
    assert_eq!(ML_ADM_NEG_PEAK_BYTES, 13_500);
    assert_eq!(ML_ADM_RECOVERY_BYTES, 16_384);
    assert_eq!(ML_HB_RESERVE, 16_384);
    assert_eq!(ML_HB_FLOOR, 29_884);
    assert_eq!(ML_HB_PIN_BUF_BYTES, 1664);
    assert_eq!(ML_HB_SLACK_BYTES, 3328);
    assert_eq!(ML_HB_PIN_BUFFERS, 6);
    assert_eq!(ML_HB_PIN_BYTES, 9984);
    assert_eq!(ML_HB_RX_SMALL_BYTES, 512);
    assert_eq!(GW_WTX_LEASE_MS, 3000);
    assert_eq!(GW_WTX_OVERHEAD, 192);
    const { assert!(GATEWAY_WIFI_RX_BAND_MAX == 4 && GATEWAY_WIFI_TX_BAND_MAX == 4) };
}

#[test]
fn hb_checks() {
    assert!(hb_ok(F, 0) && !hb_ok(F - 1, 0));
    assert!(hb_ok(F + 100, 100) && !hb_ok(F + 99, 100));
    // hb_rx_ok: a small datagram into an empty queue is taken whatever the heap says; WireGuard data (not small, or a non-empty queue) is not.
    assert!(hb_rx_ok(0, 512, true));
    assert!(!hb_rx_ok(0, 513, true));
    assert!(!hb_rx_ok(0, 100, false));
    assert!(hb_rx_ok(F + 100 + 16, 100, false) && !hb_rx_ok(F + 100 + 15, 100, false));
    assert!(hb_rx_ok(F + 600 + 16, 600, true));
}

#[test]
fn tx_rules() {
    let b = pins();
    // The band: with the RX side idle a direction gets TX_BAND_MAX of the 5 shared slots whatever the heap says, any size.
    for _ in 0..GATEWAY_WIFI_TX_BAND_MAX {
        assert_eq!(b.admit(1514, 0, 100), Band);
    }
    // Past the band a frame needs the floor plus its own cost: exactly there it is admitted, one byte less it is refused and takes nothing.
    assert!(wtx_cost(1514) == ML_HB_PIN_BUF_BYTES && wtx_cost(66) == 66 + GW_WTX_OVERHEAD as usize && wtx_cost(65535) == ML_HB_PIN_BUF_BYTES);
    let held = b.tx_outstanding();
    assert!(b.admit(1514, F + ML_HB_PIN_BUF_BYTES - 1, 100) == Heap && b.tx_outstanding() == held);
    assert_eq!(b.admit(1514, F, 100), Heap);
    assert_eq!(b.admit(66, F + 66 + GW_WTX_OVERHEAD as usize - 1, 100), Heap);
    assert_eq!(b.admit(66, F + 66 + GW_WTX_OVERHEAD as usize, 100), Elastic);
    assert_eq!(b.admit(1514, F + ML_HB_PIN_BUF_BYTES, 100), Elastic);
    // Up to the pool, then BUSY, whatever the heap.
    while b.tx_outstanding() < GATEWAY_WIFI_TX_POOL as u32 {
        assert_eq!(b.admit(1514, 1 << 30, 100), Elastic);
    }
    assert!(b.admit(66, 1 << 30, 100) == Pool && b.admit(1514, 0, 100) == Pool);
    assert!(b.stats().tx_refused_pool == 2 && b.stats().tx_high_water == GATEWAY_WIFI_TX_POOL as u32);
    // tx-done frees the oldest slot, and exactly one more frame is admitted (past the band: it takes the heap check).
    b.done();
    assert!(b.admit(1514, 1 << 30, 100) == Elastic && b.admit(1514, 1 << 30, 100) == Pool);
    conserved_tx(&b);
    // Everything done: the band is back, and a done with nothing outstanding is counted and changes nothing.
    while b.tx_outstanding() != 0 {
        b.done();
    }
    assert_eq!(b.admit(1514, 0, 100), Band);
    b.done();
    b.done();
    assert!(b.stats().tx_unmatched == 1 && b.tx_outstanding() == 0);
    conserved_tx(&b);
}

/// The joint band: RX and TX together hold at most BAND_TOTAL without a heap check, each at most 4, so neither can take the last slot from the
/// other: an ACK (RX) or an ARP reply (TX) always has a buffer, and a one-way flow gets 4 of the 5.
#[test]
fn joint_band() {
    let b = pins();
    // RX alone: 4 in the band, the 5th needs the heap (so does a TX frame once 4 RX are in: TX takes the 5th slot, then nothing).
    for _ in 0..GATEWAY_WIFI_RX_BAND_MAX {
        assert!(b.rx_admit(0));
    }
    assert!(!b.rx_admit(F - 1)); // RX at its maximum: the heap decides
    assert_eq!(b.admit(1514, 0, 1), Band); // TX still has the last slot
    assert_eq!(b.admit(1514, 0, 1), Heap); // and the band is now full
    assert!(b.rx_inflight() == 4 && b.tx_outstanding() == 1);
    b.done();
    for _ in 0..GATEWAY_WIFI_RX_BAND_MAX {
        b.rx_release();
    }
    // TX alone: 4 in the band; RX keeps the last slot.
    for _ in 0..GATEWAY_WIFI_TX_BAND_MAX {
        assert_eq!(b.admit(1514, 0, 1), Band);
    }
    assert_eq!(b.admit(1514, 0, 1), Heap);
    assert!(b.rx_admit(0) && !b.rx_admit(F - 1)); // the one RX frame, then the heap decides
    while b.tx_outstanding() != 0 {
        b.done();
    }
    b.rx_release();
    // Mixed: 2 RX + 3 TX fill the band; the sum, not either count, is what is limited.
    assert!(b.rx_admit(0) && b.rx_admit(0));
    for _ in 0..3 {
        assert_eq!(b.admit(1514, 0, 1), Band);
    }
    assert!(b.admit(1514, F + ML_HB_PIN_BUF_BYTES - 1, 1) == Heap && !b.rx_admit(F - 1));
    assert!(b.admit(1514, F + ML_HB_PIN_BUF_BYTES, 1) == Elastic && b.rx_admit(F)); // elastic: the floor after the buffer exists
    let w = b.pins_word();
    assert!((w & 0xff) == 3 && (w >> 8) == 4);
    // Elastic pins count too, so the band does not reopen while they are held.
    b.done(); // 3 RX + 3 TX = 6 >= 5: still full
    assert_eq!(b.admit(1514, F - 1, 1), Heap);
    b.done();
    b.done();
    b.done(); // 3 RX + 0 TX: two slots free again
    assert!(b.admit(1514, 0, 1) == Band && b.admit(1514, 0, 1) == Band && b.admit(1514, 0, 1) == Heap);
    // The worst the band can pin below the floor, at any interleaving of the two directions: BAND_TOTAL buffers.
    for seed in 1u64..=20 {
        let r = pins();
        let mut rs = Rs(0x2545_f491_4f6c_dd1d_u64.wrapping_mul(seed));
        let (mut peak, mut rx, mut tx) = (0u32, 0u32, 0u32);
        for i in 0..20_000u32 {
            match rs.rnd(4) {
                0 => {
                    if r.rx_admit(0) {
                        rx += 1; // no heap: the band only
                    }
                }
                1 => {
                    if r.admit(1514, 0, i).admitted() {
                        tx += 1;
                    }
                }
                2 => {
                    if rx != 0 {
                        r.rx_release();
                        rx -= 1;
                    }
                }
                _ => {
                    if tx != 0 {
                        r.done();
                        tx -= 1;
                    }
                }
            }
            assert!(r.rx_inflight() == rx && r.tx_outstanding() == tx);
            peak = peak.max(rx + tx);
        }
        assert_eq!(peak, GATEWAY_WIFI_BAND_TOTAL); // reached, and never exceeded, with no heap at all
    }
}

#[test]
fn tx_abort_flush_lease() {
    let b = pins();
    // abort: esp_wifi_internal_tx failed, so no driver buffer: the charge goes, no tx-done will come.
    assert_eq!(b.admit(1514, 0, 5), Band);
    b.abort();
    assert!(b.tx_outstanding() == 0 && b.stats().tx_aborted == 1);
    b.abort(); // nothing to abort: counted, not an underflow
    assert!(b.tx_outstanding() == 0 && b.stats().tx_unmatched == 1);
    // flush: the link changed, the driver cleared its queues.
    for i in 0..5 {
        assert!(b.admit(1514, 1 << 30, 10 + i).admitted());
    }
    assert!(b.flush() == 5 && b.tx_outstanding() == 0 && b.stats().tx_flushed == 5 && b.flush() == 0);
    b.done(); // a late done from before the flush: ignored
    assert_eq!(b.tx_outstanding(), 0);
    // the lease: a charge older than GW_WTX_LEASE_MS is presumed dropped by the driver, only the head can expire, the clock may wrap.
    let t0: u32 = 0xFFFF_FF00;
    assert!(b.admit(1514, 1 << 30, t0).admitted()); // A
    assert!(b.admit(1514, 1 << 30, t0.wrapping_add(600)).admitted()); // B
    assert!(b.stats().tx_stale == 0 && b.tx_outstanding() == 2);
    assert!(b.admit(1514, 1 << 30, t0.wrapping_add(GW_WTX_LEASE_MS)).admitted()); // C: A is exactly at the lease, not yet stale
    assert!(b.stats().tx_stale == 0 && b.tx_outstanding() == 3);
    assert!(b.admit(1514, 1 << 30, t0.wrapping_add(GW_WTX_LEASE_MS + 1)).admitted()); // D: A is stale and expired; B (601 ms old) is not
    assert!(b.stats().tx_stale == 1 && b.tx_outstanding() == 3);
    assert!(b.admit(1514, 1 << 30, t0.wrapping_add(600 + GW_WTX_LEASE_MS + 1)).admitted()); // E: B is stale now too
    assert!(b.stats().tx_stale == 2 && b.tx_outstanding() == 3);
    conserved_tx(&b);
    // a stalled driver cannot leak credits for ever: after one lease everything outstanding is gone and the band is back.
    let s = pins();
    for _ in 0..GATEWAY_WIFI_TX_POOL {
        assert!(s.admit(1514, 1 << 30, 1000).admitted());
    }
    assert_eq!(s.admit(66, 0, 1000 + GW_WTX_LEASE_MS), Pool);
    assert_eq!(s.admit(66, 0, 1000 + GW_WTX_LEASE_MS + 1), Band);
    assert!(s.stats().tx_stale == GATEWAY_WIFI_TX_POOL as u32 && s.tx_outstanding() == 1);
    conserved_tx(&s);
}

#[test]
fn rx_rules() {
    let b = pins();
    for _ in 0..GATEWAY_WIFI_RX_BAND_MAX {
        assert!(b.rx_admit(0)); // the band: whatever the heap
    }
    assert!(!b.rx_admit(F - 1) && b.stats().rx_dropped == 1 && b.rx_inflight() == GATEWAY_WIFI_RX_BAND_MAX);
    assert!(b.rx_admit(F) && b.rx_inflight() == GATEWAY_WIFI_RX_BAND_MAX + 1); // past it: the floor after the buffer exists
    b.rx_release(); // one freed: the count is back at the band, not under it
    assert!(!b.rx_admit(0));
    for _ in 0..GATEWAY_WIFI_RX_BAND_MAX {
        b.rx_release();
    }
    assert!(b.rx_inflight() == 0 && b.stats().rx_unmatched == 0);
    b.rx_release();
    assert!(b.rx_inflight() == 0 && b.stats().rx_unmatched == 1); // no underflow
    assert_eq!(b.stats().rx_high_water, GATEWAY_WIFI_RX_BAND_MAX + 1);
    conserved_rx(&b);
}

/// Exactly once, random order, with a reference model.
#[test]
fn exactly_once_random_tx() {
    for seed in 1u64..=40 {
        let mut rs = Rs(0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(seed));
        let b = pins();
        let mut model = 0u32; // outstanding charges by the reference count
        let mut now = rs.rnd(1000).wrapping_add(0xFFFF_F000); // starts close to the wrap
        for _ in 0..100_000 {
            now = now.wrapping_add(rs.rnd(7));
            match rs.rnd(8) {
                0..=2 => {
                    // submit
                    let heap = if rs.rnd(3) == 0 { F + rs.rnd(40_000) as usize } else { rs.rnd(F as u32) as usize };
                    if b.admit(1 + rs.rnd(1514), heap, now).admitted() {
                        model += 1;
                    }
                }
                3 => {
                    if rs.rnd(3) == 0 {
                        b.abort(); // the submit failed
                        model = model.saturating_sub(1);
                    }
                }
                4 | 5 => {
                    b.done();
                    model = model.saturating_sub(1);
                }
                6 => {
                    if rs.rnd(200) == 0 {
                        b.flush();
                        model = 0;
                    }
                }
                _ => now = now.wrapping_add(rs.rnd(GW_WTX_LEASE_MS / 4)), // time passes: leases expire
            }
            // The reference count differs only by what the lease took, which the counter says.
            let out = b.tx_outstanding();
            assert!(out <= GATEWAY_WIFI_TX_POOL as u32);
            assert!(out <= model, "outstanding {out} above the model {model}");
            model = out; // lease expiry is the one silent release
            conserved_tx(&b);
        }
    }
}

#[test]
fn exactly_once_random_rx() {
    for seed in 1u64..=40 {
        let mut rs = Rs(0xd1b5_4a32_d192_ed03_u64.wrapping_mul(seed));
        let b = pins();
        let mut model = 0u32;
        for _ in 0..100_000 {
            if rs.rnd(2) != 0 {
                let heap = if rs.rnd(2) != 0 { F + rs.rnd(5000) as usize } else { rs.rnd(F as u32) as usize };
                if b.rx_admit(heap) {
                    model += 1;
                }
            } else if model != 0 {
                b.rx_release();
                model -= 1;
            }
            assert_eq!(b.rx_inflight(), model);
            conserved_rx(&b);
        }
        assert_eq!(b.stats().rx_unmatched, 0);
    }
}

/// `room` heals leaked charges exactly as admission does, and the TX limit (the bridge sets 6) bounds the charges.
#[test]
fn room_and_tx_limit() {
    let b = pins();
    assert_eq!(b.tx_limit(), 0);
    assert!(b.room(0));
    b.set_tx_limit(6);
    assert_eq!(b.tx_limit(), 6);
    for i in 0..6 {
        assert!(b.admit(1514, 1 << 30, 100 + i).admitted());
    }
    assert!(!b.room(100)); // full, nothing stale
    assert_eq!(b.admit(66, 1 << 30, 100), Pool); // the limit, not the 16-deep pool
    assert_eq!(b.stats().tx_refused_pool, 1);
    b.done();
    assert!(b.room(100)); // a done opens one
    assert!(b.admit(66, 1 << 30, 100).admitted() && !b.room(100));
    // A leaked allowance: nobody calls admit, the worker only asks `room`. After a lease the charges are released under the lock.
    assert!(!b.room(100 + GW_WTX_LEASE_MS)); // exactly at the lease: not yet stale (the oldest charge was made at 100)
    assert!(b.room(100 + GW_WTX_LEASE_MS + 6)); // every charge is older than the lease now
    assert_eq!(b.stats().tx_stale, 6);
    assert_eq!(b.tx_outstanding(), 0);
    conserved_tx(&b);
    // `expire` on its own releases and counts, and an empty FIFO expires nothing.
    assert_eq!(b.expire(1_000_000), 0);
    assert!(b.admit(66, 0, 5_000_000).admitted());
    assert_eq!(b.expire(5_000_000 + GW_WTX_LEASE_MS + 1), 1);
    assert_eq!(b.stats().tx_stale, 7);
    // A limit of 0 is the pool again.
    b.set_tx_limit(0);
    for _ in 0..GATEWAY_WIFI_TX_POOL {
        assert!(b.admit(1514, 1 << 30, 9_000_000).admitted());
    }
    assert!(!b.room(9_000_000));
    assert_eq!(b.stats().tx_limit, 0);
}

/// The charge FIFO wraps its 16 slots correctly under a mix of done and abort.
#[test]
fn fifo_wraps() {
    let b = pins();
    for round in 0..200u32 {
        for i in 0..GATEWAY_WIFI_TX_POOL as u32 {
            assert!(b.admit(100, 1 << 30, round * 10 + i).admitted());
        }
        for _ in 0..GATEWAY_WIFI_TX_POOL / 2 {
            b.done();
        }
        b.abort();
        for _ in 0..GATEWAY_WIFI_TX_POOL / 2 - 1 {
            b.done();
        }
        assert_eq!(b.tx_outstanding(), 0);
    }
    conserved_tx(&b);
}
