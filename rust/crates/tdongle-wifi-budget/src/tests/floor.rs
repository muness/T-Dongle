//! Section 4 of the C test: the floor under concurrent TX and RX pins. The minimum free heap must stay at or above the recovery reserve
//! (16,384 B) with the budget, and must NOT without it (what PR #42 left unbounded), and each ingredient of the budget (the RX gate, the band
//! size, the floor) is shown to matter by removing it.

use std::prelude::v1::*;

use super::sim::{CHUNK_BYTES, Model, run};
use super::{Rs, pins};
use crate::heap_budget::*;
use crate::pins::*;

const STEPS: u64 = 400_000;

fn seeded(seed: u64) -> Rs {
    Rs(0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(seed))
}

/// THE BOUND: with the budget (both directions, download only, upload only) the minimum never goes below the recovery reserve.
#[test]
fn floor_holds_with_the_budget() {
    let now = Model {
        name: "amendment 2: bands + elastic floor (pools 16)",
        rx_mode: 1,
        tx_mode: 1,
        rx_pool: 16,
        tx_pool: 16,
        upload: true,
        download: true,
        ..Model::blank("")
    };
    let mut down = now;
    let mut up = now;
    down.upload = false;
    down.name = "  download only";
    up.download = false;
    up.name = "  upload only";
    let ms = [now, down, up];
    let mut worst = [1i64 << 30; 3];
    let mut f0 = 34_000i64;
    while f0 <= 46_000 {
        for seed in 1..=6u64 {
            for (k, m) in ms.iter().enumerate() {
                let v = run(m, f0, STEPS, seeded(seed), f0 == 38_000 && seed == 1);
                worst[k] = worst[k].min(v);
                assert!(v >= ML_HB_RESERVE as i64, "{} F0 {f0} seed {seed}: min free {v} below the reserve", m.name); // never below the recovery reserve
            }
        }
        f0 += 2000;
    }
    std::eprintln!(
        "  worst of 7 start levels x 6 seeds: both directions {} B, download {} B, upload {} B (reserve {})",
        worst[0],
        worst[1],
        worst[2],
        ML_HB_RESERVE
    );
}

/// What PR #42 left: the driver's 16 RX buffers pinned by sockets and lwIP with nothing counting them, TX held to 6 by the pool. The same
/// schedule must break the reserve.
#[test]
fn floor_broken_without_the_budget() {
    let merged = Model { name: "PR #42 as merged (RX pool 16, TX pool 6)", rx_pool: 16, tx_pool: 6, upload: true, download: true, ..Model::blank("") };
    let mut merged_dl = merged;
    merged_dl.upload = false;
    merged_dl.name = "  download only";
    let pool16 = Model { name: "TX pool 16, no budget (the experiment)", rx_pool: 6, tx_pool: 16, upload: true, download: false, ..Model::blank("") };
    let (mut wm, mut wd, mut wp) = (1i64 << 30, 1i64 << 30, 1i64 << 30);
    let mut f0 = 36_000i64;
    while f0 <= 42_000 {
        for seed in 1..=6u64 {
            let p = f0 == 38_000 && seed == 1;
            wm = wm.min(run(&merged, f0, STEPS, seeded(seed), p));
            wd = wd.min(run(&merged_dl, f0, STEPS, seeded(seed), p));
            wp = wp.min(run(&pool16, f0, STEPS, seeded(seed), p));
        }
        f0 += 2000;
    }
    std::eprintln!(
        "  without the budget: PR #42 as merged {wm} B (download only {wd} B; the board's minimum under a 6 Mbit/s UDP download was 5,000 B), TX pool 16 alone {wp} B"
    );
    let reserve = ML_HB_RESERVE as i64;
    assert!(wm < reserve - 8000 && wd < reserve - 5000 && wp < reserve - 3000, "{wm} {wd} {wp}");
}

/// Each ingredient matters: a mutant that keeps the gate but widens the RX band, or lowers the floor it checks, breaks the reserve.
#[test]
fn floor_broken_by_each_mutant() {
    let wide = Model {
        name: "mutant: gate with an RX band of 10",
        rx_mode: 2,
        tx_mode: 1,
        rx_pool: 16,
        tx_pool: 16,
        rx_band: 10,
        upload: true,
        download: true,
        ..Model::blank("")
    };
    let low = Model {
        name: "mutant: gate with a floor of reserve + 3 KB",
        rx_mode: 2,
        tx_mode: 1,
        rx_pool: 16,
        tx_pool: 16,
        rx_band: GATEWAY_WIFI_RX_BAND_MAX as usize,
        pin_floor: ML_HB_RESERVE + 3000,
        upload: true,
        download: true,
    };
    let (mut ww, mut wl) = (1i64 << 30, 1i64 << 30);
    let mut f0 = 36_000i64;
    while f0 <= 42_000 {
        for seed in 1..=6u64 {
            ww = ww.min(run(&wide, f0, STEPS, seeded(seed), false));
            wl = wl.min(run(&low, f0, STEPS, seeded(seed), false));
        }
        f0 += 2000;
    }
    std::eprintln!("  mutants: RX band 10 -> {ww} B; elastic floor reserve + 3 KB -> {wl} B");
    assert!(ww < ML_HB_RESERVE as i64 && wl < ML_HB_RESERVE as i64, "{ww} {wl}");
}

/// The arithmetic behind the schedule, with the real functions: the worst legal interleaving, written out. Three checkers (a ring chunk and two
/// USB frames, 3,064 + 1,534 + 1,534 B: the design point of ADR 0022, the TX submit being one of the concurrent ones) pass on the same free
/// value; then every pin the budget allows arrives; the minimum is the floor minus what the two smaller racers took and the pins.
#[test]
fn worst_interleaving() {
    let (c_ring, c_frame) = (i64::from(CHUNK_BYTES) + 16, 1518 + 16);
    let mut free_now = ML_HB_FLOOR as i64 + c_ring; // every check below passes here
    assert!(hb_ok(free_now as usize, c_ring as usize) && hb_ok(free_now as usize, c_frame as usize));
    let b = pins();
    free_now -= c_ring + 2 * c_frame; // the three racers allocate
    assert_eq!(free_now, ML_HB_FLOOR as i64 - 2 * c_frame);
    let mut min = free_now;
    // The pins: the band first (5 shared slots, here 4 RX and 1 TX: admitted at any heap). Nothing else is admitted below the floor.
    for _ in 0..GATEWAY_WIFI_RX_BAND_MAX {
        free_now -= ML_HB_PIN_BUF_BYTES as i64;
        assert!(b.rx_admit(free_now as usize));
    }
    assert_eq!(b.admit(1514, free_now as usize, 0), TxVerdict::Band);
    free_now -= ML_HB_PIN_BUF_BYTES as i64;
    for _ in 0..20 {
        // everything past the band is refused, whatever arrives
        assert_eq!(b.admit(1514, free_now as usize, 0), TxVerdict::Heap);
        assert!(!b.rx_admit((free_now - ML_HB_PIN_BUF_BYTES as i64) as usize));
    }
    let last = free_now - ML_HB_PIN_BUF_BYTES as i64; // the one RX buffer under check when it is refused
    min = min.min(last);
    std::eprintln!(
        "  worst legal interleaving: floor {} - racers {} - band pins {} x {} - the RX frame under check {} = {} B (reserve {})",
        ML_HB_FLOOR,
        2 * c_frame,
        GATEWAY_WIFI_BAND_TOTAL,
        ML_HB_PIN_BUF_BYTES,
        ML_HB_PIN_BUF_BYTES,
        min,
        ML_HB_RESERVE
    );
    assert!(min >= ML_HB_RESERVE as i64 && min == 16_832);
    // A fourth racer is the one place the bound is quantified, not proved (ADR 0022): it costs one more frame.
    assert!(min - c_frame < ML_HB_RESERVE as i64 && min - c_frame > 14_000);
}
