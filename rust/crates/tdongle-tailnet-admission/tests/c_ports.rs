//! Ports of the C host tests: test_admission.c, test_heap_budget.c (+ tools/test-heap-budget.py), test_negotiation.c, test_coord_token.c,
//! test_socket_budget.c, test_usb_rx_budget.c, test_net_io_drain.c, test_rx_stats_threads.c (semantic part), test_wg_rx_budget.c, the run
//! structure of test_wg_rx_batch.c, and tools/test-tcp-window.py. Each test names its C source; assertions keep the C's numbers.

#![allow(clippy::assertions_on_constants)]

use std::vec::Vec;
use tdongle_tailnet_admission::adm::*;
use tdongle_tailnet_admission::coord_state::{CoordState, token_sync};
use tdongle_tailnet_admission::heap::*;
use tdongle_tailnet_admission::negotiation::*;
use tdongle_tailnet_admission::net_io::{self, Recv};
use tdongle_tailnet_admission::rx_stats::{RX_STAT_COUNT, RxStat, RxStats};
use tdongle_tailnet_admission::tcp_window::{self, Violation};
use tdongle_tailnet_admission::usb_rx::{self, Admit, GATEWAY_USB_RX_HEAP_EXEMPT, GATEWAY_USB_RX_INFLIGHT_MAX};
use tdongle_tailnet_admission::wg_rx::{self, ML_WG_RX_BATCH, ML_WG_RX_OVERHEAD, ML_WG_RX_QUEUE_BYTES, Run, RunStats, Site};
use tdongle_tailnet_admission::{limits, sockets};

// ---------------------------------------------------------------------------------------------------------------------------------
// test_admission.c
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn admission_c_reference_numbers() {
    let p = Params::c_reference();
    let first = p.budget(false);
    let next = p.budget(true);
    // The shared tasks are charged once: the first membership pays for them, later ones do not.
    assert!(first.shared_runtime == 23040 + 3 * 340 && next.shared_runtime == 0);
    assert_eq!(first.required - next.required, first.shared_runtime);
    assert!(first.shared_runtime == 24060 && first.member_steady == 20992 + 18664 && first.required == 96400);
    assert_eq!(next.required, 72_340);
    // One negotiation peak and one recovery reserve, however many memberships there are.
    assert!(first.negotiation == ML_ADM_NEG_PEAK_BYTES && next.negotiation == first.negotiation);
    assert_eq!(next.member_steady, next.member_start + next.member_growth);
    assert_eq!(next.member_start, 10256 + 8704 + 340 + 1692);
    assert_eq!(next.member_growth, 236 + ML_ADM_PEER_SLOTS as usize * 1096 + ML_ADM_TLS_LIVE_BYTES + ML_ADM_LWIP_BYTES + ML_ADM_OTHER_BYTES);
    assert!(next.required == next.member_steady + ML_ADM_NEG_PEAK_BYTES + 16384 + 2800 && next.router == 2800);
    assert!(ML_ADM_NEG_PEAK_BYTES == 13500 && 15964 - 2780 <= ML_ADM_NEG_PEAK_BYTES);
    // Decisions: budget first, then the contiguous block.
    assert_eq!(next.decide(next.required, 24000), Verdict::Ok);
    assert_eq!(next.decide(next.required - 1, 99999), Verdict::RefusedBudget);
    assert_eq!(next.decide(999_999, 23999), Verdict::RefusedLargest);
    // The old gate charged 108,200 B to every membership.
    assert!(first.required < 108_200 && next.required < first.required);

    // Peer-slot allocation guard.
    let floor = ML_ADM_TLS_BLOCK_FLOOR;
    assert!(slot_alloc_ok(24576, 24576 - 1096, floor));
    assert!(slot_alloc_ok(24576, 24576, floor));
    assert!(!slot_alloc_ok(floor + 100, floor + 100 - 1096, floor));
    assert!(!slot_alloc_ok(floor, floor - 1, floor));
    assert!(slot_alloc_ok(floor - 1, floor - 1096, floor));
    // Why the pool is not static in C: 12 slots against the two admission charges.
    let static_extra = (12 - ML_ADM_PEER_SLOTS as usize) * p.wg_slot;
    assert!(static_extra == 10 * 1096 && static_extra > 576);

    // The first membership's margin (ADR 0020).
    let (boot, boot_low) = (107_000i64, 102_000i64);
    // The old gate: the 16,000 B peak of then, four charged slots and two "typical" pending packets.
    let old_required_c = first.required + (16_000 - ML_ADM_NEG_PEAK_BYTES) + (4 - ML_ADM_PEER_SLOTS as usize) * 1096 + 2 * 1464;
    assert_eq!(old_required_c, 104_020);
    assert!(boot - old_required_c as i64 == 2980 && boot_low - (old_required_c as i64) < 0);
    let margin = boot - first.required as i64;
    let margin_low = boot_low - first.required as i64;
    assert!(margin >= 8000 && margin_low >= 3000);
    let statics = 1184;
    assert!(margin - statics >= 6900);

    // Elastic floors.
    assert!(elastic_floor(false) == 16384 && elastic_floor(true) == 16384 + 13500 && elastic_floor(true) == 29884);
    let slot = 1096;
    assert!(slot_heap_ok(0, 16384 + slot, slot) && !slot_heap_ok(0, 16384 + slot - 1, slot));
    assert!(slot_heap_ok(1, 16384 + slot, slot) && !slot_heap_ok(1, 16384 + slot - 1, slot));
    assert!(!slot_heap_ok(2, 16384 + slot, slot) && slot_heap_ok(2, 16384 + 13500 + slot, slot) && !slot_heap_ok(2, 16384 + 13500 + slot - 1, slot));
    // How many slots a first membership can hold beyond the guaranteed ones, at 107,000 and 102,000 B boot free.
    for boot_free in [boot, boot_low] {
        let mut free_heap = boot_free - (first.shared_runtime + first.member_steady) as i64;
        let (mut live, mut extra) = (ML_ADM_PEER_SLOTS, 0);
        while live < 12 && slot_heap_ok(live, free_heap.max(0) as usize, slot) {
            free_heap -= slot as i64;
            live += 1;
            extra += 1;
        }
        assert!(live >= 5, "boot {boot_free}: {extra} elastic");
    }
}

#[test]
fn admission_rust_preset_is_comparable() {
    // The Rust task model drops the per-member stack and TCB and the shared stacks; the arithmetic is the same.
    let c = Params::c_reference();
    let m = MemberSizes { control: 3000, peer_table: 1500, derp_link: 600, queues: 1692, wg_device: 236, misc: 200 };
    let r = Params::rust(&m, 700, &SharedSizes { executor_bytes: 6000 }, &Provisional::C_MEASURED);
    let (bc, br) = (c.budget(false), r.budget(false));
    assert_eq!(br.shared_runtime, 6000);
    assert_eq!(br.member_start, 3000 + 1500 + 600 + 200 + 1692);
    assert_eq!(br.member_growth, 236 + 2 * 700 + ML_ADM_TLS_LIVE_BYTES + ML_ADM_LWIP_BYTES + ML_ADM_OTHER_BYTES);
    assert_eq!(br.required, br.shared_runtime + br.member_steady + 13_500 + 16_384 + 2800);
    assert!(br.required < bc.required, "fewer fixed costs than the C: {} < {}", br.required, bc.required);
    // Same decision rule.
    assert_eq!(br.decide(br.required, 24_000), Verdict::Ok);
    assert_eq!(br.decide(br.required - 1, 24_000), Verdict::RefusedBudget);
    assert_eq!(r.budget(true).required, br.required - 6000);
}

#[test]
fn admission_matches_wifi_budget_crate_constants() {
    use tdongle_wifi_budget::heap_budget as w;
    assert_eq!(ML_HB_FLOOR, w::ML_HB_FLOOR);
    assert_eq!(ML_HB_RESERVE, w::ML_HB_RESERVE);
    assert_eq!(ML_HB_PIN_BUF_BYTES, w::ML_HB_PIN_BUF_BYTES);
    assert_eq!(ML_HB_SLACK_BYTES, w::ML_HB_SLACK_BYTES);
    assert_eq!(ML_HB_PIN_BUFFERS, w::ML_HB_PIN_BUFFERS);
    assert_eq!(ML_HB_PIN_BYTES, w::ML_HB_PIN_BYTES);
    assert_eq!(ML_HB_RX_SMALL_BYTES, w::ML_HB_RX_SMALL_BYTES);
    for free in [0usize, 29_000, 29_884, 31_000, 40_000] {
        for cost in [0usize, 16, 1500, 3000] {
            assert_eq!(hb_ok(free, cost), w::hb_ok(free, cost));
            for empty in [false, true] {
                assert_eq!(hb_rx_ok(free, cost, empty), w::hb_rx_ok(free, cost, empty));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_heap_budget.c: every elastic consumer under an adversarial schedule
// ---------------------------------------------------------------------------------------------------------------------------------

const CHUNK_BYTES: i64 = 3048;
const MAX_HELD: usize = 64;

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u32) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        ((self.0 >> 11) % u64::from(n)) as u32
    }
}

#[derive(Clone, Copy)]
struct Model {
    legacy: bool,
    pins: u32,
    pin_cost: i64,
    upload: bool,
    wgq_floor: i64,
    other_floor: i64,
    ring_floor: i64,
    usb_floor: i64,
}

struct Sim {
    free: i64,
    min_free: i64,
    pinned: u32,
    wgq: Vec<u32>,
    ring_chunks: u32,
    usb: usb_rx::Budget,
    usb_len: Vec<u32>,
    legacy_usb_inflight: u32,
    jit_n: u32,
    derp_n: u32,
    driver_fail: u64,
    refused: [u64; 6],
    wb: wg_rx::Budget,
    legacy_wb: u32,
}

impl Sim {
    fn take(&mut self, n: i64) {
        self.free -= n;
        self.min_free = self.min_free.min(self.free);
    }
    fn wgq_check(&mut self, m: &Model, len: u32) -> bool {
        if m.legacy {
            return self.free as usize >= (m.wgq_floor as usize) + len as usize + ML_WG_RX_OVERHEAD as usize
                && self.legacy_wb + len + ML_WG_RX_OVERHEAD <= ML_WG_RX_QUEUE_BYTES;
        }
        self.wb.admit(len as usize, self.free as usize) == wg_rx::Verdict::Ok
    }
    fn wgq_commit(&mut self, m: &Model, len: u32) {
        if m.legacy {
            self.legacy_wb += len + ML_WG_RX_OVERHEAD;
        }
        self.wgq.push(len);
        self.take(i64::from(len + ML_WG_RX_OVERHEAD));
    }
    fn ring_check(&self, m: &Model) -> bool {
        let chunk = (CHUNK_BYTES + 16) as usize;
        if m.legacy { self.free as usize >= chunk + m.ring_floor as usize } else { hb_ok(self.free as usize, chunk) }
    }

    fn step(&mut self, m: &Model, rs: &mut Rng) {
        let a = rs.next(100);
        if a < 22 {
            // a burst arrives: sockets pin Wi-Fi buffers, nothing checks the heap
            let k = 1 + rs.next(m.pins);
            let mut i = 0;
            while i < k && self.pinned < m.pins {
                if self.free < m.pin_cost {
                    self.driver_fail += 1;
                    break;
                }
                self.pinned += 1;
                self.take(m.pin_cost);
                i += 1;
            }
        } else if a < 52 {
            // net_io drains the mailbox: copy into the WireGuard queue, or drop; either frees the pin
            while self.pinned > 0 {
                let len = if rs.next(4) != 0 { 1264 } else { 60 + rs.next(300) };
                let race = rs.next(4) == 0 && self.pinned >= 1;
                if race {
                    let ok1 = self.wgq.len() + 2 <= MAX_HELD && self.wgq_check(m, len);
                    let ok2 = ok1 && self.wgq_check(m, len);
                    if ok1 {
                        self.pinned -= 1;
                        self.free += m.pin_cost;
                        self.wgq_commit(m, len);
                    }
                    if ok2 {
                        self.wgq_commit(m, len);
                    }
                    if !ok1 {
                        self.pinned -= 1;
                        self.free += m.pin_cost;
                        self.refused[0] += 1;
                    }
                } else if self.wgq.len() < MAX_HELD && self.wgq_check(m, len) {
                    self.pinned -= 1;
                    self.free += m.pin_cost;
                    self.wgq_commit(m, len);
                } else {
                    self.pinned -= 1;
                    self.free += m.pin_cost;
                    self.refused[0] += 1;
                }
                if rs.next(3) == 0 {
                    break;
                }
            }
        } else if a < 64 {
            // wg_mgr pops a run of up to 8
            let mut k = 1 + rs.next(8);
            while k > 0 && !self.wgq.is_empty() {
                k -= 1;
                let len = self.wgq.pop().unwrap_or(0);
                if m.legacy {
                    self.legacy_wb -= len + ML_WG_RX_OVERHEAD;
                } else {
                    self.wb.release(len as usize);
                }
                self.free += i64::from(len + ML_WG_RX_OVERHEAD);
            }
        } else if a < 72 {
            if self.ring_check(m) && self.ring_chunks < 10 {
                self.ring_chunks += 1;
                self.take(CHUNK_BYTES + 16);
            } else if self.ring_chunks > 0 && rs.next(3) == 0 {
                self.ring_chunks -= 1;
                self.free += CHUNK_BYTES + 16;
            }
        } else if a < 84 {
            let len = 60 + rs.next(1458);
            if !m.upload {
            } else if m.legacy {
                if self.legacy_usb_inflight < GATEWAY_USB_RX_INFLIGHT_MAX
                    && (m.usb_floor == 0 || self.free as usize >= m.usb_floor as usize + len as usize + 16)
                {
                    self.usb_len.push(len);
                    self.legacy_usb_inflight += 1;
                    self.take(i64::from(len + 16));
                } else {
                    self.refused[1] += 1;
                }
            } else if self.usb.admit(len, self.free as usize) == Admit::Admitted {
                self.usb_len.push(len);
                self.take(i64::from(len + 16));
            } else {
                self.refused[1] += 1;
            }
        } else if a < 92 {
            let mut k = 1 + rs.next(4);
            while k > 0 && !self.usb_len.is_empty() {
                k -= 1;
                let len = self.usb_len.pop().unwrap_or(0);
                if m.legacy {
                    self.legacy_usb_inflight -= 1;
                } else {
                    self.usb.release();
                }
                self.free += i64::from(len + 16);
            }
        } else if a < 96 {
            let cost = 1464 + 16;
            let floor = if m.legacy { m.other_floor as usize } else { ML_HB_FLOOR };
            if self.free as usize >= floor + cost && self.jit_n < 4 {
                self.jit_n += 1;
                self.take(cost as i64);
            } else {
                self.refused[2] += 1;
            }
            if self.free as usize >= floor + cost && self.derp_n < 8 {
                self.derp_n += 1;
                self.take(cost as i64);
            } else {
                self.refused[3] += 1;
            }
        } else {
            while self.jit_n > 0 && rs.next(2) != 0 {
                self.jit_n -= 1;
                self.free += 1480;
            }
            while self.derp_n > 0 && rs.next(2) != 0 {
                self.derp_n -= 1;
                self.free += 1480;
            }
        }
    }
}

fn run(m: &Model, f0: i64, steps: u64, rs: &mut Rng) -> (i64, u64) {
    let mut s = Sim {
        free: f0,
        min_free: f0,
        pinned: 0,
        wgq: Vec::new(),
        ring_chunks: 0,
        usb: usb_rx::Budget::new(),
        usb_len: Vec::new(),
        legacy_usb_inflight: 0,
        jit_n: 0,
        derp_n: 0,
        driver_fail: 0,
        refused: [0; 6],
        wb: wg_rx::Budget::new(),
        legacy_wb: 0,
    };
    for _ in 0..steps {
        s.step(m, rs);
        assert!(s.free <= f0 + 1);
    }
    (s.min_free, s.driver_fail)
}

fn seeded(seed: u64) -> Rng {
    Rng(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(seed))
}

#[test]
fn heap_budget_adversarial_schedule() {
    assert_eq!(ML_HB_PIN_BUFFERS, 6);
    assert!(ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR);
    assert!(ROUTE_HEAP_RESERVE == ML_HB_FLOOR && wg_rx::ML_WG_RX_FLOOR_FREE == ML_HB_FLOOR);
    assert!(rt_queue_budget(ML_HB_FLOOR + 5000) == 5000 && rt_queue_budget(ML_HB_FLOOR) == tdongle_tailnet_admission::adm::ROUTE_QUEUE_BYTES_MIN);

    let now = Model {
        legacy: false,
        pins: ML_HB_PIN_BUFFERS,
        pin_cost: ML_HB_PIN_BUF_BYTES as i64,
        upload: true,
        wgq_floor: 0,
        other_floor: 0,
        ring_floor: 0,
        usb_floor: 0,
    };
    let before = Model {
        legacy: true,
        pins: 10,
        pin_cost: ML_HB_PIN_BUF_BYTES as i64,
        upload: true,
        wgq_floor: 16384,
        other_floor: 16384,
        ring_floor: 32384,
        usb_floor: 0,
    };
    // The board's case first: a download flood (no upload), 37 KB free.
    let (mut worst_now, mut worst_before) = (i64::MAX, i64::MAX);
    for seed in 1..=6 {
        let d_now = Model { upload: false, ..now };
        let d_before = Model { upload: false, ..before };
        worst_now = worst_now.min(run(&d_now, 37_000, 400_000, &mut seeded(seed)).0);
        worst_before = worst_before.min(run(&d_before, 37_000, 400_000, &mut seeded(seed)).0);
    }
    assert!(worst_now >= ML_HB_RESERVE as i64);
    assert!(worst_before < 6000 && worst_before > -4000, "board saw 3,040-3,140 B; model {worst_before}");

    let (mut worst_now, mut worst_before) = (i64::MAX, i64::MAX);
    let mut f0 = 34_000;
    while f0 <= 44_000 {
        for seed in 1..=6 {
            let a = run(&now, f0, 400_000, &mut seeded(seed)).0;
            worst_now = worst_now.min(a);
            assert!(a >= ML_HB_RESERVE as i64, "THE BOUND: never below the recovery reserve (f0 {f0} seed {seed}: {a})");
            let b = run(&before, f0, 400_000, &mut seeded(seed)).0;
            worst_before = worst_before.min(b);
        }
        f0 += 1000;
    }
    assert!(worst_before < ML_HB_RESERVE as i64 - 8000, "the old constants break the reserve by a wide margin: {worst_before}");
}

#[test]
fn heap_budget_receive_copies_racing_checkers_and_mutant() {
    // ADR 0022 amendment 2: the receive-side copies.
    assert!(hb_rx_ok(0, 150, true) && hb_rx_ok(0, ML_HB_RX_SMALL_BYTES, true));
    assert!(!hb_rx_ok(0, ML_HB_RX_SMALL_BYTES + 1, true) && !hb_rx_ok(0, 150, false));
    assert!(hb_rx_ok(ML_HB_FLOOR + 1400 + 16, 1400, false) && !hb_rx_ok(ML_HB_FLOOR + 1400 + 15, 1400, false));
    assert!(hb_rx_ok(ML_HB_FLOOR + 1400 + 16, 1400, true) && !hb_rx_ok(ML_HB_FLOOR + 1400 + 15, 1400, true));
    let per_membership = 3 * (ML_HB_RX_SMALL_BYTES + 16);
    assert!(per_membership == 1584 && per_membership < ML_HB_PIN_BUF_BYTES);

    // The racing-checker slack, by arithmetic.
    let (c_ring, c_frame) = ((CHUNK_BYTES + 16) as usize, 1518usize + 16);
    let f = ML_HB_FLOOR + c_ring;
    assert!(hb_ok(f, c_ring) && hb_ok(f, c_frame));
    let after = f - c_ring - c_frame;
    assert!(after == ML_HB_FLOOR - c_frame && ML_HB_FLOOR - after <= ML_HB_SLACK_BYTES);
    assert!(after - ML_HB_PIN_BYTES >= ML_HB_RESERVE);

    // How far the slack goes: three concurrent checkers are the design point, a fourth is quantified.
    let (pins, floor, reserve) = (ML_HB_PIN_BYTES as i64, ML_HB_FLOOR as i64, ML_HB_RESERVE as i64);
    let cf = c_frame as i64;
    let three = floor - 2 * cf - pins;
    assert!(2 * c_frame <= ML_HB_SLACK_BYTES && three >= reserve);
    let four = floor - 3 * cf - pins;
    assert!(four < reserve && four >= reserve - 1500 && four > 14_000);
    let stacked = floor - 2 * cf - 2 * cf - pins;
    assert!(stacked < reserve && stacked >= reserve - 3000);

    // A floor that leaves out the pinned buffers must break the reserve.
    let wgq_floor = (ML_HB_RESERVE + ML_HB_SLACK_BYTES) as i64;
    let m = Model {
        legacy: true,
        pins: ML_HB_PIN_BUFFERS,
        pin_cost: ML_HB_PIN_BUF_BYTES as i64,
        upload: true,
        wgq_floor,
        other_floor: wgq_floor,
        ring_floor: wgq_floor,
        usb_floor: wgq_floor,
    };
    let mut worst = i64::MAX;
    for seed in 1..=12 {
        worst = worst.min(run(&m, 37_000, 600_000, &mut seeded(seed)).0);
    }
    assert!(worst < ML_HB_RESERVE as i64, "mutant (floor without the pinned buffers) must fail: {worst}");
}

#[test]
fn heap_budget_sdkconfig_limits_are_live() {
    // tools/test-heap-budget.py: UDP mailbox and TCP window within the largest burst; one past it is rejected.
    assert!(limits::CONFIG_LWIP_UDP_RECVMBOX_SIZE <= ML_HB_PIN_BUFFERS);
    assert!(tcp_window::SDKCONFIG.window_segments() <= ML_HB_PIN_BUFFERS);
    let over = tcp_window::Params { tcp_wnd: (ML_HB_PIN_BUFFERS + 1) * 1440, recvmbox: ML_HB_PIN_BUFFERS + 3, wifi_dynamic_rx: 32, ..tcp_window::SDKCONFIG };
    assert!(over.violates(Violation::PinsMoreThanHeapBudget));
    let at = tcp_window::Params { tcp_wnd: ML_HB_PIN_BUFFERS * 1440, recvmbox: ML_HB_PIN_BUFFERS + 2, wifi_dynamic_rx: 32, ..tcp_window::SDKCONFIG };
    assert_eq!(at.violations(), 0);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_negotiation.c, test_coord_token.c
// ---------------------------------------------------------------------------------------------------------------------------------

fn k(v: u32) -> Key {
    Key::from_raw(v).unwrap()
}

#[test]
fn neg_basics() {
    let mut n = Negotiation::new(0, 0, 0);
    let t = 1000;
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted);
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted); // idempotent
    assert!(n.holds(k(1)) && !n.holds(k(2)));
    assert_eq!(n.request(t, k(2), Prio::Start, Phase::Control), Grant::Queued);
    assert!(!n.release(t, k(99))); // not the holder, not queued: harmless
    assert!(n.release(t, k(1)));
    assert!(!n.release(t, k(1))); // error paths may release twice
    assert_eq!(n.request(t, k(2), Prio::Start, Phase::Control), Grant::Granted);
    let s = n.status(t);
    assert!(s.holder == 2 && s.phase == Phase::Control && s.waiting == 0 && s.grants == 2);
}

#[test]
fn neg_key_rule() {
    assert_eq!(Key::new(1, Phase::Control), Key::new(1, Phase::Start));
    assert_ne!(Key::new(1, Phase::Derp), Key::new(1, Phase::Control));
    assert_eq!(Key::new(0, Phase::Start).raw(), 3);
    assert_eq!(Key::new(0, Phase::Derp).raw(), 2);
    for id in 0..1000 {
        assert_ne!(Key::new(id, Phase::Derp).raw(), 0);
    }
}

#[test]
fn neg_ordering_priority_then_fifo() {
    let mut n = Negotiation::new(0, 0, 0);
    let mut t = 1000;
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted);
    // Queue (in this order): start(2), start(3), relay(4), rejoin(5).
    let _ = n.request(t, k(2), Prio::Start, Phase::Start);
    t += 5;
    let _ = n.request(t, k(3), Prio::Start, Phase::Start);
    t += 5;
    let _ = n.request(t, k(4), Prio::Relay, Phase::Derp);
    t += 5;
    let _ = n.request(t, k(5), Prio::Rejoin, Phase::Control);
    t += 5;
    let expect = [4u32, 5, 2, 3];
    let mut holder = 1;
    for want in expect {
        let _ = n.release(t, k(holder));
        for p in 2..=5 {
            // everyone polls; only the best is granted
            if n.request(t, k(p), Prio::Start, Phase::Start) == Grant::Granted {
                assert_eq!(p, want);
                holder = p;
            }
            t += 1;
        }
        assert!(n.holds(k(want)));
    }
}

#[test]
fn neg_aging_promotes_a_first_join() {
    let mut n = Negotiation::new(0, 0, 20_000);
    let mut t = 1000;
    let _ = n.request(t, k(1), Prio::Relay, Phase::Derp); // holder
    let _ = n.request(t, k(10), Prio::Start, Phase::Start); // the old join
    let (mut holder, mut join_ran) = (1u32, false);
    let mut round = 0;
    while round < 8 && !join_ran {
        for _ in 0..100 {
            t += 100;
            let _ = n.request(t, k(10), Prio::Start, Phase::Start);
            if round > 0 {
                let _ = n.request(t, k(20 + round - 1), Prio::Relay, Phase::Derp);
            }
        }
        let _ = n.release(t, k(holder));
        let _ = n.request(t, k(20 + round), Prio::Relay, Phase::Derp);
        let a = n.request(t, k(10), Prio::Start, Phase::Start);
        let b = n.request(t, k(20 + round), Prio::Relay, Phase::Derp);
        if a == Grant::Granted {
            join_ran = true;
            holder = 10;
        } else if b == Grant::Granted {
            holder = 20 + round;
        } else {
            panic!("someone must hold");
        }
        round += 1;
    }
    assert!(join_ran, "granted after waiting two aging periods (2 classes up)");
    let _ = n.release(t, k(holder));
}

#[test]
fn neg_self_healing() {
    let mut n = Negotiation::new(60_000, 2000, 20_000);
    let mut t = 1000;
    // A holder that never releases loses the token after the lease; its late release is a no-op.
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted);
    assert_eq!(n.request(t, k(2), Prio::Start, Phase::Start), Grant::Queued);
    t += 59_000;
    assert_eq!(n.request(t, k(2), Prio::Start, Phase::Start), Grant::Queued);
    t += 1100;
    assert_eq!(n.request(t, k(2), Prio::Start, Phase::Start), Grant::Granted);
    assert!(!n.release(t, k(1)));
    assert!(n.holds(k(2)));
    assert_eq!(n.status(t).lease_expired, 1);
    // A waiter that stops polling cannot block the ones behind it.
    assert_eq!(n.request(t, k(3), Prio::Relay, Phase::Derp), Grant::Queued); // ahead by priority
    t += 10;
    assert_eq!(n.request(t, k(4), Prio::Start, Phase::Start), Grant::Queued);
    let _ = n.release(t, k(2));
    t += 2500; // 3 never polls again
    assert_eq!(n.request(t, k(4), Prio::Start, Phase::Start), Grant::Granted);
    assert_eq!(n.status(t).stale_dropped, 1);
    let _ = n.release(t, k(4));
}

#[test]
fn neg_bounded_acquire_leaves_no_trace_and_full_queue_refuses() {
    let mut n = Negotiation::new(0, 0, 0);
    let mut t = 0;
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted);
    // acquire() times out, leaves no trace, and the failure is retryable.
    let mut a = Acquire::new(t, 150, k(2), Prio::Start, Phase::Start);
    let t0 = t;
    let outcome = loop {
        match a.poll(&mut n, t) {
            AcquirePoll::Pending { retry_at } => {
                assert!(retry_at > t && retry_at <= t0 + 150);
                t = retry_at;
            }
            other => break other,
        }
    };
    assert_eq!(outcome, AcquirePoll::Failed(AcquireFailure::TimedOut));
    assert_eq!(t - t0, 150, "gave up exactly at the deadline");
    let s = n.status(t);
    assert!(s.waiting == 0 && s.timeouts == 1);
    let _ = n.release(t, k(1));
    let mut again = Acquire::new(t, 150, k(2), Prio::Start, Phase::Start);
    assert_eq!(again.poll(&mut n, t), AcquirePoll::Granted, "retry succeeds at once");
    // A full queue refuses instead of growing.
    for key in 10..10 + ML_NEG_MAX_WAITERS as u32 {
        assert_eq!(n.request(t, k(key), Prio::Start, Phase::Start), Grant::Queued);
    }
    assert_eq!(n.request(t, k(99), Prio::Start, Phase::Start), Grant::Full);
    let mut full = Acquire::new(t, 50, k(98), Prio::Start, Phase::Start);
    assert_eq!(full.poll(&mut n, t), AcquirePoll::Failed(AcquireFailure::Full));
    let s = n.status(t);
    assert!(s.refused_full >= 2 && s.waiting as usize == ML_NEG_MAX_WAITERS);
}

#[derive(Default)]
struct Counting {
    calls: u32,
    busy_seen: u32,
    last: bool,
}
impl Observer for Counting {
    fn changed(&mut self, busy: bool) {
        self.calls += 1;
        self.busy_seen += u32::from(busy);
        self.last = busy;
    }
}

#[test]
fn neg_observation_one_callback_per_state_change() {
    let mut n = Negotiation::with_observer(0, 0, 0, Counting::default());
    let mut t = 1000;
    assert!(!n.busy());
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted);
    assert!(n.observer_mut().calls == 1 && n.observer_mut().busy_seen == 1 && n.busy());
    assert_eq!(n.request(t, k(1), Prio::Start, Phase::Start), Grant::Granted); // polling again: no change
    assert_eq!(n.request(t, k(2), Prio::Start, Phase::Start), Grant::Queued); // a waiter: no change
    assert_eq!(n.observer_mut().calls, 1);
    assert!(!n.release(t, k(99)) && n.observer_mut().calls == 1);
    assert!(n.release(t, k(1)) && n.observer_mut().calls == 2 && n.observer_mut().busy_seen == 1 && !n.busy());
    assert!(!n.release(t, k(1)) && n.observer_mut().calls == 2);
    // A lease expiry frees the token: observed too.
    assert!(n.request(t, k(2), Prio::Start, Phase::Start) == Grant::Granted && n.observer_mut().calls == 3);
    t += u64::from(ML_NEG_LEASE_MS) + 10;
    let _ = n.request(t, k(3), Prio::Start, Phase::Start); // reaps 2, grants 3: two changes
    assert!(n.holds(k(3)) && n.observer_mut().calls == 5 && n.busy());
    assert!(n.observer_mut().last, "the new state is what the observer is told");
    n.observer_mut().calls = 0; // the C's set_observer(NULL): the caller owns the observer
    let _ = n.release(t, k(3));
    assert!(!n.busy());
}

#[test]
fn neg_next_deadline_hint_is_sound() {
    let mut n = Negotiation::new(60_000, 2000, 20_000);
    assert_eq!(n.next_deadline(), None);
    let _ = n.request(100, k(1), Prio::Start, Phase::Start);
    assert_eq!(n.next_deadline(), Some(100 + 60_000 + 1));
    let _ = n.request(150, k(2), Prio::Start, Phase::Start);
    assert_eq!(n.next_deadline(), Some(150 + 2000 + 1));
}

#[test]
fn coord_token_rule() {
    let mut neg = Negotiation::new(0, 0, 0);
    let t = std::cell::Cell::new(0u64);
    let tick = || {
        t.set(t.get() + 3);
        t.get()
    };
    let me = Key::new(1, Phase::Control);
    let other = Key::new(2, Phase::Control);
    let mut holding = false;
    assert!(me == Key::new(1, Phase::Start) && Key::new(1, Phase::Derp) != me);
    // Every state, entered from every state, with the token free: negotiating states hold it, the rest do not.
    for from in CoordState::ALL {
        for to in CoordState::ALL {
            let _ = token_sync(&mut neg, tick(), me, from, Prio::Start, &mut holding);
            assert!(token_sync(&mut neg, tick(), me, to, Prio::Start, &mut holding));
            assert_eq!(neg.holds(me), to.negotiates());
            assert_eq!(holding, to.negotiates()); // engaged: holds or waits
            let _ = token_sync(&mut neg, tick(), me, CoordState::Idle, Prio::Start, &mut holding); // loop exit
            assert!(!neg.holds(me));
        }
    }
    // An error path that jumps straight from any negotiation state to RECONNECTING lets go at the next iteration.
    for s in [
        CoordState::StunProbe,
        CoordState::DnsResolve,
        CoordState::TcpConnect,
        CoordState::NoiseHandshake,
        CoordState::H2Preface,
        CoordState::Register,
        CoordState::FetchPeers,
    ] {
        assert!(token_sync(&mut neg, tick(), me, s, Prio::Start, &mut holding));
        assert!(neg.holds(me));
        assert!(token_sync(&mut neg, tick(), me, CoordState::Reconnecting, Prio::Rejoin, &mut holding) && !neg.holds(me));
    }
    // While another membership negotiates, work in a negotiating state must not run, and nothing is leaked.
    let mut other_hold = false;
    assert!(token_sync(&mut neg, tick(), other, CoordState::NoiseHandshake, Prio::Start, &mut other_hold));
    assert!(!token_sync(&mut neg, tick(), me, CoordState::StunProbe, Prio::Start, &mut holding) && holding && !neg.holds(me)); // waiting
    assert!(token_sync(&mut neg, tick(), me, CoordState::LongPoll, Prio::Start, &mut holding)); // steady state never waits
    let _ = token_sync(&mut neg, tick(), me, CoordState::Idle, Prio::Start, &mut holding); // leaves the queue too
    let _ = token_sync(&mut neg, tick(), other, CoordState::LongPoll, Prio::Start, &mut other_hold);
    let st = neg.status(t.get());
    assert!(st.holder == 0 && st.waiting == 0);
    // Hand-over from the gateway's start path: the task starts with the token already held under the same key.
    let mut handed = true;
    assert_eq!(neg.request(tick(), me, Prio::Start, Phase::Start), Grant::Granted);
    assert!(token_sync(&mut neg, tick(), me, CoordState::StunProbe, Prio::Start, &mut handed) && neg.holds(me));
    assert!(!token_sync(&mut neg, tick(), other, CoordState::StunProbe, Prio::Start, &mut other_hold)); // nobody slips in
    let _ = token_sync(&mut neg, tick(), me, CoordState::LongPoll, Prio::Start, &mut handed);
    let _ = token_sync(&mut neg, tick(), other, CoordState::LongPoll, Prio::Start, &mut other_hold);
    handed = true;
    assert_eq!(neg.request(tick(), me, Prio::Start, Phase::Start), Grant::Granted);
    assert!(token_sync(&mut neg, tick(), me, CoordState::Idle, Prio::Start, &mut handed) && !neg.holds(me));
    let st = neg.status(t.get());
    assert!(st.holder == 0 && st.waiting == 0);
    assert_eq!(CoordState::ALL.iter().filter(|s| s.negotiates()).count(), 7);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_socket_budget.c (the network-free part: admission arithmetic and the accounting)
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn socket_admission_and_accounting() {
    use sockets::{Accounting, Operation, admit};
    // Raising the descriptor total without reservation does not pass admission.
    assert!(!admit(10, 1, 7));
    assert!(admit(20, 0, 5));
    assert!(admit(20, 1, 9));
    assert!(!admit(20, 2, 13));
    assert!(admit(32, 3, 20));
    assert!(!admit(32, 4, 24));
    // Edge cases of the arithmetic the C leaves implicit.
    assert!(!admit(7, 0, 0) && !admit(20, 0, 21) && !admit(20, 0, 16) && admit(20, 0, 15) && !admit(20, 3, 0));
    // Accounting: baseline 5 (HTTP controls, DNS, SNTP), then two admitted memberships of four, pressure, failures at the limit.
    const EMFILE: u32 = 24;
    const ENFILE: u32 = 23;
    let mut a = Accounting::new(20);
    let mut live = 0u32;
    let mut alloc = |a: &mut Accounting, op: Operation, now: u32| {
        if live == 20 {
            a.allocated(op, Err(if op == Operation::Socket { EMFILE } else { ENFILE }), now);
            false
        } else {
            live += 1;
            a.allocated(op, Ok(()), now);
            true
        }
    };
    for _ in 0..5 {
        assert!(alloc(&mut a, Operation::Socket, 1000));
    }
    for active in 0..2 {
        assert!(admit(20, active, a.snapshot().open));
        for _ in 0..4 {
            assert!(alloc(&mut a, Operation::Socket, 1000));
        }
    }
    assert!(!admit(20, 2, a.snapshot().open));
    for _ in 0..4 {
        assert!(alloc(&mut a, Operation::Socket, 1000)); // DNS forward, two per-member transients, other HTTP client
    }
    for _ in 0..3 {
        assert!(alloc(&mut a, Operation::Socket, 1000));
    }
    assert!(!alloc(&mut a, Operation::Socket, 1000));
    let s = a.snapshot();
    assert!(s.open == 20 && s.peak == 20 && s.failures == 1 && s.last_errno == EMFILE && s.last_operation == 1 && s.last_at_ms == 1000);
    assert!(!alloc(&mut a, Operation::Accept, 2000));
    let s = a.snapshot();
    assert!(s.failures == 2 && s.last_operation == 2 && s.last_errno == ENFILE && s.last_at_ms == 2000);
    a.accept_would_block(); // readiness is not a failure
    assert_eq!(a.snapshot().failures, 2);
    for _ in 0..20 {
        a.closed();
    }
    a.closed(); // a close past zero does not wrap
    assert_eq!(a.snapshot().open, 0);
    assert_eq!(a.snapshot().peak, 20);
    // The peak never exceeds the descriptor total even if the wrapper over-counts.
    let mut b = Accounting::new(4);
    for _ in 0..9 {
        b.allocated(Operation::Socket, Ok(()), 0);
    }
    assert_eq!(b.snapshot().peak, 4);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_usb_rx_budget.c
// ---------------------------------------------------------------------------------------------------------------------------------

const BIG: usize = 1 << 20;

#[test]
fn usb_rx_cap_and_accounting() {
    let b = usb_rx::Budget::new();
    let mut admitted = 0;
    for _ in 0..100 {
        admitted += u32::from(b.admit(1514, BIG) == Admit::Admitted);
    }
    assert_eq!(admitted, GATEWAY_USB_RX_INFLIGHT_MAX);
    assert_eq!(b.inflight(), GATEWAY_USB_RX_INFLIGHT_MAX);
    assert_eq!(b.dropped_busy(), 100 - GATEWAY_USB_RX_INFLIGHT_MAX);
    assert_eq!(b.high_water(), GATEWAY_USB_RX_INFLIGHT_MAX);
    // lwIP frees one: exactly one more is admitted.
    b.release();
    assert!(b.admit(60, BIG) == Admit::Admitted && b.admit(60, BIG) == Admit::Busy);
    for _ in 0..GATEWAY_USB_RX_INFLIGHT_MAX {
        b.release();
    }
    assert_eq!(b.inflight(), 0);
    b.release(); // a spurious release does not wrap
    assert_eq!(b.inflight(), 0);
}

#[test]
fn usb_rx_heap_floor() {
    let h = usb_rx::Budget::new();
    let (len, cost) = (1514u32, 1514 + 16);
    let at = ML_HB_FLOOR + cost;
    for _ in 0..GATEWAY_USB_RX_HEAP_EXEMPT {
        assert_eq!(h.admit(len, 0), Admit::Admitted); // heap 0: still admitted
    }
    assert_eq!(h.dropped_heap(), 0);
    assert!(h.admit(len, at - 1) == Admit::Heap && h.dropped_heap() == 1);
    assert_eq!(h.inflight(), GATEWAY_USB_RX_HEAP_EXEMPT); // the refused frame took no slot
    assert!(h.admit(len, at) == Admit::Admitted && h.inflight() == GATEWAY_USB_RX_HEAP_EXEMPT + 1);
    assert_eq!(h.admit(60, ML_HB_FLOOR + 60 + 16), Admit::Admitted);
    assert!(h.admit(60, ML_HB_FLOOR + 60 + 15) == Admit::Heap && h.dropped_heap() == 2);
    // The exemption is about frames in flight, not a free pass.
    while h.inflight() > 0 {
        h.release();
    }
    assert!(h.admit(len, 0) == Admit::Admitted && h.admit(len, 0) == Admit::Admitted && h.admit(len, 0) == Admit::Heap);
    assert!(GATEWAY_USB_RX_HEAP_EXEMPT as usize * cost <= ML_HB_SLACK_BYTES);
    // Priority of refusals: the in-flight cap is checked first and counted as busy, not heap.
    let c = usb_rx::Budget::new();
    for _ in 0..GATEWAY_USB_RX_INFLIGHT_MAX {
        assert_eq!(c.admit(100, BIG), Admit::Admitted);
    }
    assert!(c.admit(100, 0) == Admit::Busy && c.dropped_busy() == 1 && c.dropped_heap() == 0);
}

#[test]
fn usb_rx_invalid_lengths_take_no_slot() {
    let b = usb_rx::Budget::new();
    for bad in [0, 13, 1519, 65_535] {
        assert_eq!(b.admit(bad, BIG), Admit::Invalid);
    }
    assert!(b.dropped_invalid() == 4 && b.inflight() == 0);
    assert!(b.admit(14, BIG) == Admit::Admitted && b.admit(1518, BIG) == Admit::Admitted);
    b.release();
    b.release();
    assert_eq!(b.admit(100, BIG), Admit::Admitted);
    b.note_nomem();
    assert_eq!((b.dropped_nomem(), b.inflight()), (1, 0));
}

#[test]
fn usb_rx_concurrent_producer_consumer() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    let b = Arc::new(usb_rx::Budget::new());
    let head = Arc::new(AtomicU32::new(0));
    let tail = Arc::new(AtomicU32::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let freed = Arc::new(AtomicU32::new(0));
    let c = {
        let (b, head, tail, done, freed) = (b.clone(), head.clone(), tail.clone(), done.clone(), freed.clone());
        std::thread::spawn(move || {
            loop {
                let (t, h) = (tail.load(Ordering::Acquire), head.load(Ordering::Acquire));
                if t == h {
                    if done.load(Ordering::Acquire) && head.load(Ordering::Acquire) == t {
                        return;
                    }
                    std::thread::yield_now();
                    continue;
                }
                freed.fetch_add(1, Ordering::Relaxed);
                tail.store(t + 1, Ordering::Release);
                b.release();
            }
        })
    };
    let (mut admitted, mut refused) = (0u32, 0u32);
    for i in 0..100_000u32 {
        if b.admit(100 + i % 1400, BIG) != Admit::Admitted {
            refused += 1;
            continue;
        }
        assert!(b.inflight() <= GATEWAY_USB_RX_INFLIGHT_MAX);
        head.fetch_add(1, Ordering::Release);
        admitted += 1;
    }
    done.store(true, Ordering::Release);
    c.join().unwrap();
    assert!(freed.load(Ordering::Relaxed) == admitted && b.inflight() == 0);
    assert!(b.dropped_busy() >= refused && b.high_water() <= GATEWAY_USB_RX_INFLIGHT_MAX);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_net_io_drain.c
// ---------------------------------------------------------------------------------------------------------------------------------

struct Script {
    result: Vec<i32>, // >= 0 length, -1 empty, -2 error
    at: usize,
}
impl net_io::Source for Script {
    fn recv(&mut self, buf: &mut [u8]) -> Recv {
        let Some(&r) = self.result.get(self.at) else { return Recv::Empty };
        let i = self.at as u32;
        self.at += 1;
        match r {
            -2 => Recv::Error,
            -1 => Recv::Empty,
            n => {
                let n = n as usize;
                let cap = buf.len();
                buf[..n.min(cap)].fill(i as u8);
                Recv::Datagram { len: n, src_ip: 0x0a00_0001 + i, src_port: (1000 + i) as u16 }
            }
        }
    }
}
#[derive(Default)]
struct Collect {
    lens: Vec<usize>,
    ips: Vec<u32>,
}
impl net_io::Sink for Collect {
    fn datagram(&mut self, data: &[u8], ip: u32, _port: u16) {
        self.lens.push(data.len());
        self.ips.push(ip);
    }
}

#[test]
fn net_io_drain_counters_cap_errors_empty() {
    let mut buf = [0u8; 2048];
    {
        let st = RxStats::new();
        let mut s = Script { result: Vec::new(), at: 0 };
        let mut c = Collect::default();
        assert_eq!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16), 0);
        assert_eq!((st.get(RxStat::UdpRx), st.get(RxStat::DrainCalls), st.get(RxStat::DrainCapped), st.get(RxStat::UdpRecvErr)), (0, 1, 0, 0));
    }
    {
        // three datagrams, one empty: all counted, the empty one discarded, the others sunk in order
        let st = RxStats::new();
        let mut s = Script { result: std::vec![100, 0, 1400], at: 0 };
        let mut c = Collect::default();
        assert_eq!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16), 3);
        assert_eq!((st.get(RxStat::UdpRx), st.get(RxStat::UdpRxEmpty)), (3, 1));
        assert!(c.lens == [100, 1400] && c.ips[0] < c.ips[1]);
        assert_eq!((st.drain_burst_max(), st.get(RxStat::DrainCapped), st.get(RxStat::DrainDeep)), (3, 0, 0));
    }
    // "deep" = the mailbox was nearly full
    for depth in 0..=16usize {
        let st = RxStats::new();
        let mut s = Script { result: std::vec![20; depth], at: 0 };
        let mut c = Collect::default();
        assert_eq!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16), depth as u32);
        assert_eq!(st.get(RxStat::DrainDeep), u32::from(depth as u32 >= limits::ML_NET_IO_DEEP));
    }
    {
        // a receive error stops the drain without counting a datagram, and is counted
        let st = RxStats::new();
        let mut s = Script { result: std::vec![50, -2, 60], at: 0 };
        let mut c = Collect::default();
        assert_eq!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16), 1);
        assert_eq!((st.get(RxStat::UdpRx), st.get(RxStat::UdpRecvErr), c.lens.len()), (1, 1, 1));
        assert_eq!(s.at, 2); // the third was left for the next pass
    }
    {
        // the cap: reads exactly `max`, reports it, and leaves the rest
        let st = RxStats::new();
        let mut s = Script { result: (0..40).map(|i| 10 + i).collect(), at: 0 };
        let mut c = Collect::default();
        assert!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16) == 16 && s.at == 16 && c.lens.len() == 16);
        assert_eq!((st.get(RxStat::DrainCapped), st.drain_burst_max()), (1, 16));
        for i in 0..16 {
            assert_eq!(c.lens[i], 10 + i); // order preserved
        }
        assert!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16) == 16 && s.at == 32);
        assert!(net_io::drain(&mut s, &mut c, &st, &mut buf, 16) == 8 && s.at == 40);
        assert_eq!((st.get(RxStat::DrainCapped), st.get(RxStat::DrainDeep), st.get(RxStat::UdpRx), st.get(RxStat::DrainCalls)), (2, 3, 40, 3));
        assert_eq!(c.lens.len(), 40);
    }
}

struct Mbox {
    q: std::collections::VecDeque<u32>,
    size: usize,
    dropped: u32,
}
impl Mbox {
    fn post(&mut self, id: u32) {
        if self.q.len() == self.size {
            self.dropped += 1; // lwIP frees the datagram and counts NOTHING
        } else {
            self.q.push_back(id);
        }
    }
}
impl net_io::Source for Mbox {
    fn recv(&mut self, buf: &mut [u8]) -> Recv {
        match self.q.pop_front() {
            None => Recv::Empty,
            Some(id) => {
                buf[..4].copy_from_slice(&id.to_le_bytes());
                Recv::Datagram { len: 4, src_ip: 0, src_port: 0 }
            }
        }
    }
}
#[derive(Default)]
struct Ids(Vec<u32>);
impl net_io::Sink for Ids {
    fn datagram(&mut self, d: &[u8], _: u32, _: u16) {
        self.0.push(u32::from_le_bytes([d[0], d[1], d[2], d[3]]));
    }
}

#[test]
fn net_io_drain_removes_silent_mailbox_loss() {
    // (mailbox size, max burst, old-loop passes, new loop)
    let cfg: [(usize, u32, u32, bool); 8] =
        [(6, 6, 2, false), (6, 6, 3, false), (6, 6, 4, false), (6, 6, 6, false), (6, 6, 1, true), (6, 10, 1, true), (10, 10, 1, true), (10, 16, 1, true)];
    for (mbox_size, max_burst, passes, new_loop) in cfg {
        let mut rs = 99u64;
        let mut rnd = |n: u32| {
            rs = rs.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            ((rs >> 33) as u32) % n
        };
        let mut m = Mbox { q: Default::default(), size: mbox_size, dropped: 0 };
        let mut ids = Ids::default();
        let st = RxStats::new();
        let mut buf = [0u8; 8];
        let mut id = 0u32;
        for _ in 0..4000 {
            for _ in 0..1 + rnd(max_burst) {
                m.post(id);
                id += 1;
            }
            if new_loop {
                net_io::drain(&mut m, &mut ids, &st, &mut buf, limits::ML_NET_IO_DRAIN_CAP);
            } else {
                for _ in 0..passes {
                    // the old loop: ONE datagram per pass, however many wait
                    net_io::drain(&mut m, &mut ids, &st, &mut buf, 1);
                }
            }
        }
        while !m.q.is_empty() {
            net_io::drain(&mut m, &mut ids, &st, &mut buf, limits::ML_NET_IO_DRAIN_CAP);
        }
        assert_eq!(ids.0.len() as u32 + m.dropped, id, "every datagram is delivered or silently dropped");
        assert!(ids.0.windows(2).all(|w| w[0] < w[1]), "nothing is ever delivered out of order");
        if !new_loop && passes < max_burst {
            assert!(m.dropped > 0, "fewer passes than the longest burst: it overflows");
        }
        if new_loop && max_burst as usize <= mbox_size {
            assert_eq!(m.dropped, 0, "the new loop loses nothing a mailbox can hold");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_rx_stats_threads.c (single-threaded semantics + a threaded sum check)
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn rx_stats_names_reset_and_threads() {
    use std::sync::Arc;
    let st = Arc::new(RxStats::new());
    assert_eq!(RxStat::ALL.len(), RX_STAT_COUNT);
    assert_eq!(RxStat::ALL[0].name(), "udp_rx");
    assert_eq!(RxStat::ALL[RX_STAT_COUNT - 1].name(), "wg_to_wireguardif");
    for (i, s) in RxStat::ALL.iter().enumerate() {
        assert_eq!(*s as usize, i);
        assert!(!s.name().is_empty());
        assert_eq!(tdongle_tailnet_admission::rx_stats::name_of(i), s.name());
    }
    assert!(tdongle_tailnet_admission::rx_stats::name_of(RX_STAT_COUNT).is_empty() && st.get_index(RX_STAT_COUNT) == 0);
    let names: std::collections::HashSet<_> = RxStat::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(names.len(), RX_STAT_COUNT);
    const THREADS: u32 = 4;
    const ROUNDS: u32 = 50_000;
    let hs: Vec<_> = (0..THREADS)
        .map(|id| {
            let st = st.clone();
            std::thread::spawn(move || {
                for i in 0..ROUNDS {
                    st.add(RxStat::UdpRx, 1);
                    if (i + id) % 3 == 0 {
                        st.add(RxStat::QWgFull, 1);
                    }
                    st.burst((i * 7 + id) % 17);
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(st.get(RxStat::UdpRx), THREADS * ROUNDS);
    assert_eq!(st.drain_burst_max(), 16);
    let q: u32 = (0..THREADS).map(|id| (0..ROUNDS).filter(|i| (i + id) % 3 == 0).count() as u32).sum();
    assert_eq!(st.get(RxStat::QWgFull), q);
    st.reset();
    assert!(st.get(RxStat::UdpRx) == 0 && st.drain_burst_max() == 0);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_wg_rx_budget.c
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn wg_rx_budget_model() {
    let b = wg_rx::Budget::new();
    let mut rs = 12345u32;
    let mut rnd = move || {
        rs ^= rs << 13;
        rs ^= rs >> 17;
        rs ^= rs << 5;
        rs
    };
    let (mut model, mut admitted, mut bytes_refused, mut heap_refused) = (0u32, 0u32, 0u32, 0u32);
    let mut held: Vec<u32> = Vec::new();
    let big_heap = 1usize << 20;
    for _ in 0..400_000 {
        if !held.is_empty() && rnd() % 100 < 48 {
            let i = rnd() as usize % held.len();
            let len = held.swap_remove(i);
            b.release(len as usize);
            model -= len + ML_WG_RX_OVERHEAD;
        } else if held.len() < 256 {
            let len = if rnd() & 3 != 0 { 28 + rnd() % 1300 } else { 32 };
            let heap =
                if rnd() % 10 != 0 { big_heap } else { wg_rx::ML_WG_RX_FLOOR_FREE + len as usize + ML_WG_RX_OVERHEAD as usize - 1 + (rnd() % 3) as usize };
            let v = b.admit(len as usize, heap);
            let cost = len + ML_WG_RX_OVERHEAD;
            let want = if heap < wg_rx::ML_WG_RX_FLOOR_FREE + cost as usize {
                wg_rx::Verdict::Heap
            } else if model + cost > ML_WG_RX_QUEUE_BYTES {
                wg_rx::Verdict::Bytes
            } else {
                wg_rx::Verdict::Ok
            };
            assert_eq!(v, want);
            match v {
                wg_rx::Verdict::Ok => {
                    model += cost;
                    held.push(len);
                    admitted += 1;
                }
                wg_rx::Verdict::Bytes => bytes_refused += 1,
                wg_rx::Verdict::Heap => heap_refused += 1,
            }
        }
        assert!(b.queued() == model && model <= ML_WG_RX_QUEUE_BYTES);
    }
    assert!(b.peak() <= ML_WG_RX_QUEUE_BYTES && b.peak() > ML_WG_RX_QUEUE_BYTES - 1400);
    assert!(admitted > 0 && bytes_refused > 0 && heap_refused > 0);
    for len in held.drain(..) {
        b.release(len as usize);
    }
    assert_eq!(b.queued(), 0);
}

#[test]
fn wg_rx_one_floor_and_quoted_capacity() {
    let (len, cost) = (1264usize, 1264 + ML_WG_RX_OVERHEAD as usize);
    let b = wg_rx::Budget::new();
    assert_eq!(wg_rx::ML_WG_RX_FLOOR_FREE, ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES);
    assert_eq!(wg_rx::ML_WG_RX_FLOOR_FREE, 16384 + 13500);
    assert!(b.admit(len, wg_rx::ML_WG_RX_FLOOR_FREE + cost - 1) == wg_rx::Verdict::Heap && b.queued() == 0); // nothing reserved
    assert!(b.admit(len, wg_rx::ML_WG_RX_FLOOR_FREE + cost) == wg_rx::Verdict::Ok && b.queued() as usize == cost);
    // the old floor (recovery reserve only) no longer admits
    let b = wg_rx::Budget::new();
    assert_eq!(b.admit(len, ML_ADM_RECOVERY_BYTES + cost), wg_rx::Verdict::Heap);
    assert_eq!(b.admit(28, wg_rx::ML_WG_RX_FLOOR_FREE + 28 + ML_WG_RX_OVERHEAD as usize), wg_rx::Verdict::Ok);
    assert_eq!(b.queued(), 28 + ML_WG_RX_OVERHEAD);
    // the sizes the design quotes
    let b = wg_rx::Budget::new();
    let mut big = 0;
    while b.admit(1264, 1 << 20) == wg_rx::Verdict::Ok {
        big += 1;
    }
    assert_eq!(big, 9);
    let c = wg_rx::Budget::new();
    let mut small = 0;
    while small < 1000 && c.admit(96, 1 << 20) == wg_rx::Verdict::Ok {
        small += 1;
    }
    assert!(small > limits::ML_WG_RX_QUEUE_DEPTH, "bytes alone never bind for ACK-sized datagrams, the slot count does");
    // a double release saturates instead of wrapping
    let d = wg_rx::Budget::new();
    d.release(100);
    assert_eq!(d.queued(), 0);
}

#[test]
fn wg_rx_budget_threads() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    let tb = Arc::new(wg_rx::Budget::new());
    let over = Arc::new(AtomicU32::new(0));
    let (tx, rx) = std::sync::mpsc::channel::<u32>();
    let consumer = {
        let tb = tb.clone();
        std::thread::spawn(move || {
            while let Ok(len) = rx.recv() {
                tb.release(len as usize);
            }
        })
    };
    let producers: Vec<_> = (0..4u32)
        .map(|id| {
            let (tb, over, tx) = (tb.clone(), over.clone(), tx.clone());
            std::thread::spawn(move || {
                let mut seed = id.wrapping_mul(2_654_435_761).wrapping_add(1);
                for _ in 0..50_000 {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    let len = 28 + seed % 1300;
                    if tb.admit(len as usize, 1 << 20) == wg_rx::Verdict::Ok {
                        if tb.queued() > ML_WG_RX_QUEUE_BYTES {
                            over.fetch_add(1, Ordering::Relaxed);
                        }
                        tx.send(len).unwrap();
                    }
                }
            })
        })
        .collect();
    drop(tx);
    for p in producers {
        p.join().unwrap();
    }
    consumer.join().unwrap();
    assert_eq!(over.load(Ordering::Relaxed), 0);
    assert_eq!(tb.queued(), 0);
    assert!(tb.peak() <= ML_WG_RX_QUEUE_BYTES);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// test_wg_rx_batch.c: structure of one run (the lock sites)
// ---------------------------------------------------------------------------------------------------------------------------------

fn sites_of(is_data: &[bool]) -> (Vec<Site>, Vec<Run>, RunStats) {
    let mut st = RunStats::default();
    let (mut sites, mut runs) = (Vec::new(), Vec::new());
    wg_rx::plan_runs(is_data, &mut st, |r| {
        sites.extend_from_slice(r.sites());
        runs.push(r);
    });
    (sites, runs, st)
}

#[test]
fn wg_rx_runs_lock_structure() {
    use Site::*;
    // 8 data: exactly one run: begin, commit
    let (s, r, st) = sites_of(&[true; 8]);
    assert!(s == [Begin, Commit] && r == [Run::Data { start: 0, end: 8 }]);
    assert!(st.runs == 1 && st.runs_full == 1 && st.runs_cut == 0 && st.run_datagrams == 8);
    // 20 data: runs of 8, 8, 4
    let (s, r, st) = sites_of(&[true; 20]);
    assert_eq!(s, [Begin, Commit, Begin, Commit, Begin, Commit]);
    assert_eq!(r, [Run::Data { start: 0, end: 8 }, Run::Data { start: 8, end: 16 }, Run::Data { start: 16, end: 20 }]);
    assert!(st.runs == 3 && st.runs_full == 2 && st.runs_cut == 0);
    // data, data, handshake, data: [BEGIN COMMIT] [OTHER] [BEGIN COMMIT], in order
    let (s, r, st) = sites_of(&[true, true, false, true]);
    assert_eq!(s, [Begin, Commit, Other, Begin, Commit]);
    assert_eq!(r, [Run::Data { start: 0, end: 2 }, Run::Single { index: 2 }, Run::Data { start: 3, end: 4 }]);
    assert!(st.runs == 2 && st.runs_cut == 1 && st.runs_full == 0);
    // a single datagram and a lone non-data message
    assert_eq!(sites_of(&[true]).0, [Begin, Commit]);
    assert_eq!(sites_of(&[false]).0, [Other]);
    assert!(sites_of(&[]).0.is_empty());
    assert_eq!(ML_WG_RX_BATCH, 8);
}

#[test]
fn wg_rx_runs_cover_every_datagram_once_in_order() {
    let mut rs = 7u32;
    for _ in 0..2000 {
        rs = rs.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let n = (rs >> 16) as usize % 40;
        let pat: Vec<bool> = (0..n).map(|i| (rs.rotate_left(i as u32 % 31) & 3) != 0).collect();
        let (_, runs, st) = sites_of(&pat);
        let mut next = 0;
        let mut data_total = 0;
        for r in runs {
            match r {
                Run::Single { index } => {
                    assert!(!pat[index] && index == next);
                    next += 1;
                }
                Run::Data { start, end } => {
                    assert!(start == next && end > start && end - start <= ML_WG_RX_BATCH && pat[start..end].iter().all(|d| *d));
                    data_total += end - start;
                    next = end;
                }
            }
        }
        assert_eq!(next, n);
        assert_eq!(data_total as u32, st.run_datagrams);
        assert_eq!(data_total, pat.iter().filter(|d| **d).count());
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// tools/test-tcp-window.py
// ---------------------------------------------------------------------------------------------------------------------------------

#[test]
fn tcp_window_settings_and_each_assertion_is_live() {
    let base = tcp_window::SDKCONFIG;
    assert_eq!(base.violations(), 0);
    assert_eq!(base.window_segments(), 6);
    let refused: [(&str, tcp_window::Params, Violation); 6] = [
        ("window over 64 KB without scaling", tcp_window::Params { tcp_wnd: 70_000, ..base }, Violation::WindowOver64k),
        ("receive mailbox smaller than window/MSS + 2", tcp_window::Params { recvmbox: 6, ..base }, Violation::MailboxTooSmall),
        ("window can pin over half the Wi-Fi RX pool", tcp_window::Params { tcp_wnd: 17_280, recvmbox: 14, ..base }, Violation::PinsHalfTheRxPool),
        ("send buffer larger than the segment pool", tcp_window::Params { tcp_snd_buf: 40 * 1440, ..base }, Violation::SendBufferSegments),
        ("window below two segments", tcp_window::Params { tcp_wnd: 1440, ..base }, Violation::BelowTwoSegments),
        (
            "window pins more Wi-Fi buffers than the heap budget allows (ADR 0022)",
            tcp_window::Params { tcp_wnd: 7 * 1440, recvmbox: 9, wifi_dynamic_rx: 32, ..base },
            Violation::PinsMoreThanHeapBudget,
        ),
    ];
    for (name, p, v) in refused {
        assert!(p.violates(v), "{name}");
        assert_ne!(p.violations(), 0, "{name}");
    }
    // Window scaling would lift the 64 KB bound, so the check follows the option, not the value; the heap budget still refuses.
    let scaled = tcp_window::Params { tcp_wnd: 70_000, recvmbox: 60, wifi_dynamic_rx: 128, wnd_scale: true, ..base };
    assert!(!scaled.violates(Violation::WindowOver64k) && scaled.violates(Violation::PinsMoreThanHeapBudget));
    // The settings that the other budgets assert: UDP mailbox and drain cap.
    assert!(limits::ML_NET_IO_DRAIN_CAP >= limits::CONFIG_LWIP_UDP_RECVMBOX_SIZE);
    assert_eq!(limits::ML_GATEWAY_PLAIN_BYTES, 20_496);
    assert_eq!(limits::ML_GATEWAY_JSON_BYTES, 16_384);
}
