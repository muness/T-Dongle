//! Section 4 of the C test, the model: Wi-Fi buffers of both directions, the WireGuard queue, the USB ring, USB receive frames and pending
//! packets in one adversarial schedule, with racing checkers, through the real admission code of this crate (`admit`, `rx_admit`, `hb_ok`).
//!
//! The C test links the real `ml_wgrx_admit` (`ml_wg_rx_budget.h`) and `gateway_usb_rx_admit` (`usb_rx_budget.h`); those budgets belong to the
//! tailnet phase, so the two are ported here as small test models with the same arithmetic (see `WgRx` and `UsbRx`).

use std::prelude::v1::*;

use super::{Pins, Rs, pins};
use crate::ML_HB_FLOOR;
use crate::ML_HB_RESERVE;
use crate::heap_budget::{ML_HB_PIN_BUF_BYTES, hb_ok};
use crate::pins::wtx_cost;

/// The USB ring's chunk, plus the allocator header the C test charges (`CHUNK_BYTES`).
pub const CHUNK_BYTES: u32 = 3048;
pub const MAX_HELD: usize = 64;
/// `ML_WG_RX_OVERHEAD`: allocator header and rounding, charged per datagram.
pub const ML_WG_RX_OVERHEAD: u32 = 16;
/// `ML_WG_RX_QUEUE_BYTES`.
const ML_WG_RX_QUEUE_BYTES: u32 = 12_288;
/// `GATEWAY_USB_RX_INFLIGHT_MAX` and `GATEWAY_USB_RX_HEAP_EXEMPT`.
pub const USB_RX_INFLIGHT_MAX: usize = 22;
const USB_RX_HEAP_EXEMPT: u32 = 2;

/// `ml_wgrx_budget_t` with `ml_wgrx_admit` / `ml_wgrx_release_to`.
#[derive(Debug, Default)]
pub struct WgRx {
    bytes: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WgRxVerdict {
    Ok,
    Bytes,
    Heap,
}

impl WgRx {
    pub fn admit(&mut self, len: u32, free_internal: usize) -> WgRxVerdict {
        let cost = len + ML_WG_RX_OVERHEAD;
        if !hb_ok(free_internal, cost as usize) {
            return WgRxVerdict::Heap;
        }
        if self.bytes + cost > ML_WG_RX_QUEUE_BYTES {
            return WgRxVerdict::Bytes;
        }
        self.bytes += cost;
        WgRxVerdict::Ok
    }

    pub fn release_to(&mut self, len: u32) {
        self.bytes -= len + ML_WG_RX_OVERHEAD;
    }
}

/// `gateway_usb_rx_budget` with `gateway_usb_rx_admit` / `gateway_usb_rx_release`.
#[derive(Debug, Default)]
pub struct UsbRx {
    inflight: u32,
}

impl UsbRx {
    pub fn admit(&mut self, len: u32, free_internal: usize) -> bool {
        if !(14..=1518).contains(&len) {
            return false;
        }
        let now = self.inflight + 1;
        if now as usize > USB_RX_INFLIGHT_MAX {
            return false;
        }
        if now > USB_RX_HEAP_EXEMPT && !hb_ok(free_internal, len as usize + 16) {
            return false;
        }
        self.inflight = now;
        true
    }

    pub fn release(&mut self) {
        self.inflight -= 1;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Model {
    pub name: &'static str,
    /// 0: the driver's pool alone, 1: the budget (real code), 2 (RX): a mutant of it (`rx_band`, `pin_floor`).
    pub rx_mode: u32,
    pub tx_mode: u32,
    /// The driver's pools: what it can pin when nothing else stops it.
    pub rx_pool: usize,
    pub tx_pool: usize,
    /// Mutants only.
    pub rx_band: usize,
    /// Mutants only: the elastic pin floor; 0 = the real `ML_HB_FLOOR`.
    pub pin_floor: usize,
    pub upload: bool,
    pub download: bool,
}

impl Model {
    pub const fn blank(name: &'static str) -> Self {
        Self { name, rx_mode: 0, tx_mode: 0, rx_pool: 0, tx_pool: 0, rx_band: 0, pin_floor: 0, upload: false, download: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Wgq,
    Ring,
    Usb,
    Tx,
    Jit,
}

const KINDS: [Kind; 5] = [Kind::Wgq, Kind::Ring, Kind::Usb, Kind::Tx, Kind::Jit];

#[derive(Clone, Copy, Debug)]
struct Check {
    kind: Kind,
    ok: bool,
    len: u32,
}

pub struct Sim {
    pub free: i64,
    pub min_free: i64,
    pub pins: Pins,
    rx_cost: [u32; 64],
    pub rx_n: usize,
    tx_cost: [u32; 32],
    pub tx_n: usize,
    wgq: [u32; MAX_HELD],
    wgq_n: usize,
    ring_chunks: u32,
    usb: UsbRx,
    usb_len: [u32; USB_RX_INFLIGHT_MAX],
    usb_n: usize,
    jit_n: u32,
    derp_n: u32,
    pub rx_refused: u64,
    pub tx_refused: u64,
    wb: WgRx,
    now: u32,
    rs: Rs,
}

fn rx_cost_of(len: u32) -> u32 {
    (len + 130).min(ML_HB_PIN_BUF_BYTES as u32)
}

impl Sim {
    pub fn new(f0: i64, rs: Rs) -> Self {
        Self {
            free: f0,
            min_free: f0,
            pins: pins(),
            rx_cost: [0; 64],
            rx_n: 0,
            tx_cost: [0; 32],
            tx_n: 0,
            wgq: [0; MAX_HELD],
            wgq_n: 0,
            ring_chunks: 0,
            usb: UsbRx::default(),
            usb_len: [0; USB_RX_INFLIGHT_MAX],
            usb_n: 0,
            jit_n: 0,
            derp_n: 0,
            rx_refused: 0,
            tx_refused: 0,
            wb: WgRx::default(),
            now: 0,
            rs,
        }
    }

    fn take(&mut self, n: i64) {
        self.free -= n;
        if self.free < self.min_free {
            self.min_free = self.free;
        }
    }

    fn do_check(&mut self, m: &Model, kind: Kind, snapshot: usize) -> Check {
        // The C initialiser draws the length for every kind, in this order.
        let len = if kind == Kind::Wgq { if self.rs.rnd(4) != 0 { 1264 } else { 60 + self.rs.rnd(300) } } else { 60 + self.rs.rnd(1454) };
        let mut c = Check { kind, ok: false, len };
        match kind {
            Kind::Wgq => c.ok = self.wgq_n + 2 <= MAX_HELD && self.wb.admit(c.len, snapshot) == WgRxVerdict::Ok,
            Kind::Ring => c.ok = self.ring_chunks < 10 && hb_ok(snapshot, CHUNK_BYTES as usize + 16),
            Kind::Usb => c.ok = m.upload && self.usb_n < USB_RX_INFLIGHT_MAX && self.usb.admit(c.len, snapshot),
            Kind::Tx => {
                c.ok = false;
                if !m.upload {
                    return c;
                }
                c.ok = if m.tx_mode == 1 { self.pins.admit(c.len, snapshot, self.now).admitted() } else { self.tx_n < m.tx_pool };
                if c.ok && self.tx_n >= 16 {
                    self.pins.abort(); // the driver refuses: abort
                    c.ok = false;
                }
                if !c.ok {
                    self.tx_refused += 1;
                }
            }
            Kind::Jit => c.ok = self.jit_n + self.derp_n < 12 && hb_ok(snapshot, 1480),
        }
        c
    }

    fn do_commit(&mut self, c: Check) {
        if !c.ok {
            return;
        }
        match c.kind {
            Kind::Wgq => {
                self.wgq[self.wgq_n] = c.len;
                self.wgq_n += 1;
                self.take(i64::from(c.len + ML_WG_RX_OVERHEAD));
            }
            Kind::Ring => {
                self.ring_chunks += 1;
                self.take(i64::from(CHUNK_BYTES + 16));
            }
            Kind::Usb => {
                self.usb_len[self.usb_n] = c.len;
                self.usb_n += 1;
                self.take(i64::from(c.len + 16));
            }
            Kind::Tx => {
                let cost = wtx_cost(c.len) as u32;
                self.tx_cost[self.tx_n] = cost;
                self.tx_n += 1;
                self.take(i64::from(cost));
            }
            Kind::Jit => {
                if self.jit_n < 4 {
                    self.jit_n += 1;
                } else {
                    self.derp_n += 1;
                }
                self.take(1480);
            }
        }
    }

    fn rx_arrive(&mut self, m: &Model, len: u32) {
        let cost = rx_cost_of(len);
        if self.free < i64::from(cost) {
            return; // driver_fail
        }
        self.take(i64::from(cost)); // the driver allocated it: nothing has checked anything yet
        let keep = match m.rx_mode {
            1 => self.rx_n < 64 && self.pins.rx_admit(self.free as usize),
            2 => {
                let floor = if m.pin_floor != 0 { m.pin_floor } else { ML_HB_FLOOR };
                self.rx_n < m.rx_pool && (self.rx_n < m.rx_band || self.free as usize >= floor) // a mutant gate
            }
            _ => self.rx_n < m.rx_pool, // the driver's pool is the only limit
        };
        if !keep {
            self.free += i64::from(cost);
            self.rx_refused += 1;
            return;
        }
        self.rx_cost[self.rx_n] = cost;
        self.rx_n += 1;
    }

    /// net_io (or lwIP) frees one pinned buffer, maybe into the WireGuard queue.
    fn rx_consume(&mut self, m: &Model) {
        if self.rx_n == 0 {
            return;
        }
        let i = self.rs.rnd(self.rx_n as u32) as usize;
        let cost = self.rx_cost[i];
        self.rx_n -= 1;
        self.rx_cost[i] = self.rx_cost[self.rx_n];
        let len = if self.rs.rnd(4) != 0 { 1264 } else { 60 + self.rs.rnd(300) };
        // checked while the pin is still held
        let queue = m.download && self.rs.rnd(4) != 0 && self.wgq_n < MAX_HELD && self.wb.admit(len, self.free as usize) == WgRxVerdict::Ok;
        if m.rx_mode == 1 {
            self.pins.rx_release();
        }
        self.free += i64::from(cost);
        if queue {
            self.wgq[self.wgq_n] = len;
            self.wgq_n += 1;
            self.take(i64::from(len + ML_WG_RX_OVERHEAD));
        }
    }

    fn tx_complete(&mut self, m: &Model) {
        if self.tx_n == 0 {
            if m.tx_mode == 1 && self.rs.rnd(8) == 0 {
                self.pins.done(); // a done for a frame that was not ours
            }
            return;
        }
        let i = self.rs.rnd(self.tx_n as u32) as usize;
        self.free += i64::from(self.tx_cost[i]);
        self.tx_n -= 1;
        self.tx_cost[i] = self.tx_cost[self.tx_n];
        let r = self.rs.rnd(100);
        if m.tx_mode == 1 && r >= 4 {
            self.pins.done(); // 4 %: the driver recycled the buffer without a callback (queue clear): the lease takes it
        }
    }

    pub fn step(&mut self, m: &Model) {
        self.now += 1;
        let a = self.rs.rnd(100);
        if a < 24 {
            // download: a burst of frames, as one A-MPDU or a window of segments
            if m.download {
                let mut k = 1 + self.rs.rnd(8);
                while k > 0 {
                    k -= 1;
                    let len = if self.rs.rnd(4) != 0 { 1264 + 66 } else { 60 + self.rs.rnd(300) };
                    self.rx_arrive(m, len);
                }
            }
        } else if a < 44 {
            // consumers drain, partially (preempted by the Wi-Fi task)
            let mut k = 1 + self.rs.rnd(5);
            while k > 0 {
                k -= 1;
                self.rx_consume(m);
                if self.rs.rnd(3) == 0 {
                    break;
                }
            }
        } else if a < 52 {
            // wg_mgr pops a run
            let mut k = 1 + self.rs.rnd(8);
            while k > 0 && self.wgq_n != 0 {
                k -= 1;
                self.wgq_n -= 1;
                let len = self.wgq[self.wgq_n];
                self.wb.release_to(len);
                self.free += i64::from(len + ML_WG_RX_OVERHEAD);
            }
        } else if a < 76 {
            // elastic consumers and TX submit, one to three checking on the same free value. The checkers that can overlap are different sites
            // (the USB ring worker, TinyUSB's receive, lwIP's transmit, the packet-pending path; net_io and the DERP loop both feed the
            // WireGuard queue, so that one may appear twice): a site is one task and cannot race itself.
            let mut kinds = [KINDS[self.rs.rnd(5) as usize], KINDS[self.rs.rnd(5) as usize], KINDS[self.rs.rnd(5) as usize]];
            if m.upload && self.rs.rnd(3) == 0 {
                kinds[0] = Kind::Tx;
            }
            let racers = if self.rs.rnd(16) == 0 {
                3
            } else if self.rs.rnd(4) == 0 {
                2
            } else {
                1
            };
            for i in 1..racers {
                for _ in 0..16 {
                    let dup = (0..i).filter(|&j| kinds[j] == kinds[i]).count();
                    if dup == 0 || (kinds[i] == Kind::Wgq && dup == 1) {
                        break;
                    }
                    kinds[i] = KINDS[self.rs.rnd(5) as usize];
                }
            }
            let snapshot = if self.free > 0 { self.free as usize } else { 0 };
            let mut c = [Check { kind: Kind::Wgq, ok: false, len: 0 }; 3];
            for i in 0..racers {
                c[i] = self.do_check(m, kinds[i], snapshot);
            }
            for &chk in &c[..racers] {
                self.do_commit(chk);
            }
            if racers == 1 && kinds[0] == Kind::Ring && !c[0].ok && self.ring_chunks != 0 && self.rs.rnd(3) == 0 {
                self.ring_chunks -= 1;
                self.free += i64::from(CHUNK_BYTES + 16);
            }
        } else if a < 86 {
            // TX frames complete; sometimes the driver clears a queue
            let mut k = 1 + self.rs.rnd(3);
            while k > 0 {
                k -= 1;
                self.tx_complete(m);
            }
            if m.tx_mode == 1 && self.rs.rnd(300) == 0 {
                for i in 0..self.tx_n {
                    self.free += i64::from(self.tx_cost[i]);
                }
                self.tx_n = 0;
                self.pins.flush();
            }
        } else if a < 94 {
            // USB frames leave
            let mut k = 1 + self.rs.rnd(4);
            while k > 0 && self.usb_n != 0 {
                k -= 1;
                self.usb_n -= 1;
                let len = self.usb_len[self.usb_n];
                self.usb.release();
                self.free += i64::from(len + 16);
            }
        } else {
            while self.jit_n != 0 && self.rs.rnd(2) != 0 {
                self.jit_n -= 1;
                self.free += 1480;
            }
            while self.derp_n != 0 && self.rs.rnd(2) != 0 {
                self.derp_n -= 1;
                self.free += 1480;
            }
            if self.ring_chunks != 0 && self.rs.rnd(3) == 0 {
                self.ring_chunks -= 1;
                self.free += i64::from(CHUNK_BYTES + 16);
            }
        }
    }
}

/// `run()`: one schedule from free level `f0`; returns the minimum free heap seen. `rs` is seeded by the caller as the C does.
pub fn run(m: &Model, f0: i64, steps: u64, rs: Rs, print: bool) -> i64 {
    let mut s = Sim::new(f0, rs);
    for _ in 0..steps {
        s.step(m);
        assert!(s.free <= f0 + 1);
        if m.rx_mode == 1 {
            assert_eq!(s.pins.rx_inflight() as usize, s.rx_n);
        }
    }
    let min = s.min_free;
    if print {
        let st = s.pins.stats();
        std::eprintln!(
            "  {:<46} F0 {:6} B: min free {:6} B ({:+} vs the {} B reserve); pins held at the end RX {} TX {} (high water RX {} TX {}); refused RX {} TX {}; stale {}",
            m.name,
            f0,
            min,
            min - ML_HB_RESERVE as i64,
            ML_HB_RESERVE,
            s.rx_n,
            s.tx_n,
            st.rx_high_water,
            st.tx_high_water,
            s.rx_refused,
            s.tx_refused,
            st.tx_stale
        );
    }
    if m.tx_mode == 1 {
        super::conserved_tx(&s.pins);
    }
    min
}
