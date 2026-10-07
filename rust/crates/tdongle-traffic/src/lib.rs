//! Traffic through the dongle's USB side, for the Traffic screen page and the serial `status` report: the port of `main/traffic.{h,c}`
//! (tests: `tests/test_traffic.c`).
//!
//! * [`Counters`]: [`count_down`](Counters::count_down) / [`count_up`](Counters::count_up) are called for every frame that crosses the USB
//!   network interface (to the host, from the host), in every mode, from the two TinyUSB NCM callbacks. Relaxed atomics on 32 bit words (the
//!   S3 has no 64 bit atomics); a reader takes differences modulo 2^32.
//! * [`Sampler`]: turns two readings into rates and totals. Called from one task only. Rates are measured over windows of at least
//!   [`WINDOW_MS`], in kilobits per second, in integers (no floating point in the firmware's text path).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

/// Graph history length (bars).
pub const HISTORY: usize = 32;
/// Rates are measured over windows of at least this long.
pub const WINDOW_MS: u32 = 1000;
/// Tallest bar.
pub const BAR_MAX: u32 = 20;

/// A reading of the four counters (`traffic_counters`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// Bytes delivered to the host.
    pub down_bytes: u32,
    /// Bytes received from the host.
    pub up_bytes: u32,
    /// Frames delivered to the host.
    pub down_frames: u32,
    /// Frames received from the host.
    pub up_frames: u32,
}

/// The live counters.
#[derive(Debug, Default)]
pub struct Counters {
    down_bytes: AtomicU32,
    up_bytes: AtomicU32,
    down_frames: AtomicU32,
    up_frames: AtomicU32,
}

impl Counters {
    /// Zeroed counters (usable in a `static`).
    #[must_use]
    pub const fn new() -> Self {
        Self { down_bytes: AtomicU32::new(0), up_bytes: AtomicU32::new(0), down_frames: AtomicU32::new(0), up_frames: AtomicU32::new(0) }
    }

    /// A frame delivered to the USB host.
    pub fn count_down(&self, bytes: u32) {
        self.down_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.down_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// A frame received from the USB host.
    pub fn count_up(&self, bytes: u32) {
        self.up_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.up_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// The current counts.
    #[must_use]
    pub fn read(&self) -> Reading {
        Reading {
            down_bytes: self.down_bytes.load(Ordering::Relaxed),
            up_bytes: self.up_bytes.load(Ordering::Relaxed),
            down_frames: self.down_frames.load(Ordering::Relaxed),
            up_frames: self.up_frames.load(Ordering::Relaxed),
        }
    }
}

/// The windowed rate sampler (`traffic_sampler`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sampler {
    last: Reading,
    window_start_ms: u32,
    window_down: u32,
    window_up: u32,
    started: bool,
    /// Bytes since the first sample (64 bit: keeps counting past 4 GB).
    pub down_total: u64,
    /// Bytes since the first sample.
    pub up_total: u64,
    /// Frames since the first sample.
    pub down_frames_total: u64,
    /// Frames since the first sample.
    pub up_frames_total: u64,
    /// The last complete window, kbit/s.
    pub down_kbps: u32,
    /// The last complete window, kbit/s.
    pub up_kbps: u32,
    /// Down + up per window in kbit/s, saturating at 65535 (the USB link carries 12 Mbit/s at most), as a ring.
    pub history_kbps: [u16; HISTORY],
    /// Next history slot (free-running; the oldest entry sits at `cursor % HISTORY`).
    pub cursor: u32,
}

/// `bytes * 8 / ms` in kbit/s.
fn kbps(bytes: u32, ms: u32) -> u32 {
    if ms == 0 { 0 } else { (u64::from(bytes) * 8 / u64::from(ms)) as u32 }
}

impl Sampler {
    /// A sampler that has taken no reading yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: Reading { down_bytes: 0, up_bytes: 0, down_frames: 0, up_frames: 0 },
            window_start_ms: 0,
            window_down: 0,
            window_up: 0,
            started: false,
            down_total: 0,
            up_total: 0,
            down_frames_total: 0,
            up_frames_total: 0,
            down_kbps: 0,
            up_kbps: 0,
            history_kbps: [0; HISTORY],
            cursor: 0,
        }
    }

    /// Feed a reading taken at `now_ms`. Totals follow every call; rates and history only advance when a window of at least [`WINDOW_MS`] has
    /// passed since the last one. The first reading only sets the baseline.
    pub fn sample(&mut self, now: &Reading, now_ms: u32) {
        if !self.started {
            self.started = true;
            self.last = *now;
            self.window_start_ms = now_ms;
            return;
        }
        // Differences modulo 2^32, so a counter that wrapped (4 GB) is not a negative burst.
        let down = now.down_bytes.wrapping_sub(self.last.down_bytes);
        let up = now.up_bytes.wrapping_sub(self.last.up_bytes);
        self.down_total += u64::from(down);
        self.up_total += u64::from(up);
        self.down_frames_total += u64::from(now.down_frames.wrapping_sub(self.last.down_frames));
        self.up_frames_total += u64::from(now.up_frames.wrapping_sub(self.last.up_frames));
        self.window_down = self.window_down.wrapping_add(down);
        self.window_up = self.window_up.wrapping_add(up);
        self.last = *now;
        let elapsed = now_ms.wrapping_sub(self.window_start_ms);
        if elapsed < WINDOW_MS {
            return;
        }
        self.down_kbps = kbps(self.window_down, elapsed);
        self.up_kbps = kbps(self.window_up, elapsed);
        let both = self.down_kbps + self.up_kbps;
        self.history_kbps[self.cursor as usize % HISTORY] = both.min(65535) as u16;
        self.cursor = self.cursor.wrapping_add(1);
        self.window_down = 0;
        self.window_up = 0;
        self.window_start_ms = now_ms;
    }

    /// The history as bar heights `0..=BAR_MAX`, oldest first, scaled to the busiest window shown (never below 1 Mbit/s full scale, so an idle
    /// link draws nothing instead of full-height noise).
    #[must_use]
    pub fn bars(&self) -> [u8; HISTORY] {
        let scale = self.history_kbps.iter().map(|&v| u32::from(v)).fold(1000, u32::max);
        let mut out = [0u8; HISTORY];
        for (i, bar) in out.iter_mut().enumerate() {
            // the oldest entry sits at the cursor
            let v = u32::from(self.history_kbps[(self.cursor as usize + i) % HISTORY]);
            *bar = (u64::from(v) * u64::from(BAR_MAX) / u64::from(scale)) as u8;
        }
        out
    }
}

/// `"1.23"` from kilobits per second (two decimals, rounded down).
#[derive(Clone, Copy, Debug)]
pub struct Mbps(pub u32);

impl fmt::Display for Mbps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.0 / 1000, self.0 % 1000 / 10)
    }
}

/// `"12.3"` or `"1234"` megabytes from a byte total: one decimal below 100 MB, none above.
#[derive(Clone, Copy, Debug)]
pub struct Megabytes(pub u64);

impl fmt::Display for Megabytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tenths = self.0 / 100_000; // 0.1 MB steps
        if tenths >= 1000 { write!(f, "{}", tenths / 10) } else { write!(f, "{}.{}", tenths / 10, tenths % 10) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::format;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn at(down: u32, up: u32, down_f: u32, up_f: u32) -> Reading {
        Reading { down_bytes: down, up_bytes: up, down_frames: down_f, up_frames: up_f }
    }

    #[test]
    fn rates_and_totals() {
        let mut t = Sampler::new();
        t.sample(&at(0, 0, 0, 0), 5000); // the first reading only sets the baseline
        assert_eq!((t.down_total, t.down_kbps), (0, 0));
        t.sample(&at(62500, 12500, 50, 10), 5500); // half a window: totals move, rates wait
        assert_eq!((t.down_total, t.up_total, t.down_kbps, t.cursor), (62500, 12500, 0, 0));
        t.sample(&at(125_000, 25_000, 100, 20), 6000);
        assert_eq!((t.down_kbps, t.up_kbps, t.cursor, t.history_kbps[0]), (1000, 200, 1, 1200)); // 125000 B in 1 s = 1 Mbit/s
        assert_eq!((t.down_frames_total, t.up_frames_total), (100, 20));
        t.sample(&at(125_000, 25_000, 100, 20), 7000); // idle second
        assert_eq!((t.down_kbps, t.up_kbps, t.history_kbps[1]), (0, 0, 0));
        t.sample(&at(125_000 + 250_000, 25_000, 100, 20), 9000); // a longer window: 2 s, 1 Mbit/s
        assert_eq!((t.down_kbps, t.cursor), (1000, 3));
    }

    #[test]
    fn counter_wrap() {
        let mut t = Sampler::new();
        t.sample(&at(0xffff_0000, 0xffff_fff0, 0xffff_ffff, 0), 0);
        let mut c = at(0xffff_0000u32.wrapping_add(125_000), 0xffff_fff0u32.wrapping_add(100), 1, 0); // wrapped past 2^32
        t.sample(&c, 1000);
        assert_eq!((t.down_total, t.up_total, t.down_kbps, t.up_kbps, t.down_frames_total), (125_000, 100, 1000, 0, 2));
        // Totals are 64 bit and keep counting past 4 GB.
        for i in 0..40u32 {
            c.down_bytes = c.down_bytes.wrapping_add(0x1000_0000);
            t.sample(&c, 2000 + i * 1000);
        }
        assert!(t.down_total > 0xffff_ffff);
    }

    #[test]
    fn bars() {
        let mut t = Sampler::new();
        assert_eq!(t.bars(), [0; HISTORY], "idle draws nothing");
        let mut c = at(0, 0, 0, 0);
        t.sample(&c, 0);
        for i in 1..=40u32 {
            c.down_bytes += if i <= 20 { 31_250 } else { 62_500 }; // 0.25 then 0.5 Mbit/s
            t.sample(&c, i * 1000);
        }
        let b = t.bars();
        assert!(b.iter().all(|&v| u32::from(v) <= BAR_MAX));
        assert_eq!(b.iter().copied().max(), Some(10), "full scale is at least 1 Mbit/s: 0.5 Mbit/s is half height, not full");
        assert_eq!(b[HISTORY - 1], 10, "newest on the right");
        c.down_bytes += 125_000 * 8; // 8 Mbit/s in one window scales the graph to the busiest second
        t.sample(&c, 41_000);
        let b = t.bars();
        assert_eq!((u32::from(b[HISTORY - 1]), b[HISTORY - 2]), (BAR_MAX, 1));
    }

    #[test]
    fn formatting() {
        assert_eq!(format!("{}", Mbps(0)), "0.00");
        assert_eq!(format!("{}", Mbps(1234)), "1.23");
        assert_eq!(format!("{}", Mbps(999)), "0.99");
        assert_eq!(format!("{}", Mbps(9400)), "9.40");
        assert_eq!(format!("{}", Megabytes(0)), "0.0");
        assert_eq!(format!("{}", Megabytes(12_345_678)), "12.3");
        assert_eq!(format!("{}", Megabytes(99_999_999)), "99.9");
        assert_eq!(format!("{}", Megabytes(100_000_000)), "100");
        assert_eq!(format!("{}", Megabytes(5 * 1000 * 1000 * 1000)), "5000");
    }

    #[test]
    fn counters_from_threads() {
        let c = Arc::new(Counters::new());
        let before = c.read();
        let workers: std::vec::Vec<_> = (0..3)
            .map(|i| {
                let c = c.clone();
                thread::spawn(move || {
                    for _ in 0..100_000 {
                        if i < 2 { c.count_down(1500) } else { c.count_up(60) }
                    }
                })
            })
            .collect();
        for _ in 0..100 {
            let _ = c.read(); // a reader racing the writers
        }
        workers.into_iter().for_each(|w| w.join().unwrap());
        let after = c.read();
        assert_eq!(after.down_bytes - before.down_bytes, 2 * 100_000 * 1500);
        assert_eq!(after.up_bytes - before.up_bytes, 100_000 * 60);
        assert_eq!((after.down_frames - before.down_frames, after.up_frames - before.up_frames), (200_000, 100_000));
    }
}
