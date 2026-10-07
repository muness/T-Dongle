//! CPU frequency scaling (C ADR 0016, ADR 0023 section 4): 240 MHz while forwarding work is pending, 80 MHz when idle, no light sleep.
//!
//! The registry, the counted bursts and the forwarding-activity hold are `tdongle-pm` (host-tested); this file is the hardware half. With no ESP-IDF `esp_pm` here the "lock"
//! is a counted hold of ours: the CPU runs at 240 MHz while any lock is held and at 80 MHz when none is. The switch is the one the IDF's `rtc_clk_cpu_freq_set` makes on the
//! PLL path (`SYSTEM_CPU_PER_CONF.CPUPERIOD_SEL`, then the ROM's tick update); the APB clock stays 80 MHz at both, so UART, SPI and the radio do not notice. The core voltage
//! stays at the 240 MHz setting (the IDF lowers it at 80 MHz; the saving that is given up is small, and the sequence is the part that can brown out a board).
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::Timer;
use tdongle_pm::{BurstId, LockCreate, MAX_BURSTS, Pm, PmHardware, PmStatus};

/// `CPUPERIOD_SEL` values for a 480 MHz PLL (TRM table 7.2-2).
const SEL_80: u8 = 0;
const SEL_160: u8 = 1;
const SEL_240: u8 = 2;

static CPU_MHZ: AtomicU32 = AtomicU32::new(240);
static HOLDS: AtomicU32 = AtomicU32::new(0);
static LOCKED: [AtomicBool; MAX_BURSTS] = [const { AtomicBool::new(false) }; MAX_BURSTS];
static TIMER_SIG: Signal<CriticalSectionRawMutex, u32> = Signal::new();

/// Switch the CPU clock between the PLL taps. Register writes only: safe in any context.
fn set_cpu_mhz(mhz: u32) {
    let sel = match mhz {
        80 => SEL_80,
        160 => SEL_160,
        _ => SEL_240,
    };
    critical_section::with(|_| {
        esp_hal::peripherals::SYSTEM::regs().cpu_per_conf().modify(|_, w| {
            // SAFETY: a documented value of the 2-bit field; the PLL is already the clock source (esp-hal init at `CpuClock::max()`).
            unsafe { w.cpuperiod_sel().bits(sel) }
        });
        CPU_MHZ.store(mhz, Ordering::Relaxed);
    });
    // ROM tick-per-microsecond table (`ets_delay_us` and friends): as the IDF's `rtc_clk_cpu_freq_set` does.
    esp_rom_sys::rom::ets_update_cpu_frequency_rom(mhz);
}

/// The hardware half of [`Pm`].
#[derive(Debug)]
pub struct Hardware;

impl PmHardware for Hardware {
    fn configure(&self, _max_mhz: u32, min_mhz: u32) -> Result<(), i32> {
        // Scaling is on from here: idle is the minimum clock until a hold is taken.
        if HOLDS.load(Ordering::Relaxed) == 0 {
            set_cpu_mhz(min_mhz);
        }
        Ok(())
    }

    fn cpu_mhz(&self) -> u32 {
        CPU_MHZ.load(Ordering::Relaxed)
    }

    fn now_us(&self) -> u32 {
        embassy_time::Instant::now().as_micros() as u32
    }

    fn in_isr(&self) -> bool {
        false
    }

    fn lock_create(&self, slot: usize, _name: &str) -> LockCreate {
        LOCKED[slot].store(false, Ordering::Relaxed);
        LockCreate::Created
    }

    fn lock_acquire(&self, slot: usize) -> bool {
        LOCKED[slot].store(true, Ordering::Relaxed);
        if HOLDS.fetch_add(1, Ordering::AcqRel) == 0 {
            set_cpu_mhz(tdongle_pm::MAX_MHZ);
        }
        true
    }

    fn lock_release(&self, slot: usize) {
        LOCKED[slot].store(false, Ordering::Relaxed);
        if HOLDS.fetch_sub(1, Ordering::AcqRel) == 1 {
            set_cpu_mhz(tdongle_pm::MIN_MHZ);
        }
    }

    fn timer_create(&self) -> bool {
        true
    }

    fn timer_start_once(&self, delay_us: u32) {
        TIMER_SIG.signal(delay_us);
    }
}

/// The one power-management registry of the image.
pub static PM: Pm<Hardware> = Pm::new(Hardware);

static USB_TX: critical_section::Mutex<core::cell::Cell<Option<BurstId>>> = critical_section::Mutex::new(core::cell::Cell::new(None));

/// Enable scaling and register the transmit ring's burst. Once, after the radio is up.
pub fn start() {
    if PM.start().is_err() {
        return;
    }
    let id = match PM.register_burst("usb_txq") {
        Ok(id) => Some(id),
        Err(e) => e.failed_id(),
    };
    critical_section::with(|cs| USB_TX.borrow(cs).set(id));
}

/// The ring worker's CPU-max hold begins / ends (`usb_tx_pm_begin` / `usb_tx_pm_end`).
pub fn usb_tx_begin() {
    if let Some(id) = critical_section::with(|cs| USB_TX.borrow(cs).get()) {
        PM.begin(id);
    }
}

/// See [`usb_tx_begin`].
pub fn usb_tx_end() {
    if let Some(id) = critical_section::with(|cs| USB_TX.borrow(cs).get()) {
        PM.end(id);
    }
}

/// A packet is passing: raise the clock for the activity hold (one atomic load while it is held).
#[inline]
pub fn note_activity() {
    PM.note_activity();
}

/// The `pm` command's data.
pub fn status() -> PmStatus {
    PM.status()
}

/// The one-shot timer of the activity hold: waits the requested delay, then lets go (`esp_timer` in the IDF).
#[embassy_executor::task]
pub async fn timer_task() -> ! {
    loop {
        let delay_us = TIMER_SIG.wait().await;
        Timer::after_micros(u64::from(delay_us)).await;
        PM.activity_fire();
    }
}
