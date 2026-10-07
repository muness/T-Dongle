//! Progress supervision and the rescue self-tests, shared by the esp-hal images. Included with `#[path = "../../common/supervise.rs"] mod supervise;`.
//!
//! Two executors (the console and USB device in an interrupt-mode one, everything else in the thread executor), a heartbeat in each, and a supervisor in the
//! higher-priority one that feeds the hardware watchdogs **only while both heartbeats advance** (`tdongle_boot_guard::watch`), calls the image healthy only after USB is
//! configured and everything has advanced for 30 s (`tdongle_rescue::HealthyTimer`), and names a stalled executor before resetting.
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_executor::SendSpawner;
use embassy_sync::once_lock::OnceLock;
use embassy_time::{Instant, Timer};
use tdongle_boot_guard::usb_watch::{Fault, Policy, Sample};
use tdongle_boot_guard::watch::{Verdict, Watch};
use tdongle_rescue::{HealthyTimer, Selftest};

use crate::guard;

/// Bumped by `thread_pulse_task` (thread executor) and by the console task's own loop (so a console that stops being polled stops it).
pub static PULSE_THREAD: AtomicU32 = AtomicU32::new(0);
pub static PULSE_CONSOLE: AtomicU32 = AtomicU32::new(0);
/// The host has configured the device (set by the USB handler's `configured`).
pub static USB_CONFIGURED: AtomicBool = AtomicBool::new(false);
/// `selftest console`: the console task stops being polled.
pub static CONSOLE_FROZEN: AtomicBool = AtomicBool::new(false);
/// A spawner of the thread executor, for `selftest spin`.
pub static THREAD_SPAWNER: OnceLock<SendSpawner> = OnceLock::new();

/// The OTG core's registers, read-only here (the driver owns writes): the supervisor's USB liveness input. Reading status registers has no side effects.
mod otg {
    const BASE: usize = 0x6008_0000;
    const GINTSTS: usize = 0x014;
    const GINTMSK: usize = 0x018;
    const DSTS: usize = 0x808;
    /// RXFLVL, USBSUSP, USBRST, ENUMDNE, IEPINT, OEPINT, WKUPINT: the causes the driver's handler clears or masks.
    pub const EVENTS: u32 = (1 << 4) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 18) | (1 << 19) | (1 << 31);

    fn rd(off: usize) -> u32 {
        // SAFETY: the DWC2 register block of the ESP32-S3 FS core, always mapped; word-aligned reads of status registers.
        unsafe { core::ptr::read_volatile((BASE + off) as *const u32) }
    }
    pub fn pending() -> u32 {
        rd(GINTSTS) & rd(GINTMSK) & EVENTS
    }
    /// `(frame number, suspended)` from DSTS.
    pub fn dsts() -> (u32, bool) {
        let v = rd(DSTS);
        ((v >> 8) & 0x3FFF, v & 1 != 0)
    }
    /// Pull the bus to SE0 (pad override: D+ and D- pulled down, no pull-ups) and soft-disconnect the core: the host sees the device unplugged. Held until the driver
    /// attaches again (its `enable_device_mode` clears the override, `init` clears the soft disconnect). Called at boot, after any reset that kept the host attached, and
    /// just before every unplanned reset (panic, supervisor), so the host never keeps talking to a device that has forgotten its address and configuration. Needs the USB
    /// peripheral clocked (after `Usb::new_fs`; the running driver keeps it on).
    pub fn detach() {
        let lpwr = esp_hal::peripherals::LPWR::regs();
        // the internal PHY to the OTG core (not the USB-Serial-JTAG controller, whose own pull-up would hold D+ high)
        lpwr.usb_conf().modify(|_, w| {
            w.sw_hw_usb_phy_sel().set_bit();
            w.sw_usb_phy_sel().set_bit()
        });
        esp_hal::peripherals::USB_WRAP::regs().otg_conf().modify(|_, w| {
            w.usb_pad_enable().set_bit();
            w.phy_sel().clear_bit();
            w.pad_pull_override().set_bit();
            w.dp_pullup().clear_bit();
            w.dm_pullup().clear_bit();
            w.dp_pulldown().set_bit();
            w.dm_pulldown().set_bit()
        });
        // SAFETY: DCTL of the FS core, always mapped; SftDiscon is bit 1. The driver writes DCTL again in its `init`.
        unsafe {
            let dctl = (BASE + DCTL) as *mut u32;
            dctl.write_volatile(dctl.read_volatile() | (1 << 1));
        }
    }
    const DCTL: usize = 0x804;

    /// `selftest usb`: switch the USB interrupt off and leave the bus attached (no soft disconnect, no bounce: a bus bounce wedged a real hub on the board). The next thing the host
    /// does (any console command) then stays pending with nobody to service it.
    pub fn stop_servicing() {
        esp_hal::interrupt::disable(esp_hal::system::Cpu::ProCpu, esp_hal::peripherals::Interrupt::USB);
    }
}

/// Enforced USB resets in a row with no configured device since (`usb_watch::Policy::prior_resets`). RTC fast memory keeps it over the software reset; a power-on zeroes
/// it; the supervisor clears it once the host configures the device.
#[esp_hal::ram(unstable(rtc_fast, persistent))]
static mut USB_RESET_STREAK: u32 = 0;

fn usb_streak() -> u32 {
    // SAFETY: only the supervisor task touches it (one task, never concurrently); valid for any bit pattern (clamped below).
    unsafe { core::ptr::addr_of!(USB_RESET_STREAK).read_volatile() }.min(1_000)
}

fn set_usb_streak(n: u32) {
    // SAFETY: as in `usb_streak`.
    unsafe { core::ptr::addr_of_mut!(USB_RESET_STREAK).write_volatile(n) }
}

/// When the boot's detach hold ends (ms since boot): `usb_task` attaches no earlier.
static ATTACH_AT_MS: AtomicU32 = AtomicU32::new(0);

/// Boot: detach the bus at once (call right after `Usb::new_fs`) and, unless this was a power-on, keep it detached for `usb_watch::DETACH_HOLD_MS` so the host sees a
/// disconnect and enumerates the device afresh (a core-only reset otherwise leaves the host with the old, configured device and nothing answering it).
pub fn boot_detach(power_on: bool) {
    otg::detach();
    let hold = tdongle_boot_guard::usb_watch::detach_hold_ms(power_on);
    ATTACH_AT_MS.store(Instant::now().as_millis() as u32 + hold, Ordering::Relaxed);
}

/// `usb_task` awaits this before the device attaches.
pub async fn attach_allowed() {
    let at = u64::from(ATTACH_AT_MS.load(Ordering::Relaxed));
    let now = Instant::now().as_millis();
    if at > now {
        Timer::after_millis(at - now).await;
    }
}

/// Detach the bus before an unplanned reset (panic handler, supervisor): the disconnect starts now and lasts through the reboot and the next boot's hold.
pub fn detach_for_reset() {
    otg::detach();
}

/// The supervisor's own counters (`boot-status` `sup`): a supervisor that stopped, or one that never feeds, shows here without a debugger.
pub static SUP_TICKS: AtomicU32 = AtomicU32::new(0);
pub static SUP_FEEDS: AtomicU32 = AtomicU32::new(0);

/// `[ticks, feeds, thread pulse, console pulse]`.
pub fn stats() -> [u32; 4] {
    [SUP_TICKS.load(Ordering::Relaxed), SUP_FEEDS.load(Ordering::Relaxed), PULSE_THREAD.load(Ordering::Relaxed), PULSE_CONSOLE.load(Ordering::Relaxed)]
}

/// The console task calls this at the top of its loop: it proves the console is polled, and `selftest console` parks it for good.
pub async fn console_alive() {
    PULSE_CONSOLE.fetch_add(1, Ordering::Relaxed);
    if CONSOLE_FROZEN.load(Ordering::Relaxed) {
        core::future::pending::<()>().await;
    }
}

#[embassy_executor::task]
pub async fn thread_pulse_task() -> ! {
    loop {
        PULSE_THREAD.fetch_add(1, Ordering::Relaxed);
        Timer::after_millis(500).await;
    }
}

#[embassy_executor::task]
async fn spin_task() -> ! {
    tdongle_rescue::spin()
}

/// Feeds the watchdogs while both executors make progress; otherwise records which one did not and resets. Marks the image healthy (bootloader) and the boot stable (guard) once
/// USB has been configured and everything advanced for `HEALTHY_AFTER_MS`. Runs in the interrupt executor: nothing in the thread executor can starve it.
#[embassy_executor::task]
pub async fn supervisor_task(mut dogs: guard::Dogs, safe_mode: bool) -> ! {
    // deadlines: the thread executor may be inside a long synchronous call (radio init takes seconds) but must come back well inside the 10 s hardware watchdog
    let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], Instant::now().as_millis());
    let mut healthy = HealthyTimer::new();
    let mut marked = false;
    let mut usb_policy = Policy::new();
    usb_policy.prior_resets = usb_streak();
    let mut last_frame = otg::dsts().0;
    #[cfg(feature = "tailnet")]
    let mut last_masked = crate::dirflash::MASKED_OPS.load(Ordering::Relaxed);
    loop {
        let now = Instant::now().as_millis();
        SUP_TICKS.fetch_add(1, Ordering::Relaxed);
        match watch.check(now, [PULSE_THREAD.load(Ordering::Relaxed), PULSE_CONSOLE.load(Ordering::Relaxed)]) {
            Verdict::Healthy => {
                // USB liveness: the console task looping proves nothing about the device stack (a wedged OTG core or a lost driver wake-up keeps both heartbeats advancing)
                let (frame, suspended) = otg::dsts();
                // a flash erase or write of the peer directory since the last tick masked interrupts: a pending cause is not the handler's fault this tick
                #[cfg(feature = "tailnet")]
                let excused = {
                    let m = crate::dirflash::MASKED_OPS.load(Ordering::Relaxed);
                    let moved = m != last_masked;
                    last_masked = m;
                    moved
                };
                #[cfg(not(feature = "tailnet"))]
                let excused = false;
                let configured = USB_CONFIGURED.load(Ordering::Relaxed);
                let sample = Sample { host_active: frame != last_frame, suspended, configured, pending: otg::pending(), excused };
                last_frame = frame;
                if configured && usb_policy.prior_resets != 0 {
                    // the host has the device again: the reset streak is over
                    usb_policy.prior_resets = 0;
                    set_usb_streak(0);
                }
                usb_policy.enforce = USB_ENFORCE.load(Ordering::Relaxed);
                let decision = usb_policy.decide(now, &sample);
                for (cell, n) in USB_TRIPS.iter().zip(usb_policy.trips) {
                    cell.store(n, Ordering::Relaxed);
                }
                if let Some(fault) = decision {
                    USB_FAULT.store(match fault { Fault::NotConfigured => 1, Fault::IrqNotServiced => 2, }, Ordering::Relaxed);
                    healthy.observe(now, false);
                    guard::hang(Fault::HANG);
                    tdongle_rescue::demote(); // an unplanned reset the bootloader must count, even if this image had been healthy
                    set_usb_streak(usb_policy.prior_resets.saturating_add(1));
                    otg::detach();
                    esp_hal::system::software_reset()
                }
                dogs.feed();
                SUP_FEEDS.fetch_add(1, Ordering::Relaxed);
                if healthy.observe(now, USB_CONFIGURED.load(Ordering::Relaxed)) && !marked {
                    tdongle_rescue::mark_healthy();
                    guard::mark_stable(safe_mode);
                    marked = true;
                }
            }
            Verdict::Stalled(task) => {
                healthy.observe(now, false);
                // the last thing a gateway task started names where a stalled thread executor is (`previous_op` of the next boot)
                #[cfg(feature = "tailnet")]
                guard::op(tdongle_tailnet_runtime::optag::name());
                guard::hang(task);
                otg::detach();
                esp_hal::system::software_reset()
            }
        }
        Timer::after_millis(500).await;
    }
}

/// Which USB fault the supervisor saw (1 not configured, 2 interrupt not serviced), for the log line of the next boot's `boot-status` neighbours.
/// Reset on a confirmed USB fault: on at every boot (`usb_watch::Policy` confirms a trip before it resets); the console's `usbwatch enforce off` turns it off for this boot.
pub static USB_ENFORCE: AtomicBool = AtomicBool::new(true);
/// Trips per USB rule (not configured, interrupt not serviced), enforced or not.
pub static USB_TRIPS: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
pub static USB_FAULT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// `selftest NAME`: deliberately break the image so the rescue is proven on the board. Returns only for `console` (the console task parks itself at its next turn).
pub fn selftest(kind: Selftest) {
    tdongle_rescue::demote(); // count this reset against the image even if it had become healthy
    match kind {
        Selftest::Spin => {
            if let Some(spawner) = THREAD_SPAWNER.try_get() {
                if let Ok(token) = spin_task() {
                    spawner.spawn(token);
                }
            }
        }
        Selftest::IrqOff => tdongle_rescue::irqoff(),
        Selftest::Panic => panic!("selftest panic"),
        Selftest::Console => CONSOLE_FROZEN.store(true, Ordering::Relaxed),
        Selftest::Usb => {
            USB_ENFORCE.store(true, Ordering::Relaxed); // the self-test proves the enforced path
            otg::stop_servicing()
        }
    }
}

/// The `usb_live` line of `status`: what the supervisor's USB liveness check reads, so a wedge can be seen (and the selftest proven) from the console.
pub fn write_usb_live(out: &mut alloc::string::String) {
    use core::fmt::Write;
    let (frame, suspended) = otg::dsts();
    let _ = write!(
        out,
        "usb_live configured={} frame={} suspended={} pending={:#x} fault={} enforce={} trips={}/{}\r\n",
        u8::from(USB_CONFIGURED.load(Ordering::Relaxed)),
        frame,
        u8::from(suspended),
        otg::pending(),
        USB_FAULT.load(Ordering::Relaxed),
        u8::from(USB_ENFORCE.load(Ordering::Relaxed)),
        USB_TRIPS[0].load(Ordering::Relaxed),
        USB_TRIPS[1].load(Ordering::Relaxed)
    );
}
