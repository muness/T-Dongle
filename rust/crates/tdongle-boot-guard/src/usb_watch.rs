//! USB liveness for the supervisor: the console heartbeat proves the console task loops, not that the USB device stack still serves the host. A wedged OTG core or a lost
//! driver wake-up keeps the heartbeats advancing and the watchdog fed while the host sees a dead port (the lockout after an esptool reset). These rules read what the OTG core
//! itself says, independently of the driver's tasks, and name the failure so the next `boot-status` carries `previous_hang=usb`.
//!
//! Inputs are sampled by the firmware every supervisor tick (register reads: the device frame number, the suspend bit, the interrupt status against its mask). There was a third
//! rule, "the console waits on an OUT endpoint whose `EPENA` is clear", and it is gone: `EPENA` is not what this driver keeps set while it waits, and on the board it tripped 31
//! times in two minutes of healthy idle (`trips=0/0/31`). A suspended or absent host (no frames: a power-only charger, a host asleep) is never a failure: nothing is required of a
//! device nobody is talking to. Pure: `no_std`, no unsafe code.

/// The host is sending frames but the device has not been configured within this long (ms). Enumeration takes well under a second; fifteen leaves room for a slow
/// host (a hub that resets the port twice, a Windows driver install) without tripping.
pub const CONFIGURE_MS: u32 = 15_000;
/// An enabled interrupt cause has stayed pending (nothing serviced it) this long (ms).
pub const IRQ_MS: u32 = 3_000;
/// An interrupt-not-serviced trip resets only when it is confirmed by this many trips in a row (no healthy sample between): two windows, six seconds at least.
/// One window of a pending cause can be a long masked stretch (back-to-back flash erases of the peer directory); two in a row, with the handler at the highest
/// priority, is a handler that is not running.
pub const IRQ_CONFIRM_TRIPS: u32 = 2;
/// Enforced USB resets in a row (no configured device between them, counted across resets in RTC memory) after which the policy stops resetting for not-configured:
/// a host that never configures this device (a broken host driver) must not loop it through resets and into safe mode or a rollback for something a reset cannot fix.
pub const MAX_CONSECUTIVE_RESETS: u32 = 3;
/// How long the boot holds the bus detached (D+ and D- pulled down) before the device attaches, after any reset that was not a power-on (ms). A reset of the digital core
/// (panic, supervisor, the rescue watchdog) leaves the host believing the old device is still there and configured; half a second of SE0 is a disconnect every host
/// and hub sees (a replug, which is what the board needed by hand), and the host enumerates the device afresh. A power-on needs none.
pub const DETACH_HOLD_MS: u32 = 500;

/// The detach hold for this boot: [`DETACH_HOLD_MS`] unless the chip came out of a power-on reset.
#[must_use]
pub const fn detach_hold_ms(power_on: bool) -> u32 {
    if power_on { 0 } else { DETACH_HOLD_MS }
}

/// What the OTG core and the console showed at one tick.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// The device frame number advanced since the last sample: a host is sending SOF to this device.
    pub host_active: bool,
    /// The core reports the bus suspended (the host sleeps or stopped the port).
    pub suspended: bool,
    /// The host has configured the device.
    pub configured: bool,
    /// Interrupt causes that are both pending and enabled (the event bits the driver's handler clears): non-zero for long means the handler is not running.
    pub pending: u32,
    /// Something legitimately kept interrupts masked since the last sample (a flash erase or write of the peer directory): a pending cause is not held against the
    /// handler for this sample.
    pub excused: bool,
}

/// What failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A host is active and the device was never configured.
    NotConfigured,
    /// An enabled interrupt stayed pending: the USB interrupt handler is not servicing the core.
    IrqNotServiced,
}

impl Fault {
    /// The name `boot-status` reports as `previous_hang` for every USB fault.
    pub const HANG: &'static str = "usb";
}

/// The two timers.
#[derive(Clone, Copy, Debug, Default)]
pub struct UsbWatch {
    unconfigured_since: Option<u64>,
    pending_since: Option<u64>,
}

fn run(since: &mut Option<u64>, bad: bool, now: u64, limit: u32) -> bool {
    match (bad, *since) {
        (false, _) => {
            *since = None;
            false
        }
        (true, None) => {
            *since = Some(now);
            false
        }
        (true, Some(t)) => now.saturating_sub(t) > u64::from(limit),
    }
}

impl UsbWatch {
    /// A fresh watch.
    #[must_use]
    pub const fn new() -> Self {
        Self { unconfigured_since: None, pending_since: None }
    }

    /// Look at one sample at `now_ms`; the first fault found, if any.
    pub fn check(&mut self, now_ms: u64, s: &Sample) -> Option<Fault> {
        if s.suspended {
            // a sleeping host owes the device nothing, and the device owes it nothing
            *self = Self::new();
            return None;
        }
        let not_configured = run(&mut self.unconfigured_since, s.host_active && !s.configured, now_ms, CONFIGURE_MS);
        let irq = run(&mut self.pending_since, s.pending != 0 && !s.excused, now_ms, IRQ_MS);
        if irq {
            Some(Fault::IrqNotServiced)
        } else if not_configured {
            Some(Fault::NotConfigured)
        } else {
            None
        }
    }
}

/// The rules plus the decision to act on them. **Enforced by default** (it was shadow-only while a rule, since deleted, reset a healthy board eight seconds after every
/// boot; the remaining two showed `trips=0/0` on the board). Every trip is counted (`usb_live trips=`); a trip resets the chip only when `enforce` is on (the console's
/// `usbwatch enforce on|off` flips it for this boot) and it is confirmed:
/// * interrupt not serviced: [`IRQ_CONFIRM_TRIPS`] trips in a row, with no healthy sample between;
/// * not configured: fewer than [`MAX_CONSECUTIVE_RESETS`] USB resets in a row before this boot (`prior_resets`, kept in RTC memory by the firmware and cleared once the
///   host configures the device).
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    watch: UsbWatch,
    /// Reset on a fault (otherwise only count it).
    pub enforce: bool,
    /// Enforced USB resets in a row before this boot, none of them followed by a configured device.
    pub prior_resets: u32,
    /// Trips per rule: not configured, interrupt not serviced.
    pub trips: [u32; 2],
    /// The most recent fault, enforced or not.
    pub last: Option<Fault>,
    /// Interrupt-not-serviced trips in a row.
    irq_streak: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy {
    /// Enforcing, no prior resets.
    #[must_use]
    pub const fn new() -> Self {
        Self { watch: UsbWatch::new(), enforce: true, prior_resets: 0, trips: [0; 2], last: None, irq_streak: 0 }
    }

    /// Counting only (the console's `usbwatch enforce off`).
    #[must_use]
    pub const fn shadow() -> Self {
        let mut p = Self::new();
        p.enforce = false;
        p
    }

    /// Look at a sample; `Some` only when a rule tripped, is confirmed, and `enforce` is on. A tripped rule starts its clock again, so it is counted once per limit, not
    /// once per tick.
    pub fn decide(&mut self, now_ms: u64, s: &Sample) -> Option<Fault> {
        if !s.suspended && (s.pending == 0 || s.excused) {
            self.irq_streak = 0;
        }
        let fault = self.watch.check(now_ms, s)?;
        let i = match fault {
            Fault::NotConfigured => 0,
            Fault::IrqNotServiced => 1,
        };
        self.trips[i] = self.trips[i].saturating_add(1);
        self.last = Some(fault);
        self.watch = UsbWatch::new();
        let confirmed = match fault {
            Fault::IrqNotServiced => {
                self.irq_streak = self.irq_streak.saturating_add(1);
                self.irq_streak >= IRQ_CONFIRM_TRIPS
            }
            Fault::NotConfigured => self.prior_resets < MAX_CONSECUTIVE_RESETS,
        };
        (self.enforce && confirmed).then_some(fault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: Sample = Sample { host_active: true, suspended: false, configured: true, pending: 0, excused: false };

    fn run_for(w: &mut UsbWatch, s: &Sample, from: u64, to: u64) -> Option<Fault> {
        let mut t = from;
        while t <= to {
            if let Some(f) = w.check(t, s) {
                return Some(f);
            }
            t += 500;
        }
        None
    }

    #[test]
    fn a_healthy_device_never_faults() {
        let mut w = UsbWatch::new();
        assert_eq!(run_for(&mut w, &OK, 0, 600_000), None);
    }

    #[test]
    fn no_host_is_never_a_fault() {
        // a charger: no frames, never configured, nothing pending
        let mut w = UsbWatch::new();
        let s = Sample { host_active: false, configured: false, ..OK };
        assert_eq!(run_for(&mut w, &s, 0, 600_000), None);
    }

    #[test]
    fn a_host_that_never_gets_the_device_configured_is_a_fault_after_fifteen_seconds() {
        let mut w = UsbWatch::new();
        let s = Sample { configured: false, ..OK };
        assert_eq!(run_for(&mut w, &s, 0, 15_000), None);
        assert_eq!(w.check(15_600, &s), Some(Fault::NotConfigured));
    }

    #[test]
    fn configuring_in_time_resets_the_clock() {
        let mut w = UsbWatch::new();
        let unconf = Sample { configured: false, ..OK };
        assert_eq!(run_for(&mut w, &unconf, 0, 14_000), None);
        assert_eq!(run_for(&mut w, &OK, 14_500, 60_000), None);
        // a later re-enumeration starts a new fifteen seconds
        assert_eq!(run_for(&mut w, &unconf, 60_500, 75_000), None);
    }

    #[test]
    fn a_pending_interrupt_nobody_services_is_a_fault() {
        let mut w = UsbWatch::new();
        let s = Sample { pending: 1 << 12, ..OK }; // USBRST
        assert_eq!(run_for(&mut w, &s, 0, 3_000), None);
        assert_eq!(w.check(3_600, &s), Some(Fault::IrqNotServiced));
    }

    #[test]
    fn a_transient_pending_interrupt_is_not() {
        let mut w = UsbWatch::new();
        for t in (0..60_000).step_by(500) {
            let s = Sample { pending: if t % 1_000 == 0 { 1 << 4 } else { 0 }, ..OK };
            assert_eq!(w.check(t, &s), None);
        }
    }

    #[test]
    fn a_suspended_host_clears_everything() {
        let mut w = UsbWatch::new();
        let bad = Sample { pending: 1, configured: false, ..OK };
        assert_eq!(run_for(&mut w, &bad, 0, 2_500), None);
        let asleep = Sample { suspended: true, ..bad };
        assert_eq!(run_for(&mut w, &asleep, 3_000, 600_000), None);
        // and it wakes up with fresh clocks
        assert_eq!(run_for(&mut w, &bad, 600_500, 603_000), None);
    }

    #[test]
    fn the_selftest_signature_is_caught_within_four_seconds_of_a_bus_event() {
        // `selftest usb`: the interrupt handler is off and the host's reset is pending
        let mut w = UsbWatch::new();
        let s = Sample { pending: 1 << 12, ..OK };
        let mut found = None;
        for t in (0..).step_by(500) {
            if let Some(f) = w.check(t, &s) {
                found = Some((t, f));
                break;
            }
        }
        let (t, f) = found.unwrap();
        assert_eq!(f, Fault::IrqNotServiced);
        assert!(t <= 4_000, "{t}");
    }

    /// The board's healthy idle device: configured, a host sending frames, nothing pending. Ten minutes of that must not trip any rule, shadow or enforced (the board saw
    /// `trips=0/0` for the two rules that remain).
    #[test]
    fn the_boards_idle_samples_never_trip_in_ten_minutes_even_enforced() {
        let board = Sample { host_active: true, suspended: false, configured: true, pending: 0, excused: false };
        for enforce in [false, true] {
            let mut p = Policy::new();
            p.enforce = enforce;
            for t in (0..=600_000u64).step_by(500) {
                assert_eq!(p.decide(t, &board), None, "enforce={enforce} reset at {t} ms");
            }
            assert_eq!(p.trips, [0, 0]);
        }
    }

    /// With the interrupt handler masked and the bus left attached (the self-test), the host's next transaction stays pending and the shadow policy counts it without resetting;
    /// enforced, it resets once a second trip in a row confirms the first, within eight seconds.
    #[test]
    fn masked_interrupt_selftest_is_counted_in_shadow_and_resets_when_enforced() {
        let stuck = Sample { host_active: true, suspended: false, configured: true, pending: 1 << 4, excused: false };
        let mut shadow = Policy::shadow();
        for t in (0..=20_000u64).step_by(500) {
            assert_eq!(shadow.decide(t, &stuck), None);
        }
        assert!(shadow.trips[1] >= 3);
        let mut enforced = Policy::new();
        assert!(enforced.enforce, "enforced by default");
        let hit = (0..=20_000u64).step_by(500).find_map(|t| enforced.decide(t, &stuck).map(|f| (t, f)));
        let (t, f) = hit.unwrap();
        assert_eq!(f, Fault::IrqNotServiced);
        assert!((6_000..=8_000).contains(&t), "{t}");
        assert_eq!(enforced.trips[1], 2);
    }

    /// The whole supervisor on the host model for 60 s of idle uptime: both heartbeats advance, the USB samples are the board's, the verdict stays healthy and nothing resets.
    #[test]
    fn sixty_seconds_idle_whole_supervisor_model() {
        use crate::watch::{Verdict, Watch};
        let board = Sample { host_active: true, suspended: false, configured: true, pending: 0, excused: false };
        let mut watch = Watch::new(["thread", "console"], [8_000, 3_000], 0);
        let mut policy = Policy::new();
        let (mut thread, mut console) = (0u32, 0u32);
        for t in (0..=60_000u64).step_by(500) {
            thread += 1;
            console += 1;
            assert_eq!(watch.check(t, [thread, console]), Verdict::Healthy, "stalled at {t}");
            assert_eq!(policy.decide(t, &board), None, "usb reset at {t}");
        }
    }

    /// Heavy traffic: the bulk endpoints raise RXFLVL / IEPINT / OEPINT every few milliseconds and the handler clears them; a sample now and then catches one in
    /// flight, sometimes several in a row. Ten minutes of that, enforced, never resets.
    #[test]
    fn heavy_traffic_with_causes_caught_in_flight_never_resets() {
        let mut p = Policy::new();
        let mut x = 0x2545_f491u32;
        for t in (0..=600_000u64).step_by(500) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            // a cause seen in most samples, but a clean one at least every three seconds
            let caught = x % 5 != 0 && t % 3_000 != 0;
            let s = Sample { pending: if caught { (1 << 4) | (1 << 18) } else { 0 }, ..OK };
            assert_eq!(p.decide(t, &s), None, "reset at {t}");
        }
        assert_eq!(p.trips, [0, 0]);
    }

    /// The peer directory erasing sector after sector (interrupts masked ~45 ms each) while the host keeps the bus busy: those samples are excused, so a pending cause
    /// through a minute of erases is not a dead handler.
    #[test]
    fn flash_erase_storm_is_excused() {
        let mut p = Policy::new();
        for t in (0..=60_000u64).step_by(500) {
            let s = Sample { pending: 1 << 4, excused: true, ..OK };
            assert_eq!(p.decide(t, &s), None, "reset at {t}");
        }
        assert_eq!(p.trips, [0, 0]);
        // once the erases stop, a cause that stays pending is a fault again
        let hit = (60_500..=80_000u64).step_by(500).find_map(|t| p.decide(t, &Sample { pending: 1 << 4, ..OK }));
        assert_eq!(hit, Some(Fault::IrqNotServiced));
    }

    /// One pending window, then the handler catches up: counted, not enforced (the confirmation needs a second window in a row).
    #[test]
    fn a_single_irq_trip_is_counted_but_not_enforced() {
        let mut p = Policy::new();
        let stuck = Sample { pending: 1 << 4, ..OK };
        for t in (0..=3_500u64).step_by(500) {
            assert_eq!(p.decide(t, &stuck), None);
        }
        assert_eq!(p.trips[1], 1);
        for t in (4_000..=10_000u64).step_by(500) {
            assert_eq!(p.decide(t, &OK), None);
        }
        // a later single window starts the streak again from zero
        for t in (10_500..=14_000u64).step_by(500) {
            assert_eq!(p.decide(t, &stuck), None);
        }
        assert_eq!(p.trips[1], 2);
    }

    /// The board after a core-only reset: the host sends frames, the device is never configured. Enforced, it resets after fifteen seconds; after
    /// `MAX_CONSECUTIVE_RESETS` such resets in a row it only counts (a host that never configures must not loop the device).
    #[test]
    fn not_configured_resets_until_the_consecutive_cap() {
        let unconf = Sample { configured: false, ..OK };
        for prior in 0..=MAX_CONSECUTIVE_RESETS + 1 {
            let mut p = Policy::new();
            p.prior_resets = prior;
            let hit = (0..=60_000u64).step_by(500).find_map(|t| p.decide(t, &unconf).map(|f| (t, f)));
            if prior < MAX_CONSECUTIVE_RESETS {
                let (t, f) = hit.unwrap();
                assert_eq!(f, Fault::NotConfigured);
                assert!((15_000..=16_000).contains(&t), "{t}");
            } else {
                assert_eq!(hit, None, "prior={prior}");
                assert!(p.trips[0] >= 3);
            }
        }
    }

    /// The detach hold: none after a power-on, half a second after any other reset.
    #[test]
    fn detach_hold_only_after_resets_that_kept_the_host_attached() {
        assert_eq!(detach_hold_ms(true), 0);
        assert_eq!(detach_hold_ms(false), DETACH_HOLD_MS);
        assert!((100..=1_000).contains(&DETACH_HOLD_MS));
    }
}
