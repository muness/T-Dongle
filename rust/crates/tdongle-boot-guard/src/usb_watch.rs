//! USB liveness for the supervisor: the console heartbeat proves the console task loops, not that the USB device stack still serves the host. A wedged OTG core or a lost
//! driver wake-up keeps the heartbeats advancing and the watchdog fed while the host sees a dead port (the lockout after an esptool reset). These rules read what the OTG core
//! itself says, independently of the driver's tasks, and name the failure so the next `boot-status` carries `previous_hang=usb`.
//!
//! Inputs are sampled by the firmware every supervisor tick (register reads: the device frame number, the suspend bit, the interrupt status against its mask). There was a third
//! rule, "the console waits on an OUT endpoint whose `EPENA` is clear", and it is gone: `EPENA` is not what this driver keeps set while it waits, and on the board it tripped 31
//! times in two minutes of healthy idle (`trips=0/0/31`). A suspended or absent host (no frames: a power-only charger, a host asleep) is never a failure: nothing is required of a
//! device nobody is talking to. Pure: `no_std`, no unsafe code.

/// The host is sending frames but the device has not been configured within this long (ms).
pub const CONFIGURE_MS: u32 = 10_000;
/// An enabled interrupt cause has stayed pending (nothing serviced it) this long (ms).
pub const IRQ_MS: u32 = 3_000;

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
        let irq = run(&mut self.pending_since, s.pending != 0, now_ms, IRQ_MS);
        if irq {
            Some(Fault::IrqNotServiced)
        } else if not_configured {
            Some(Fault::NotConfigured)
        } else {
            None
        }
    }
}

/// The rules plus the decision to act on them. **Shadow by default**: the first image with these rules reset a healthy board about eight seconds after every boot (a1b8f4e,
/// board run, from a rule that is now deleted). A rule's trips are counted and reported (`usb_live trips=`) whether or not they are enforced; they
/// reset the chip only when `enforce` is on (the `selftest usb` command turns it on; the console's `usbwatch enforce on|off` flips it) until the board has shown that no rule trips
/// on a healthy idle device.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    watch: UsbWatch,
    /// Reset on a fault (otherwise only count it).
    pub enforce: bool,
    /// Trips per rule: not configured, interrupt not serviced.
    pub trips: [u32; 2],
    /// The most recent fault, enforced or not.
    pub last: Option<Fault>,
}

impl Policy {
    /// Shadow mode.
    #[must_use]
    pub const fn new() -> Self {
        Self { watch: UsbWatch::new(), enforce: false, trips: [0; 2], last: None }
    }

    /// Look at a sample; `Some` only when a rule tripped **and** `enforce` is on. A tripped rule starts its clock again, so it is counted once per limit, not once per tick.
    pub fn decide(&mut self, now_ms: u64, s: &Sample) -> Option<Fault> {
        let fault = self.watch.check(now_ms, s)?;
        let i = match fault {
            Fault::NotConfigured => 0,
            Fault::IrqNotServiced => 1,
        };
        self.trips[i] = self.trips[i].saturating_add(1);
        self.last = Some(fault);
        self.watch = UsbWatch::new();
        self.enforce.then_some(fault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: Sample = Sample { host_active: true, suspended: false, configured: true, pending: 0 };

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
    fn a_host_that_never_gets_the_device_configured_is_a_fault_after_ten_seconds() {
        let mut w = UsbWatch::new();
        let s = Sample { configured: false, ..OK };
        assert_eq!(run_for(&mut w, &s, 0, 10_000), None);
        assert_eq!(w.check(10_600, &s), Some(Fault::NotConfigured));
    }

    #[test]
    fn configuring_in_time_resets_the_clock() {
        let mut w = UsbWatch::new();
        let unconf = Sample { configured: false, ..OK };
        assert_eq!(run_for(&mut w, &unconf, 0, 9_000), None);
        assert_eq!(run_for(&mut w, &OK, 9_500, 60_000), None);
        // a later re-enumeration starts a new ten seconds
        assert_eq!(run_for(&mut w, &unconf, 60_500, 70_000), None);
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
        let board = Sample { host_active: true, suspended: false, configured: true, pending: 0 };
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
    /// enforced, it resets within four seconds.
    #[test]
    fn masked_interrupt_selftest_is_counted_in_shadow_and_resets_when_enforced() {
        let stuck = Sample { host_active: true, suspended: false, configured: true, pending: 1 << 4 };
        let mut shadow = Policy::new();
        for t in (0..=20_000u64).step_by(500) {
            assert_eq!(shadow.decide(t, &stuck), None);
        }
        assert!(shadow.trips[1] >= 3);
        let mut enforced = Policy::new();
        enforced.enforce = true;
        let hit = (0..=20_000u64).step_by(500).find_map(|t| enforced.decide(t, &stuck).map(|f| (t, f)));
        let (t, f) = hit.unwrap();
        assert_eq!(f, Fault::IrqNotServiced);
        assert!(t <= 4_000);
    }

    /// The whole supervisor on the host model for 60 s of idle uptime: both heartbeats advance, the USB samples are the board's, the verdict stays healthy and nothing resets.
    #[test]
    fn sixty_seconds_idle_whole_supervisor_model() {
        use crate::watch::{Verdict, Watch};
        let board = Sample { host_active: true, suspended: false, configured: true, pending: 0 };
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
}
