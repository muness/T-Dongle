//! The registry (`tdongle_pm.c`) over a fake `esp_pm`: start, lock creation and its failures, the status, the activity hold bound to the
//! registry, `dump_locks`.

use std::prelude::v1::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering::SeqCst};

use crate::{ACTIVITY_BURST_NAME, ACTIVITY_HOLD_US, Burst, LockCreate, MAX_BURSTS, MAX_MHZ, MIN_MHZ, Pm, PmHardware, RegisterError};

struct Hw {
    configure_result: Mutex<Result<(), i32>>,
    configured_with: Mutex<Option<(u32, u32)>>,
    create: Mutex<Vec<LockCreate>>,
    held: [AtomicI32; MAX_BURSTS],
    acquires: AtomicU32,
    releases: AtomicU32,
    timer_ok: AtomicBool,
    timer_starts: AtomicU32,
    last_delay: AtomicU32,
    clock: AtomicU32,
    isr: AtomicBool,
    dump: Mutex<Vec<u8>>,
}

impl Hw {
    fn new() -> Self {
        Self {
            configure_result: Mutex::new(Ok(())),
            configured_with: Mutex::new(None),
            create: Mutex::new(Vec::new()),
            held: Default::default(),
            acquires: AtomicU32::new(0),
            releases: AtomicU32::new(0),
            timer_ok: AtomicBool::new(true),
            timer_starts: AtomicU32::new(0),
            last_delay: AtomicU32::new(0),
            clock: AtomicU32::new(5000),
            isr: AtomicBool::new(false),
            dump: Mutex::new(Vec::new()),
        }
    }
}

impl PmHardware for Hw {
    fn configure(&self, max_mhz: u32, min_mhz: u32) -> Result<(), i32> {
        *self.configured_with.lock().unwrap() = Some((max_mhz, min_mhz));
        *self.configure_result.lock().unwrap()
    }
    fn cpu_mhz(&self) -> u32 {
        240
    }
    fn now_us(&self) -> u32 {
        self.clock.load(SeqCst)
    }
    fn in_isr(&self) -> bool {
        self.isr.load(SeqCst)
    }
    fn lock_create(&self, _slot: usize, _name: &str) -> LockCreate {
        let mut c = self.create.lock().unwrap();
        if c.is_empty() { LockCreate::Created } else { c.remove(0) }
    }
    fn lock_acquire(&self, slot: usize) -> bool {
        self.acquires.fetch_add(1, SeqCst);
        self.held[slot].fetch_add(1, SeqCst);
        true
    }
    fn lock_release(&self, slot: usize) {
        self.releases.fetch_add(1, SeqCst);
        self.held[slot].fetch_sub(1, SeqCst);
    }
    fn timer_create(&self) -> bool {
        self.timer_ok.load(SeqCst)
    }
    fn timer_start_once(&self, delay_us: u32) {
        self.timer_starts.fetch_add(1, SeqCst);
        self.last_delay.store(delay_us, SeqCst);
    }
    fn dump_locks(&self, buf: &mut [u8]) -> usize {
        let d = self.dump.lock().unwrap();
        let n = d.len().min(buf.len());
        buf[..n].copy_from_slice(&d[..n]);
        if n < buf.len() {
            buf[n] = 0; // fmemopen NUL terminates when there is room
        }
        n
    }
}

#[test]
fn start_enables_scaling_and_the_activity_hold() {
    let pm = Pm::new(Hw::new());
    assert!(!pm.status().scaling && pm.status().max_mhz == 0 && !pm.activity_ready());
    pm.note_activity(); // a no-op while scaling is off
    assert_eq!(pm.hw().acquires.load(SeqCst), 0);
    assert_eq!(pm.start(), Ok(()));
    assert_eq!(*pm.hw().configured_with.lock().unwrap(), Some((MAX_MHZ, MIN_MHZ)));
    assert_eq!((MAX_MHZ, MIN_MHZ, ACTIVITY_HOLD_US), (240, 80, 200_000));
    assert!(pm.activity_ready());
    let st = pm.status();
    assert!(st.scaling && st.configure_error == 0 && st.max_mhz == 240 && st.min_mhz == 80 && st.cpu_mhz == 240 && st.lock_create_failures == 0);
    assert!(st.bursts == 1 && st.bursts()[0].name.as_str() == ACTIVITY_BURST_NAME);
    // The first packet after a quiet spell takes the lock and arms the timer for the whole hold; a stream adds nothing.
    pm.hw().clock.store(1_000_000, SeqCst);
    pm.note_activity();
    assert!(pm.hw().acquires.load(SeqCst) == 1 && pm.hw().timer_starts.load(SeqCst) == 1 && pm.hw().last_delay.load(SeqCst) == ACTIVITY_HOLD_US);
    for i in 1..50u32 {
        pm.hw().clock.store(1_000_000 + i * 1000, SeqCst);
        pm.note_activity();
    }
    assert_eq!(pm.hw().acquires.load(SeqCst), 1);
    assert_eq!(pm.hw().held[0].load(SeqCst), 1);
    // The timer fires 200 ms after the start while the last note was at +49 ms: it re-arms for the remainder, then releases.
    pm.hw().clock.store(1_000_000 + ACTIVITY_HOLD_US, SeqCst);
    pm.activity_fire();
    assert_eq!(pm.hw().last_delay.load(SeqCst), ACTIVITY_HOLD_US - (ACTIVITY_HOLD_US - 49_000));
    assert_eq!(pm.hw().releases.load(SeqCst), 0);
    pm.hw().clock.store(1_000_000 + 49_000 + ACTIVITY_HOLD_US, SeqCst);
    pm.activity_fire();
    assert!(pm.hw().releases.load(SeqCst) == 1 && pm.hw().held[0].load(SeqCst) == 0);
    let s = pm.status().burst[0];
    assert!(s.acquires == 1 && s.releases == 1 && s.depth == 0 && s.underflows == 0 && s.held_us > 0);
    assert_eq!(pm.activity().starts(), 1);
}

#[test]
fn start_twice_keeps_one_activity_burst() {
    let pm = Pm::new(Hw::new());
    assert_eq!(pm.start(), Ok(()));
    assert_eq!(pm.start(), Ok(()));
    assert!(pm.status().bursts == 1 && pm.activity_ready());
}

#[test]
fn start_failure_leaves_the_cpu_at_its_boot_frequency() {
    let hw = Hw::new();
    *hw.configure_result.lock().unwrap() = Err(0x103);
    let pm = Pm::new(hw);
    assert_eq!(pm.start(), Err(0x103));
    let st = pm.status();
    assert!(!st.scaling && st.configure_error == 0x103 && st.max_mhz == 0 && st.min_mhz == 0 && st.bursts == 0);
    assert!(!pm.activity_ready());
    pm.note_activity();
    pm.activity_fire();
    assert_eq!(pm.hw().acquires.load(SeqCst), 0);
    // A burst registered anyway counts but holds nothing: with scaling off the backend neither takes nor releases a lock.
    let id = pm.register_burst("usb_txq").unwrap();
    pm.begin(id);
    pm.begin(id);
    pm.end(id);
    pm.end(id);
    let s = pm.burst_stats(id);
    assert!(s.acquires == 1 && s.releases == 1 && s.backend_failures == 0 && s.name.as_str() == "usb_txq");
    assert!(pm.hw().acquires.load(SeqCst) == 0 && pm.hw().releases.load(SeqCst) == 0);
}

#[test]
fn bursts_take_their_own_lock() {
    let pm = Pm::new(Hw::new());
    pm.start().unwrap();
    let a = pm.register_burst("wifi").unwrap();
    let b = pm.register_burst("usb_txq").unwrap();
    assert_ne!(a, b);
    pm.begin(a);
    pm.begin(b);
    pm.begin(b);
    assert!(pm.hw().held[a.index()].load(SeqCst) == 1 && pm.hw().held[b.index()].load(SeqCst) == 1);
    pm.end(a);
    assert_eq!(pm.hw().held[a.index()].load(SeqCst), 0);
    pm.release_all(b); // the task exits mid-burst
    assert_eq!(pm.hw().held[b.index()].load(SeqCst), 0);
    assert!(pm.burst_stats(b).forced_releases == 1 && pm.burst_stats(b).max_depth == 2);
    // The `Burst` view is the same burst.
    let v = pm.burst(a);
    v.begin();
    assert_eq!(pm.hw().held[a.index()].load(SeqCst), 1);
    v.end();
    pm.hw().isr.store(true, SeqCst);
    assert!(v.refuse_in_isr());
    v.begin();
    pm.hw().isr.store(false, SeqCst);
    assert!(pm.burst_stats(a).isr_rejects == 2 && pm.hw().held[a.index()].load(SeqCst) == 0);
    // The status lists the bursts in registration order, with the activity burst first.
    let st = pm.status();
    let names: Vec<&str> = st.bursts().iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["fwd_activity", "wifi", "usb_txq"]);
}

#[test]
fn lock_creation_failures() {
    let hw = Hw::new();
    // Slot 0 is the activity burst (created); then a not-supported lock, then a failure, then a good one.
    *hw.create.lock().unwrap() = vec![LockCreate::Created, LockCreate::NotSupported, LockCreate::Failed(0x101), LockCreate::Created];
    let pm = Pm::new(hw);
    pm.start().unwrap();
    let ns = pm.register_burst("ns").unwrap(); // not supported is not an error ...
    pm.begin(ns); // ... but the burst has no lock to take while scaling is on: counted
    assert!(pm.burst_stats(ns).backend_failures == 1 && pm.hw().acquires.load(SeqCst) == 0);
    pm.end(ns);
    let bad = pm.register_burst("bad");
    assert!(matches!(bad, Err(RegisterError::LockFailed(_))));
    let failed = bad.unwrap_err().failed_id().unwrap();
    assert_eq!(pm.status().lock_create_failures, 1);
    pm.begin(failed);
    pm.end(failed);
    assert!(pm.burst_stats(failed).backend_failures == 1 && pm.burst_stats(failed).releases == 1 && pm.hw().releases.load(SeqCst) == 0);
    let ok = pm.register_burst("ok").unwrap();
    pm.begin(ok);
    assert_eq!(pm.hw().held[ok.index()].load(SeqCst), 1);
    assert_eq!(pm.status().bursts, 4); // the activity burst, ns, bad, ok
}

#[test]
fn registry_is_bounded() {
    let pm = Pm::new(Hw::new());
    pm.start().unwrap(); // takes slot 0
    for i in 1..MAX_BURSTS {
        assert!(pm.register_burst("b").is_ok(), "slot {i}");
    }
    assert_eq!(pm.register_burst("one too many"), Err(RegisterError::Full));
    assert_eq!(pm.register_burst("and again"), Err(RegisterError::Full));
    let st = pm.status();
    assert_eq!(st.bursts as usize, MAX_BURSTS);
    assert_eq!(st.bursts().len(), MAX_BURSTS);
}

#[test]
fn activity_unavailable_without_a_timer() {
    let hw = Hw::new();
    hw.timer_ok.store(false, SeqCst);
    let pm = Pm::new(hw);
    assert_eq!(pm.start(), Ok(())); // scaling still works; only the hold is missing
    assert!(pm.status().scaling && !pm.activity_ready());
    pm.note_activity();
    assert_eq!(pm.hw().acquires.load(SeqCst), 0);
}

#[test]
fn dump_locks_truncates_and_terminates() {
    let hw = Hw::new();
    *hw.dump.lock().unwrap() = b"cpu_freq_max 1\napb 0\n".to_vec();
    let pm = Pm::new(hw);
    let mut big = [0xAAu8; 64];
    let n = pm.dump_locks(&mut big);
    assert_eq!(&big[..n], b"cpu_freq_max 1\napb 0\n");
    assert_eq!(big[n], 0);
    let mut small = [0xAAu8; 8];
    let n = pm.dump_locks(&mut small);
    assert!(n == 7 && &small[..7] == b"cpu_fre" && small[7] == 0);
    assert_eq!(pm.dump_locks(&mut []), 0);
    let mut one = [0xAAu8; 1];
    assert!(pm.dump_locks(&mut one) == 0 && one[0] == 0);
}
