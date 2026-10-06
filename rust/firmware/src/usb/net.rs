//! The NCM network callbacks TinyUSB's class driver calls, and the hook on its transfer-complete handler.
//!
//! Port of the callback half of `components/esp_tinyusb/tinyusb_net.c` plus the traffic counting of `main/traffic_hooks.c` (which wrapped the
//! same two callbacks at link time; here they are the callbacks themselves, so no wrapper is needed for them).
//!
//! Receive path (host -> device), as ADR 0023 amendment 2 designs it: the class driver hands each datagram to [`tud_network_recv_cb`] from the
//! TinyUSB task and expects the glue to call `tud_network_recv_renew()` when it is ready for more. It also supports the glue REFUSING a datagram:
//! returning `false` leaves it (and the rest of its NTB) where it is, the class driver stops re-arming the OUT endpoint once its
//! `CFG_TUD_NCM_OUT_NTB_N` receive buffers are full, and the host sees NAKs: real backpressure, with the TinyUSB task never blocked. The datagram
//! is offered again by the next `tud_network_recv_renew()`, which [`rx_resume`] defers into the TinyUSB task.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

use esp_idf_svc::sys;
use tdongle_bridge::HostOutcome;
use tdongle_traffic::Counters as TrafficCounters;

use crate::sys::now_us;

/// Frames crossing the USB network interface in either direction (the status `traffic` line and the Traffic screen).
pub static TRAFFIC: TrafficCounters = TrafficCounters::new();

/// Receive-side evidence (`s_rx` of `tinyusb_net.c`; gated on the ring being enabled). A datagram's dwell is measured from the newest OUT NTB
/// to complete, which is when the class driver could first have handed it over: held datagrams show up as dwell and as hold time.
/// `datagrams / ntbs` is how many frames an NTB carries, i.e. how many frames the class driver's receive buffers can hold.
#[derive(Debug, Default)]
pub struct RxStats {
    ntbs: AtomicU32,
    ntb_bytes: AtomicU32,
    ntb_max_bytes: AtomicU32,
    datagrams: AtomicU32,
    dwell_us_sum: AtomicU32,
    dwell_us_max: AtomicU32,
    holds: AtomicU32,
    hold_us_sum: AtomicU32,
    hold_us_max: AtomicU32,
    /// TinyUSB task only (relaxed atomics keep it safe to read).
    ntb_us: AtomicU32,
    hold_since_us: AtomicU32,
}

/// A snapshot of [`RxStats`] (`tinyusb_net_rx_stats_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxSnapshot {
    /// OUT NTBs completed.
    pub ntbs: u32,
    /// Their bytes.
    pub ntb_bytes: u32,
    /// The largest.
    pub ntb_max_bytes: u32,
    /// Datagrams offered to the receive callback (a held one is offered again).
    pub datagrams: u32,
    /// Per offer: time since the newest OUT NTB completed, summed.
    pub dwell_us_sum: u32,
    /// Largest such dwell.
    pub dwell_us_max: u32,
    /// Hold episodes.
    pub holds: u32,
    /// How long each kept the host waiting for room, summed.
    pub hold_us_sum: u32,
    /// Longest.
    pub hold_us_max: u32,
}

impl RxStats {
    const fn new() -> Self {
        Self {
            ntbs: AtomicU32::new(0),
            ntb_bytes: AtomicU32::new(0),
            ntb_max_bytes: AtomicU32::new(0),
            datagrams: AtomicU32::new(0),
            dwell_us_sum: AtomicU32::new(0),
            dwell_us_max: AtomicU32::new(0),
            holds: AtomicU32::new(0),
            hold_us_sum: AtomicU32::new(0),
            hold_us_max: AtomicU32::new(0),
            ntb_us: AtomicU32::new(0),
            hold_since_us: AtomicU32::new(0),
        }
    }

    fn snapshot(&self) -> RxSnapshot {
        RxSnapshot {
            ntbs: self.ntbs.load(Relaxed),
            ntb_bytes: self.ntb_bytes.load(Relaxed),
            ntb_max_bytes: self.ntb_max_bytes.load(Relaxed),
            datagrams: self.datagrams.load(Relaxed),
            dwell_us_sum: self.dwell_us_sum.load(Relaxed),
            dwell_us_max: self.dwell_us_max.load(Relaxed),
            holds: self.holds.load(Relaxed),
            hold_us_sum: self.hold_us_sum.load(Relaxed),
            hold_us_max: self.hold_us_max.load(Relaxed),
        }
    }
}

static RX: RxStats = RxStats::new();

/// The receive-side counters (`tinyusb_net_rx_stats`).
pub fn rx_stats() -> RxSnapshot {
    RX.snapshot()
}

/// Whether the evidence counters run (the C gates them on the transmit ring being enabled, so a build without the ring makes no extra clock
/// reads).
fn evidence_on() -> bool {
    super::ring::enabled()
}

/// `tud_network_recv_cb`: one datagram from the host. Never blocks, allocates or calls into the Wi-Fi driver (ADR 0023).
///
/// Returns `false` to HOLD the datagram: the class driver keeps it and the host is NAKed until [`rx_resume`].
#[unsafe(no_mangle)]
pub extern "C" fn tud_network_recv_cb(src: *const u8, size: u16) -> bool {
    let stats = evidence_on();
    let mut now = 0;
    if stats {
        now = now_us();
        let dwell = now.wrapping_sub(RX.ntb_us.load(Relaxed));
        RX.datagrams.fetch_add(1, Relaxed);
        RX.dwell_us_sum.fetch_add(dwell, Relaxed);
        RX.dwell_us_max.fetch_max(dwell, Relaxed);
    }
    // SAFETY: TinyUSB passes `size` readable bytes at `src`, valid for the duration of this call.
    let frame = unsafe { core::slice::from_raw_parts(src, usize::from(size)) };
    if crate::bridge::host_frame(frame) == HostOutcome::Hold {
        if stats && RX.hold_since_us.load(Relaxed) == 0 {
            RX.hold_since_us.store(if now == 0 { 1 } else { now }, Relaxed);
            RX.holds.fetch_add(1, Relaxed);
        }
        return false; // no renew: that is what would deliver it again
    }
    if stats {
        let since = RX.hold_since_us.load(Relaxed);
        if since != 0 {
            // the held datagram has been taken: how long the host was kept waiting for room
            let held = now.wrapping_sub(since);
            RX.hold_us_sum.fetch_add(held, Relaxed);
            RX.hold_us_max.fetch_max(held, Relaxed);
            RX.hold_since_us.store(0, Relaxed);
        }
    }
    TRAFFIC.count_up(u32::from(size));
    // SAFETY: called from the TinyUSB task, as the class driver requires.
    unsafe { sys::tud_network_recv_renew() };
    true
}

static RENEW_PENDING: AtomicBool = AtomicBool::new(false);

extern "C" fn do_renew(_context: *mut c_void) {
    RENEW_PENDING.store(false, Relaxed); // before renewing: a hold that happens during it asks again
    // SAFETY: runs in the TinyUSB task (deferred by `rx_resume`).
    unsafe { sys::tud_network_recv_renew() };
}

/// A refused datagram is waiting in the class driver: offer it again, in the TinyUSB task. Any task may ask; asks coalesce. On a USB reset or a
/// detach the class driver re-initialises its receive state, so a renew that arrives afterwards finds nothing pending and does nothing, and the
/// next SET_INTERFACE renews by itself: a deferred renew cannot wedge the endpoint.
///
/// May wait for TinyUSB's event queue like any `usbd_defer_func` caller, so call it from a worker that holds no lock, not from a callback.
pub fn rx_resume() {
    if !RENEW_PENDING.swap(true, Relaxed) {
        // SAFETY: `do_renew` is a valid callback; the context is unused.
        unsafe { sys::usbd_defer_func(Some(do_renew), core::ptr::null_mut(), false) };
    }
}

/// `tud_network_xmit_cb`: copy one datagram into the IN transfer block. `reference` is the frame pointer the ring passed to `tud_network_xmit`
/// (the slab holding it stays valid until `tud_network_xmit` returns: the copy is synchronous), `arg` its length.
#[unsafe(no_mangle)]
pub extern "C" fn tud_network_xmit_cb(dst: *mut u8, reference: *mut c_void, arg: u16) -> u16 {
    // SAFETY: `dst` has room for `arg` bytes (TinyUSB checked `tud_network_can_xmit(arg)` first) and `reference` points at `arg` readable bytes;
    // the two never overlap (a slab in the ring versus an NTB).
    unsafe { core::ptr::copy_nonoverlapping(reference.cast::<u8>().cast_const(), dst, usize::from(arg)) };
    if arg != 0 {
        TRAFFIC.count_down(u32::from(arg));
    }
    arg
}

/// `tud_network_init_cb`: the class driver (re)initialised. The bridge has nothing to do here.
#[unsafe(no_mangle)]
pub extern "C" fn tud_network_init_cb() {}

unsafe extern "C" {
    /// The NCM class driver's own transfer-complete handler (`--wrap=netd_xfer_cb`, see build.rs).
    fn __real_netd_xfer_cb(rhport: u8, ep_addr: u8, result: sys::xfer_result_t, xferred_bytes: u32) -> bool;
}

/// Linker wrap of the NCM class driver's transfer-complete handler: runs in the TinyUSB task. An OUT NTB is stamped BEFORE the class driver
/// offers its datagrams (the receive statistics); an IN completion refills the NTB that just came back (the transmit ring's drain).
#[unsafe(no_mangle)]
pub extern "C" fn __wrap_netd_xfer_cb(rhport: u8, ep_addr: u8, result: sys::xfer_result_t, xferred_bytes: u32) -> bool {
    let out = ep_addr & 0x80 == 0;
    if out && evidence_on() {
        RX.ntb_us.store(now_us(), Relaxed);
        RX.ntbs.fetch_add(1, Relaxed);
        RX.ntb_bytes.fetch_add(xferred_bytes, Relaxed);
        RX.ntb_max_bytes.fetch_max(xferred_bytes, Relaxed);
    }
    // SAFETY: forwards to the real handler with the arguments TinyUSB gave us.
    let handled = unsafe { __real_netd_xfer_cb(rhport, ep_addr, result, xferred_bytes) };
    if !out {
        super::ring::on_in_complete(xferred_bytes);
    }
    handled
}

/// Tell the host the carrier changed (`tud_network_link_state`).
pub fn link_state(up: bool) {
    // SAFETY: TinyUSB serialises this against its own task; the C bridge calls it from the event task the same way.
    unsafe { sys::tud_network_link_state(0, up) };
}
