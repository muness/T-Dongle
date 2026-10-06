//! The command replies that read the rest of the firmware: `status`, `pm`, `list`, `mode`, `use`, `display`. The formatting is `tdongle-serial`
//! (golden-tested against the C); this file gathers the values, once, into the typed snapshot the formatter takes.

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tdongle_nvs_format::mode::Mode;
use tdongle_serial::bridge_report::{self, Report, RingReport, RxClassReport, WifiTxReport};
use tdongle_serial::clock::Clock;
use tdongle_serial::pm_report;
use tdongle_serial::reply::{self, ListLine};
use tdongle_serial::status::{self, DisplayState, Prefs, Snapshot, Traffic};

use crate::console::{mgmt_write, mgmt_write_bytes};
use crate::sys::{heap, now_us64};
use crate::{VERSION, diag, pm, usb, wifi};

static DOWN_KBPS: AtomicU32 = AtomicU32::new(0);
static UP_KBPS: AtomicU32 = AtomicU32::new(0);

/// The control task's sampler publishes the last complete window's rates here (`ui.traffic.down_kbps` in C).
pub fn set_rates(down: u32, up: u32) {
    DOWN_KBPS.store(down, Ordering::Relaxed);
    UP_KBPS.store(up, Ordering::Relaxed);
}

/// The SNTP supervision state (`sntp_clock`): written by the manager, read by `status`.
pub static CLOCK: Mutex<Clock> = Mutex::new(Clock { synced: false, server: 0, restarts: 0, backoff_ms: 0, next_retry_ms: 0, retry_in_ms: 0 });

/// The display settings the device booted with (phase 1 only reads them).
pub static DISPLAY: std::sync::OnceLock<tdongle_nvs_format::ui_settings::UiSettings> = std::sync::OnceLock::new();

/// The `fmt::Write` sinks of the console never fail (they drop on a full queue, like C), so a formatting result carries no information.
fn infallible(result: core::fmt::Result) {
    debug_assert!(result.is_ok());
}

/// `status`.
pub fn status<W: Write>(out: &mut W) {
    let wifi = wifi::get();
    let (records, record_count) = diag::memory_records();
    let (saved, preferred, priorities) = match wifi.and_then(|w| w.lock_selection(Duration::from_millis(100))) {
        Some(selection) => {
            let mut priorities = [0u8; 8];
            for (p, slot) in priorities.iter_mut().zip(selection.meta.slot.iter()) {
                *p = slot.priority;
            }
            (selection.saved.count as u32, selection.meta.preferred.map(|p| p as u32), priorities)
        }
        None => (0, None, [0u8; 8]),
    };
    let clock = *CLOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let display = DISPLAY.get().copied().unwrap_or_default();
    let records_slice: &[tdongle_serial::memory_log::Record] = &records[..record_count];
    let snapshot = Snapshot {
        mode: status::Mode::Adapter,
        wifi_current: wifi.and_then(wifi::Wifi::current).map_or(-1, |c| c as i32),
        online: wifi.is_some_and(wifi::Wifi::online),
        firmware: VERSION,
        usb_mounted: usb::task::mounted(),
        usb_ready: usb::task::ready(),
        uptime_ms: now_us64() / 1000,
        free_heap: heap::free_heap_size(),
        temperature: diag::temperature(),
        clock,
        clock_valid: false, // bridge mode runs no SNTP: the wall clock is never set
        link: wifi.map(wifi::Wifi::link_info).unwrap_or_default(),
        events: wifi.map(wifi::Wifi::events).unwrap_or_default(),
        prefs: Prefs { saved, preferred, priorities: &priorities, roaming_assist: true },
        display: DisplayState { brightness: display.brightness, rotation: display.rotation, dim_seconds: display.dim_seconds, page: 0 },
        setup_ap_name: "",
        setup_seconds_left: 0,
        traffic: Traffic {
            counters: usb::net::TRAFFIC.read(),
            down_kbps: DOWN_KBPS.load(Ordering::Relaxed),
            up_kbps: UP_KBPS.load(Ordering::Relaxed),
            usb_resets: usb::task::bus_resets(),
            control_stack_free_bytes: crate::sys::task::current_stack_free(),
        },
        memory: &records_slice,
    };
    infallible(status::write_status(out, &snapshot));
    bridge_lines(out);
    // New line (additions never go onto an old one): which firmware answered, for A/B runs against the C image.
    infallible(write!(out, "rust_port phase=1 stored_mode={} running=wifi_bridge\r\n", crate::stored_mode().name()));
    // Memory made visible (rule 7 of ADR 0001): what Rust allocated, and the heap as the allocator sees it.
    let total = crate::alloc::total();
    infallible(write!(
        out,
        "rust_heap live={} peak={} allocs={} frees={} failed={} free_internal={} minimum_internal={} largest_block={}\r\n",
        total.live,
        total.peak,
        total.allocs,
        total.frees,
        total.failed,
        heap::free_internal(),
        heap::minimum_free_internal(),
        heap::largest_free_block()
    ));
}

fn bridge_lines<W: Write>(out: &mut W) {
    let Some(l2) = crate::bridge::stats() else { return };
    let ring = usb::ring::stats().unwrap_or_default();
    let rx = usb::net::rx_stats();
    let pins = wifi::pins::stats();
    let ring = RingReport {
        ring_bytes: ring.ring_bytes,
        high_water_slabs: ring.high_water_slabs,
        enqueued_frames: ring.enqueued_frames,
        sent_frames: ring.sent_frames,
        dropped_full: ring.dropped_full,
        dropped_link_down: ring.dropped_link_down,
        flushed_link_down: ring.flushed_link_down,
        grow_events: ring.grow_events,
        shrink_events: ring.shrink_events,
        grow_denied_heap: ring.grow_denied_heap,
        grow_denied_largest: ring.grow_denied_largest,
        max_bytes: ring.max_bytes,
        cold_starts: ring.cold_starts,
        cold_us_sum: ring.cold_us_sum,
        cold_us_max: ring.cold_us_max,
    };
    let rx = RxClassReport {
        ntbs: rx.ntbs,
        ntb_bytes: rx.ntb_bytes,
        ntb_max_bytes: rx.ntb_max_bytes,
        datagrams: rx.datagrams,
        dwell_us_sum: rx.dwell_us_sum,
        dwell_us_max: rx.dwell_us_max,
        holds: rx.holds,
        hold_us_sum: rx.hold_us_sum,
        hold_us_max: rx.hold_us_max,
    };
    let wifi_tx = WifiTxReport {
        installed: true,
        tx_done_cb: wifi::pins::tx_done_registered(),
        charged: pins.tx_charged,
        done: pins.tx_done,
        aborted: pins.tx_aborted,
        flushed: pins.tx_flushed,
        stale: pins.tx_stale,
        unmatched: pins.tx_unmatched,
        inflight: pins.tx_outstanding,
        high_water: pins.tx_high_water,
        refused_pool: pins.tx_refused_pool,
        refused_heap: pins.tx_refused_heap,
    };
    infallible(bridge_report::write_status_lines(out, &Report { l2: &l2, ring: &ring, rx: &rx, wifi_tx: &wifi_tx }));
}

/// `pm`.
pub fn pm<W: Write>(out: &mut W) {
    let status = pm::status();
    let power = pm_report::Power {
        scaling: status.scaling,
        configure_error: status.configure_error,
        cpu_mhz: status.cpu_mhz,
        max_mhz: status.max_mhz,
        min_mhz: status.min_mhz,
        lock_create_failures: status.lock_create_failures,
    };
    let locks: Vec<pm_report::Lock<'_>> = status
        .bursts()
        .iter()
        .map(|b| pm_report::Lock {
            name: b.name.as_str(),
            depth: b.depth,
            acquires: b.acquires,
            releases: b.releases,
            held_us: b.held_us,
            max_depth: b.max_depth,
            underflows: b.underflows,
            forced_releases: b.forced_releases,
            backend_failures: b.backend_failures,
            isr_rejects: b.isr_rejects,
        })
        .collect();
    // IDF's own lock table, on the heap briefly: the control task's stack has no room for 1 KB of table next to the formatting.
    let mut dump = vec![0u8; 1024];
    let length = pm::dump_locks(&mut dump);
    let text = core::str::from_utf8(&dump[..length]).ok().filter(|t| !t.is_empty());
    infallible(pm_report::write_report(out, &power, &locks, text));
}

/// `list`.
pub fn list<W: Write>(_out: &mut W) {
    let Some(wifi) = wifi::get() else { return };
    let Some(selection) = wifi.lock_selection(Duration::from_millis(100)) else {
        mgmt_write(reply::SETTINGS_BUSY);
        return;
    };
    let current = wifi.current();
    for (i, profile) in selection.saved.list().iter().enumerate() {
        let slot = &selection.meta.slot[i];
        let line = ListLine::new(i as u32, current == Some(i), slot.name_bytes(), profile.ssid_bytes(), slot.priority);
        mgmt_write_bytes(line.as_bytes());
    }
}

/// `display` without arguments.
pub fn display<W: Write>(out: &mut W) {
    let d = DISPLAY.get().copied().unwrap_or_default();
    infallible(reply::write_display(out, d.brightness, d.rotation, d.dim_seconds));
}

/// `mode NAME`. Phase 1 can run the Wi-Fi bridge only: `wifi_bridge` is saved (the one NVS write the port makes) and the device restarts;
/// `tailnet_gateway` is refused, not saved, so the board cannot be left configured for firmware that is not in this image.
pub fn mode(requested: Option<Mode>) {
    match requested {
        None => mgmt_write(reply::MODE_INVALID),
        Some(Mode::TailnetGateway) => mgmt_write("ERR Tailnet gateway mode is not part of this firmware yet; flash the C image\r\n"),
        Some(Mode::WifiBridge) => match crate::sys::nvs::write_u8(c"tn_settings", c"mode", Mode::WifiBridge.to_u8()) {
            Ok(()) => {
                mgmt_write(reply::MODE_SAVED);
                std::thread::sleep(Duration::from_millis(300));
                crate::sys::restart();
            }
            Err(error) => {
                log::error!("mode was not saved: {error}");
                mgmt_write(reply::MODE_NOT_SAVED);
            }
        },
    }
}

/// `use N`: switch to saved network N and keep it. The preference is not saved in phase 1 (read-only NVS), and the reply says so.
pub fn use_network(slot: i64) {
    let Some(wifi) = wifi::get() else {
        mgmt_write(reply::USE_INVALID);
        return;
    };
    let Some(mut selection) = wifi.lock_selection(Duration::from_millis(100)) else {
        mgmt_write(reply::SETTINGS_BUSY);
        return;
    };
    match wifi.use_profile(&mut selection, slot) {
        0 => {
            let mut text = String::new();
            infallible(reply::write_use_ok(&mut text, slot as i32, false));
            mgmt_write(&text);
        }
        -2 => mgmt_write(reply::USE_DRIVER_REFUSED),
        _ => mgmt_write(reply::USE_INVALID),
    }
}
