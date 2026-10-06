//! The serial `status` report: the port of `serial_status()` in `serial_setup.inc`.
//!
//! [`write_status`] writes, in this order, exactly what the C function sends through `mgmt_write`:
//!
//! 1. one block of five lines: `mode=... trial=0 active=... wifi=... rssi=... usb_enumerated=... usb_transport_ready=...
//!    host_interface_ready=unknown internet=not_checked`, `firmware=`, `uptime_ms= free_heap=`, `chip_temperature ...`,
//!    `chip_temperature_detail ...` (one `snprintf`: see below)
//! 2. `clock ...`
//! 3. `wifi_link ...` (omitted when it does not fit, which the 448 byte buffer makes unreachable)
//! 4. `wifi_prefs ...`
//! 5. `display ...`
//! 6. `setup ...`
//! 7. `traffic ...`
//! 8. one `memory_pressure ...` line per recorded heap record, oldest first
//!
//! In bridge mode the command task then appends the `bridge_*` lines ([`crate::bridge_report`]).
//!
//! # The Android contract
//!
//! The Android app parses the first lines with end-anchored patterns. Additions therefore go on new lines, never onto an old one: the
//! `chip_temperature` line must stay `chip_temperature valid=[01] current_tenths=N peak_tenths=N sampled_uptime_ms=N errors=N` with nothing
//! appended (its extra fields live on `chip_temperature_detail`), and the first line keeps its field order.
//!
//! # `printf` fidelity
//!
//! Every line is formatted into a 448 byte buffer in C and silently cut at 447 bytes if longer. [`write_status`] reproduces that cut. The
//! first block is one buffer, so a very long firmware version would cut *it* mid-line; with realistic versions the block is under 420 bytes.
//! Integer conversions follow the C ones: `%lu` is a `u32` here (a 32 bit `long` on the target), `%ld` an `i32`, `%llu` a `u64`.

use crate::clock::Clock;
use crate::memory_log::RecordSource;
use crate::text::emit;
use crate::wifi_link::{self, Events, Info};
use core::fmt;
use tdongle_traffic::Reading;

/// `TDONGLE_TEMPERATURE_STEP_TENTHS`: the sensor reports whole degrees.
pub const TEMPERATURE_STEP_TENTHS: i32 = 10;

/// `char reply[448]` of `serial_status`.
pub const REPLY_MAX: usize = 448;

/// The value of `mode=` and (with [`Mode::Setup`]) of `setup active=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The setup access point is up (`setup_active`): `mode=setup`, whatever the stored mode is.
    Setup,
    /// Tailnet gateway: `mode=tailnet`.
    Tailnet,
    /// Wi-Fi bridge: `mode=adapter` (the name Android knows).
    Adapter,
}

impl Mode {
    /// The text of `mode=`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Tailnet => "tailnet",
            Self::Adapter => "adapter",
        }
    }
}

/// `tdongle_temperature`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Temperature {
    /// The latest sample succeeded.
    pub valid: bool,
    /// Latest reading, tenths of a degree C (re-read by every sample, never a peak).
    pub current_tenths: i32,
    /// Highest reading since boot.
    pub peak_tenths: i32,
    /// Uptime of the latest successful sample (0 before any).
    pub sampled_at_ms: u32,
    /// Failed samples.
    pub errors: u32,
    /// Successful samples since boot.
    pub samples: u32,
    /// Uptime when `current` last differed from the sample before it.
    pub changed_at_ms: u32,
    /// Snapshot time minus `sampled_at_ms`; `u32::MAX` before the first sample.
    pub age_ms: u32,
}

/// What the `wifi_prefs` line reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefs<'a> {
    /// Saved networks (`wifi_saved.count`).
    pub saved: u32,
    /// Preferred network, 0-based (`wifi_meta.preferred`), `None` when there is none (printed `0`; a slot prints as `index + 1`).
    pub preferred: Option<u32>,
    /// Priority of each saved network in order (`wifi_meta.slot[i].priority`). Like the C loop, only the first `saved` are printed, and
    /// an entry missing from the slice reads as 0 (an unused slot of the C array).
    pub priorities: &'a [u8],
    /// `wifi_roaming_assist()`.
    pub roaming_assist: bool,
}

/// The `display` line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayState {
    /// Backlight, percent.
    pub brightness: u8,
    /// 0 or 1.
    pub rotation: u8,
    /// Seconds before the screen dims.
    pub dim_seconds: u16,
    /// The page on screen (`ui.page`).
    pub page: u32,
}

/// The `traffic` line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    /// `traffic_read()`.
    pub counters: Reading,
    /// Rate of the last complete window, down (`ui.traffic.down_kbps`).
    pub down_kbps: u32,
    /// Rate of the last complete window, up.
    pub up_kbps: u32,
    /// `gateway_usb_health(8)`.
    pub usb_resets: u32,
    /// The control task's lowest free stack so far (`uxTaskGetStackHighWaterMark`): `status` runs on it.
    pub control_stack_free_bytes: u32,
}

/// Everything `serial_status` reads, as plain values taken by the firmware in one go.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot<'a> {
    /// `setup_active ? setup : tailnet ? tailnet : adapter`; also decides `setup active=`.
    pub mode: Mode,
    /// `wifi_current`: index of the saved network in use, -1 for none; printed as `active=<n + 1>`.
    pub wifi_current: i32,
    /// The uplink is up: `wifi=up`, else `wifi=joining`.
    pub online: bool,
    /// `GATEWAY_VERSION`.
    pub firmware: &'a str,
    /// `tud_mounted()`.
    pub usb_mounted: bool,
    /// `tud_ready()`.
    pub usb_ready: bool,
    /// `esp_timer_get_time() / 1000`.
    pub uptime_ms: u64,
    /// `esp_get_free_heap_size()`.
    pub free_heap: u32,
    /// The chip temperature.
    pub temperature: Temperature,
    /// The SNTP supervisor (`sntp_clock`).
    pub clock: Clock,
    /// `ml_derp_clock_valid()`: the wall clock is set.
    pub clock_valid: bool,
    /// `wifi_link_read()`.
    pub link: Info,
    /// `wifi_link_stats` (also the source of `roams=`).
    pub events: Events,
    /// Saved networks and preferences.
    pub prefs: Prefs<'a>,
    /// The front panel settings.
    pub display: DisplayState,
    /// The setup access point name, shown only while [`Mode::Setup`] (otherwise the line says `ap=-`).
    pub setup_ap_name: &'a str,
    /// `setup_session_seconds_left(...)`.
    pub setup_seconds_left: u32,
    /// Traffic counters and rates.
    pub traffic: Traffic,
    /// The heap low-water records, oldest first.
    pub memory: &'a dyn RecordSource,
}

/// Write the whole `status` report (see the module documentation for the order).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_status<W: fmt::Write>(w: &mut W, s: &Snapshot<'_>) -> fmt::Result {
    let mut reply = [0u8; REPLY_MAX];
    let t = &s.temperature;
    let setup = s.mode == Mode::Setup;
    emit(
        w,
        &mut reply,
        format_args!(
            "mode={} trial=0 active={} wifi={} rssi={} usb_enumerated={} usb_transport_ready={} host_interface_ready=unknown \
             internet=not_checked\r\nfirmware={}\r\nuptime_ms={} free_heap={}\r\nchip_temperature valid={} current_tenths={} \
             peak_tenths={} sampled_uptime_ms={} errors={}\r\nchip_temperature_detail age_ms={} samples={} changed_uptime_ms={} \
             step_tenths={}\r\n",
            s.mode.name(),
            s.wifi_current.wrapping_add(1),
            if s.online { "up" } else { "joining" },
            s.link.rssi_text(),
            u8::from(s.usb_mounted),
            u8::from(s.usb_ready),
            s.firmware,
            s.uptime_ms,
            s.free_heap,
            u8::from(t.valid),
            t.current_tenths,
            t.peak_tenths,
            t.sampled_at_ms,
            t.errors,
            t.age_ms,
            t.samples,
            t.changed_at_ms,
            TEMPERATURE_STEP_TENTHS
        ),
    )?;
    emit(
        w,
        &mut reply,
        format_args!(
            "clock={} valid={} sntp_restarts={} server={} retry_in_ms={}\r\n",
            s.clock.state(s.clock_valid, s.online),
            u8::from(s.clock_valid),
            s.clock.restarts,
            s.clock.server_name(),
            s.clock.retry_in_ms
        ),
    )?;
    if let Some(n) = wifi_link::line(&mut reply, &s.link, &s.events) {
        // The line is ASCII and NUL free.
        w.write_str(core::str::from_utf8(&reply[..n]).unwrap_or(""))?;
    }
    // The v0.1.1 front panel, one new line each (additions never go onto a line a client already parses).
    let mut priorities = [0u8; 8 * 4 + 1];
    let used = priorities_text(&mut priorities, s.prefs.saved, s.prefs.priorities);
    let priorities = core::str::from_utf8(&priorities[..used]).unwrap_or("");
    emit(
        w,
        &mut reply,
        format_args!(
            "wifi_prefs saved={} preferred={} priorities={} roaming_assist={} roams={}\r\n",
            s.prefs.saved,
            s.prefs.preferred.map_or(0, |p| p.wrapping_add(1)),
            if priorities.is_empty() { "-" } else { priorities },
            u8::from(s.prefs.roaming_assist),
            s.events.roams
        ),
    )?;
    emit(
        w,
        &mut reply,
        format_args!(
            "display brightness={} rotation={} dim_seconds={} page={}\r\n",
            s.display.brightness, s.display.rotation, s.display.dim_seconds, s.display.page
        ),
    )?;
    emit(
        w,
        &mut reply,
        format_args!("setup active={} ap={} seconds_left={}\r\n", u8::from(setup), if setup { s.setup_ap_name } else { "-" }, s.setup_seconds_left),
    )?;
    let c = &s.traffic.counters;
    emit(
        w,
        &mut reply,
        format_args!(
            "traffic down_bytes={} up_bytes={} down_frames={} up_frames={} down_kbps={} up_kbps={} usb_resets={} \
             control_stack_free_bytes={}\r\n",
            c.down_bytes,
            c.up_bytes,
            c.down_frames,
            c.up_frames,
            s.traffic.down_kbps,
            s.traffic.up_kbps,
            s.traffic.usb_resets,
            s.traffic.control_stack_free_bytes
        ),
    )?;
    for i in 0..s.memory.count() {
        // C: `tdongle_memory_get(i)` of a vanished record reads as all zeros.
        let m = s.memory.get(i).unwrap_or_default();
        emit(
            w,
            &mut reply,
            format_args!(
                "memory_pressure uptime_ms={} operation={} requested={} free={} minimum={} largest={} failed={}\r\n",
                m.uptime_ms, m.operation, m.requested, m.free_bytes, m.minimum_bytes, m.largest_bytes, m.failed
            ),
        )?;
    }
    Ok(())
}

/// The `priorities=` value: `"80,30"` into a 33 byte buffer, by the C loop (`i < count && used + 4 < sizeof(buffer)`). Returns its length.
fn priorities_text(buffer: &mut [u8; 33], count: u32, priorities: &[u8]) -> usize {
    use core::fmt::Write;
    let mut used = 0;
    let mut i = 0u32;
    while i < count && used + 4 < buffer.len() {
        let priority = priorities.get(i as usize).copied().unwrap_or(0);
        let mut tail = crate::text::Counting::new(&mut buffer[used..]);
        // Cannot fail: `Counting` accepts everything and the guard above leaves room for `,100`.
        let _ = write!(tail, "{}{}", if i == 0 { "" } else { "," }, priority);
        used += tail.total();
        i += 1;
    }
    used
}
