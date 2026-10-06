//! C `lcd_view` and `lcd_compose` / `lcd_compose_rows` / `lcd_format_*`, plus `traffic_format_*` of `main/traffic.c`.

use crate::fmt::{cstr, snprintf};
use crate::state::LcdState;
use crate::{LCD_BARS, LCD_PAGES, LCD_ROWS, ROW_BYTES};

/// `LCD_LAYOUT_STATUS`: title, detail, hint, extra, footer.
pub const LAYOUT_STATUS: u8 = 0;
/// `LCD_LAYOUT_ROWS`: five rows, row 0 the heading (menu, Traffic, Health, Setup).
pub const LAYOUT_ROWS: u8 = 1;

/// Size of the shared text area (the C union: `max(14 + 4 * 27, 5 * 27)`).
pub const TEXT_BYTES: usize = LCD_ROWS * ROW_BYTES;
/// Offsets of the status layout fields in [`View::text`] (`char title[14], detail[27], hint[27], extra[27], footer[27]`).
pub const TITLE: usize = 0;
/// See [`TITLE`].
pub const DETAIL: usize = 14;
/// See [`TITLE`].
pub const HINT: usize = 41;
/// See [`TITLE`].
pub const EXTRA: usize = 68;
/// See [`TITLE`].
pub const FOOTER: usize = 95;
const TITLE_CAP: usize = 14;

/// C `lcd_view`, byte for byte (170 bytes, no padding): `text` is the union of the status layout and `row[5][27]`.
///
/// `==` is `memcmp(a, b, sizeof(lcd_view)) == 0`, which is what the C driver uses to skip an unchanged frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct View {
    /// The text area; use the accessors.
    pub text: [u8; TEXT_BYTES],
    /// Traffic graph bars, 0..20 (anything larger is drawn as 20; 0 is drawn as 1).
    pub bars: [u8; LCD_BARS],
    /// Heading (rows layout) or title (status layout) drawn in the attention colour.
    pub attention: bool,
    /// [`LAYOUT_STATUS`] or [`LAYOUT_ROWS`] (any other value renders as the status layout, like the C).
    pub layout: u8,
    /// Bars drawn (at most `LCD_BARS`).
    pub bar_count: u8,
}

impl View {
    /// `memset(view, 0, sizeof *view)`.
    pub const ZERO: Self = Self { text: [0; TEXT_BYTES], bars: [0; LCD_BARS], attention: false, layout: 0, bar_count: 0 };

    /// A view that is never equal to a composed one (C `memset(&previous, 0xff, sizeof previous)`: forces the next draw).
    pub const POISONED: Self = Self { text: [0xff; TEXT_BYTES], bars: [0xff; LCD_BARS], attention: true, layout: 0xff, bar_count: 0xff };

    /// The `title` field (status layout) as a C string.
    #[must_use]
    pub fn title(&self) -> &[u8] {
        cstr(&self.text[TITLE..TITLE + TITLE_CAP])
    }
    /// The `detail` field.
    #[must_use]
    pub fn detail(&self) -> &[u8] {
        cstr(&self.text[DETAIL..DETAIL + ROW_BYTES])
    }
    /// The `hint` field.
    #[must_use]
    pub fn hint(&self) -> &[u8] {
        cstr(&self.text[HINT..HINT + ROW_BYTES])
    }
    /// The `extra` field.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        cstr(&self.text[EXTRA..EXTRA + ROW_BYTES])
    }
    /// The `footer` field.
    #[must_use]
    pub fn footer(&self) -> &[u8] {
        cstr(&self.text[FOOTER..FOOTER + ROW_BYTES])
    }
    /// `row[i]` as a C string (rows layout; `i < LCD_ROWS`).
    #[must_use]
    pub fn row(&self, i: usize) -> &[u8] {
        cstr(&self.text[i * ROW_BYTES..(i + 1) * ROW_BYTES])
    }
    fn field(&mut self, off: usize, cap: usize) -> &mut [u8] {
        &mut self.text[off..off + cap]
    }
    fn row_mut(&mut self, i: usize) -> &mut [u8] {
        self.field(i * ROW_BYTES, ROW_BYTES)
    }
}

impl Default for View {
    fn default() -> Self {
        Self::ZERO
    }
}

/// C `lcd_format_duration`: "45s", "12m05s", "3h12m", "2d04h", through `snprintf(out, size, ...)` (`size` is `out.len()`).
pub fn format_duration(out: &mut [u8], s: u32) {
    let mut text = [0u8; 24];
    snprintf(&mut text, |w| {
        if s < 60 {
            w.u(u64::from(s)).s("s");
        } else if s < 3600 {
            w.u(u64::from(s / 60)).s("m").u02(s % 60);
        } else if s < 86400 {
            w.u(u64::from(s / 3600)).s("h").u02(s % 3600 / 60);
        } else {
            w.u(u64::from(s / 86400)).s("d").u02(s % 86400 / 3600);
        }
    });
    snprintf(out, |w| {
        w.b(&text);
    });
}

/// C `lcd_format_count`: "123456", "1234k", "1234M": at most 7 characters.
pub fn format_count(out: &mut [u8], n: u64) {
    let mut text = [0u8; 24];
    snprintf(&mut text, |w| {
        if n < 1_000_000 {
            w.u(n);
        } else if n < 1_000_000_000 {
            w.u(u64::from((n / 1000) as u32)).s("k");
        } else {
            let m = if n / 1_000_000 > 999_999 { 999_999 } else { n / 1_000_000 };
            w.u(u64::from(m as u32)).s("M");
        }
    });
    snprintf(out, |w| {
        w.b(&text);
    });
}

/// C `traffic_format_mbps`: "1.23" (kbit/s to Mbit/s, two decimals, truncated).
pub fn format_mbps(out: &mut [u8], kbps: u32) {
    snprintf(out, |w| {
        w.u(u64::from(kbps / 1000)).s(".").u02(kbps % 1000 / 10);
    });
}

/// C `traffic_format_megabytes`: "12.3" below 100 MB, else whole megabytes (the C truncates to `unsigned`).
pub fn format_megabytes(out: &mut [u8], bytes: u64) {
    let tenths = bytes / 100_000;
    snprintf(out, |w| {
        if tenths >= 1000 {
            w.u(u64::from((tenths / 10) as u32));
        } else {
            w.u(u64::from((tenths / 10) as u32)).s(".").u(u64::from((tenths % 10) as u32));
        }
    });
}

/// The joined network and its signal: "HomeNet -57dBm".
fn signal_line(s: &LcdState, out: &mut [u8]) {
    // out[0]=0
    out[0] = 0;
    if !s.wifi {
        return;
    }
    let mut level = [0u8; 12];
    if s.rssi_valid {
        let r = if s.rssi > 0 {
            0
        } else if s.rssi < -127 {
            -127
        } else {
            s.rssi
        };
        snprintf(&mut level, |w| {
            w.i(r).s("dBm");
        });
    }
    let ssid = cstr(&s.ssid);
    let lvl = cstr(&level);
    if !ssid.is_empty() && !lvl.is_empty() {
        snprintf(out, |w| {
            w.bn(ssid, 26 - 1 - lvl.len()).s(" ").b(lvl);
        });
    } else if !ssid.is_empty() {
        snprintf(out, |w| {
            w.bn(ssid, 26);
        });
    } else if !lvl.is_empty() {
        snprintf(out, |w| {
            w.s("Signal ").b(lvl);
        });
    }
}

fn put(dst: &mut [u8], text: &str) {
    snprintf(dst, |w| {
        w.s(text);
    });
}

fn compose_connection(s: &LcdState, version: &str, v: &mut View) {
    let suspended = s.usb_configured && s.usb_suspended;
    let usb_wait = if suspended { "USB suspended" } else { "Waiting for USB host" };
    let (title, mut detail, mut hint);
    if s.installing {
        (title, detail, hint) = ("INSTALLING", "Installing firmware", "Keep USB plugged in");
    } else if s.starting {
        (title, detail, hint) = ("STARTING", "Starting dongle services", "Please wait");
    } else if s.recovery {
        (title, detail, hint) = ("RECOVERY", "App: Overview", "Tap Restart services");
        v.attention = true;
    } else if !s.wifi {
        title = if s.saved_wifi { "JOINING WI-FI" } else { "SET UP WI-FI" };
        detail = if s.saved_wifi { "Trying saved Wi-Fi" } else { "App: Networks" };
        hint = if s.saved_wifi { "App: Networks to change" } else { "Add a 2.4 GHz network" };
        if s.bridge && !s.saved_wifi {
            detail = "Hold button: setup AP";
            hint = "or muness.com/T-Dongle";
        } else if !s.saved_wifi {
            detail = "Hold button: setup AP";
            hint = "or App: Networks";
        }
    } else if s.bridge {
        (title, detail) = ("WI-FI BRIDGE", "Wi-Fi connected");
        hint = if s.usb { "USB host connected" } else { usb_wait };
    } else if s.login != 0 {
        (title, detail, hint) = ("APPROVE LOGIN", "App: Networks - Sign in", "Approve in your browser");
    } else if s.ready != 0 {
        (title, detail) = ("TAILNET READY", "Wi-Fi connected");
        hint = if !s.usb {
            usb_wait
        } else if s.ready < s.enabled {
            "App: Networks for details"
        } else {
            "USB routing is ready"
        };
    } else if s.enabled == 0 {
        title = if s.saved != 0 { "TAILNET OFF" } else { "ADD A TAILNET" };
        detail = if s.saved != 0 { "Wi-Fi connected" } else { "App: Networks" };
        hint = if s.saved != 0 { "App: Networks - Reconnect" } else { "Sign in with Tailscale" };
    } else {
        title = if s.failed != 0 { "RETRYING" } else { "CONNECTING" };
        detail = if s.failed != 0 { "Tailnet connection failed" } else { "Joining your tailnet" };
        hint = if s.failed != 0 { "App: Networks for details" } else { "Please wait" };
        v.attention = s.failed > 0;
    }
    put(v.field(TITLE, TITLE_CAP), title);
    put(v.field(DETAIL, ROW_BYTES), detail);
    put(v.field(HINT, ROW_BYTES), hint);
    if !s.bridge && s.ready != 0 && !s.recovery && !s.installing && !s.starting && s.login == 0 && s.wifi {
        snprintf(v.field(DETAIL, ROW_BYTES), |w| {
            w.u(u64::from(s.ready.min(999))).s(" OF ").u(u64::from(s.enabled.min(999))).s(" TAILNET");
            w.s(if s.enabled == 1 { "" } else { "S" }).s(" READY");
        });
    }
    if !s.installing && !s.starting && !s.recovery {
        signal_line(s, v.field(EXTRA, ROW_BYTES));
    }
    snprintf(v.field(FOOTER, ROW_BYTES), |w| {
        w.s("v").bn(version.as_bytes(), 10).s("  USB ");
        w.s(if s.usb {
            "READY"
        } else if suspended {
            "SUSPENDED"
        } else {
            "NOT READY"
        });
    });
}

fn compose_setup_ap(s: &LcdState, version: &str, v: &mut View) {
    put(v.field(TITLE, TITLE_CAP), "SETUP WI-FI");
    snprintf(v.field(DETAIL, ROW_BYTES), |w| {
        w.s("Join ").bn(&s.ap_ssid, 20);
    });
    put(v.field(HINT, ROW_BYTES), "Then open 192.168.4.1");
    let left = s.setup_seconds_left.min(5999);
    snprintf(v.field(EXTRA, ROW_BYTES), |w| {
        w.s("No password. Closes ").u(u64::from(left / 60)).s(":").u02(left % 60);
    });
    snprintf(v.field(FOOTER, ROW_BYTES), |w| {
        w.s("v").bn(version.as_bytes(), 10).s("  Hold: menu");
    });
}

fn compose_traffic(s: &LcdState, v: &mut View) {
    v.layout = LAYOUT_ROWS;
    put(v.row_mut(0), "TRAFFIC");
    let (mut down, mut up) = ([0u8; 12], [0u8; 12]);
    format_mbps(&mut down, s.down_kbps);
    format_mbps(&mut up, s.up_kbps);
    snprintf(v.row_mut(1), |w| {
        w.s("D ").bn(&down, 6).s(" U ").bn(&up, 6).s(" Mb/s");
    });
    let (mut down_mb, mut up_mb) = ([0u8; 16], [0u8; 16]);
    format_megabytes(&mut down_mb, s.down_bytes);
    format_megabytes(&mut up_mb, s.up_bytes);
    snprintf(v.row_mut(2), |w| {
        w.s("D ").bn(&down_mb, 8).s(" U ").bn(&up_mb, 8).s(" MB");
    });
    let (mut down_frames, mut up_frames) = ([0u8; 10], [0u8; 10]);
    format_count(&mut down_frames, s.down_frames);
    format_count(&mut up_frames, s.up_frames);
    snprintf(v.row_mut(3), |w| {
        w.s("Frames D ").bn(&down_frames, 7).s(" U ").bn(&up_frames, 7);
    });
    v.bars = s.bars;
    v.bar_count = LCD_BARS as u8;
}

fn compose_health(s: &LcdState, v: &mut View) {
    let view = s.health_view % 3;
    v.layout = LAYOUT_ROWS;
    snprintf(v.row_mut(0), |w| {
        w.s("HEALTH ").u(u64::from(view + 1)).s("/3");
    });
    if view == 0 {
        let (mut up, mut wifi) = ([0u8; 10], [0u8; 10]);
        format_duration(&mut up, s.uptime_s);
        format_duration(&mut wifi, s.wifi_up_s);
        snprintf(v.row_mut(1), |w| {
            w.s("Up ").bn(&up, 8).s(" WiFi ").bn(&wifi, 8);
        });
        snprintf(v.row_mut(2), |w| {
            w.s("Joins ").u(u64::from(s.connects)).s(" Reason ").u(u64::from(s.last_reason));
        });
        snprintf(v.row_mut(3), |w| {
            w.s("USB resets ").u(u64::from(s.usb_resets));
        });
    } else if view == 1 {
        snprintf(v.row_mut(1), |w| {
            w.s("Heap ").u(u64::from(s.heap_free));
        });
        snprintf(v.row_mut(2), |w| {
            w.s("Min heap ").u(u64::from(s.heap_min));
        });
        snprintf(v.row_mut(3), |w| {
            w.s("Largest ").u(u64::from(s.heap_largest)).s(" Rst ").u(u64::from(s.reset_reason));
        });
    } else {
        snprintf(v.row_mut(1), |w| {
            w.s("Session boots ").u(u64::from(s.boots));
        });
        snprintf(v.row_mut(2), |w| {
            w.s("WDT ").u(u64::from(s.watchdogs)).s(" Panic ").u(u64::from(s.panics));
        });
        put(v.row_mut(3), if s.recovery { "Recovery: services off" } else { "No recovery needed" });
        v.attention = s.recovery;
    }
    put(v.row_mut(4), "Details rotate every 4s");
}

fn compose_setup_page(s: &LcdState, v: &mut View) {
    v.layout = LAYOUT_ROWS;
    put(v.row_mut(0), "SETUP / NETWORKS");
    if s.active_slot != 0 {
        snprintf(v.row_mut(1), |w| {
            w.u(u64::from(s.active_slot % 10)).s(" ").bn(&s.active_name, 22);
        });
    } else {
        put(v.row_mut(1), if s.saved_wifi { "No network joined" } else { "No Wi-Fi saved" });
    }
    put(v.row_mut(2), if s.bridge { "Mode: Wi-Fi bridge" } else { "Mode: tailnet gateway" });
    put(v.row_mut(3), "Hold to open menu");
    put(v.row_mut(4), "Hold BOOT at plug: ROM");
}

/// C `lcd_compose`: builds `view` from `state`; `view` is zeroed first (so `==` between two composes of equal states holds, and the
/// padding semantics of the C `memcmp` are kept). `version` is the firmware version string (`GATEWAY_VERSION`), cut at 10 characters.
pub fn compose_into(state: &LcdState, version: &str, view: &mut View) {
    *view = View::ZERO;
    let overlay = state.installing || state.starting;
    if state.setup && !overlay {
        compose_setup_ap(state, version, view);
        return;
    }
    let page = if state.page < LCD_PAGES { state.page } else { 0 };
    if overlay || page == 0 {
        compose_connection(state, version, view);
    } else if page == 1 {
        compose_traffic(state, view);
    } else if page == 2 {
        compose_health(state, view);
    } else {
        compose_setup_page(state, view);
    }
}

/// [`compose_into`] returning the view.
#[must_use]
pub fn compose(state: &LcdState, version: &str) -> View {
    let mut v = View::ZERO;
    compose_into(state, version, &mut v);
    v
}

/// C `lcd_compose_rows`: the button menu's rows (as `menu_render` produced them; the first is the heading), each cut at its NUL.
pub fn compose_rows_into(view: &mut View, rows: &[[u8; ROW_BYTES]; LCD_ROWS], attention: bool) {
    *view = View::ZERO;
    view.layout = LAYOUT_ROWS;
    view.attention = attention;
    for (i, row) in rows.iter().enumerate() {
        snprintf(view.row_mut(i), |w| {
            w.b(row);
        });
    }
}

/// [`compose_rows_into`] returning the view.
#[must_use]
pub fn compose_rows(rows: &[[u8; ROW_BYTES]; LCD_ROWS], attention: bool) -> View {
    let mut v = View::ZERO;
    compose_rows_into(&mut v, rows, attention);
    v
}
