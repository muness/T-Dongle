//! Wi-Fi link visibility for the status reports: the port of `main/wifi_link.h` (tests: `tests/test_wifi_link.c`).
//!
//! Pure data and formatting; the driver reads that fill [`Info`] live in the firmware. Privacy rule of the C file, kept: nothing here
//! carries the BSSID or the SSID, and the BSSID kept for roam detection ([`Events::last_bssid`]) never appears in a report.
//!
//! Sizes: [`LINE_MAX`] and [`JSON_MAX`] are the worst cases of the C header; the bounded renderers ([`line()`], [`json()`]) return `None` when
//! the output does not fit the buffer they are given, exactly where C returns 0 (`n >= cap`: one byte is reserved for the terminator,
//! which is stored as in C).

use crate::text::Counting;
use core::fmt::{self, Display, Write};

/// `WIFI_LINK_PHY_LR`: `wifi_phy_mode_t` values.
pub const PHY_LR: u8 = 0;
/// 802.11b.
pub const PHY_11B: u8 = 1;
/// 802.11g.
pub const PHY_11G: u8 = 2;
/// 802.11a.
pub const PHY_11A: u8 = 3;
/// HT20.
pub const PHY_HT20: u8 = 4;
/// HT40.
pub const PHY_HT40: u8 = 5;
/// HE20.
pub const PHY_HE20: u8 = 6;
/// VHT20.
pub const PHY_VHT20: u8 = 7;
/// Number of named PHY modes.
pub const PHY_COUNT: u32 = 8;
/// A failed driver call is never reported as a real zero.
pub const PHY_UNKNOWN: u8 = 0xff;
/// Unknown power-save type.
pub const PS_UNKNOWN: u8 = 0xff;
/// Unknown secondary channel.
pub const SECOND_UNKNOWN: u8 = 0xff;
/// AP capability bit: 802.11b.
pub const AP_B: u8 = 1;
/// AP capability bit: 802.11g.
pub const AP_G: u8 = 2;
/// AP capability bit: 802.11n.
pub const AP_N: u8 = 4;
/// AP capability bit: 802.11ax.
pub const AP_AX: u8 = 8;
/// `WIFI_REASON_BEACON_TIMEOUT`: the station stopped hearing the AP (the loss signature the diagnostics hunt).
pub const REASON_BEACON_TIMEOUT: u32 = 200;

/// Worst-case JSON object length (`WIFI_LINK_JSON_MAX`): callers size buffers with it.
pub const JSON_MAX: usize = 480;
/// Worst-case serial line length (`WIFI_LINK_LINE_MAX`).
pub const LINE_MAX: usize = 380;

/// The state of the link (`wifi_link_info`). All-zero is the C `{0}`: disconnected, PHY 0 (`lr`), nothing known.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    /// An AP record exists: associated.
    pub connected: bool,
    /// [`rssi`](Self::rssi) is a real reading.
    pub rssi_valid: bool,
    /// dBm, driver average when available, else the AP record's value.
    pub rssi: i8,
    /// Primary channel.
    pub channel: u8,
    /// 0 none, 1 above, 2 below, [`SECOND_UNKNOWN`].
    pub secondary: u8,
    /// Negotiated `wifi_phy_mode_t` or [`PHY_UNKNOWN`].
    pub phy: u8,
    /// Bandwidth the station is configured to use: 20, 40 or 0 unknown.
    pub bw_cfg_mhz: u8,
    /// Bandwidth the AP advertises, 0 unknown.
    pub ap_bw_mhz: u8,
    /// `AP_*` capability bits of the AP.
    pub ap_modes: u8,
    /// `wifi_ps_type_t`, or [`PS_UNKNOWN`].
    pub ps: u8,
    /// [`tx_power_qdbm`](Self::tx_power_qdbm) is a real reading.
    pub tx_power_valid: bool,
    /// Maximum transmit power, quarter dBm.
    pub tx_power_qdbm: i8,
    /// Saved network being used, 1-based, 0 none (the slot number, never its name).
    pub selected_slot: u8,
    /// Chosen with `use N` and kept against roaming.
    pub pinned: bool,
    /// A pinned network that failed to join and was given up, 1-based, 0 none.
    pub pin_failed_slot: u8,
}

/// Where the join of the configured network stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinState {
    /// Associated.
    Connected = 0,
    /// Not associated, a pinned network is being tried.
    Joining = 1,
    /// Not associated, the pinned network failed and was given up.
    Failed = 2,
    /// Not associated, nothing pinned.
    Disconnected = 3,
}

impl JoinState {
    /// C `wifi_link_join_name`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Joining => "joining",
            Self::Failed => "failed",
            Self::Disconnected => "disconnected",
        }
    }

    /// From the C enum value; anything above 3 reads as `Disconnected` (what `wifi_link_join_name` prints for it).
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Connected,
            1 => Self::Joining,
            2 => Self::Failed,
            _ => Self::Disconnected,
        }
    }
}

impl Info {
    /// C `wifi_link_join_state`.
    #[must_use]
    pub const fn join_state(&self) -> JoinState {
        if self.connected {
            JoinState::Connected
        } else if self.pinned {
            JoinState::Joining
        } else if self.pin_failed_slot != 0 {
            JoinState::Failed
        } else {
            JoinState::Disconnected
        }
    }

    /// C `wifi_link_rssi_text`: the token of `rssi=` in status line one: `unknown` or a signed integer (Android accepts exactly those).
    #[must_use]
    pub const fn rssi_text(&self) -> RssiText {
        RssiText { rssi: if self.connected && self.rssi_valid { Some(self.rssi) } else { None } }
    }
}

/// The `rssi=` token: [`Display`] prints `unknown` or the integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RssiText {
    rssi: Option<i8>,
}

impl Display for RssiText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rssi {
            Some(rssi) => write!(f, "{rssi}"),
            None => f.write_str("unknown"),
        }
    }
}

/// Cumulative event counters, written by the Wi-Fi event handler (`wifi_link_events`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events {
    /// Associations.
    pub connects: u32,
    /// Disconnects.
    pub disconnects: u32,
    /// Disconnects with reason [`REASON_BEACON_TIMEOUT`].
    pub beacon_timeouts: u32,
    /// Uptime at the last disconnect; meaningful when `disconnects != 0`.
    pub last_disconnect_ms: u32,
    /// `wifi_err_reason_t` of the last disconnect.
    pub last_reason: u16,
    /// RSSI the driver reported at that disconnect.
    pub last_disconnect_rssi: i8,
    /// Associations to a different access point than the previous one (never part of a report line or JSON: the BSSID stays internal).
    pub roams: u32,
    /// Uptime at the last association; meaningful when `connects != 0`.
    pub last_connect_ms: u32,
    /// BSSID of the last association.
    pub last_bssid: [u8; 6],
    /// [`last_bssid`](Self::last_bssid) is set.
    pub have_bssid: bool,
}

impl Events {
    /// C `wifi_link_note_connect`.
    pub const fn note_connect(&mut self) {
        self.connects = self.connects.wrapping_add(1);
    }

    /// An association completed to the access point `bssid`: counts a connect, remembers when, and counts a roam when the access point is
    /// not the one the previous association used (the first association is never a roam; an event without an address never is either).
    pub fn note_association(&mut self, bssid: Option<&[u8; 6]>, now_ms: u32) {
        self.note_connect();
        self.last_connect_ms = now_ms;
        if let Some(bssid) = bssid {
            if self.have_bssid && self.last_bssid != *bssid {
                self.roams = self.roams.wrapping_add(1);
            }
            self.last_bssid = *bssid;
            self.have_bssid = true;
        }
    }

    /// C `wifi_link_note_disconnect`. `reason` is truncated to 16 bits like the C cast; `rssi` is clamped to the `i8` range, never wrapped.
    pub fn note_disconnect(&mut self, reason: u32, rssi: i32, now_ms: u32) {
        self.disconnects = self.disconnects.wrapping_add(1);
        if reason == REASON_BEACON_TIMEOUT {
            self.beacon_timeouts = self.beacon_timeouts.wrapping_add(1);
        }
        self.last_reason = reason as u16;
        self.last_disconnect_rssi = rssi.clamp(-128, 127) as i8;
        self.last_disconnect_ms = now_ms;
    }
}

/// C `wifi_link_phy_name`.
#[must_use]
pub const fn phy_name(phy: u32) -> &'static str {
    match phy {
        0 => "lr",
        1 => "11b",
        2 => "11g",
        3 => "11a",
        4 => "HT20",
        5 => "HT40",
        6 => "HE20",
        7 => "VHT20",
        _ => "unknown",
    }
}

/// C `wifi_link_secondary_name`.
#[must_use]
pub const fn secondary_name(secondary: u32) -> &'static str {
    match secondary {
        0 => "none",
        1 => "above",
        2 => "below",
        _ => "unknown",
    }
}

/// C `wifi_link_ps_name`.
#[must_use]
pub const fn ps_name(ps: u32) -> &'static str {
    match ps {
        0 => "none",
        1 => "min_modem",
        2 => "max_modem",
        _ => "unknown",
    }
}

/// C `wifi_link_join_name` for a raw join state value.
#[must_use]
pub const fn join_name(state: u32) -> &'static str {
    JoinState::from_u32(state).name()
}

/// AP capability letters in fixed order (C `wifi_link_modes_text`): `bgn`, `bgnax`, ...; `-` when none is advertised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModesText {
    buf: [u8; 5],
    len: usize,
}

impl ModesText {
    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("-")
    }
}

impl Display for ModesText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// C `wifi_link_modes_text`.
#[must_use]
pub fn modes_text(modes: u8) -> ModesText {
    let mut text = ModesText { buf: [0; 5], len: 0 };
    for (bit, letters) in [(AP_B, "b"), (AP_G, "g"), (AP_N, "n"), (AP_AX, "ax")] {
        if modes & bit != 0 {
            text.buf[text.len..text.len + letters.len()].copy_from_slice(letters.as_bytes());
            text.len += letters.len();
        }
    }
    if text.len == 0 {
        text.buf[0] = b'-';
        text.len = 1;
    }
    text
}

/// The `"wifi_link"` JSON object (`wifi_link_json`) written to a sink, braces included. The text has no length limit here; use [`json()`] for
/// the bounded form.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_json<W: Write>(w: &mut W, l: &Info, e: &Events) -> fmt::Result {
    write!(
        w,
        "{{\"connected\":{},\"join\":\"{}\",\"selected_slot\":{},\"pinned\":{},\"pin_failed_slot\":{},",
        l.connected,
        l.join_state().name(),
        l.selected_slot,
        l.pinned,
        l.pin_failed_slot
    )?;
    if l.connected {
        if l.rssi_valid {
            write!(w, "\"rssi_dbm\":{},", l.rssi)?;
        } else {
            w.write_str("\"rssi_dbm\":null,")?;
        }
        write!(
            w,
            "\"channel\":{},\"secondary\":\"{}\",\"phy\":\"{}\",\"bandwidth_cfg_mhz\":{},\"ap_bandwidth_mhz\":{},",
            l.channel,
            secondary_name(l.secondary.into()),
            phy_name(l.phy.into()),
            l.bw_cfg_mhz,
            l.ap_bw_mhz
        )?;
        write!(w, "\"ap_modes\":\"{}\",\"power_save\":\"{}\",", modes_text(l.ap_modes), ps_name(l.ps.into()))?;
        if l.tx_power_valid {
            write!(w, "\"tx_power_qdbm\":{},", l.tx_power_qdbm)?;
        } else {
            w.write_str("\"tx_power_qdbm\":null,")?;
        }
    }
    write!(
        w,
        "\"connects\":{},\"disconnects\":{},\"beacon_timeouts\":{},\"last_disconnect_reason\":{},\
         \"last_disconnect_rssi_dbm\":{},\"last_disconnect_uptime_ms\":{}}}",
        e.connects, e.disconnects, e.beacon_timeouts, e.last_reason, e.last_disconnect_rssi, e.last_disconnect_ms
    )
}

/// The serial `status` line (`wifi_link_line`) written to a sink, CRLF included; no length limit (see [`line()`]).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_line<W: Write>(w: &mut W, l: &Info, e: &Events) -> fmt::Result {
    if l.connected {
        write!(
            w,
            "wifi_link connected=1 join={} selected={} pinned={} pin_failed={} rssi_dbm={} channel={} secondary={} phy={} \
             bandwidth_cfg_mhz={} ap_bandwidth_mhz={} ap_modes={} power_save={} tx_power_qdbm=",
            l.join_state().name(),
            l.selected_slot,
            u8::from(l.pinned),
            l.pin_failed_slot,
            l.rssi_text(),
            l.channel,
            secondary_name(l.secondary.into()),
            phy_name(l.phy.into()),
            l.bw_cfg_mhz,
            l.ap_bw_mhz,
            modes_text(l.ap_modes),
            ps_name(l.ps.into()),
        )?;
        if l.tx_power_valid {
            write!(w, "{}", l.tx_power_qdbm)?;
        } else {
            w.write_str("unknown")?;
        }
        write!(w, " connects={} disconnects={} beacon_timeouts={} last_disconnect_reason={}\r\n", e.connects, e.disconnects, e.beacon_timeouts, e.last_reason)
    } else {
        write!(
            w,
            "wifi_link connected=0 join={} selected={} pinned={} pin_failed={} connects={} disconnects={} beacon_timeouts={} \
             last_disconnect_reason={}\r\n",
            l.join_state().name(),
            l.selected_slot,
            u8::from(l.pinned),
            l.pin_failed_slot,
            e.connects,
            e.disconnects,
            e.beacon_timeouts,
            e.last_reason
        )
    }
}

fn bounded(out: &mut [u8], render: impl FnOnce(&mut Counting<'_>) -> fmt::Result) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    let mut counting = Counting::new(out);
    let rendered = render(&mut counting);
    if rendered.is_err() || !counting.fits() {
        // C: `out[0] = 0; return 0`: the buffer holds the empty string, nothing half written is left to be mistaken for a result.
        out[0] = 0;
        return None;
    }
    counting.terminate();
    Some(counting.total())
}

/// C `wifi_link_json(out, cap, ...)` with `cap = out.len()`: the object (NUL terminated after the returned length) or `None` when it
/// does not fit (the caller then omits it; a half object never leaves this function). An empty buffer yields `None`.
#[must_use]
pub fn json(out: &mut [u8], l: &Info, e: &Events) -> Option<usize> {
    bounded(out, |w| write_json(w, l, e))
}

/// C `wifi_link_line(out, cap, ...)` with `cap = out.len()`: the line with its CRLF (NUL terminated after the returned length) or `None`
/// when it does not fit.
#[must_use]
pub fn line(out: &mut [u8], l: &Info, e: &Events) -> Option<usize> {
    bounded(out, |w| write_line(w, l, e))
}
