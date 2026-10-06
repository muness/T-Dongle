//! C `lcd_state`: the snapshot of the dongle the screen is built from.

use crate::LCD_BARS;

/// Same fields, types and meaning as C `lcd_state` (lcd_view.h). Text fields are NUL-terminated byte arrays of the C sizes; helper
/// setters fill them with the C's truncation. All-zero is [`LcdState::ZERO`] (C `lcd_state s = {0}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcdState {
    pub bridge: bool,
    pub wifi: bool,
    pub saved_wifi: bool,
    pub recovery: bool,
    pub starting: bool,
    pub installing: bool,
    pub usb: bool,
    pub usb_configured: bool,
    pub usb_suspended: bool,
    pub saved: u32,
    pub enabled: u32,
    pub ready: u32,
    pub login: u32,
    pub failed: u32,
    /// 0 to `LCD_PAGES - 1`; anything else shows page 0.
    pub page: u32,
    pub rssi_valid: bool,
    /// dBm.
    pub rssi: i32,
    /// The joined network, empty when none (`char ssid[33]`).
    pub ssid: [u8; 33],
    /// A setup boot is running: the setup access point screen replaces the pages.
    pub setup: bool,
    /// `char ap_ssid[16]`.
    pub ap_ssid: [u8; 16],
    pub setup_seconds_left: u32,
    pub down_kbps: u32,
    pub up_kbps: u32,
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub down_frames: u64,
    pub up_frames: u64,
    /// 0..20, oldest first.
    pub bars: [u8; LCD_BARS],
    pub uptime_s: u32,
    pub wifi_up_s: u32,
    pub connects: u32,
    pub last_reason: u32,
    pub usb_resets: u32,
    pub heap_free: u32,
    pub heap_min: u32,
    pub heap_largest: u32,
    pub reset_reason: u32,
    pub boots: u32,
    pub watchdogs: u32,
    pub panics: u32,
    /// Which of the three Health views (0 to 2); other values are taken modulo 3.
    pub health_view: u32,
    /// Saved network in use, 1-based, 0 none.
    pub active_slot: u32,
    /// `char active_name[25]`.
    pub active_name: [u8; 25],
}

impl LcdState {
    /// All zero, like `lcd_state s = {0}`.
    pub const ZERO: Self = Self {
        bridge: false,
        wifi: false,
        saved_wifi: false,
        recovery: false,
        starting: false,
        installing: false,
        usb: false,
        usb_configured: false,
        usb_suspended: false,
        saved: 0,
        enabled: 0,
        ready: 0,
        login: 0,
        failed: 0,
        page: 0,
        rssi_valid: false,
        rssi: 0,
        ssid: [0; 33],
        setup: false,
        ap_ssid: [0; 16],
        setup_seconds_left: 0,
        down_kbps: 0,
        up_kbps: 0,
        down_bytes: 0,
        up_bytes: 0,
        down_frames: 0,
        up_frames: 0,
        bars: [0; LCD_BARS],
        uptime_s: 0,
        wifi_up_s: 0,
        connects: 0,
        last_reason: 0,
        usb_resets: 0,
        heap_free: 0,
        heap_min: 0,
        heap_largest: 0,
        reset_reason: 0,
        boots: 0,
        watchdogs: 0,
        panics: 0,
        health_view: 0,
        active_slot: 0,
        active_name: [0; 25],
    };

    /// Set `ssid` (truncated to 32 bytes, NUL terminated).
    pub fn set_ssid(&mut self, text: &[u8]) {
        fill(&mut self.ssid, text);
    }
    /// Set `ap_ssid` (truncated to 15 bytes).
    pub fn set_ap_ssid(&mut self, text: &[u8]) {
        fill(&mut self.ap_ssid, text);
    }
    /// Set `active_name` (truncated to 24 bytes).
    pub fn set_active_name(&mut self, text: &[u8]) {
        fill(&mut self.active_name, text);
    }
}

impl Default for LcdState {
    fn default() -> Self {
        Self::ZERO
    }
}

fn fill(dst: &mut [u8], text: &[u8]) {
    dst.fill(0);
    let text = crate::fmt::cstr(text);
    let n = text.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&text[..n]);
}
