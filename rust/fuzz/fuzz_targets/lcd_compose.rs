//! compose never panics on any state, every field stays inside its buffer, and render_row never panics or reads out of bounds for any View.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_lcd::{LCD_BARS, LcdState, View, compose, render_row};

fuzz_target!(|data: &[u8]| {
    // First half of the input builds a state (bytes taken round robin), the rest is the raw view for the renderer.
    let mut it = data.iter().copied().cycle();
    let mut next = || if data.is_empty() { 0 } else { it.next().unwrap() };
    let mut s = LcdState::ZERO;
    let mut w = |n: usize| (0..n).fold(0u64, |a, _| a << 8 | u64::from(next()));
    let f = w(2);
    (s.bridge, s.wifi, s.saved_wifi, s.recovery, s.starting, s.installing) = (f & 1 != 0, f & 2 != 0, f & 4 != 0, f & 8 != 0, f & 16 != 0, f & 32 != 0);
    (s.usb, s.usb_configured, s.usb_suspended, s.rssi_valid, s.setup) = (f & 64 != 0, f & 128 != 0, f & 256 != 0, f & 512 != 0, f & 1024 != 0);
    (s.saved, s.enabled, s.ready, s.login, s.failed, s.page) = (w(4) as u32, w(4) as u32, w(4) as u32, w(4) as u32, w(4) as u32, w(1) as u32);
    s.rssi = w(4) as i32;
    (s.setup_seconds_left, s.down_kbps, s.up_kbps, s.uptime_s, s.wifi_up_s) = (w(4) as u32, w(4) as u32, w(4) as u32, w(4) as u32, w(4) as u32);
    (s.down_bytes, s.up_bytes, s.down_frames, s.up_frames) = (w(8), w(8), w(8), w(8));
    (s.health_view, s.active_slot, s.heap_free, s.panics) = (w(4) as u32, w(4) as u32, w(4) as u32, w(4) as u32);
    for b in s.ssid.iter_mut().chain(s.ap_ssid.iter_mut()).chain(s.active_name.iter_mut()).chain(s.bars.iter_mut()) {
        *b = w(1) as u8;
    }
    let version: String = data.iter().take(24).map(|&b| char::from(b)).collect();
    let v = compose(&s, &version);
    assert!(usize::from(v.bar_count) <= LCD_BARS);
    let mut px = [0u16; 160];
    for y in [0, 1, 7, 63, 79, 80, 255] {
        render_row(&v, y, &mut px);
    }
    let mut raw = View::ZERO;
    for b in raw.text.iter_mut().chain(raw.bars.iter_mut()) {
        *b = w(1) as u8;
    }
    (raw.attention, raw.layout, raw.bar_count) = (w(1) & 1 != 0, w(1) as u8, w(1) as u8);
    for y in 0..96 {
        render_row(&raw, y, &mut px);
    }
});
