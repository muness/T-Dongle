//! compose never panics and keeps every field inside its C buffer; render_row never panics for any bytes in a View.

use proptest::prelude::*;
use tdongle_lcd::view::{DETAIL, EXTRA, FOOTER, HINT, LAYOUT_ROWS, View};
use tdongle_lcd::{LCD_BARS, LcdState, compose, compose_rows, render_row};

fn text<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    proptest::collection::vec(any::<u8>(), N).prop_map(|v| <[u8; N]>::try_from(v).unwrap())
}

fn state() -> impl Strategy<Value = LcdState> {
    let flags = proptest::collection::vec(any::<bool>(), 11);
    let nums = proptest::collection::vec(prop_oneof![Just(0u32), Just(1), Just(999), Just(u32::MAX), any::<u32>()], 24);
    let wide = proptest::collection::vec(prop_oneof![Just(0u64), Just(u64::MAX), any::<u64>()], 4);
    (flags, nums, wide, any::<i32>(), text::<33>(), text::<16>(), text::<25>(), text::<LCD_BARS>()).prop_map(|(f, n, w, rssi, ssid, ap, name, bars)| {
        let mut s = LcdState::ZERO;
        (s.bridge, s.wifi, s.saved_wifi, s.recovery, s.starting, s.installing) = (f[0], f[1], f[2], f[3], f[4], f[5]);
        (s.usb, s.usb_configured, s.usb_suspended, s.rssi_valid, s.setup) = (f[6], f[7], f[8], f[9], f[10]);
        (s.saved, s.enabled, s.ready, s.login, s.failed, s.page) = (n[0], n[1], n[2], n[3], n[4], n[5]);
        (s.setup_seconds_left, s.down_kbps, s.up_kbps, s.uptime_s, s.wifi_up_s, s.connects) = (n[6], n[7], n[8], n[9], n[10], n[11]);
        (s.last_reason, s.usb_resets, s.heap_free, s.heap_min, s.heap_largest) = (n[12], n[13], n[14], n[15], n[16]);
        (s.reset_reason, s.boots, s.watchdogs, s.panics, s.health_view, s.active_slot) = (n[17], n[18], n[19], n[20], n[21], n[22]);
        (s.down_bytes, s.up_bytes, s.down_frames, s.up_frames) = (w[0], w[1], w[2], w[3]);
        s.rssi = rssi;
        // NUL-terminate like the C's char arrays (a non-terminated array is UB in C); Rust must still not panic without it.
        (s.ssid, s.ap_ssid, s.active_name, s.bars) = (ssid, ap, name, bars);
        s.ssid[32] = 0;
        s.ap_ssid[15] = 0;
        s.active_name[24] = 0;
        s
    })
}

fn view() -> impl Strategy<Value = View> {
    (text::<135>(), text::<32>(), any::<bool>(), any::<u8>(), any::<u8>()).prop_map(|(text, bars, attention, layout, bar_count)| View {
        text,
        bars,
        attention,
        layout,
        bar_count,
    })
}

proptest! {
    #[test]
    fn compose_fits_every_buffer(s in state(), ver in "\\PC{0,40}") {
        let v = compose(&s, &ver);
        if v.layout == 0 {
            prop_assert!(v.title().len() <= 13 && v.detail().len() <= 26 && v.hint().len() <= 26 && v.extra().len() <= 26 && v.footer().len() <= 26);
            // The NUL of every field is inside its own buffer, so no field runs into the next.
            prop_assert_eq!(v.text[13], 0);
            for off in [DETAIL, HINT, EXTRA, FOOTER] {
                prop_assert_eq!(v.text[off + 26], 0);
            }
        } else {
            prop_assert_eq!(v.layout, LAYOUT_ROWS);
            for i in 0..5 {
                prop_assert!(v.row(i).len() <= 26);
                prop_assert_eq!(v.text[i * 27 + 26], 0);
            }
        }
        prop_assert!(usize::from(v.bar_count) <= LCD_BARS);
        // Deterministic: equal states compose to equal (memcmp) views.
        prop_assert_eq!(v, compose(&s, &ver));
    }

    #[test]
    fn render_row_never_panics_and_is_pure(v in view(), y in 0usize..400) {
        let mut a = [0u16; 160];
        render_row(&v, y, &mut a);
        let mut b = [0x1234u16; 160];
        render_row(&v, y, &mut b);
        prop_assert_eq!(a, b); // every pixel is written, none depends on the previous contents
        if y >= 80 {
            prop_assert!(a.iter().all(|&p| p == tdongle_lcd::render::BACKGROUND));
        }
    }

    #[test]
    fn compose_rows_never_panics(rows in proptest::collection::vec(text::<27>(), 5), attention in any::<bool>(), y in 0usize..80) {
        let rows: [[u8; 27]; 5] = rows.try_into().unwrap();
        let v = compose_rows(&rows, attention);
        let mut px = [0u16; 160];
        render_row(&v, y, &mut px);
        prop_assert_eq!(v.layout, LAYOUT_ROWS);
    }
}
