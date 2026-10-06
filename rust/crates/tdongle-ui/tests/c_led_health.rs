//! Ports of `tests/test_led.c`, `tests/test_health.c`, `tests/test_ui_settings.c`.
use tdongle_ui::health::{self, Counters, ResetClass};
use tdongle_ui::led::*;
use tdongle_ui::settings::*;

#[test]
fn states_bridge() {
    let mut i = LedInputs::default();
    assert_eq!(select(&i), LedMode::Join); // saved network, joining
    i.no_network = true;
    assert_eq!(select(&i), LedMode::Setup);
    i.no_network = false;
    i.setup = true;
    assert_eq!(select(&i), LedMode::Setup);
    i = LedInputs { associated: true, ..Default::default() };
    assert_eq!(select(&i), LedMode::Join); // joined, waiting for the USB side
    i.usb_ready = true;
    assert_eq!(select(&i), LedMode::Up);
    i.associated = false;
    assert_eq!(select(&i), LedMode::Join);
    for r in [201u16, 202, 15] {
        let i = LedInputs { last_reason: r, ..Default::default() };
        assert!(select(&i) == LedMode::Fail && reason_is_join_failure(r));
    }
    let mut i = LedInputs { last_reason: 8, ..Default::default() };
    assert!(select(&i) == LedMode::Join && !reason_is_join_failure(8)); // an ordinary disconnect
    i.last_reason = 201;
    i.associated = true;
    i.usb_ready = true;
    assert_eq!(select(&i), LedMode::Up); // a stale failure never shows over a good link
    i.setup = true;
    assert_eq!(select(&i), LedMode::Setup);
}

#[test]
fn states_tailnet_and_recovery() {
    let mut i = LedInputs { tailnet: true, associated: true, usb_ready: true, ..Default::default() };
    assert_eq!(select(&i), LedMode::Join); // Wi-Fi up, tailnet not ready
    i.tailnet_ready = 1;
    assert_eq!(select(&i), LedMode::Up);
    i.usb_ready = false;
    assert_eq!(select(&i), LedMode::Join);
    i.usb_ready = true;
    i.tailnet_ready = 0;
    i.tailnet_failed = 1;
    assert_eq!(select(&i), LedMode::Fail);
    i.tailnet_login = 1;
    assert_eq!(select(&i), LedMode::Login);
    i.associated = false;
    assert_eq!(select(&i), LedMode::Join);
    i.recovery = true;
    i.associated = true;
    assert_eq!(select(&i), LedMode::Attention); // recovery outranks everything, setup too
    i.setup = true;
    assert_eq!(select(&i), LedMode::Attention);
}

#[test]
fn colours() {
    let (mut low, mut high) = (255u8, 0u8);
    for t in (0..3000).step_by(10) {
        let c = color(LedMode::Setup, t, 0);
        assert!(c.r == 0 && c.g == 0 && c.b <= 180);
        low = low.min(c.b);
        high = high.max(c.b);
    }
    assert!(low < 40 && high > 170);
    let c = color(LedMode::Up, 1000, 1000);
    assert!(c.g == 180 && c.r == 120 && c.b == 120);
    let c = color(LedMode::Up, 1600, 1000);
    assert!(c.g == 180 && c.r == 60 && c.b == 60);
    assert_eq!(color(LedMode::Up, 2200, 1000), Rgb { r: 0, g: 180, b: 0 });
    assert_eq!(color(LedMode::Up, 900_000, 1000), Rgb { r: 0, g: 180, b: 0 });
    assert_eq!(color(LedMode::Up, 5, 0xffff_fff0).g, 180); // the clock wrapped during the glow
    let mut on = 0;
    for t in 0..2000 {
        let c = color(LedMode::Fail, 7000 + t, 7000);
        assert!(c.g == 0 && c.b == 0 && (c.r == 0 || c.r == 180));
        on += (c.r != 0) as u32;
    }
    assert_eq!(on, 300);
    let f = |t| color(LedMode::Fail, t, 7000).r;
    assert!(f(7100) == 180 && f(7200) == 0 && f(7350) == 180 && f(8000) == 0 && f(9100) == 180);
    for t in (0..1600).step_by(7) {
        let c = color(LedMode::Join, t, 0);
        assert!(c.b == 0 && c.r >= c.g && c.r <= 120 && c.g <= 60);
    }
    for t in (0..4000).step_by(50) {
        let c = color(LedMode::Attention, t, 0);
        assert!(c.g == 0 && c.b == 0 && c.r <= 180);
        let c = color(LedMode::Login, t, 0);
        assert!(c.r == 0 && c.g != 0 && c.b != 0);
    }
}

#[test]
fn apa102() {
    assert_eq!(apa102_frame(Rgb { r: 1, g: 2, b: 3 }), [0, 0, 0, 0, 0xe2, 3, 2, 1, 0xff, 0xff, 0xff, 0xff]); // BGR order
    assert_eq!((DATA_PIN, CLK_PIN), (40, 39));
}

#[test]
fn health_tallies() {
    let mut h = Counters { magic: 0xaaaa_aaaa, boots: 0xaaaa_aaaa, watchdogs: 0xaaaa_aaaa, panics: 0xaaaa_aaaa }; // power-on RTC is indeterminate
    h.note_boot(ResetClass::Cold);
    assert!(h.magic == health::MAGIC && h.boots == 1 && h.watchdogs == 0 && h.panics == 0);
    h.note_boot(ResetClass::Other);
    assert_eq!(h.boots, 2);
    h.note_boot(ResetClass::Panic);
    assert!(h.boots == 3 && h.panics == 1 && h.watchdogs == 0);
    h.note_boot(ResetClass::Watchdog);
    assert!(h.boots == 4 && h.panics == 1 && h.watchdogs == 1);
    h.note_boot(ResetClass::Panic);
    assert_eq!(h.panics, 2);
    h.note_boot(ResetClass::Cold);
    assert!(h.boots == 1 && h.panics == 0 && h.watchdogs == 0);
    let mut h = Counters { magic: 0x5555_5555, boots: 0x5555_5555, watchdogs: 0x5555_5555, panics: 0x5555_5555 };
    h.note_boot(ResetClass::Panic);
    assert!(h.boots == 1 && h.panics == 1 && h.magic == health::MAGIC);
}

#[test]
fn recovery_policy() {
    assert!(
        health::should_recover(true, true, false, false)
            && health::should_recover(true, false, true, false)
            && health::should_recover(true, false, false, true)
    );
    assert!(!health::should_recover(false, true, true, true) && !health::should_recover(true, false, false, false));
    let mut e = [0i32; health::stage::COUNT];
    assert!(!health::needs_attention(false, &e));
    e[health::stage::DISPLAY] = -1;
    assert!(!health::needs_attention(false, &e)); // a missing panel is not an emergency
    e[7] = 5;
    assert!(health::needs_attention(false, &e));
    assert!(health::needs_attention(true, &[0; health::stage::COUNT]));
}

#[test]
fn settings_defaults_and_ranges() {
    let s = Settings::default();
    assert!(s.brightness == 60 && s.rotation == 0 && s.dim_seconds == 60 && s.valid());
    let t = |b, r, d| Settings { brightness: b, rotation: r, dim_seconds: d }.valid();
    assert!(!t(4, 0, 60) && t(5, 0, 60) && t(100, 0, 60) && !t(101, 0, 60));
    assert!(t(60, 1, 60) && !t(60, 2, 60));
    assert!(!t(60, 0, 9) && t(60, 0, 10) && t(60, 0, 3600) && !t(60, 0, 3601));
}

#[test]
fn settings_parse() {
    assert_eq!(Settings::parse("60 0 60"), Some(Settings { brightness: 60, rotation: 0, dim_seconds: 60 }));
    assert_eq!(Settings::parse("100 1 3600"), Some(Settings { brightness: 100, rotation: 1, dim_seconds: 3600 }));
    assert_eq!(Settings::parse("  5   0   10  "), Some(Settings { brightness: 5, rotation: 0, dim_seconds: 10 }));
    assert_eq!(Settings::parse("075 1 0100"), Some(Settings { brightness: 75, rotation: 1, dim_seconds: 100 }));
    for bad in [
        "",
        "60",
        "60 0",
        "60 0 60 1",
        "60 0 60 x",
        "4 0 60",
        "101 0 60",
        "60 2 60",
        "60 0 9",
        "60 0 3601",
        "-5 0 60",
        "+5 0 60",
        "60,0,60",
        "60 0 60abc",
        "x 0 60",
        "60 0 99999999",
        "999999 0 60",
        "6O 0 60",
        "60\t0 60",
        "60 0 60\n",
    ] {
        assert_eq!(Settings::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn settings_backlight_and_blob() {
    let mut s = Settings { brightness: 60, rotation: 0, dim_seconds: 60 };
    assert!(s.backlight_percent(false) == 60 && s.backlight_percent(true) == DIM_PERCENT);
    s.brightness = 5;
    assert_eq!(s.backlight_percent(true), 5); // dimming never brightens
    assert!(backlight_duty(100) == 0 && backlight_duty(0) == 255);
    assert!(backlight_duty(60) == 255 - 153 && backlight_duty(200) == 0);
    let mut prev = 256;
    for p in 0..=100 {
        let d = backlight_duty(p);
        assert!(d <= prev && d <= 255);
        prev = d;
    }
    let s = Settings { brightness: 33, rotation: 1, dim_seconds: 900 };
    let b = s.encode();
    assert_eq!(b.len(), 8);
    assert_eq!(&b[..4], &[1, 0, 0, 0]);
    assert_eq!(Settings::decode(&b), Some(s));
    let mut bad = b;
    bad[0] = 2;
    assert_eq!(Settings::decode(&bad), None);
    let mut bad = b;
    bad[4] = 1;
    assert_eq!(Settings::decode(&bad), None);
    let mut bad = b;
    bad[5] = 2;
    assert_eq!(Settings::decode(&bad), None);
    assert!(Settings::decode(&b[..7]).is_none() && Settings::decode(&[&b[..], &[0]].concat()).is_none());
}
