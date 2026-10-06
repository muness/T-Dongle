//! Ports of `tests/test_setup_boot.c` and `tests/test_setup_access.c`.
use tdongle_ui::access::*;
use tdongle_ui::setup_boot::*;

#[test]
fn decisions() {
    const M: u32 = BOOT_MAGIC;
    let (e, l) = (SetupRequest::Enter as u32, SetupRequest::Leave as u32);
    let d = decide(true, M, e, 0, true, true);
    assert!(d.setup && d.preselect == 0);
    let d = decide(true, M, e, 3, true, true);
    assert!(d.setup && d.preselect == 3);
    let d = decide(true, M, e, 9, true, true);
    assert!(d.setup && d.preselect == 0); // slot out of range
    assert!(decide(true, M, e, 0, true, false).setup); // explicit request, even over a bad store
    assert!(!decide(false, M, e, 0, true, true).setup); // a power cycle with stale RTC contents
    assert!(!decide(true, M ^ 1, e, 0, true, true).setup); // no magic
    assert!(!decide(true, M, 7, 0, true, true).setup); // garbage request word
    let d = decide(false, 0, 0, 0, false, true);
    assert!(d.setup && d.preselect == 0); // first plug-in
    assert!(!decide(false, 0, 0, 0, false, false).setup);
    assert!(!decide(false, 0, 0, 0, true, true).setup);
    assert!(!decide(true, M, l, 0, false, true).setup); // the restart that closes setup reaches normal mode
    assert!(decide(false, M, l, 0, false, true).setup); // the next cold boot is a first plug-in again
    assert!(decide(true, M, e, 0, false, true).setup);
}

#[test]
fn request_words_roundtrip() {
    assert_eq!(request_words(SetupRequest::Enter, 4), (BOOT_MAGIC, 1, 4));
    assert_eq!(request_words(SetupRequest::Enter, 0).2, 0);
    assert_eq!(request_words(SetupRequest::Enter, 99).2, 0);
    let (_, n, s) = request_words(SetupRequest::Leave, 4);
    assert!(n == 2 && s == 0);
    let (m, n, s) = request_words(SetupRequest::Enter, 6);
    let d = decide(true, m, n, s, true, true);
    assert!(d.setup && d.preselect == 6);
}

#[test]
fn session() {
    let s = Session::inactive();
    assert!(!s.expired(1_000_000) && s.seconds_left(0) == 0);
    let s = Session::start(5000);
    assert_eq!(SESSION_MS, 10 * 60 * 1000);
    assert!(!s.expired(5000) && s.seconds_left(5000) == 600);
    assert!(s.seconds_left(5001) == 600 && s.seconds_left(6000) == 599 && s.seconds_left(5000 + 599_000) == 1);
    assert!(!s.expired(5000 + 599_999) && s.expired(5000 + 600_000) && s.seconds_left(5000 + 600_000) == 0);
    assert!(s.expired(5000 + 7_200_000));
    let s = Session::start(0xffff_ff00);
    assert!(!s.expired(0xffff_ff00u32.wrapping_add(599_000)) && s.expired(0xffff_ff00u32.wrapping_add(600_000)));
    assert_eq!(s.seconds_left(0xffff_ff00u32.wrapping_add(1000)), 599);
}

#[test]
fn giving_up() {
    assert!(!Session::inactive().should_end(1_000_000, false));
    let s = Session::start(1000);
    assert!(!s.should_end(1000, false) && !s.should_end(1000 + 29_999, false));
    assert!(s.should_end(1000 + 30_000, false)); // the access point never came up
    assert!(!s.should_end(1000 + 30_000, true) && !s.should_end(1000 + 599_999, true));
    assert!(s.should_end(1000 + 600_000, true));
    let s = Session::start(0xffff_ff00);
    assert!(!s.should_end(0xffff_ff00u32.wrapping_add(29_999), false) && s.should_end(0xffff_ff00u32.wrapping_add(30_000), false));
}

#[test]
fn failsafe() {
    assert_eq!(Session::inactive().failsafe_delay_ms(5, false), 0);
    let s = Session::start(1000);
    assert_eq!(s.failsafe_delay_ms(1000, false), AP_GRACE_MS);
    assert_eq!(s.failsafe_delay_ms(1000 + 10_000, false), AP_GRACE_MS - 10_000);
    assert_eq!(s.failsafe_delay_ms(1000 + 30_000, false), 0);
    assert_eq!(s.failsafe_delay_ms(1000 + 5000, true), SESSION_MS - 5000);
    assert_eq!(s.failsafe_delay_ms(1000 + 599_999, true), 1);
    assert_eq!(s.failsafe_delay_ms(1000 + 600_000, true), 0);
    let (mut now, mut fired, mut up) = (1000u32, 0, false);
    loop {
        if now >= 1000 + 4000 {
            up = true;
        }
        let d = s.failsafe_delay_ms(now, up);
        if d == 0 {
            break;
        }
        now += d;
        fired += 1;
        assert!(fired < 10);
    }
    assert!(now == 1000 + SESSION_MS && fired == 2);
    let (mut now, mut fired) = (1000u32, 0);
    loop {
        let d = s.failsafe_delay_ms(now, false);
        if d == 0 {
            break;
        }
        now += d;
        fired += 1;
    }
    assert!(now == 1000 + AP_GRACE_MS && fired == 1);
}

#[test]
fn access_point_name() {
    let s = ap_ssid([0x34, 0x85, 0x18, 0xab, 0x0c, 0xf9]);
    assert!(s.as_str() == "TDongle-AB0CF9" && s.as_bytes().len() == 14);
}

const fn ip(a: u32, b: u32, c: u32, d: u32) -> u32 {
    (a << 24) | (b << 16) | (c << 8) | d
}
fn cl(peer: u32, setup: bool, host: Option<&str>, origin: Option<&str>) -> Origin {
    let local = if peer & 0xffff_ff00 == ip(192, 168, 4, 0) { ip(192, 168, 4, 1) } else { ip(192, 168, 77, 1) };
    classify(Some(peer), Some(local), setup, host, origin)
}

#[test]
fn usb_origin_is_unchanged() {
    let u = ip(192, 168, 77, 2);
    assert_eq!(cl(u, false, Some("192.168.77.1"), None), Origin::Usb);
    assert_eq!(cl(u, false, Some("192.168.77.1:80"), Some("http://192.168.77.1")), Origin::Usb);
    assert_eq!(cl(ip(192, 168, 77, 254), true, Some("192.168.77.1"), Some("http://192.168.77.1:80")), Origin::Usb);
    assert_eq!(cl(u, false, Some("evil.example"), None), Origin::Denied);
    assert_eq!(cl(u, false, None, None), Origin::Denied);
    assert_eq!(cl(u, false, Some("192.168.77.1"), Some("http://evil.example")), Origin::Denied);
    assert_eq!(cl(u, false, Some("192.168.77.1:8080"), None), Origin::Denied);
    assert_eq!(classify(None, Some(ip(192, 168, 77, 1)), false, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(classify(Some(u), None, false, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(cl(ip(192, 168, 78, 2), false, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(cl(ip(10, 0, 0, 2), false, Some("192.168.77.1"), None), Origin::Denied);
}

#[test]
fn setup_access_point_origin() {
    let a = ip(192, 168, 4, 2);
    assert_eq!(cl(a, true, Some("192.168.4.1"), None), Origin::SetupAp);
    assert_eq!(cl(a, true, Some("192.168.4.1:80"), Some("http://192.168.4.1")), Origin::SetupAp);
    assert_eq!(cl(a, false, Some("192.168.4.1"), None), Origin::Denied);
    assert_eq!(cl(a, true, Some("captive.apple.com"), None), Origin::Denied);
    assert_eq!(cl(a, true, Some("192.168.4.1"), Some("http://captive.apple.com")), Origin::Denied);
    assert_eq!(cl(a, true, None, None), Origin::Denied);
    assert!(in_setup_subnet(ip(192, 168, 4, 77)) && !in_setup_subnet(ip(192, 168, 5, 1)) && !in_setup_subnet(ip(192, 168, 77, 2)));
    assert_eq!(cl(a, true, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(cl(ip(192, 168, 77, 2), true, Some("192.168.4.1"), None), Origin::Denied);
}

#[test]
fn spoofed_sources_are_refused() {
    let c = |p, l, s, h| classify(Some(p), Some(l), s, Some(h), None);
    assert_eq!(c(ip(192, 168, 77, 2), ip(192, 168, 4, 1), true, "192.168.77.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 4, 2), ip(192, 168, 77, 1), true, "192.168.4.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 4, 2), ip(192, 168, 4, 77), true, "192.168.4.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 77, 2), ip(192, 168, 77, 2), false, "192.168.77.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 77, 2), ip(192, 168, 77, 1), false, "192.168.77.1"), Origin::Usb);
    assert_eq!(c(ip(192, 168, 4, 2), ip(192, 168, 4, 1), true, "192.168.4.1"), Origin::SetupAp);
}

#[test]
fn what_each_origin_may_ask_for() {
    for e in ENDPOINTS {
        assert!(endpoint_allowed(Origin::Usb, e) && !endpoint_allowed(Origin::Denied, e));
    }
    use Endpoint::*;
    for e in [Home, WifiScan, WifiSaved, Command] {
        assert!(endpoint_allowed(Origin::SetupAp, e));
    }
    for e in [Status, Diagnostics, BootStatus] {
        assert!(!endpoint_allowed(Origin::SetupAp, e));
    }
    for a in ACTIONS {
        assert!(action_allowed(Origin::Usb, a) && !action_allowed(Origin::Denied, a));
    }
    for a in [Action::Wifi, Action::WifiRemove, Action::SetupDone] {
        assert!(action_allowed(Origin::SetupAp, a));
    }
    for a in [Action::Mode, Action::Add, Action::Remove, Action::Enable] {
        assert!(!action_allowed(Origin::SetupAp, a));
    }
    assert!(!action_allowed(Origin::Usb, Action::Unknown) && !action_allowed(Origin::SetupAp, Action::Unknown));
    assert!(may_set_metadata(Origin::Usb) && may_replace(Origin::Usb));
    assert!(!may_set_metadata(Origin::SetupAp) && !may_replace(Origin::SetupAp) && !may_set_metadata(Origin::Denied) && !may_replace(Origin::Denied));
}

#[test]
fn actions_parse_and_tokens() {
    for (n, a) in [("mode", Action::Mode), ("wifi", Action::Wifi), ("wifi_remove", Action::WifiRemove), ("add", Action::Add), ("remove", Action::Remove), ("enable", Action::Enable), ("setup_done", Action::SetupDone)] {
        assert_eq!(action_parse(Some(n)), a);
    }
    for n in [Some(""), Some("WIFI"), Some("wifi "), None] {
        assert_eq!(action_parse(n), Action::Unknown);
    }
    let random = [0x00, 0x01, 0x0a, 0x0f, 0x10, 0xa5, 0xff, 0x80, 1, 2, 3, 4, 5, 6, 7, 8];
    let t = token_format(&random);
    let ts = core::str::from_utf8(&t).unwrap();
    assert_eq!(ts, "00010a0f10a5ff800102030405060708");
    assert!(token_equal(Some(ts), Some(ts)));
    let mut other = t;
    for i in 0..32 {
        other[i] ^= 1;
        assert!(!token_equal(core::str::from_utf8(&other).ok(), Some(ts)));
        other[i] ^= 1;
    }
    assert!(!token_equal(Some(""), Some(ts)) && !token_equal(None, Some(ts)) && !token_equal(Some(ts), Some("")) && !token_equal(Some(ts), None) && !token_equal(Some(""), Some("")));
    assert!(!token_equal(Some("0001"), Some(ts)) && !token_equal(Some("00010a0f10a5ff800102030405060708x"), Some(ts)));
}
