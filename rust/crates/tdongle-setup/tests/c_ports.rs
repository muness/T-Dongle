//! The cases of the C unit tests (`tests/test_captive_dns.c`, `test_setup_access.c`, `test_setup_boot.c`), one for one.
use tdongle_setup::access::*;
use tdongle_setup::boot::*;
use tdongle_setup::dns;

const DONGLE: [u8; 4] = [192, 168, 4, 1];

fn query(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut q = vec![0u8; 12];
    q[0] = 0x12;
    q[1] = 0x34;
    q[2] = 0x01;
    q[5] = 1;
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&qclass.to_be_bytes());
    q
}

fn reply(q: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; cap];
    dns::reply(q, &mut out, DONGLE).map(|n| out[..n].to_vec())
}

#[test]
fn dns_a_record() {
    let q = query("captive.apple.com", 1, 1);
    let n = q.len();
    let r = reply(&q, 512).unwrap();
    assert_eq!(r.len(), n + 16);
    assert_eq!(&r[..2], &[0x12, 0x34]);
    assert!(r[2] & 0x80 != 0 && r[2] & 0x78 == 0 && r[2] & 1 != 0 && r[3] == 0x80);
    assert_eq!(&r[4..12], &[0, 1, 0, 1, 0, 0, 0, 0]);
    assert_eq!(&r[12..n], &q[12..]);
    assert_eq!(&r[n..n + 12], &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    assert_eq!(&r[n + 12..], &DONGLE);
    for name in ["connectivitycheck.gstatic.com", "www.msftconnecttest.com", "neverssl.com", "a", "x.y.z.example.org", "detectportal.firefox.com"] {
        let q = query(name, 1, 1);
        assert_eq!(reply(&q, 512).unwrap().len(), q.len() + 16);
    }
}

#[test]
fn dns_other_types_get_an_empty_answer() {
    for (t, c) in [(28, 1), (1, 3), (65, 1)] {
        let q = query("captive.apple.com", t, c);
        let r = reply(&q, 512).unwrap();
        assert_eq!(r.len(), q.len());
        assert_eq!((r[3], r[6], r[7]), (0x80, 0, 0));
    }
}

#[test]
fn dns_things_that_are_ignored() {
    let q = query("example.com", 1, 1);
    let n = q.len();
    for len in [0, 11, 16] {
        assert!(reply(&q[..len.min(n)], 512).is_none());
    }
    let mut m = q.clone();
    m[2] |= 0x80;
    assert!(reply(&m, 512).is_none(), "a response");
    let mut m = q.clone();
    m[2] |= 0x08;
    assert!(reply(&m, 512).is_none(), "opcode 1");
    let mut m = q.clone();
    m[5] = 2;
    assert!(reply(&m, 512).is_none(), "two questions");
    m[5] = 0;
    assert!(reply(&m, 512).is_none(), "none");
    let mut m = q.clone();
    m[12] = 0xc0;
    assert!(reply(&m, 512).is_none(), "compression pointer");
    m[12] = 64;
    assert!(reply(&m, 512).is_none(), "label longer than 63");
    for cut in 0..n {
        assert!(reply(&q[..cut], 512).is_none() || cut >= 17, "truncation at {cut}");
    }
    let mut unterminated = vec![5u8; 40];
    unterminated[..12].fill(0);
    unterminated[5] = 1;
    assert!(reply(&unterminated, 512).is_none());
    assert!(reply(&q, n + 15).is_none(), "output too small for the answer");
    assert_eq!(reply(&q, n + 16).unwrap().len(), n + 16);
}

#[test]
fn dns_trailing_data_is_not_copied() {
    let mut q = query("example.com", 1, 1);
    let n = q.len();
    q.extend_from_slice(&[0xee; 100]);
    let r = reply(&q, 512).unwrap();
    assert_eq!(r.len(), n + 16);
    assert!(!r.contains(&0xee));
}

#[test]
fn dns_oversized_datagram_is_cut_like_recvfrom() {
    let mut q = query("example.com", 1, 1);
    q.resize(1500, 0xee);
    let mut out = [0u8; dns::REPLY_MAX];
    assert_eq!(dns::serve(&q, &mut out), Some(query("example.com", 1, 1).len() + 16));
    // a name that only ends past byte 256 is cut off and ignored
    let long = (0..5).map(|_| "a".repeat(60)).collect::<Vec<_>>().join(".");
    let q = query(&long, 1, 1);
    assert!(q.len() > 256);
    assert_eq!(dns::serve(&q, &mut out), None);
}

fn ip(a: u32, b: u32, c: u32, d: u32) -> u32 {
    a << 24 | b << 16 | c << 8 | d
}

fn classify(peer: u32, setup: bool, host: Option<&str>, origin: Option<&str>) -> Origin {
    let local = if peer & 0xffff_ff00 == ip(192, 168, 4, 0) { ip(192, 168, 4, 1) } else { ip(192, 168, 77, 1) };
    classify_full(Some(peer), Some(local), setup, host, origin)
}

fn classify_full(peer: Option<u32>, local: Option<u32>, setup: bool, host: Option<&str>, origin: Option<&str>) -> Origin {
    classify_f(&Facts { peer, local, setup_active: setup, host: host.map(str::as_bytes), origin: origin.map(str::as_bytes) })
}

fn classify_f(f: &Facts<'_>) -> Origin {
    tdongle_setup::access::classify(f)
}

#[test]
fn access_usb_origin_is_unchanged() {
    let u = ip(192, 168, 77, 2);
    assert_eq!(classify(u, false, Some("192.168.77.1"), None), Origin::Usb);
    assert_eq!(classify(u, false, Some("192.168.77.1:80"), Some("http://192.168.77.1")), Origin::Usb);
    assert_eq!(classify(ip(192, 168, 77, 254), true, Some("192.168.77.1"), Some("http://192.168.77.1:80")), Origin::Usb);
    assert_eq!(classify(u, false, Some("evil.example"), None), Origin::Denied);
    assert_eq!(classify(u, false, None, None), Origin::Denied);
    assert_eq!(classify(u, false, Some("192.168.77.1"), Some("http://evil.example")), Origin::Denied);
    assert_eq!(classify(u, false, Some("192.168.77.1:8080"), None), Origin::Denied);
    assert_eq!(classify_full(None, Some(ip(192, 168, 77, 1)), false, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(classify_full(Some(u), None, false, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(classify(ip(192, 168, 78, 2), false, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(classify(ip(10, 0, 0, 2), false, Some("192.168.77.1"), None), Origin::Denied);
}

#[test]
fn access_setup_access_point_origin() {
    let a = ip(192, 168, 4, 2);
    assert_eq!(classify(a, true, Some("192.168.4.1"), None), Origin::SetupAp);
    assert_eq!(classify(a, true, Some("192.168.4.1:80"), Some("http://192.168.4.1")), Origin::SetupAp);
    assert_eq!(classify(a, false, Some("192.168.4.1"), None), Origin::Denied);
    assert_eq!(classify(a, true, Some("captive.apple.com"), None), Origin::Denied);
    assert_eq!(classify(a, true, Some("192.168.4.1"), Some("http://captive.apple.com")), Origin::Denied);
    assert_eq!(classify(a, true, None, None), Origin::Denied);
    assert!(in_setup_subnet(ip(192, 168, 4, 77)) && !in_setup_subnet(ip(192, 168, 5, 1)) && !in_setup_subnet(ip(192, 168, 77, 2)));
    assert_eq!(classify(a, true, Some("192.168.77.1"), None), Origin::Denied);
    assert_eq!(classify(ip(192, 168, 77, 2), true, Some("192.168.4.1"), None), Origin::Denied);
}

#[test]
fn access_spoofed_sources_are_refused() {
    let c = |peer, local, setup, host| classify_full(Some(peer), Some(local), setup, Some(host), None);
    assert_eq!(c(ip(192, 168, 77, 2), ip(192, 168, 4, 1), true, "192.168.77.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 4, 2), ip(192, 168, 77, 1), true, "192.168.4.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 4, 2), ip(192, 168, 4, 77), true, "192.168.4.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 77, 2), ip(192, 168, 77, 2), false, "192.168.77.1"), Origin::Denied);
    assert_eq!(c(ip(192, 168, 77, 2), ip(192, 168, 77, 1), false, "192.168.77.1"), Origin::Usb);
    assert_eq!(c(ip(192, 168, 4, 2), ip(192, 168, 4, 1), true, "192.168.4.1"), Origin::SetupAp);
}

#[test]
fn access_what_each_origin_may_ask_for() {
    use Endpoint::*;
    let all = [Home, Status, Diagnostics, WifiScan, WifiSaved, Command, BootStatus];
    for e in all {
        assert!(endpoint_allowed(Origin::Usb, e) && !endpoint_allowed(Origin::Denied, e));
    }
    for e in [Home, WifiScan, WifiSaved, Command] {
        assert!(endpoint_allowed(Origin::SetupAp, e));
    }
    for e in [Status, Diagnostics, BootStatus] {
        assert!(!endpoint_allowed(Origin::SetupAp, e));
    }
    for a in [Action::Mode, Action::Wifi, Action::WifiRemove, Action::Add, Action::Remove, Action::Enable, Action::SetupDone] {
        assert!(action_allowed(Origin::Usb, a) && !action_allowed(Origin::Denied, a));
    }
    for a in [Action::Wifi, Action::WifiRemove, Action::SetupDone] {
        assert!(action_allowed(Origin::SetupAp, a));
    }
    for a in [Action::Mode, Action::Add, Action::Remove, Action::Enable] {
        assert!(!action_allowed(Origin::SetupAp, a));
    }
    assert!(!action_allowed(Origin::Usb, Action::Unknown) && !action_allowed(Origin::SetupAp, Action::Unknown));
}

#[test]
fn access_the_open_network_may_add_but_not_rewrite() {
    assert!(may_set_metadata(Origin::Usb) && may_replace(Origin::Usb));
    for o in [Origin::SetupAp, Origin::Denied] {
        assert!(!may_set_metadata(o) && !may_replace(o));
    }
}

#[test]
fn access_actions_parse() {
    for (n, a) in [("mode", Action::Mode), ("wifi", Action::Wifi), ("wifi_remove", Action::WifiRemove), ("add", Action::Add), ("remove", Action::Remove), ("enable", Action::Enable), ("setup_done", Action::SetupDone)] {
        assert_eq!(parse_action(Some(n.as_bytes())), a);
    }
    for n in ["", "WIFI", "wifi "] {
        assert_eq!(parse_action(Some(n.as_bytes())), Action::Unknown);
    }
    assert_eq!(parse_action(None), Action::Unknown);
}

#[test]
fn access_tokens() {
    let random = [0x00, 0x01, 0x0a, 0x0f, 0x10, 0xa5, 0xff, 0x80, 1, 2, 3, 4, 5, 6, 7, 8];
    let t = token_format(&random);
    assert_eq!(&t, b"00010a0f10a5ff800102030405060708");
    assert!(token_equal(Some(&t), &t));
    for i in 0..32 {
        let mut o = t;
        o[i] ^= 1;
        assert!(!token_equal(Some(&o), &t));
    }
    assert!(!token_equal(Some(b""), &t) && !token_equal(None, &t) && !token_equal(Some(&t), b"") && !token_equal(Some(b""), b""));
    assert!(!token_equal(Some(b"0001"), &t) && !token_equal(Some(b"00010a0f10a5ff800102030405060708x"), &t));
}

const M: u32 = MAGIC;

fn d(sr: bool, magic: u32, next: u32, slot: u32, saved: bool, ok: bool) -> Option<u8> {
    SetupBoot::decide(sr, magic, next, slot, saved, ok).map(|b| b.preselect())
}

#[test]
fn boot_decisions() {
    assert_eq!(d(true, M, 1, 0, true, true), Some(0));
    assert_eq!(d(true, M, 1, 3, true, true), Some(3));
    assert_eq!(d(true, M, 1, 9, true, true), Some(0));
    assert_eq!(d(true, M, 1, 0, true, false), Some(0), "explicit request, even over a bad store");
    assert_eq!(d(false, M, 1, 0, true, true), None, "a power cycle with stale RTC contents");
    assert_eq!(d(true, M ^ 1, 1, 0, true, true), None);
    assert_eq!(d(true, M, 7, 0, true, true), None);
    assert_eq!(d(false, 0, 0, 0, false, true), Some(0), "first plug-in");
    assert_eq!(d(false, 0, 0, 0, false, false), None, "never over an unreadable store");
    assert_eq!(d(false, 0, 0, 0, true, true), None);
    assert_eq!(d(true, M, 2, 0, false, true), None, "leaving never loops");
    assert_eq!(d(false, M, 2, 0, false, true), Some(0), "the next cold boot is a first plug-in again");
    assert_eq!(d(true, M, 1, 0, false, true), Some(0));
}

#[test]
fn boot_request_words() {
    assert_eq!(request_words(Request::Enter, 4), (MAGIC, 1, 4));
    assert_eq!(request_words(Request::Enter, 0).2, 0);
    assert_eq!(request_words(Request::Enter, 99).2, 0);
    assert_eq!(request_words(Request::Leave, 4), (MAGIC, 2, 0));
    let (m, n, s) = request_words(Request::Enter, 6);
    assert_eq!(d(true, m, n, s, true, true), Some(6));
}

fn setup() -> SetupBoot {
    SetupBoot::decide(false, 0, 0, 0, false, true).unwrap()
}

#[test]
fn boot_session() {
    assert_eq!(SESSION_MS, 10 * 60 * 1000);
    let i = Session::INACTIVE;
    assert!(!i.expired(1_000_000) && i.seconds_left(0) == 0);
    let s = setup().session(5000);
    assert!(!s.expired(5000) && s.seconds_left(5000) == 600);
    assert_eq!((s.seconds_left(5001), s.seconds_left(6000), s.seconds_left(5000 + 599_000)), (600, 599, 1));
    assert!(!s.expired(5000 + 599_999) && s.expired(5000 + 600_000) && s.seconds_left(5000 + 600_000) == 0);
    assert!(s.expired(5000 + 7_200_000));
    let w = setup().session(0xffff_ff00);
    assert!(!w.expired(0xffff_ff00u32.wrapping_add(599_000)) && w.expired(0xffff_ff00u32.wrapping_add(600_000)));
    assert_eq!(w.seconds_left(0xffff_ff00u32.wrapping_add(1000)), 599);
}

#[test]
fn boot_giving_up() {
    assert!(!Session::INACTIVE.should_end(1_000_000, false));
    let s = setup().session(1000);
    assert!(!s.should_end(1000, false) && !s.should_end(1000 + 29_999, false));
    assert!(s.should_end(1000 + 30_000, false));
    assert!(!s.should_end(1000 + 30_000, true) && !s.should_end(1000 + 599_999, true));
    assert!(s.should_end(1000 + 600_000, true));
    let w = setup().session(0xffff_ff00);
    assert!(!w.should_end(0xffff_ff00u32.wrapping_add(29_999), false) && w.should_end(0xffff_ff00u32.wrapping_add(30_000), false));
}

#[test]
fn boot_failsafe() {
    assert_eq!(Session::INACTIVE.failsafe_delay_ms(5, false), 0);
    let s = setup().session(1000);
    assert_eq!(s.failsafe_delay_ms(1000, false), AP_GRACE_MS);
    assert_eq!(s.failsafe_delay_ms(11_000, false), AP_GRACE_MS - 10_000);
    assert_eq!(s.failsafe_delay_ms(31_000, false), 0);
    assert_eq!(s.failsafe_delay_ms(6000, true), SESSION_MS - 5000);
    assert_eq!(s.failsafe_delay_ms(1000 + 599_999, true), 1);
    assert_eq!(s.failsafe_delay_ms(1000 + 600_000, true), 0);
    // driven as the timer drives it: the AP comes up at 4 s; fires at 30 s (grace), then at the session end
    let (mut now, mut fired, mut up) = (1000u32, 0, false);
    loop {
        if now >= 5000 {
            up = true;
        }
        let dl = s.failsafe_delay_ms(now, up);
        if dl == 0 {
            break;
        }
        now += dl;
        fired += 1;
        assert!(fired < 10);
    }
    assert_eq!((now, fired), (1000 + SESSION_MS, 2));
    now = 1000;
    fired = 0;
    loop {
        let dl = s.failsafe_delay_ms(now, false);
        if dl == 0 {
            break;
        }
        now += dl;
        fired += 1;
    }
    assert_eq!((now, fired), (1000 + AP_GRACE_MS, 1));
}

#[test]
fn boot_access_point_name() {
    let mac = [0x34, 0x85, 0x18, 0xab, 0x0c, 0xf9];
    assert_eq!(&ap_ssid(&mac), b"TDongle-AB0CF9");
    let mut small = [b'x'; 8];
    assert_eq!(ap_ssid_into(&mut small, &mac), 7);
    assert_eq!(&small, b"TDongle\0");
}
