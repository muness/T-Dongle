//! The portal as a whole, on the host: every rule of ADR 0024 as a test, the response bytes, the page, the setup page's requests against
//! the allowlist (`tests/test_setup_page.py`), and the exclusion rules (`tests/test_setup_exclusion.py`, `tests/test_open_ap.py`).
mod common;
use common::*;
use tdongle_setup::boot::{Boot, SetupBoot};
use tdongle_setup::http::{HttpError, Reader, Step, MAX_BODY, MAX_HEAD, MAX_URI, RECV_TIMEOUT_MS};
use tdongle_setup::page;
use tdongle_setup::response::{ErrCode, Response};
use tdongle_setup::router::Conn;

const H: &str = "192.168.4.1";

fn tok_hdr(p: &tdongle_setup::router::Portal) -> String {
    format!("X-Setup-Token: {}\r\n", token(p))
}

fn text(r: &[u8]) -> String {
    String::from_utf8_lossy(r).into_owned()
}

fn run(raw: &[u8]) -> (String, FakeHost) {
    let p = portal();
    let mut h = FakeHost::new();
    let (r, _) = exchange(&p, &ap_conn(), &mut h, raw);
    (text(&r), h)
}

fn has_error(resp: &str, status: &str, msg: &str) -> bool {
    resp.starts_with(&format!("HTTP/1.1 {status}\r\n")) && resp.contains(msg)
}

// ------------------------------------------------------------------------------------------------ response bytes

#[test]
fn forbidden_bytes() {
    let p = portal();
    let mut h = FakeHost::new();
    let (r, close) = exchange(&p, &ap_conn(), &mut h, &get("/status", H, &tok_hdr(&p)));
    assert_eq!(text(&r), "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 19\r\n\r\nUSB access required");
    assert!(!close, "a handler's 403 keeps the connection (the C handler returns the send result)");
}

#[test]
fn captive_redirect_bytes() {
    for path in ["/generate_204", "/hotspot-detect.html", "/connecttest.txt", "/ncsi.txt", "/redirect", "/fwlink/", "/library/test/success.html", "/favicon.ico", "/canonical.html", "/success.txt", "/wifi-scan/", "/Command", "//"] {
        let (r, _) = run(&get(path, "connectivitycheck.gstatic.com", ""));
        assert_eq!(
            r,
            "HTTP/1.1 302 Found\r\nContent-Type: text/html\r\nContent-Length: 0\r\nLocation: http://192.168.4.1/\r\nCache-Control: no-store\r\n\r\n",
            "{path}"
        );
    }
}

#[test]
fn probes_for_the_known_os_checks_redirect_even_with_a_query_and_any_host() {
    for (path, host) in [("/generate_204?x=1", "clients3.google.com"), ("/hotspot-detect.html", "captive.apple.com"), ("/connecttest.txt", "www.msftconnecttest.com"), ("/", "captive.apple.com")] {
        let (r, _) = run(&get(path, host, ""));
        assert!(r.starts_with("HTTP/1.1 302 Found\r\n") && r.contains("Location: http://192.168.4.1/\r\n"), "{path} {host}: {r}");
    }
}

#[test]
fn page_headers_and_body_are_the_c_page_with_the_token() {
    let p = portal();
    let mut h = FakeHost::new();
    let (r, close) = exchange(&p, &ap_conn(), &mut h, &get("/", H, ""));
    assert!(!close);
    let head_end = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    assert_eq!(
        text(&r[..head_end + 4]),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {}\r\n\r\n",
            page::AP_CSP
        )
    );
    // de-chunk
    let mut body = Vec::new();
    let mut rest = &r[head_end + 4..];
    let mut chunks = 0;
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n").unwrap();
        let n = usize::from_str_radix(std::str::from_utf8(&rest[..eol]).unwrap(), 16).unwrap();
        rest = &rest[eol + 2..];
        if n == 0 {
            assert_eq!(rest, b"\r\n");
            break;
        }
        body.extend_from_slice(&rest[..n]);
        assert_eq!(&rest[n..n + 2], b"\r\n");
        rest = &rest[n + 2..];
        chunks += 1;
    }
    assert_eq!(chunks, 3, "before the token, the token, after it");
    let want = text(page::SETUP_AP_HTML).replace("@@TOKEN@@", &token(&p));
    assert_eq!(text(&body), want);
    assert!(text(&body).contains(&format!("const token='{}';", token(&p))));
}

#[test]
fn wifi_saved_bytes_for_the_setup_network_hide_priority_and_preference() {
    let p = portal();
    let mut h = FakeHost::new();
    h.saved = vec![(b"home".to_vec(), b"My Home".to_vec(), 90), (b"cafe\"x".to_vec(), b"c".to_vec(), 10)];
    h.preferred = Some(0);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &tok_hdr(&p)));
    let body = text(&body_of(&r));
    assert_eq!(body, r#"{"ok":true,"networks":[{"slot":1,"name":"home","ssid":"home"},{"slot":2,"name":"cafe\"x","ssid":"cafe\"x"}],"free":3,"max":8}"#);
    assert!(r.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "));
    assert!(text(&r).contains("\r\nCache-Control: no-store\r\n\r\n"));
    assert!(!h.locked, "the settings lock is released");
}

#[test]
fn wifi_saved_for_usb_has_everything() {
    let p = portal();
    let mut h = FakeHost::new();
    h.saved = vec![(b"home".to_vec(), b"My Home".to_vec(), 90)];
    h.preferred = Some(0);
    let usb = Conn { peer: Some(USB_PEER), local: Some(USB_LOCAL) };
    let (r, _) = exchange(&p, &usb, &mut h, &get("/wifi-saved", "192.168.77.1", ""));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true,"networks":[{"slot":1,"name":"My Home","ssid":"home","priority":90,"preferred":true}],"free":2,"max":8}"#);
}

#[test]
fn free_slot_and_preselect() {
    let mut p = portal();
    let mut h = FakeHost::new();
    h.saved = (0..8).map(|i| (format!("n{i}").into_bytes(), vec![], 50)).collect();
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &tok_hdr(&p)));
    assert!(text(&body_of(&r)).ends_with(r#""free":0,"max":8}"#), "all eight used and none preselected");
    p.set_preselect(3);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &tok_hdr(&p)));
    assert!(text(&body_of(&r)).ends_with(r#""free":3,"max":8}"#));
    h.saved.truncate(1);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &tok_hdr(&p)));
    assert!(text(&body_of(&r)).ends_with(r#""free":2,"max":8}"#), "a preselect beyond count + 1 is ignored");
}

#[test]
fn json_failure_bytes() {
    let p = portal();
    let mut h = FakeHost::new();
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &tok_hdr(&p), "{\"action\":\"mode\"}"));
    let body = r#"{"ok":false,"error":"That is not available from the setup network"}"#;
    assert_eq!(text(&r), format!("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{body}", body.len()));
}

#[test]
fn scan_requests_a_scan_only_when_asked() {
    let p = portal();
    let mut h = FakeHost::new();
    h.busy = true;
    for (q, again) in [("", false), ("?again=1", true), ("?x=again", true), ("?AGAIN", false), ("?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&again", false)] {
        h.kicks.clear();
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(&format!("/wifi-scan{q}"), H, &tok_hdr(&p)));
        assert_eq!(h.kicks, vec![again], "{q}");
        assert_eq!(text(&body_of(&r)), r#"{"ok":true,"busy":true,"networks":[]}"#);
    }
    h.ready = false;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-scan", H, &tok_hdr(&p)));
    assert!(has_error(&text(&r), "400 Bad Request", "Wi-Fi startup failed; saved diagnostics contain the reason"));
}

// ------------------------------------------------------------------------------------------------ ADR 0024 rules

#[test]
fn rule_token_is_required_and_constant_time_checked() {
    let p = portal();
    let mut h = FakeHost::new();
    let wrong = "X-Setup-Token: 00000000000000000000000000000000\r\n";
    let mut flipped = token(&p);
    flipped.replace_range(31.., if flipped.ends_with('0') { "1" } else { "0" });
    let flipped = format!("X-Setup-Token: {flipped}\r\n");
    let longer = format!("X-Setup-Token: {}0\r\n", token(&p));
    let empty = "X-Setup-Token:\r\n".to_string();
    for extra in ["", wrong, flipped.as_str(), longer.as_str(), empty.as_str()] {
        for path in ["/wifi-scan", "/wifi-saved"] {
            let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(path, H, extra));
            assert!(has_error(&text(&r), "403 Forbidden", "Invalid setup token"), "{path} {extra:?}");
        }
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, extra, "{\"action\":\"setup_done\"}"));
        assert!(has_error(&text(&r), "403 Forbidden", "Invalid setup token"));
    }
    assert_eq!(h.leave_requests, 0, "nothing was done without the token");
    assert!(h.kicks.is_empty() && h.saves.is_empty());
    // the page itself is open: that is how a phone gets the token
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/", H, ""));
    assert!(text(&r).starts_with("HTTP/1.1 200 OK"));
    // the token is per boot
    let other = Portal2::new([0x22; 16]);
    assert_ne!(token(&p), token(&other));
}

#[test]
fn token_header_lookup_is_case_insensitive_and_first_wins() {
    let p = portal();
    let mut h = FakeHost::new();
    let t = token(&p);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &format!("x-setup-token: {t}\r\n")));
    assert!(text(&r).starts_with("HTTP/1.1 200 OK"));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &format!("X-Setup-Token: nope\r\nX-Setup-Token: {t}\r\n")));
    assert!(has_error(&text(&r), "403 Forbidden", "Invalid setup token"), "the C reads the first one");
}

type Portal2 = TestPortal;
struct TestPortal;
impl TestPortal {
    fn new(random: [u8; 16]) -> tdongle_setup::router::Portal {
        let boot = SetupBoot::decide(false, 0, 0, 0, false, true).unwrap();
        tdongle_setup::router::Portal::new(&boot, &random, &[0; 6], 0)
    }
}

#[test]
fn rule_host_must_be_the_canonical_name() {
    let p = portal();
    let mut h = FakeHost::new();
    for host in ["captive.apple.com", "evil.example", "192.168.4.2", "192.168.4.1:8080", "192.168.4.1.evil.example", "192.168.77.1", "", "localhost", "192.168.4.1 "] {
        for path in ["/wifi-scan", "/wifi-saved"] {
            let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(path, host, &tok_hdr(&p)));
            let r = text(&r);
            assert!(r.starts_with("HTTP/1.1 403 Forbidden") && r.contains("USB access required"), "{host:?} {path}: {r}");
        }
        // DNS rebinding: the page itself under a foreign name is a redirect to the canonical address, never the page or the token
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/", host, ""));
        let r = text(&r);
        assert!(r.starts_with("HTTP/1.1 302 Found") && !r.contains(&token(&p)), "{host:?}");
    }
    // no Host at all (HTTP/1.0)
    let (r, _) = exchange(&p, &ap_conn(), &mut h, b"GET /wifi-saved HTTP/1.0\r\nX-Setup-Token: x\r\n\r\n");
    assert!(text(&r).starts_with("HTTP/1.1 403 Forbidden"));
    for host in ["192.168.4.1", "192.168.4.1:80"] {
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", host, &tok_hdr(&p)));
        assert!(text(&r).starts_with("HTTP/1.1 200 OK"));
    }
    // a Host of 64 or more bytes does not fit the C buffer and counts as absent
    let long = format!("192.168.4.1{}", " ".repeat(60));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", &long, &tok_hdr(&p)));
    assert!(text(&r).starts_with("HTTP/1.1 403"));
}

#[test]
fn rule_peer_must_be_on_the_ap_subnet_and_reach_the_aps_own_address() {
    let p = portal();
    let mut h = FakeHost::new();
    let req = get("/wifi-saved", H, &tok_hdr(&p));
    let bad = [
        Conn { peer: Some(0x0a00_0005), local: Some(0xc0a8_0401) },
        Conn { peer: Some(0xc0a8_0502), local: Some(0xc0a8_0401) },
        Conn { peer: Some(0xc0a8_4d02), local: Some(0xc0a8_0401) }, // forged USB source arriving on the AP address
        Conn { peer: Some(0xc0a8_0402), local: Some(0xc0a8_4d01) }, // AP source addressed to the USB side
        Conn { peer: Some(0xc0a8_0402), local: Some(0xc0a8_044d) }, // not the dongle's own address
        Conn { peer: None, local: Some(0xc0a8_0401) },
        Conn { peer: Some(0xc0a8_0402), local: None },
        Conn { peer: Some(0x7f00_0001), local: Some(0x7f00_0001) },
    ];
    for c in bad {
        let (r, _) = exchange(&p, &c, &mut h, &req);
        assert!(text(&r).starts_with("HTTP/1.1 403 Forbidden"), "{c:?}");
        let (r, _) = exchange(&p, &c, &mut h, &post("/command", H, &tok_hdr(&p), "{\"action\":\"setup_done\"}"));
        assert!(text(&r).starts_with("HTTP/1.1 403 Forbidden"), "{c:?}");
    }
    assert_eq!(h.leave_requests, 0);
}

#[test]
fn rule_off_subnet_clients_get_no_redirect_and_no_page() {
    let p = portal();
    let mut h = FakeHost::new();
    let off = Conn { peer: Some(0x0a00_0005), local: Some(0xc0a8_0401) };
    let (r, _) = exchange(&p, &off, &mut h, &get("/", H, ""));
    assert!(has_error(&text(&r), "403 Forbidden", "Open this page through USB Ethernet at 192.168.77.1") && !text(&r).contains(&token(&p)));
    let (r, _) = exchange(&p, &off, &mut h, &get("/generate_204", H, ""));
    assert!(has_error(&text(&r), "404 Not Found", "Not found"));
}

#[test]
fn rule_endpoint_allowlist() {
    let p = portal();
    let mut h = FakeHost::new();
    for path in ["/status", "/diagnostics", "/boot-status"] {
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(path, H, &tok_hdr(&p)));
        assert!(has_error(&text(&r), "403 Forbidden", "USB access required"), "{path}");
    }
    // anything else is a captive-portal probe, never a handler
    for path in ["/admin", "/command/", "/wifi", "/status/", "/STATUS", "/../status", "/%73tatus", "/status%00", "/status?x"] {
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(path, H, &tok_hdr(&p)));
        let r = text(&r);
        if path == "/status?x" {
            assert!(r.starts_with("HTTP/1.1 403"), "the query is not part of the path");
        } else {
            assert!(r.starts_with("HTTP/1.1 302 Found"), "{path}: {r}");
        }
    }
}

#[test]
fn rule_action_allowlist_from_the_setup_network() {
    let p = portal();
    let mut h = FakeHost::new();
    for a in ["mode", "add", "remove", "enable"] {
        let body = format!("{{\"action\":\"{a}\",\"mode\":\"tailnet_gateway\",\"label\":\"x\",\"key\":\"k\",\"id\":1,\"enabled\":true}}");
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &tok_hdr(&p), &body));
        assert!(has_error(&text(&r), "400 Bad Request", "That is not available from the setup network"), "{a}");
    }
    for a in ["", "nope", "WIFI", "Wifi", "wifi ", "setup"] {
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &tok_hdr(&p), &format!("{{\"action\":\"{a}\"}}")));
        assert!(has_error(&text(&r), "400 Bad Request", "That is not available from the setup network"), "{a:?}");
    }
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &tok_hdr(&p), "{}"));
    assert!(has_error(&text(&r), "400 Bad Request", "not available"));
    assert!(h.saves.is_empty() && h.removes.is_empty() && h.leave_requests == 0 && !h.locked);
}

#[test]
fn rule_the_setup_network_may_add_and_delete_but_not_rewrite() {
    let p = portal();
    let mut h = FakeHost::new();
    let t = tok_hdr(&p);
    // a name and a priority are ignored, the defaults apply
    let body = r#"{"action":"wifi","ssid":"cafe","password":"hunter22","name":"Evil","priority":100,"slot":1}"#;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, body));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    assert_eq!(h.saves, vec![(b"cafe".to_vec(), b"hunter22".to_vec(), None, -1, 0)]);
    // the same network again, or any occupied slot: refused
    let again = r#"{"action":"wifi","ssid":"cafe","password":"another99","slot":3}"#;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, again));
    assert!(text(&r).contains("That network is already saved. Delete it first to change it"));
    let occupied = r#"{"action":"wifi","ssid":"other","password":"another99","slot":1}"#;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, occupied));
    assert!(text(&r).contains("That network is already saved"));
    assert_eq!(h.saves.len(), 1);
    // a free slot works
    let free = r#"{"action":"wifi","ssid":"other","password":"","slot":2}"#;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, free));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    // short passwords are refused on the setup network only
    let short = r#"{"action":"wifi","ssid":"x","password":"short"}"#;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, short));
    assert!(text(&r).contains("Passwords need at least 8 characters. Leave it empty only for an open network."));
    // deleting is allowed
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"wifi_remove","ssid":"cafe"}"#));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    assert_eq!(h.removes, vec![b"cafe".to_vec()]);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"wifi_remove","ssid":"missing"}"#));
    assert!(text(&r).contains("Could not remove that saved network"));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"wifi_remove"}"#));
    assert!(text(&r).contains("Could not remove that saved network"));
}

#[test]
fn usb_origin_keeps_everything_in_a_setup_boot_it_cannot_actually_have() {
    let p = portal();
    let mut h = FakeHost::new();
    h.saved = vec![(b"cafe".to_vec(), b"c".to_vec(), 50)];
    let usb = Conn { peer: Some(USB_PEER), local: Some(USB_LOCAL) };
    let body = r#"{"action":"wifi","ssid":"cafe","password":"another99","name":"Cafe","priority":7,"slot":1}"#;
    let (r, _) = exchange(&p, &usb, &mut h, &post("/command", "192.168.77.1", "", body));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    assert_eq!(h.saves.last().unwrap(), &(b"cafe".to_vec(), b"another99".to_vec(), Some(b"Cafe".to_vec()), 7, 0));
    // the tailnet seam answers the C's "not available" text
    for a in ["mode", "add", "remove", "enable"] {
        let (r, _) = exchange(&p, &usb, &mut h, &post("/command", "192.168.77.1", "", &format!("{{\"action\":\"{a}\"}}")));
        assert!(text(&r).contains("That is not available from the setup network"), "{a}");
    }
    let (r, _) = exchange(&p, &usb, &mut h, &post("/command", "192.168.77.1", "", r#"{"action":"zzz"}"#));
    assert!(text(&r).contains("Unknown action"));
    for path in ["/status", "/diagnostics", "/boot-status"] {
        let (r, _) = exchange(&p, &usb, &mut h, &get(path, "192.168.77.1", ""));
        assert!(text(&r).contains("not available"), "{path}");
    }
    let (r, _) = exchange(&p, &usb, &mut h, &get("/", "192.168.77.1", ""));
    assert!(text(&r).starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ") && text(&r).contains(page::USB_CSP));
}

#[test]
fn wifi_field_validation_texts() {
    let p = portal();
    let t = tok_hdr(&p);
    let cases: &[(&str, &str)] = &[
        (r#"{"action":"wifi"}"#, "Enter a valid Wi-Fi name and password"),
        (r#"{"action":"wifi","ssid":"a"}"#, "Enter a valid Wi-Fi name and password"),
        (r#"{"action":"wifi","ssid":"","password":""}"#, "Enter a valid Wi-Fi name and password"),
        (r#"{"action":"wifi","ssid":"123456789012345678901234567890123","password":""}"#, "Enter a valid Wi-Fi name and password"),
        (r#"{"action":"wifi","ssid":"a","password":5}"#, "Enter a valid Wi-Fi name and password"),
        (r#"{"action":"wifi","ssid":"a","password":"","slot":0}"#, "Use a name of up to 24 plain characters, a slot from 1 to 8 and a priority from 0 to 100"),
        (r#"{"action":"wifi","ssid":"a","password":"","slot":9}"#, "Use a name of up to 24"),
        (r#"{"action":"wifi","ssid":"a","password":"","slot":1.5}"#, "Use a name of up to 24"),
        (r#"{"action":"wifi","ssid":"a","password":"","slot":"1"}"#, "Use a name of up to 24"),
        (r#"{"action":"wifi","ssid":"a","password":"","slot":null}"#, "Use a name of up to 24"),
    ];
    for (body, msg) in cases {
        let mut h = FakeHost::new();
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, body));
        assert!(has_error(&text(&r), "400 Bad Request", msg), "{body}: {}", text(&r));
        assert!(h.saves.is_empty());
    }
    // a full store
    let mut h = FakeHost::new();
    h.save_ok = false;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"wifi","ssid":"a","password":""}"#));
    assert!(text(&r).contains("Could not save Wi-Fi; at most eight networks can be saved, and a network can only be in one slot"));
}

#[test]
fn usb_origin_validates_name_and_priority() {
    let p = portal();
    let usb = Conn { peer: Some(USB_PEER), local: Some(USB_LOCAL) };
    let mut h = FakeHost::new();
    for body in [r#"{"action":"wifi","ssid":"a","password":"","name":"bad\u0001"}"#, r#"{"action":"wifi","ssid":"a","password":"","priority":101}"#, r#"{"action":"wifi","ssid":"a","password":"","priority":-1}"#] {
        let (r, _) = exchange(&p, &usb, &mut h, &post("/command", "192.168.77.1", "", body));
        assert!(text(&r).contains("Use a name of up to 24 plain characters"), "{body}");
    }
    let (r, _) = exchange(&p, &usb, &mut h, &post("/command", "192.168.77.1", "", r#"{"action":"wifi","ssid":"a","password":"","name":""}"#));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    assert_eq!(h.saves[0].2, None, "an empty name is the default name");
}

#[test]
fn setup_done_leaves_and_reports_failure() {
    let p = portal();
    let t = tok_hdr(&p);
    let mut h = FakeHost::new();
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"setup_done"}"#));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    assert_eq!(h.leave_requests, 1);
    h.leave_ok = false;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"setup_done"}"#));
    assert!(text(&r).contains("Setup is not running"));
}

#[test]
fn locks_recovery_and_wifi_not_ready() {
    let p = portal();
    let t = tok_hdr(&p);
    let mut h = FakeHost::new();
    h.lock_ok = false;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"setup_done"}"#));
    assert!(text(&r).contains("Memberships are busy; retry shortly"));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &t));
    assert!(text(&r).contains("Settings are busy; retry shortly"));
    let mut h = FakeHost::new();
    h.recovery = true;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"setup_done"}"#));
    assert!(text(&r).contains("Recovery mode: settings are preserved. Use Restart services in the app after saving diagnostics."));
    assert_eq!(h.leave_requests, 0);
    let mut h = FakeHost::new();
    h.ready = false;
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, r#"{"action":"wifi","ssid":"a","password":""}"#));
    assert!(text(&r).contains("Wi-Fi did not start; restart services after saving diagnostics"));
    assert!(!h.locked);
}

// ------------------------------------------------------------------------------------------------ cross-origin, sizes, methods

#[test]
fn rule_cross_origin_is_refused_and_no_cors_header_exists() {
    let p = portal();
    let mut h = FakeHost::new();
    let t = tok_hdr(&p);
    for origin in ["http://evil.example", "https://192.168.4.1", "null", "http://192.168.4.1.evil.example", "http://192.168.4.1:8080", "http://192.168.77.1"] {
        for path in ["/wifi-scan", "/wifi-saved"] {
            let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(path, H, &format!("{t}Origin: {origin}\r\n")));
            assert!(text(&r).starts_with("HTTP/1.1 403 Forbidden"), "{origin} {path}");
        }
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &format!("{t}Origin: {origin}\r\n"), r#"{"action":"setup_done"}"#));
        assert!(text(&r).starts_with("HTTP/1.1 403 Forbidden"), "{origin}");
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/", H, &format!("Origin: {origin}\r\n")));
        assert!(text(&r).starts_with("HTTP/1.1 302 Found") && !text(&r).contains(&token(&p)), "{origin}: the page and its token never go to a foreign origin");
    }
    assert_eq!(h.leave_requests, 0);
    for origin in ["http://192.168.4.1", "http://192.168.4.1:80"] {
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &format!("{t}Origin: {origin}\r\n")));
        assert!(text(&r).starts_with("HTTP/1.1 200 OK"));
        assert!(!text(&r).to_ascii_lowercase().contains("access-control"), "no CORS header is ever sent");
    }
    // an Origin that does not fit the C buffer (96 bytes) is refused outright
    let long = format!("http://192.168.4.1/{}", "a".repeat(80));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &format!("{t}Origin: {long}\r\n")));
    assert!(text(&r).starts_with("HTTP/1.1 403"));
    // C quirk kept: an empty Origin header counts as absent
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/wifi-saved", H, &format!("{t}Origin:\r\n")));
    assert!(text(&r).starts_with("HTTP/1.1 200 OK"));
}

#[test]
fn preflight_and_other_methods_are_405_and_close() {
    let p = portal();
    let mut h = FakeHost::new();
    for (method, path) in [("OPTIONS", "/command"), ("GET", "/command"), ("POST", "/wifi-scan"), ("POST", "/"), ("HEAD", "/"), ("PUT", "/wifi-saved"), ("DELETE", "/command"), ("PATCH", "/"), ("TRACE", "/")] {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: {H}\r\nOrigin: http://evil.example\r\nAccess-Control-Request-Method: POST\r\n\r\n");
        let (r, close) = exchange(&p, &ap_conn(), &mut h, raw.as_bytes());
        assert_eq!(text(&r), "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\nSpecified method is invalid for this resource", "{method} {path}");
        assert!(close);
    }
    // an unknown method token is a 400
    let (r, close) = exchange(&p, &ap_conn(), &mut h, b"BREW / HTTP/1.1\r\n\r\n");
    assert!(text(&r).starts_with("HTTP/1.1 400 Bad Request") && close);
}

#[test]
fn rule_body_limits_and_content_type() {
    let p = portal();
    let t = tok_hdr(&p);
    let mut h = FakeHost::new();
    let big = "x".repeat(MAX_BODY + 1);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, &big));
    assert!(text(&r).contains("Request is too large"));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, ""));
    assert!(text(&r).contains("Request is too large"), "an empty body");
    let (r, _) = exchange(&p, &ap_conn(), &mut h, format!("POST /command HTTP/1.1\r\nHost: {H}\r\n{t}Content-Type: application/json\r\n\r\n").as_bytes());
    assert!(text(&r).contains("Request is too large"), "no Content-Length");
    // exactly the limit is read and judged as JSON
    let exact = format!("{{\"action\":\"setup_done\"}}{}", " ".repeat(MAX_BODY - 23));
    assert_eq!(exact.len(), MAX_BODY);
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, &exact));
    assert_eq!(text(&body_of(&r)), r#"{"ok":true}"#);
    // content types: exact match only
    for ct in ["text/plain", "application/json; charset=utf-8", "Application/JSON", "application/jsonx", ""] {
        let raw = format!("POST /command HTTP/1.1\r\nHost: {H}\r\n{t}Content-Type: {ct}\r\nContent-Length: 2\r\n\r\n{{}}");
        let (r, _) = exchange(&p, &ap_conn(), &mut h, raw.as_bytes());
        assert!(text(&r).contains("JSON required"), "{ct:?}");
    }
    let raw = format!("POST /command HTTP/1.1\r\nHost: {H}\r\n{t}Content-Length: 2\r\n\r\n{{}}");
    let (r, _) = exchange(&p, &ap_conn(), &mut h, raw.as_bytes());
    assert!(text(&r).contains("JSON required"));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, "{not json"));
    assert!(text(&r).contains("Invalid JSON"));
    // a chunked body has content_len 0 in the C: refused, and the connection is closed so its chunks are not read as a request
    let raw = format!("POST /command HTTP/1.1\r\nHost: {H}\r\n{t}Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n");
    let (r, close) = exchange(&p, &ap_conn(), &mut h, raw.as_bytes());
    assert!(text(&r).contains("Request is too large") && close);
}

#[test]
fn rule_request_size_limits() {
    let p = portal();
    let mut h = FakeHost::new();
    // URI: 512 bytes of request line is the window
    let path = format!("/{}", "a".repeat(MAX_URI + 10));
    let (r, close) = exchange(&p, &ap_conn(), &mut h, &get(&path, H, ""));
    assert_eq!(text(&r), "HTTP/1.1 414 URI Too Long\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\nURI is too long");
    assert!(close);
    let ok_path = format!("/{}", "a".repeat(400));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get(&ok_path, H, ""));
    assert!(text(&r).starts_with("HTTP/1.1 302 Found"), "a long probe path still redirects");
    // headers
    let filler = format!("X-Pad: {}\r\n", "p".repeat(MAX_HEAD));
    let (r, close) = exchange(&p, &ap_conn(), &mut h, &get("/", H, &filler));
    assert!(text(&r).starts_with("HTTP/1.1 431 Request Header Fields Too Large") && close);
    let mut many = String::new();
    for i in 0..200 {
        many.push_str(&format!("X-{i}: v\r\n"));
    }
    let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/", H, &many));
    assert!(text(&r).starts_with("HTTP/1.1 431"));
    // version
    let (r, _) = exchange(&p, &ap_conn(), &mut h, b"GET / HTTP/2.0\r\nHost: 192.168.4.1\r\n\r\n");
    assert!(text(&r).starts_with("HTTP/1.1 505 Version Not Supported"));
    let (r, _) = exchange(&p, &ap_conn(), &mut h, b"GET / HTTP/1.0\r\n\r\n");
    assert!(text(&r).starts_with("HTTP/1.1 302"), "HTTP/1.0 without Host is parsed, then judged by the rules");
    // malformed
    for bad in [&b"GET /\r\n\r\n"[..], b"GET  / HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n", b"GET / HTTP/1.1\r\n folded\r\n\r\n", b"GET / HTTP/1.1\r\nNoColon\r\n\r\n", b"GET\x00/ HTTP/1.1\r\n\r\n", b"get / HTTP/1.1\r\n\r\n"] {
        let (r, close) = exchange(&p, &ap_conn(), &mut h, bad);
        assert!(text(&r).starts_with("HTTP/1.1 400 Bad Request") && close, "{:?}", text(bad));
    }
    // duplicate or bad Content-Length, upgrade
    for bad in ["Content-Length: 1\r\nContent-Length: 1\r\n", "Content-Length: abc\r\n", "Content-Length: -1\r\n", "Content-Length: 99999999999999999999999\r\n", "Connection: Upgrade\r\nUpgrade: websocket\r\n"] {
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &get("/", H, bad));
        assert!(text(&r).starts_with("HTTP/1.1 400"), "{bad:?}");
    }
    // an absolute URL without a path: the C closes without answering
    let mut reader = Reader::new(0);
    let (_, step) = reader.push(b"GET http://192.168.4.1 HTTP/1.1\r\nHost: 192.168.4.1\r\n\r\n", 0);
    assert_eq!(step, Step::Ready);
    let mut out = [0u8; 64];
    let resp = p.serve(&ap_conn(), &reader.request().unwrap(), tdongle_setup::router::BodyIn::NONE, &mut h, &mut out);
    assert!(resp.silent && resp.close);
    // an absolute URL with a path is routed by its path
    let (r, _) = exchange(&p, &ap_conn(), &mut h, b"GET http://192.168.4.1/ HTTP/1.1\r\nHost: 192.168.4.1\r\n\r\n");
    assert!(text(&r).starts_with("HTTP/1.1 200 OK"));
}

// ------------------------------------------------------------------------------------------------ slow and partial requests

fn feed_by(chunk: usize, raw: &[u8]) -> (Vec<u8>, Step) {
    let mut reader = Reader::new(0);
    let mut step = Step::More;
    let mut at = 0;
    let mut now = 0;
    while at < raw.len() && step == Step::More {
        let end = (at + chunk).min(raw.len());
        let (used, s) = reader.push(&raw[at..end], now);
        at += used;
        step = s;
        now += 10;
    }
    let req = reader.request().map(|r| (r.uri.to_vec(), r.content_len));
    (format!("{req:?}{:?}", reader.body()).into_bytes(), step)
}

#[test]
fn partial_requests_give_the_same_result_whatever_the_chunking() {
    let p = portal();
    let raws = [
        get("/wifi-saved", H, &tok_hdr(&p)),
        post("/command", H, &tok_hdr(&p), r#"{"action":"setup_done"}"#),
        get(&format!("/{}", "a".repeat(600)), H, ""),
        get("/", H, &format!("X-Pad: {}\r\n", "p".repeat(2000))),
        b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n".to_vec(),
    ];
    for raw in raws {
        let whole = feed_by(raw.len(), &raw);
        for chunk in [1, 2, 3, 7, 64, 100] {
            assert_eq!(feed_by(chunk, &raw), whole, "chunk {chunk}");
        }
    }
}

#[test]
fn a_request_trickled_in_bytes_is_served_like_a_whole_one() {
    let p = portal();
    let raw = post("/command", H, &tok_hdr(&p), r#"{"action":"setup_done"}"#);
    let mut reader = Reader::new(0);
    let mut now = 0;
    for (i, b) in raw.iter().enumerate() {
        now += 4000; // each gap is under the 5 s receive timeout: the C keeps waiting
        let (used, step) = reader.push(std::slice::from_ref(b), now);
        assert_eq!(used, 1);
        assert_eq!(step, if i + 1 == raw.len() { Step::Ready } else { Step::More });
    }
}

#[test]
fn receive_timeout_before_the_head_is_a_408_and_a_close() {
    let mut reader = Reader::new(1000);
    let (_, step) = reader.push(b"GET / HT", 1000);
    assert_eq!(step, Step::More);
    assert_eq!(reader.timeout(1000 + RECV_TIMEOUT_MS - 1), Step::More);
    assert_eq!(reader.timeout(1000 + RECV_TIMEOUT_MS), Step::Reject(HttpError::Timeout));
    let r = Response::error(ErrCode::Timeout, None, true);
    let mut buf = [0u8; 200];
    let n = r.write_into(&mut buf).unwrap();
    assert_eq!(text(&buf[..n]), "HTTP/1.1 408 Request Timeout\r\nContent-Type: text/html\r\nContent-Length: 29\r\n\r\nServer closed this connection");
    // a connection that never sends anything
    let mut idle = Reader::new(0);
    assert_eq!(idle.timeout(RECV_TIMEOUT_MS), Step::Reject(HttpError::Timeout));
    // the timer is wrap safe
    let mut wrap = Reader::new(u32::MAX - 100);
    assert_eq!(wrap.timeout((u32::MAX - 100).wrapping_add(RECV_TIMEOUT_MS)), Step::Reject(HttpError::Timeout));
}

#[test]
fn receive_timeout_in_the_body_is_incomplete_request() {
    let p = portal();
    let t = tok_hdr(&p);
    let raw = format!("POST /command HTTP/1.1\r\nHost: {H}\r\n{t}Content-Type: application/json\r\nContent-Length: 40\r\n\r\n{{\"action\":");
    let mut reader = Reader::new(0);
    let (_, step) = reader.push(raw.as_bytes(), 0);
    assert_eq!(step, Step::More);
    assert_eq!(reader.timeout(RECV_TIMEOUT_MS), Step::Ready);
    assert!(reader.body_incomplete() && reader.must_close());
    let mut h = FakeHost::new();
    let mut out = vec![0u8; 1024];
    let resp = p.serve(&ap_conn(), &reader.request().unwrap(), tdongle_setup::router::BodyIn { bytes: reader.body(), incomplete: true }, &mut h, &mut out);
    let mut buf = vec![0u8; 1024];
    let n = resp.write_into(&mut buf).unwrap();
    assert!(text(&buf[..n]).contains("Incomplete request"));
    assert_eq!(h.leave_requests, 0);
}

#[test]
fn a_pipelined_second_request_is_left_unread() {
    let mut reader = Reader::new(0);
    let two = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
    let (used, step) = reader.push(two, 0);
    assert_eq!(step, Step::Ready);
    assert_eq!(used, 27);
}

// ------------------------------------------------------------------------------------------------ the page

fn script() -> String {
    let html = text(page::SETUP_AP_HTML);
    let a = html.find("<script>").unwrap() + 8;
    let b = html.rfind("</script>").unwrap();
    html[a..b].to_string()
}

#[test]
fn assets_are_the_c_files_byte_for_byte() {
    let root = format!("{}/../../../alternative/tailnet/main", env!("CARGO_MANIFEST_DIR"));
    assert_eq!(page::SETUP_AP_HTML, std::fs::read(format!("{root}/setup_ap.html")).unwrap().as_slice());
    assert_eq!(page::SETUP_HTML, std::fs::read(format!("{root}/setup.html")).unwrap().as_slice());
}

#[test]
fn the_page_carries_the_token_on_every_request() {
    let html = text(page::SETUP_AP_HTML);
    assert_eq!(html.matches("@@TOKEN@@").count(), 1);
    assert!(html.contains("const token='@@TOKEN@@';"));
    let s = script();
    assert!(s.contains("const H={'X-Setup-Token':token}"));
    assert_eq!(s.matches("fetch(").count(), 1);
    assert!(s.contains("Object.assign({headers:H},opt||{})"));
    assert!(s.contains("headers:Object.assign({'Content-Type':'application/json'},H)"));
}

#[test]
fn the_page_stays_on_the_dongle() {
    let html = text(page::SETUP_AP_HTML);
    assert!(!html.contains("http://") && !html.contains("https://") && !html.contains("//cdn"));
    for forbidden in ["eval(", "document.write", "new Function", "XMLHttpRequest", "WebSocket", "<iframe", "<link", "src="] {
        assert!(!html.contains(forbidden), "{forbidden}");
    }
    assert!(!html.contains("name=priority") && !html.contains("name=name") && !script().contains("d.priority"));
    assert!(script().contains("savedNets.some(n=>n.ssid===d.ssid)"));
}

#[test]
fn every_request_and_action_the_page_makes_is_allowed_on_the_setup_network() {
    let s = script();
    let mut paths = std::collections::BTreeSet::new();
    for needle in ["api('", "send("] {
        let mut rest = s.as_str();
        while let Some(i) = rest.find(needle) {
            rest = &rest[i + needle.len()..];
            if needle == "send(" {
                paths.insert("/command".to_string());
            } else if rest.starts_with('/') {
                paths.insert(rest.split(['\'', '?']).next().unwrap().to_string());
            }
        }
    }
    assert!(paths.is_superset(&["/wifi-scan", "/wifi-saved", "/command"].iter().map(|s| s.to_string()).collect()), "{paths:?}");
    let p = portal();
    let t = tok_hdr(&p);
    for path in &paths {
        let mut h = FakeHost::new();
        let raw = if path == "/command" { post(path, H, &t, r#"{"action":"setup_done"}"#) } else { get(path, H, &t) };
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &raw);
        assert!(text(&r).starts_with("HTTP/1.1 200 OK"), "the page asks for {path}: {}", text(&r));
    }
    let mut actions = std::collections::BTreeSet::new();
    for key in ["action:'", "d.action='"] {
        let mut rest = s.as_str();
        while let Some(i) = rest.find(key) {
            rest = &rest[i + key.len()..];
            actions.insert(rest.split('\'').next().unwrap().to_string());
        }
    }
    assert!(actions.is_superset(&["wifi", "wifi_remove", "setup_done"].iter().map(|s| s.to_string()).collect()), "{actions:?}");
    for a in &actions {
        let mut h = FakeHost::new();
        let body = format!("{{\"action\":\"{a}\",\"ssid\":\"x\",\"password\":\"\"}}");
        let (r, _) = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &t, &body));
        assert!(!text(&r).contains("not available"), "the page sends {a}: {}", text(&r));
    }
    // and the element ids the script uses exist
    let html = text(page::SETUP_AP_HTML);
    let mut rest = s.as_str();
    while let Some(i) = rest.find("$('") {
        rest = &rest[i + 3..];
        let id = rest.split('\'').next().unwrap();
        assert!(html.contains(&format!("id={id}")) || html.contains(&format!("id=\"{id}\"")), "#{id}");
    }
}

// ------------------------------------------------------------------------------------------------ exclusion

#[test]
fn a_setup_boot_has_no_usb_network_by_construction() {
    // The type that carries the USB network capability is produced only by BridgeBoot (and the uninhabited TailnetBoot); a setup boot is a
    // different variant and SetupBoot has no method for it (see the compile_fail doctests in `boot`).
    let setup = SetupBoot::decide(false, 0, 0, 0, false, true);
    match Boot::decide(setup, false) {
        Boot::Setup(_) => {}
        other => panic!("{other:?}"),
    }
    // Without a setup decision the boot is the bridge, which owns the USB network.
    match Boot::decide(None, true) {
        Boot::Bridge(b) => {
            let _usb = b.usb_network();
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn recovery_outranks_a_setup_request_by_passing_none() {
    // `if(gateway_boot_recovery())setup_active=false;`: the caller discards the decision; the boot is then the bridge.
    let decided = SetupBoot::decide(true, tdongle_setup::boot::MAGIC, 1, 0, true, true);
    assert!(decided.is_some());
    assert!(matches!(Boot::decide(None, false), Boot::Bridge(_)));
}

#[test]
fn the_access_point_is_open_and_the_session_is_not_extendable() {
    // ADR 0024 / test_open_ap.py: the open access point is the owner's decision. This crate has no password or WPA setting at all; the
    // firmware sets WIFI_AUTH_OPEN. The ten minutes cannot be extended by a request: serving any request does not touch the session.
    let p = portal();
    let mut h = FakeHost::new();
    let before = *p.session();
    let _ = exchange(&p, &ap_conn(), &mut h, &get("/", H, ""));
    let _ = exchange(&p, &ap_conn(), &mut h, &post("/command", H, &tok_hdr(&p), r#"{"action":"wifi","ssid":"x","password":""}"#));
    assert_eq!(*p.session(), before);
    assert!(p.session().expired(1000 + 600_000));
}

#[test]
fn usb_page_includes_the_nul_of_the_text_embed() {
    let p = portal();
    let usb = Conn { peer: Some(USB_PEER), local: Some(USB_LOCAL) };
    let mut h = FakeHost::new();
    let (r, _) = exchange(&p, &usb, &mut h, &get("/", "192.168.77.1", ""));
    let body = body_of(&r);
    assert_eq!(body.len(), page::SETUP_HTML.len() + 1);
    assert_eq!(body.last(), Some(&0));
    assert!(text(&r).contains(&format!("Content-Length: {}\r\n", body.len())));
}
