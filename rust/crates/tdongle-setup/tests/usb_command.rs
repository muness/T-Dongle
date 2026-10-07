//! `GET /wifi-scan` and `POST /command` on tailnet mode's USB side: the endpoints the Android app's tailnet setup view proxies
//! (`TailnetSetupView.allowedUsbRequest`: `GET /status`, `GET /wifi-scan`, `POST /command`), with the C handler's checks, texts and JSON shapes
//! (`wifi_scan` and `command` in `alternative/tailnet/main/gateway_main.c`).

use tdongle_setup::json::Json;
use tdongle_setup::router::Conn;
use tdongle_setup::usb::{self, Answer, LineKind, Outcome, Plan, Text, WifiPlan, command_plan, line_outcome, parse_head, route, text, write_command_body, write_wifi_scan};

const USB: Conn = Conn { peer: Some(0xc0a8_4d02), local: Some(0xc0a8_4d01) };
const AP: Conn = Conn { peer: Some(0xc0a8_0402), local: Some(0xc0a8_0401) };

/// What `TailnetSetupView.usbRequest` sends: `Origin: http://192.168.77.1`, `Content-Type: application/json`, a fixed length.
fn app_post(path: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: 192.168.77.1\r\nOrigin: http://192.168.77.1\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn app_get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: 192.168.77.1\r\nOrigin: http://192.168.77.1\r\nConnection: close\r\n\r\n").into_bytes()
}

fn routed(conn: &Conn, raw: &[u8]) -> Answer<'static> {
    let raw: &'static [u8] = Box::leak(raw.to_vec().into_boxed_slice());
    let (head, used) = parse_head(raw).unwrap();
    route(conn, &head, &raw[used..])
}

fn plan(body: &str) -> Plan {
    match routed(&USB, &app_post("/command", "application/json", body)) {
        Answer::Command(p) => p,
        other => panic!("{other:?}"),
    }
}

fn line(l: &str, kind: LineKind) -> Plan {
    Plan::Line(Text::from(l.as_bytes()).unwrap(), kind)
}

#[test]
fn routes_and_access() {
    assert_eq!(routed(&USB, &app_get("/wifi-scan")), Answer::WifiScan);
    assert_eq!(routed(&USB, &app_get("/wifi-scan?again=1")), Answer::WifiScan);
    assert!(matches!(routed(&USB, &app_post("/command", "application/json", "{\"action\":\"mode\",\"mode\":\"wifi_bridge\"}")), Answer::Command(_)));
    for raw in [app_get("/command"), app_post("/wifi-scan", "application/json", "{}")] {
        let Answer::Refuse(r) = routed(&USB, &raw) else { panic!() };
        assert_eq!(r.status, "405 Method Not Allowed");
    }
    // only the USB origin: never the setup access point, never a foreign page
    let Answer::Refuse(r) = routed(&AP, &app_get("/wifi-scan")) else { panic!() };
    assert_eq!(r.status, "403 Forbidden");
    let foreign = String::from_utf8(app_post("/command", "application/json", "{}")).unwrap().replace("http://192.168.77.1", "http://evil.example");
    let Answer::Refuse(r) = routed(&USB, foreign.as_bytes()) else { panic!() };
    assert_eq!(r.status, "403 Forbidden");
}

#[test]
fn checks_before_the_action_in_the_c_order() {
    let p = |ct: &str, body: &str| match routed(&USB, &app_post("/command", ct, body)) {
        Answer::Command(p) => p,
        other => panic!("{other:?}"),
    };
    assert_eq!(p("text/plain", "{}"), Plan::Refuse(text::JSON_REQUIRED));
    assert_eq!(p("application/json; charset=utf-8", "{}"), Plan::Refuse(text::JSON_REQUIRED));
    assert_eq!(p("application/json", ""), Plan::Refuse(text::TOO_LARGE));
    assert_eq!(p("application/json", &format!("{{\"action\":\"mode\",\"x\":\"{}\"}}", "a".repeat(1100))), Plan::Refuse(text::TOO_LARGE));
    let short = String::from_utf8(app_post("/command", "application/json", "{}")).unwrap().replace("Content-Length: 2", "Content-Length: 9");
    let (head, used) = parse_head(short.as_bytes()).unwrap();
    assert_eq!(command_plan(&head, &short.as_bytes()[used..]), Plan::Refuse(text::INCOMPLETE));
    assert_eq!(p("application/json", "{"), Plan::Refuse(text::INVALID_JSON));
    assert_eq!(p("application/json", "{\"action\":\"nope\"}"), Plan::Refuse(text::UNKNOWN_ACTION));
    assert_eq!(p("application/json", "{}"), Plan::Refuse(text::UNKNOWN_ACTION));
    // the body limit is the C's 1024, not /serial's
    let mut head_only = app_post("/command", "application/json", "{}");
    head_only.truncate(head_only.len() - 2);
    let (head, _) = parse_head(&head_only).unwrap();
    assert_eq!(usb::body_limit(&head), 1024);
}

#[test]
fn actions_become_console_lines_or_settings_requests() {
    assert_eq!(plan(r#"{"action":"mode","mode":"tailnet_gateway"}"#), line("mode tailnet_gateway", LineKind::Mode));
    assert_eq!(plan(r#"{"action":"mode","mode":"Tailnet"}"#), Plan::Fail(text::MODE_CHOOSE));
    assert_eq!(plan(r#"{"action":"mode"}"#), Plan::Fail(text::MODE_CHOOSE));
    assert_eq!(plan(r#"{"action":"add","label":"work","key":"tskey-auth-abc"}"#), line("member add work tskey-auth-abc", LineKind::Member));
    assert_eq!(plan(r#"{"action":"add","label":"home-2"}"#), line("member add home-2", LineKind::Member));
    assert_eq!(plan(r#"{"action":"add","label":""}"#), Plan::Fail(text::ADD_INPUT));
    assert_eq!(plan(r#"{"action":"add"}"#), Plan::Fail(text::ADD_INPUT));
    assert_eq!(plan(&format!(r#"{{"action":"add","label":"{}"}}"#, "a".repeat(21))), Plan::Fail(text::ADD_INPUT));
    assert_eq!(plan(&format!(r#"{{"action":"add","label":"a","key":"{}"}}"#, "k".repeat(160))), Plan::Fail(text::ADD_INPUT));
    assert_eq!(plan(r#"{"action":"add","label":"my work"}"#), Plan::Fail(text::LABEL_CHARS));
    assert_eq!(plan(r#"{"action":"add","label":"w_1"}"#), Plan::Fail(text::LABEL_CHARS));
    assert_eq!(plan(r#"{"action":"enable","id":3,"enabled":true}"#), line("member enable 3", LineKind::Member));
    assert_eq!(plan(r#"{"action":"enable","id":3,"enabled":false}"#), line("member disable 3", LineKind::Member));
    assert_eq!(plan(r#"{"action":"enable","id":3}"#), line("member disable 3", LineKind::Member));
    assert_eq!(plan(r#"{"action":"remove","id":4294967295}"#), line("member remove 4294967295", LineKind::Member));
    for id in ["\"3\"", "1.5", "0", "-1", "4294967296", "null"] {
        assert_eq!(plan(&format!(r#"{{"action":"remove","id":{id}}}"#)), Plan::Fail(text::NOT_FOUND), "{id}");
    }
    assert_eq!(plan(r#"{"action":"setup_done"}"#), Plan::Fail(text::SETUP_NOT_RUNNING));
    assert_eq!(plan(r#"{"action":"wifi_remove","ssid":"Cafe"}"#), Plan::WifiRemove(Text::from(b"Cafe").unwrap()));
    assert_eq!(plan(r#"{"action":"wifi_remove"}"#), Plan::Fail(text::WIFI_REMOVE_FAILED));
}

#[test]
fn the_wifi_action_with_usb_rights() {
    let w = |ssid: &str, pw: &str, name: Option<&str>, priority: i32, slot: i32| {
        Plan::Wifi(WifiPlan {
            ssid: Text::from(ssid.as_bytes()).unwrap(),
            password: Text::from(pw.as_bytes()).unwrap(),
            name: name.map(|n| Text::from(n.as_bytes()).unwrap()),
            priority,
            slot,
        })
    };
    assert_eq!(plan(r#"{"action":"wifi","ssid":"Cafe","password":"secret-pass"}"#), w("Cafe", "secret-pass", None, -1, -1));
    assert_eq!(plan(r#"{"action":"wifi","ssid":"Cafe","password":"","name":"Corner","priority":70,"slot":2}"#), w("Cafe", "", Some("Corner"), 70, 1));
    // the USB origin may use a short password (the 8-character rule is the setup network's) and may replace a saved network
    assert_eq!(plan(r#"{"action":"wifi","ssid":"Cafe","password":"abc"}"#), w("Cafe", "abc", None, -1, -1));
    for bad in [
        r#"{"action":"wifi","ssid":"","password":"x"}"#,
        r#"{"action":"wifi","ssid":"Cafe"}"#,
        r#"{"action":"wifi","password":"x"}"#,
        r#"{"action":"wifi","ssid":"123456789012345678901234567890123","password":""}"#,
    ] {
        assert_eq!(plan(bad), Plan::Fail("Enter a valid Wi-Fi name and password"), "{bad}");
    }
    for bad in [r#"{"action":"wifi","ssid":"C","password":"","slot":9}"#, r#"{"action":"wifi","ssid":"C","password":"","priority":101}"#] {
        assert_eq!(plan(bad), Plan::Fail("Use a name of up to 24 plain characters, a slot from 1 to 8 and a priority from 0 to 100"), "{bad}");
    }
}

#[test]
fn console_replies_read_as_the_c_answers() {
    assert_eq!(line_outcome(LineKind::Mode, tdongle_serial::reply::MODE_SAVED), Outcome::Ok);
    assert_eq!(line_outcome(LineKind::Mode, tdongle_serial::reply::MODE_INVALID), Outcome::Fail(text::MODE_CHOOSE));
    assert_eq!(line_outcome(LineKind::Mode, tdongle_serial::reply::MODE_NOT_SAVED), Outcome::Fail(text::MODE_NOT_SAVED));
    // the `member` console command already answers with the C body
    assert_eq!(line_outcome(LineKind::Member, "{\"ok\":true}\r\n"), Outcome::Body("{\"ok\":true}"));
    assert_eq!(
        line_outcome(LineKind::Member, "{\"ok\":false,\"error\":\"That label is already saved\"}\r\n"),
        Outcome::Body("{\"ok\":false,\"error\":\"That label is already saved\"}")
    );
    assert_eq!(line_outcome(LineKind::Member, "ERR tailnet worker busy\r\n"), Outcome::Fail(text::BUSY));
    let body = |o| {
        let mut s = String::new();
        let status = write_command_body(&mut s, o).unwrap();
        (status, s)
    };
    assert_eq!(body(Outcome::Ok), ("200 OK", "{\"ok\":true}".to_string()));
    assert_eq!(body(Outcome::Fail(text::RECOVERY)), ("400 Bad Request", format!("{{\"ok\":false,\"error\":\"{}\"}}", text::RECOVERY)));
    assert_eq!(body(Outcome::Body("{\"ok\":false,\"error\":\"x\"}")).0, "400 Bad Request");
    // every body is JSON the page's `r.json()` reads
    for o in [Outcome::Ok, Outcome::Fail(text::WIFI_NOT_SAVED), Outcome::Fail(text::JSON_REQUIRED)] {
        let v: serde_json::Value = serde_json::from_str(&body(o).1).unwrap();
        assert!(v["ok"].is_boolean());
    }
}

#[test]
fn wifi_scan_body_has_the_c_shape() {
    let mut buf = [0u8; 4096];
    let mut j = Json::new(&mut buf);
    let rows: Vec<(Vec<u8>, i32, bool)> = (0..14).map(|i| (format!("Net{i}").into_bytes(), -40 - i, i % 2 == 0)).collect();
    write_wifi_scan(&mut j, rows.iter().map(|(s, r, sec)| (s.as_slice(), *r, *sec)));
    assert!(!j.overflowed());
    let text = std::str::from_utf8(j.bytes()).unwrap().to_string();
    assert!(text.starts_with("{\"networks\":[{\"ssid\":\"Net0\",\"rssi\":-40,\"secure\":true},{\"ssid\":\"Net1\",\"rssi\":-41,\"secure\":false},"), "{text}");
    assert!(text.ends_with("],\"ok\":true,\"count\":12,\"truncated\":true}"), "{text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["networks"].as_array().unwrap().len(), 12);
    let mut buf = [0u8; 256];
    let mut j = Json::new(&mut buf);
    write_wifi_scan(&mut j, [(&b"Q\"uote"[..], -70, true)].into_iter());
    assert_eq!(std::str::from_utf8(j.bytes()).unwrap(), "{\"networks\":[{\"ssid\":\"Q\\\"uote\",\"rssi\":-70,\"secure\":true}],\"ok\":true,\"count\":1,\"truncated\":false}");
    let mut buf = [0u8; 256];
    let mut j = Json::new(&mut buf);
    write_wifi_scan(&mut j, core::iter::empty());
    assert_eq!(std::str::from_utf8(j.bytes()).unwrap(), "{\"networks\":[],\"ok\":true,\"count\":0,\"truncated\":false}");
}
