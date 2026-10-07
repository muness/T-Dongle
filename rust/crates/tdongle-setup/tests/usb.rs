//! The USB-side controller server (tailnet mode): the access matrix, the request head, the command allowlist, the response head and
//! the serial reply goldens through the HTTP endpoint, and the one-bundle rule (the page the firmware embeds equals the page published in `site/`).
use std::fs;
use std::path::PathBuf;
use tdongle_setup::router::Conn;
use tdongle_setup::usb::{self, Answer, HeadError, Kind, Method, parse_head, route};

const USB: Conn = Conn { peer: Some(0xc0a8_4d02), local: Some(0xc0a8_4d01) }; // 192.168.77.2 -> 192.168.77.1
const AP: Conn = Conn { peer: Some(0xc0a8_0402), local: Some(0xc0a8_0401) }; // 192.168.4.2 -> 192.168.4.1
const WIFI_PEER: Conn = Conn { peer: Some(0x0a00_0005), local: Some(0xc0a8_4d01) };
const WRONG_LOCAL: Conn = Conn { peer: Some(0xc0a8_4d02), local: Some(0xc0a8_4d02) };

fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut s = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        s += &format!("{k}: {v}\r\n");
    }
    s += &format!("\r\n{body}");
    s.into_bytes()
}

fn post(headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let len = body.len().to_string();
    let mut h =
        vec![("Host", "192.168.77.1"), ("Origin", "http://192.168.77.1"), ("Content-Type", "application/x-tdongle-command"), ("Content-Length", len.as_str())];
    for (k, v) in headers {
        h.retain(|(hk, _)| !hk.eq_ignore_ascii_case(k));
        if !v.is_empty() {
            h.push((k, v));
        }
    }
    let h: Vec<(String, String)> = h.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    req("POST", "/serial", &h, body)
}

fn answer(conn: &Conn, raw: &[u8]) -> String {
    let (head, used) = match parse_head(raw) {
        Ok(x) => x,
        Err(e) => return format!("head:{e:?}"),
    };
    match route(conn, &head, &raw[used..]) {
        Answer::Page => "page".into(),
        Answer::Status => "status".into(),
        Answer::Serial(l) => format!("serial:{l}"),
        Answer::Refuse(r) => r.status[..3].to_string(),
        Answer::WifiScan => "wifi-scan".into(),
        Answer::Command(_) => "command".into(),
    }
}

#[test]
fn access_matrix() {
    let get = |host: &str, origin: Option<&str>, path: &str| {
        let mut h = vec![("Host", host)];
        if let Some(o) = origin {
            h.push(("Origin", o));
        }
        req("GET", path, &h, "")
    };
    for path in ["/", "/status"] {
        let want = if path == "/" { "page" } else { "status" };
        assert_eq!(answer(&USB, &get("192.168.77.1", None, path)), want);
        assert_eq!(answer(&USB, &get("192.168.77.1:80", Some("http://192.168.77.1"), path)), want);
        // Host and Origin checks (DNS rebinding, cross-site)
        assert_eq!(answer(&USB, &get("evil.example", None, path)), "403");
        assert_eq!(answer(&USB, &get("192.168.77.1.evil.example", None, path)), "403");
        assert_eq!(answer(&USB, &get("192.168.77.1", Some("http://evil.example"), path)), "403");
        assert_eq!(answer(&USB, &get("192.168.77.1", Some("null"), path)), "403");
        // local address check: the request must have reached the USB netif's address
        assert_eq!(answer(&WRONG_LOCAL, &get("192.168.77.1", None, path)), "403");
        // nothing from the setup access point, the radio side, or an unknown peer
        assert_eq!(answer(&AP, &get("192.168.4.1", None, path)), "403");
        assert_eq!(answer(&AP, &get("192.168.77.1", None, path)), "403");
        assert_eq!(answer(&WIFI_PEER, &get("192.168.77.1", None, path)), "403");
        assert_eq!(answer(&Conn { peer: None, local: None }, &get("192.168.77.1", None, path)), "403");
    }
    // the refusal comes before the path is looked at: no oracle for other paths
    assert_eq!(answer(&AP, &get("192.168.4.1", None, "/serial")), "403");
    assert_eq!(answer(&USB, &get("192.168.77.1", None, "/nope")), "404");
    assert_eq!(answer(&USB, &get("192.168.77.1", None, "/serial")), "405");
    assert_eq!(answer(&USB, &req("OPTIONS", "/serial", &[("Host", "192.168.77.1"), ("Origin", "http://192.168.77.1")], "")), "405");
    assert_eq!(answer(&USB, &req("POST", "/", &[("Host", "192.168.77.1")], "")), "405");
}

#[test]
fn serial_endpoint_rules() {
    assert_eq!(answer(&USB, &post(&[], "status")), "serial:status");
    assert_eq!(answer(&USB, &post(&[], "status\n")), "serial:status");
    assert_eq!(answer(&USB, &post(&[], "use 2")), "serial:use 2");
    // mutating commands: every one needs the USB origin
    for c in ["del 1", "mode tailnet_gateway", "reboot", "member add work", "profile {\"slot\":1}", "display 50 0 60"] {
        assert_eq!(answer(&USB, &post(&[], c)), format!("serial:{c}"));
        assert_eq!(answer(&AP, &post(&[("Host", "192.168.4.1"), ("Origin", "http://192.168.4.1")], c)), "403", "{c} from the setup AP");
        assert_eq!(answer(&WIFI_PEER, &post(&[], c)), "403");
        assert_eq!(answer(&USB, &post(&[("Origin", "http://evil.example")], c)), "403");
        assert_eq!(answer(&USB, &post(&[("Host", "evil.example")], c)), "403");
        // CSRF: Origin is required, and the content type is the one a cross-site form or simple fetch cannot send
        assert_eq!(answer(&USB, &post(&[("Origin", "")], c)), "403");
        assert_eq!(answer(&USB, &post(&[("Content-Type", "text/plain")], c)), "415");
        assert_eq!(answer(&USB, &post(&[("Content-Type", "application/x-www-form-urlencoded")], c)), "415");
        assert_eq!(answer(&USB, &post(&[("Content-Type", "application/json")], c)), "415");
    }
    // size and framing
    assert_eq!(answer(&USB, &post(&[("Content-Length", "0")], "")), "413");
    assert_eq!(answer(&USB, &post(&[("Content-Length", "99999")], "status")), "413");
    assert_eq!(answer(&USB, &post(&[("Content-Length", "50")], "status")), "400");
    assert_eq!(answer(&USB, &post(&[("Content-Length", "abc")], "status")), "head:Bad");
    let long = format!("profile {{{}", "a".repeat(usb::BODY_MAX));
    assert_eq!(answer(&USB, &post(&[], &long)), "413");
}

#[test]
fn allowlist() {
    for ok in [
        "status",
        "list",
        "scan",
        "tailnet-status",
        "help",
        "display",
        "display 60 1 120",
        "use 3",
        "del 8",
        "mode wifi_bridge",
        "member remove 2",
        "reboot",
        "profile {\"slot\":2}",
        "display-settings",
        "preference",
        "metadata {\"slot\":1}",
    ] {
        assert!(usb::command_allowed(ok), "{ok}");
    }
    for no in [
        "",
        "bootloader",
        "selftest panic",
        "setup",
        "setup 2",
        "confirm-reset",
        "reset",
        "normal",
        "cancel",
        "usb sink",
        "heap on",
        "status\r\nbootloader",
        "status\0",
        "list ",
        "tn force-derp on",
        "memory",
        "Status",
        " status",
        "reboot now",
        "retry-startup",
        "boot-status",
        "metadata",
        "preference ",
    ] {
        assert!(!usb::command_allowed(no), "{no:?}");
    }
    assert_eq!(answer(&USB, &post(&[], "bootloader")), "403");
    assert_eq!(answer(&USB, &post(&[], "selftest panic")), "403");
    assert_eq!(answer(&USB, &post(&[], "status\r\nbootloader")), "403");
}

#[test]
fn head_parser() {
    assert_eq!(parse_head(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap_err(), HeadError::Incomplete);
    let (h, n) = parse_head(b"GET /status?x=1 HTTP/1.1\r\nhost:  192.168.77.1 \r\nORIGIN: http://192.168.77.1\r\n\r\nBODY").unwrap();
    assert_eq!((h.method, h.path, h.host, h.origin), (Method::Get, &b"/status"[..], Some(&b"192.168.77.1"[..]), Some(&b"http://192.168.77.1"[..])));
    assert_eq!(n, 83 - 4);
    // duplicates of the headers the decision reads, chunked bodies, bare LF, odd versions and a huge head are refused
    for bad in [
        &b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nOrigin: a\r\nOrigin: b\r\n\r\n",
        b"POST /serial HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"POST /serial HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/2\r\n\r\n",
        b"GET / HTTP/1.1\nHost: a\n\n\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\nOrigin: b\r\n\r\n",
        b"GET http://x/ HTTP/1.1\r\n\r\n",
        b"get / HTTP/1.1\r\n\r\n",
        b"GET /\r\n\r\n",
        b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
    ] {
        assert_eq!(parse_head(bad).unwrap_err(), HeadError::Bad, "{:?}", String::from_utf8_lossy(bad));
    }
    let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(usb::HEAD_MAX));
    assert_eq!(parse_head(big.as_bytes()).unwrap_err(), HeadError::TooLarge);
    assert_eq!(parse_head(&vec![b'a'; usb::HEAD_MAX]).unwrap_err(), HeadError::TooLarge);
    // a browser head (Chrome, same-origin POST) fits
    let chrome = "POST /serial HTTP/1.1\r\nHost: 192.168.77.1\r\nConnection: keep-alive\r\nContent-Length: 6\r\nsec-ch-ua: \"Chromium\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\nsec-ch-ua-platform: \"macOS\"\r\nsec-ch-ua-mobile: ?0\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nContent-Type: application/x-tdongle-command\r\nAccept: */*\r\nOrigin: http://192.168.77.1\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nReferer: http://192.168.77.1/\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\n\r\nstatus";
    assert!(chrome.len() < usb::HEAD_MAX);
    assert_eq!(answer(&USB, chrome.as_bytes()), "serial:status");
}

#[test]
fn response_heads_never_carry_cors() {
    let mut h = String::new();
    usb::write_head(&mut h, "200 OK", usb::TEXT, None, Kind::Text).unwrap();
    assert_eq!(
        h,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n"
    );
    let mut p = String::new();
    usb::write_head(&mut p, "200 OK", "text/html; charset=utf-8", Some(usb::PAGE.len()), Kind::Page).unwrap();
    assert!(p.contains(&format!("Content-Length: {}\r\n", usb::PAGE.len())) && p.contains(usb::CSP));
    for head in [&h, &p] {
        assert!(!head.to_ascii_lowercase().contains("access-control"), "no CORS header");
    }
}

fn golden_replies(file: &str) -> Vec<(String, Vec<u8>)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tdongle-serial/tests/golden").join(file);
    let text = fs::read(path).unwrap();
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
    let mut out = Vec::new();
    let mut rest = text.as_slice();
    while let Some(i) = find(rest, b"@@@@ SCENARIO ") {
        rest = &rest[i + 14..];
        let j = find(rest, b" @@@@\n").unwrap();
        let header = String::from_utf8_lossy(&rest[..j]).into_owned();
        let (name, len) = header.rsplit_once(" LEN ").unwrap();
        let len: usize = len.parse().unwrap();
        let body_start = &rest[j + 6..];
        assert!(body_start[len..].starts_with(b"\n@@@@ END @@@@"), "golden framing of {name}");
        out.push((name.to_string(), body_start[..len].to_vec()));
        rest = &body_start[len..];
    }
    out
}

/// What the firmware writes for `POST /serial`: the head, then the dispatcher's reply, untouched. The goldens are the serial console's replies
/// (`tdongle-serial/tests/golden`, the text the Android app parses); the HTTP endpoint must put exactly those bytes in its body.
fn http_body(reply: &[u8]) -> Vec<u8> {
    let mut wire = String::new();
    usb::write_head(&mut wire, "200 OK", usb::TEXT, None, Kind::Text).unwrap();
    let mut bytes = wire.into_bytes();
    bytes.extend_from_slice(reply);
    let at = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    bytes.split_off(at)
}

#[test]
fn serial_goldens_pass_through_http_unchanged() {
    let mut n = 0;
    for file in ["status.golden", "replies.golden", "fixed_replies.golden", "wifi_link.golden"] {
        for (name, reply) in golden_replies(file) {
            assert_eq!(http_body(&reply), reply, "{file}/{name}");
            n += 1;
        }
    }
    assert!(n > 30, "{n} golden replies");
}

#[test]
fn one_bundle_two_homes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let site = fs::read(root.join("site/controller.html")).unwrap();
    let source = fs::read(root.join("rust/webui/controller.html")).unwrap();
    assert_eq!(site, source, "site/controller.html must be a byte-identical copy of rust/webui/controller.html (rust/webui/sync.sh)");
    assert_eq!(usb::PAGE, source.as_slice(), "the firmware embeds the same bytes");
    let text = String::from_utf8(source).unwrap();
    assert!(!text.contains("http://") || !text.contains("src=\"http"), "no external resources");
    for banned in ["https://cdn", "//unpkg", "googleapis", "<link ", "src=\"http"] {
        assert!(!text.contains(banned), "{banned}");
    }
}
