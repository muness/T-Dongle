//! The controller page and the one command endpoint of tailnet mode's USB side (`http://192.168.77.1/`).
//!
//! One web UI, two transports, one command layer: the page speaks the serial console protocol. Over Web Serial it types the lines into the
//! console; over HTTP it POSTs the same line to `/serial`, and the firmware hands that line to the **same dispatcher** the console runs and
//! returns the reply bytes unchanged. This module decides *whether* a request may reach the dispatcher; the firmware moves bytes.
//!
//! Access rules (ADR 0024, as [`crate::access`]): only a peer in 192.168.77.0/24 that connected to 192.168.77.1 with `Host: 192.168.77.1[:80]`
//! and no foreign `Origin` is the USB origin; everything else, in particular the setup access point's subnet, is refused (`setup_active` is
//! false here: this server does not exist in a setup boot). No CORS header is ever sent and `OPTIONS` is `405`, so no other origin can read
//! an answer or preflight a request. `POST /serial` additionally needs an `Origin` header (a browser always sends one on a POST), the
//! non-safelisted `Content-Type: application/x-tdongle-command` (a cross-site form cannot send it, a cross-site `fetch` needs a preflight
//! this server refuses) and a command from the [`command_allowed`] list.
//!
//! The C USB page's own endpoints are served too, because the Android app's tailnet setup view proxies exactly those (`GET /status`,
//! `GET /wifi-scan`, `POST /command`): [`command_plan`] decides a `/command` body with the C handler's checks and texts, in its order, and
//! turns every action that has a console form (`mode`, `add`, `enable`, `remove`) into that console line, so it runs through the same dispatcher
//! as `/serial` and the serial console; `wifi` and `wifi_remove` go to the settings worker the console's `profile` and `del` use.

use crate::access::{self, Facts, Origin};
use crate::router::Conn;
use core::fmt;

/// The controller page (the one bundle; `site/controller.html` is a byte-identical copy, a test keeps them equal).
pub const PAGE: &[u8] = include_bytes!("../../../webui/controller.html");
/// The only `Content-Type` `/serial` accepts.
pub const COMMAND_TYPE: &[u8] = b"application/x-tdongle-command";
/// The largest request head read (`CONFIG_HTTPD_MAX_REQ_HDR_LEN` of the C is 1024: a browser's head is close to that, so this is larger).
pub const HEAD_MAX: usize = 1536;
/// The largest command line (a `profile` line is at most 511 bytes).
pub const BODY_MAX: usize = 640;
/// The largest `/command` body (the C refuses `content_len > 1024`).
pub const COMMAND_BODY_MAX: usize = 1024;
/// The most networks `/wifi-scan` lists (C `WIFI_SCAN_RESULT_LIMIT`).
pub const SCAN_RESULT_LIMIT: usize = 12;

/// How many body bytes to read for a request with this head.
#[must_use]
pub fn body_limit(head: &Head<'_>) -> usize {
    if head.path == b"/command" { COMMAND_BODY_MAX } else { BODY_MAX }
}
/// The page's Content-Security-Policy.
pub const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'";

/// A request method this server distinguishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// Anything else (`OPTIONS`, `HEAD`, `PUT`, ...).
    Other,
}

/// Why a request head could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// More bytes are needed.
    Incomplete,
    /// The head does not fit [`HEAD_MAX`].
    TooLarge,
    /// Malformed, duplicated security header, chunked, or not HTTP/1.x.
    Bad,
}

/// The parts of a request head the access decision reads.
#[derive(Clone, Copy, Debug)]
pub struct Head<'a> {
    /// Request method.
    pub method: Method,
    /// Path up to `?` or `#`.
    pub path: &'a [u8],
    /// `Host`.
    pub host: Option<&'a [u8]>,
    /// `Origin` (empty counts as absent, as in the setup portal).
    pub origin: Option<&'a [u8]>,
    /// `Content-Type`.
    pub content_type: Option<&'a [u8]>,
    /// `Content-Length`.
    pub content_len: Option<usize>,
}

fn trim(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// Parse a request head from the start of `buf`. Returns it and the number of bytes it occupies (the body follows).
///
/// # Errors
/// [`HeadError`]. Duplicated `Host`, `Origin`, `Content-Type` or `Content-Length`, any `Transfer-Encoding` and bare-LF line ends are refused outright.
pub fn parse_head(buf: &[u8]) -> Result<(Head<'_>, usize), HeadError> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(if buf.len() >= HEAD_MAX { HeadError::TooLarge } else { HeadError::Incomplete });
    };
    if end + 4 > HEAD_MAX {
        return Err(HeadError::TooLarge);
    }
    let text = &buf[..end + 1]; // through the CR of the last header line: every line then ends in CR
    let mut lines = text.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r"));
    let first = lines.next().flatten().ok_or(HeadError::Bad)?;
    let mut parts = first.split(|&b| b == b' ');
    let (method, target, version) = (parts.next().ok_or(HeadError::Bad)?, parts.next().ok_or(HeadError::Bad)?, parts.next().ok_or(HeadError::Bad)?);
    if parts.next().is_some() || !matches!(version, b"HTTP/1.1" | b"HTTP/1.0") || target.first() != Some(&b'/') {
        return Err(HeadError::Bad);
    }
    let method = match method {
        b"GET" => Method::Get,
        b"POST" => Method::Post,
        m if !m.is_empty() && m.iter().all(u8::is_ascii_uppercase) => Method::Other,
        _ => return Err(HeadError::Bad),
    };
    let path = &target[..target.iter().position(|&b| b == b'?' || b == b'#').unwrap_or(target.len())];
    let mut head = Head { method, path, host: None, origin: None, content_type: None, content_len: None };
    let mut seen = [false; 4];
    for line in lines {
        let line = line.ok_or(HeadError::Bad)?;
        let colon = line.iter().position(|&b| b == b':').ok_or(HeadError::Bad)?;
        let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
        if name.is_empty() || name.iter().any(|b| b.is_ascii_whitespace() || *b < 33) {
            return Err(HeadError::Bad);
        }
        let mut once = |slot: usize| -> Result<(), HeadError> {
            if seen[slot] {
                return Err(HeadError::Bad);
            }
            seen[slot] = true;
            Ok(())
        };
        if name.eq_ignore_ascii_case(b"host") {
            once(0)?;
            head.host = Some(value);
        } else if name.eq_ignore_ascii_case(b"origin") {
            once(1)?;
            head.origin = (!value.is_empty()).then_some(value);
        } else if name.eq_ignore_ascii_case(b"content-type") {
            once(2)?;
            head.content_type = Some(value);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            once(3)?;
            if value.is_empty() || value.len() > 9 || !value.iter().all(u8::is_ascii_digit) {
                return Err(HeadError::Bad);
            }
            head.content_len = Some(value.iter().fold(0usize, |a, d| a * 10 + usize::from(d - b'0')));
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(HeadError::Bad);
        }
    }
    Ok((head, end + 4))
}

/// What a request resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// `GET /`: the page.
    Page,
    /// `GET /status`: the tailnet status JSON (what the app and the page have always read there).
    Status,
    /// `POST /serial`: run this line through the console dispatcher and send its reply as is.
    Serial(&'a str),
    /// `GET /wifi-scan`: run `scan` through the dispatcher, then answer [`write_wifi_scan`] from the scan table.
    WifiScan,
    /// `POST /command`: what [`command_plan`] decided.
    Command(Plan),
    /// Refused.
    Refuse(Refusal),
}

/// A refusal: status line, one line of text, and whether the connection must be closed (always, here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// `"403 Forbidden"` and the like.
    pub status: &'static str,
    /// The body.
    pub message: &'static str,
}

const fn refuse<'a>(status: &'static str, message: &'static str) -> Answer<'a> {
    Answer::Refuse(Refusal { status, message })
}

/// The commands `/serial` hands to the dispatcher: what the controller page uses, nothing that restarts into download mode, wipes or runs a test.
///
/// A line passes only if the serial console would also take it as one line, byte for byte (1 to
/// [`tdongle_serial::console::LINE_CHARS_MAX`] printable ASCII characters, what `LineReader` stores): the HTTP transport never reaches the
/// dispatcher with a line the console would have discarded. `rust/webui/contract.txt` lists every command form and which transports serve it.
#[must_use]
pub fn command_allowed(line: &str) -> bool {
    if line.is_empty() || line.len() > tdongle_serial::console::LINE_CHARS_MAX || !line.bytes().all(|b| (32..=126).contains(&b)) {
        return false;
    }
    matches!(line, "status" | "list" | "scan" | "tailnet-status" | "help" | "capabilities" | "display" | "reboot" | "display-settings" | "preference")
        || ["display ", "use ", "del ", "profile {", "mode ", "member ", "metadata {"].iter().any(|p| line.starts_with(p))
}

/// Decide what a request gets. `body` is what was read after the head.
#[must_use]
pub fn route<'a>(conn: &Conn, head: &Head<'_>, body: &'a [u8]) -> Answer<'a> {
    let facts = Facts { peer: conn.peer, local: conn.local, setup_active: false, host: head.host, origin: head.origin };
    if access::classify(&facts) != Origin::Usb {
        return refuse("403 Forbidden", "USB access required");
    }
    match (head.path, head.method) {
        (b"/", Method::Get) => Answer::Page,
        (b"/status", Method::Get) => Answer::Status,
        (b"/serial", Method::Post) => serial(head, body),
        (b"/wifi-scan", Method::Get) => Answer::WifiScan,
        (b"/command", Method::Post) => Answer::Command(command_plan(head, body)),
        (b"/" | b"/status" | b"/serial" | b"/wifi-scan" | b"/command", _) => refuse("405 Method Not Allowed", "Method not allowed"),
        _ => refuse("404 Not Found", "Not found"),
    }
}

fn serial<'a>(head: &Head<'_>, body: &'a [u8]) -> Answer<'a> {
    if head.origin.is_none() {
        return refuse("403 Forbidden", "Same-origin request required");
    }
    if head.content_type != Some(COMMAND_TYPE) {
        return refuse("415 Unsupported Media Type", "Content type not supported");
    }
    let Some(len) = head.content_len.filter(|n| (1..=BODY_MAX).contains(n)) else {
        return refuse("413 Payload Too Large", "Request is too large");
    };
    if body.len() < len {
        return refuse("400 Bad Request", "Incomplete request");
    }
    let Ok(text) = core::str::from_utf8(&body[..len]) else { return refuse("400 Bad Request", "Invalid command") };
    let line = text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text);
    if !command_allowed(line) {
        return refuse("403 Forbidden", "That command is not available here");
    }
    Answer::Serial(line)
}

/// What kind of body follows the head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The page.
    Page,
    /// JSON or serial text.
    Text,
    /// A refusal.
    Refusal,
}

/// Write a response head. `len` is `None` for a streamed body that ends when the connection closes. No CORS header, ever.
///
/// # Errors
/// Only the writer's.
pub fn write_head(out: &mut dyn fmt::Write, status: &str, content_type: &str, len: Option<usize>, kind: Kind) -> fmt::Result {
    write!(out, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n")?;
    if let Some(n) = len {
        write!(out, "Content-Length: {n}\r\n")?;
    }
    write!(out, "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n")?;
    match kind {
        Kind::Page => write!(out, "Content-Security-Policy: {CSP}\r\n")?,
        _ => write!(out, "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n")?,
    }
    write!(out, "Connection: close\r\n\r\n")
}

/// Up to `N` bytes held by value (a [`Plan`] outlives the request buffer it was decided from).
#[derive(Clone, PartialEq, Eq)]
pub struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Text<N> {
    fn new() -> Self {
        Self { bytes: [0; N], len: 0 }
    }
    /// `None` if `b` does not fit.
    #[must_use]
    pub fn from(b: &[u8]) -> Option<Self> {
        let mut t = Self::new();
        t.push(b).then_some(t)
    }
    fn push(&mut self, b: &[u8]) -> bool {
        if self.len + b.len() > N {
            return false;
        }
        self.bytes[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        true
    }
    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    /// The bytes as text (lines built here are ASCII).
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    // a Wi-Fi password or an auth key may be in here: never print the bytes
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Text({} bytes)", self.len)
    }
}

impl<const N: usize> Drop for Text<N> {
    fn drop(&mut self) {
        self.bytes.iter_mut().for_each(|b| *b = 0);
    }
}

/// The texts of the C `command()` handler (`alternative/tailnet/main/gateway_main.c`) that this module answers itself.
pub mod text {
    /// `Content-Type` is not exactly `application/json`.
    pub const JSON_REQUIRED: &str = "JSON required";
    /// No body, or more than 1024 bytes.
    pub const TOO_LARGE: &str = "Request is too large";
    /// Fewer bytes than `Content-Length`.
    pub const INCOMPLETE: &str = "Incomplete request";
    /// `cJSON_Parse` refused the body.
    pub const INVALID_JSON: &str = "Invalid JSON";
    /// No such action.
    pub const UNKNOWN_ACTION: &str = "Unknown action";
    /// Settings unusable, or a crash-loop recovery boot.
    pub const RECOVERY: &str = "Recovery mode: settings are preserved. Use Restart services in the app after saving diagnostics.";
    /// `mode` with a value that is not a mode name.
    pub const MODE_CHOOSE: &str = "Choose Wi-Fi bridge or tailnet gateway";
    /// `mode` that could not be stored.
    pub const MODE_NOT_SAVED: &str = "Mode could not be saved; current mode remains active";
    /// `setup_done` outside setup (always, here: this server does not run in a setup boot).
    pub const SETUP_NOT_RUNNING: &str = "Setup is not running";
    /// `wifi_remove` that found nothing to remove or could not store the list.
    pub const WIFI_REMOVE_FAILED: &str = "Could not remove that saved network";
    /// `wifi` whose save failed.
    pub const WIFI_NOT_SAVED: &str = crate::router::WIFI_NOT_SAVED;
    /// `add`: label missing, empty or over 20 bytes, or a key of 160 bytes or more.
    pub const ADD_INPUT: &str = "Use a short label and valid auth key";
    /// `add`: a label character that is not a letter, digit or hyphen.
    pub const LABEL_CHARS: &str = "Labels use letters, numbers and hyphens";
    /// `enable` / `remove` with an id no membership has.
    pub const NOT_FOUND: &str = "Membership not found";
    /// The member worker did not answer.
    pub const BUSY: &str = "Memberships are busy; retry shortly";
    /// `/wifi-scan` whose scan did not complete.
    pub const SCAN_FAILED: &str = "The dongle could not scan for Wi-Fi. Try again.";
}

/// Which console command a [`Plan::Line`] runs, for reading its reply ([`line_outcome`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// `mode NAME`
    Mode,
    /// `member ...` (its reply is already the C `/command` JSON)
    Member,
}

/// A `wifi` action, validated ([`crate::router::wifi_fields`] for the USB origin).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiPlan {
    /// SSID.
    pub ssid: Text<32>,
    /// Password.
    pub password: Text<63>,
    /// Name, `None` for the default.
    pub name: Option<Text<24>>,
    /// Priority, -1 for the default.
    pub priority: i32,
    /// 0-based slot, -1 for the network's own or the next free one.
    pub slot: i32,
}

/// What a `/command` body asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Refused before the C takes its lock (content type, size, JSON, action name): answer this, whatever the settings state.
    Refuse(&'static str),
    /// Refused by the action's own checks (the C answers [`text::RECOVERY`] first when the settings are unusable).
    Fail(&'static str),
    /// Run this console line through the dispatcher, then [`line_outcome`].
    Line(Text<200>, LineKind),
    /// `wifi`: `wifi_save_with(...)`.
    Wifi(WifiPlan),
    /// `wifi_remove`: delete the saved network with this SSID.
    WifiRemove(Text<32>),
}

/// The membership id of an `enable` / `remove`: C compares `m->id == id->valuedouble`, so only a number equal to a possible id names one.
fn member_id(v: crate::json::Val) -> Option<u32> {
    let crate::json::Val::Num(d) = v else { return None };
    (d >= 1.0 && d <= f64::from(u32::MAX) && d == f64::from(d as u32)).then_some(d as u32)
}

/// Decide a `POST /command` (USB origin) with the C `command()` handler's checks, in its order.
#[must_use]
pub fn command_plan(head: &Head<'_>, body: &[u8]) -> Plan {
    use crate::access::Action;
    if head.content_type != Some(b"application/json") {
        return Plan::Refuse(text::JSON_REQUIRED);
    }
    let Some(len) = head.content_len.filter(|n| (1..=COMMAND_BODY_MAX).contains(n)) else { return Plan::Refuse(text::TOO_LARGE) };
    if body.len() < len {
        return Plan::Refuse(text::INCOMPLETE);
    }
    let Some(f) = crate::json::parse(&body[..len]) else { return Plan::Refuse(text::INVALID_JSON) };
    let line = |parts: &[&[u8]], kind| {
        let mut t = Text::<200>::new();
        for p in parts {
            if !t.push(p) {
                return Plan::Fail(text::ADD_INPUT);
            }
        }
        Plan::Line(t, kind)
    };
    match access::parse_action(f.string(f.action)) {
        Action::Unknown => Plan::Refuse(text::UNKNOWN_ACTION),
        Action::SetupDone => Plan::Fail(text::SETUP_NOT_RUNNING),
        Action::Mode => match f.string(f.mode) {
            Some(m @ (b"wifi_bridge" | b"tailnet_gateway")) => line(&[b"mode ", m], LineKind::Mode),
            _ => Plan::Fail(text::MODE_CHOOSE),
        },
        Action::Wifi => match crate::router::wifi_fields(Origin::Usb, &f, |_, _| false) {
            Err(m) => Plan::Fail(m),
            Ok(w) => match (Text::from(w.ssid), Text::from(w.password), w.name.map(Text::from)) {
                (Some(ssid), Some(password), None) => Plan::Wifi(WifiPlan { ssid, password, name: None, priority: w.priority, slot: w.slot }),
                (Some(ssid), Some(password), Some(Some(n))) => Plan::Wifi(WifiPlan { ssid, password, name: Some(n), priority: w.priority, slot: w.slot }),
                _ => Plan::Fail(text::WIFI_NOT_SAVED),
            },
        },
        Action::WifiRemove => match f.string(f.ssid).and_then(Text::from) {
            Some(ssid) if !ssid.as_bytes().is_empty() => Plan::WifiRemove(ssid),
            _ => Plan::Fail(text::WIFI_REMOVE_FAILED),
        },
        Action::Add => {
            let label = f.string(f.label).unwrap_or(b"");
            let key = f.string(f.key).unwrap_or(b"");
            if label.is_empty() || label.len() > 20 || key.len() >= 160 {
                return Plan::Fail(text::ADD_INPUT);
            }
            if !label.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
                return Plan::Fail(text::LABEL_CHARS);
            }
            // the console line cannot carry a key with a space or a control byte (no auth key has one)
            if !key.iter().all(|b| (33..=126).contains(b)) {
                return Plan::Fail(text::ADD_INPUT);
            }
            if key.is_empty() { line(&[b"member add ", label], LineKind::Member) } else { line(&[b"member add ", label, b" ", key], LineKind::Member) }
        }
        Action::Remove | Action::Enable => {
            let Some(id) = member_id(f.id) else { return Plan::Fail(text::NOT_FOUND) };
            let mut digits = Text::<10>::new();
            let _ = fmt::Write::write_fmt(&mut TextWriter(&mut digits), format_args!("{id}"));
            let verb: &[u8] = match (access::parse_action(f.string(f.action)), f.enabled) {
                (Action::Remove, _) => b"member remove ",
                (_, crate::json::Val::True) => b"member enable ",
                _ => b"member disable ",
            };
            line(&[verb, digits.as_bytes()], LineKind::Member)
        }
    }
}

struct TextWriter<'t, const N: usize>(&'t mut Text<N>);

impl<const N: usize> fmt::Write for TextWriter<'_, N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.0.push(s.as_bytes()) { Ok(()) } else { Err(fmt::Error) }
    }
}

/// How a [`Plan::Line`]'s console reply reads as a `/command` answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome<'r> {
    /// `{"ok":true}`.
    Ok,
    /// `{"ok":false,"error":...}` with this text.
    Fail(&'static str),
    /// The reply already is the C body (a `member` command): send it, 200 if it is `{"ok":true}`, 400 otherwise.
    Body(&'r str),
}

/// Read a console reply as the C `/command` answer.
#[must_use]
pub fn line_outcome(kind: LineKind, reply: &str) -> Outcome<'_> {
    match kind {
        LineKind::Mode if reply.starts_with("OK mode saved") => Outcome::Ok,
        LineKind::Mode if reply == tdongle_serial::reply::MODE_INVALID => Outcome::Fail(text::MODE_CHOOSE),
        LineKind::Mode => Outcome::Fail(text::MODE_NOT_SAVED),
        LineKind::Member => match reply.trim_end() {
            b if b.starts_with("{\"ok\":") => Outcome::Body(b),
            _ => Outcome::Fail(text::BUSY),
        },
    }
}

/// A reply body: `{"ok":true}` (200) or `{"ok":false,"error":"..."}` (400), as `cJSON_PrintUnformatted` writes them. Returns the status line.
///
/// # Errors
/// Only the writer's.
pub fn write_command_body(out: &mut dyn fmt::Write, outcome: Outcome<'_>) -> Result<&'static str, fmt::Error> {
    match outcome {
        Outcome::Ok => out.write_str("{\"ok\":true}").map(|()| "200 OK"),
        Outcome::Fail(m) => {
            out.write_str("{\"ok\":false,\"error\":\"")?;
            for c in m.chars() {
                match c {
                    '"' => out.write_str("\\\"")?,
                    '\\' => out.write_str("\\\\")?,
                    c => out.write_char(c)?,
                }
            }
            out.write_str("\"}").map(|()| "400 Bad Request")
        }
        Outcome::Body(b) => out.write_str(b).map(|()| if b == "{\"ok\":true}" { "200 OK" } else { "400 Bad Request" }),
    }
}

/// The `/wifi-scan` body of the C USB page (`wifi_scan` in `gateway_main.c`): `{"networks":[{"ssid":..,"rssi":..,"secure":..},...],"ok":true,
/// "count":N,"truncated":B}` with at most [`SCAN_RESULT_LIMIT`] networks in the order given (strongest first) and `truncated` when the scan found
/// more. `rows` are (SSID, RSSI, not open); hidden networks are the caller's to leave out (the C scans with `show_hidden = false`).
pub fn write_wifi_scan<'s>(j: &mut crate::json::Json<'_>, rows: impl Iterator<Item = (&'s [u8], i32, bool)>) {
    j.raw(b"{\"networks\":[");
    let mut total = 0usize;
    for (ssid, rssi, secure) in rows {
        if total < SCAN_RESULT_LIMIT {
            if total > 0 {
                j.raw(b",");
            }
            j.raw(b"{\"ssid\":").string(ssid).raw(b",\"rssi\":").int(i64::from(rssi)).raw(b",\"secure\":").boolean(secure).raw(b"}");
        }
        total += 1;
    }
    let count = total.min(SCAN_RESULT_LIMIT);
    j.raw(b"],\"ok\":true,\"count\":").int(count as i64).raw(b",\"truncated\":").boolean(total > count).raw(b"}");
}

/// The content type of a serial reply and of `/status`.
pub const TEXT: &str = "text/plain; charset=utf-8";
/// The content type of `/status`.
pub const JSON: &str = "application/json";
