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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// `GET /`: the page.
    Page,
    /// `GET /status`: the tailnet status JSON (what the app and the page have always read there).
    Status,
    /// `POST /serial`: run this line through the console dispatcher and send its reply as is.
    Serial(&'a str),
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
#[must_use]
pub fn command_allowed(line: &str) -> bool {
    if line.is_empty() || line.len() > BODY_MAX || line.chars().any(|c| c.is_control()) {
        return false;
    }
    matches!(line, "status" | "list" | "scan" | "tailnet-status" | "help" | "capabilities" | "display" | "reboot")
        || ["display ", "use ", "del ", "profile {", "mode ", "member "].iter().any(|p| line.starts_with(p))
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
        (b"/" | b"/status" | b"/serial", _) => refuse("405 Method Not Allowed", "Method not allowed"),
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

/// The content type of a serial reply and of `/status`.
pub const TEXT: &str = "text/plain; charset=utf-8";
/// The content type of `/status`.
pub const JSON: &str = "application/json";
