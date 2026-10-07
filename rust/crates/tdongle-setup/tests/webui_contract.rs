//! The transport contract of the web controller (`rust/webui/contract.txt`): Web Serial and `POST /serial` must serve the same command
//! set with the same dispatcher. Fails when the two drift apart:
//!
//! - a `both` command the HTTP allowlist refuses, or hands to the dispatcher as a different line;
//! - a `serial` command the HTTP allowlist lets through;
//! - a line the HTTP side would dispatch that the serial console would discard or split (length, bytes);
//! - a `both` command the dispatcher does not know, or an `absent` one it has started to know (classify it in the contract);
//! - the page sending a console-only command;
//! - the firmware dispatcher branching on the transport outside its one output function.
use proptest::prelude::*;
use std::fs;
use std::path::PathBuf;
use tdongle_serial::command::Command;
use tdongle_serial::console::{Event, LINE_CHARS_MAX, LineReader};
use tdongle_setup::router::Conn;
use tdongle_setup::usb::{self, Answer, parse_head, route};

const USB: Conn = Conn { peer: Some(0xc0a8_4d02), local: Some(0xc0a8_4d01) }; // 192.168.77.2 -> 192.168.77.1

#[derive(Debug)]
struct Entry {
    kind: String,
    exemplar: String,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn contract() -> Vec<Entry> {
    let text = fs::read_to_string(root().join("rust/webui/contract.txt")).unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(" | ").map(str::trim).collect();
        assert_eq!(f.len(), 4, "contract line needs KIND | PATTERN | EXEMPLAR | NOTE: {line}");
        assert!(matches!(f[0], "both" | "serial" | "absent"), "kind of {line}");
        out.push(Entry { kind: f[0].to_string(), exemplar: f[2].to_string() });
    }
    assert!(out.len() > 20, "contract has {} entries", out.len());
    out
}

/// What the serial console makes of `line` typed with a newline: the line it hands to the dispatcher, if any.
fn console_line(line: &str) -> Option<String> {
    let mut r = LineReader::new();
    let mut got = None;
    for &b in line.as_bytes().iter().chain(b"\n") {
        if let Some(Event::Line(l)) = r.feed(b) {
            got = Some(l.to_string());
        }
    }
    got
}

/// What `POST /serial` with `line` as the body resolves to: `Ok(line handed to the dispatcher)` or `Err(status)`.
fn http_line(line: &str) -> Result<String, String> {
    let len = line.len().to_string();
    let raw = format!(
        "POST /serial HTTP/1.1\r\nHost: 192.168.77.1\r\nOrigin: http://192.168.77.1\r\nContent-Type: application/x-tdongle-command\r\nContent-Length: {len}\r\n\r\n{line}"
    );
    let (head, used) = parse_head(raw.as_bytes()).map_err(|e| format!("{e:?}"))?;
    match route(&USB, &head, &raw.as_bytes()[used..]) {
        Answer::Serial(l) => Ok(l.to_string()),
        Answer::Refuse(r) => Err(format!("{} {}", r.status, r.message)),
        other => Err(format!("{other:?}")),
    }
}

/// Lines the dispatcher handles before `Command::parse` (firmware `handle`, and the tailnet gateway's `tailnet::console`).
fn dispatcher_special(line: &str) -> bool {
    matches!(line, "heap" | "heap on" | "heap off" | "boot-status" | "init" | "normal" | "bootloader" | "tailnet-status" | "selftest flash" | "scan-detail")
        || ["selftest ", "member ", "usbwatch enforce "].iter().any(|p| line.starts_with(p))
}

fn dispatcher_knows(line: &str) -> bool {
    dispatcher_special(line) || !matches!(Command::parse(line), Command::Unknown)
}

#[test]
fn both_commands_reach_the_same_dispatcher_line_on_both_transports() {
    for e in contract().iter().filter(|e| e.kind == "both") {
        let l = &e.exemplar;
        assert!(usb::command_allowed(l), "HTTP refuses `{l}`, which the contract says both transports serve");
        assert_eq!(http_line(l).as_deref(), Ok(l.as_str()), "HTTP must hand `{l}` to the dispatcher unchanged");
        assert_eq!(console_line(l).as_deref(), Some(l.as_str()), "the serial console must hand `{l}` to the dispatcher unchanged");
        assert!(dispatcher_knows(l), "the dispatcher does not know `{l}`");
        // a CRLF or LF the client adds is stripped the way the console strips it
        assert_eq!(http_line(&format!("{l}\r\n")).as_deref(), Ok(l.as_str()), "`{l}` + CRLF over HTTP");
    }
}

#[test]
fn serial_only_commands_are_refused_over_http_and_served_on_the_console() {
    for e in contract().iter().filter(|e| e.kind == "serial") {
        let l = &e.exemplar;
        assert!(!usb::command_allowed(l), "HTTP lets `{l}` through; the contract says console only");
        assert_eq!(http_line(l), Err("403 Forbidden That command is not available here".into()), "{l}");
        assert_eq!(console_line(l).as_deref(), Some(l.as_str()), "the console must take `{l}`");
        assert!(dispatcher_knows(l), "the dispatcher does not know `{l}`");
    }
}

#[test]
fn absent_commands_are_unknown_everywhere() {
    for e in contract().iter().filter(|e| e.kind == "absent") {
        let l = &e.exemplar;
        assert!(matches!(Command::parse(l), Command::Unknown), "`{l}` is now a command: classify it as both or serial in rust/webui/contract.txt");
        assert!(!dispatcher_special(l), "`{l}`");
        assert!(!usb::command_allowed(l), "HTTP lets `{l}` through");
    }
}

#[test]
fn every_allowlisted_prefix_has_a_contract_entry() {
    // the allowlist's shapes, each must be covered by at least one `both` exemplar
    let both: Vec<String> = contract().into_iter().filter(|e| e.kind == "both").map(|e| e.exemplar).collect();
    for shape in [
        "status",
        "list",
        "scan",
        "tailnet-status",
        "help",
        "capabilities",
        "display",
        "reboot",
        "display-settings",
        "preference",
        "display ",
        "use ",
        "del ",
        "profile {",
        "mode ",
        "member ",
        "metadata {",
    ] {
        assert!(
            both.iter().any(|b| b == shape || (shape.ends_with([' ', '{']) && b.starts_with(shape))),
            "allowlisted `{shape}` has no `both` entry in the contract"
        );
    }
}

#[test]
fn the_page_sends_no_console_only_command() {
    let page = String::from_utf8(usb::PAGE.to_vec()).unwrap();
    for e in contract().iter().filter(|e| e.kind != "both") {
        let head = e.exemplar.split(' ').next().unwrap();
        for quoted in [format!("'{head}'"), format!("'{head} "), format!("\"{head}\""), format!("\"{head} ")] {
            assert!(!page.contains(&quoted), "the controller page contains {quoted}: `{}` is {} in the contract", e.exemplar, e.kind);
        }
    }
}

#[test]
fn the_dispatcher_does_not_branch_on_the_transport() {
    // rust/firmware/src/main.rs: `Sink` is matched only in `emit` (where the bytes go) and named only where each transport enters `handle`
    let src = fs::read_to_string(root().join("rust/firmware/src/main.rs")).unwrap();
    let count = |s: &str| src.matches(s).count();
    assert_eq!(count("Sink::Http"), 2, "Sink::Http: one arm in emit, one call in http_line");
    assert_eq!(count("Sink::Console("), 2, "Sink::Console: one arm in emit, one call in console_task");
    assert_eq!(count("handle(Sink::"), 2, "both transports enter the same `handle`");
    for banned in ["matches!(wr", "if let Sink", "match wr", "wr == Sink"] {
        assert!(!src.contains(banned), "the dispatcher branches on its transport: {banned}");
    }
}

#[test]
fn http_never_dispatches_a_line_the_console_would_discard() {
    // too long for the console's line buffer
    let long = format!("profile {{\"x\":\"{}\"}}", "a".repeat(LINE_CHARS_MAX));
    assert!(console_line(&long).is_none());
    assert!(!usb::command_allowed(&long));
    // non-ASCII: the console discards the line
    for l in ["use 2\u{e9}", "profile {\"ssid\":\"caf\u{e9}\"}", "status\u{a0}"] {
        assert!(console_line(l).is_none(), "{l:?}");
        assert!(!usb::command_allowed(l), "{l:?}");
    }
    let edge = format!("profile {{{}}}", "a".repeat(LINE_CHARS_MAX - 10));
    assert_eq!(edge.len(), LINE_CHARS_MAX);
    assert!(usb::command_allowed(&edge));
    assert_eq!(console_line(&edge).as_deref(), Some(edge.as_str()));
}

proptest! {
    #[test]
    fn allowed_over_http_implies_identical_on_the_console(s in "(status|list|use |del |display |mode |member |profile \\{)([ -~]{0,40}|[ -~\u{e9}\u{a0}\t]{0,40}|[ -~]{480,560})") {
        if usb::command_allowed(&s) {
            prop_assert_eq!(console_line(&s), Some(s.clone()));
            prop_assert_eq!(http_line(&s), Ok(s.clone()));
        }
    }
}
