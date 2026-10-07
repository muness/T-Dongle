//! The member API against the behaviour of `command()` and the tests/test_settings.c cases.

use tdongle_tailnet_members::command::{ActionKind, text};
use tdongle_tailnet_members::*;

#[derive(Default)]
struct Io {
    recovery: bool,
    persist_ok: bool,
    persisted: Vec<Vec<u8>>,
    clients: Vec<u32>,
    stop_ok: bool,
    stopped: Vec<u32>,
    forgotten: Vec<u32>,
    erase_ok: bool,
    erased: Vec<Vec<u8>>,
    dns: u32,
}
impl Io {
    fn new() -> Io {
        Io { persist_ok: true, stop_ok: true, erase_ok: true, ..Io::default() }
    }
}
impl MemberIo for Io {
    fn recovery(&self) -> bool {
        self.recovery
    }
    fn persist(&mut self, json: &[u8]) -> bool {
        self.persisted.push(json.to_vec());
        self.persist_ok
    }
    fn has_client(&self, id: u32) -> bool {
        self.clients.contains(&id)
    }
    fn stop(&mut self, id: u32) -> bool {
        self.stopped.push(id);
        self.stop_ok
    }
    fn forget(&mut self, id: u32) {
        self.forgotten.push(id);
    }
    fn erase_identity(&mut self, ns: &[u8]) -> bool {
        self.erased.push(ns.to_vec());
        self.erase_ok
    }
    fn refresh_dns(&mut self) {
        self.dns += 1;
    }
}

fn run(reg: &mut MemberRegistry, io: &mut Io, a: MemberAction) -> Reply {
    let mut scratch = vec![0u8; ENCODE_BUFFER];
    apply(reg, &a, io, &mut scratch)
}
fn body(r: &Reply) -> String {
    let mut s = String::new();
    r.write_body(&mut s).unwrap();
    s
}
fn req(origin: Origin, json: &str) -> Result<Parsed, Reply> {
    parse_request(origin, Some(b"application/json"), json.len(), json.as_bytes())
}
fn err(r: Result<Parsed, Reply>) -> &'static str {
    r.unwrap_err().error.unwrap()
}

#[test]
fn reply_bodies_and_statuses() {
    assert_eq!(body(&Reply::OK), r#"{"ok":true}"#);
    assert_eq!(Reply::OK.status().code(), 200);
    let r = Reply::failure("Membership not found");
    assert_eq!(body(&r), r#"{"ok":false,"error":"Membership not found"}"#);
    assert_eq!(r.status().code(), 400);
    assert_eq!(r.status().line(), "400 Bad Request");
    assert_eq!(body(&Reply::busy()), r#"{"ok":false,"error":"Memberships are busy; retry shortly"}"#);
}

#[test]
fn envelope_errors_in_the_c_order() {
    let ok = r#"{"action":"add","label":"a","key":""}"#;
    assert_eq!(parse_request(Origin::Usb, None, ok.len(), ok.as_bytes()).unwrap_err().error, Some(text::JSON_REQUIRED));
    assert_eq!(parse_request(Origin::Usb, Some(b"application/json; charset=utf-8"), ok.len(), ok.as_bytes()).unwrap_err().error, Some(text::JSON_REQUIRED));
    assert_eq!(parse_request(Origin::Usb, Some(b"text/plain"), 0, b"").unwrap_err().error, Some(text::JSON_REQUIRED));
    assert_eq!(parse_request(Origin::Usb, Some(b"application/json"), 0, b"").unwrap_err().error, Some(text::TOO_LARGE));
    assert_eq!(parse_request(Origin::Usb, Some(b"application/json"), 1025, &[b' '; 1025]).unwrap_err().error, Some(text::TOO_LARGE));
    assert_eq!(parse_request(Origin::Usb, Some(b"application/json"), 10, b"{}").unwrap_err().error, Some(text::INCOMPLETE));
    assert_eq!(err(req(Origin::Usb, "not json")), text::INVALID_JSON);
    assert_eq!(err(req(Origin::Usb, "{")), text::INVALID_JSON);
    assert_eq!(err(req(Origin::Usb, "{}")), text::UNKNOWN_ACTION);
    assert_eq!(err(req(Origin::Usb, "[]")), text::UNKNOWN_ACTION);
    assert_eq!(err(req(Origin::Usb, r#"{"action":5}"#)), text::UNKNOWN_ACTION);
    assert_eq!(err(req(Origin::Usb, r#"{"action":"explode"}"#)), text::UNKNOWN_ACTION);
    assert_eq!(err(req(Origin::Usb, r#"{"action":"ADD"}"#)), text::UNKNOWN_ACTION); // the action NAME is case sensitive; member names are not
    assert!(req(Origin::Usb, r#"{"ACTION":"add"}"#).is_ok());
    for a in ["add", "remove", "enable", "mode", "nonsense"] {
        assert_eq!(err(req(Origin::SetupAp, &format!(r#"{{"action":"{a}"}}"#))), text::NOT_FROM_SETUP);
    }
    assert_eq!(err(req(Origin::SetupAp, "{}")), text::NOT_FROM_SETUP);
    assert_eq!(req(Origin::SetupAp, r#"{"action":"wifi"}"#), Ok(Parsed::Other(ActionKind::Wifi)));
    assert_eq!(req(Origin::SetupAp, r#"{"action":"setup_done"}"#), Ok(Parsed::Other(ActionKind::SetupDone)));
    assert_eq!(req(Origin::Usb, r#"{"action":"mode","mode":"x"}"#), Ok(Parsed::Other(ActionKind::Mode)));
    assert!(req(Origin::Usb, r#"{"action":"remove","id":1} garbage"#).is_ok(), "cJSON_Parse ignores what follows the value");
}

#[test]
fn request_fields_become_typed_actions() {
    assert_eq!(req(Origin::Usb, r#"{"action":"add","label":"work","key":"tskey"}"#), Ok(Parsed::Member(MemberAction::add(b"work", b"tskey"))));
    assert_eq!(req(Origin::Usb, r#"{"action":"add","label":"work"}"#), Ok(Parsed::Member(MemberAction::add(b"work", b""))));
    assert_eq!(req(Origin::Usb, r#"{"action":"add","label":"work","key":7}"#), Ok(Parsed::Member(MemberAction::add(b"work", b""))));
    let Ok(Parsed::Member(MemberAction::Add { label, .. })) = req(Origin::Usb, r#"{"action":"add","label":5}"#) else { panic!() };
    assert!(label.is_none());
    assert_eq!(req(Origin::Usb, r#"{"action":"remove","id":3}"#), Ok(Parsed::Member(MemberAction::Remove(3))));
    assert_eq!(req(Origin::Usb, r#"{"action":"enable","id":3,"enabled":true}"#), Ok(Parsed::Member(MemberAction::Enable(3))));
    for e in [r#""enabled":false"#, r#""enabled":1"#, r#""enabled":"true""#, r#""enabled":null"#, r#""x":0"#] {
        assert_eq!(req(Origin::Usb, &format!(r#"{{"action":"enable","id":3,{e}}}"#)), Ok(Parsed::Member(MemberAction::Disable(3))), "{e}");
    }
    for bad in [r#""id":"3""#, r#""id":3.5"#, r#""id":-1"#, r#""id":0"#, r#""id":4294967296"#, r#""x":1"#, r#""id":null"#] {
        assert_eq!(req(Origin::Usb, &format!(r#"{{"action":"remove",{bad}}}"#)), Ok(Parsed::Member(MemberAction::Remove(0))), "{bad}");
    }
    assert_eq!(req(Origin::Usb, r#"{"action":"remove","id":3.0}"#), Ok(Parsed::Member(MemberAction::Remove(3))));
}

#[test]
fn add_validation_and_its_precedence() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    let add = |reg: &mut MemberRegistry, io: &mut Io, l: &[u8], k: &[u8]| body(&run(reg, io, MemberAction::add(l, k)));
    let e = |m: &str| format!(r#"{{"ok":false,"error":"{m}"}}"#);
    assert_eq!(add(&mut reg, &mut io, b"", b""), e(text::ADD_INPUT));
    assert_eq!(add(&mut reg, &mut io, &[b'a'; 21], b""), e(text::ADD_INPUT));
    assert_eq!(add(&mut reg, &mut io, b"ok", &[b'k'; 160]), e(text::ADD_INPUT));
    assert_eq!(add(&mut reg, &mut io, b"bad label", b""), e(text::LABEL_CHARS));
    assert_eq!(add(&mut reg, &mut io, b"under_score", b""), e(text::LABEL_CHARS));
    assert_eq!(add(&mut reg, &mut io, "é".as_bytes(), b""), e(text::LABEL_CHARS));
    assert!(io.persisted.is_empty(), "nothing is saved for a refused add");
    assert_eq!(add(&mut reg, &mut io, &[b'a'; 20], &[b'k'; 159]), r#"{"ok":true}"#);
    assert_eq!(add(&mut reg, &mut io, b"Work-1", b""), r#"{"ok":true}"#);
    assert_eq!(add(&mut reg, &mut io, b"work-1", b""), e(text::LABEL_TAKEN));
    assert_eq!(add(&mut reg, &mut io, b"WORK-1", b""), e(text::LABEL_TAKEN));
    assert_eq!(add(&mut reg, &mut io, b"Work 1", b""), e(text::LABEL_CHARS));
    assert_eq!(reg.len(), 2);
    assert_eq!(io.dns, 11, "gateway_dns_domains_refresh runs on every path that reaches the action");
}

#[test]
fn a_duplicate_beats_a_bad_character() {
    // The C records the LAST of its checks that fails. Only reachable with a loaded (unvalidated) label.
    let mut reg = MemberRegistry::new();
    reg.set_next_id(5);
    reg.append(Member::restored(1, b"we ird", b"", true));
    let mut io = Io::new();
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"WE IRD", b"")), Reply::failure(text::LABEL_TAKEN));
}

#[test]
fn add_inserts_at_the_head_and_numbers_from_next_id() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    for l in ["a", "b", "c"] {
        assert_eq!(run(&mut reg, &mut io, MemberAction::add(l.as_bytes(), b"")), Reply::OK);
    }
    let order: Vec<_> = reg.iter().map(|m| (m.id, String::from_utf8_lossy(m.label()).into_owned(), m.enabled)).collect();
    assert_eq!(order, [(3, "c".into(), true), (2, "b".into(), true), (1, "a".into(), true)]);
    assert_eq!(reg.next_id(), 4);
    assert_eq!(
        String::from_utf8(io.persisted.last().unwrap().clone()).unwrap(),
        r#"{"members":[{"id":3,"label":"c","key":"","enabled":true},{"id":2,"label":"b","key":"","enabled":true},{"id":1,"label":"a","key":"","enabled":true}],"next_id":4}"#
    );
    let m = reg.get(2).unwrap();
    assert_eq!(m.namespace().as_str(), Some("tn_00000002"));
    assert_eq!(m.hostname().as_str(), Some("tdongle-b-2"));
}

#[test]
fn add_that_cannot_be_saved_leaves_nothing_behind() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    io.persist_ok = false;
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"a", b"secret")), Reply::failure(text::ADD_NOT_SAVED));
    assert!(reg.is_empty());
    assert_eq!(reg.next_id(), 1, "the id counter goes back");
    io.persist_ok = true;
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"a", b"")), Reply::OK);
    assert_eq!(reg.get(1).unwrap().label(), b"a");
}

#[test]
fn registry_full_is_cannot_allocate() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    for i in 0..MAX_MEMBERS {
        assert_eq!(run(&mut reg, &mut io, MemberAction::add(format!("m{i}").as_bytes(), b"")), Reply::OK);
    }
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"one-more", b"")), Reply::failure(text::NO_ROOM));
    assert_eq!(reg.next_id(), MAX_MEMBERS as u32 + 1);
}

#[test]
fn id_counter_exhaustion() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    reg.set_next_id(u32::MAX);
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"a", b"")), Reply::failure(text::NO_ROOM));
    reg.set_next_id(0);
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"a", b"")), Reply::failure(text::NO_ROOM));
    reg.set_next_id(u32::MAX - 1);
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"a", b"")), Reply::OK);
    assert_eq!(reg.next_id(), u32::MAX);
}

#[test]
fn recovery_mode_refuses_everything() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    io.recovery = true;
    assert_eq!(run(&mut reg, &mut io, MemberAction::add(b"a", b"")), Reply::failure(text::RECOVERY));
    assert_eq!(run(&mut reg, &mut io, MemberAction::Remove(1)), Reply::failure(text::RECOVERY));
    assert!(reg.is_empty() && io.persisted.is_empty());
}

fn two() -> (MemberRegistry, Io) {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    run(&mut reg, &mut io, MemberAction::add(b"work", b"k1"));
    run(&mut reg, &mut io, MemberAction::add(b"home", b"k2"));
    io.persisted.clear();
    io.dns = 0;
    (reg, io)
}

#[test]
fn enable_and_disable() {
    let (mut reg, mut io) = two();
    assert_eq!(run(&mut reg, &mut io, MemberAction::Enable(9)), Reply::failure(text::NOT_FOUND));
    assert_eq!(run(&mut reg, &mut io, MemberAction::Disable(0)), Reply::failure(text::NOT_FOUND));
    assert_eq!(run(&mut reg, &mut io, MemberAction::Disable(1)), Reply::OK);
    assert!(!reg.get(1).unwrap().enabled && io.stopped.is_empty() && io.persisted.len() == 1);
    io.clients.push(2);
    reg.get_mut(2).unwrap().set_error("old error");
    assert_eq!(run(&mut reg, &mut io, MemberAction::Disable(2)), Reply::OK);
    assert_eq!(io.stopped, [2]);
    assert!(reg.get(2).unwrap().error.is_empty());
    io.stopped.clear();
    assert_eq!(run(&mut reg, &mut io, MemberAction::Enable(2)), Reply::OK);
    assert!(reg.get(2).unwrap().enabled && io.stopped.is_empty());
}

#[test]
fn enable_change_not_saved_restores_the_flag() {
    let (mut reg, mut io) = two();
    io.persist_ok = false;
    assert_eq!(run(&mut reg, &mut io, MemberAction::Disable(1)), Reply::failure(text::CHANGE_NOT_SAVED));
    assert!(reg.get(1).unwrap().enabled);
    assert!(io.stopped.is_empty());
}

#[test]
fn disconnect_still_finishing() {
    let (mut reg, mut io) = two();
    io.clients.push(1);
    io.stop_ok = false;
    assert_eq!(run(&mut reg, &mut io, MemberAction::Disable(1)), Reply::failure(text::DISCONNECT_PENDING));
    let m = reg.get(1).unwrap();
    assert!(!m.enabled, "the disabled state was saved and stays");
    assert_eq!(m.error.as_str(), Some(text::SHUTDOWN_RUNNING));
}

#[test]
fn remove_runs_the_whole_sequence() {
    let (mut reg, mut io) = two();
    assert_eq!(run(&mut reg, &mut io, MemberAction::Remove(7)), Reply::failure(text::NOT_FOUND));
    assert_eq!(run(&mut reg, &mut io, MemberAction::Remove(1)), Reply::OK);
    assert!(reg.get(1).is_none() && reg.len() == 1);
    assert_eq!(io.stopped, [1]);
    assert_eq!(io.forgotten, [1]);
    assert_eq!(io.erased, [b"tn_00000001".to_vec()]);
    assert_eq!(
        String::from_utf8(io.persisted.last().unwrap().clone()).unwrap(),
        r#"{"members":[{"id":2,"label":"home","key":"k2","enabled":true}],"next_id":3}"#
    );
    assert_eq!(reg.next_id(), 3, "ids are never reused");
}

#[test]
fn remove_waiting_for_shutdown_keeps_the_member_disabled_and_saved() {
    let (mut reg, mut io) = two();
    io.stop_ok = false;
    assert_eq!(run(&mut reg, &mut io, MemberAction::Remove(2)), Reply::failure(text::REMOVAL_PENDING));
    assert!(!reg.get(2).unwrap().enabled);
    assert_eq!(reg.len(), 2);
    assert_eq!(io.persisted.len(), 1, "the disabled state is written (result ignored)");
    assert!(String::from_utf8_lossy(&io.persisted[0]).contains(r#""label":"home","key":"k2","enabled":false"#));
    assert!(io.forgotten.is_empty() && io.erased.is_empty());
}

#[test]
fn remove_not_saved_puts_it_back_in_place() {
    let (mut reg, mut io) = two();
    io.persist_ok = false;
    let before: Vec<u32> = reg.iter().map(|m| m.id).collect();
    assert_eq!(run(&mut reg, &mut io, MemberAction::Remove(1)), Reply::failure(text::REMOVAL_NOT_SAVED));
    assert_eq!(reg.iter().map(|m| m.id).collect::<Vec<_>>(), before);
    assert!(!reg.get(1).unwrap().enabled, "the C leaves it disabled in memory");
    assert!(io.forgotten.is_empty() && io.erased.is_empty());
}

#[test]
fn identity_cleanup_failure_is_reported_but_the_member_is_gone() {
    let (mut reg, mut io) = two();
    io.erase_ok = false;
    assert_eq!(run(&mut reg, &mut io, MemberAction::Remove(2)), Reply::failure(text::IDENTITY_CLEANUP));
    assert!(reg.get(2).is_none());
    assert_eq!(io.forgotten, [2]);
}

// ---- tests/test_settings.c ----
#[test]
fn settings_roundtrip_reverses_order_like_the_c() {
    let mut reg = MemberRegistry::new();
    reg.set_next_id(3);
    assert!(reg.append(Member::restored(1, b"work", b"", false)));
    assert!(reg.append(Member::restored(2, b"personal", b"test-key", true)));
    let mut buf = vec![0u8; ENCODE_BUFFER];
    let n = reg.encode(&mut buf).unwrap();
    let good = buf[..n].to_vec();
    assert_eq!(
        std::str::from_utf8(&good).unwrap(),
        r#"{"members":[{"id":1,"label":"work","key":"","enabled":false},{"id":2,"label":"personal","key":"test-key","enabled":true}],"next_id":3}"#
    );
    let mut loaded = MemberRegistry::new();
    loaded.load(&good).unwrap();
    assert_eq!(loaded.iter().map(|m| m.id).collect::<Vec<_>>(), [2, 1], "each load reverses the list");
    assert_eq!(loaded.next_id(), 3);
    assert_eq!(loaded.get(2).unwrap().hostname().as_str(), Some("tdongle-personal-2"));
}

#[test]
fn failed_load_changes_nothing() {
    let mut reg = MemberRegistry::new();
    let mut io = Io::new();
    run(&mut reg, &mut io, MemberAction::add(b"keep", b""));
    let before = reg.next_id();
    for bad in [
        &br#"{"next_id":3,"members":[{"id":1,"label":"work","key":"","enabled":true},{"id":1,"label":"bad","key":"","enabled":true}]}"#[..],
        b"not JSON",
        b"",
        b"{}",
    ] {
        assert!(reg.load(bad).is_err());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.next_id(), before);
        assert_eq!(reg.iter().next().unwrap().label(), b"keep");
    }
}

#[test]
fn every_load_rejection_branch() {
    use LoadError::*;
    let m = |l: &str, k: &str, id: &str, en: &str| format!(r#"{{"id":{id},"label":{l},"key":{k},"enabled":{en}}}"#);
    let doc = |next: &str, ms: &[String]| format!(r#"{{"members":[{}],"next_id":{next}}}"#, ms.join(","));
    let good = m("\"a\"", "\"\"", "1", "true");
    assert_eq!(MemberRegistry::new().load(doc("2", std::slice::from_ref(&good)).as_bytes()), Ok(()));
    let cases: Vec<(String, LoadError)> = vec![
        (doc("0", &[]), Header),
        (doc("4294967295", &[]), Header),
        (doc("1.5", &[]), Header),
        (doc("\"2\"", &[]), Header),
        (r#"{"members":[]}"#.into(), Header),
        (r#"{"next_id":2}"#.into(), Header),
        (r#"{"members":{},"next_id":2}"#.into(), Header),
        ("[]".into(), Header),
        (doc("2", &[m("\"\"", "\"\"", "1", "true")]), Entry),
        (doc("2", &[m("\"aaaaaaaaaaaaaaaaaaaaa\"", "\"\"", "1", "true")]), Entry),
        (doc("2", &[m("7", "\"\"", "1", "true")]), Entry),
        (doc("2", &[m("\"a\"", &format!("\"{}\"", "k".repeat(160)), "1", "true")]), Entry),
        (doc("2", &[m("\"a\"", "null", "1", "true")]), Entry),
        (doc("2", &[m("\"a\"", "\"\"", "1", "1")]), Entry),
        (doc("2", &[m("\"a\"", "\"\"", "0", "true")]), Entry),
        (doc("2", &[m("\"a\"", "\"\"", "2", "true")]), Entry),
        (doc("2", &[m("\"a\"", "\"\"", "1.5", "true")]), Entry),
        (doc("2", &[m("\"a\"", "\"\"", "\"1\"", "true")]), Entry),
        (doc("3", &[m("\"a\"", "\"\"", "1", "true"), m("\"A\"", "\"\"", "2", "true")]), Duplicate),
        (doc("3", &[m("\"a\"", "\"\"", "1", "true"), m("\"b\"", "\"\"", "1", "true")]), Duplicate),
        ("{\"members\":[".into(), Syntax),
        (r#"{"members":[],"next_id":2,}"#.into(), Syntax),
        (String::new(), Size),
        (format!(r#"{{"members":[],"next_id":1}}{}"#, " ".repeat(16384)), Size),
    ];
    for (input, want) in cases {
        assert_eq!(MemberRegistry::new().load(input.as_bytes()), Err(want), "{input}");
    }
    let pad = |n: usize| format!(r#"{{"members":[],"next_id":1}}{}"#, " ".repeat(n - 26));
    assert_eq!(MemberRegistry::new().load(pad(16383).as_bytes()), Ok(()));
    assert_eq!(MemberRegistry::new().load(pad(16384).as_bytes()), Err(Size));
    let many: Vec<String> = (1..=9).map(|i| m(&format!("\"m{i}\""), "\"\"", &i.to_string(), "true")).collect();
    assert_eq!(MemberRegistry::new().load(doc("10", &many).as_bytes()), Err(Capacity));
}

#[test]
fn encode_size_limit() {
    let mut reg = Registry::<100>::new();
    reg.set_next_id(500);
    for i in 0..90 {
        assert!(reg.append(Member::restored(i + 1, format!("m{i}").as_bytes(), &[b'k'; 159], true)));
    }
    let mut buf = vec![0u8; 1 << 16];
    assert_eq!(reg.encode(&mut buf), Err(EncodeError::TooLarge));
    let mut small = [0u8; 10];
    let mut one = Registry::<1>::new();
    one.append(Member::restored(1, b"a", b"", true));
    assert_eq!(one.encode(&mut small), Err(EncodeError::Buffer));
}

#[test]
fn escapes_roundtrip_through_the_stored_string() {
    let mut reg = MemberRegistry::new();
    reg.set_next_id(2);
    reg.append(Member::restored(1, b"a", b"q\"\\\x01\n\x7f\xc3\xa9", true));
    let mut buf = vec![0u8; ENCODE_BUFFER];
    let n = reg.encode(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"{\"members\":[{\"id\":1,\"label\":\"a\",\"key\":\"q\\\"\\\\\\u0001\\n\x7f\xc3\xa9\",\"enabled\":true}],\"next_id\":2}");
    let mut back = MemberRegistry::new();
    back.load(&buf[..n]).unwrap();
    assert_eq!(back.get(1).unwrap().key(), b"q\"\\\x01\n\x7f\xc3\xa9");
}

#[test]
fn state_sizes() {
    println!("MemberRegistry: {} bytes ({} members), one Member {} bytes", MemberRegistry::STATE_BYTES, MAX_MEMBERS, core::mem::size_of::<Member>());
    const { assert!(MemberRegistry::STATE_BYTES < 3000) };
}

#[test]
fn debug_never_prints_the_key() {
    let m = Member::restored(1, b"a", b"tskey-auth-SECRET", true);
    assert!(!format!("{m:?}").contains("SECRET"));
}

#[test]
fn the_c_texts_are_all_here() {
    // Every literal text of command() and the membership error strings of gateway_main.c is a constant of this crate (skipped without the C tree).
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../alternative/tailnet/main/gateway_main.c");
    let Ok(c) = std::fs::read_to_string(path) else { return };
    let ours = include_str!("../src/command.rs");
    for literal in [
        "JSON required",
        "Request is too large",
        "Incomplete request",
        "Invalid JSON",
        "That is not available from the setup network",
        "Unknown action",
        "Memberships are busy; retry shortly",
        "Use a short label and valid auth key",
        "Labels use letters, numbers and hyphens",
        "That label is already saved",
        "Cannot allocate another membership",
        "Membership could not be saved",
        "Membership not found",
        "Change could not be saved",
        "Disconnect is still finishing; retry shortly",
        "Removal is waiting for shutdown; retry shortly",
        "Removal could not be saved",
        "Shutdown is still running; retry after it finishes",
        "Waiting for another membership to finish joining",
        "Not enough free memory to activate this membership",
        "Socket capacity reserved for USB setup and DNS",
        "Could not allocate or save this identity",
        "Routing storage is damaged; tailnet access is disabled",
        "Recovery mode: settings are preserved. Use Restart services in the app after saving diagnostics.",
    ] {
        assert!(c.contains(&format!("\"{literal}\"")), "C no longer says {literal:?}");
        assert!(ours.contains(&format!("\"{literal}\"")), "crate lacks {literal:?}");
    }
    assert!(c.contains("Membership removed, but stored identity \""));
    assert!(c.contains("cleanup failed\""));
    assert!(c.contains("Connected; provisioning-key cleanup could not \""));
}
