//! Ports of `tests/test_profile_json.c`, plus a replay of 2,500 cases that the real C parser (cJSON 1.7.19 + `profile_parse_json`)
//! accepted or refused (`tests/golden/json_corpus.bin`, written by `tools/gen_golden.c`).
use tdongle_nvs_format::cstr::c_str;
use tdongle_nvs_format::legacy::LegacyProfile;
use tdongle_nvs_format::profile_json::{ProfileJsonError, profile_parse_json};

const VALID: &str =
    r#"{"slot":8,"priority":100,"name":"Home","ssid":"Network","password":"12345678"}"#;

#[test]
fn the_valid_command() {
    let p = profile_parse_json(VALID.as_bytes()).unwrap();
    assert_eq!(p.slot, 7);
    assert_eq!(c_str(&p.profile.pass), b"12345678");
    assert_eq!(
        (
            c_str(&p.profile.name),
            c_str(&p.profile.ssid),
            p.profile.priority
        ),
        (&b"Home"[..], &b"Network"[..], 100)
    );
    // Unused bytes of the profile are zero (C memsets it first).
    assert!(
        p.profile.name[4..].iter().all(|&b| b == 0) && p.profile.pass[8..].iter().all(|&b| b == 0)
    );
}

#[test]
fn refused_commands() {
    let bad = [
        "",
        "{}",
        "[]",
        "null",
        "{",
        r#"{"slot":1}"#,
        r#"{"slot":1,"slot":2,"priority":1,"name":"x","ssid":"x","password":""}"#,
        r#"{"slot":1,"priority":1,"name":"x","ssid":"x","password":"\u0000hidden"}"#,
        r#"{"slot":1,"priority":1,"name":"x","ssid":"x","password":"short"}"#,
        r#"{"slot":1.5,"priority":1,"name":"x","ssid":"x","password":""}"#,
        r#"{"slot":1,"priority":1,"name":"x","ssid":"x","password":"","extra":0}"#,
        r#"{"slot":1,"priority":1,"name":"x","ssid":"x\n","password":""}"#,
    ];
    for text in bad {
        assert!(profile_parse_json(text.as_bytes()).is_err(), "{text}");
    }
    assert!(profile_parse_json(format!("{VALID} trailing").as_bytes()).is_err());
}

#[test]
fn errors_name_the_rule() {
    let e = |t: &str| profile_parse_json(t.as_bytes()).unwrap_err();
    assert_eq!(e(&" ".repeat(501)), ProfileJsonError::TooLong);
    assert_eq!(e(r#"{"a":"\u0041"}"#), ProfileJsonError::EscapeNotAllowed);
    assert_eq!(e("{\"a\":\"x\\"), ProfileJsonError::EscapeNotAllowed);
    assert_eq!(e("[]"), ProfileJsonError::Malformed);
    assert_eq!(e(r#"{"nope":1}"#), ProfileJsonError::BadKey);
    assert_eq!(e(r#"{"slot":1,"slot":1}"#), ProfileJsonError::BadKey);
    assert_eq!(e(r#"{"slot":1}"#), ProfileJsonError::MissingKey);
    assert_eq!(
        e(r#"{"slot":9,"priority":1,"name":"x","ssid":"x","password":""}"#),
        ProfileJsonError::BadValue
    );
    assert_eq!(
        e(r#"{"slot":1,"priority":1,"name":"x","ssid":"x","password":"1234567"}"#),
        ProfileJsonError::InvalidProfile
    );
}

fn with(slot: &str, priority: &str) -> String {
    format!(r#"{{"slot":{slot},"priority":{priority},"name":"x","ssid":"x","password":""}}"#)
}

#[test]
fn numbers_follow_strtod() {
    // Accepted by cJSON because strtod reads them as exact integers.
    for (slot, priority, expect) in [
        ("1.0", "1", 0),
        ("1e0", "1E0", 0),
        ("0.8e1", "1000e-1", 7),
        ("01", "001", 0),
        ("1.", "1", 0),
        ("8", "-0", 7),
        ("8", "-.0", 7),
        ("8", "-0.0e5", 7),
        ("3", "0", 2),
        ("1", "1.00000000000000000000001", 0),
        ("1e+0", "2e-0", 0),
        ("2", "100.0000000000000001", 1),
    ] {
        let p = profile_parse_json(with(slot, priority).as_bytes())
            .unwrap_or_else(|e| panic!("{slot} {priority}: {e:?}"));
        assert_eq!(p.slot, expect, "{slot}");
    }
    // Refused.
    for (slot, priority) in [
        ("+1", "1"),
        ("1", "101"),
        ("0", "1"),
        ("9", "1"),
        ("1e999", "1"),
        ("-1e999", "1"),
        ("1e", "1"),
        ("1-2", "1"),
        ("0x1", "1"),
        ("\"1\"", "1"),
        ("true", "1"),
        ("2147483648", "1"),
        ("4294967297", "1"),
        ("1", "-1"),
        ("-", "1"),
        ("1", ".5"),
        ("1", "1.5"),
    ] {
        assert!(
            profile_parse_json(with(slot, priority).as_bytes()).is_err(),
            "{slot} {priority}"
        );
    }
    assert_eq!(
        profile_parse_json(with("1", "1e2").as_bytes())
            .unwrap()
            .profile
            .priority,
        100
    );
}

#[test]
fn whitespace_bom_and_nul() {
    let body = with("1", "1");
    assert!(profile_parse_json(format!(" \t\r\n{body} \t\r\n").as_bytes()).is_ok());
    assert!(profile_parse_json(format!("\x01\x02{body}\x1f ").as_bytes()).is_ok()); // any byte up to 0x20 is whitespace
    assert!(
        profile_parse_json([&b"\xEF\xBB\xBF"[..], body.as_bytes()].concat().as_slice()).is_ok()
    );
    assert!(profile_parse_json(b"\xEF\xBB\xBF").is_err());
    assert!(profile_parse_json([&b"\xEF\xBB"[..], body.as_bytes()].concat().as_slice()).is_err());
    assert!(profile_parse_json(format!("{body}}}").as_bytes()).is_err());
    assert!(profile_parse_json(format!("{body},").as_bytes()).is_err());
    // A C string ends at its first NUL: what follows is not part of the command.
    assert!(profile_parse_json([body.as_bytes(), b"\0garbage"].concat().as_slice()).is_ok());
    assert!(profile_parse_json([&b"{\"slot\":1\0"[..], b"}"].concat().as_slice()).is_err());
}

#[test]
fn limits() {
    let make = |n: usize, s: usize, p: usize| {
        format!(
            r#"{{"slot":5,"priority":9,"name":"{}","ssid":"{}","password":"{}"}}"#,
            "n".repeat(n),
            "s".repeat(s),
            "p".repeat(p)
        )
    };
    for (n, s, p, ok) in [
        (24, 32, 63, true),
        (23, 31, 62, true),
        (25, 32, 63, false),
        (24, 33, 63, false),
        (24, 32, 64, false),
        (24, 32, 7, false),
        (24, 32, 8, true),
        (24, 32, 0, true),
        (0, 32, 0, false),
        (24, 0, 0, false),
    ] {
        assert_eq!(
            profile_parse_json(make(n, s, p).as_bytes()).is_ok(),
            ok,
            "{n} {s} {p}"
        );
    }
    let base = with("1", "1");
    for extra in 495..=502usize {
        let padded = format!("{base}{}", " ".repeat(extra.saturating_sub(base.len())));
        assert_eq!(
            profile_parse_json(padded.as_bytes()).is_ok(),
            padded.len() <= 500,
            "{}",
            padded.len()
        );
    }
}

#[test]
fn escapes_and_raw_bytes() {
    let ok = |name: &str, ssid: &str, pass: &str| {
        profile_parse_json(
            format!(
                r#"{{"slot":1,"priority":1,"name":"{name}","ssid":"{ssid}","password":"{pass}"}}"#
            )
            .as_bytes(),
        )
    };
    let p = ok(r#"a\"b"#, r"x\\y", r"p\/q\/r\/s\/t").unwrap();
    assert_eq!(
        (
            c_str(&p.profile.name),
            c_str(&p.profile.ssid),
            c_str(&p.profile.pass)
        ),
        (&b"a\"b"[..], &b"x\\y"[..], &b"p/q/r/s/t"[..])
    );
    for bad in [r"a\tb", r"a\bb", r"a\nb", r"a\qb", r"a\fb", r"a\rb"] {
        assert!(ok(bad, "x", "").is_err(), "{bad}"); // valid JSON escapes that decode to control characters, or are not JSON at all
    }
    assert!(ok("a\tb", "x", "").is_err()); // a raw control character
    assert!(ok("caf\u{e9}", "x", "").is_err() && ok("a\u{7f}", "x", "").is_err());
    assert!(ok("a b~", r##" !\"#$%&'()*+,-./"##, "        ").is_ok());
    assert!(
        profile_parse_json(br#"{"s\/ot":1,"priority":1,"name":"x","ssid":"x","password":""}"#)
            .is_err()
    );
    assert!(
        profile_parse_json(br#"{"Slot":1,"priority":1,"name":"x","ssid":"x","password":""}"#)
            .is_err()
    );
    assert!(
        profile_parse_json(br#"{"password":"","ssid":"x","name":"x","priority":7,"slot":3}"#)
            .is_ok()
    );
}

#[test]
fn structure() {
    for bad in [
        r#"{"slot":1 "priority":1,"name":"x","ssid":"x","password":""}"#,
        r#"{slot:1,"priority":1,"name":"x","ssid":"x","password":""}"#,
        r#"{"slot":1,"priority":1,"name":"x","ssid":"x","password":"",}"#,
        r#"{,"slot":1}"#,
        r#"{"slot":1,"priority":1,"name":"x","ssid":"x","password":{}}"#,
        r#"{"slot":1,"priority":1,"name":null,"ssid":"x","password":""}"#,
        r#"{"slot":1,"priority":1,"name":1,"ssid":"x","password":""}"#,
        r#""{}""#,
        "1",
        "-",
        "\"",
        "{\"",
        "{\"a",
        "{\"a\"",
        "{\"a\":",
        "{\"a\":1",
        "{\"a\":1,",
        "{\"a\":}",
    ] {
        assert!(profile_parse_json(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(
        profile_parse_json(
            br#"{ "slot" : 1 , "priority" : 1 , "name" : "x" , "ssid" : "x" , "password" : "" }"#
        )
        .is_ok()
    );
    assert!(
        profile_parse_json(
            b"{\"slot\"\t:\t1,\"priority\"\n:1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}"
        )
        .is_ok()
    );
}

#[test]
fn matches_the_c_parser_on_the_golden_corpus() {
    let corpus = include_bytes!("golden/json_corpus.bin");
    let (mut at, mut cases, mut accepted) = (0, 0, 0);
    while at < corpus.len() {
        let len = usize::from(u16::from_le_bytes([corpus[at], corpus[at + 1]]));
        let text = &corpus[at + 2..at + 2 + len];
        let (ok, slot) = (corpus[at + 2 + len] != 0, usize::from(corpus[at + 3 + len]));
        at += 4 + len;
        let shown = String::from_utf8_lossy(text);
        match profile_parse_json(text) {
            Ok(parsed) => {
                assert!(ok, "Rust accepts what C refused: {shown:?}");
                assert_eq!(parsed.slot, slot, "{shown:?}");
                let c = &corpus[at..at + 124];
                let mut expected = LegacyProfile::EMPTY;
                expected.name.copy_from_slice(&c[0..25]);
                expected.ssid.copy_from_slice(&c[25..58]);
                expected.pass.copy_from_slice(&c[58..123]);
                expected.priority = c[123];
                assert_eq!(parsed.profile, expected, "{shown:?}");
                assert!(parsed.profile.valid());
                accepted += 1;
            }
            Err(e) => assert!(!ok, "Rust refuses ({e:?}) what C accepted: {shown:?}"),
        }
        if ok {
            at += 124;
        }
        cases += 1;
    }
    assert_eq!(at, corpus.len());
    assert!(cases >= 2500, "{cases}");
    assert!(
        accepted >= 100,
        "the corpus must exercise acceptance too: {accepted} of {cases}"
    );
}
