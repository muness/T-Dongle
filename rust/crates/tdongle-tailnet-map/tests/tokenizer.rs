//! The tokenizer against `serde_json`, chunking invariance, and the adversarial inputs the bounds exist for.

use proptest::prelude::*;
use serde_json::Value;
use tdongle_tailnet_map::json::*;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Start,
    End,
    StartA,
    EndA,
    Key(Vec<u8>, u8, u32, u32),
    Str(Vec<u8>, u8, u32, u32),
    Num(Vec<u8>),
    Bool(bool),
    Null,
}

#[derive(Default)]
struct Collect(Vec<Ev>);
impl TokenSink for Collect {
    type Error = ();
    fn event(&mut self, e: Event<'_>) -> Result<(), ()> {
        self.0.push(match e {
            Event::StartObject => Ev::Start,
            Event::EndObject => Ev::End,
            Event::StartArray => Ev::StartA,
            Event::EndArray => Ev::EndA,
            Event::Key(t) => Ev::Key(t.bytes.to_vec(), t.flags, t.decoded_len, t.raw_len),
            Event::Str(t) => Ev::Str(t.bytes.to_vec(), t.flags, t.decoded_len, t.raw_len),
            Event::Number(n) => Ev::Num(n.to_vec()),
            Event::Bool(b) => Ev::Bool(b),
            Event::Null => Ev::Null,
        });
        Ok(())
    }
}

fn tokenize(policy: Policy, chunks: &[&[u8]]) -> (Result<(), JsonError>, Vec<Ev>) {
    let mut t = Tokenizer::new(policy);
    let mut c = Collect::default();
    for ch in chunks {
        if let Err(e) = t.feed(ch, &mut c) {
            return (Err(unwrap(e)), c.0);
        }
    }
    match t.finish(&mut c) {
        Ok(()) => (Ok(()), c.0),
        Err(e) => (Err(unwrap(e)), c.0),
    }
}

fn unwrap(e: ParseError<()>) -> JsonError {
    match e {
        ParseError::Json(j) => j,
        ParseError::Sink(()) => unreachable!(),
    }
}

fn whole(policy: Policy, doc: &[u8]) -> (Result<(), JsonError>, Vec<Ev>) {
    tokenize(policy, &[doc])
}

fn is_limit(e: &JsonError) -> bool {
    matches!(e, JsonError::Depth | JsonError::KeyTooLong | JsonError::ScalarTooLong)
}

/// Rebuild a `serde_json::Value` from strict events (numbers via the text, which serde parses itself).
fn rebuild(events: &[Ev]) -> Option<Value> {
    enum Frame {
        Obj(serde_json::Map<String, Value>, Option<String>),
        Arr(Vec<Value>),
    }
    let mut stack: Vec<Frame> = vec![];
    let mut result = None;
    let put = |stack: &mut Vec<Frame>, v: Value, result: &mut Option<Value>| match stack.last_mut() {
        None => *result = Some(v),
        Some(Frame::Arr(a)) => a.push(v),
        Some(Frame::Obj(m, k)) => {
            m.insert(k.take().unwrap(), v);
        }
    };
    for e in events {
        match e {
            Ev::Start => stack.push(Frame::Obj(Default::default(), None)),
            Ev::StartA => stack.push(Frame::Arr(vec![])),
            Ev::End | Ev::EndA => {
                let v = match stack.pop().unwrap() {
                    Frame::Obj(m, _) => Value::Object(m),
                    Frame::Arr(a) => Value::Array(a),
                };
                put(&mut stack, v, &mut result);
            }
            Ev::Key(b, ..) => {
                if let Some(Frame::Obj(_, k)) = stack.last_mut() {
                    *k = Some(String::from_utf8(b.clone()).ok()?);
                }
            }
            Ev::Str(b, ..) => put(&mut stack, Value::String(String::from_utf8(b.clone()).ok()?), &mut result),
            Ev::Num(n) => put(&mut stack, serde_json::from_slice(n).ok()?, &mut result),
            Ev::Bool(b) => put(&mut stack, Value::Bool(*b), &mut result),
            Ev::Null => put(&mut stack, Value::Null, &mut result),
        }
    }
    result
}

// ---- generators ---------------------------------------------------------------------------------------------------------------------------------

fn arb_string() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9 _./:-]{0,12}",
        proptest::collection::vec(any::<char>(), 0..8).prop_map(|v| v.into_iter().collect()),
        Just("\u{0}\"\\\n\t\u{1f}\u{7f}é€😀".to_string()),
        "[\u{0}-\u{ff}]{0,6}",
    ]
}

fn arb_number() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        (-1.0e300..1.0e300f64).prop_map(|f| serde_json::Number::from_f64(f).map(Value::Number).unwrap()),
        Just(Value::from(0)),
        Just(Value::from(-0.0)),
        Just(serde_json::from_str("1e5").unwrap()),
        Just(serde_json::from_str("-1.5E-7").unwrap()),
    ]
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![Just(Value::Null), any::<bool>().prop_map(Value::Bool), arb_number(), arb_string().prop_map(Value::String)];
    leaf.prop_recursive(6, 64, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::vec(("[a-zA-Z0-9_\u{e9}\u{20ac}\"\\\\ ]{0,10}", inner), 0..6).prop_map(|kv| Value::Object(kv.into_iter().collect())),
        ]
    })
}

/// Serialise `v` with random insignificant whitespace and, at random, `\uXXXX` escapes for non-ASCII.
fn render(v: &Value, ws: &mut impl Iterator<Item = u8>, out: &mut String) {
    let space = |out: &mut String, ws: &mut dyn Iterator<Item = u8>| {
        if let Some(b) = ws.next() {
            match b % 8 {
                0 => out.push(' '),
                1 => out.push('\n'),
                2 => out.push('\t'),
                3 => out.push('\r'),
                _ => {}
            }
        }
    };
    match v {
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                space(out, ws);
                render(x, ws, out);
                space(out, ws);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                space(out, ws);
                out.push_str(&serde_json::to_string(k).unwrap());
                space(out, ws);
                out.push(':');
                space(out, ws);
                render(x, ws, out);
                space(out, ws);
            }
            out.push('}');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap()),
    }
}

fn escape_unicode(s: &str) -> String {
    // every non-ASCII char as \uXXXX (surrogate pairs for astral)
    let mut o = String::new();
    for c in s.chars() {
        if c.is_ascii() {
            o.push(c);
        } else {
            let mut b = [0u16; 2];
            for u in c.encode_utf16(&mut b) {
                o.push_str(&format!("\\u{:04x}", u));
            }
        }
    }
    o
}

fn split_points(len: usize, cuts: &[usize]) -> Vec<usize> {
    let mut v: Vec<usize> = cuts.iter().map(|c| if len == 0 { 0 } else { c % (len + 1) }).collect();
    v.sort_unstable();
    v
}

fn pieces<'a>(doc: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    let mut out = vec![];
    let mut prev = 0;
    for p in split_points(doc.len(), cuts) {
        out.push(&doc[prev..p]);
        prev = p;
    }
    out.push(&doc[prev..]);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Valid documents: the strict tokenizer accepts exactly what serde_json accepts and rebuilds the same value.
    #[test]
    fn valid_documents_match_serde(v in arb_value(), noise in proptest::collection::vec(any::<u8>(), 0..64), esc in any::<bool>()) {
        let mut s = String::new();
        render(&v, &mut noise.into_iter(), &mut s);
        if esc { s = escape_unicode(&s); }
        let reference: Value = serde_json::from_str(&s).unwrap();
        let (r, ev) = whole(Policy::Strict, s.as_bytes());
        prop_assert_eq!(r, Ok(()));
        prop_assert_eq!(rebuild(&ev), Some(reference.clone()));
        // C-compatible policy: the same events, and nothing flagged in well formed text except NULs and truncation
        let (r2, ev2) = whole(Policy::CCompat, s.as_bytes());
        prop_assert_eq!(r2, Ok(()));
        prop_assert_eq!(ev.len(), ev2.len());
    }

    /// Chunking never matters: any partition of any bytes (valid or not) gives the same events and the same verdict.
    #[test]
    fn chunking_invariance_on_valid(v in arb_value(), cuts in proptest::collection::vec(any::<usize>(), 0..24), esc in any::<bool>()) {
        let mut s = serde_json::to_string(&v).unwrap();
        if esc { s = escape_unicode(&s); }
        for policy in [Policy::Strict, Policy::CCompat] {
            let expect = whole(policy, s.as_bytes());
            let got = tokenize(policy, &pieces(s.as_bytes(), &cuts));
            prop_assert_eq!(expect, got);
        }
    }

    #[test]
    fn chunking_invariance_on_garbage(bytes in proptest::collection::vec(prop_oneof![
            Just(b'{'), Just(b'}'), Just(b'['), Just(b']'), Just(b','), Just(b':'), Just(b'"'), Just(b'\\'), Just(b'u'), Just(b'1'), Just(b'-'), Just(b'e'),
            Just(b'.'), Just(b't'), Just(b'n'), Just(b'a'), Just(b' '), Just(0xc3u8), Just(0xa9u8), Just(0xedu8), Just(0xa0u8), any::<u8>()], 0..96),
        cuts in proptest::collection::vec(any::<usize>(), 0..16)) {
        for policy in [Policy::Strict, Policy::CCompat] {
            let expect = whole(policy, &bytes);
            let got = tokenize(policy, &pieces(&bytes, &cuts));
            prop_assert_eq!(&expect, &got);
            // and one byte at a time
            let singles: Vec<&[u8]> = bytes.chunks(1).collect();
            prop_assert_eq!(expect, tokenize(policy, &singles));
        }
    }

    /// Mutated valid documents: accept/reject agrees with serde_json (modulo the documented bounds and serde's own range/recursion limits).
    #[test]
    fn mutated_documents_agree_with_serde(v in arb_value(), edits in proptest::collection::vec((any::<usize>(), any::<u8>(), 0u8..3), 1..4)) {
        let mut b = serde_json::to_vec(&v).unwrap();
        for (at, byte, kind) in edits {
            if b.is_empty() { break; }
            let i = at % b.len();
            match kind { 0 => b[i] = byte, 1 => { b.insert(i, byte); } _ => { b.remove(i); } }
        }
        let (r, ev) = whole(Policy::Strict, &b);
        if let Err(e) = &r && is_limit(e) { return Ok(()); }
        let reference = serde_json::from_slice::<Value>(&b);
        match (&r, &reference) {
            (Ok(()), Ok(rv)) => { prop_assert_eq!(rebuild(&ev), Some(rv.clone())); }
            (Err(_), Err(_)) => {}
            (Ok(()), Err(e)) => {
                // serde refuses numbers beyond f64; the tokenizer only checks the grammar (the projector never reads those fields as floats)
                prop_assert!(e.to_string().contains("number out of range"), "tokenizer accepted what serde refuses: {:?} {}", String::from_utf8_lossy(&b), e);
            }
            (Err(e), Ok(_)) => prop_assert!(false, "tokenizer refused {:?} with {:?}", String::from_utf8_lossy(&b), e),
        }
        // the lenient policy accepts at least everything the strict one does, and the same syntax errors
        let (rc, _) = whole(Policy::CCompat, &b);
        if r.is_ok() { prop_assert_eq!(rc, Ok(())); }
        if let Err(e) = r && !matches!(e, JsonError::BadUtf8 | JsonError::LoneSurrogate) { prop_assert_eq!(rc, Err(e)); }
    }

    /// The C's discarded-value check accepts lone surrogates and invalid UTF-8 (gp_string); serde_json's `IgnoredAny` is the same lenient reader.
    #[test]
    fn ccompat_matches_serde_ignored_any(v in arb_value(), edits in proptest::collection::vec((any::<usize>(), any::<u8>(), 0u8..3), 0..4)) {
        let mut b = serde_json::to_vec(&v).unwrap();
        for (at, byte, kind) in edits {
            if b.is_empty() { break; }
            let i = at % b.len();
            match kind { 0 => b[i] = byte, 1 => { b.insert(i, byte); } _ => { b.remove(i); } }
        }
        let (r, _) = whole(Policy::CCompat, &b);
        if let Err(e) = &r && is_limit(e) { return Ok(()); }
        let reference = serde_json::from_slice::<serde::de::IgnoredAny>(&b);
        prop_assert_eq!(r.is_ok(), reference.is_ok(), "{:?}: {:?} vs {:?}", String::from_utf8_lossy(&b), r, reference);
    }

    /// Huge but bounded: strings of any length leave a fixed prefix and exact lengths.
    #[test]
    fn long_strings_keep_prefix_and_lengths(n in 0usize..5000, chunk in 1usize..700) {
        let body = "ab".repeat(n);
        let doc = format!("\"{body}\"");
        let chunks: Vec<&[u8]> = doc.as_bytes().chunks(chunk).collect();
        let (r, ev) = tokenize(Policy::Strict, &chunks);
        prop_assert_eq!(r, Ok(()));
        match &ev[0] {
            Ev::Str(bytes, flags, dec, raw) => {
                prop_assert_eq!(*dec as usize, 2 * n);
                prop_assert_eq!(*raw as usize, 2 * n + 2);
                prop_assert_eq!(bytes.len(), (2 * n).min(MAX_STRING));
                prop_assert_eq!(*flags & text_flags::TRUNCATED != 0, 2 * n > MAX_STRING);
                prop_assert_eq!(&bytes[..], &body.as_bytes()[..bytes.len()]);
            }
            other => prop_assert!(false, "{:?}", other),
        }
    }
}

// ---- adversarial cases ----------------------------------------------------------------------------------------------------------------------------

#[test]
fn depth_bombs_and_deep_arrays() {
    for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
        for depth in [1usize, 31, 32] {
            let doc = format!("{}1{}", open.repeat(depth), close.repeat(depth));
            assert_eq!(whole(Policy::Strict, doc.as_bytes()).0, Ok(()), "{open} {depth}");
        }
        for depth in [33usize, 64, 5000, 1_000_000] {
            let doc = format!("{}1{}", open.repeat(depth), close.repeat(depth));
            for cs in [doc.len(), 1, 4096] {
                let chunks: Vec<&[u8]> = doc.as_bytes().chunks(cs).collect();
                assert_eq!(tokenize(Policy::Strict, &chunks).0, Err(JsonError::Depth), "{open} {depth} {cs}");
            }
        }
    }
    // only openers, never closed: refused at the limit, not at the end
    let (r, ev) = whole(Policy::Strict, "[".repeat(100_000).as_bytes());
    assert_eq!(r, Err(JsonError::Depth));
    assert_eq!(ev.len(), MAX_DEPTH);
    // a deep array that closes early is fine and a flat wide one is too
    let wide = format!("[{}]", "[],".repeat(100_000) + "[]");
    assert_eq!(whole(Policy::Strict, wide.as_bytes()).0, Ok(()));
}

#[test]
fn huge_strings_cost_no_memory() {
    let mut t = Tokenizer::new(Policy::CCompat);
    let mut c = Collect::default();
    t.feed(b"\"", &mut c).unwrap();
    let chunk = vec![b'z'; 65536];
    for _ in 0..160 {
        t.feed(&chunk, &mut c).unwrap(); // 10 MiB
    }
    t.feed(b"\"", &mut c).unwrap();
    t.finish(&mut c).unwrap();
    match &c.0[0] {
        Ev::Str(b, flags, dec, raw) => {
            assert_eq!(b.len(), MAX_STRING);
            assert_eq!(*dec, 160 * 65536);
            assert_eq!(*raw, 160 * 65536 + 2);
            assert_eq!(flags & text_flags::TRUNCATED, text_flags::TRUNCATED);
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(t.consumed(), 160 * 65536 + 2);
    assert!(std::mem::size_of::<Tokenizer>() < 400);
    // escapes in a huge string: decoded length counts the decoded bytes
    let mut doc = String::from("\"");
    doc.push_str(&"\\u00e9".repeat(10_000));
    doc.push('"');
    let (r, ev) = whole(Policy::Strict, doc.as_bytes());
    assert_eq!(r, Ok(()));
    assert!(matches!(&ev[0], Ev::Str(b, f, 20_000, 60_002) if b.len() == MAX_STRING && f & text_flags::TRUNCATED != 0));
}

#[test]
fn keys_and_scalars_have_the_c_limits() {
    let key = |n: usize| format!("{{\"{}\":1}}", "k".repeat(n));
    assert_eq!(whole(Policy::Strict, key(MAX_KEY_RAW).as_bytes()).0, Ok(()));
    assert_eq!(whole(Policy::Strict, key(MAX_KEY_RAW + 1).as_bytes()).0, Err(JsonError::KeyTooLong));
    // escapes count raw: 126 raw bytes can decode to fewer
    assert_eq!(whole(Policy::Strict, format!("{{\"{}\":1}}", "\\u006b".repeat(21)).as_bytes()).0, Ok(()));
    assert_eq!(whole(Policy::Strict, format!("{{\"{}\":1}}", "\\u006b".repeat(22)).as_bytes()).0, Err(JsonError::KeyTooLong));
    let num = |n: usize| format!("[{}]", "9".repeat(n));
    assert_eq!(whole(Policy::Strict, num(MAX_SCALAR).as_bytes()).0, Ok(()));
    assert_eq!(whole(Policy::Strict, num(MAX_SCALAR + 1).as_bytes()).0, Err(JsonError::ScalarTooLong));
    // big numbers: the grammar only; exponent overflow is the consumer's problem
    for n in ["1e999", "-1e-999", "123456789012345678901234567890", "0.000000000000000000000000001", "1E+400", "-0", "0e0"] {
        assert_eq!(whole(Policy::Strict, format!("[{n}]").as_bytes()).0, Ok(()), "{n}");
    }
    for n in ["01", "-", "+1", ".5", "5.", "1e", "1e+", "--1", "0x10", "1_0", "NaN", "Infinity", "-Infinity", "1.5.2", "00", "-01"] {
        assert!(whole(Policy::Strict, format!("[{n}]").as_bytes()).0.is_err(), "{n}");
    }
    assert_eq!(number_i64(b"9223372036854775807"), Some(i64::MAX));
    assert_eq!(number_i64(b"-9223372036854775808"), Some(i64::MIN));
    assert_eq!(number_i64(b"9223372036854775808"), None);
    assert_eq!(number_i64(b"1.0"), None);
    assert_eq!(number_f64(b"1e999"), Some(f64::INFINITY));
    assert_eq!(number_f64(b"-12.34e+2"), Some(-1234.0));
}

#[test]
fn duplicate_keys_are_all_reported_in_order() {
    let (r, ev) = whole(Policy::Strict, br#"{"a":1,"a":2,"A":3}"#);
    assert_eq!(r, Ok(()));
    let keys: Vec<_> = ev.iter().filter_map(|e| if let Ev::Key(k, ..) = e { Some(k.clone()) } else { None }).collect();
    assert_eq!(keys, vec![b"a".to_vec(), b"a".to_vec(), b"A".to_vec()]);
}

#[test]
fn string_findings_and_policies() {
    use text_flags::*;
    // NUL escape: legal JSON, flagged
    for p in [Policy::Strict, Policy::CCompat] {
        let (r, ev) = whole(p, br#""a\u0000b""#);
        assert_eq!(r, Ok(()));
        assert!(matches!(&ev[0], Ev::Str(b, f, 3, 10) if b == b"a\0b" && f & HAS_NUL != 0));
    }
    // lone surrogates
    for doc in [&br#""\ud800""#[..], br#""\ud800x""#, br#""\udc00""#, br#""\ud800\ud800""#, br#""\ud800\n""#, br#""x\udbff""#] {
        assert_eq!(whole(Policy::Strict, doc).0, Err(JsonError::LoneSurrogate), "{}", String::from_utf8_lossy(doc));
        let (r, ev) = whole(Policy::CCompat, doc);
        assert_eq!(r, Ok(()));
        assert!(matches!(&ev[0], Ev::Str(_, f, _, _) if f & BAD_SURROGATE != 0));
        assert!(serde_json::from_slice::<serde::de::IgnoredAny>(doc).is_ok());
    }
    // a valid pair, including an escaped pair split across chunks
    let doc = br#""\ud83d\ude00""#;
    for cut in 0..doc.len() {
        let (r, ev) = tokenize(Policy::Strict, &[&doc[..cut], &doc[cut..]]);
        assert_eq!(r, Ok(()));
        assert!(matches!(&ev[0], Ev::Str(b, 0, 4, 14) if b == "😀".as_bytes()), "{cut}");
    }
    // raw invalid UTF-8
    let bad: &[&[u8]] = &[b"\"\xff\"", b"\"\xc3\"", b"\"\xc3(\"", b"\"\xe2\x82\"", b"\"\xed\xa0\x80\"", b"\"\xc0\xaf\"", b"\"\xf4\x90\x80\x80\"", b"\"\x80\""];
    for doc in bad {
        assert_eq!(whole(Policy::Strict, doc).0, Err(JsonError::BadUtf8), "{doc:?}");
        let (r, ev) = whole(Policy::CCompat, doc);
        assert_eq!(r, Ok(()), "{doc:?}");
        assert!(matches!(&ev[0], Ev::Str(_, f, _, _) if f & BAD_UTF8 != 0), "{doc:?}");
    }
    // valid multi-byte text split at every byte
    let doc = "\"é€😀\"".as_bytes();
    for cut in 0..doc.len() {
        let (r, ev) = tokenize(Policy::Strict, &[&doc[..cut], &doc[cut..]]);
        assert_eq!(r, Ok(()));
        assert!(matches!(&ev[0], Ev::Str(b, 0, 9, 11) if b == "é€😀".as_bytes()));
    }
    // errors inside strings
    for doc in [&b"\"\n\""[..], b"\"\x1f\"", b"\"\\x\"", b"\"\\u12\"", b"\"\\u12g4\"", b"\"\\\"", b"\"\\U0041\""] {
        assert!(whole(Policy::CCompat, doc).0.is_err(), "{doc:?}");
        assert!(serde_json::from_slice::<serde::de::IgnoredAny>(doc).is_err(), "{doc:?}");
    }
    // 0x7f and `/` escapes are fine
    assert_eq!(whole(Policy::Strict, b"\"\x7f\\/\"").0, Ok(()));
    // truncation: a prefix, flagged, lengths exact
    let doc = format!("\"{}\"", "é".repeat(200));
    let (r, ev) = whole(Policy::Strict, doc.as_bytes());
    assert_eq!(r, Ok(()));
    assert!(matches!(&ev[0], Ev::Str(b, f, 400, 402) if b.len() == MAX_STRING && f & TRUNCATED != 0));
}

#[test]
fn grammar_edges() {
    let accept: &[&str] = &[
        "{}",
        "[]",
        " {} ",
        "\t\r\n{\"a\":[1,2.5,-3e2,true,false,null,\"x\",{},[]]}\n",
        "[[],[[]],{}]",
        "\"s\"",
        "0",
        "-0.5e+3",
        "true",
        "null",
        "{\"a\":{\"b\":{\"c\":[]}}}",
    ];
    for d in accept {
        assert_eq!(whole(Policy::Strict, d.as_bytes()).0, Ok(()), "{d:?}");
        assert!(serde_json::from_str::<Value>(d).is_ok());
    }
    let reject: &[&str] = &[
        "",
        " ",
        "{",
        "[",
        "}",
        "]",
        "{]",
        "[}",
        "{,}",
        "[,]",
        "[1,]",
        "{\"a\":1,}",
        "{\"a\"}",
        "{\"a\":}",
        "{a:1}",
        "{'a':1}",
        "[1 2]",
        "{\"a\" 1}",
        "{\"a\":1 \"b\":2}",
        "tru",
        "nul",
        "truee",
        "falsey",
        "nulll",
        "[1]x",
        "{}{}",
        "[] []",
        "\"unterminated",
        "1 2",
        "[1,,2]",
        "{\"a\":1}}",
        "[[]",
        "\u{feff}{}",
        "{\"a\":01}",
        "[tru e]",
        ":",
        ",",
        "{\"a\":1,\"a\"}",
    ];
    for d in reject {
        assert!(whole(Policy::Strict, d.as_bytes()).0.is_err(), "{d:?}");
        assert!(serde_json::from_str::<Value>(d).is_err(), "{d:?}");
    }
    // a root scalar completes at finish()
    let mut t = Tokenizer::default();
    let mut c = Collect::default();
    t.feed(b"123", &mut c).unwrap();
    assert!(!t.is_complete());
    t.finish(&mut c).unwrap();
    assert_eq!(c.0, vec![Ev::Num(b"123".to_vec())]);
    // reset starts over
    t.reset();
    assert_eq!(t.depth(), 0);
    let mut c = Collect::default();
    t.feed(b"[1]", &mut c).unwrap();
    t.finish(&mut c).unwrap();
    assert!(t.is_complete());
    // after the root, whitespace only
    assert_eq!(t.feed(b"  \n", &mut c), Ok(()));
    assert_eq!(t.feed(b"x", &mut c), Err(ParseError::Json(JsonError::TrailingData)));
}

#[test]
fn sink_refusal_poisons_the_tokenizer() {
    struct Refuse(u32);
    impl TokenSink for Refuse {
        type Error = &'static str;
        fn event(&mut self, _: Event<'_>) -> Result<(), &'static str> {
            self.0 += 1;
            if self.0 == 2 { Err("no") } else { Ok(()) }
        }
    }
    let mut t = Tokenizer::default();
    let mut s = Refuse(0);
    assert_eq!(t.feed(b"[1,2,3]", &mut s), Err(ParseError::Sink("no")));
    assert_eq!(s.0, 2, "no event after the refusal");
    assert_eq!(t.feed(b"]", &mut s), Err(ParseError::Json(JsonError::Poisoned)));
    assert_eq!(t.finish(&mut s), Err(ParseError::Json(JsonError::Poisoned)));
}
