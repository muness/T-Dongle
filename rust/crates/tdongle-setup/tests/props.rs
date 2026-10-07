//! Property tests: nothing panics, and the security rules hold for arbitrary input.
mod common;
use common::*;
use proptest::prelude::*;
use tdongle_setup::http::{Reader, Step};
use tdongle_setup::router::{BodyIn, Conn};
use tdongle_setup::{dns, json};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn dns_never_panics_and_never_amplifies(q in proptest::collection::vec(any::<u8>(), 0..400), cap in 0usize..400) {
        let mut out = vec![0u8; cap];
        if let Some(n) = dns::reply(&q, &mut out, dns::DONGLE) {
            prop_assert!(n <= cap);
            prop_assert!(n <= q.len() + 16);
            prop_assert!(out[2] & 0x80 != 0, "a reply is a response");
            prop_assert!(q[2] & 0x80 == 0, "never answers a response");
            prop_assert_eq!(&out[..2], &q[..2]);
        }
        let mut full = [0u8; dns::REPLY_MAX];
        if let Some(n) = dns::serve(&q, &mut full) {
            prop_assert!(n <= dns::REPLY_MAX);
        }
    }

    #[test]
    fn dns_header_mutations_of_a_valid_query(flip in 0usize..40, v in any::<u8>()) {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];
        let at = flip % q.len();
        q[at] = v;
        let mut out = [0u8; 300];
        let _ = dns::reply(&q, &mut out, dns::DONGLE);
    }

    #[test]
    fn reader_outcome_does_not_depend_on_chunking(raw in proptest::collection::vec(prop_oneof![any::<u8>(), Just(b'\r'), Just(b'\n'), Just(b' '), Just(b':')], 0..1300), chunk in 1usize..200) {
        let run = |chunk: usize| {
            let mut r = Reader::new(0);
            let mut at = 0;
            let mut step = Step::More;
            while at < raw.len() && step == Step::More {
                let end = (at + chunk).min(raw.len());
                let (used, s) = r.push(&raw[at..end], 0);
                at += used;
                step = s;
            }
            (step, r.request().map(|q| (q.uri.to_vec(), q.content_len)), r.body().to_vec())
        };
        prop_assert_eq!(run(chunk), run(raw.len().max(1)));
    }

    #[test]
    fn json_parse_never_panics(body in proptest::collection::vec(any::<u8>(), 0..1100)) {
        let _ = json::parse(&body);
    }

    #[test]
    fn json_nesting_is_bounded(depth in 1usize..1300) {
        let mut b = vec![b'['; depth];
        b.extend(std::iter::repeat_n(b']', depth));
        let ok = json::parse(&b).is_some();
        prop_assert_eq!(ok, depth <= 1000);
    }

    /// Without the token, whatever the request, nothing mutates and no scan starts.
    #[test]
    fn nothing_acts_without_the_token(
        method in prop_oneof![Just("GET"), Just("POST"), Just("PUT"), Just("OPTIONS")],
        path in prop_oneof![Just("/command".to_string()), Just("/wifi-scan".to_string()), Just("/wifi-saved".to_string()), Just("/".to_string()), Just("/status".to_string()), "/[a-z/-]{0,20}"],
        token in prop_oneof![Just(String::new()), "[0-9a-f]{0,40}"],
        body in prop_oneof![Just(r#"{"action":"setup_done"}"#.to_string()), Just(r#"{"action":"wifi","ssid":"a","password":""}"#.to_string()), Just(r#"{"action":"wifi_remove","ssid":"a"}"#.to_string()), ".{0,60}"],
    ) {
        let p = portal();
        prop_assume!(token != self::token(&p));
        let mut h = FakeHost::new();
        h.saved = vec![(b"a".to_vec(), b"a".to_vec(), 1)];
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: 192.168.4.1\r\nX-Setup-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let (resp, _) = exchange(&p, &ap_conn(), &mut h, raw.as_bytes());
        prop_assert!(h.saves.is_empty() && h.removes.is_empty() && h.leave_requests == 0 && h.kicks.is_empty());
        // and the page token never appears in anything but the page itself
        if !(method == "GET" && path == "/") {
            prop_assert!(!String::from_utf8_lossy(&resp).contains(&self::token(&p)));
        }
    }

    /// From any address that is not a client of the setup network's own address, nothing acts, token or not.
    #[test]
    fn nothing_acts_from_the_wrong_place(peer in any::<u32>(), local in any::<u32>(), path in prop_oneof![Just("/command"), Just("/wifi-scan"), Just("/wifi-saved"), Just("/")]) {
        prop_assume!(!(peer & 0xffff_ff00 == 0xc0a8_0400 && local == 0xc0a8_0401));
        prop_assume!(!(peer & 0xffff_ff00 == 0xc0a8_4d00 && local == 0xc0a8_4d01));
        let p = portal();
        let mut h = FakeHost::new();
        let body = r#"{"action":"setup_done"}"#;
        let raw = format!("POST {path} HTTP/1.1\r\nHost: 192.168.4.1\r\nX-Setup-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", token(&p), body.len());
        let conn = Conn { peer: Some(peer), local: Some(local) };
        let (resp, _) = exchange(&p, &conn, &mut h, raw.as_bytes());
        prop_assert!(h.leave_requests == 0 && h.saves.is_empty());
        prop_assert!(!String::from_utf8_lossy(&resp).contains(&token(&p)));
    }

    /// Arbitrary bytes through reader and router never panic, and every response fits the write path.
    #[test]
    fn arbitrary_requests_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..1500), prefix in prop_oneof![Just(true), Just(false)]) {
        let p = portal();
        let mut h = FakeHost::new();
        let mut bytes = Vec::new();
        if prefix {
            bytes.extend_from_slice(format!("POST /command HTTP/1.1\r\nHost: 192.168.4.1\r\nX-Setup-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", token(&p), raw.len().min(1024)).as_bytes());
        }
        bytes.extend_from_slice(&raw);
        let mut reader = Reader::new(0);
        let (_, step) = reader.push(&bytes, 0);
        if step == Step::Ready {
            let req = reader.request().unwrap();
            let mut out = vec![0u8; 4096];
            let resp = p.serve(&ap_conn(), &req, BodyIn { bytes: reader.body(), incomplete: reader.body_incomplete() }, &mut h, &mut out);
            let mut sink = vec![0u8; 60000];
            prop_assert!(resp.write_into(&mut sink).is_some());
        }
    }
}
