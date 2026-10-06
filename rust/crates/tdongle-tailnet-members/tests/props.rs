//! Property tests and a deterministic mini-fuzz of the decoder and the request parser: no panics, and the invariants the C relies on.

use proptest::prelude::*;
use tdongle_tailnet_members::json_in::Reader;
use tdongle_tailnet_members::*;

fn label() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', Just(b'-')], 1..=20)
}
fn key() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(1u8..=255, 0..=159)
}

proptest! {
    #[test]
    fn encode_then_load_roundtrips_reversed(entries in proptest::collection::vec((label(), key(), any::<bool>()), 0..=8), extra in 0u32..1000) {
        let mut reg = MemberRegistry::new();
        let mut seen = std::collections::HashSet::new();
        let mut id = 0;
        for (l, k, e) in entries {
            if !seen.insert(l.to_ascii_lowercase()) { continue; }
            id += 1;
            prop_assert!(reg.append(Member::restored(id, &l, &k, e)));
        }
        reg.set_next_id(id + 1 + extra);
        let mut buf = vec![0u8; ENCODE_BUFFER];
        let n = reg.encode(&mut buf).unwrap();
        let mut back = MemberRegistry::new();
        back.load(&buf[..n]).unwrap();
        prop_assert_eq!(back.next_id(), reg.next_id());
        let a: Vec<_> = reg.iter().map(|m| (m.id, m.label().to_vec(), m.key().to_vec(), m.enabled)).collect();
        let mut b: Vec<_> = back.iter().map(|m| (m.id, m.label().to_vec(), m.key().to_vec(), m.enabled)).collect();
        b.reverse();
        prop_assert_eq!(a, b);
        // and a second save/load is a fixed point of the reversal
        let n2 = back.encode(&mut buf).unwrap();
        let mut again = MemberRegistry::new();
        again.load(&buf[..n2]).unwrap();
        prop_assert_eq!(again.iter().map(|m| m.id).collect::<Vec<_>>(), reg.iter().map(|m| m.id).collect::<Vec<_>>());
    }

    #[test]
    fn load_never_panics_and_accepted_state_is_valid(input in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut reg = MemberRegistry::new();
        if reg.load(&input).is_ok() {
            check_invariants(&reg);
        }
    }

    #[test]
    fn mutated_documents_keep_the_invariants(pos in 0usize..200, byte in any::<u8>(), cut in 0usize..200) {
        let doc = br#"{"members":[{"id":1,"label":"work","key":"","enabled":true},{"id":2,"label":"home","key":"abc","enabled":false}],"next_id":3}"#;
        let mut d = doc.to_vec();
        if pos < d.len() { d[pos] = byte; }
        d.truncate(d.len().max(1) - cut.min(d.len().saturating_sub(1)));
        let mut reg = MemberRegistry::new();
        if reg.load(&d).is_ok() { check_invariants(&reg); }
    }

    #[test]
    fn request_parser_never_panics(body in proptest::collection::vec(any::<u8>(), 0..1200), ct in any::<bool>()) {
        let ctype: Option<&[u8]> = if ct { Some(b"application/json") } else { None };
        let _ = parse_request(Origin::Usb, ctype, body.len(), &body);
        let _ = parse_request(Origin::SetupAp, ctype, body.len(), &body);
    }

    #[test]
    fn reader_never_panics_on_structured_noise(input in "[\\[\\]{}\",:\\\\ntruefalsu0-9eE.+x-]{0,200}") {
        let r = Reader::new(input.as_bytes());
        let _ = r.root();
    }

    #[test]
    fn apply_sequences_keep_the_registry_consistent(ops in proptest::collection::vec((0u8..4, 0u32..6, label()), 0..40)) {
        struct Io;
        impl MemberIo for Io {
            fn recovery(&self) -> bool { false }
            fn persist(&mut self, _: &[u8]) -> bool { true }
            fn has_client(&self, id: u32) -> bool { id.is_multiple_of(2) }
            fn stop(&mut self, id: u32) -> bool { !id.is_multiple_of(3) }
            fn forget(&mut self, _: u32) {}
            fn erase_identity(&mut self, _: &[u8]) -> bool { true }
            fn refresh_dns(&mut self) {}
        }
        let mut reg = MemberRegistry::new();
        let mut scratch = vec![0u8; ENCODE_BUFFER];
        let mut last_next = 1;
        for (op, id, l) in ops {
            let a = match op { 0 => MemberAction::add(&l, b"k"), 1 => MemberAction::Enable(id), 2 => MemberAction::Disable(id), _ => MemberAction::Remove(id) };
            let _ = apply(&mut reg, &a, &mut Io, &mut scratch);
            prop_assert!(reg.next_id() >= last_next, "ids are never reused");
            last_next = reg.next_id();
            check_invariants(&reg);
            let n = reg.encode(&mut scratch).unwrap();
            let mut back = MemberRegistry::new();
            prop_assert!(back.load(&scratch[..n]).is_ok());
        }
    }
}

fn check_invariants(reg: &MemberRegistry) {
    let ids: Vec<u32> = reg.iter().map(|m| m.id).collect();
    for (i, m) in reg.iter().enumerate() {
        assert!(m.id >= 1 && m.id < reg.next_id());
        assert!(!m.label().is_empty() && m.label().len() <= LABEL_MAX);
        assert!(m.key().len() <= KEY_MAX);
        assert_eq!(ids.iter().filter(|&&x| x == m.id).count(), 1);
        assert!(reg.iter().skip(i + 1).all(|o| !o.label().eq_ignore_ascii_case(m.label())));
    }
}

#[test]
fn deterministic_mini_fuzz() {
    // xorshift: mutate real documents and requests, 40k rounds, no panic; accepted registries are valid.
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let seeds: [&[u8]; 4] = [
        br#"{"members":[{"id":1,"label":"work","key":"","enabled":true},{"id":2,"label":"home","key":"abc","enabled":false}],"next_id":3}"#,
        br#"{"action":"add","label":"work","key":"tskey-auth-1234"}"#,
        br#"{"action":"enable","id":2,"enabled":true}"#,
        br#"{"members":[],"next_id":1,"x":[[],{"a":[1,2.5e3,"\u0041\ud83d\ude00",null,true,false]}]}"#,
    ];
    let tokens: [&[u8]; 14] = [b"\"", b"\\", b"\\u", b"\\ud83d", b"{", b"}", b"[", b"]", b",", b":", b"\0", b"\xff", b"1e999", b"nul"];
    let mut buf = vec![0u8; ENCODE_BUFFER];
    for _ in 0..40_000 {
        let mut d = seeds[(next() % 4) as usize].to_vec();
        for _ in 0..(next() % 4) {
            let at = (next() as usize) % (d.len() + 1);
            match next() % 4 {
                0 if at < d.len() => d[at] = next() as u8,
                1 if at < d.len() => {
                    d.remove(at);
                }
                2 => {
                    let t = tokens[(next() % 14) as usize];
                    d.splice(at..at, t.iter().copied());
                }
                _ => d.truncate(at),
            }
        }
        let mut reg = MemberRegistry::new();
        if reg.load(&d).is_ok() {
            check_invariants(&reg);
            assert!(reg.encode(&mut buf).is_ok());
        }
        let _ = parse_request(Origin::Usb, Some(b"application/json"), d.len().min(1024), &d);
    }
}

#[test]
fn nesting_limit_is_1000_containers() {
    let deep = |n: usize| format!("{{\"x\":{}{},\"members\":[],\"next_id\":1}}", "[".repeat(n), "]".repeat(n));
    assert!(MemberRegistry::new().load(deep(999).as_bytes()).is_ok(), "root + 999 = 1000 levels");
    assert!(MemberRegistry::new().load(deep(1000).as_bytes()).is_err());
}
