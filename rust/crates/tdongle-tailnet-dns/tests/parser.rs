//! Property tests and a deterministic mini-fuzz of the DNS wire parser and the whole responder: any bytes, no panic, bounded work, and the
//! invariants of whatever comes out.
#![allow(clippy::type_complexity, clippy::single_match, clippy::manual_range_contains)]
use proptest::prelude::*;
use tdongle_tailnet_dns::wire::{self, NAME_MAX, ParseError};
use tdongle_tailnet_dns::*;

fn msg_with_name(name: &[u8]) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(name);
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn parse_question_never_panics_and_is_in_bounds(data in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut name = [0u8; NAME_MAX];
        if let Ok(q) = wire::parse_question(&data, &mut name) {
            prop_assert!(q.end <= data.len() && q.name_len < NAME_MAX && q.end >= wire::HEADER + 5);
            // the question parsed is exactly what is on the wire
            let mut text = Vec::new();
            let mut pos = wire::HEADER;
            while data[pos] != 0 {
                if !text.is_empty() { text.push(b'.'); }
                let l = data[pos] as usize;
                text.extend_from_slice(&data[pos + 1..pos + 1 + l]);
                pos += 1 + l;
            }
            prop_assert_eq!(&name[..q.name_len], &text[..]);
        }
        let _ = wire::question_hash(&data);
    }

    /// `read_name` is loop-proof: whatever the pointers say it terminates, and a success is in bounds with a monotonic walk.
    #[test]
    fn read_name_terminates_on_any_pointer_graph(data in proptest::collection::vec(any::<u8>(), 0..300), start in 0usize..320) {
        let mut out = [0u8; 300];
        match wire::read_name(&data, start, &mut out) {
            Ok((len, next)) => prop_assert!(len < NAME_MAX && next <= data.len() && next > start),
            Err(_) => {}
        }
    }

    /// Dense pointer soup: every byte pair a pointer.
    #[test]
    fn pointer_soup(data in proptest::collection::vec(0xc0u8..=0xff, 2..200), start in 0usize..200) {
        let mut out = [0u8; 300];
        let _ = wire::read_name(&data, start, &mut out);
    }

    /// The full responder on arbitrary datagrams from the USB net: no panic, replies fit and keep the question.
    #[test]
    fn responder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..600), upstream in proptest::option::of(any::<u32>())) {
        let mut r = Responder::new();
        let mut out = [0u8; 1500];
        let a = r.handle_query(&data, Client { addr: 0xc0a8_4d02, port: 5 }, 10, &NoDirectory, upstream, &mut out);
        match a {
            Action::Answer { len } => prop_assert!(len >= wire::HEADER && len <= out.len() && out[2] & 0x80 != 0),
            Action::Forward { len, .. } => {
                prop_assert_eq!(len, data.len());
                prop_assert_eq!(&out[2..len], &data[2..]);
            }
            Action::Drop(_) => {}
        }
        let mut resp = data.clone();
        let _ = r.handle_upstream(&mut resp);
    }
}

#[test]
fn pointer_loops_and_forward_references_are_errors() {
    let mut out = [0u8; 300];
    // self pointer at 12
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[0xc0, 12]);
    assert_eq!(wire::read_name(&m, 12, &mut out), Err(ParseError::BadPointer));
    // pointer forward
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[0xc0, 20, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c', 0]);
    assert_eq!(wire::read_name(&m, 12, &mut out), Err(ParseError::BadPointer));
    // two pointers pointing at each other cannot both be backwards
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[0xc0, 14, 0xc0, 12]);
    assert_eq!(wire::read_name(&m, 12, &mut out), Err(ParseError::BadPointer));
    // a legal backwards pointer to a name
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[3, b'w', b'w', b'w', 0]); // at 12
    m.extend_from_slice(&[3, b'f', b'o', b'o', 0xc0, 12]); // at 17: foo.www
    let (l, next) = wire::read_name(&m, 17, &mut out).unwrap();
    assert_eq!((&out[..l], next), (&b"foo.www"[..], m.len()));
    // a chain of backwards pointers (each two bytes) is bounded and fine
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[1, b'a', 0]);
    for i in 0..100u16 {
        let target = if i == 0 { 12 } else { 15 + 2 * (i - 1) };
        m.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
    }
    let (l, _) = wire::read_name(&m, m.len() - 2, &mut out).unwrap();
    assert_eq!(&out[..l], b"a");
    // reserved label types
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[0x40, 0]);
    assert_eq!(wire::read_name(&m, 12, &mut out), Err(ParseError::BadLabel));
    // truncated
    assert_eq!(wire::read_name(&[], 0, &mut out), Err(ParseError::Truncated));
    assert_eq!(wire::read_name(&[5, b'a'], 0, &mut out), Err(ParseError::Truncated));
    assert_eq!(wire::read_name(&[0xc0], 0, &mut out), Err(ParseError::Truncated));
}

#[test]
fn name_length_limits() {
    let mut out = [0u8; NAME_MAX];
    // allowed boundary is len + size + 1 < 256
    let mut name = Vec::new();
    for _ in 0..3 {
        name.push(63);
        name.extend(std::iter::repeat_n(b'a', 63));
    }
    name.push(61);
    name.extend(std::iter::repeat_n(b'b', 61)); // 63*3 + 61 + 3 dots = 253
    assert_eq!(wire::parse_question(&msg_with_name(&name), &mut out).map(|q| q.name_len), Ok(253));
    let mut name2 = name.clone();
    name2.push(1);
    name2.push(b'c'); // 253 + dot + 1 = 255 text bytes: the longest the C accepts
    assert!(wire::parse_question(&msg_with_name(&name2), &mut out).is_ok());
    name2.push(2);
    name2.extend_from_slice(b"dd"); // 258: too long
    assert_eq!(wire::parse_question(&msg_with_name(&name2), &mut out), Err(ParseError::TooLong));
    // question hash: invalid forms are 0, valid ones never 0
    assert_eq!(wire::question_hash(&msg_with_name(&[0xc0, 12])), 0);
    assert_ne!(wire::question_hash(&msg_with_name(&[3, b'a', b'b', b'c'])), 0);
    // different type -> different hash
    let mut a = msg_with_name(&[3, b'a', b'b', b'c']);
    let h1 = wire::question_hash(&a);
    let l = a.len();
    a[l - 3] = 28;
    assert_ne!(h1, wire::question_hash(&a));
}

/// A deterministic mini-fuzz that runs in plain `cargo test`: mutated real queries against a populated directory.
#[test]
fn mini_fuzz_responder_with_directory() {
    struct D;
    impl Directory for D {
        fn member_count(&self) -> usize {
            1
        }
        fn member(&self, _: usize) -> Option<MemberView<'_>> {
            Some(MemberView { id: 1, label: "work", self_dns_name: "gw.example.ts.net.", connected: true, session_valid: true, generation: 1, peer_count: 2 })
        }
        fn peer(&self, _: usize, j: usize) -> Option<PeerView<'_>> {
            Some(PeerView { hostname: if j == 0 { "server.example.ts.net" } else { "alpha" }, vpn_ip: 0x6440_0001 + j as u32 })
        }
        fn generation(&self, _: usize) -> u32 {
            1
        }
        fn alias(&self, _: u32, p: u32) -> Option<u32> {
            Some(0xc612_0000 + (p & 0xff))
        }
    }
    let mut s = 0x1234_5678_9abc_def0u64;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        (s >> 11) as u32
    };
    let seeds: [&[u8]; 4] =
        [b"\x06server\x07example\x02ts\x03net", b"\x05alpha\x07example\x02ts\x03net", b"\x06server\x04work\x07tailnet", b"\x07example\x03com"];
    let mut r = Responder::new();
    let mut answers = 0;
    for i in 0..100_000u32 {
        let mut q = msg_with_name(seeds[rnd() as usize % 4]);
        for _ in 0..rnd() % 4 {
            let k = rnd() as usize % q.len();
            q[k] = rnd() as u8;
        }
        if rnd() % 5 == 0 {
            q.truncate(rnd() as usize % (q.len() + 1));
        }
        if rnd() % 7 == 0 {
            q.extend((0..rnd() % 200).map(|_| rnd() as u8));
        }
        let mut out = [0u8; 1500];
        match r.handle_query(&q, Client { addr: 0xc0a8_4d02, port: 9 }, u64::from(i), &D, Some(1), &mut out) {
            Action::Answer { len } => {
                assert!(len <= 1500 && len >= 12);
                answers += 1;
            }
            Action::Forward { slot, len, .. } => {
                assert_eq!(len, q.len());
                if i % 2 == 0 {
                    r.forward_failed(slot);
                }
            }
            Action::Drop(_) => {}
        }
        r.expire(u64::from(i) + 5000);
    }
    assert!(answers > 1000);
}
