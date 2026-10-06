//! Property tests and a deterministic mini-fuzz: arbitrary chunk splits must never change what the frame reader, the HTTP/2 session, the HPACK decoder
//! and the map framer say, and arbitrary or mutated bytes must never panic or break a bound.

use proptest::prelude::*;
use tdongle_tailnet_control::early::EarlyReader;
use tdongle_tailnet_control::h2::{Config, Event, FrameError, FrameEvent, FrameHeader, FrameReader, OUT_CAP, Session, flag, kind};
use tdongle_tailnet_control::hpack::HpackDecoder;
use tdongle_tailnet_control::http::{UpgradeReader, parse_host_port, parse_key_response};
use tdongle_tailnet_control::json;
use tdongle_tailnet_control::map::{MapEvent, MapFramer};
use tdongle_tailnet_control::requests::parse_register_response;
use tdongle_tailnet_types::Entropy;
use tdongle_tailnet_types::test_util::TestRng;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = FrameHeader { length: payload.len() as u32, kind, flags, stream }.encode().to_vec();
    v.extend_from_slice(payload);
    v
}

/// A frame the way a peer might send it: valid padding most of the time, raw junk sometimes.
fn arb_frame() -> impl Strategy<Value = Vec<u8>> {
    let kinds = prop_oneof![
        Just(kind::DATA),
        Just(kind::HEADERS),
        Just(kind::PRIORITY),
        Just(kind::RST_STREAM),
        Just(kind::SETTINGS),
        Just(kind::PING),
        Just(kind::GOAWAY),
        Just(kind::WINDOW_UPDATE),
        Just(kind::CONTINUATION),
        Just(0xee_u8)
    ];
    (kinds, any::<u8>(), 0u32..8, proptest::collection::vec(any::<u8>(), 0..40), 0u8..6, any::<bool>()).prop_map(
        |(k, flags, stream, payload, pad, wellformed)| {
            let mut flags = flags;
            let mut p = payload;
            if wellformed && matches!(k, kind::DATA | kind::HEADERS) && flags & flag::PADDED != 0 {
                let mut q = vec![pad];
                if k == kind::HEADERS && flags & flag::PRIORITY != 0 {
                    q.extend([0, 0, 0, 0, 7]);
                }
                q.extend_from_slice(&p);
                q.extend(std::iter::repeat_n(0, pad as usize));
                p = q;
            } else if wellformed {
                flags &= !(flag::PADDED | flag::PRIORITY);
            }
            frame(k, flags, stream, &p)
        },
    )
}

fn splits(len: usize, cuts: &[usize]) -> Vec<usize> {
    let mut c: Vec<usize> = cuts.iter().map(|x| x % (len + 1)).collect();
    c.sort_unstable();
    c.dedup();
    c
}

fn chunks_at<'a>(data: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    let mut out = vec![];
    let mut last = 0;
    for c in splits(data.len(), cuts) {
        out.push(&data[last..c]);
        last = c;
    }
    out.push(&data[last..]);
    out
}

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    H(FrameHeader),
    P(Vec<u8>),
    E(FrameHeader, Vec<u8>),
    Err(FrameError),
}

fn reader_trace(chunks: &[&[u8]]) -> Vec<Tok> {
    let mut r = FrameReader::new(1000);
    let mut out: Vec<Tok> = vec![];
    for chunk in chunks {
        let mut rest = *chunk;
        loop {
            match r.push(rest) {
                Err(e) => {
                    out.push(Tok::Err(e));
                    return out;
                }
                Ok((n, ev)) => {
                    assert!(n <= rest.len());
                    rest = &rest[n..];
                    match ev {
                        Some(FrameEvent::Header(h)) => out.push(Tok::H(h)),
                        Some(FrameEvent::Payload(b)) => {
                            assert!(!b.is_empty());
                            if let Some(Tok::P(v)) = out.last_mut() {
                                v.extend_from_slice(b);
                            } else {
                                out.push(Tok::P(b.to_vec()));
                            }
                        }
                        Some(FrameEvent::End(h)) => out.push(Tok::E(h, r.special().to_vec())),
                        None if n == 0 => break,
                        None => {}
                    }
                }
            }
        }
    }
    out
}

fn session_trace(chunks: &[&[u8]]) -> (Vec<String>, Vec<u8>) {
    let mut s = Session::new(Config::default());
    let mut sent = vec![];
    let mut tmp = [0u8; 40];
    let mut events = vec![];
    let mut data: Vec<(u32, Vec<u8>)> = vec![];
    let mut drain = |s: &mut Session, sent: &mut Vec<u8>| {
        loop {
            let n = s.poll_output(&mut tmp);
            if n == 0 {
                break;
            }
            sent.extend_from_slice(&tmp[..n]);
        }
    };
    drain(&mut s, &mut sent);
    for chunk in chunks {
        let mut rest = *chunk;
        loop {
            let (n, ev) = s.on_input(rest);
            assert!(n <= rest.len());
            rest = &rest[n..];
            assert!(s.pending_output() <= OUT_CAP);
            drain(&mut s, &mut sent);
            match ev {
                Event::Idle | Event::Closed => break,
                Event::Blocked => {}
                Event::Data { stream, bytes } => {
                    assert!(!bytes.is_empty());
                    match data.last_mut() {
                        Some((st, v)) if *st == stream && matches!(events.last().map(String::as_str), Some("D")) => v.extend_from_slice(bytes),
                        _ => {
                            events.push("D".into());
                            data.push((stream, bytes.to_vec()));
                        }
                    }
                }
                e => events.push(format!("{e:?}")),
            }
        }
    }
    events.push(format!("{data:?}"));
    (events, sent)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    #[test]
    fn frame_reader_is_split_invariant(frames in proptest::collection::vec(arb_frame(), 0..8), cuts in proptest::collection::vec(any::<usize>(), 0..12)) {
        let all: Vec<u8> = frames.concat();
        let whole = reader_trace(&[&all]);
        let cut = reader_trace(&chunks_at(&all, &cuts));
        prop_assert_eq!(&whole, &cut);
        let ones: Vec<&[u8]> = all.chunks(1).collect();
        prop_assert_eq!(&whole, &reader_trace(&ones));
    }

    #[test]
    fn session_is_split_invariant(frames in proptest::collection::vec(arb_frame(), 0..8), cuts in proptest::collection::vec(any::<usize>(), 0..12)) {
        let all: Vec<u8> = frames.concat();
        let whole = session_trace(&[&all]);
        let cut = session_trace(&chunks_at(&all, &cuts));
        prop_assert_eq!(&whole, &cut);
    }

    #[test]
    fn data_payload_arrives_intact_in_any_split(payload in proptest::collection::vec(any::<u8>(), 0..2000), pad in 0u8..20, cuts in proptest::collection::vec(any::<usize>(), 0..10)) {
        let mut p = vec![pad];
        p.extend_from_slice(&payload);
        p.extend(std::iter::repeat_n(0xaa, pad as usize));
        let all = frame(kind::DATA, flag::PADDED | flag::END_STREAM, 3, &p);
        let mut s = Session::new(Config::default());
        let mut tmp = [0u8; 200];
        while s.poll_output(&mut tmp) > 0 {}
        let mut got = vec![];
        let mut ended = false;
        for chunk in chunks_at(&all, &cuts) {
            let mut rest = chunk;
            loop {
                let (n, ev) = s.on_input(rest);
                rest = &rest[n..];
                while s.poll_output(&mut tmp) > 0 {}
                match ev {
                    Event::Data { stream, bytes } => { prop_assert_eq!(stream, 3); got.extend_from_slice(bytes); }
                    Event::StreamEnd { stream } => { prop_assert_eq!(stream, 3); ended = true; }
                    Event::Idle => break,
                    e => prop_assert!(false, "{:?}", e),
                }
            }
        }
        prop_assert_eq!(got, payload);
        prop_assert!(ended);
    }

    #[test]
    fn map_framer_reassembles(msgs in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..300), 1..5), cuts in proptest::collection::vec(any::<usize>(), 0..16)) {
        let mut all = vec![];
        for m in &msgs {
            all.extend((m.len() as u32).to_le_bytes());
            all.extend_from_slice(m);
        }
        let mut f = MapFramer::new(1 << 20);
        let mut got: Vec<Vec<u8>> = vec![];
        for chunk in chunks_at(&all, &cuts) {
            let mut rest = chunk;
            loop {
                let (n, ev) = f.push(rest).unwrap();
                rest = &rest[n..];
                match ev {
                    Some(MapEvent::Start { len }) => { prop_assert!(len > 0); got.push(vec![]); }
                    Some(MapEvent::Json(j)) => got.last_mut().unwrap().extend_from_slice(j),
                    Some(MapEvent::End) => {}
                    None if n == 0 => break,
                    None => {}
                }
            }
        }
        prop_assert_eq!(got, msgs);
        prop_assert!(f.at_boundary());
    }

    #[test]
    fn hpack_counts_every_field(fields in proptest::collection::vec((0u8..4, 1u32..62, proptest::collection::vec(any::<u8>(), 0..200), any::<bool>()), 0..10), updates in 0usize..3) {
        let mut block = vec![];
        for _ in 0..updates {
            block.push(0x20 | 5);
        }
        for (form, idx, bytes, huff) in &fields {
            let h = if *huff { 0x80 } else { 0 };
            match form {
                0 => block.push(0x80 | *idx as u8),
                1 => { block.push(0x40 | *idx as u8); block.extend(str_lit(h, bytes)); }
                2 => { block.push(0x00); block.extend(str_lit(h, b"name")); block.extend(str_lit(h, bytes)); }
                _ => { block.push(0x10 | (*idx as u8 % 14 + 1)); block.extend(str_lit(h, bytes)); }
            }
        }
        let mut d = HpackDecoder::new(4096, 1 << 20);
        d.start_block();
        for &b in &block { d.feed(b).unwrap(); }
        let s = d.end_block().unwrap();
        prop_assert_eq!(s.fields as usize, fields.len());
    }

    #[test]
    fn json_string_roundtrip(s in "\\PC{0,60}") {
        let mut buf = [0u8; 512];
        let mut w = json::JsonWriter::new(&mut buf);
        w.begin_object();
        w.field_str("k", &s);
        w.end_object();
        let n = w.finish().unwrap();
        let mut v = [None; 1];
        json::scan_top(&buf[..n], 2, false, &["k"], &mut v).unwrap();
        let Some(json::Value::Str(raw)) = v[0] else { panic!() };
        let mut out = [0u8; 512];
        let m = json::unescape(raw, &mut out).unwrap();
        prop_assert_eq!(std::str::from_utf8(&out[..m]).unwrap(), s.as_str());
    }
}

fn str_lit(h: u8, bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![];
    let n = bytes.len();
    if n < 127 {
        v.push(h | n as u8);
    } else {
        v.push(h | 127);
        v.push((n - 127) as u8); // n < 327, so one continuation byte
    }
    v.extend_from_slice(bytes);
    v
}

fn bytes(rng: &mut TestRng, max: usize) -> Vec<u8> {
    let mut l = [0u8; 2];
    rng.fill(&mut l);
    let n = u16::from_le_bytes(l) as usize % (max + 1);
    let mut v = vec![0; n];
    rng.fill(&mut v);
    v
}

fn mutate(rng: &mut TestRng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    let mut r = [0u8; 4];
    rng.fill(&mut r);
    for _ in 0..1 + r[0] % 6 {
        if v.is_empty() {
            break;
        }
        let mut p = [0u8; 3];
        rng.fill(&mut p);
        let i = (p[0] as usize | (p[1] as usize) << 8) % v.len();
        match p[2] % 4 {
            0 => v[i] ^= 1 << (p[2] >> 2 & 7),
            1 => v[i] = p[2],
            2 => {
                v.remove(i);
            }
            _ => v.insert(i, p[2]),
        }
    }
    v
}

#[test]
fn mini_fuzz_everything_parses_without_panicking() {
    let mut rng = TestRng(0x7a11_0c0d_e5ee_d001);
    // Seeds: a plausible server stream, a /key answer, an upgrade answer, an early payload, a register response, a map stream.
    let mut server = vec![];
    server.extend(frame(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100, 0, 4, 0, 1, 0, 0]));
    server.extend(frame(kind::SETTINGS, flag::ACK, 0, &[]));
    server.extend(frame(
        kind::HEADERS,
        flag::END_HEADERS,
        1,
        &[0x88, 0x5f, 0x10, b'a', b'p', b'p', b'l', b'i', b'c', b'a', b't', b'i', b'o', b'n', b'/', b'j', b's', b'o', b'n'],
    ));
    server.extend(frame(kind::DATA, flag::PADDED, 1, &[2, b'{', b'}', 0, 0]));
    server.extend(frame(kind::PING, 0, 0, &[1; 8]));
    server.extend(frame(kind::WINDOW_UPDATE, 0, 0, &[0, 0, 1, 0]));
    server.extend(frame(kind::DATA, flag::END_STREAM, 1, b""));
    server.extend(frame(kind::GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 1, b'o', b'k']));
    let key = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"legacyPublicKey\":\"mkey:00\",\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b\"}".to_vec();
    let up = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n\x02\x00\x30".to_vec();
    let mut early = vec![255, 255, 255, b'T', b'S', 0, 0, 0, 20];
    early.extend_from_slice(b"{\"nodeKeyChallenge\":");
    let reg = br#"{"User":{"ID":1,"Logins":[{"ID":2}]},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"https:\/\/x&y","Error":""}"#.to_vec();
    let mut tmp = [0u8; 64];
    for round in 0..30_000u32 {
        let pick = |rng: &mut TestRng, base: &[u8]| if round % 3 == 0 { bytes(rng, 300) } else { mutate(rng, base) };
        // HTTP/2 session, random chunking.
        let input = pick(&mut rng, &server);
        let mut sel = [0u8; 1];
        rng.fill(&mut sel);
        let mut s = Session::new(Config::default());
        let mut was_dead = false;
        for chunk in input.chunks(1 + sel[0] as usize % 40) {
            let mut rest = chunk;
            loop {
                let (n, ev) = s.on_input(rest);
                assert!(n <= rest.len());
                rest = &rest[n..];
                assert!(s.pending_output() <= OUT_CAP);
                while s.poll_output(&mut tmp) > 0 {}
                if was_dead {
                    assert!(matches!(ev, Event::Closed));
                }
                was_dead |= s.is_dead();
                if matches!(ev, Event::Idle | Event::Closed) {
                    break;
                }
            }
        }
        // The rest.
        let k = pick(&mut rng, &key);
        let _ = parse_key_response(&k);
        let mut u = UpgradeReader::new();
        for c in pick(&mut rng, &up).chunks(1 + sel[0] as usize % 9) {
            let _ = u.push(c);
        }
        let mut jbuf = [0u8; 1024];
        let mut e = EarlyReader::new(&mut jbuf);
        for c in pick(&mut rng, &early).chunks(1 + sel[0] as usize % 11) {
            if e.push(c).is_err() {
                break;
            }
        }
        let r = pick(&mut rng, &reg);
        let _ = parse_register_response(&r);
        let mut v = [None; 2];
        let _ = json::scan_top(&r, 16, true, &["Error", "AuthURL"], &mut v);
        let mut d = HpackDecoder::new(4096, 4096);
        d.start_block();
        for &b in &r {
            if d.feed(b).is_err() {
                break;
            }
        }
        let _ = d.end_block();
        let mut f = MapFramer::new(1 << 20);
        let mut rest = &r[..];
        while let Ok((n, ev)) = f.push(rest) {
            rest = &rest[n..];
            if ev.is_none() && n == 0 {
                break;
            }
        }
        if let Ok(t) = std::str::from_utf8(&r) {
            let _ = parse_host_port(t);
        }
    }
}
