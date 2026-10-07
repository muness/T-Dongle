//! Property tests and a deterministic mini-fuzz: the writer's chunking invariants, escaping, sink failure, the query/command parsers (no panics, bounds).

use proptest::prelude::*;
use tdongle_tailnet_status::diag::Command;
use tdongle_tailnet_status::glue::{self, MAX_PEER_OFFSET, PeerQuery};
use tdongle_tailnet_status::*;

#[derive(Clone, Debug)]
enum Op {
    Raw(Vec<u8>),
    Str(Vec<u8>),
    Key(Vec<u8>),
    Num(u64),
    Bool(bool),
    Ch(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..400).prop_map(Op::Raw),
        proptest::collection::vec(any::<u8>(), 0..400).prop_map(Op::Str),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Op::Key),
        any::<u64>().prop_map(Op::Num),
        any::<bool>().prop_map(Op::Bool),
        any::<u8>().prop_map(Op::Ch),
    ]
}

/// A model of what the C writes: bytes up to the first NUL for raw/string/key, `%llu`, `true`/`false`, one byte.
fn model(ops: &[Op]) -> Vec<u8> {
    fn cstr(b: &[u8]) -> &[u8] {
        &b[..b.iter().position(|&x| x == 0).unwrap_or(b.len())]
    }
    fn quoted(out: &mut Vec<u8>, s: &[u8]) {
        out.push(b'"');
        for &c in cstr(s) {
            match c {
                b'"' | b'\\' => out.extend_from_slice(&[b'\\', c]),
                0..=31 => out.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
                _ => out.push(c),
            }
        }
        out.push(b'"');
    }
    let mut out = vec![];
    for o in ops {
        match o {
            Op::Raw(b) => out.extend_from_slice(cstr(b)),
            Op::Str(b) => quoted(&mut out, b),
            Op::Key(b) => {
                quoted(&mut out, b);
                out.push(b':');
            }
            Op::Num(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Op::Bool(v) => out.extend_from_slice(if *v { b"true" } else { b"false" }),
            Op::Ch(c) => out.push(*c),
        }
    }
    out
}

fn apply(w: &mut JsonWriter<'_>, o: &Op) {
    match o {
        Op::Raw(b) => drop(w.raw(b)),
        Op::Str(b) => drop(w.string(b)),
        Op::Key(b) => {
            w.string(b);
            w.ch(b':');
        }
        Op::Num(n) => drop(w.number(*n)),
        Op::Bool(v) => drop(w.boolean(*v)),
        Op::Ch(c) => drop(w.ch(*c)),
    }
}

proptest! {
    #[test]
    fn writer_equals_the_model_and_chunks_are_full(ops in proptest::collection::vec(op(), 0..30)) {
        let mut chunks: Vec<Vec<u8>> = vec![];
        let mut sink = |c: &[u8]| { chunks.push(c.to_vec()); true };
        let mut w = JsonWriter::new(&mut sink);
        for o in &ops { apply(&mut w, o); }
        prop_assert!(w.flush());
        prop_assert!(!w.failed());
        let got: Vec<u8> = chunks.concat();
        prop_assert_eq!(&got, &model(&ops));
        for (i, c) in chunks.iter().enumerate() {
            prop_assert!(!c.is_empty() && c.len() <= 256);
            if i + 1 < chunks.len() { prop_assert_eq!(c.len(), 256, "only the last chunk may be short"); }
        }
    }

    #[test]
    fn a_failing_sink_latches_and_is_never_called_again(ops in proptest::collection::vec(op(), 1..30), fail_at in 1usize..6) {
        let mut calls = 0usize;
        let mut sink = |_: &[u8]| { calls += 1; calls != fail_at };
        let mut w = JsonWriter::new(&mut sink);
        for o in &ops { apply(&mut w, o); }
        let ok = w.flush();
        let failed = w.failed();
        prop_assert_eq!(ok, !failed);
        if failed { prop_assert_eq!(calls, fail_at, "no chunk after the failed one"); } else { prop_assert!(calls < fail_at); }
    }

    #[test]
    fn strings_are_valid_json_when_the_input_is_valid_utf8(s in "[^\\x00]{0,300}") {
        let mut out = vec![];
        let mut sink = |c: &[u8]| { out.extend_from_slice(c); true };
        let mut w = JsonWriter::new(&mut sink);
        w.string(s.as_bytes());
        w.flush();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        prop_assert_eq!(v.as_str().unwrap(), s.as_str());
    }

    #[test]
    fn query_parser_never_panics_and_bounds_hold(q in proptest::collection::vec(any::<u8>(), 0..120), has in any::<bool>(), id in any::<u32>()) {
        let r = PeerQuery::parse(if has { Some(&q) } else { None });
        prop_assert!(r.offset <= MAX_PEER_OFFSET);
        let start = r.page_start(id);
        prop_assert!(start == 0 || start == r.offset);
    }

    #[test]
    fn well_formed_queries_parse_as_the_c_does(offset in 0u32..200_000, member in 0u32..1000, swap in any::<bool>()) {
        let q = if swap { format!("peer_member={member}&peer_offset={offset}") } else { format!("peer_offset={offset}&peer_member={member}") };
        let r = PeerQuery::parse(Some(q.as_bytes()));
        prop_assert_eq!(r.member, member);
        prop_assert_eq!(r.offset, if offset > MAX_PEER_OFFSET { 0 } else { offset });
    }

    #[test]
    fn fill_page_never_exceeds_its_bounds(count in 0u32..40, start in 0u32..60, max in 1usize..9, holes in proptest::collection::vec(any::<bool>(), 40)) {
        let mut taken = vec![];
        let (n, next) = glue::fill_page(count, start, max, |i| { let ok = holes[i as usize]; if ok { taken.push(i); } ok });
        prop_assert_eq!(n, taken.len());
        prop_assert!(n <= max);
        prop_assert!(taken.iter().all(|&i| i >= start && i < count));
        prop_assert_eq!(next, taken.last().map_or(start, |l| l + 1));
    }

    #[test]
    fn memory_command_parser_never_panics(line in proptest::collection::vec(any::<u8>(), 0..40)) {
        let _ = Command::parse(&line);
    }

    #[test]
    fn guard_accepts_exactly_0_to_65536(n in 0u64..200_000) {
        let line = format!("memory guard {n}");
        let want = if n <= 65536 { Some(Command::Guard(n as u32)) } else { Some(Command::GuardUsage) };
        prop_assert_eq!(Command::parse(line.as_bytes()), want);
    }
}

#[test]
fn deterministic_mini_fuzz_of_the_whole_status() {
    // 3000 random statuses: nothing panics, output is chunked at 256, and a sink that dies anywhere stops the writer cleanly.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            let len = self.next() as usize % (n + 1);
            (0..len).map(|_| self.next() as u8).collect()
        }
    }
    let mut r = Rng(0x2545_F491_4F6C_DD1D);
    for round in 0..3000u32 {
        let label = r.bytes(23);
        let err = r.bytes(63);
        let url = r.bytes(383);
        let names: Vec<Vec<u8>> = (0..(r.next() % 4)).map(|_| r.bytes(63)).collect();
        let peers: Vec<Peer<'_>> = names.iter().map(|n| Peer { name: n, address: r.next() as u32 }).collect();
        let client = Client {
            vpn_ip: r.next() as u32,
            dns: &err,
            login_url: &url,
            protocol_error: &err,
            derp_state: b"ready",
            peers: &peers,
            diagnostics: [r.next() as u32; 21],
            ..Client::default()
        };
        let members = [
            Member { id: r.next() as u32, label: &label, error: &err, client: Some(client), ..Member::default() },
            Member { id: 2, label: &label, ..Member::default() },
        ];
        let st = Status {
            firmware: &label,
            members: &members[..(r.next() % 3) as usize],
            chip_temperature: Temperature { current_tenths: r.next() as i32, ..Temperature::default() },
            ..Status::default()
        };
        let fail_at = if round % 3 == 0 { (r.next() % 8) as usize + 1 } else { 0 };
        let mut chunks: Vec<usize> = vec![];
        let mut calls = 0usize;
        let mut sink = |c: &[u8]| {
            calls += 1;
            if fail_at != 0 && calls == fail_at {
                return false;
            }
            chunks.push(c.len());
            true
        };
        let ok = write_status(&mut sink, &st);
        assert_eq!(ok, fail_at == 0 || calls < fail_at);
        assert!(chunks.iter().all(|&c| c <= 256));
        if ok {
            assert!(chunks[..chunks.len() - 1].iter().all(|&c| c == 256));
        }
    }
}

#[test]
fn state_sizes_for_the_adr() {
    println!(
        "JsonWriter {} B (staging {} B), Status {} B, Member {} B, Client {} B, HeapLow {} B",
        core::mem::size_of::<JsonWriter<'_>>(),
        jw::CHUNK,
        core::mem::size_of::<Status<'_>>(),
        core::mem::size_of::<Member<'_>>(),
        core::mem::size_of::<Client<'_>>(),
        diag::HeapLow::STATE_BYTES
    );
    assert_eq!(jw::CHUNK, 256);
}
