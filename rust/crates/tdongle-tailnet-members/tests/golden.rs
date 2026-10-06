//! The registry against the real C: tests/golden/{load,save}.golden come from `load_members`/`save_members`/`identify` cut out of gateway_main.c and
//! compiled with the real cJSON (tools/gen_golden.py).

use std::fmt::Write as _;
use tdongle_tailnet_members::{Member, Registry};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return vec![];
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn describe(r: &Registry<128>) -> String {
    let mut s = format!("OK next_id={} n={}", r.next_id(), r.len());
    for m in r.iter() {
        write!(
            s,
            " [{},{},{},{},{},{}]",
            m.id,
            u8::from(m.enabled),
            hex(m.label()),
            hex(m.key()),
            m.namespace().as_str().unwrap(),
            hex(m.hostname().as_bytes())
        )
        .unwrap();
    }
    s
}

#[test]
fn load_matches_the_c_on_the_corpus() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/load.golden")).unwrap();
    let (mut ok, mut rejected) = (0, 0);
    for (n, line) in text.lines().enumerate() {
        let (input, expected) = line.split_once('\t').unwrap();
        let input = unhex(input);
        let mut r = Registry::<128>::new();
        if input.is_empty() {
            // The C harness stores "" as "no such key" (success); an existing empty string is refused (n < 2).
            assert_eq!(r.load(&input), Err(tdongle_tailnet_members::LoadError::Size));
            assert_eq!(r.load_stored(None), Ok(()));
            assert_eq!(expected, "OK next_id=777 n=0");
            continue;
        }
        let got = match r.load(&input) {
            Ok(()) => describe(&r),
            Err(_) => "REJECT".into(),
        };
        assert_eq!(got, expected, "case {n}: {:?}", String::from_utf8_lossy(&input));
        if expected == "REJECT" { rejected += 1 } else { ok += 1 }
    }
    assert!(ok > 100 && rejected > 1500, "the corpus must exercise both outcomes: {ok} / {rejected}");
}

#[test]
fn encode_matches_the_c_on_the_corpus() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/save.golden")).unwrap();
    let mut buf = vec![0u8; 1 << 17];
    let (mut ok, mut refused) = (0, 0);
    for (n, line) in text.lines().enumerate() {
        let (spec, expected) = line.split_once('\t').unwrap();
        let mut f = spec.split(' ');
        let next_id: u32 = f.next().unwrap().parse().unwrap();
        let count: usize = f.next().unwrap().parse().unwrap();
        let mut r = Registry::<128>::new();
        r.set_next_id(next_id);
        for _ in 0..count {
            let id: u32 = f.next().unwrap().parse().unwrap();
            let en = f.next().unwrap() == "1";
            let label = unhex(f.next().unwrap());
            let key = unhex(f.next().unwrap());
            assert!(r.append(Member::restored(id, &label, &key, en)));
        }
        let got = match r.encode(&mut buf) {
            Ok(len) => format!("OK {}", hex(&buf[..len])),
            Err(_) => "FAIL".into(),
        };
        assert_eq!(got, expected, "case {n}");
        if got == "FAIL" { refused += 1 } else { ok += 1 }
    }
    assert!(ok > 300 && refused == 4, "{ok} / {refused}");
}
