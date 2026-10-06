//! The HTTP request reader and the `/command` JSON parser take whatever a client of the open setup network sends. The first byte picks the
//! chunk size, so the same bytes also run through every partial-read pattern; the outcome must not depend on it.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_setup::http::{Reader, Step};

fn run(data: &[u8], chunk: usize) -> (Step, Option<(Vec<u8>, u64)>, Vec<u8>) {
    let mut r = Reader::new(0);
    let mut at = 0;
    let mut step = Step::More;
    while at < data.len() && step == Step::More {
        let end = (at + chunk).min(data.len());
        let (used, s) = r.push(&data[at..end], 0);
        at += used;
        step = s;
    }
    if let Some(q) = r.request() {
        let _ = (q.header("Host", 64), q.header("Origin", 96), q.header("Content-Type", 64), q.header_len("Origin"));
        let _ = tdongle_setup::json::parse(r.body());
    }
    (step, r.request().map(|q| (q.uri.to_vec(), q.content_len)), r.body().to_vec())
}

fuzz_target!(|data: &[u8]| {
    let Some((&c, rest)) = data.split_first() else { return };
    let chunk = usize::from(c % 97) + 1;
    assert_eq!(run(rest, chunk), run(rest, rest.len().max(1)));
});
