#![no_main]
//! tdongle-tailnet-status: the /status query-string reader and the diagnostics command parser over arbitrary bytes, and the JSON writer over arbitrary strings.
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_status::diag::Command;
use tdongle_tailnet_status::glue::{MAX_PEER_OFFSET, PeerQuery};
use tdongle_tailnet_status::{JsonWriter, Member, Status, write_status};

fuzz_target!(|data: &[u8]| {
    let q = PeerQuery::parse(Some(data));
    assert!(q.offset <= MAX_PEER_OFFSET);
    let _ = PeerQuery::parse(None);
    let _ = Command::parse(data);
    let half = data.len() / 2;
    let (a, b) = data.split_at(half);
    let members = [Member { id: 1, label: a, error: b, ..Member::default() }];
    let st = Status { firmware: a, members: &members, ..Status::default() };
    let mut total = 0usize;
    let mut sink = |c: &[u8]| {
        assert!(c.len() <= 256);
        total += c.len();
        true
    };
    assert!(write_status(&mut sink, &st));
    let mut sink2 = |_: &[u8]| false;
    let mut w = JsonWriter::new(&mut sink2);
    w.string(data);
    w.flush();
});
