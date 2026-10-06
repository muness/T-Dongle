//! The flash directory's byte formats: bank validation, record decoding, the alias log and the operation application over arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_peers::directory::{
    OpLog, RecordFile, Op, alias_find, alias_scan, commit, decode_record, encode_record, validate, RECORD_BYTES,
};
use tdongle_tailnet_peers::record::{Action, DirRecord};

#[derive(Default)]
struct Mem(Vec<DirRecord>);
impl RecordFile for Mem {
    type Error = ();
    fn count(&self) -> usize { self.0.len() }
    fn read(&mut self, i: usize) -> Result<DirRecord, ()> { self.0.get(i).cloned().ok_or(()) }
    fn write(&mut self, i: usize, r: &DirRecord) -> Result<(), ()> { *self.0.get_mut(i).ok_or(())? = r.clone(); Ok(()) }
    fn append(&mut self, r: &DirRecord) -> Result<(), ()> { if self.0.len() >= 4096 { return Err(()); } self.0.push(r.clone()); Ok(()) }
}
struct Ops(Vec<Op>);
impl OpLog for Ops {
    type Error = ();
    fn replay(&mut self, f: &mut dyn FnMut(&Op) -> Result<(), ()>) -> Result<(), ()> { self.0.iter().try_for_each(f) }
}

fuzz_target!(|data: &[u8]| {
    let _ = validate(&data);
    alias_scan(&data, |_| {});
    let _ = alias_find(&data, 1, 2, 3);
    let mut ops = Vec::new();
    for chunk in data.chunks_exact(RECORD_BYTES).take(64) {
        let mut b = [0u8; RECORD_BYTES];
        b.copy_from_slice(chunk);
        let r = decode_record(&b);
        // decode is total and stable under re-encoding
        assert_eq!(decode_record(&encode_record(&r)), r);
        let action = [Action::Add, Action::Remove, Action::UpdateEndpoint][usize::from(b[0]) % 3];
        ops.push(Op { group: u32::from(b[1] % 8), action, record: r });
    }
    let mut out = Mem::default();
    let mut prev = Mem::default();
    let _ = commit(&mut out, Some(&mut prev), &mut Ops(ops), data.first().is_some_and(|b| b & 1 == 1));
    assert!(out.0.len() <= 4096);
});
