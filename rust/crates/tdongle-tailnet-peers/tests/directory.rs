//! Port of tests/test_peer_directory.c over an in-memory flash model: 1000 records, isolation between memberships, an aborted transaction is never
//! visible, delta/rotation/endpoint semantics, reboot validates the banks, a torn newest generation falls back to the previous complete one,
//! authoritative omission removes, a failed write leaves the generation untouched, and the alias log.

use tdongle_tailnet_peers::directory::*;
use tdongle_tailnet_peers::record::{Action, DirRecord, Endpoint};
use tdongle_tailnet_types::FixedStr;

#[derive(Debug, PartialEq, Eq)]
struct IoError;

/// A bank under construction in RAM, with write failure injection.
#[derive(Default)]
struct MemFile {
    recs: Vec<DirRecord>,
    fail_after: Option<u32>,
}
impl MemFile {
    fn tick(&mut self) -> Result<(), IoError> {
        match &mut self.fail_after {
            Some(0) => Err(IoError),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }
}
impl RecordFile for MemFile {
    type Error = IoError;
    fn count(&self) -> usize {
        self.recs.len()
    }
    fn read(&mut self, i: usize) -> Result<DirRecord, IoError> {
        self.recs.get(i).cloned().ok_or(IoError)
    }
    fn write(&mut self, i: usize, r: &DirRecord) -> Result<(), IoError> {
        self.tick()?;
        *self.recs.get_mut(i).ok_or(IoError)? = r.clone();
        Ok(())
    }
    fn append(&mut self, r: &DirRecord) -> Result<(), IoError> {
        self.tick()?;
        self.recs.push(r.clone());
        Ok(())
    }
}
struct Staged(Vec<Op>);
impl OpLog for Staged {
    type Error = IoError;
    fn replay(&mut self, f: &mut dyn FnMut(&Op) -> Result<(), IoError>) -> Result<(), IoError> {
        self.0.iter().try_for_each(f)
    }
}

/// One membership's two banks, as flash files.
struct Store {
    banks: [Vec<u8>; 2],
    current: Option<(u8, BankInfo)>,
    staged: Option<Vec<Op>>,
    session_valid: bool,
    fail_after: Option<u32>,
}

fn image(generation: u32, recs: &[DirRecord]) -> Vec<u8> {
    let mut b = encode_header(generation).to_vec();
    for r in recs {
        b.extend_from_slice(&encode_record(r));
    }
    let crc = image_crc(&b.as_slice(), b.len()).unwrap();
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

impl Store {
    fn new() -> Self {
        Store { banks: [Vec::new(), Vec::new()], current: None, staged: None, session_valid: false, fail_after: None }
    }
    /// `prepare` at boot: validate both banks, choose.
    fn reboot(&mut self) {
        let v = |b: &Vec<u8>| validate(&b.as_slice());
        self.current = select_bank(v(&self.banks[0]), v(&self.banks[1]));
    }
    fn generation(&self) -> u32 {
        self.current.map_or(0, |(_, i)| i.generation)
    }
    fn begin(&mut self) {
        self.staged = Some(Vec::new());
    }
    fn stage(&mut self, group: u32, action: Action, record: DirRecord) {
        self.staged.as_mut().unwrap().push(Op { group, action, record });
    }
    fn abort(&mut self) {
        self.staged = None;
    }
    fn records(&self, bank: u8) -> MemFile {
        let b = &self.banks[usize::from(bank)];
        let n = (b.len() - HEADER_BYTES - TRAILER_BYTES) / RECORD_BYTES;
        MemFile {
            recs: (0..n).map(|i| decode_record(b[HEADER_BYTES + i * RECORD_BYTES..HEADER_BYTES + (i + 1) * RECORD_BYTES].try_into().unwrap())).collect(),
            fail_after: None,
        }
    }
    fn commit(&mut self, authoritative: bool) -> bool {
        let Some(ops) = self.staged.take() else { return false };
        if self.generation() == u32::MAX {
            return false;
        }
        let next = next_bank(self.current.map(|c| c.0));
        let mut out = MemFile { fail_after: self.fail_after, ..MemFile::default() };
        let mut prev = self.current.map(|(b, _)| self.records(b));
        let ok = commit(&mut out, prev.as_mut(), &mut Staged(ops), authoritative).is_ok();
        if !ok {
            return false;
        }
        let generation = self.generation() + 1;
        self.banks[usize::from(next)] = image(generation, &out.recs);
        self.current = Some((next, BankInfo { generation, count: out.recs.len() as u32 }));
        if authoritative {
            self.session_valid = true;
        }
        true
    }
    fn find(&self, ip: u32, node_id: u64, key: Option<&[u8; 32]>) -> Option<DirRecord> {
        let (bank, info) = self.current?;
        let mut f = self.records(bank);
        (0..info.count as usize).find_map(|i| f.read(i).ok().filter(|r| matches(r, ip, node_id, key, None)))
    }
}

fn peer(id: u32) -> DirRecord {
    let mut r = DirRecord { vpn_ip: 0x6440_0000 + id, has_node_id: true, node_id: u64::from(id), endpoint_count: 1, ..DirRecord::default() };
    r.public_key[..4].copy_from_slice(&id.to_le_bytes());
    r.disco_key[0] = id as u8;
    r.endpoints[0] = Endpoint { ip: id, port: 0, is_ipv6: false };
    r.hostname.set(&format!("peer-{id}"));
    r
}

#[test]
fn directory_scenario_of_test_peer_directory_c() {
    let (mut a, mut b) = (Store::new(), Store::new());
    a.begin();
    for i in 1..=1000 {
        a.stage(2, Action::Add, peer(i));
    }
    assert!(a.commit(true));
    assert_eq!(a.current.unwrap().1.count, 1000);
    let out = a.find(0x6440_03e8, 0, None).unwrap();
    assert_eq!(out.node_id, 1000);
    // Identical IP in an independent membership cannot see A's directory.
    assert!(b.find(out.vpn_ip, 0, None).is_none());
    b.begin();
    let mut p = peer(1000);
    p.public_key[0] = 77;
    b.stage(2, Action::Add, p.clone());
    assert!(b.commit(true));
    assert_eq!(b.find(p.vpn_ip, 0, None).unwrap().public_key[0], 77);
    // Incomplete transaction is never visible.
    a.begin();
    let p1001 = peer(1001);
    a.stage(6, Action::Add, p1001.clone());
    a.abort();
    assert!(a.find(p1001.vpn_ip, 0, None).is_none());
    // Removal, rotation, absent endpoints and explicit empty endpoints.
    a.begin();
    let mut rm = peer(10);
    rm.has_node_id = true;
    a.stage(3, Action::Remove, rm);
    let mut upd = peer(1000);
    upd.endpoint_count = -1;
    upd.public_key[0] = 99;
    a.stage(4, Action::UpdateEndpoint, upd.clone());
    assert!(a.commit(false));
    assert!(a.find(0x6440_000a, 0, None).is_none());
    let o = a.find(0, 1000, None).unwrap();
    assert!(o.public_key[0] == 99 && o.endpoint_count == 1, "a rotated key, endpoints preserved when the update carries none");
    a.begin();
    upd.endpoint_count = 0;
    a.stage(4, Action::UpdateEndpoint, upd);
    assert!(a.commit(false));
    assert_eq!(a.find(0, 1000, None).unwrap().endpoint_count, 0);
    // Reboot validates banks rather than trusting RAM.
    a.current = None;
    a.reboot();
    assert_eq!(a.find(0, 1000, None).unwrap().endpoint_count, 0);
    let (generation_before, bank) = (a.generation(), a.current.unwrap().0);
    // Tear the newest generation; recovery selects the previous complete generation.
    let n = a.banks[usize::from(bank)].len();
    a.banks[usize::from(bank)][n - 2] = 123;
    a.reboot();
    assert_eq!(a.generation(), generation_before - 1);
    assert_eq!(a.find(0, 1000, None).unwrap().endpoint_count, 1);
    // Authoritative omission removes all prior records, not merely warm peers.
    a.begin();
    let p2000 = peer(2000);
    a.stage(2, Action::Add, p2000.clone());
    assert!(a.commit(true));
    assert!(a.find(0, 1000, None).is_none());
    assert!(a.find(p2000.vpn_ip, 0, None).is_some());
    // A write that fails mid-commit leaves the generation and the visible records untouched.
    let before = a.generation();
    a.begin();
    let p3000 = peer(3000);
    a.stage(6, Action::Add, p3000.clone());
    a.fail_after = Some(1);
    assert!(!a.commit(false));
    a.fail_after = None;
    assert_eq!(a.generation(), before);
    assert!(a.find(p3000.vpn_ip, 0, None).is_none());
    assert!(a.find(0, 2000, None).is_some());
}

#[test]
fn removed_slots_are_reused_and_three_passes_order_the_operations() {
    let mut s = Store::new();
    s.begin();
    for i in 1..=4 {
        s.stage(2, Action::Add, peer(i));
    }
    assert!(s.commit(true));
    let live = |s: &Store| -> Vec<u64> { s.records(s.current.unwrap().0).recs.iter().filter(|r| r.vpn_ip != 0).map(|r| r.node_id).collect() };
    // One map removes peer 2 and adds peer 9, in that order in the file. Pass order is ADD, REMOVE, UPDATE: the add finds no empty slot yet and
    // appends, then the removal blanks peer 2's slot in place.
    s.begin();
    s.stage(1, Action::Remove, peer(2));
    s.stage(1, Action::Add, peer(9));
    assert!(s.commit(false));
    assert_eq!(s.current.unwrap().1.count, 5);
    assert_eq!(live(&s), [1, 3, 4, 9]);
    assert_eq!(s.records(s.current.unwrap().0).recs[1].vpn_ip, 0, "the removed record is an empty slot");
    // The next partial commit starts from the live records only (the empty slot is not carried over), so the file does not grow for ever.
    s.begin();
    s.stage(1, Action::Add, peer(10));
    assert!(s.commit(false));
    assert_eq!(s.current.unwrap().1.count, 5);
    assert_eq!(live(&s), [1, 3, 4, 9, 10]);
    // An add and a remove of the same peer in one map: the removal runs after the add and wins (the C's pass order).
    s.begin();
    s.stage(1, Action::Remove, peer(3));
    s.stage(1, Action::Add, peer(3));
    assert!(s.commit(false));
    assert!(!live(&s).contains(&3));
    // An update for an unknown peer changes nothing; removing an unknown peer is fine.
    let before = live(&s);
    s.begin();
    s.stage(4, Action::UpdateEndpoint, peer(77));
    s.stage(4, Action::Remove, peer(78));
    assert!(s.commit(false));
    assert_eq!(live(&s), before);
    // Same peer by key when the update carries no node id.
    s.begin();
    let mut by_key = peer(4);
    by_key.has_node_id = false;
    by_key.endpoint_count = 0;
    s.stage(4, Action::UpdateEndpoint, by_key);
    assert!(s.commit(false));
    assert_eq!(s.find(0, 4, None).unwrap().endpoint_count, 0);
}

#[test]
fn record_codec_roundtrip_and_totality() {
    let mut r = peer(7);
    r.endpoint_count = 3;
    r.endpoints[2] = Endpoint { ip: 0x0a00_0001, port: 41641, is_ipv6: true };
    r.is_exit_node = true;
    r.subnet_route_count = 2;
    r.subnet_routes[1] = tdongle_tailnet_peers::record::Route { network: 0xc0a8_0100, prefix_len: 24 };
    r.has_online = true;
    r.online = true;
    r.derp_region = 9;
    r.hostname = FixedStr::new();
    r.hostname.set(&"h".repeat(64));
    assert_eq!(decode_record(&encode_record(&r)), r);
    assert_eq!(RECORD_BYTES, encode_record(&r).len());
    // every byte pattern decodes (counts clamp, a broken hostname is cut)
    let mut seed = 5u64;
    for _ in 0..2000 {
        let mut b = [0u8; RECORD_BYTES];
        for x in &mut b {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *x = (seed >> 56) as u8;
        }
        let d = decode_record(&b);
        assert!((-1..=8).contains(&d.endpoint_count) && d.subnet_route_count <= 8);
        let _ = decode_record(&encode_record(&d));
    }
}

#[test]
fn validation_rejects_every_kind_of_damage() {
    let img = image(5, &[peer(1), peer(2)]);
    assert_eq!(validate(&img.as_slice()), Some(BankInfo { generation: 5, count: 2 }));
    for cut in [0, 3, HEADER_BYTES, img.len() - 1, img.len() - TRAILER_BYTES, img.len() - RECORD_BYTES] {
        assert_eq!(validate(&&img[..cut]), None, "truncated to {cut}");
    }
    for i in [0usize, 5, 9, 13, HEADER_BYTES + 10, img.len() - 1] {
        let mut bad = img.clone();
        bad[i] ^= 1;
        assert_eq!(validate(&bad.as_slice()), None, "flipped byte {i}");
    }
    // The C's version-1 bank (a native struct) is not read: it is rebuilt from the next authoritative map.
    let mut v1 = img.clone();
    v1[4] = 1;
    assert_eq!(validate(&v1.as_slice()), None);
    // bank choice
    let (a, b) = (BankInfo { generation: 3, count: 1 }, BankInfo { generation: 4, count: 1 });
    assert_eq!(select_bank(Some(a), Some(b)).unwrap().0, 1);
    assert_eq!(select_bank(Some(b), Some(a)).unwrap().0, 0);
    assert_eq!(select_bank(Some(a), Some(a)).unwrap().0, 0, "a tie goes to bank 0");
    assert!(select_bank(None, None).is_none());
    assert_eq!((next_bank(None), next_bank(Some(0)), next_bank(Some(1))), (0, 1, 0));
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926, "the standard CRC-32 check value");
}

#[test]
fn alias_log() {
    let mut f: Vec<u8> = Vec::new();
    for i in 1..=1000u32 {
        let off = alias_append_offset(f.len());
        f.truncate(off);
        f.extend_from_slice(&encode_alias(&AliasRecord { id: 1, peer: i, alias: 0xc612_0000 + i }));
    }
    assert_eq!(alias_find(&f.as_slice(), 1, 1000, 0).unwrap().alias, 0xc612_03e8);
    // a torn tail (one byte) is truncated by the next save
    f.push(1);
    assert_eq!(alias_append_offset(f.len()), 16_000);
    let off = alias_append_offset(f.len());
    f.truncate(off);
    f.extend_from_slice(&encode_alias(&AliasRecord { id: 2, peer: 1000, alias: 0xc613_0001 }));
    assert_eq!(alias_find(&f.as_slice(), 0, 0, 0xc613_0001).unwrap().id, 2);
    // the boot-time scan visits every valid record in file order
    let (mut n, mut last, mut ordered) = (0, 0u32, true);
    alias_scan(&f.as_slice(), |a| {
        ordered &= a.alias > last;
        last = a.alias;
        n += 1;
    });
    assert!(n == 1001 && ordered && last == 0xc613_0001);
    // a corrupt entry is skipped, not fatal
    f[16 * 500 + 3] ^= 0xff;
    let mut m = 0;
    assert_eq!(alias_scan(&f.as_slice(), |_| m += 1), 1000);
    assert!(alias_find(&f.as_slice(), 1, 501, 0).is_none());
    // an empty file: nothing visited
    assert_eq!(alias_scan(&[].as_slice(), |_| panic!()), 0);
}
