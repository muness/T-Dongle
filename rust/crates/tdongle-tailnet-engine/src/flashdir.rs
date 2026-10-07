//! The peer directory in flash (ADR 0012, `ml_directory.c`): the live records of every membership sit in a raw flash partition, not on the heap.
//!
//! What stays in RAM is a *view* of the live records (address, position and hostname: about 20 bytes a peer, for the DNS forwarder and the status page) and the
//! indices a commit builds while it runs (about 100 bytes a peer, returned when it ends). The 288-byte records, the bank a commit builds beside the live
//! one and the staged updates are all in flash, so the directory no longer has the 24-peer limit of [`crate::dir::RamDirectory`]: it holds `N` peers a membership
//! (the partition's size decides) and costs the heap what the tailnet's names weigh.
//!
//! # Layout (per membership, all sectors of [`SECTOR`] bytes)
//!
//! `bank 0 | bank 1 | tx`. A bank is `header (16, the crate-wide codec) | count (4) | count records of 242 | crc32 (4)`; the trailer is the last thing written, so a bank
//! torn by power loss is invalid and the other bank (the previous generation) stays in force; boot picks the valid bank with the higher generation. The count word is
//! outside the checksummed image (the checksum is the codec's, over header and records); a wrong count moves the trailer and fails the check. The `tx` area is the
//! staged operation log: one 256-byte slot per update (`action, group, record`), erased a sector (16 slots) at a time as staging reaches it; a commit replays it
//! three times (adds, removes, endpoint updates) like the C.
//!
//! # Commit
//!
//! The next generation is described in RAM by an index of what each slot holds (its identity and where its record is: the old bank, a staged slot, or a patched
//! copy), the three passes run over the index, and only then is the next bank written in one sequential pass (erase, header, records, trailer). The rules are
//! those of [`tdongle_tailnet_peers::directory::commit`] and `apply`, and a test checks the two give the same directory on random update streams.
//!
//! Flash operations block (a sector erase is about 45 ms with interrupts masked, one call at a time), so commits belong to the tasks that already write flash.

extern crate alloc;

use crate::dir::{DirError, PeerDirectory, PeerInfo, action_of, to_dir_record};
use alloc::vec::Vec;
use core::cell::RefCell;
use tdongle_tailnet_map::directory::is_storable;
use tdongle_tailnet_map::types::{PeerAction, PeerRecord};
use tdongle_tailnet_peers::directory::{self as dirfmt, HEADER_BYTES, ReadAt, RECORD_BYTES, TRAILER_BYTES};
use tdongle_tailnet_peers::record::{Action, DirRecord, PubKey};

/// Flash sector, the erase unit.
pub const SECTOR: usize = 4096;
/// One staged operation: action (1), group (4), padding (3), record (242), padding (6).
pub const SLOT_BYTES: usize = 256;
/// The bank's count word, between the header and the records.
const COUNT_BYTES: usize = 4;
/// Records a commit keeps patched in RAM at most (an endpoint update needs its record whole); more fail the map like any directory failure.
const PATCHED_MAX: usize = 64;

/// The flash partition behind a directory (offsets are relative to its start). Writes only ever go to erased bytes.
pub trait DirFlash {
    /// Fill `buf` from `offset`; false on an error.
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> bool;
    /// Erase sector number `sector` (`SECTOR` bytes at `sector * SECTOR`).
    fn erase_sector(&mut self, sector: usize) -> bool;
    /// Program `data` at `offset` (any alignment; the bytes are erased).
    fn write(&mut self, offset: usize, data: &[u8]) -> bool;
    /// Bytes of the partition.
    fn size(&self) -> usize;
}

/// Sectors of one bank holding `n` records.
pub const fn bank_sectors(n: usize) -> usize {
    (HEADER_BYTES + COUNT_BYTES + n * RECORD_BYTES + TRAILER_BYTES).div_ceil(SECTOR)
}
/// Sectors of the staging log for `n` updates.
pub const fn tx_sectors(n: usize) -> usize {
    (n * SLOT_BYTES).div_ceil(SECTOR)
}
/// Sectors of one membership (two banks and the log).
pub const fn member_sectors(n: usize) -> usize {
    2 * bank_sectors(n) + tx_sectors(n)
}
/// Bytes of partition `m` memberships of `n` peers need.
pub const fn partition_bytes(m: usize, n: usize) -> usize {
    m * member_sectors(n) * SECTOR
}

#[derive(Clone, Copy, Debug)]
struct View {
    ip: u32,
    pos: u16,
    off: u16,
    len: u8,
    /// What the status page shows of the record, so it needs no flash read.
    key: [u8; 4],
    derp: u16,
    endpoints: u8,
    routes: u8,
    /// 0 = unknown, 1 = offline, 2 = online.
    online: u8,
}

/// One membership's state.
struct Slot {
    bank: Option<u8>,
    /// Records in the live bank, empties included.
    slots: u32,
    generation: u32,
    view: Vec<View>,
    names: Vec<u8>,
    staged: u32,
    overflow: u32,
    stage_dropped: u32,
}

impl Slot {
    const fn new() -> Self {
        Self { bank: None, slots: 0, generation: 0, view: Vec::new(), names: Vec::new(), staged: 0, overflow: 0, stage_dropped: 0 }
    }
    fn name(&self, v: &View) -> &str {
        let s = &self.names[v.off as usize..v.off as usize + v.len as usize];
        core::str::from_utf8(s).unwrap_or("")
    }
    fn add_view(&mut self, pos: usize, r: &DirRecord) {
        let name = r.hostname.as_str().as_bytes();
        let name = &name[..name.len().min(255)];
        if self.view.try_reserve(1).is_err() || self.names.try_reserve(name.len()).is_err() || self.names.len() + name.len() > u16::MAX as usize {
            return; // the peer stays in flash and is found there; only its name is missing from DNS
        }
        self.view.push(View {
            ip: r.vpn_ip,
            pos: pos as u16,
            off: self.names.len() as u16,
            len: name.len() as u8,
            key: [r.public_key[0], r.public_key[1], r.public_key[2], r.public_key[3]],
            derp: r.derp_region,
            endpoints: r.endpoint_count.max(0) as u8,
            routes: r.subnet_route_count,
            online: if r.has_online { 1 + u8::from(r.online) } else { 0 },
        });
        self.names.extend_from_slice(name);
    }
}

/// Where the record of a slot of the bank being built comes from.
#[derive(Clone, Copy)]
enum Src {
    Empty,
    Prev(u16),
    Tx(u16),
    Ram(u16),
}

struct Ent {
    ip: u32,
    has_id: bool,
    id: u64,
    key: [u8; 32],
    src: Src,
}

impl Ent {
    fn of(r: &DirRecord, src: Src) -> Self {
        Self { ip: r.vpn_ip, has_id: r.has_node_id, id: r.node_id, key: r.public_key, src }
    }
    /// `directory::same(self, u)`.
    fn same(&self, u: &DirRecord) -> bool {
        (self.has_id && u.has_node_id && self.id == u.node_id) || (!u.has_node_id && self.key == u.public_key)
    }
}

/// The ReadAt of a bank image for the codec's `validate`: the count word is skipped, and the length is the one the count implies.
struct Window<'a, F: DirFlash> {
    f: RefCell<&'a mut F>,
    base: usize,
    len: usize,
}

impl<F: DirFlash> ReadAt for Window<'_, F> {
    fn len(&self) -> usize {
        self.len
    }
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> bool {
        let mut f = self.f.borrow_mut();
        let end = offset + buf.len();
        if end > self.len {
            return false;
        }
        if end <= HEADER_BYTES {
            f.read(self.base + offset, buf)
        } else if offset >= HEADER_BYTES {
            f.read(self.base + COUNT_BYTES + offset, buf)
        } else {
            let (a, b) = buf.split_at_mut(HEADER_BYTES - offset);
            f.read(self.base + offset, a) && f.read(self.base + HEADER_BYTES + COUNT_BYTES, b)
        }
    }
}

/// The peer directory of `M` memberships of up to `N` peers each, in flash.
pub struct FlashDirectory<F: DirFlash, const M: usize, const N: usize> {
    f: F,
    m: [Slot; M],
}

impl<F: DirFlash, const M: usize, const N: usize> FlashDirectory<F, M, N> {
    const _CHECK: () = assert!(N > 0 && N <= 4000, "positions are 16 bits and the names arena is 64 KB");
    /// An empty directory over `f` (nothing is read until [`FlashDirectory::mount`]).
    pub const fn new(f: F) -> Self {
        let () = Self::_CHECK;
        Self { f, m: [const { Slot::new() }; M] }
    }
    /// Bytes of the partition this directory needs.
    pub const PARTITION_BYTES: usize = partition_bytes(M, N);

    fn bank_off(m: usize, b: u8) -> usize {
        (m * member_sectors(N) + b as usize * bank_sectors(N)) * SECTOR
    }
    fn tx_off(m: usize) -> usize {
        (m * member_sectors(N) + 2 * bank_sectors(N)) * SECTOR
    }

    /// Read both banks of every membership, take the valid one with the higher generation, and rebuild the views. Run once at start. Returns the live peers found.
    pub fn mount(&mut self) -> usize {
        if self.f.size() < Self::PARTITION_BYTES {
            return 0;
        }
        let mut total = 0;
        for m in 0..M {
            self.mount_member(m);
            total += self.m[m].view.len();
        }
        total
    }

    fn bank_info(&mut self, m: usize, b: u8) -> Option<dirfmt::BankInfo> {
        let base = Self::bank_off(m, b);
        let mut c = [0u8; COUNT_BYTES];
        if !self.f.read(base + HEADER_BYTES, &mut c) {
            return None;
        }
        let count = u32::from_le_bytes(c) as usize;
        if count > N {
            return None;
        }
        let w = Window { f: RefCell::new(&mut self.f), base, len: HEADER_BYTES + count * RECORD_BYTES + TRAILER_BYTES };
        dirfmt::validate(&w).filter(|i| i.count as usize == count)
    }

    fn mount_member(&mut self, m: usize) {
        let (a, b) = (self.bank_info(m, 0), self.bank_info(m, 1));
        let s = &mut self.m[m];
        *s = Slot::new();
        if let Some((bank, info)) = dirfmt::select_bank(a, b) {
            s.bank = Some(bank);
            s.slots = info.count;
            s.generation = info.generation;
            for pos in 0..info.count as usize {
                if let Some(r) = self.read_rec(m, bank, pos).filter(|r| r.vpn_ip != 0) {
                    self.m[m].add_view(pos, &r);
                }
            }
        }
    }

    fn read_rec(&mut self, m: usize, bank: u8, i: usize) -> Option<DirRecord> {
        let mut b = [0u8; RECORD_BYTES];
        self.f.read(Self::bank_off(m, bank) + HEADER_BYTES + COUNT_BYTES + i * RECORD_BYTES, &mut b).then(|| dirfmt::decode_record(&b))
    }

    fn read_slot(&mut self, m: usize, i: usize) -> Option<(Action, u32, DirRecord)> {
        let mut b = [0u8; SLOT_BYTES];
        if !self.f.read(Self::tx_off(m) + i * SLOT_BYTES, &mut b) {
            return None;
        }
        let action = match b[0] {
            0 => Action::Add,
            1 => Action::Remove,
            2 => Action::UpdateEndpoint,
            _ => return None,
        };
        let mut r = [0u8; RECORD_BYTES];
        r.copy_from_slice(&b[8..8 + RECORD_BYTES]);
        Some((action, u32::from_le_bytes([b[1], b[2], b[3], b[4]]), dirfmt::decode_record(&r)))
    }

    /// First live record satisfying `pred`, by reading the live bank.
    fn find(&mut self, m: usize, pred: impl Fn(&DirRecord) -> bool) -> Option<DirRecord> {
        let bank = self.m.get(m)?.bank?;
        for k in 0..self.m[m].view.len() {
            let pos = self.m[m].view[k].pos as usize;
            if let Some(r) = self.read_rec(m, bank, pos).filter(|r| pred(r)) {
                return Some(r);
            }
        }
        None
    }

    /// The record of an index entry of the commit in progress.
    fn materialise(&mut self, m: usize, e: &Ent, patched: &[DirRecord]) -> Option<DirRecord> {
        match e.src {
            Src::Empty => Some(DirRecord::default()),
            Src::Prev(i) => self.read_rec(m, self.m[m].bank?, i as usize),
            Src::Tx(i) => self.read_slot(m, i as usize).map(|(_, _, r)| r),
            Src::Ram(k) => patched.get(k as usize).cloned(),
        }
    }

    fn do_commit(&mut self, m: usize, authoritative: bool) -> Result<(), DirError> {
        let staged = self.m[m].staged as usize;
        let live = self.m[m].slots as usize;
        let mut ents: Vec<Ent> = Vec::new();
        ents.try_reserve_exact((live + staged).min(N)).map_err(|_| DirError)?;
        let mut patched: Vec<DirRecord> = Vec::new();
        let mut dropped = 0u32;
        // a partial map starts from the live records; an authoritative one starts empty (omission removes)
        if !authoritative && let Some(bank) = self.m[m].bank {
            for i in 0..live {
                let r = self.read_rec(m, bank, i).ok_or(DirError)?;
                if r.vpn_ip != 0 {
                    ents.push(Ent::of(&r, Src::Prev(i as u16)));
                }
            }
        }
        for pass in 0..3u8 {
            for i in 0..staged {
                let (action, group, rec) = self.read_slot(m, i).ok_or(DirError)?;
                if authoritative && group == 6 {
                    continue;
                }
                let order = match action {
                    Action::Add => 0,
                    Action::Remove => 1,
                    Action::UpdateEndpoint => 2,
                };
                if pass != order {
                    continue;
                }
                if authoritative && group == 2 && action == Action::Add {
                    if ents.len() >= N {
                        dropped += 1;
                    } else {
                        ents.push(Ent::of(&rec, Src::Tx(i as u16)));
                    }
                    continue;
                }
                self.apply(m, &mut ents, &mut patched, &mut dropped, action, &rec, i)?;
            }
        }
        self.write_bank(m, &ents, &patched, dropped)
    }

    /// `directory::apply` on the index.
    #[allow(clippy::too_many_arguments)]
    fn apply(&mut self, m: usize, ents: &mut Vec<Ent>, patched: &mut Vec<DirRecord>, dropped: &mut u32, action: Action, u: &DirRecord, slot: usize) -> Result<(), DirError> {
        let (mut found, mut empty) = (None, None);
        for (i, e) in ents.iter().enumerate() {
            if e.ip == 0 {
                empty.get_or_insert(i);
                continue;
            }
            if e.same(u) {
                found = Some(i);
                break;
            }
        }
        if action != Action::Add && found.is_none() {
            return Ok(());
        }
        let new_ent = match (action, found) {
            (Action::Remove, _) => Ent { ip: 0, has_id: false, id: 0, key: [0; 32], src: Src::Empty },
            (Action::UpdateEndpoint, Some(i)) => {
                let mut v = self.materialise(m, &ents[i], patched).ok_or(DirError)?;
                if u.public_key != [0; 32] {
                    v.public_key = u.public_key;
                }
                if u.disco_key != [0; 32] {
                    v.disco_key = u.disco_key;
                }
                if u.endpoint_count >= 0 {
                    v.endpoint_count = u.endpoint_count;
                    v.endpoints = u.endpoints;
                }
                if u.derp_region != 0 {
                    v.derp_region = u.derp_region;
                }
                if u.has_online {
                    v.has_online = true;
                    v.online = u.online;
                }
                let k = match ents[i].src {
                    Src::Ram(k) => {
                        patched[k as usize] = v.clone();
                        k
                    }
                    _ => {
                        if patched.len() >= PATCHED_MAX {
                            return Err(DirError);
                        }
                        patched.try_reserve(1).map_err(|_| DirError)?;
                        patched.push(v.clone());
                        (patched.len() - 1) as u16
                    }
                };
                Ent::of(&v, Src::Ram(k))
            }
            _ => Ent::of(u, Src::Tx(slot as u16)),
        };
        match found.or(empty) {
            Some(at) => ents[at] = new_ent,
            None if ents.len() >= N => *dropped += 1,
            None => ents.push(new_ent),
        }
        Ok(())
    }

    /// Erase the next bank and write the generation: header, count, records, trailer. The live bank is not touched.
    fn write_bank(&mut self, m: usize, ents: &[Ent], patched: &[DirRecord], dropped: u32) -> Result<(), DirError> {
        let next = dirfmt::next_bank(self.m[m].bank);
        let base = Self::bank_off(m, next);
        let generation = self.m[m].generation.wrapping_add(1);
        let bytes = HEADER_BYTES + COUNT_BYTES + ents.len() * RECORD_BYTES + TRAILER_BYTES;
        for s in 0..bytes.div_ceil(SECTOR) {
            if !self.f.erase_sector(base / SECTOR + s) {
                return Err(DirError);
            }
        }
        let mut view = Slot::new();
        let mut crc = !0u32;
        let header = dirfmt::encode_header(generation);
        crc = dirfmt::crc32_update(crc, &header);
        // the sink borrows the flash; records are read through it one at a time, so it is rebuilt around each read
        let mut at = base;
        let mut buf = [0u8; 512];
        let mut n = 0usize;
        let mut ok = true;
        let put = |this: &mut Self, data: &[u8], at: &mut usize, n: &mut usize, buf: &mut [u8; 512], ok: &mut bool| {
            let mut data = data;
            while !data.is_empty() {
                let take = (buf.len() - *n).min(data.len());
                buf[*n..*n + take].copy_from_slice(&data[..take]);
                *n += take;
                data = &data[take..];
                if *n == buf.len() {
                    *ok &= this.f.write(*at, &buf[..*n]);
                    *at += *n;
                    *n = 0;
                }
            }
        };
        put(self, &header, &mut at, &mut n, &mut buf, &mut ok);
        put(self, &(ents.len() as u32).to_le_bytes(), &mut at, &mut n, &mut buf, &mut ok);
        for (pos, e) in ents.iter().enumerate() {
            let r = self.materialise(m, e, patched).ok_or(DirError)?;
            let enc = dirfmt::encode_record(&r);
            crc = dirfmt::crc32_update(crc, &enc);
            put(self, &enc, &mut at, &mut n, &mut buf, &mut ok);
            if r.vpn_ip != 0 {
                view.add_view(pos, &r);
            }
        }
        put(self, &(!crc).to_le_bytes(), &mut at, &mut n, &mut buf, &mut ok);
        if n > 0 {
            ok &= self.f.write(at, &buf[..n]);
        }
        if !ok {
            return Err(DirError);
        }
        let s = &mut self.m[m];
        s.bank = Some(next);
        s.slots = ents.len() as u32;
        s.generation = generation;
        s.view = view.view;
        s.names = view.names;
        s.overflow = dropped;
        Ok(())
    }
}

impl<F: DirFlash, const M: usize, const N: usize> core::fmt::Debug for FlashDirectory<F, M, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FlashDirectory({M} members of {N} peers)")
    }
}

impl<F: DirFlash, const M: usize, const N: usize> PeerDirectory for FlashDirectory<F, M, N> {
    fn find_by_key(&mut self, member: usize, key: &PubKey) -> Option<DirRecord> {
        self.find(member, |r| dirfmt::matches(r, 0, 0, Some(key), None))
    }
    fn find_by_ip(&mut self, member: usize, ip: u32) -> Option<DirRecord> {
        // the view knows every live address: one read instead of a scan
        let s = self.m.get(member)?;
        let pos = s.view.iter().find(|v| v.ip == ip)?.pos as usize;
        let bank = s.bank?;
        self.read_rec(member, bank, pos).filter(|r| dirfmt::matches(r, ip, 0, None, None))
    }
    fn find_by_disco(&mut self, member: usize, key: &PubKey) -> Option<DirRecord> {
        self.find(member, |r| dirfmt::matches(r, 0, 0, None, Some(key)))
    }
    fn stage(&mut self, member: usize, rec: &PeerRecord) -> Result<(), DirError> {
        if member >= M {
            return Err(DirError);
        }
        if rec.action == PeerAction::Add && !is_storable(rec) {
            return Ok(());
        }
        let i = self.m[member].staged as usize;
        if i >= N {
            // a map with more updates than the log holds keeps what fits and counts the rest, as with the RAM directory
            self.m[member].stage_dropped = self.m[member].stage_dropped.saturating_add(1);
            return Ok(());
        }
        let base = Self::tx_off(member) + i * SLOT_BYTES;
        if i % (SECTOR / SLOT_BYTES) == 0 && !self.f.erase_sector(base / SECTOR) {
            return Err(DirError);
        }
        let mut b = [0u8; SLOT_BYTES];
        b[0] = action_of(rec.action) as u8;
        b[1..5].copy_from_slice(&(rec.group as u32).to_le_bytes());
        b[8..8 + RECORD_BYTES].copy_from_slice(&dirfmt::encode_record(&to_dir_record(rec)));
        if !self.f.write(base, &b) {
            return Err(DirError);
        }
        self.m[member].staged += 1;
        Ok(())
    }
    fn commit(&mut self, member: usize, authoritative: bool) -> Result<(), DirError> {
        if member >= M {
            return Err(DirError);
        }
        let r = self.do_commit(member, authoritative);
        // staging is consumed either way
        self.m[member].staged = 0;
        r
    }
    fn abort(&mut self, member: usize) {
        if let Some(s) = self.m.get_mut(member) {
            s.staged = 0;
        }
    }
    fn clear(&mut self, member: usize) {
        if member >= M {
            return;
        }
        // a cleared membership must not come back at the next boot: its banks lose their header sectors
        if self.m[member].bank.is_some() {
            for b in 0..2u8 {
                let _ = self.f.erase_sector(Self::bank_off(member, b) / SECTOR);
            }
        }
        let g = self.m[member].generation.wrapping_add(1);
        self.m[member] = Slot::new();
        self.m[member].generation = g;
    }
    fn count(&self, member: usize) -> usize {
        self.m.get(member).map_or(0, |s| s.view.len())
    }
    fn peer_view(&self, member: usize, j: usize) -> Option<(&str, u32)> {
        let s = self.m.get(member)?;
        let v = s.view.get(j)?;
        Some((s.name(v), v.ip))
    }
    fn peer_info(&self, member: usize, j: usize) -> Option<PeerInfo> {
        let v = self.m.get(member)?.view.get(j)?;
        Some(PeerInfo {
            ip: v.ip,
            key: v.key,
            derp_region: v.derp,
            endpoints: v.endpoints,
            routes: v.routes,
            online: match v.online {
                0 => None,
                n => Some(n == 2),
            },
        })
    }
    fn generation(&self, member: usize) -> u32 {
        self.m.get(member).map_or(0, |s| s.generation)
    }
    fn overflow(&self, member: usize) -> (u32, u32) {
        self.m.get(member).map_or((0, 0), |s| (s.overflow, s.stage_dropped))
    }
    fn stage_cost(&self) -> usize {
        16
    }
    fn commit_cost(&self, member: usize) -> usize {
        let s = &self.m[member.min(M - 1)];
        let n = (s.view.len() + s.staged as usize).min(N);
        n * (core::mem::size_of::<Ent>() + core::mem::size_of::<View>() + 24) + 1024
    }
}

impl<F: DirFlash, const M: usize, const N: usize> FlashDirectory<F, M, N> {
    /// Heap bytes the views hold now.
    pub fn heap_bytes(&self) -> usize {
        self.m.iter().map(|s| s.view.capacity() * core::mem::size_of::<View>() + s.names.capacity()).sum()
    }
    /// Staged updates waiting for a commit.
    pub fn staged(&self, member: usize) -> usize {
        self.m.get(member).map_or(0, |s| s.staged as usize)
    }
}

/// A flash in memory that enforces the rules of the real one: erase to 0xFF a sector at a time, programming only clears bits.
pub struct MemFlash {
    /// The bytes.
    pub d: Vec<u8>,
    /// Fail the n-th write from now (power loss mid-commit), when set.
    pub fail_after: Option<usize>,
    /// Writes so far.
    pub writes: usize,
}
impl MemFlash {
    /// An erased flash of `bytes`.
    pub fn new(bytes: usize) -> Self {
        Self { d: alloc::vec![0xFF; bytes], fail_after: None, writes: 0 }
    }
}
impl DirFlash for MemFlash {
    fn read(&mut self, o: usize, b: &mut [u8]) -> bool {
        b.copy_from_slice(&self.d[o..o + b.len()]);
        true
    }
    fn erase_sector(&mut self, s: usize) -> bool {
        self.d[s * SECTOR..(s + 1) * SECTOR].fill(0xFF);
        true
    }
    fn write(&mut self, o: usize, data: &[u8]) -> bool {
        self.writes += 1;
        if self.fail_after.is_some_and(|n| self.writes > n) {
            return false;
        }
        for (i, &x) in data.iter().enumerate() {
            assert!(self.d[o + i] == 0xFF || self.d[o + i] == x, "write over live flash at {}", o + i);
            self.d[o + i] = x;
        }
        true
    }
    fn size(&self) -> usize {
        self.d.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir::RamDirectory;
    use tdongle_tailnet_map::types::Group;
    use tdongle_tailnet_types::Key32;

    fn rec(ip: u32, key: u8, id: u64, name: &str) -> PeerRecord {
        let mut r = PeerRecord::new(PeerAction::Add, Group::Peers);
        r.vpn_ip = ip;
        r.node_key = Key32([key; 32]);
        r.disco_key = Key32([key ^ 0x55; 32]);
        r.node_id = Some(id);
        r.name.set(name);
        r
    }

    const N: usize = 40;
    type D = FlashDirectory<MemFlash, 2, N>;
    fn dir() -> D {
        FlashDirectory::new(MemFlash::new(D::PARTITION_BYTES))
    }

    #[test]
    fn the_partition_holds_two_members_of_n_peers() {
        assert_eq!(partition_bytes(3, 256), 3 * (2 * 16 + 16) * SECTOR, "three members of 256 peers: 576 KB of the 4 MB partition");
        assert!(partition_bytes(3, 256) <= 0x40_0000);
    }

    #[test]
    fn stage_commit_find_remove_patch_like_the_ram_directory() {
        let mut d = dir();
        d.stage(0, &rec(0x64400002, 2, 2, "alpha")).unwrap();
        d.stage(0, &rec(0x64400003, 3, 3, "beta")).unwrap();
        assert!(d.find_by_ip(0, 0x64400002).is_none(), "not visible before commit");
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), 2);
        assert_eq!(d.peer_view(0, 1), Some(("beta", 0x64400003)));
        assert!(d.find_by_key(0, &[3; 32]).is_some() && d.find_by_disco(0, &[3 ^ 0x55; 32]).is_some());
        assert!(d.find_by_ip(1, 0x64400002).is_none(), "per membership");
        d.stage(0, &rec(0x64400002, 2, 2, "alpha")).unwrap();
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), 1, "an authoritative map that omits a peer removes it");
        d.stage(0, &rec(0x64400004, 4, 4, "gamma")).unwrap();
        d.commit(0, false).unwrap();
        assert_eq!(d.count(0), 2);
        let mut rm = PeerRecord::new(PeerAction::Remove, Group::Removed);
        rm.node_id = Some(2);
        d.stage(0, &rm).unwrap();
        d.commit(0, false).unwrap();
        assert_eq!(d.count(0), 1);
        let mut p = PeerRecord::new(PeerAction::Patch, Group::Patch);
        p.node_id = Some(4);
        p.home_derp = 9;
        d.stage(0, &p).unwrap();
        d.commit(0, false).unwrap();
        assert_eq!(d.find_by_ip(0, 0x64400004).unwrap().derp_region, 9);
        assert_eq!(d.peer_info(0, 0).unwrap().derp_region, 9);
        assert_eq!(d.generation(0), 5);
        assert_eq!(d.heap_bytes() < 200, true, "the heap holds names, not records");
    }

    #[test]
    fn a_directory_survives_a_restart_and_a_cleared_one_does_not() {
        let mut d = dir();
        for i in 0..12u8 {
            d.stage(1, &rec(0x64400002 + u32::from(i), i + 1, u64::from(i) + 2, "peer")).unwrap();
        }
        d.commit(1, true).unwrap();
        d.commit(1, false).unwrap(); // a second generation: the other bank
        let gen_before = d.generation(1);
        let flash = core::mem::replace(&mut d.f, MemFlash::new(0));
        let mut d2 = FlashDirectory::<MemFlash, 2, N>::new(flash);
        assert_eq!(d2.mount(), 12);
        assert_eq!((d2.count(1), d2.generation(1)), (12, gen_before));
        assert!(d2.find_by_ip(1, 0x64400005).is_some());
        d2.clear(1);
        let flash = core::mem::replace(&mut d2.f, MemFlash::new(0));
        let mut d3 = FlashDirectory::<MemFlash, 2, N>::new(flash);
        assert_eq!(d3.mount(), 0, "cleared means gone at the next boot");
    }

    #[test]
    fn a_torn_commit_leaves_the_previous_generation() {
        let mut d = dir();
        for i in 0..6u8 {
            d.stage(0, &rec(0x64400002 + u32::from(i), i + 1, u64::from(i) + 2, "peer")).unwrap();
        }
        d.commit(0, true).unwrap();
        for i in 0..9u8 {
            d.stage(0, &rec(0x64400100 + u32::from(i), 0x80 + i, u64::from(i) + 100, "new")).unwrap();
        }
        // power fails somewhere in the bank write
        d.f.fail_after = Some(d.f.writes + 3);
        assert!(d.commit(0, true).is_err());
        assert_eq!(d.count(0), 6, "the live view is the old one");
        assert!(d.find_by_ip(0, 0x64400003).is_some());
        let flash = core::mem::replace(&mut d.f, MemFlash::new(0));
        let mut d2 = FlashDirectory::<MemFlash, 2, N>::new(flash);
        d2.f.fail_after = None;
        assert_eq!(d2.mount(), 6, "boot finds the previous generation, not the torn bank");
    }

    #[test]
    fn a_map_bigger_than_the_directory_keeps_what_fits_and_counts_the_rest() {
        let mut d = dir();
        for i in 0..(N as u32 + 5) {
            // staging holds N updates: the others are counted
            d.stage(0, &rec(0x64400002 + i, (i % 200) as u8 + 1, u64::from(i) + 2, "p")).unwrap();
        }
        assert_eq!((d.staged(0), d.overflow(0).1), (N, 5));
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), N);
    }

    /// The same random update streams into the RAM directory and the flash directory give the same peers in the same order.
    #[test]
    fn it_gives_the_same_directory_as_the_ram_one_on_random_updates() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let mut f = dir();
        let mut r = RamDirectory::<2, N, N>::new();
        for round in 0..300 {
            let m = rnd(2) as usize;
            let authoritative = rnd(3) == 0;
            for _ in 0..rnd(12) {
                let id = rnd(30) + 1;
                let mut u = rec(0x64400000 + id as u32, id as u8, id, ["a", "bb", "ccc", "dddd"][rnd(4) as usize]);
                match rnd(5) {
                    0 => u.action = PeerAction::Remove,
                    1 => {
                        u.action = PeerAction::Patch;
                        u.home_derp = rnd(5) as u16 + 1;
                        u.online = Some(rnd(2) == 0);
                    }
                    _ => {}
                }
                if u.action == PeerAction::Remove {
                    u.group = Group::Removed;
                }
                if u.action == PeerAction::Patch {
                    u.group = Group::Patch;
                }
                f.stage(m, &u).unwrap();
                r.stage(m, &u).unwrap();
            }
            if rnd(10) == 0 {
                f.abort(m);
                r.abort(m);
            }
            assert_eq!(f.commit(m, authoritative).is_ok(), r.commit(m, authoritative).is_ok(), "round {round}");
            for m in 0..2 {
                assert_eq!(f.count(m), r.count(m), "count, round {round} member {m}");
                assert_eq!(f.generation(m), r.generation(m));
                for j in 0..r.count(m) {
                    assert_eq!(f.peer_view(m, j), r.peer_view(m, j), "peer {j}, round {round}");
                    assert_eq!(f.peer_info(m, j), r.peer_info(m, j), "info {j}, round {round}");
                }
                for id in 1..=30u64 {
                    let ip = 0x64400000 + id as u32;
                    assert_eq!(f.find_by_ip(m, ip).map(|x| (x.node_id, x.derp_region, x.endpoint_count)), r.find_by_ip(m, ip).map(|x| (x.node_id, x.derp_region, x.endpoint_count)));
                }
            }
        }
    }
}
