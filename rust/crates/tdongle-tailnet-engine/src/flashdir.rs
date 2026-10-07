//! The peer directory in flash (ADR 0012, `ml_directory.c`): every record of every membership lives in the raw `peerstore` partition, and the heap holds
//! no per-peer state at all. There is no peer cap: a membership holds what its share of the partition holds (about 1,300 live peers for each of three
//! memberships of the 4 MB partition, see [`Geometry`]), and the RAM cost is fixed: the per-membership counters and a small cache of hot peers.
//!
//! # Layout (per membership: `tx | area 0 | area 1`, all in [`SECTOR`]s)
//!
//! * `tx`: the staging log of the map being received, one [`SLOT_BYTES`] slot per update (`action, group, record`). It is not crash-safe and need not be: a map
//!   cut by a reset is fetched again.
//! * Two **areas**, one active and one spare. An area is `slots | 5 hash tables`. Slots are appended, never rewritten: a `PUT` (a record version), a `TOMB`
//!   (an identity removed), a `COMMIT` (a map applied: generation, live count) and, in slot 0, the `HEADER` (epoch and owning node public key, written last when an area takes over).
//!   Every slot carries the transaction that wrote it and a CRC over its bytes.
//! * The hash tables index the slots by node id, WireGuard key, address, DISCO key and the first label of the hostname: open addressing over 4-byte buckets
//!   `[tag:16 | slot:16]` (erased = `FFFF_FFFF`), at most half full, written once like the slots. A lookup probes one table, reads the candidate slots whose
//!   tag matches, and keeps the one that is the *latest visible version* of its identity (a second probe, in the id or key table). Nothing scans flash.
//!
//! # Identity and versions
//!
//! A record's identity is its node id, or its key when it has none (`directory::same`). A newer slot of the same identity supersedes an older one (slots are
//! ordered by position); a `TOMB` ends it. A slot is visible when its transaction committed: transactions are numbered, a `COMMIT` slot ends one, and the
//! transactions that wrote slots but never their `COMMIT` (power loss, a flash error) are remembered as aborted. So a torn commit never loses anything: the
//! previous versions are still there and the torn ones are invisible, at once and after a reboot.
//!
//! # Commit
//!
//! The rules are those of `tdongle_tailnet_peers::directory::commit`: three passes over the staged updates (adds, removes, endpoint updates); an authoritative
//! map starts from nothing (its unchanged records are only marked *seen*, in a bitmap of a bit per slot, so they are not written again) and the unseen live
//! records get a `TOMB` at the end. Unchanged updates write nothing: a full map of an idle tailnet costs one `COMMIT` slot.
//!
//! # Maintenance (never blocks the executor)
//!
//! [`FlashDirectory::maintain`] does one bounded step and returns: erase one sector (the staging log behind a commit, or the spare area), or copy up to
//! [`COPY_STEP`] slots into the spare area. The engine calls it once a tick while [`FlashDirectory::wants_maintenance`] says so, so the executor runs between
//! any two sector erases. Compaction copies the latest live version of every identity into the spare area (commits go on meanwhile, into the active area, and
//! the copy catches up with them), then writes the spare's header with a higher epoch: that one 256-byte write is the switch, and the old area is erased
//! sector by sector afterwards. A crash before the header leaves the old area in force. Only when a commit finds no room (the background did not keep up)
//! does it compact synchronously.
//!
//! # RAM
//!
//! `size_of::<FlashDirectory<_, M, C>>()`: about 180 bytes a membership and `C` cached records (the `C` most recently used peers, the WireGuard-resident ones
//! pinned; see [`PeerDirectory::pin`]). A commit takes a transient bitmap of one bit per slot (about 200 bytes) and a few records on the stack.

extern crate alloc;

use crate::dir::{DirError, PeerDirectory, PeerInfo, action_of, to_dir_record};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use tdongle_tailnet_map::directory::is_storable;
use tdongle_tailnet_map::types::{PeerAction, PeerRecord};
use tdongle_tailnet_peers::directory::{self as dirfmt, RECORD_BYTES};
use tdongle_tailnet_peers::record::{Action, DirRecord, PubKey};

/// Flash sector, the erase unit.
pub const SECTOR: usize = 4096;
/// One slot: kind (1), padding (3), transaction (4), payload (244: a record of 242), crc32 (4). A staged update uses the same size.
pub const SLOT_BYTES: usize = 256;
const PER_SECTOR: usize = SECTOR / SLOT_BYTES;
const PAYLOAD: usize = 8;
const CRC_AT: usize = SLOT_BYTES - 4;
/// Hash tables of an area: node id, key, address, DISCO key, hostname label.
const TABLES: usize = 5;
const T_ID: usize = 0;
const T_KEY: usize = 1;
const T_IP: usize = 2;
const T_DISCO: usize = 3;
const T_NAME: usize = 4;
const BUCKET: usize = 4;
/// Slot positions are 16 bits and `FFFF` is the erased bucket.
const MAX_SLOTS: usize = 0xFFF0;
/// Aborted transactions remembered per membership; a commit compacts first when this many are pending.
const ABORTED: usize = 8;
/// Commits accepted but not yet applied (waiting for an erased area or a compaction), a membership.
pub const QUEUED: usize = 4;
/// Slots a compaction step copies at most.
pub const COPY_STEP: usize = 16;
/// Erased sectors a maintenance step may skip over (blank checks are reads) before it returns.
const BLANK_RUN: usize = 8;

const K_PUT: u8 = 0x5A;
const K_TOMB: u8 = 0x5B;
const K_COMMIT: u8 = 0x5C;
const K_HEADER: u8 = 0x5D;

/// The flash partition behind a directory (offsets are relative to its start). Writes only ever go to erased bytes.
pub trait DirFlash {
    /// Fill `buf` from `offset`; false on an error.
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> bool;
    /// Erase sector number `sector` (`SECTOR` bytes at `sector * SECTOR`).
    fn erase_sector(&mut self, sector: usize) -> bool;
    /// Program `data` at `offset` (any alignment); only clear bits, never set them.
    fn write(&mut self, offset: usize, data: &[u8]) -> bool;
    /// Bytes of the partition.
    fn size(&self) -> usize;
}

/// How a partition is cut between `members` memberships.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Sectors of one membership.
    pub region: usize,
    /// Sectors of its staging log.
    pub tx: usize,
    /// Sectors of each of its two areas.
    pub area: usize,
    /// Slots of an area (records, tombstones, commits, the header).
    pub slots: usize,
    /// Buckets of each hash table (twice the slots: never more than half full).
    pub buckets: usize,
}

impl Geometry {
    /// The geometry of a partition of `bytes` for `members` memberships (`None`: too small).
    pub const fn of(bytes: usize, members: usize) -> Option<Self> {
        if members == 0 {
            return None;
        }
        let region = bytes / SECTOR / members;
        let tx = region / 4;
        let area = (region - tx) / 2;
        let mut slots = area * SECTOR / (SLOT_BYTES + TABLES * 2 * BUCKET);
        if slots > MAX_SLOTS {
            slots = MAX_SLOTS;
        }
        if tx == 0 || slots < 16 {
            return None;
        }
        Some(Self { region, tx, area, slots, buckets: 2 * slots })
    }
    /// Updates one map can stage.
    pub const fn tx_slots(&self) -> usize {
        self.tx * PER_SECTOR
    }
    /// Live peers a membership holds with room to compact (three quarters of the slots).
    pub const fn capacity(&self) -> usize {
        self.slots * 3 / 4
    }
    const fn tx_sector(&self, m: usize, s: usize) -> usize {
        m * self.region + s
    }
    const fn area_sector(&self, m: usize, a: u8, s: usize) -> usize {
        m * self.region + self.tx + a as usize * self.area + s
    }
    const fn slot_off(&self, m: usize, a: u8, p: usize) -> usize {
        self.area_sector(m, a, 0) * SECTOR + p * SLOT_BYTES
    }
    const fn bucket_off(&self, m: usize, a: u8, t: usize, b: usize) -> usize {
        self.area_sector(m, a, 0) * SECTOR + self.slots * SLOT_BYTES + (t * self.buckets + b) * BUCKET
    }
}

/// Bytes of the `peerstore` partition (what the host harness gives its in-memory flash).
pub const PEERSTORE_BYTES: usize = 0x40_0000;

// ---- hashing ----------------------------------------------------------------------------------------------------------------------------------------

fn fnv(t: usize, data: &[u8], lower: bool) -> u32 {
    let mut h = 0x811c_9dc5u32 ^ (t as u32).wrapping_mul(0x0100_0193);
    for &b in data {
        h ^= u32::from(if lower { b.to_ascii_lowercase() } else { b });
        h = h.wrapping_mul(0x0100_0193);
    }
    h ^= h >> 15;
    h = h.wrapping_mul(0x2c1b_3c6d);
    h ^ (h >> 12)
}
fn tag_of(h: u32) -> u16 {
    (h.rotate_left(11).wrapping_mul(0x9e37_79b1) >> 16) as u16
}
fn h_id(id: u64) -> u32 {
    fnv(T_ID, &id.to_le_bytes(), false)
}
fn h_key(k: &PubKey) -> u32 {
    fnv(T_KEY, k, false)
}
fn h_ip(ip: u32) -> u32 {
    fnv(T_IP, &ip.to_le_bytes(), false)
}
fn h_disco(k: &PubKey) -> u32 {
    fnv(T_DISCO, k, false)
}
fn h_name(label: &[u8]) -> u32 {
    fnv(T_NAME, label, true)
}

/// The first label of a stored hostname as DNS compares it (the responder looks at 63 bytes of it).
pub fn first_label(host: &str) -> &[u8] {
    let h = &host.as_bytes()[..host.len().min(63)];
    &h[..h.iter().position(|&c| c == b'.').unwrap_or(h.len())]
}

/// A record's identity (`directory::same`): its node id, or its key when it has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Canon {
    /// Tailscale node id.
    Id(u64),
    /// WireGuard key of a record without a node id.
    Key(PubKey),
}

impl Canon {
    /// The identity of `r`.
    pub fn of(r: &DirRecord) -> Self {
        if r.has_node_id { Self::Id(r.node_id) } else { Self::Key(r.public_key) }
    }
    fn table(&self) -> (usize, u32) {
        match self {
            Self::Id(id) => (T_ID, h_id(*id)),
            Self::Key(k) => (T_KEY, h_key(k)),
        }
    }
    fn record(&self) -> DirRecord {
        let mut r = DirRecord::default();
        match self {
            Self::Id(id) => {
                r.has_node_id = true;
                r.node_id = *id;
            }
            Self::Key(k) => r.public_key = *k,
        }
        r
    }
}

// ---- slots ------------------------------------------------------------------------------------------------------------------------------------------

type Raw = [u8; SLOT_BYTES];

fn seal(kind: u8, txn: u32, payload: &[u8]) -> Raw {
    let mut b = [0u8; SLOT_BYTES];
    b[0] = kind;
    b[4..8].copy_from_slice(&txn.to_le_bytes());
    b[PAYLOAD..PAYLOAD + payload.len()].copy_from_slice(payload);
    let crc = !dirfmt::crc32_update(!0, &b[..CRC_AT]);
    b[CRC_AT..].copy_from_slice(&crc.to_le_bytes());
    b
}
fn header(epoch: u32, generation: u32, count: u32, txn: u32, owner: &PubKey) -> Raw {
    let mut payload = [0u8; 48];
    payload[..16].copy_from_slice(&words(&[epoch, generation, count, txn]));
    payload[16..].copy_from_slice(owner);
    seal(K_HEADER, 0, &payload)
}

fn sealed(b: &Raw) -> bool {
    let crc = !dirfmt::crc32_update(!0, &b[..CRC_AT]);
    b[CRC_AT..] == crc.to_le_bytes()
}
fn txn_of(b: &Raw) -> u32 {
    u32::from_le_bytes([b[4], b[5], b[6], b[7]])
}
fn word(b: &Raw, i: usize) -> u32 {
    let o = PAYLOAD + 4 * i;
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn record_of(b: &Raw) -> DirRecord {
    let mut r = [0u8; RECORD_BYTES];
    r.copy_from_slice(&b[PAYLOAD..PAYLOAD + RECORD_BYTES]);
    dirfmt::decode_record(&r)
}
fn words(w: &[u32]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for (i, x) in w.iter().enumerate() {
        o[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    o
}

/// `directory::apply`'s endpoint update.
fn patch(mut v: DirRecord, u: &DirRecord) -> DirRecord {
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
    v
}

fn info_of(r: &DirRecord) -> PeerInfo {
    PeerInfo {
        ip: r.vpn_ip,
        key: [r.public_key[0], r.public_key[1], r.public_key[2], r.public_key[3]],
        derp_region: r.derp_region,
        endpoints: r.endpoint_count.max(0) as u8,
        routes: r.subnet_route_count,
        online: if r.has_online { Some(r.online) } else { None },
    }
}

// ---- state ------------------------------------------------------------------------------------------------------------------------------------------

/// Which slots a lookup sees.
#[derive(Clone, Copy)]
enum View<'a> {
    /// Committed transactions.
    Committed,
    /// And the transaction being written.
    Pending(u32),
    /// An authoritative commit: the transaction being written and the committed slots it has seen.
    Auth { txn: u32, start: u32, seen: &'a [u64] },
    /// Everything (the area a compaction fills: only committed slots are copied into it).
    All,
}

/// One membership.
#[derive(Clone, Copy, Debug)]
struct Member {
    active: Option<u8>,
    /// WireGuard public key owning the persisted directory. Zero means legacy/unbound.
    owner: PubKey,
    epoch: u32,
    /// Next free slot of the active area.
    end: u32,
    generation: u32,
    count: u32,
    /// Last committed transaction.
    txn: u32,
    next_txn: u32,
    aborted: [u32; ABORTED],
    n_aborted: u8,
    /// A torn transaction found no room in `aborted`: no commit until a compaction leaves the torn ones behind (the committed state stays the one before it).
    abort_over: bool,
    /// Sectors of the spare area known erased, from its start (the spare is area 0 when there is no active one).
    spare_clean: u32,
    /// Compaction in progress: next slot of the active area to copy, next free slot of the spare.
    copy: Option<(u32, u32)>,
    /// A compaction that did not fit is retried only after the active area grew to this.
    retry_at: u32,
    staged: u32,
    stage_dropped: u32,
    overflow: u32,
    /// Staging-log sectors `[tx_ready, tx_dirty)` may hold old updates; the others are erased.
    tx_ready: u32,
    tx_dirty: u32,
    /// Staging-log index where the map being received starts (the ones before it are queued commits).
    open: u32,
    /// Accepted commits, oldest first: the staging-log range each applies, whether it is authoritative, whether it already waited for a compaction.
    queue: [Queued; QUEUED],
    n_queued: u8,
    /// The head of the queue waits for a compaction, to start once the spare area is erased.
    want_copy: bool,
}

#[derive(Clone, Copy, Debug)]
struct Queued {
    lo: u16,
    hi: u16,
    auth: bool,
    compacted: bool,
}

/// What applying the head of the queue came to.
enum Apply {
    Done,
    Wait,
    Failed,
}

impl Member {
    const fn new() -> Self {
        Self {
            active: None,
            owner: [0; 32],
            epoch: 0,
            end: 0,
            generation: 0,
            count: 0,
            txn: 0,
            next_txn: 1,
            aborted: [0; ABORTED],
            n_aborted: 0,
            abort_over: false,
            spare_clean: 0,
            copy: None,
            retry_at: 0,
            staged: 0,
            stage_dropped: 0,
            overflow: 0,
            tx_ready: 0,
            tx_dirty: u32::MAX,
            open: 0,
            queue: [Queued { lo: 0, hi: 0, auth: false, compacted: false }; QUEUED],
            n_queued: 0,
            want_copy: false,
        }
    }
    fn spare(&self) -> u8 {
        self.active.map_or(0, |a| 1 - a)
    }
    fn committed(&self, txn: u32) -> bool {
        txn <= self.txn && !self.aborted[..self.n_aborted as usize].contains(&txn)
    }
    fn visible(&self, v: View<'_>, pos: u32, txn: u32) -> bool {
        match v {
            View::Committed => self.committed(txn),
            View::Pending(t) => txn == t || self.committed(txn),
            View::Auth { txn: t, start, seen } => txn == t || (pos < start && self.committed(txn) && bit(seen, pos)),
            View::All => true,
        }
    }
    fn abort(&mut self, txn: u32) {
        if (self.n_aborted as usize) < ABORTED {
            self.aborted[self.n_aborted as usize] = txn;
            self.n_aborted += 1;
        } else {
            // never forget a torn transaction: it is above `txn`, so it stays invisible as long as no later commit raises `txn`
            self.abort_over = true;
        }
    }
    /// A commit has to wait for a compaction first.
    fn short(&self, g: &Geometry) -> bool {
        self.end as usize + 2 > g.slots || self.n_aborted as usize >= ABORTED - 1 || self.abort_over
    }
}

fn bit(s: &[u64], p: u32) -> bool {
    s.get(p as usize / 64).is_some_and(|w| w >> (p % 64) & 1 != 0)
}
fn set_bit(s: &mut [u64], p: u32) {
    if let Some(w) = s.get_mut(p as usize / 64) {
        *w |= 1 << (p % 64);
    }
}

/// A cached record.
#[derive(Clone, Debug)]
struct Cached {
    member: u8,
    pinned: bool,
    pos: u16,
    used: u32,
    rec: DirRecord,
}

/// Counters of the directory (`tn_dir`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirStats {
    /// Lookups answered from the cache.
    pub cache_hits: u32,
    /// Lookups that went to flash.
    pub cache_misses: u32,
    /// Sectors erased.
    pub erases: u32,
    /// Compactions completed.
    pub compactions: u32,
    /// Compactions a commit had to run synchronously (the background did not keep up).
    pub sync_compactions: u32,
    /// Compactions abandoned (the live records did not fit the spare area).
    pub compactions_failed: u32,
    /// Flash operations that failed.
    pub flash_errors: u32,
    /// Commits that failed (the previous generation stayed).
    pub commits_failed: u32,
    /// Resident peers the cache had no room to pin.
    pub pins_refused: u32,
    /// Commits accepted before their area was ready, applied later by [`FlashDirectory::maintain`].
    pub deferred_commits: u32,
    /// Commits refused because the queue of deferred ones was full.
    pub queue_full: u32,
}

/// The working state of one commit.
struct Ctx {
    txn: u32,
    start: u32,
    auth: bool,
    seen: Vec<u64>,
    count: i64,
}

impl Ctx {
    fn view(&self) -> View<'_> {
        if self.auth { View::Auth { txn: self.txn, start: self.start, seen: &self.seen } } else { View::Pending(self.txn) }
    }
}

/// The peer directory of `M` memberships in flash, with a cache of `C` hot records.
pub struct FlashDirectory<F: DirFlash, const M: usize, const C: usize> {
    f: RefCell<F>,
    io_error: Cell<bool>,
    full: Cell<bool>,
    geo: Option<Geometry>,
    mounted: bool,
    m: [Member; M],
    cache: [Option<Cached>; C],
    clock: u32,
    stats: Cell<DirStats>,
}

impl<F: DirFlash, const M: usize, const C: usize> FlashDirectory<F, M, C> {
    /// An empty directory over `f`. Nothing is read until the first use (or [`FlashDirectory::mount`]).
    pub const fn new(f: F) -> Self {
        Self {
            f: RefCell::new(f),
            io_error: Cell::new(false),
            full: Cell::new(false),
            geo: None,
            mounted: false,
            m: [const { Member::new() }; M],
            cache: [const { None }; C],
            clock: 0,
            stats: Cell::new(DirStats {
                cache_hits: 0,
                cache_misses: 0,
                erases: 0,
                compactions: 0,
                sync_compactions: 0,
                compactions_failed: 0,
                flash_errors: 0,
                commits_failed: 0,
                pins_refused: 0,
                deferred_commits: 0,
                queue_full: 0,
            }),
        }
    }
    /// Bytes of RAM the directory takes (it holds nothing on the heap between commits).
    pub const RAM_BYTES: usize = core::mem::size_of::<Self>();
    /// Bytes of the partition the host harness gives it.
    pub const PARTITION_BYTES: usize = PEERSTORE_BYTES;

    /// The geometry (after the first use).
    pub fn geometry(&self) -> Option<Geometry> {
        self.geo
    }
    /// The counters.
    pub fn stats(&self) -> DirStats {
        self.stats.get()
    }
    /// The flash (tests: power loss, inspection).
    pub fn flash(&mut self) -> &mut F {
        self.f.get_mut()
    }
    /// Give the flash back.
    pub fn into_flash(self) -> F {
        self.f.into_inner()
    }
    /// Staged updates waiting for a commit.
    pub fn staged(&self, member: usize) -> usize {
        self.m.get(member).map_or(0, |s| s.staged as usize)
    }
    /// Slots of the active area in use (records, versions, tombstones and commits not yet compacted away).
    pub fn slots_used(&self, member: usize) -> usize {
        self.m.get(member).map_or(0, |s| s.end as usize)
    }
    /// Pinned cache entries of `member`.
    pub fn pinned(&self, member: usize) -> usize {
        self.cache.iter().flatten().filter(|c| c.member as usize == member && c.pinned).count()
    }
    /// Commits of `member` accepted but not yet applied.
    pub fn queued(&self, member: usize) -> usize {
        self.m.get(member).map_or(0, |s| s.n_queued as usize)
    }
    /// Cached records.
    pub fn cached(&self) -> usize {
        self.cache.iter().flatten().count()
    }

    fn bump(&self, f: impl FnOnce(&mut DirStats)) {
        let mut s = self.stats.get();
        f(&mut s);
        self.stats.set(s);
    }

    // ---- flash ------------------------------------------------------------------------------------------------------------------------------

    fn read(&self, off: usize, buf: &mut [u8]) -> bool {
        let ok = self.f.borrow_mut().read(off, buf);
        if !ok {
            self.io_error.set(true);
            self.bump(|s| s.flash_errors += 1);
        }
        ok
    }
    fn write(&self, off: usize, data: &[u8]) -> bool {
        let ok = self.f.borrow_mut().write(off, data);
        if !ok {
            self.io_error.set(true);
            self.bump(|s| s.flash_errors += 1);
        }
        ok
    }
    fn blank(&self, sector: usize) -> bool {
        let mut b = [0u8; SLOT_BYTES];
        (0..PER_SECTOR).all(|i| self.read(sector * SECTOR + i * SLOT_BYTES, &mut b) && b.iter().all(|&x| x == 0xFF))
    }
    /// Erase `sector` unless it is already blank.
    fn clean(&self, sector: usize) -> bool {
        if self.blank(sector) {
            return true;
        }
        self.bump(|s| s.erases += 1);
        let ok = self.f.borrow_mut().erase_sector(sector);
        if !ok {
            self.io_error.set(true);
            self.bump(|s| s.flash_errors += 1);
        }
        ok
    }
    fn slot(&self, g: &Geometry, m: usize, a: u8, p: u32) -> Option<Raw> {
        let mut b = [0u8; SLOT_BYTES];
        (self.read(g.slot_off(m, a, p as usize), &mut b) && sealed(&b)).then_some(b)
    }

    /// Visit the slot positions in table `t` whose tag matches `h`, until `f` says stop.
    fn probe(&self, g: &Geometry, m: usize, a: u8, t: usize, h: u32, mut f: impl FnMut(u32) -> bool) {
        let tag = tag_of(h);
        let mut b = (h as usize) % g.buckets;
        let mut buf = [0u8; 8 * BUCKET];
        for _ in 0..g.buckets.div_ceil(8) + 1 {
            let n = 8.min(g.buckets - b);
            if !self.read(g.bucket_off(m, a, t, b), &mut buf[..n * BUCKET]) {
                return;
            }
            for i in 0..n {
                let e = &buf[i * BUCKET..(i + 1) * BUCKET];
                if e == [0xFF; 4] {
                    return;
                }
                let pos = u16::from_le_bytes([e[2], e[3]]) as usize;
                if u16::from_le_bytes([e[0], e[1]]) == tag && pos < g.slots && !f(pos as u32) {
                    return;
                }
            }
            b = (b + n) % g.buckets;
        }
    }
    /// Put `pos` in table `t` under `h`: the first erased bucket from its home.
    fn insert(&self, g: &Geometry, m: usize, a: u8, t: usize, h: u32, pos: u32) -> bool {
        let mut b = (h as usize) % g.buckets;
        let mut buf = [0u8; 8 * BUCKET];
        for _ in 0..g.buckets.div_ceil(8) + 1 {
            let n = 8.min(g.buckets - b);
            if !self.read(g.bucket_off(m, a, t, b), &mut buf[..n * BUCKET]) {
                return false;
            }
            for i in 0..n {
                if buf[i * BUCKET..(i + 1) * BUCKET] == [0xFF; 4] {
                    let mut e = [0u8; BUCKET];
                    e[..2].copy_from_slice(&tag_of(h).to_le_bytes());
                    e[2..].copy_from_slice(&(pos as u16).to_le_bytes());
                    return self.write(g.bucket_off(m, a, t, b + i), &e);
                }
            }
            b = (b + n) % g.buckets;
        }
        false
    }
    /// Append a slot to area `a` at `*end` and index it.
    fn append(&self, g: &Geometry, m: usize, a: u8, end: &mut u32, raw: &Raw) -> Result<u32, DirError> {
        let p = *end;
        if p as usize >= g.slots {
            self.full.set(true);
            return Err(DirError);
        }
        // the slot is consumed even if the write fails: a torn slot is skipped by its checksum
        *end += 1;
        if !self.write(g.slot_off(m, a, p as usize), raw) {
            return Err(DirError);
        }
        let ok = match raw[0] {
            K_PUT => {
                let r = record_of(raw);
                (!r.has_node_id || self.insert(g, m, a, T_ID, h_id(r.node_id), p))
                    && self.insert(g, m, a, T_KEY, h_key(&r.public_key), p)
                    && (r.vpn_ip == 0 || self.insert(g, m, a, T_IP, h_ip(r.vpn_ip), p))
                    && (r.disco_key == [0; 32] || self.insert(g, m, a, T_DISCO, h_disco(&r.disco_key), p))
                    && (first_label(r.hostname.as_str()).is_empty() || self.insert(g, m, a, T_NAME, h_name(first_label(r.hostname.as_str())), p))
            }
            K_TOMB => {
                let (t, h) = Canon::of(&record_of(raw)).table();
                self.insert(g, m, a, t, h, p)
            }
            _ => true,
        };
        if ok { Ok(p) } else { Err(DirError) }
    }

    // ---- lookups ----------------------------------------------------------------------------------------------------------------------------

    /// The latest version of `c` that `v` sees in area `a`: position, live (a `PUT`), record.
    fn latest(&self, g: &Geometry, m: usize, a: u8, c: Canon, v: View<'_>) -> Option<(u32, bool, DirRecord)> {
        let ms = &self.m[m];
        let (t, h) = c.table();
        let mut best: Option<(u32, bool, DirRecord)> = None;
        self.probe(g, m, a, t, h, |p| {
            if best.as_ref().is_some_and(|b| b.0 >= p) {
                return true;
            }
            if let Some(raw) = self.slot(g, m, a, p)
                && (raw[0] == K_PUT || raw[0] == K_TOMB)
                && ms.visible(v, p, txn_of(&raw))
            {
                let r = record_of(&raw);
                if Canon::of(&r) == c {
                    best = Some((p, raw[0] == K_PUT, r));
                }
            }
            true
        });
        best
    }
    /// A live record found through table `t` under `h` that satisfies `pred`.
    // Explicit transaction geometry and cursor arguments keep flash ownership visible.
    #[allow(clippy::too_many_arguments)]
    fn find_in(&self, g: &Geometry, m: usize, a: u8, t: usize, h: u32, v: View<'_>, pred: &dyn Fn(&DirRecord) -> bool) -> Option<(u32, DirRecord)> {
        let ms = &self.m[m];
        let mut found = None;
        self.probe(g, m, a, t, h, |p| {
            if let Some(raw) = self.slot(g, m, a, p)
                && raw[0] == K_PUT
                && ms.visible(v, p, txn_of(&raw))
            {
                let r = record_of(&raw);
                if r.vpn_ip != 0 && pred(&r) && self.latest(g, m, a, Canon::of(&r), v).is_some_and(|l| l.0 == p) {
                    found = Some((p, r));
                    return false;
                }
            }
            true
        });
        found
    }
    fn find_key(&self, g: &Geometry, m: usize, a: u8, key: &PubKey, v: View<'_>) -> Option<(u32, DirRecord)> {
        self.find_in(g, m, a, T_KEY, h_key(key), v, &|r| r.public_key == *key)
    }
    /// `directory::same`: by node id when the update has one, else by key.
    fn find_same(&self, g: &Geometry, m: usize, a: u8, u: &DirRecord, v: View<'_>) -> Option<(u32, DirRecord)> {
        if u.has_node_id {
            self.latest(g, m, a, Canon::Id(u.node_id), v).filter(|l| l.1 && l.2.vpn_ip != 0).map(|l| (l.0, l.2))
        } else {
            self.find_key(g, m, a, &u.public_key, v)
        }
    }

    fn lookup(&mut self, member: usize, t: usize, h: u32, pred: &dyn Fn(&DirRecord) -> bool) -> Option<DirRecord> {
        self.ensure_mounted();
        let g = self.geo?;
        let a = self.m.get(member)?.active?;
        self.clock = self.clock.wrapping_add(1);
        let clock = self.clock;
        if let Some(c) = self.cache.iter_mut().flatten().find(|c| c.member as usize == member && pred(&c.rec)) {
            c.used = clock;
            let r = c.rec.clone();
            self.bump(|s| s.cache_hits += 1);
            return Some(r);
        }
        self.bump(|s| s.cache_misses += 1);
        let (p, r) = self.find_in(&g, member, a, t, h, View::Committed, pred)?;
        self.cache_put(member, p, &r, false);
        Some(r)
    }

    fn cache_put(&mut self, member: usize, pos: u32, r: &DirRecord, pinned: bool) -> bool {
        let clock = self.clock;
        let slot = match self.cache.iter().position(Option::is_none) {
            Some(i) => Some(i),
            None => self
                .cache
                .iter()
                .enumerate()
                .filter(|(_, c)| c.as_ref().is_some_and(|c| !c.pinned))
                .min_by_key(|(_, c)| c.as_ref().map_or(0, |c| c.used))
                .map(|(i, _)| i),
        };
        let Some(i) = slot else { return false };
        self.cache[i] = Some(Cached { member: member as u8, pinned, pos: pos as u16, used: clock, rec: r.clone() });
        true
    }

    /// After a commit, a compaction or a clear: every cached record of `member` is reloaded from its latest version, or dropped.
    fn revalidate(&mut self, member: usize) {
        let (g, a) = (self.geo, self.m.get(member).and_then(|s| s.active));
        for i in 0..C {
            let Some(c) = self.cache[i].as_ref().filter(|c| c.member as usize == member) else { continue };
            let fresh = match (g, a) {
                (Some(g), Some(a)) => self.latest(&g, member, a, Canon::of(&c.rec), View::Committed).filter(|l| l.1 && l.2.vpn_ip != 0),
                _ => None,
            };
            match (fresh, self.cache[i].as_mut()) {
                (Some((p, _, r)), Some(c)) => {
                    c.pos = p as u16;
                    c.rec = r;
                }
                _ => self.cache[i] = None,
            }
        }
    }

    fn clear_member(&mut self, member: usize, owner: PubKey) {
        self.ensure_mounted();
        let Some(g) = self.geo else { return };
        if member >= M {
            return;
        }
        // what was queued goes too
        let st = &mut self.m[member];
        st.n_queued = 0;
        st.want_copy = false;
        self.consume_staging(member);
        let s = self.m[member];
        let generation = s.generation.wrapping_add(1);
        // a cleared membership must not come back at the next boot: an empty area takes over, or the headers go
        let swapped = s.active.is_some()
            && s.copy.is_none()
            && s.spare_clean as usize == g.area
            && self.write(g.slot_off(member, s.spare(), 0), &header(s.epoch + 1, generation, 0, s.txn, &owner));
        let st = &mut self.m[member];
        if swapped {
            st.active = Some(st.spare());
            st.epoch += 1;
            st.end = 1;
        } else if let Some(a) = s.active {
            // Invalidate the older header first, then the active one: clearing the
            // kind word only programs bits from 1 to 0 and needs no sector erase.
            // Bulk cleanup stays in maintain(), one sector per executor tick.
            // If a write fails, retain the active state rather than claim success.
            if s.spare_clean == 0 && !self.write(g.slot_off(member, 1 - a, 0), &[0; 4]) {
                return;
            }
            if !self.write(g.slot_off(member, a, 0), &[0; 4]) {
                return;
            }
            let st = &mut self.m[member];
            if a == 0 || s.spare_clean == 0 || s.copy.is_some() {
                st.spare_clean = 0;
            }
            st.active = None;
            st.end = 0;
        }
        let st = &mut self.m[member];
        st.copy = None;
        st.count = 0;
        st.n_aborted = 0;
        st.abort_over = false;
        st.generation = generation;
        st.owner = owner;
        if swapped {
            st.spare_clean = 0;
        }
        st.retry_at = 0;
        self.revalidate(member);
    }

    // ---- mount ------------------------------------------------------------------------------------------------------------------------------

    /// Read every membership's areas: take the valid one with the higher epoch and replay its commits. Runs once, on first use. Returns the live peers.
    pub fn mount(&mut self) -> usize {
        if !self.mounted {
            self.mounted = true;
            self.geo = Geometry::of(self.f.borrow().size(), M);
            if let Some(g) = self.geo {
                for m in 0..M {
                    self.mount_member(&g, m);
                }
            }
        }
        self.m.iter().map(|s| s.count as usize).sum()
    }
    fn ensure_mounted(&mut self) {
        if !self.mounted {
            self.mount();
        }
    }

    fn mount_member(&mut self, g: &Geometry, m: usize) {
        let header = |a: u8| self.slot(g, m, a, 0).filter(|b| b[0] == K_HEADER).map(|b| (word(&b, 0), word(&b, 1), word(&b, 2), word(&b, 3)));
        let (h0, h1) = (header(0), header(1));
        let mut s = Member::new();
        s.tx_dirty = g.tx as u32;
        let pick = match (h0, h1) {
            (Some(x), Some(y)) => Some(if y.0 > x.0 { (1, y) } else { (0, x) }),
            (Some(x), None) => Some((0, x)),
            (None, Some(y)) => Some((1, y)),
            (None, None) => None,
        };
        if let Some((a, (epoch, generation, count, txn))) = pick {
            s.active = Some(a);
            if let Some(b) = self.slot(g, m, a, 0) {
                s.owner.copy_from_slice(&b[PAYLOAD + 16..PAYLOAD + 48]);
            }
            s.epoch = epoch;
            s.generation = generation;
            s.count = count;
            s.txn = txn;
            // the transactions after the header: each one's slots are contiguous and end with its COMMIT, or it was torn
            let mut open: Option<(u32, bool)> = None;
            let mut max_txn = txn;
            let mut end = 1;
            let mut b = [0u8; SLOT_BYTES];
            for p in 1..g.slots as u32 {
                if !self.read(g.slot_off(m, a, p as usize), &mut b) {
                    continue;
                }
                if b.iter().all(|&x| x == 0xFF) {
                    continue;
                }
                end = p + 1;
                if !sealed(&b) {
                    continue;
                }
                let t = txn_of(&b);
                if t <= txn {
                    continue; // copied by the compaction that wrote the header
                }
                max_txn = max_txn.max(t);
                match b[0] {
                    K_PUT | K_TOMB => {
                        if open.is_some_and(|o| o.0 != t) {
                            if let Some((o, false)) = open {
                                s.abort(o);
                            }
                            open = None;
                        }
                        open.get_or_insert((t, false));
                    }
                    K_COMMIT => {
                        if let Some((o, false)) = open.filter(|o| o.0 != t) {
                            s.abort(o);
                        }
                        open = Some((t, true));
                        if !s.abort_over {
                            s.txn = t;
                            s.generation = word(&b, 0);
                            s.count = word(&b, 1);
                        }
                    }
                    _ => {}
                }
            }
            if let Some((o, false)) = open {
                s.abort(o);
            }
            s.end = end;
            s.next_txn = max_txn + 1;
        }
        self.m[m] = s;
    }

    // ---- areas, compaction --------------------------------------------------------------------------------------------------------------------

    /// The membership has an active area: a header over the erased spare (the caller checked it is all erased; nothing is erased here).
    fn ensure_area(&mut self, g: &Geometry, m: usize) -> Result<u8, DirError> {
        if let Some(a) = self.m[m].active {
            return Ok(a);
        }
        if (self.m[m].spare_clean as usize) < g.area {
            return Err(DirError);
        }
        let s = self.m[m];
        let epoch = s.epoch + 1;
        if !self.write(g.slot_off(m, 0, 0), &header(epoch, s.generation, 0, s.txn, &s.owner)) {
            return Err(DirError);
        }
        let s = &mut self.m[m];
        s.active = Some(0);
        s.epoch = epoch;
        s.end = 1;
        s.count = 0;
        s.spare_clean = 0;
        Ok(0)
    }
    fn should_compact(&self, g: &Geometry, m: usize) -> bool {
        let s = &self.m[m];
        s.active.is_some()
            && s.end >= s.retry_at
            && ((s.end as usize >= g.slots / 2 && (s.end - s.count) as usize >= g.slots / 8) || s.n_aborted as usize >= ABORTED / 2 || s.abort_over)
    }
    /// One compaction step: copy up to [`COPY_STEP`] slots, or switch areas when the copy has caught up. `Ok(true)`: done.
    fn copy_step(&mut self, g: &Geometry, m: usize) -> Result<bool, DirError> {
        let s = self.m[m];
        let (Some(a), Some((mut cur, mut dst))) = (s.active, s.copy) else { return Ok(true) };
        let d = 1 - a;
        let mut r = Ok(false);
        for _ in 0..COPY_STEP {
            if cur >= s.end {
                break;
            }
            if let Some(raw) = self.slot(g, m, a, cur)
                && (raw[0] == K_PUT || raw[0] == K_TOMB)
                && s.committed(txn_of(&raw))
            {
                let c = Canon::of(&record_of(&raw));
                let latest = self.latest(g, m, a, c, View::Committed).is_some_and(|l| l.0 == cur);
                // a tombstone is copied only over a version this compaction already copied
                let wanted = latest && (raw[0] == K_PUT || self.latest(g, m, d, c, View::All).is_some_and(|l| l.1));
                if wanted && let Err(e) = self.append(g, m, d, &mut dst, &raw) {
                    r = Err(e);
                    break;
                }
            }
            cur += 1;
        }
        if r.is_err() {
            // the live records do not fit (or the spare failed): give up, erase the spare again, retry once the active area has grown
            let s = &mut self.m[m];
            s.copy = None;
            s.spare_clean = 0;
            s.retry_at = s.end + (g.slots / 8) as u32;
            self.bump(|x| x.compactions_failed += 1);
            return r.map(|_| true);
        }
        self.m[m].copy = Some((cur, dst));
        if cur < s.end {
            return Ok(false);
        }
        // caught up: the header is the switch
        let epoch = s.epoch + 1;
        if !self.write(g.slot_off(m, d, 0), &header(epoch, s.generation, s.count, s.txn, &s.owner)) {
            let s = &mut self.m[m];
            s.copy = None;
            s.spare_clean = 0;
            return Err(DirError);
        }
        let s = &mut self.m[m];
        s.active = Some(d);
        s.epoch = epoch;
        s.end = dst;
        s.n_aborted = 0;
        s.abort_over = false;
        s.copy = None;
        s.spare_clean = 0;
        s.retry_at = 0;
        self.bump(|x| x.compactions += 1);
        self.revalidate(m);
        Ok(true)
    }
    /// Whether [`FlashDirectory::maintain`] has work: a staging log or a spare area to erase, a compaction to run.
    pub fn wants_maintenance(&self) -> bool {
        let Some(g) = self.geo else { return !self.mounted };
        (0..M).any(|m| {
            let s = &self.m[m];
            s.n_queued > 0 || s.tx_ready < s.tx_dirty.min(g.tx as u32) || (s.spare_clean as usize) < g.area || s.copy.is_some() || self.should_compact(&g, m)
        })
    }

    /// One bounded step of background work: at most one sector erase, one compaction step, or applying one deferred commit (writes only). Returns whether
    /// there is more.
    pub fn maintain(&mut self) -> bool {
        if !self.mounted {
            self.mount();
            return self.wants_maintenance();
        }
        let Some(g) = self.geo else { return false };
        for m in 0..M {
            // the staging log behind the last commit
            let mut blanks = 0;
            while self.m[m].tx_ready < self.m[m].tx_dirty.min(g.tx as u32) && blanks < BLANK_RUN {
                let sector = g.tx_sector(m, self.m[m].tx_ready as usize);
                let was_blank = self.blank(sector);
                if !was_blank && !self.clean(sector) {
                    return true;
                }
                self.m[m].tx_ready += 1;
                if !was_blank {
                    return true;
                }
                blanks += 1;
            }
            if blanks > 0 {
                return true;
            }
            // a deferred commit whose area is ready
            if self.m[m].n_queued > 0 && !matches!(self.apply_head(&g, m), Apply::Wait) {
                return true;
            }
            // compaction: copy, then switch
            if self.m[m].copy.is_some() {
                let _ = self.copy_step(&g, m);
                return true;
            }
            // the spare area
            if (self.m[m].spare_clean as usize) < g.area {
                let mut blanks = 0;
                while (self.m[m].spare_clean as usize) < g.area && blanks < BLANK_RUN {
                    let s = self.m[m];
                    let sector = g.area_sector(m, s.spare(), s.spare_clean as usize);
                    let was_blank = self.blank(sector);
                    if !was_blank && !self.clean(sector) {
                        return true;
                    }
                    self.m[m].spare_clean += 1;
                    if !was_blank {
                        break;
                    }
                    blanks += 1;
                }
                return true;
            }
            if self.m[m].want_copy {
                // the spare is erased: the compaction a queued commit waits for starts
                self.m[m].want_copy = false;
                if self.m[m].copy.is_none() {
                    self.m[m].copy = Some((1, 1));
                }
                return true;
            }
            if self.should_compact(&g, m) {
                self.m[m].copy = Some((1, 1));
                return true;
            }
        }
        false
    }

    // ---- commit -----------------------------------------------------------------------------------------------------------------------------

    fn read_tx(&self, g: &Geometry, m: usize, i: usize) -> Option<(Action, u32, DirRecord)> {
        let mut b = [0u8; SLOT_BYTES];
        if !self.read(g.tx_sector(m, 0) * SECTOR + i * SLOT_BYTES, &mut b) {
            return None;
        }
        let action = match b[0] {
            0 => Action::Add,
            1 => Action::Remove,
            2 => Action::UpdateEndpoint,
            _ => return None,
        };
        Some((action, u32::from_le_bytes([b[1], b[2], b[3], b[4]]), record_of(&b)))
    }

    fn put(&self, g: &Geometry, m: usize, a: u8, end: &mut u32, cx: &mut Ctx, v: &DirRecord) -> Result<(), DirError> {
        let cur = self.latest(g, m, a, Canon::of(v), View::Pending(cx.txn));
        if let Some((p, true, e)) = &cur
            && dirfmt::encode_record(e) == dirfmt::encode_record(v)
        {
            // unchanged: nothing is written, an authoritative map only notes it saw the record
            if cx.auth && *p < cx.start {
                set_bit(&mut cx.seen, *p);
            }
            return Ok(());
        }
        self.append(g, m, a, end, &seal(K_PUT, cx.txn, &dirfmt::encode_record(v)))?;
        if !cur.is_some_and(|c| c.1) {
            cx.count += 1;
        }
        Ok(())
    }
    fn tomb(&self, g: &Geometry, m: usize, a: u8, end: &mut u32, cx: &mut Ctx, c: Canon) -> Result<(), DirError> {
        if self.latest(g, m, a, c, View::Pending(cx.txn)).is_some_and(|l| l.1) {
            self.append(g, m, a, end, &seal(K_TOMB, cx.txn, &dirfmt::encode_record(&c.record())))?;
            cx.count -= 1;
        }
        Ok(())
    }
    /// Replace `old` (when there is one) by `v`.
    // Explicit transaction geometry and cursor arguments keep flash ownership visible.
    #[allow(clippy::too_many_arguments)]
    fn replace(&self, g: &Geometry, m: usize, a: u8, end: &mut u32, cx: &mut Ctx, old: Option<&DirRecord>, v: &DirRecord) -> Result<(), DirError> {
        if let Some(e) = old
            && Canon::of(e) != Canon::of(v)
        {
            self.tomb(g, m, a, end, cx, Canon::of(e))?;
        }
        self.put(g, m, a, end, cx, v)
    }

    // Explicit transaction geometry and cursor arguments keep flash ownership visible.
    #[allow(clippy::too_many_arguments)]
    fn commit_body(&self, g: &Geometry, m: usize, a: u8, end: &mut u32, cx: &mut Ctx, lo: usize, hi: usize) -> Result<(), DirError> {
        for pass in 0..3u8 {
            for i in lo..hi {
                let (action, group, u) = self.read_tx(g, m, i).ok_or(DirError)?;
                if cx.auth && group == 6 {
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
                // the full list of an authoritative map: by identity
                let found = if cx.auth && group == 2 && action == Action::Add {
                    self.latest(g, m, a, Canon::of(&u), cx.view()).filter(|l| l.1).map(|l| (l.0, l.2))
                } else {
                    self.find_same(g, m, a, &u, cx.view())
                };
                match (action, found) {
                    (Action::Add, f) => self.replace(g, m, a, end, cx, f.as_ref().map(|f| &f.1), &u)?,
                    (Action::Remove, Some((_, e))) => self.tomb(g, m, a, end, cx, Canon::of(&e))?,
                    (Action::UpdateEndpoint, Some((_, e))) => {
                        let v = patch(e.clone(), &u);
                        self.replace(g, m, a, end, cx, Some(&e), &v)?;
                    }
                    _ => {}
                }
            }
        }
        if cx.auth {
            // omission removes: every live record the map did not carry
            for p in 1..cx.start {
                let Some(raw) = self.slot(g, m, a, p) else { continue };
                if raw[0] != K_PUT || bit(&cx.seen, p) || !self.m[m].committed(txn_of(&raw)) {
                    continue;
                }
                let c = Canon::of(&record_of(&raw));
                if self.latest(g, m, a, c, View::Pending(cx.txn)).is_some_and(|l| l.0 == p) {
                    self.tomb(g, m, a, end, cx, c)?;
                }
            }
        }
        let generation = self.m[m].generation.wrapping_add(1);
        self.append(g, m, a, end, &seal(K_COMMIT, cx.txn, &words(&[generation, cx.count.max(0) as u32])))?;
        if self.io_error.get() { Err(DirError) } else { Ok(()) }
    }

    /// Apply the oldest queued commit of `m` if its area is ready. Never erases: an area that is not erased yet, or a compaction it needs, makes it wait
    /// for [`FlashDirectory::maintain`]. Meanwhile the previous generation keeps serving lookups.
    fn apply_head(&mut self, g: &Geometry, m: usize) -> Apply {
        let s = self.m[m];
        let Some(&q) = s.queue.first().filter(|_| s.n_queued > 0) else { return Apply::Done };
        let r = self.try_apply(g, m, q);
        if !matches!(r, Apply::Wait) {
            let s = &mut self.m[m];
            s.queue.copy_within(1..QUEUED, 0);
            s.n_queued -= 1;
            s.want_copy = false;
            if matches!(r, Apply::Failed) {
                self.bump(|x| x.commits_failed += 1);
            }
            let s = self.m[m];
            if s.n_queued == 0 && s.open == s.staged {
                self.consume_staging(m);
            }
        }
        r
    }

    fn try_apply(&mut self, g: &Geometry, m: usize, q: Queued) -> Apply {
        let s = self.m[m];
        if s.want_copy || (q.compacted && s.copy.is_some()) {
            return Apply::Wait;
        }
        if s.active.is_none() {
            if (s.spare_clean as usize) < g.area {
                return Apply::Wait;
            }
            if self.ensure_area(g, m).is_err() {
                return Apply::Failed;
            }
        }
        let need_compaction = |d: &mut Self| {
            let s = &mut d.m[m];
            // full: the last compaction could not make room, or this commit already had one
            if q.compacted || s.retry_at > s.end {
                return Apply::Failed;
            }
            s.queue[0].compacted = true;
            // one already running will do (the head waits for it); otherwise one starts once the spare is erased
            s.want_copy = s.copy.is_none();
            d.bump(|x| x.sync_compactions += 1);
            Apply::Wait
        };
        if self.m[m].short(g) {
            return need_compaction(self);
        }
        let s = self.m[m];
        let Some(a) = s.active else { return Apply::Failed };
        let mut cx = Ctx { txn: s.next_txn, start: s.end, auth: q.auth, seen: Vec::new(), count: i64::from(s.count) };
        if q.auth {
            let words = (s.end as usize).div_ceil(64);
            if cx.seen.try_reserve_exact(words).is_err() {
                return Apply::Failed;
            }
            cx.seen.resize(words, 0);
        }
        self.m[m].next_txn += 1;
        self.io_error.set(false);
        self.full.set(false);
        let mut end = s.end;
        let r = self.commit_body(g, m, a, &mut end, &mut cx, q.lo.into(), q.hi.into());
        let st = &mut self.m[m];
        st.end = end;
        match r {
            Ok(()) => {
                st.txn = cx.txn;
                st.generation = st.generation.wrapping_add(1);
                st.count = cx.count.max(0) as u32;
                st.overflow = 0;
                self.revalidate(m);
                Apply::Done
            }
            Err(_) => {
                st.abort(cx.txn);
                // unchanged records cost nothing, so the room a map needs is not known before it runs: one that runs out is retried once over a
                // compacted area
                if self.full.get() && !self.io_error.get() { need_compaction(self) } else { Apply::Failed }
            }
        }
    }

    fn consume_staging(&mut self, m: usize) {
        let s = &mut self.m[m];
        let used = (s.staged as usize).div_ceil(PER_SECTOR) as u32;
        s.tx_dirty = used.max(if s.tx_ready < s.tx_dirty { s.tx_dirty } else { 0 });
        s.tx_ready = 0;
        s.staged = 0;
        s.open = 0;
    }

    /// Drop the map being received: its slots of the staging log are skipped, the whole log is recycled once nothing queued needs it.
    fn drop_open(&mut self, m: usize) {
        let s = &mut self.m[m];
        s.open = s.staged;
        if s.n_queued == 0 {
            self.consume_staging(m);
        }
    }

    /// Call `f` with every live record of `member` (diagnostics: reads the whole active area).
    fn scan(&self, member: usize, f: &mut dyn FnMut(&DirRecord) -> bool) {
        let (Some(g), Some(s)) = (self.geo, self.m.get(member)) else { return };
        let Some(a) = s.active else { return };
        for p in 1..s.end {
            let Some(raw) = self.slot(&g, member, a, p) else { continue };
            if raw[0] != K_PUT || !s.committed(txn_of(&raw)) {
                continue;
            }
            let r = record_of(&raw);
            if r.vpn_ip != 0 && self.latest(&g, member, a, Canon::of(&r), View::Committed).is_some_and(|l| l.0 == p) && !f(&r) {
                return;
            }
        }
    }
}

impl<F: DirFlash, const M: usize, const C: usize> core::fmt::Debug for FlashDirectory<F, M, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FlashDirectory({M} members, cache of {C})")
    }
}

impl<F: DirFlash, const M: usize, const C: usize> PeerDirectory for FlashDirectory<F, M, C> {
    fn find_by_key(&mut self, member: usize, key: &PubKey) -> Option<DirRecord> {
        let k = *key;
        self.lookup(member, T_KEY, h_key(key), &move |r| r.public_key == k)
    }
    fn find_by_ip(&mut self, member: usize, ip: u32) -> Option<DirRecord> {
        if ip == 0 {
            return None;
        }
        self.lookup(member, T_IP, h_ip(ip), &move |r| r.vpn_ip == ip)
    }
    fn find_by_disco(&mut self, member: usize, key: &PubKey) -> Option<DirRecord> {
        let k = *key;
        self.lookup(member, T_DISCO, h_disco(key), &move |r| r.disco_key == k)
    }
    fn stage(&mut self, member: usize, rec: &PeerRecord) -> Result<(), DirError> {
        self.ensure_mounted();
        let g = self.geo.ok_or(DirError)?;
        if member >= M {
            return Err(DirError);
        }
        if rec.action == PeerAction::Add && !is_storable(rec) {
            return Ok(());
        }
        let i = self.m[member].staged as usize;
        // the queue keeps staging-log indices as u16
        if i >= g.tx_slots().min(u16::MAX as usize) {
            // a map with more updates than the log holds keeps what fits and counts the rest
            self.m[member].stage_dropped = self.m[member].stage_dropped.saturating_add(1);
            return Ok(());
        }
        let sector = i / PER_SECTOR;
        let s = self.m[member];
        if i.is_multiple_of(PER_SECTOR) && (sector as u32) >= s.tx_ready && (sector as u32) < s.tx_dirty {
            // the background has not erased this one yet
            if !self.clean(g.tx_sector(member, sector)) {
                return Err(DirError);
            }
            self.m[member].tx_ready = sector as u32 + 1;
        }
        let mut b = [0u8; SLOT_BYTES];
        b[0] = action_of(rec.action) as u8;
        b[1..5].copy_from_slice(&(rec.group as u32).to_le_bytes());
        b[PAYLOAD..PAYLOAD + RECORD_BYTES].copy_from_slice(&dirfmt::encode_record(&to_dir_record(rec)));
        if !self.write(g.tx_sector(member, 0) * SECTOR + i * SLOT_BYTES, &b) {
            return Err(DirError);
        }
        self.m[member].staged += 1;
        Ok(())
    }
    fn commit(&mut self, member: usize, authoritative: bool) -> Result<(), DirError> {
        self.ensure_mounted();
        if member >= M {
            return Err(DirError);
        }
        let Some(g) = self.geo else { return Err(DirError) };
        let s = self.m[member];
        if s.n_queued as usize >= QUEUED {
            self.bump(|x| x.queue_full += 1);
            self.drop_open(member);
            return Err(DirError);
        }
        let st = &mut self.m[member];
        st.queue[st.n_queued as usize] = Queued { lo: s.open as u16, hi: s.staged as u16, auth: authoritative, compacted: false };
        st.n_queued += 1;
        st.open = s.staged;
        if s.n_queued > 0 {
            // behind an earlier one: applied in order
            self.bump(|x| x.deferred_commits += 1);
            return Ok(());
        }
        match self.apply_head(&g, member) {
            Apply::Done => Ok(()),
            Apply::Failed => Err(DirError),
            Apply::Wait => {
                self.bump(|x| x.deferred_commits += 1);
                Ok(())
            }
        }
    }
    fn abort(&mut self, member: usize) {
        if member < M {
            self.drop_open(member);
        }
    }
    fn attach(&mut self, member: usize, owner: &PubKey) -> bool {
        self.ensure_mounted();
        if member < M && (self.m[member].owner == [0; 32] || self.m[member].owner != *owner) {
            self.clear_member(member, *owner);
        }
        member < M && *owner != [0; 32] && self.m[member].owner == *owner
    }
    fn clear(&mut self, member: usize) {
        if member < M {
            self.clear_member(member, self.m[member].owner);
        }
    }
    fn count(&self, member: usize) -> usize {
        self.m.get(member).map_or(0, |s| s.count as usize)
    }
    fn peer_view(&self, _member: usize, _j: usize) -> Option<(&str, u32)> {
        None // records are in flash: see `for_each_peer` and `for_each_named`
    }
    fn for_each_peer(&self, member: usize, f: &mut dyn FnMut(&str, PeerInfo) -> bool) {
        self.scan(member, &mut |r| f(r.hostname.as_str(), info_of(r)));
    }
    fn for_each_named(&self, member: usize, label: &[u8], f: &mut dyn FnMut(&str, u32)) -> bool {
        let (Some(g), Some(s)) = (self.geo, self.m.get(member)) else { return true };
        let Some(a) = s.active else { return true };
        self.io_error.set(false);
        self.probe(&g, member, a, T_NAME, h_name(label), |p| {
            if let Some(raw) = self.slot(&g, member, a, p)
                && raw[0] == K_PUT
                && s.committed(txn_of(&raw))
            {
                let r = record_of(&raw);
                if r.vpn_ip != 0
                    && first_label(r.hostname.as_str()).eq_ignore_ascii_case(label)
                    && self.latest(&g, member, a, Canon::of(&r), View::Committed).is_some_and(|l| l.0 == p)
                {
                    f(r.hostname.as_str(), r.vpn_ip);
                }
            }
            true
        });
        !self.io_error.get()
    }
    fn pin(&mut self, member: usize, keys: &[PubKey]) {
        for c in self.cache.iter_mut().flatten().filter(|c| c.member as usize == member) {
            c.pinned = keys.contains(&c.rec.public_key);
        }
        for k in keys {
            if self.cache.iter().flatten().any(|c| c.member as usize == member && c.rec.public_key == *k) {
                continue;
            }
            if !self.cache.iter().any(|c| c.as_ref().is_none_or(|c| !c.pinned)) {
                self.bump(|s| s.pins_refused += 1);
                continue;
            }
            if self.find_by_key(member, k).is_some()
                && let Some(c) = self.cache.iter_mut().flatten().find(|c| c.member as usize == member && c.rec.public_key == *k)
            {
                c.pinned = true;
            }
        }
    }
    fn maintain(&mut self) -> bool {
        FlashDirectory::maintain(self)
    }
    fn wants_maintenance(&self) -> bool {
        FlashDirectory::wants_maintenance(self)
    }
    fn generation(&self, member: usize) -> u32 {
        self.m.get(member).map_or(0, |s| s.generation)
    }
    fn overflow(&self, member: usize) -> (u32, u32) {
        self.m.get(member).map_or((0, 0), |s| (s.overflow, s.stage_dropped))
    }
    fn commit_cost(&self, member: usize) -> usize {
        // the authoritative commit's seen-bitmap and a few records on the stack
        self.m.get(member).map_or(0, |s| (s.end as usize).div_ceil(8)) + 256
    }
}

// ---- the in-memory flash ------------------------------------------------------------------------------------------------------------------------------

/// A flash in memory that enforces the rules of the real one: erase to 0xFF a sector at a time, programming only clears bits.
/// It can lose power: at the n-th write from now, which is then programmed only in part (torn), and every operation after it fails until `power_on`.
pub struct MemFlash {
    /// The bytes.
    pub d: Vec<u8>,
    /// Fail the n-th write from now, when set (power loss mid-commit). The failing write programs `torn_bytes` of its data first.
    pub fail_after: Option<usize>,
    /// Bytes of the failing write that reach the flash.
    pub torn_bytes: usize,
    /// Power is off: every operation fails.
    pub dead: bool,
    /// Writes so far.
    pub writes: usize,
    /// Sector erases so far.
    pub erases: usize,
    /// Reads so far.
    pub reads: core::cell::Cell<usize>,
}
impl core::fmt::Debug for MemFlash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MemFlash({} bytes, {} writes, {} reads, {} erases)", self.d.len(), self.writes, self.reads.get(), self.erases)
    }
}
impl MemFlash {
    /// An erased flash of `bytes`.
    pub fn new(bytes: usize) -> Self {
        Self { d: alloc::vec![0xFF; bytes], fail_after: None, torn_bytes: 0, dead: false, writes: 0, erases: 0, reads: core::cell::Cell::new(0) }
    }
    /// Lose power at the `n`-th write from now, `torn` bytes of it programmed.
    pub fn cut_after(&mut self, n: usize, torn: usize) {
        self.fail_after = Some(self.writes + n);
        self.torn_bytes = torn;
    }
    /// Power back (a reboot): the bytes are what they were.
    pub fn power_on(&mut self) {
        self.dead = false;
        self.fail_after = None;
    }
}
impl DirFlash for MemFlash {
    fn read(&mut self, o: usize, b: &mut [u8]) -> bool {
        if self.dead || o + b.len() > self.d.len() {
            return false;
        }
        self.reads.set(self.reads.get() + 1);
        b.copy_from_slice(&self.d[o..o + b.len()]);
        true
    }
    fn erase_sector(&mut self, s: usize) -> bool {
        if self.dead || (s + 1) * SECTOR > self.d.len() {
            return false;
        }
        self.erases += 1;
        self.d[s * SECTOR..(s + 1) * SECTOR].fill(0xFF);
        true
    }
    fn write(&mut self, o: usize, data: &[u8]) -> bool {
        if self.dead || o + data.len() > self.d.len() {
            return false;
        }
        self.writes += 1;
        let n = if self.fail_after.is_some_and(|n| self.writes > n) {
            self.dead = true;
            self.torn_bytes.min(data.len())
        } else {
            data.len()
        };
        for (i, &x) in data[..n].iter().enumerate() {
            assert!(self.d[o + i] & x == x, "write sets programmed flash bits at {}", o + i);
            self.d[o + i] = x;
        }
        !self.dead
    }
    fn size(&self) -> usize {
        self.d.len()
    }
}

#[cfg(test)]
mod tests;
