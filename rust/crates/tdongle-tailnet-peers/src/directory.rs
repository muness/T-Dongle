//! The flash peer directory: image codec, delta application and alias log (`ml_directory.c`, ADR 0012).
//!
//! Each membership's directory is a pair of banks (`<key>.a`, `<key>.b`) of fixed-size records between a header and a CRC-32 trailer. A map is
//! staged separately as an operation log (`.tx`); only a complete, checksummed generation is published, written to the bank that is NOT current, so
//! a failed write leaves the previous complete generation intact. Boot validates both banks and picks the valid one with the higher generation.
//! A saved record does not authorize a session: a current authoritative map must be committed first ([`crate::membership::Membership::session_valid`]).
//!
//! This module is the pure part: the byte formats, the validation, the bank choice, and the three-pass application of staged operations over any
//! [`RecordFile`]. Reading and writing flash files is the firmware's, behind [`ReadAt`] and [`RecordFile`].
//!
//! # Format
//!
//! Little endian. `header { magic "PDR1", version, record_bytes, generation }` (16 bytes), `count` records of [`RECORD_BYTES`], `crc32` of everything
//! before it (standard CRC-32, stored as `!crc` as the C does). The C stored its native 288-byte struct as **version 1**; this crate writes its own
//! packed record as **version 2**. The C's banks fail validation here (size mismatch) and the directory is rebuilt from the next authoritative map,
//! exactly as after a torn write: it is a cache of the control plane, never the source of truth.
//!
//! The alias file (`aliases`) is an append-only log of 16-byte entries `{id, peer, alias, crc32}`, byte-compatible with the C: a torn tail is
//! truncated before the next append, and entries with a bad CRC are skipped.

use crate::record::{Action, DirRecord, Endpoint, MICROLINK_MAX_PEER_ROUTES, ML_MAX_ENDPOINTS, Route};
use tdongle_tailnet_types::FixedStr;

/// `DIRECTORY_MAGIC`: "PDR1".
pub const DIRECTORY_MAGIC: u32 = 0x5044_5231;
/// This crate's record format. The C's native-struct banks are version 1 and are not read.
pub const DIRECTORY_VERSION: u32 = 2;
/// `sizeof(dir_header)`.
pub const HEADER_BYTES: usize = 16;
/// Bytes of one packed record.
pub const RECORD_BYTES: usize = 242;
/// Bytes of the CRC trailer.
pub const TRAILER_BYTES: usize = 4;
/// Alias entry bytes (`{id, peer, alias}` plus CRC).
pub const ALIAS_ENTRY_BYTES: usize = 16;

/// Random access to a stored file (flash, or a slice in tests).
pub trait ReadAt {
    /// Length in bytes.
    fn len(&self) -> usize;
    /// True when empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Fill `buf` from `offset`; false when out of range or on an I/O error.
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> bool;
}

impl ReadAt for &[u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> bool {
        match offset.checked_add(buf.len()) {
            Some(end) if end <= <[u8]>::len(self) => {
                buf.copy_from_slice(&self[offset..end]);
                true
            }
            _ => false,
        }
    }
}

/// `crc_bytes`: update a reflected CRC-32 (polynomial 0xEDB88320) state; start from `!0` and finish with `!`.
#[must_use]
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

/// The standard CRC-32 of `data` (`!crc_bytes(!0, data)`).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

/// What validation learned about a bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BankInfo {
    /// The generation counter in the header.
    pub generation: u32,
    /// Number of records (including removed ones, whose `vpn_ip` is zero).
    pub count: u32,
}

/// The 16-byte header of a bank with `generation`.
#[must_use]
pub fn encode_header(generation: u32) -> [u8; HEADER_BYTES] {
    let mut h = [0u8; HEADER_BYTES];
    h[0..4].copy_from_slice(&DIRECTORY_MAGIC.to_le_bytes());
    h[4..8].copy_from_slice(&DIRECTORY_VERSION.to_le_bytes());
    h[8..12].copy_from_slice(&(RECORD_BYTES as u32).to_le_bytes());
    h[12..16].copy_from_slice(&generation.to_le_bytes());
    h
}

/// `validate`: header, size arithmetic and CRC of a bank image. `None` when any of them is wrong.
pub fn validate(f: &impl ReadAt) -> Option<BankInfo> {
    let n = f.len();
    let mut h = [0u8; HEADER_BYTES];
    if !f.read_at(0, &mut h) {
        return None;
    }
    let word = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    if word(0) != DIRECTORY_MAGIC || word(4) != DIRECTORY_VERSION || word(8) != RECORD_BYTES as u32 {
        return None;
    }
    if n < HEADER_BYTES + TRAILER_BYTES || !(n - HEADER_BYTES - TRAILER_BYTES).is_multiple_of(RECORD_BYTES) {
        return None;
    }
    let count = ((n - HEADER_BYTES - TRAILER_BYTES) / RECORD_BYTES) as u32;
    let crc = image_crc(f, n - TRAILER_BYTES)?;
    let mut stored = [0u8; 4];
    if !f.read_at(n - TRAILER_BYTES, &mut stored) || u32::from_le_bytes(stored) != crc {
        return None;
    }
    Some(BankInfo { generation: word(12), count })
}

/// The value to store as the trailer of the first `len` bytes of `f` (`!crc`), read in 256-byte chunks.
pub fn image_crc(f: &impl ReadAt, len: usize) -> Option<u32> {
    let (mut crc, mut at) = (!0u32, 0usize);
    let mut chunk = [0u8; 256];
    while at < len {
        let take = (len - at).min(chunk.len());
        if !f.read_at(at, &mut chunk[..take]) {
            return None;
        }
        crc = crc32_update(crc, &chunk[..take]);
        at += take;
    }
    Some(!crc)
}

/// Boot: the bank to read. The valid bank with the higher generation wins; a tie goes to bank 0 (the C's loop order).
#[must_use]
pub fn select_bank(a: Option<BankInfo>, b: Option<BankInfo>) -> Option<(u8, BankInfo)> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.generation > x.generation { (1, y) } else { (0, x) }),
        (Some(x), None) => Some((0, x)),
        (None, Some(y)) => Some((1, y)),
        (None, None) => None,
    }
}

/// The bank a commit writes: the one that is not current (bank 0 when there is none).
#[must_use]
pub const fn next_bank(current: Option<u8>) -> u8 {
    match current {
        Some(0) => 1,
        _ => 0,
    }
}

/// Pack a record.
#[must_use]
pub fn encode_record(r: &DirRecord) -> [u8; RECORD_BYTES] {
    let mut o = [0u8; RECORD_BYTES];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        o[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(&r.vpn_ip.to_le_bytes());
    put(&r.public_key);
    put(&r.disco_key);
    let mut name = [0u8; 64];
    name[..r.hostname.len()].copy_from_slice(r.hostname.as_str().as_bytes());
    put(&name);
    put(&r.derp_region.to_le_bytes());
    put(&[r.endpoint_count.clamp(-1, ML_MAX_ENDPOINTS as i32) as i8 as u8]);
    for e in &r.endpoints {
        put(&e.ip.to_le_bytes());
        put(&e.port.to_le_bytes());
        put(&[u8::from(e.is_ipv6)]);
    }
    put(&[u8::from(r.is_exit_node), r.subnet_route_count.min(MICROLINK_MAX_PEER_ROUTES as u8)]);
    for rt in &r.subnet_routes {
        put(&rt.network.to_le_bytes());
        put(&[rt.prefix_len]);
    }
    put(&[u8::from(r.has_online) | u8::from(r.online) << 1 | u8::from(r.has_node_id) << 2]);
    put(&r.node_id.to_le_bytes());
    debug_assert_eq!(at, RECORD_BYTES);
    o
}

/// Unpack a record. Total: every byte pattern decodes (counts are clamped, a hostname that is not UTF-8 is cut at the first bad byte).
#[must_use]
pub fn decode_record(b: &[u8; RECORD_BYTES]) -> DirRecord {
    let mut at = 0;
    let mut take = |n: usize| {
        let s = &b[at..at + n];
        at += n;
        s
    };
    let u32le = |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
    let mut r = DirRecord { vpn_ip: u32le(take(4)), ..DirRecord::default() };
    r.public_key.copy_from_slice(take(32));
    r.disco_key.copy_from_slice(take(32));
    let name = take(64);
    let end = name.iter().position(|&c| c == 0).unwrap_or(64);
    let valid = match core::str::from_utf8(&name[..end]) {
        Ok(s) => s,
        Err(e) => core::str::from_utf8(&name[..e.valid_up_to()]).unwrap_or(""),
    };
    r.hostname = FixedStr::new();
    r.hostname.set(valid);
    let d = take(2);
    r.derp_region = u16::from_le_bytes([d[0], d[1]]);
    r.endpoint_count = i32::from((take(1)[0] as i8).clamp(-1, ML_MAX_ENDPOINTS as i8));
    for e in &mut r.endpoints {
        let s = take(7);
        *e = Endpoint { ip: u32le(s), port: u16::from_le_bytes([s[4], s[5]]), is_ipv6: s[6] != 0 };
    }
    let f = take(2);
    r.is_exit_node = f[0] != 0;
    r.subnet_route_count = f[1].min(MICROLINK_MAX_PEER_ROUTES as u8);
    for rt in &mut r.subnet_routes {
        let s = take(5);
        *rt = Route { network: u32le(s), prefix_len: s[4].min(32) };
    }
    let flags = take(1)[0];
    r.has_online = flags & 1 != 0;
    r.online = flags & 2 != 0;
    r.has_node_id = flags & 4 != 0;
    let n = take(8);
    r.node_id = u64::from_le_bytes([n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]]);
    r
}

/// One staged operation (`dir_operation`): `group` is the map section it came from (2 = the full peer list, 6 = discarded by an authoritative
/// commit), `action` what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    /// Map section code.
    pub group: u32,
    /// Add, remove or update endpoints.
    pub action: Action,
    /// The record (for `Remove`, only its identity matters).
    pub record: DirRecord,
}

/// A bank being built: records addressed by index.
pub trait RecordFile {
    /// I/O error.
    type Error;
    /// Records so far (the header is not counted).
    fn count(&self) -> usize;
    /// Read record `i`.
    fn read(&mut self, i: usize) -> Result<DirRecord, Self::Error>;
    /// Overwrite record `i`.
    fn write(&mut self, i: usize, r: &DirRecord) -> Result<(), Self::Error>;
    /// Append a record.
    fn append(&mut self, r: &DirRecord) -> Result<(), Self::Error>;
}

/// The staged operations, replayable from the start (three passes read them).
pub trait OpLog {
    /// I/O error.
    type Error;
    /// Call `f` on every operation in order; stop at the first error.
    fn replay(&mut self, f: &mut dyn FnMut(&Op) -> Result<(), Self::Error>) -> Result<(), Self::Error>;
}

impl OpLog for &[Op] {
    type Error = core::convert::Infallible;
    fn replay(&mut self, f: &mut dyn FnMut(&Op) -> Result<(), Self::Error>) -> Result<(), Self::Error> {
        self.iter().try_for_each(f)
    }
}

/// `same`: does stored record `a` stand for update `b`? By node id when both carry one, else by public key when the update has no id.
#[must_use]
pub fn same(a: &DirRecord, b: &DirRecord) -> bool {
    (a.has_node_id && b.has_node_id && a.node_id == b.node_id) || (!b.has_node_id && a.public_key == b.public_key)
}

/// `apply`: one operation against the bank under construction. Records with `vpn_ip == 0` are empty slots, reused before the file grows.
pub fn apply<F: RecordFile>(f: &mut F, action: Action, u: &DirRecord) -> Result<(), F::Error> {
    let (mut found, mut empty) = (None, None);
    for i in 0..f.count() {
        let old = f.read(i)?;
        if old.vpn_ip == 0 {
            if empty.is_none() {
                empty = Some(i);
            }
            continue;
        }
        if same(&old, u) {
            found = Some((i, old));
            break;
        }
    }
    if action != Action::Add && found.is_none() {
        return Ok(());
    }
    let value = match (action, &found) {
        (Action::Remove, _) => DirRecord::default(),
        (Action::UpdateEndpoint, Some((_, old))) => {
            let mut v = old.clone();
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
        _ => u.clone(),
    };
    match found.map(|(i, _)| i).or(empty) {
        Some(at) => f.write(at, &value),
        None => f.append(&value),
    }
}

/// `ml_directory_commit`'s body: build the next generation in `out` (which is empty). A partial update (`authoritative == false`) starts from the
/// live records of `previous`; an authoritative one starts empty, so omission removes. Then the staged operations in three passes (adds, then
/// removes, then endpoint updates), whatever their order in the map: an add and a remove of the same peer in one map therefore ends removed. Section 6 is dropped from an
/// authoritative map. Any error leaves `out` unusable and the previous generation untouched: the caller discards `out`.
pub fn commit<E, O, P, L>(out: &mut O, previous: Option<&mut P>, ops: &mut L, authoritative: bool) -> Result<(), E>
where
    O: RecordFile<Error = E>,
    P: RecordFile<Error = E>,
    L: OpLog<Error = E>,
{
    if !authoritative && let Some(prev) = previous {
        for i in 0..prev.count() {
            let r = prev.read(i)?;
            if r.vpn_ip != 0 {
                out.append(&r)?;
            }
        }
    }
    for pass in 0..3u8 {
        ops.replay(&mut |op| {
            if authoritative && op.group == 6 {
                return Ok(());
            }
            let order = match op.action {
                Action::Add => 0,
                Action::Remove => 1,
                Action::UpdateEndpoint => 2,
            };
            if pass != order {
                return Ok(());
            }
            if authoritative && op.group == 2 && op.action == Action::Add { out.append(&op.record) } else { apply(out, op.action, &op.record) }
        })?;
    }
    Ok(())
}

/// `ml_directory_find`'s predicate: a live record matches by IP, node id, public key or disco key. Zero/`None` arguments do not match.
#[must_use]
pub fn matches(r: &DirRecord, ip: u32, node_id: u64, key: Option<&[u8; 32]>, disco: Option<&[u8; 32]>) -> bool {
    r.vpn_ip != 0
        && ((ip != 0 && r.vpn_ip == ip)
            || (node_id != 0 && r.node_id == node_id)
            || key.is_some_and(|k| *k == r.public_key)
            || disco.is_some_and(|k| *k == r.disco_key))
}

/// `ml_directory_alias_t`: a stable USB alias address for a peer of a membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasRecord {
    /// Membership id.
    pub id: u32,
    /// Peer id.
    pub peer: u32,
    /// The alias address.
    pub alias: u32,
}

/// One 16-byte log entry.
#[must_use]
pub fn encode_alias(a: &AliasRecord) -> [u8; ALIAS_ENTRY_BYTES] {
    let mut e = [0u8; ALIAS_ENTRY_BYTES];
    e[0..4].copy_from_slice(&a.id.to_le_bytes());
    e[4..8].copy_from_slice(&a.peer.to_le_bytes());
    e[8..12].copy_from_slice(&a.alias.to_le_bytes());
    let crc = crc32(&e[..12]);
    e[12..16].copy_from_slice(&crc.to_le_bytes());
    e
}

fn decode_alias(e: &[u8; ALIAS_ENTRY_BYTES]) -> Option<AliasRecord> {
    let w = |i: usize| u32::from_le_bytes([e[i], e[i + 1], e[i + 2], e[i + 3]]);
    (w(12) == crc32(&e[..12])).then(|| AliasRecord { id: w(0), peer: w(4), alias: w(8) })
}

/// `ml_directory_alias_scan`: every valid entry in file order; a torn tail and corrupt entries are skipped. Returns how many were visited.
pub fn alias_scan(f: &impl ReadAt, mut visit: impl FnMut(&AliasRecord)) -> usize {
    let mut n = 0;
    let mut e = [0u8; ALIAS_ENTRY_BYTES];
    let mut at = 0;
    while at + ALIAS_ENTRY_BYTES <= f.len() && f.read_at(at, &mut e) {
        if let Some(a) = decode_alias(&e) {
            visit(&a);
            n += 1;
        }
        at += ALIAS_ENTRY_BYTES;
    }
    n
}

/// `ml_directory_alias_find`: by alias when `alias != 0`, else by `(id, peer)`. The first valid match in file order.
pub fn alias_find(f: &impl ReadAt, id: u32, peer: u32, alias: u32) -> Option<AliasRecord> {
    let mut e = [0u8; ALIAS_ENTRY_BYTES];
    let mut at = 0;
    while at + ALIAS_ENTRY_BYTES <= f.len() && f.read_at(at, &mut e) {
        if let Some(a) = decode_alias(&e)
            && ((alias != 0 && a.alias == alias) || (alias == 0 && a.id == id && a.peer == peer))
        {
            return Some(a);
        }
        at += ALIAS_ENTRY_BYTES;
    }
    None
}

/// `ml_directory_alias_save`: where the next entry goes: the file is truncated to whole entries first (a torn tail is cut off), then appended.
#[must_use]
pub const fn alias_append_offset(file_len: usize) -> usize {
    file_len - file_len % ALIAS_ENTRY_BYTES
}
