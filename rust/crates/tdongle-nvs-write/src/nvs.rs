//! The storage engine: a port of the write side of `nvs_page.cpp`, `nvs_pagemanager.cpp` and `nvs_storage.cpp` of ESP-IDF v5.5.
//!
//! On-flash format (one 4096-byte page): 32-byte header (`state:u32`, `seq:u32`, `version:u8` (0xFE = v2), 19 reserved bytes of 0xFF,
//! `crc32` of bytes 4..28), a 32-byte entry-state table (2 bits per entry: `11` empty, `10` written, `00` erased), 126 entries of 32 bytes.
//! An item is a header entry (`ns`, `type`, `span`, `chunk`, `crc32` over bytes 0..4 and 8..32, 15-byte key + NUL, 8 data bytes) followed by
//! `span - 1` data entries for strings and blobs.

use crate::crc::crc32;
use crate::{Error, Flash};

/// Bytes per page (flash sector).
pub const PAGE_SIZE: usize = 4096;
/// Bytes per entry.
pub const ENTRY_SIZE: usize = 32;
/// Entries per page.
pub const ENTRY_COUNT: usize = 126;
/// The largest partition the engine handles, in pages (128 KiB).
pub const MAX_PAGES: usize = 32;
/// The smallest partition IDF accepts (one spare page, two for data).
pub const MIN_PAGES: usize = 3;

const CHUNK_MAX: usize = ENTRY_SIZE * (ENTRY_COUNT - 1);
const TABLE_OFF: u32 = 32;
const ENTRIES_OFF: u32 = 64;
const CHUNK_ANY: u8 = 0xff;
const VER_0: u8 = 0x00;
const VER_1: u8 = 0x80;
const NVS_VERSION: u8 = 0xfe;

const PS_ACTIVE: u32 = 0xffff_fffe;
const PS_FULL: u32 = 0xffff_fffc;
const PS_FREEING: u32 = 0xffff_fff8;

const ES_ERASED: u8 = 0;
const ES_ILLEGAL: u8 = 1;
const ES_WRITTEN: u8 = 2;
const ES_EMPTY: u8 = 3;

const T_U8: u8 = 0x01;
const T_I8: u8 = 0x11;
const T_U16: u8 = 0x02;
const T_I16: u8 = 0x12;
const T_U32: u8 = 0x04;
const T_I32: u8 = 0x14;
const T_U64: u8 = 0x08;
const T_I64: u8 = 0x18;
const T_SZ: u8 = 0x21;
const T_BLOB: u8 = 0x41;
const T_BLOB_DATA: u8 = 0x42;
const T_BLOB_IDX: u8 = 0x48;

const NO_HASH: u32 = u32::MAX;
/// Blob indexes the mount-time consistency check tracks at once (see [`Nvs::mount`]).
const BLOB_CAP: usize = 24;

type R<T, F> = Result<T, Error<<F as Flash>::Error>>;

fn is_var(ty: u8) -> bool {
    ty == T_SZ || ty == T_BLOB || ty == T_BLOB_DATA
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn es(table: &[u8; 32], i: usize) -> u8 {
    (table[i / 4] >> ((i % 4) * 2)) & 3
}

fn eaddr(p: usize, i: usize) -> u32 {
    (p * PAGE_SIZE) as u32 + ENTRIES_OFF + (i * ENTRY_SIZE) as u32
}

/// A validated key or namespace name: 1 to 15 bytes, no NUL.
#[derive(Clone, Copy)]
struct Key {
    b: [u8; 16],
    len: usize,
}

impl Key {
    fn new<E>(s: &str) -> Result<Self, Error<E>> {
        let s = s.as_bytes();
        if s.is_empty() || s.len() > 15 || s.contains(&0) {
            return Err(Error::InvalidKey);
        }
        let mut b = [0u8; 16];
        b[..s.len()].copy_from_slice(s);
        Ok(Self { b, len: s.len() })
    }
}

/// One 32-byte entry read as an item header.
#[derive(Clone, Copy)]
struct Item {
    raw: [u8; 32],
}

impl Item {
    fn build(ns: u8, ty: u8, span: u8, chunk: u8, key: &[u8; 16], data: [u8; 8]) -> Self {
        let mut raw = [0u8; 32];
        raw[0] = ns;
        raw[1] = ty;
        raw[2] = span;
        raw[3] = chunk;
        raw[8..24].copy_from_slice(key);
        raw[24..32].copy_from_slice(&data);
        let mut item = Self { raw };
        let crc = item.crc();
        item.raw[4..8].copy_from_slice(&crc.to_le_bytes());
        item
    }

    fn crc(&self) -> u32 {
        crc32(crc32(0xffff_ffff, &self.raw[0..4]), &self.raw[8..32])
    }

    fn ns(&self) -> u8 {
        self.raw[0]
    }

    fn ty(&self) -> u8 {
        self.raw[1]
    }

    fn span(&self) -> usize {
        usize::from(self.raw[2])
    }

    fn chunk(&self) -> u8 {
        self.raw[3]
    }

    fn data(&self) -> &[u8] {
        &self.raw[24..32]
    }

    fn var_len(&self) -> usize {
        usize::from(u16::from_le_bytes([self.raw[24], self.raw[25]]))
    }

    fn var_crc(&self) -> u32 {
        le32(&self.raw[28..32])
    }

    fn idx_size(&self) -> u32 {
        le32(&self.raw[24..28])
    }

    fn key16(&self) -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(&self.raw[8..24]);
        k
    }

    /// `strncmp(key, item.key, 15) == 0`.
    fn key_is(&self, key: &Key) -> bool {
        self.raw[8..8 + key.len] == key.b[..key.len] && self.raw[8 + key.len] == 0
    }

    /// Entries this item occupies for the purpose of scanning (`span` for variable-length types, else 1).
    fn advance(&self) -> usize {
        if is_var(self.ty()) { self.span().max(1) } else { 1 }
    }

    /// `HashList` hash: CRC-32 of namespace, key and chunk index, 24 bits.
    fn hash(&self) -> u32 {
        let c = crc32(0xffff_ffff, &self.raw[0..1]);
        let c = crc32(c, &self.raw[8..24]);
        crc32(c, &self.raw[3..4]) & 0x00ff_ffff
    }

    /// `Item::checkHeaderConsistency`.
    fn consistent(&self, index: usize) -> bool {
        if self.crc() != le32(&self.raw[4..8]) {
            return false;
        }
        let left = ENTRY_COUNT - index;
        match self.ty() {
            T_U8 | T_I8 | T_U16 | T_I16 | T_U32 | T_I32 | T_U64 | T_I64 => self.span() == 1,
            T_BLOB_IDX => {
                let max = (255 / 2) * (ENTRY_COUNT as u32 - 1) * ENTRY_SIZE as u32;
                self.span() == 1 && self.chunk() == CHUNK_ANY && self.idx_size() <= max
            }
            T_SZ | T_BLOB | T_BLOB_DATA => {
                if self.ty() == T_BLOB_DATA && self.chunk() == CHUNK_ANY {
                    return false;
                }
                let len = self.var_len();
                len <= (left - 1) * ENTRY_SIZE && self.span() <= left && self.span() == len.div_ceil(ENTRY_SIZE) + 1
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PState {
    /// Blank (or, in the page list, activated in RAM but not yet written).
    Uninit,
    Active,
    Full,
    Freeing,
    Corrupt,
}

#[derive(Clone, Copy, Debug)]
struct PInfo {
    state: PState,
    seq: u32,
    next_free: u8,
}

enum Class {
    Blank,
    Corrupt,
    Valid(PState, u32),
}

#[derive(Clone, Copy)]
enum Match {
    /// Any item that is not a `BLOB_DATA` chunk: primitive, string, v1 blob or v2 blob index.
    Primary,
    Chunk(u8),
    Index(Option<u8>),
}

impl Match {
    fn ok(self, it: &Item) -> bool {
        match self {
            Self::Primary => it.ty() != T_BLOB_DATA,
            Self::Chunk(c) => it.ty() == T_BLOB_DATA && it.chunk() == c,
            Self::Index(start) => it.ty() == T_BLOB_IDX && start.is_none_or(|s| it.data()[5] == s),
        }
    }
}

#[derive(Clone, Copy)]
struct Loc {
    page: usize,
    idx: usize,
    item: Item,
}

/// The type of a stored value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `uint8_t`.
    U8,
    /// `int8_t`.
    I8,
    /// `uint16_t`.
    U16,
    /// `int16_t`.
    I16,
    /// `uint32_t`.
    U32,
    /// `int32_t`.
    I32,
    /// `uint64_t`.
    U64,
    /// `int64_t`.
    I64,
    /// A NUL-terminated string (`size` includes the NUL).
    Str,
    /// A blob (single-item v1 or chunked v2).
    Blob,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Self::U8 => T_U8,
            Self::I8 => T_I8,
            Self::U16 => T_U16,
            Self::I16 => T_I16,
            Self::U32 => T_U32,
            Self::I32 => T_I32,
            Self::U64 => T_U64,
            Self::I64 => T_I64,
            Self::Str => T_SZ,
            Self::Blob => T_BLOB,
        }
    }

    fn width(self) -> usize {
        usize::from(self.code() & 0x0f)
    }
}

/// One live item, as returned by [`Nvs::next_item`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemInfo {
    /// Namespace index (0 for the namespace table itself, whose items are `U8` with the namespace name as key).
    pub namespace: u8,
    /// The key, NUL padded.
    pub key: [u8; 16],
    /// The type.
    pub kind: Kind,
    /// Length in bytes (the width for primitives).
    pub size: usize,
}

impl ItemInfo {
    /// The key as bytes without the padding.
    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        let n = self.key.iter().position(|&b| b == 0).unwrap_or(16);
        &self.key[..n]
    }
}

/// Position of an iteration over the live items; start with `Cursor::default()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cursor {
    page: usize,
    entry: usize,
}

/// Space accounting, as `nvs_get_stats` would report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Pages in the partition.
    pub pages: usize,
    /// Pages that are free (blank or corrupt, to be erased on use).
    pub free_pages: usize,
    /// Written entries in all pages.
    pub used_entries: usize,
    /// Sector erases the engine has issued since mount (wear).
    pub erases: u32,
}

/// The engine. See the crate documentation.
#[derive(Debug)]
pub struct Nvs<F: Flash> {
    flash: F,
    pages: usize,
    info: [PInfo; MAX_PAGES],
    order: [u8; MAX_PAGES],
    n_order: usize,
    free: [u8; MAX_PAGES],
    n_free: usize,
    seq: u32,
    broken: bool,
    erases: u32,
}

impl<F: Flash> Nvs<F> {
    /// An unmounted engine over the partition `flash` of `size` bytes (`0x10000` for this firmware). Call [`Nvs::mount`].
    pub fn new(flash: F, size: u32) -> Self {
        let pages = (size as usize / PAGE_SIZE).min(MAX_PAGES + 1);
        Self {
            flash,
            pages,
            info: [PInfo { state: PState::Uninit, seq: 0, next_free: 0 }; MAX_PAGES],
            order: [0; MAX_PAGES],
            n_order: 0,
            free: [0; MAX_PAGES],
            n_free: 0,
            seq: 0,
            broken: true,
            erases: 0,
        }
    }

    /// [`Nvs::new`] and [`Nvs::mount`]; on failure the flash is dropped (use `new` + `mount` to keep it).
    ///
    /// # Errors
    /// See [`Nvs::mount`].
    pub fn open(flash: F, size: u32) -> R<Self, F> {
        let mut nvs = Self::new(flash, size);
        nvs.mount()?;
        Ok(nvs)
    }

    /// Give the flash back.
    pub fn into_flash(self) -> F {
        self.flash
    }

    /// Borrow the flash.
    pub fn flash(&self) -> &F {
        &self.flash
    }

    /// Borrow the flash mutably (tests inject faults through it). The engine's view is stale after changing its contents: mount again.
    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    /// `nvs_commit`: nothing to do, every write is on flash when it returns (see the crate documentation); only checks that the engine
    /// is usable.
    ///
    /// # Errors
    /// [`Error::Broken`].
    pub fn commit(&self) -> R<(), F> {
        if self.broken { Err(Error::Broken) } else { Ok(()) }
    }

    /// Space accounting.
    ///
    /// # Errors
    /// [`Error::Broken`] or [`Error::Flash`].
    pub fn stats(&mut self) -> R<Stats, F> {
        self.live()?;
        let mut used = 0;
        for k in 0..self.n_order {
            let p = usize::from(self.order[k]);
            if matches!(self.info[p].state, PState::Active | PState::Full | PState::Freeing) {
                let t = self.table(p)?;
                used += (0..ENTRY_COUNT).filter(|&i| es(&t, i) == ES_WRITTEN).count();
            }
        }
        Ok(Stats { pages: self.pages, free_pages: self.n_free, used_entries: used, erases: self.erases })
    }

    /// Erase the pages that failed validation at mount (a header cut in the middle of its write, a blank page that is not blank).
    /// ESP-IDF keeps such pages until it runs out of free pages (for diagnostics) and the engine does the same, so this is optional; call
    /// it after a mount that found damage if the partition should be clean for external tools (IDF's `nvs_tool.py -i` reports them).
    /// Returns how many pages it erased.
    ///
    /// # Errors
    /// [`Error::Broken`], [`Error::Flash`].
    pub fn scrub(&mut self) -> R<usize, F> {
        self.live()?;
        let mut n = 0;
        for k in 0..self.n_free {
            let p = usize::from(self.free[k]);
            if self.info[p].state == PState::Corrupt {
                self.erase_page(p)?;
                n += 1;
            }
        }
        Ok(n)
    }

    fn live(&self) -> R<(), F> {
        if self.broken { Err(Error::Broken) } else { Ok(()) }
    }

    // ---- raw flash access -------------------------------------------------------------------------------------------------------

    fn rd(&mut self, off: u32, buf: &mut [u8]) -> R<(), F> {
        self.flash.read(off, buf).map_err(|e| {
            self.broken = true;
            Error::Flash(e)
        })
    }

    fn wr(&mut self, off: u32, data: &[u8]) -> R<(), F> {
        debug_assert!(off.is_multiple_of(4) && data.len().is_multiple_of(4) && !data.is_empty());
        self.flash.write(off, data).map_err(|e| {
            self.broken = true;
            Error::Flash(e)
        })
    }

    fn table(&mut self, p: usize) -> R<[u8; 32], F> {
        let mut t = [0u8; 32];
        self.rd((p * PAGE_SIZE) as u32 + TABLE_OFF, &mut t)?;
        Ok(t)
    }

    fn read_item(&mut self, p: usize, i: usize) -> R<Item, F> {
        let mut raw = [0u8; 32];
        self.rd(eaddr(p, i), &mut raw)?;
        Ok(Item { raw })
    }

    /// `Page::alterEntryState`: one word of the entry-state table, bits only cleared.
    fn alter_state(&mut self, p: usize, i: usize, st: u8) -> R<(), F> {
        self.alter_word(p, i / 16, i, i + 1, st)
    }

    /// `Page::alterEntryRangeState`: the words from the last one down to the first, one write each.
    fn alter_range(&mut self, p: usize, begin: usize, end: usize, st: u8) -> R<(), F> {
        for w in (begin / 16..=(end - 1) / 16).rev() {
            self.alter_word(p, w, begin, end, st)?;
        }
        Ok(())
    }

    fn alter_word(&mut self, p: usize, w: usize, begin: usize, end: usize, st: u8) -> R<(), F> {
        let off = (p * PAGE_SIZE) as u32 + TABLE_OFF + (w * 4) as u32;
        let mut b = [0u8; 4];
        self.rd(off, &mut b)?;
        let mut word = u32::from_le_bytes(b);
        for j in begin.max(w * 16)..end.min(w * 16 + 16) {
            let sh = (j % 16) * 2;
            let mask = 3u32 << sh;
            word &= !mask | (u32::from(st) << sh);
        }
        self.wr(off, &word.to_le_bytes())
    }

    fn set_page_state(&mut self, p: usize, word: u32, st: PState) -> R<(), F> {
        self.wr((p * PAGE_SIZE) as u32, &word.to_le_bytes())?;
        self.info[p].state = st;
        Ok(())
    }

    fn erase_page(&mut self, p: usize) -> R<(), F> {
        self.flash.erase_sector(p as u32).map_err(|e| {
            self.broken = true;
            Error::Flash(e)
        })?;
        self.erases += 1;
        self.info[p] = PInfo { state: PState::Uninit, seq: 0, next_free: 0 };
        Ok(())
    }

    fn page_end(&self, p: usize) -> usize {
        match self.info[p].state {
            PState::Active => usize::from(self.info[p].next_free),
            PState::Full | PState::Freeing => ENTRY_COUNT,
            _ => 0,
        }
    }

    // ---- page lists -------------------------------------------------------------------------------------------------------------

    fn push_free(&mut self, p: usize) {
        self.free[self.n_free] = p as u8;
        self.n_free += 1;
    }

    fn remove_order(&mut self, p: usize) {
        if let Some(k) = self.order[..self.n_order].iter().position(|&x| usize::from(x) == p) {
            self.order.copy_within(k + 1..self.n_order, k);
            self.n_order -= 1;
        }
    }

    fn cur(&self) -> usize {
        usize::from(self.order[self.n_order - 1])
    }

    /// `PageManager::activatePage`: the first free page becomes the newest page (blank in RAM until its first item).
    fn activate_page(&mut self) -> R<usize, F> {
        if self.n_free == 0 {
            return Err(Error::NoSpace);
        }
        let p = usize::from(self.free[0]);
        if self.info[p].state == PState::Corrupt {
            self.erase_page(p)?;
        }
        self.free.copy_within(1..self.n_free, 0);
        self.n_free -= 1;
        self.order[self.n_order] = p as u8;
        self.n_order += 1;
        self.info[p] = PInfo { state: PState::Uninit, seq: self.seq, next_free: 0 };
        self.seq = self.seq.wrapping_add(1);
        Ok(p)
    }

    // ---- page level writes --------------------------------------------------------------------------------------------------------

    /// `Page::initialize`.
    fn init_page(&mut self, p: usize) -> R<(), F> {
        let mut h = [0xffu8; 32];
        h[0..4].copy_from_slice(&PS_ACTIVE.to_le_bytes());
        h[4..8].copy_from_slice(&self.info[p].seq.to_le_bytes());
        h[8] = NVS_VERSION;
        let crc = crc32(0xffff_ffff, &h[4..28]);
        h[28..32].copy_from_slice(&crc.to_le_bytes());
        self.wr((p * PAGE_SIZE) as u32, &h)?;
        self.info[p].state = PState::Active;
        self.info[p].next_free = 0;
        Ok(())
    }

    /// `Page::writeEntry`: the entry, then its state bits.
    fn write_entry(&mut self, p: usize, raw: &[u8; 32]) -> R<(), F> {
        let nf = usize::from(self.info[p].next_free);
        self.wr(eaddr(p, nf), raw)?;
        self.alter_state(p, nf, ES_WRITTEN)?;
        self.info[p].next_free += 1;
        Ok(())
    }

    /// `Page::writeEntryData`: whole entries, then their state bits (last word first).
    fn write_data(&mut self, p: usize, data: &[u8]) -> R<(), F> {
        let nf = usize::from(self.info[p].next_free);
        let count = data.len() / ENTRY_SIZE;
        self.wr(eaddr(p, nf), data)?;
        self.alter_range(p, nf, nf + count, ES_WRITTEN)?;
        self.info[p].next_free += count as u8;
        Ok(())
    }

    /// `Page::writeItem`: returns the index of the header entry.
    fn put_item(&mut self, p: usize, ns: u8, ty: u8, key: &[u8; 16], data: &[u8], chunk: u8) -> R<usize, F> {
        match self.info[p].state {
            PState::Uninit => self.init_page(p)?,
            PState::Active => {}
            PState::Full => return Err(Error::PageFull),
            PState::Freeing | PState::Corrupt => return Err(Error::Broken),
        }
        let var = is_var(ty);
        if data.len() > CHUNK_MAX {
            return Err(Error::ValueTooLong);
        }
        if !var && data.len() > 8 {
            return Err(Error::InvalidArg);
        }
        let entries = if var { 1 + data.len().div_ceil(ENTRY_SIZE) } else { 1 };
        let at = usize::from(self.info[p].next_free);
        if at + entries > ENTRY_COUNT {
            return Err(Error::PageFull);
        }
        if !var {
            let mut d = [0xffu8; 8];
            d[..data.len()].copy_from_slice(data);
            self.write_entry(p, &Item::build(ns, ty, 1, chunk, key, d).raw)?;
        } else {
            let mut d = [0xffu8; 8];
            d[0..2].copy_from_slice(&(data.len() as u16).to_le_bytes());
            d[4..8].copy_from_slice(&crc32(0xffff_ffff, data).to_le_bytes());
            self.write_entry(p, &Item::build(ns, ty, entries as u8, chunk, key, d).raw)?;
            let rest = data.len() % ENTRY_SIZE;
            let left = data.len() - rest;
            if left > 0 {
                self.write_data(p, &data[..left])?;
            }
            if rest > 0 {
                let mut tail = [0xffu8; 32];
                tail[..rest].copy_from_slice(&data[left..]);
                self.write_entry(p, &tail)?;
            }
        }
        Ok(at)
    }

    /// `Page::eraseEntryAndSpan`.
    fn erase_entry_and_span(&mut self, p: usize, idx: usize) -> R<(), F> {
        let table = self.table(p)?;
        let mut span = 1;
        if es(&table, idx) == ES_WRITTEN {
            let item = self.read_item(p, idx)?;
            if item.consistent(idx) {
                span = item.span();
                if span == 1 {
                    self.alter_state(p, idx, ES_ERASED)?;
                } else {
                    self.alter_range(p, idx, idx + span, ES_ERASED)?;
                }
            } else {
                self.alter_state(p, idx, ES_ERASED)?;
            }
        } else {
            self.alter_state(p, idx, ES_ERASED)?;
        }
        if self.info[p].state == PState::Active && usize::from(self.info[p].next_free) < idx + span {
            self.info[p].next_free = (idx + span) as u8;
        }
        Ok(())
    }

    fn mark_full(&mut self, p: usize) -> R<(), F> {
        if self.info[p].state != PState::Active {
            return Err(Error::Broken);
        }
        self.set_page_state(p, PS_FULL, PState::Full)
    }

    fn mark_freeing(&mut self, p: usize) -> R<(), F> {
        if !matches!(self.info[p].state, PState::Active | PState::Full) {
            return Err(Error::Broken);
        }
        self.set_page_state(p, PS_FREEING, PState::Freeing)
    }

    /// `Page::copyItems`: every written entry of `src`, header and data entries one by one, into `dst` (initialised on first use). A page
    /// with nothing written leaves `dst` untouched.
    fn copy_items(&mut self, src: usize, dst: usize) -> R<(), F> {
        let table = self.table(src)?;
        let mut i = (0..ENTRY_COUNT).find(|&i| es(&table, i) == ES_WRITTEN);
        let mut inited = self.info[dst].state != PState::Uninit;
        while let Some(at) = i {
            if es(&table, at) != ES_WRITTEN {
                i = (at + 1..ENTRY_COUNT).find(|&j| es(&table, j) == ES_WRITTEN);
                continue;
            }
            let item = self.read_item(src, at)?;
            if !item.consistent(at) {
                i = (at + 1..ENTRY_COUNT).find(|&j| es(&table, j) == ES_WRITTEN);
                continue;
            }
            if !inited {
                self.init_page(dst)?;
                inited = true;
            }
            self.write_entry(dst, &item.raw)?;
            let end = at + item.span();
            for k in at + 1..end {
                let e = self.read_item(src, k)?;
                self.write_entry(dst, &e.raw)?;
            }
            i = (end..ENTRY_COUNT).find(|&j| es(&table, j) == ES_WRITTEN);
        }
        Ok(())
    }

    /// `PageManager::requestNewPage`: activate a free page, or, when only the spare is left, move the page with the most reclaimable
    /// entries into it, erase that page and keep it as the new spare.
    fn request_new_page(&mut self) -> R<(), F> {
        if self.n_free == 0 {
            return Err(Error::Broken);
        }
        if self.n_free >= 2 {
            self.activate_page()?;
            return Ok(());
        }
        let mut victim = None;
        let mut max_unused = 0;
        for k in 0..self.n_order {
            let p = usize::from(self.order[k]);
            if !matches!(self.info[p].state, PState::Active | PState::Full) {
                continue;
            }
            let t = self.table(p)?;
            let used = (0..ENTRY_COUNT).filter(|&i| es(&t, i) == ES_WRITTEN).count();
            if ENTRY_COUNT - used > max_unused {
                max_unused = ENTRY_COUNT - used;
                victim = Some(p);
            }
        }
        let Some(victim) = victim else { return Err(Error::NoSpace) };
        self.mark_freeing(victim)?;
        let dst = self.activate_page()?;
        self.copy_items(victim, dst)?;
        self.erase_page(victim)?;
        self.remove_order(victim);
        self.push_free(victim);
        Ok(())
    }

    // ---- scanning ---------------------------------------------------------------------------------------------------------------

    /// The first consistent written item at or after entry `i` of page `p`.
    fn next_live(&mut self, p: usize, table: &[u8; 32], mut i: usize) -> R<Option<(usize, Item)>, F> {
        let end = self.page_end(p);
        while i < end {
            if es(table, i) == ES_WRITTEN {
                let it = self.read_item(p, i)?;
                if it.consistent(i) {
                    return Ok(Some((i, it)));
                }
            }
            i += 1;
        }
        Ok(None)
    }

    /// The newest item (highest page sequence, then highest entry) of namespace `ns` and `key` that matches `m`, ignoring `skip`.
    fn find(&mut self, ns: u8, key: &Key, m: Match, skip: Option<(usize, usize)>) -> R<Option<Loc>, F> {
        let mut best = None;
        for k in 0..self.n_order {
            let p = usize::from(self.order[k]);
            let table = self.table(p)?;
            let mut i = 0;
            while let Some((idx, item)) = self.next_live(p, &table, i)? {
                i = idx + item.advance();
                if item.ns() == ns && item.key_is(key) && m.ok(&item) && skip != Some((p, idx)) {
                    best = Some(Loc { page: p, idx, item });
                }
            }
        }
        Ok(best)
    }

    /// Read the data entries of a variable-length item into `out` (exactly its length) and check the data CRC.
    fn read_var(&mut self, loc: &Loc, out: &mut [u8]) -> R<bool, F> {
        debug_assert_eq!(out.len(), loc.item.var_len());
        if !out.is_empty() {
            self.rd(eaddr(loc.page, loc.idx + 1), out)?;
        }
        Ok(crc32(0xffff_ffff, out) == loc.item.var_crc())
    }

    /// Whether the data of the variable-length item equals `data` (reads entry by entry, checks the CRC on the way).
    fn var_equals(&mut self, loc: &Loc, data: &[u8]) -> R<bool, F> {
        let it = &loc.item;
        if it.var_len() != data.len() || crc32(0xffff_ffff, data) != it.var_crc() {
            return Ok(false);
        }
        let mut buf = [0u8; ENTRY_SIZE];
        let mut crc = 0xffff_ffff;
        for (k, part) in data.chunks(ENTRY_SIZE).enumerate() {
            let b = &mut buf[..part.len()];
            self.rd(eaddr(loc.page, loc.idx + 1 + k), b)?;
            if b != part {
                return Ok(false);
            }
            crc = crc32(crc, b);
        }
        Ok(data.is_empty() || crc == it.var_crc())
    }

    // ---- mount ------------------------------------------------------------------------------------------------------------------

    fn classify(&mut self, p: usize) -> R<Class, F> {
        let base = (p * PAGE_SIZE) as u32;
        let mut h = [0u8; 32];
        self.rd(base, &mut h)?;
        let sw = le32(&h[0..4]);
        if sw == 0xffff_ffff {
            let mut blk = [0u8; 128];
            for off in (0..PAGE_SIZE as u32).step_by(128) {
                self.rd(base + off, &mut blk)?;
                if blk.iter().any(|&b| b != 0xff) {
                    return Ok(Class::Corrupt);
                }
            }
            return Ok(Class::Blank);
        }
        if crc32(0xffff_ffff, &h[4..28]) != le32(&h[28..32]) {
            return Ok(Class::Corrupt);
        }
        if h[8] < NVS_VERSION {
            return Err(Error::NewVersion);
        }
        let state = match sw {
            PS_ACTIVE => PState::Active,
            PS_FULL => PState::Full,
            PS_FREEING => PState::Freeing,
            _ => return Ok(Class::Corrupt),
        };
        Ok(Class::Valid(state, le32(&h[4..8])))
    }

    /// `Page::mLoadEntryTable`: find the first free entry, erase half-written entries and incomplete or duplicate items.
    fn scan_page(&mut self, p: usize) -> R<(), F> {
        let mut table = self.table(p)?;
        if self.info[p].state == PState::Active {
            let mut nf = (0..ENTRY_COUNT).find(|&i| es(&table, i) == ES_EMPTY).unwrap_or(ENTRY_COUNT);
            // An entry whose state is still "empty" but whose first word is not blank was cut in the middle of its write.
            while nf < ENTRY_COUNT {
                let mut w = [0u8; 4];
                self.rd(eaddr(p, nf), &mut w)?;
                if w == [0xff; 4] {
                    break;
                }
                self.alter_state(p, nf, ES_ERASED)?;
                nf += 1;
            }
            self.info[p].next_free = nf as u8;
            table = self.table(p)?;
            let mut hashes = [NO_HASH; ENTRY_COUNT];
            let mut i = 0;
            while i < nf {
                match es(&table, i) {
                    ES_ERASED => {
                        i += 1;
                        continue;
                    }
                    ES_ILLEGAL => {
                        self.erase_entry_and_span(p, i)?;
                        table = self.table(p)?;
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                let item = self.read_item(p, i)?;
                if !item.consistent(i) {
                    self.erase_entry_and_span(p, i)?;
                    table = self.table(p)?;
                    i += 1;
                    continue;
                }
                let h = item.hash();
                hashes[i] = h;
                let mut dup = None;
                for j in (0..i).filter(|&j| hashes[j] == h) {
                    {
                        let other = self.read_item(p, j)?;
                        if other.ns() == item.ns() && other.chunk() == item.chunk() && other.key16() == item.key16() {
                            dup = Some(j);
                            break;
                        }
                    }
                }
                let span = item.advance();
                if is_var(item.ty()) && (i..i + span).any(|j| es(&table, j) != ES_WRITTEN) {
                    hashes[i] = NO_HASH;
                    self.erase_entry_and_span(p, i)?;
                    table = self.table(p)?;
                    i += span;
                    continue;
                }
                if let Some(j) = dup {
                    hashes[j] = NO_HASH;
                    self.erase_entry_and_span(p, j)?;
                    table = self.table(p)?;
                }
                i += span;
            }
        } else {
            let mut i = 0;
            while i < ENTRY_COUNT {
                if es(&table, i) != ES_WRITTEN {
                    i += 1;
                    continue;
                }
                let item = self.read_item(p, i)?;
                if !item.consistent(i) {
                    self.erase_entry_and_span(p, i)?;
                    table = self.table(p)?;
                    i += 1;
                    continue;
                }
                let span = item.advance();
                if is_var(item.ty()) && (i + 1..i + span).any(|j| es(&table, j) != ES_WRITTEN) {
                    self.erase_entry_and_span(p, i)?;
                    table = self.table(p)?;
                }
                i += span;
            }
        }
        Ok(())
    }

    /// Load the partition and repair what a power cut can have left (`PageManager::load` and `Storage::init`):
    ///
    /// 1. every page is classified (blank, corrupt, or valid with its sequence number); the entries of valid pages are checked, half-written
    ///    and incomplete items erased, duplicates inside the active page erased;
    /// 2. the pages are ordered by sequence number; the last item of the newest page supersedes an older item with the same key on an
    ///    earlier page (a cut between "write the new item" and "erase the old one");
    /// 3. a page in the `FREEING` state (a cut during compaction) is finished: the half-filled target page is erased and the items are
    ///    copied again;
    /// 4. blob indexes whose chunks do not add up are erased, and chunks that no index claims are erased. The check tracks at most 24 blob
    ///    indexes at once; with more, the extra ones are not verified and no chunk is treated as an orphan (nothing is ever erased on
    ///    incomplete knowledge).
    ///
    /// # Errors
    /// [`Error::NoFreePages`] when every page holds data, [`Error::NewVersion`], [`Error::InvalidArg`] for a partition below [`MIN_PAGES`]
    /// or above [`MAX_PAGES`] pages, [`Error::Flash`].
    pub fn mount(&mut self) -> R<(), F> {
        self.broken = true;
        if !(MIN_PAGES..=MAX_PAGES).contains(&self.pages) {
            return Err(Error::InvalidArg);
        }
        self.n_order = 0;
        self.n_free = 0;
        for p in 0..self.pages {
            match self.classify(p)? {
                Class::Blank => {
                    self.info[p] = PInfo { state: PState::Uninit, seq: 0, next_free: 0 };
                    self.push_free(p);
                }
                Class::Corrupt => {
                    self.info[p] = PInfo { state: PState::Corrupt, seq: 0, next_free: 0 };
                    self.push_free(p);
                }
                Class::Valid(state, seq) => {
                    self.info[p] = PInfo { state, seq, next_free: ENTRY_COUNT as u8 };
                    self.scan_page(p)?;
                    let pos = self.order[..self.n_order].iter().position(|&o| self.info[usize::from(o)].seq > seq).unwrap_or(self.n_order);
                    self.order.copy_within(pos..self.n_order, pos + 1);
                    self.order[pos] = p as u8;
                    self.n_order += 1;
                }
            }
        }
        if self.n_order == 0 {
            self.seq = 0;
            self.activate_page()?;
            self.broken = false;
            return Ok(());
        }
        self.seq = self.info[self.cur()].seq.wrapping_add(1);
        self.supersede_last_item()?;
        self.recover_freeing()?;
        if self.n_free == 0 {
            return Err(Error::NoFreePages);
        }
        self.clean_blobs()?;
        self.broken = false;
        Ok(())
    }

    /// The last item written to the newest page was the last write before the power cut: if an older page still holds the previous version
    /// of that key, erase it. IDF erases the first older item of the same *type* (and a v1 blob under a new index); here an item of any
    /// other non-chunk type with the same namespace and key goes too, because a key that changed type (`u8` over a blob) and lost the
    /// power before the old item was erased would otherwise keep two live items, and which one wins would depend on page order (which
    /// compaction changes).
    fn supersede_last_item(&mut self) -> R<(), F> {
        let last = self.cur();
        let table = self.table(last)?;
        let mut item = None;
        let mut i = 0;
        while let Some((idx, it)) = self.next_live(last, &table, i)? {
            i = idx + it.advance();
            item = Some(it);
        }
        let Some(item) = item else { return Ok(()) };
        for k in 0..self.n_order - 1 {
            let p = usize::from(self.order[k]);
            if self.info[p].state == PState::Freeing {
                continue;
            }
            loop {
                let table = self.table(p)?;
                let mut i = 0;
                let mut hit = None;
                while let Some((idx, it)) = self.next_live(p, &table, i)? {
                    i = idx + it.advance();
                    let same = it.ns() == item.ns() && it.key16() == item.key16();
                    let kind = if item.ty() == T_BLOB_DATA { it.ty() == T_BLOB_DATA && it.chunk() == item.chunk() } else { it.ty() != T_BLOB_DATA };
                    if same && kind {
                        hit = Some(idx);
                        break;
                    }
                }
                let Some(idx) = hit else { break };
                self.erase_entry_and_span(p, idx)?;
            }
        }
        Ok(())
    }

    fn recover_freeing(&mut self) -> R<(), F> {
        while let Some(k) = (0..self.n_order).find(|&k| self.info[usize::from(self.order[k])].state == PState::Freeing) {
            let victim = usize::from(self.order[k]);
            let newest = self.cur();
            if self.info[newest].state == PState::Active {
                self.erase_page(newest)?;
                self.remove_order(newest);
                self.push_free(newest);
            }
            let dst = self.activate_page()?;
            self.copy_items(victim, dst)?;
            self.erase_page(victim)?;
            self.remove_order(victim);
            self.push_free(victim);
        }
        Ok(())
    }

    fn clean_blobs(&mut self) -> R<(), F> {
        #[derive(Clone, Copy)]
        struct Idx {
            ns: u8,
            key: [u8; 16],
            start: u8,
            count: u8,
            size: u32,
            seen: u32,
            seen_count: u32,
            live: bool,
        }
        let none = Idx { ns: 0, key: [0; 16], start: 0, count: 0, size: 0, seen: 0, seen_count: 0, live: false };
        let mut list = [none; BLOB_CAP];
        let mut n = 0;
        let mut overflow = false;
        let pages = self.n_order;
        for k in 0..pages {
            let p = usize::from(self.order[k]);
            let table = self.table(p)?;
            let mut i = 0;
            while let Some((idx, it)) = self.next_live(p, &table, i)? {
                i = idx + it.advance();
                if it.ty() == T_BLOB_IDX {
                    if n == BLOB_CAP {
                        overflow = true;
                    } else {
                        list[n] = Idx {
                            ns: it.ns(),
                            key: it.key16(),
                            start: it.data()[5],
                            count: it.data()[4],
                            size: it.idx_size(),
                            seen: 0,
                            seen_count: 0,
                            live: true,
                        };
                        n += 1;
                    }
                }
            }
        }
        if n == 0 && !overflow {
            // No blob index at all: every chunk is an orphan, but there may be none; the third pass below finds out.
        }
        for k in 0..pages {
            let p = usize::from(self.order[k]);
            let table = self.table(p)?;
            let mut i = 0;
            while let Some((idx, it)) = self.next_live(p, &table, i)? {
                i = idx + it.advance();
                if it.ty() == T_BLOB_DATA {
                    let c = it.chunk();
                    if let Some(e) = list[..n]
                        .iter_mut()
                        .find(|e| e.ns == it.ns() && e.key == it.key16() && c >= e.start && c < if e.start == VER_0 { VER_1 } else { CHUNK_ANY })
                    {
                        e.seen += it.var_len() as u32;
                        e.seen_count += 1;
                    }
                }
            }
        }
        for e in &mut list[..n] {
            if e.seen != e.size || e.seen_count != u32::from(e.count) {
                e.live = false;
                let mut key = [0u8; 16];
                key.copy_from_slice(&e.key);
                if let Some(loc) = self.find_raw(e.ns, &key, Match::Index(Some(e.start)))? {
                    self.erase_entry_and_span(loc.page, loc.idx)?;
                }
            }
        }
        if overflow {
            return Ok(());
        }
        for k in 0..pages {
            let p = usize::from(self.order[k]);
            let mut table = self.table(p)?;
            let mut i = 0;
            while let Some((idx, it)) = self.next_live(p, &table, i)? {
                i = idx + it.advance();
                if it.ty() == T_BLOB_DATA {
                    let c = u16::from(it.chunk());
                    let claimed = list[..n]
                        .iter()
                        .any(|e| e.live && e.ns == it.ns() && e.key == it.key16() && c >= u16::from(e.start) && c < u16::from(e.start) + u16::from(e.count));
                    if !claimed {
                        self.erase_entry_and_span(p, idx)?;
                        table = self.table(p)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// [`Nvs::find`] with the raw 16-byte key of an existing item.
    fn find_raw(&mut self, ns: u8, key16: &[u8; 16], m: Match) -> R<Option<Loc>, F> {
        let len = key16.iter().position(|&b| b == 0).unwrap_or(15).min(15);
        let mut b = [0u8; 16];
        b[..len].copy_from_slice(&key16[..len]);
        self.find(ns, &Key { b, len }, m, None)
    }

    // ---- namespaces -------------------------------------------------------------------------------------------------------------

    /// The index of namespace `name`, creating it (the next free index from 1) when `create`.
    fn namespace(&mut self, name: &str, create: bool) -> R<Option<u8>, F> {
        let key = Key::new(name)?;
        if let Some(loc) = self.find(0, &key, Match::Primary, None)?
            && loc.item.ty() == T_U8
        {
            return Ok(Some(loc.item.data()[0]));
        }
        if !create {
            return Ok(None);
        }
        let mut used = [false; 256];
        for k in 0..self.n_order {
            let p = usize::from(self.order[k]);
            let table = self.table(p)?;
            let mut i = 0;
            while let Some((idx, it)) = self.next_live(p, &table, i)? {
                i = idx + it.advance();
                if it.ns() == 0 && it.ty() == T_U8 {
                    used[usize::from(it.data()[0])] = true;
                }
            }
        }
        let Some(ns) = (1..255usize).find(|&n| !used[n]) else { return Err(Error::NoSpace) };
        self.write_storage_item(0, T_U8, &key.b, &[ns as u8])?;
        Ok(Some(ns as u8))
    }

    // ---- writing ----------------------------------------------------------------------------------------------------------------

    /// `Storage::writeItem` for everything but blobs: write to the current page, moving on to a new page when it is full.
    fn write_storage_item(&mut self, ns: u8, ty: u8, key: &[u8; 16], data: &[u8]) -> R<(usize, usize), F> {
        let p = self.cur();
        match self.put_item(p, ns, ty, key, data, CHUNK_ANY) {
            Ok(i) => Ok((p, i)),
            Err(Error::PageFull) => {
                if self.info[p].state != PState::Full {
                    self.mark_full(p)?;
                }
                self.request_new_page()?;
                let p = self.cur();
                match self.put_item(p, ns, ty, key, data, CHUNK_ANY) {
                    Ok(i) => Ok((p, i)),
                    Err(Error::PageFull) => Err(Error::NoSpace),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// `Page::getVarDataTailroom`.
    fn tailroom(&self, p: usize) -> usize {
        match self.info[p].state {
            PState::Uninit => CHUNK_MAX,
            PState::Full => 0,
            _ => {
                let nf = usize::from(self.info[p].next_free);
                if nf < ENTRY_COUNT - 1 { (ENTRY_COUNT - nf - 1) * ENTRY_SIZE } else { 0 }
            }
        }
    }

    /// `Storage::writeMultiPageBlob`: chunks of version `start`, then the index. Returns the location of the index.
    fn write_multipage_blob(&mut self, ns: u8, key: &[u8; 16], data: &[u8], start: u8) -> R<(usize, usize), F> {
        let max_pages = (self.pages - 1).min(usize::from(CHUNK_ANY - 1) / 2);
        if data.len() > max_pages * CHUNK_MAX {
            return Err(Error::ValueTooLong);
        }
        let mut chunks = 0u8;
        let mut offset = 0usize;
        let res = self.write_chunks(ns, key, data, start, &mut chunks, &mut offset);
        if res.is_err() && !self.broken {
            // Anything failed: erase the chunks written so far (they are not referenced by any index).
            let k16 = *key;
            for c in 0..chunks {
                if let Some(loc) = self.find_raw(ns, &k16, Match::Chunk(start + c))? {
                    self.erase_entry_and_span(loc.page, loc.idx)?;
                }
            }
        }
        res
    }

    fn write_chunks(&mut self, ns: u8, key: &[u8; 16], data: &[u8], start: u8, chunks: &mut u8, offset: &mut usize) -> R<(usize, usize), F> {
        let mut remaining = data.len();
        loop {
            let p = self.cur();
            let tailroom = self.tailroom(p);
            if *chunks == 0 && (tailroom < data.len() || (tailroom == 0 && data.is_empty())) && tailroom < CHUNK_MAX / 10 {
                if self.info[p].state != PState::Full {
                    self.mark_full(p)?;
                }
                self.request_new_page()?;
                if self.tailroom(self.cur()) == tailroom {
                    return Err(Error::NoSpace);
                }
                continue;
            } else if tailroom == 0 {
                return Err(Error::NoSpace);
            }
            let size = remaining.min(tailroom);
            remaining -= size;
            self.put_item(p, ns, T_BLOB_DATA, key, &data[*offset..*offset + size], start + *chunks)?;
            *chunks += 1;
            if remaining > 0 || tailroom - size < ENTRY_SIZE {
                if self.info[p].state != PState::Full {
                    self.mark_full(p)?;
                }
                self.request_new_page()?;
            }
            *offset += size;
            if remaining == 0 {
                let mut d = [0xffu8; 8];
                d[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
                d[4] = *chunks;
                d[5] = start;
                let p = self.cur();
                let i = self.put_item(p, ns, T_BLOB_IDX, key, &d, CHUNK_ANY)?;
                return Ok((p, i));
            }
        }
    }

    /// Erase a multi-chunk blob: the index first (making the chunks orphans), then the chunks of its version. `keep` is the version of a blob
    /// that was just written under the same key and must not be touched.
    fn erase_multipage(&mut self, loc: &Loc, keep: Option<u8>) -> R<(), F> {
        let ns = loc.item.ns();
        let key16 = loc.item.key16();
        let (count, start) = (loc.item.data()[4], loc.item.data()[5]);
        self.erase_entry_and_span(loc.page, loc.idx)?;
        if (start == VER_0 || start == VER_1) && keep != Some(start) {
            for c in 0..count {
                if let Some(l) = self.find_raw(ns, &key16, Match::Chunk(start + c))? {
                    self.erase_entry_and_span(l.page, l.idx)?;
                }
            }
        }
        Ok(())
    }

    /// Erase every item of namespace `ns` and `key` except the one at `new` (the "then mark the old one erased" step).
    fn erase_others(&mut self, ns: u8, key: &Key, new: (usize, usize), keep: Option<u8>) -> R<(), F> {
        while let Some(old) = self.find(ns, key, Match::Primary, Some(new))? {
            if old.item.ty() == T_BLOB_IDX {
                self.erase_multipage(&old, keep)?;
            } else {
                self.erase_entry_and_span(old.page, old.idx)?;
            }
        }
        Ok(())
    }

    fn set_item(&mut self, namespace: &str, key: &str, ty: u8, data: &[u8]) -> R<(), F> {
        self.live()?;
        let k = Key::new(key)?;
        let Some(ns) = self.namespace(namespace, true)? else { return Err(Error::NotFound) };
        if let Some(old) = self.find(ns, &k, Match::Primary, None)?
            && old.item.ty() == ty
        {
            let same = if is_var(ty) { self.var_equals(&old, data)? } else { old.item.data()[..data.len()] == *data };
            if same {
                return Ok(());
            }
        }
        let new = self.write_storage_item(ns, ty, &k.b, data)?;
        self.erase_others(ns, &k, new, None)
    }

    /// `nvs_set_blob`. Writes nothing when the stored value is already equal. Otherwise: the chunks of the other version (0 or 0x80), then
    /// the index, then the old index and its chunks are erased.
    ///
    /// # Errors
    /// [`Error::ValueTooLong`] above `(pages - 1) * 4000` bytes, [`Error::NoSpace`], [`Error::InvalidKey`], [`Error::Flash`].
    pub fn set_blob(&mut self, namespace: &str, key: &str, data: &[u8]) -> R<(), F> {
        self.live()?;
        let k = Key::new(key)?;
        let Some(ns) = self.namespace(namespace, true)? else { return Err(Error::NotFound) };
        let mut next = VER_0;
        if let Some(old) = self.find(ns, &k, Match::Primary, None)?
            && old.item.ty() == T_BLOB_IDX
        {
            if self.blob_equals(&old, &k, data)? {
                return Ok(());
            }
            next = if old.item.data()[5] == VER_1 { VER_0 } else { VER_1 };
        }
        let new = self.write_multipage_blob(ns, &k.b, data, next)?;
        self.erase_others(ns, &k, new, Some(next))
    }

    /// `Storage::cmpMultiPageBlob`.
    fn blob_equals(&mut self, idx: &Loc, key: &Key, data: &[u8]) -> R<bool, F> {
        if idx.item.idx_size() as usize != data.len() {
            return Ok(false);
        }
        let (count, start) = (idx.item.data()[4], idx.item.data()[5]);
        let mut offset = 0;
        for c in 0..count {
            let Some(loc) = self.find(idx.item.ns(), key, Match::Chunk(start.wrapping_add(c)), None)? else { return Ok(false) };
            let len = loc.item.var_len();
            let Some(part) = data.get(offset..offset + len) else { return Ok(false) };
            if !self.var_equals(&loc, part)? {
                return Ok(false);
            }
            offset += len;
        }
        Ok(offset == data.len())
    }

    /// `nvs_set_str`: the string and a NUL.
    ///
    /// # Errors
    /// [`Error::ValueTooLong`] above 3999 bytes, [`Error::NoSpace`], [`Error::InvalidKey`], [`Error::InvalidArg`] for a string holding a NUL.
    pub fn set_str(&mut self, namespace: &str, key: &str, value: &str) -> R<(), F> {
        let v = value.as_bytes();
        if v.contains(&0) {
            return Err(Error::InvalidArg);
        }
        if v.len() + 1 > CHUNK_MAX {
            return Err(Error::ValueTooLong);
        }
        let mut stack = [0u8; 64];
        if v.len() < stack.len() {
            stack[..v.len()].copy_from_slice(v);
            return self.set_item(namespace, key, T_SZ, &stack[..v.len() + 1]);
        }
        // Long strings: write the bytes, then the NUL, through the same item (the data is read in place, so build it chunk-free).
        self.set_str_long(namespace, key, v)
    }

    fn set_str_long(&mut self, namespace: &str, key: &str, v: &[u8]) -> R<(), F> {
        // The item writer wants one contiguous slice; the caller's `&str` has no NUL, so a long string needs a scratch copy. Strings this
        // long are not used by the firmware; keep the stack bounded by writing in the page directly.
        self.live()?;
        let k = Key::new(key)?;
        let Some(ns) = self.namespace(namespace, true)? else { return Err(Error::NotFound) };
        let len = v.len() + 1;
        let old = self.find(ns, &k, Match::Primary, None)?;
        if let Some(old) = &old
            && old.item.ty() == T_SZ
            && old.item.var_len() == len
            && self.str_equals(old, v)?
        {
            return Ok(());
        }
        let new = self.write_long_str(ns, &k.b, v)?;
        self.erase_others(ns, &k, new, None)
    }

    fn str_equals(&mut self, loc: &Loc, v: &[u8]) -> R<bool, F> {
        let mut buf = [0u8; ENTRY_SIZE];
        let mut crc = 0xffff_ffff;
        let total = v.len() + 1;
        for k in 0..total.div_ceil(ENTRY_SIZE) {
            let n = (total - k * ENTRY_SIZE).min(ENTRY_SIZE);
            self.rd(eaddr(loc.page, loc.idx + 1 + k), &mut buf[..n])?;
            for (j, &b) in buf[..n].iter().enumerate() {
                let at = k * ENTRY_SIZE + j;
                let want = if at < v.len() { v[at] } else { 0 };
                if b != want {
                    return Ok(false);
                }
            }
            crc = crc32(crc, &buf[..n]);
        }
        Ok(crc == loc.item.var_crc())
    }

    /// A string longer than the stack scratch of [`Nvs::set_str`]: header from a streaming CRC, data entries written in 32-byte steps.
    fn write_long_str(&mut self, ns: u8, key: &[u8; 16], v: &[u8]) -> R<(usize, usize), F> {
        let total = v.len() + 1;
        let entries = 1 + total.div_ceil(ENTRY_SIZE);
        let mut p = self.cur();
        if usize::from(self.info[p].next_free) + entries > ENTRY_COUNT || self.info[p].state == PState::Full {
            if self.info[p].state != PState::Full {
                self.mark_full(p)?;
            }
            self.request_new_page()?;
            p = self.cur();
            if self.info[p].state == PState::Active && usize::from(self.info[p].next_free) + entries > ENTRY_COUNT {
                return Err(Error::NoSpace);
            }
        }
        if self.info[p].state == PState::Uninit {
            self.init_page(p)?;
        }
        let at = usize::from(self.info[p].next_free);
        let mut crc = crc32(0xffff_ffff, v);
        crc = crc32(crc, &[0]);
        let mut d = [0xffu8; 8];
        d[0..2].copy_from_slice(&(total as u16).to_le_bytes());
        d[4..8].copy_from_slice(&crc.to_le_bytes());
        self.write_entry(p, &Item::build(ns, T_SZ, entries as u8, CHUNK_ANY, key, d).raw)?;
        let mut off = 0;
        while off < total {
            let mut e = [0xffu8; 32];
            let n = (total - off).min(ENTRY_SIZE);
            for (j, slot) in e[..n].iter_mut().enumerate() {
                *slot = v.get(off + j).copied().unwrap_or(0);
            }
            self.write_entry(p, &e)?;
            off += n;
        }
        Ok((p, at))
    }

    fn set_prim(&mut self, namespace: &str, key: &str, kind: Kind, bytes: &[u8]) -> R<(), F> {
        debug_assert_eq!(bytes.len(), kind.width());
        self.set_item(namespace, key, kind.code(), bytes)
    }

    /// `nvs_set_u8`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_u8(&mut self, namespace: &str, key: &str, v: u8) -> R<(), F> {
        self.set_prim(namespace, key, Kind::U8, &[v])
    }

    /// `nvs_set_i8`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_i8(&mut self, namespace: &str, key: &str, v: i8) -> R<(), F> {
        self.set_prim(namespace, key, Kind::I8, &v.to_le_bytes())
    }

    /// `nvs_set_u16`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_u16(&mut self, namespace: &str, key: &str, v: u16) -> R<(), F> {
        self.set_prim(namespace, key, Kind::U16, &v.to_le_bytes())
    }

    /// `nvs_set_i16`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_i16(&mut self, namespace: &str, key: &str, v: i16) -> R<(), F> {
        self.set_prim(namespace, key, Kind::I16, &v.to_le_bytes())
    }

    /// `nvs_set_u32`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_u32(&mut self, namespace: &str, key: &str, v: u32) -> R<(), F> {
        self.set_prim(namespace, key, Kind::U32, &v.to_le_bytes())
    }

    /// `nvs_set_i32`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_i32(&mut self, namespace: &str, key: &str, v: i32) -> R<(), F> {
        self.set_prim(namespace, key, Kind::I32, &v.to_le_bytes())
    }

    /// `nvs_set_u64`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_u64(&mut self, namespace: &str, key: &str, v: u64) -> R<(), F> {
        self.set_prim(namespace, key, Kind::U64, &v.to_le_bytes())
    }

    /// `nvs_set_i64`.
    ///
    /// # Errors
    /// See [`Nvs::set_blob`].
    pub fn set_i64(&mut self, namespace: &str, key: &str, v: i64) -> R<(), F> {
        self.set_prim(namespace, key, Kind::I64, &v.to_le_bytes())
    }

    // ---- erasing ----------------------------------------------------------------------------------------------------------------

    /// `nvs_erase_key`: erase the item (a blob's index first, then its chunks).
    ///
    /// # Errors
    /// [`Error::NotFound`] when the namespace or key does not exist (the C callers tolerate that), [`Error::Flash`].
    pub fn erase_key(&mut self, namespace: &str, key: &str) -> R<(), F> {
        self.live()?;
        let k = Key::new(key)?;
        let Some(ns) = self.namespace(namespace, false)? else { return Err(Error::NotFound) };
        let Some(loc) = self.find(ns, &k, Match::Primary, None)? else { return Err(Error::NotFound) };
        if loc.item.ty() == T_BLOB_IDX { self.erase_multipage(&loc, None) } else { self.erase_entry_and_span(loc.page, loc.idx) }
    }

    /// `nvs_erase_all`: erase every item of the namespace; the namespace itself stays. Nothing to do (and no error) when the namespace does
    /// not exist. IDF walks the pages entry by entry, which can erase a blob's chunks before its index and leave the key half-erased if the
    /// power goes; this version erases everything that is not a chunk first (indexes make a blob disappear in one step), then the chunks
    /// (now orphans, which mount would erase anyway), so every key is either whole or gone at any instant.
    ///
    /// # Errors
    /// [`Error::Flash`].
    pub fn erase_namespace(&mut self, namespace: &str) -> R<(), F> {
        self.live()?;
        let Some(ns) = self.namespace(namespace, false)? else { return Ok(()) };
        for chunks in [false, true] {
            for k in 0..self.n_order {
                let p = usize::from(self.order[k]);
                loop {
                    let table = self.table(p)?;
                    let mut i = 0;
                    let mut hit = None;
                    while let Some((idx, it)) = self.next_live(p, &table, i)? {
                        i = idx + it.advance();
                        if it.ns() == ns && (it.ty() == T_BLOB_DATA) == chunks {
                            hit = Some(idx);
                            break;
                        }
                    }
                    let Some(idx) = hit else { break };
                    self.erase_entry_and_span(p, idx)?;
                }
            }
        }
        Ok(())
    }

    // ---- reading ----------------------------------------------------------------------------------------------------------------

    fn get_item(&mut self, namespace: &str, key: &str) -> R<Option<Loc>, F> {
        self.live()?;
        let k = Key::new(key)?;
        let Some(ns) = self.namespace(namespace, false)? else { return Ok(None) };
        self.find(ns, &k, Match::Primary, None)
    }

    fn get_prim(&mut self, namespace: &str, key: &str, kind: Kind) -> R<Option<[u8; 8]>, F> {
        let Some(loc) = self.get_item(namespace, key)? else { return Ok(None) };
        if loc.item.ty() != kind.code() {
            return Err(Error::TypeMismatch);
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(loc.item.data());
        Ok(Some(out))
    }

    /// `nvs_get_u8`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// [`Error::TypeMismatch`], [`Error::Flash`].
    pub fn get_u8(&mut self, namespace: &str, key: &str) -> R<Option<u8>, F> {
        Ok(self.get_prim(namespace, key, Kind::U8)?.map(|d| d[0]))
    }

    /// `nvs_get_u16`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// See [`Nvs::get_u8`].
    pub fn get_u16(&mut self, namespace: &str, key: &str) -> R<Option<u16>, F> {
        Ok(self.get_prim(namespace, key, Kind::U16)?.map(|d| u16::from_le_bytes([d[0], d[1]])))
    }

    /// `nvs_get_u32`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// See [`Nvs::get_u8`].
    pub fn get_u32(&mut self, namespace: &str, key: &str) -> R<Option<u32>, F> {
        Ok(self.get_prim(namespace, key, Kind::U32)?.map(|d| le32(&d)))
    }

    /// `nvs_get_i32`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// See [`Nvs::get_u8`].
    pub fn get_i32(&mut self, namespace: &str, key: &str) -> R<Option<i32>, F> {
        Ok(self.get_prim(namespace, key, Kind::I32)?.map(|d| le32(&d) as i32))
    }

    /// `nvs_get_u64`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// See [`Nvs::get_u8`].
    pub fn get_u64(&mut self, namespace: &str, key: &str) -> R<Option<u64>, F> {
        Ok(self.get_prim(namespace, key, Kind::U64)?.map(u64::from_le_bytes))
    }

    /// The raw primitive of any width: the item's 8 data bytes (little endian, unused bytes 0xFF), with its kind.
    ///
    /// # Errors
    /// [`Error::TypeMismatch`] for a string or blob, [`Error::Flash`].
    pub fn get_raw(&mut self, namespace: &str, key: &str) -> R<Option<(Kind, [u8; 8])>, F> {
        let Some(loc) = self.get_item(namespace, key)? else { return Ok(None) };
        let kind = match loc.item.ty() {
            T_U8 => Kind::U8,
            T_I8 => Kind::I8,
            T_U16 => Kind::U16,
            T_I16 => Kind::I16,
            T_U32 => Kind::U32,
            T_I32 => Kind::I32,
            T_U64 => Kind::U64,
            T_I64 => Kind::I64,
            _ => return Err(Error::TypeMismatch),
        };
        let mut out = [0u8; 8];
        out.copy_from_slice(loc.item.data());
        Ok(Some((kind, out)))
    }

    /// Whether `namespace`/`key` exists, of any type.
    ///
    /// # Errors
    /// [`Error::Flash`].
    pub fn contains(&mut self, namespace: &str, key: &str) -> R<bool, F> {
        Ok(self.get_item(namespace, key)?.is_some())
    }

    /// `nvs_get_str` into `out`; returns the length without the NUL, `Ok(None)` when absent. A string whose data fails its CRC is erased
    /// (as IDF does) and reported as [`Error::Corrupt`].
    ///
    /// # Errors
    /// [`Error::TooSmall`] when `out` cannot hold the string and its NUL, [`Error::TypeMismatch`], [`Error::Corrupt`], [`Error::Flash`].
    pub fn get_str(&mut self, namespace: &str, key: &str, out: &mut [u8]) -> R<Option<usize>, F> {
        let Some(loc) = self.get_item(namespace, key)? else { return Ok(None) };
        if loc.item.ty() != T_SZ {
            return Err(Error::TypeMismatch);
        }
        let len = loc.item.var_len();
        let dst = out.get_mut(..len).ok_or(Error::TooSmall)?;
        if !self.read_var(&loc, dst)? {
            self.erase_entry_and_span(loc.page, loc.idx)?;
            return Err(Error::Corrupt);
        }
        Ok(Some(len.saturating_sub(1)))
    }

    /// The length of the string (without NUL) or blob, from the item header only.
    ///
    /// # Errors
    /// [`Error::TypeMismatch`] for a primitive, [`Error::Flash`].
    pub fn value_len(&mut self, namespace: &str, key: &str) -> R<Option<usize>, F> {
        let Some(loc) = self.get_item(namespace, key)? else { return Ok(None) };
        match loc.item.ty() {
            T_BLOB => Ok(Some(loc.item.var_len())),
            T_BLOB_IDX => Ok(Some(loc.item.idx_size() as usize)),
            T_SZ => Ok(Some(loc.item.var_len().saturating_sub(1))),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// `nvs_get_blob` into `out`; returns the length, `Ok(None)` when absent. Handles both the v1 single-item and the v2 chunked form.
    /// Every byte returned passed its CRC. A blob that fails verification is erased (as IDF does) and reported as [`Error::Corrupt`].
    ///
    /// # Errors
    /// [`Error::TooSmall`], [`Error::TypeMismatch`], [`Error::Corrupt`], [`Error::Flash`].
    pub fn get_blob(&mut self, namespace: &str, key: &str, out: &mut [u8]) -> R<Option<usize>, F> {
        let Some(loc) = self.get_item(namespace, key)? else { return Ok(None) };
        match loc.item.ty() {
            T_BLOB => {
                let dst = out.get_mut(..loc.item.var_len()).ok_or(Error::TooSmall)?;
                if !self.read_var(&loc, dst)? {
                    self.erase_entry_and_span(loc.page, loc.idx)?;
                    return Err(Error::Corrupt);
                }
                Ok(Some(loc.item.var_len()))
            }
            T_BLOB_IDX => {
                let total = loc.item.idx_size() as usize;
                if total > out.len() {
                    return Err(Error::TooSmall);
                }
                let (count, start) = (loc.item.data()[4], loc.item.data()[5]);
                let k = Key::new(key)?;
                let mut done = 0usize;
                let mut ok = (start == VER_0 || start == VER_1) && count <= 127;
                for c in 0..if ok { count } else { 0 } {
                    let Some(chunk) = self.find(loc.item.ns(), &k, Match::Chunk(start + c), None)? else {
                        ok = false;
                        break;
                    };
                    let len = chunk.item.var_len();
                    let Some(dst) = out.get_mut(done..done + len).filter(|_| done + len <= total) else {
                        ok = false;
                        break;
                    };
                    if !self.read_var(&chunk, dst)? {
                        ok = false;
                        break;
                    }
                    done += len;
                }
                if ok && done == total {
                    Ok(Some(total))
                } else {
                    self.erase_multipage(&loc, None)?;
                    Err(Error::Corrupt)
                }
            }
            _ => Err(Error::TypeMismatch),
        }
    }

    /// The name of namespace index `ns`, NUL padded.
    ///
    /// # Errors
    /// [`Error::Flash`].
    pub fn namespace_name(&mut self, ns: u8) -> R<Option<[u8; 16]>, F> {
        self.live()?;
        let mut cur = Cursor::default();
        while let Some(info) = self.next_item(&mut cur)? {
            if info.namespace == 0
                && info.kind == Kind::U8
                && let Some(loc) = self.find_raw(0, &info.key, Match::Primary)?
                && loc.item.data()[0] == ns
            {
                return Ok(Some(info.key));
            }
        }
        Ok(None)
    }

    /// The next live item (primitive, string, blob; chunks and indexes are folded into their blob), pages oldest first. For inspection and
    /// tests; the newest of two items with the same key is not singled out, a mounted partition has no such pair.
    ///
    /// # Errors
    /// [`Error::Flash`].
    pub fn next_item(&mut self, cur: &mut Cursor) -> R<Option<ItemInfo>, F> {
        self.live()?;
        while cur.page < self.n_order {
            let p = usize::from(self.order[cur.page]);
            let table = self.table(p)?;
            while let Some((idx, it)) = self.next_live(p, &table, cur.entry)? {
                cur.entry = idx + it.advance();
                let (kind, size) = match it.ty() {
                    T_U8 => (Kind::U8, 1),
                    T_I8 => (Kind::I8, 1),
                    T_U16 => (Kind::U16, 2),
                    T_I16 => (Kind::I16, 2),
                    T_U32 => (Kind::U32, 4),
                    T_I32 => (Kind::I32, 4),
                    T_U64 => (Kind::U64, 8),
                    T_I64 => (Kind::I64, 8),
                    T_SZ => (Kind::Str, it.var_len()),
                    T_BLOB => (Kind::Blob, it.var_len()),
                    T_BLOB_IDX => (Kind::Blob, it.idx_size() as usize),
                    _ => continue,
                };
                return Ok(Some(ItemInfo { namespace: it.ns(), key: it.key16(), kind, size }));
            }
            cur.page += 1;
            cur.entry = 0;
        }
        Ok(None)
    }
}
