//! A read-only parser of the ESP-IDF NVS on-flash format (ESP-IDF v5.5, format versions 1 and 2), for `no_std` firmware that has no
//! ESP-IDF underneath it but must read what the C firmware saved in the `nvs` partition.
//!
//! * Strictly read-only: the only flash access is [`Flash::read`]; there is no write or erase path.
//! * No allocation and no unsafe code; the working set is a few 32-byte entry buffers on the stack (well under 512 bytes), because
//!   everything is read piecewise through [`Flash::read`]. Blob contents are read straight into the caller's buffer.
//! * Garbage-safe: every length, span and index read from flash is bounds-checked, and every item header, page header and data run is
//!   CRC-32 checked. An item or page that fails a check is skipped as if absent (the C code erases such items on load); a variable
//!   length value whose data CRC fails is reported as [`Error::Corrupt`] rather than trusted.
//!
//! # Format notes
//!
//! A partition is a sequence of 4096-byte pages. Each page has a 32-byte header (state, sequence number, version, CRC-32 over bytes
//! 4..28), a 32-byte entry-state bitmap (2 bits per entry, 126 entries: `11` empty, `10` written, `00` erased) and 126 32-byte entries.
//! An item is an entry (namespace index, type, span, chunk index, CRC-32, 15-byte key, 8 bytes of data) followed by `span - 1` data
//! entries for strings and blobs. Namespaces are items in namespace 0 of type `U8` whose key is the name and whose value is the
//! namespace index. The same `(namespace, key)` can appear several times (an update appends a new item and erases the old one, but a
//! power cut or an unfinished page move can leave both): the item on the page with the highest sequence number wins, and within a page
//! the later entry wins. Chunked blobs (v2) are a `BLOB_IDX` item (total size, chunk count, chunk start 0 or 0x80) plus `BLOB_DATA`
//! items with chunk indices `start..start + count`; v1 blobs are a single `BLOB` item.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

/// Read access to the NVS partition. Implementations must never write or erase.
pub trait Flash {
    /// The error of a failed read.
    type Error;

    /// Fill `buf` with the bytes at `offset`, relative to the start of the NVS partition.
    ///
    /// # Errors
    /// Whatever the underlying flash driver reports.
    fn read(&self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// A [`Flash`] over a byte slice holding an image of the partition, for host tools and tests.
#[derive(Debug, Clone, Copy)]
pub struct SliceFlash<'a>(pub &'a [u8]);

/// A read past the end of a [`SliceFlash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfRange;

impl Flash for SliceFlash<'_> {
    type Error = OutOfRange;

    fn read(&self, offset: u32, buf: &mut [u8]) -> Result<(), OutOfRange> {
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or(OutOfRange)?;
        buf.copy_from_slice(self.0.get(start..end).ok_or(OutOfRange)?);
        Ok(())
    }
}

/// Why a lookup failed. "Not found" is not an error (the getters return `Ok(None)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<E> {
    /// [`Flash::read`] failed.
    Flash(E),
    /// The output buffer is shorter than the blob.
    TooSmall,
    /// The item exists but has another type than the getter asks for.
    TypeMismatch,
    /// The item's data is damaged: bad data CRC, inconsistent chunk list, or a missing chunk.
    Corrupt,
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flash(e) => write!(f, "flash read failed: {e:?}"),
            Self::TooSmall => f.write_str("output buffer too small"),
            Self::TypeMismatch => f.write_str("item has a different type"),
            Self::Corrupt => f.write_str("item data is corrupt"),
        }
    }
}

impl<E: fmt::Debug> core::error::Error for Error<E> {}

const PAGE_SIZE: u32 = 4096;
const ENTRY_SIZE: usize = 32;
const ENTRY_COUNT: usize = 126;
const FIRST_ENTRY: u32 = 64;
const MAX_KEY: usize = 15;
const CHUNK_ANY: u8 = 0xff;

const T_U8: u8 = 0x01;
const T_SZ: u8 = 0x21;
const T_BLOB: u8 = 0x41;
const T_BLOB_DATA: u8 = 0x42;
const T_BLOB_IDX: u8 = 0x48;

/// Nibble-wise CRC-32 table (reflected polynomial `0xEDB88320`): 64 bytes of flash instead of the 1 KiB byte table.
const CRC_NIBBLE: [u32; 16] = {
    let mut t = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 4 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// zlib-style incremental CRC-32 (what `esp_rom_crc32_le` computes); start from `0xffff_ffff`.
fn crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c ^= u32::from(b);
        c = (c >> 4) ^ CRC_NIBBLE[(c & 0xf) as usize];
        c = (c >> 4) ^ CRC_NIBBLE[(c & 0xf) as usize];
    }
    !c
}

fn le32(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    for (d, s) in a.iter_mut().zip(b) {
        *d = *s;
    }
    u32::from_le_bytes(a)
}

/// A validated item header.
#[derive(Clone, Copy)]
struct Item {
    ns: u8,
    ty: u8,
    span: u8,
    chunk: u8,
    key: [u8; 16],
    data: [u8; 8],
}

impl Item {
    /// The ESP-IDF `Item::checkHeaderConsistency` rules, including the header CRC. `index` is the entry index within the page.
    fn parse(raw: &[u8; ENTRY_SIZE], index: usize) -> Option<Self> {
        let crc = crc32(crc32(0xffff_ffff, &raw[0..4]), &raw[8..32]);
        if crc != le32(&raw[4..8]) {
            return None;
        }
        let mut item = Self { ns: raw[0], ty: raw[1], span: raw[2], chunk: raw[3], key: [0; 16], data: [0; 8] };
        item.key.copy_from_slice(&raw[8..24]);
        item.data.copy_from_slice(&raw[24..32]);
        let left = ENTRY_COUNT - index; // entries from this one to the end of the page
        match item.ty {
            0x01 | 0x11 | 0x02 | 0x12 | 0x04 | 0x14 | 0x08 | 0x18 => (item.span == 1).then_some(item),
            T_BLOB_IDX => {
                let max = (255 / 2) * (ENTRY_COUNT as u32 - 1) * ENTRY_SIZE as u32;
                (item.span == 1 && item.chunk == CHUNK_ANY && le32(&item.data[0..4]) <= max).then_some(item)
            }
            T_SZ | T_BLOB | T_BLOB_DATA => {
                if item.ty == T_BLOB_DATA && item.chunk == CHUNK_ANY {
                    return None;
                }
                let len = usize::from(u16::from_le_bytes([item.data[0], item.data[1]]));
                let fits = len <= (left - 1) * ENTRY_SIZE && usize::from(item.span) <= left;
                (fits && usize::from(item.span) == len.div_ceil(ENTRY_SIZE) + 1).then_some(item)
            }
            _ => None,
        }
    }

    fn var_len(&self) -> usize {
        usize::from(u16::from_le_bytes([self.data[0], self.data[1]]))
    }

    fn var_crc(&self) -> u32 {
        le32(&self.data[4..8])
    }

    fn key_is(&self, key: &[u8]) -> bool {
        key.len() <= MAX_KEY && self.key.get(..key.len()) == Some(key) && self.key.get(key.len()) == Some(&0)
    }
}

/// Which item to look for.
#[derive(Clone, Copy)]
enum Want {
    /// Any type except `BLOB_DATA` chunks (so the newest of v1 blob / v2 index / primitive / string wins).
    Primary,
    /// The `BLOB_DATA` chunk with this chunk index.
    Chunk(u8),
}

struct Found {
    item: Item,
    /// Partition offset of the first data entry (the one after the header entry).
    data_at: u32,
}

/// A read-only view of an NVS partition.
#[derive(Debug)]
pub struct Nvs<F: Flash> {
    flash: F,
    pages: u32,
}

impl<F: Flash> Nvs<F> {
    /// A reader over `flash`; `size` is the partition size in bytes (`0x10000` for this firmware), rounded down to whole pages.
    pub fn new(flash: F, size: u32) -> Self {
        Self { flash, pages: size / PAGE_SIZE }
    }

    /// Give the flash back.
    pub fn into_inner(self) -> F {
        self.flash
    }

    /// The `U8` stored at `namespace`/`key`. `Ok(None)` if absent (or the names are longer than 15 bytes), [`Error::TypeMismatch`] if
    /// the newest item with that key has another type.
    ///
    /// # Errors
    /// [`Error::Flash`] or [`Error::TypeMismatch`].
    pub fn get_u8(&mut self, namespace: &str, key: &str) -> Result<Option<u8>, Error<F::Error>> {
        let Some(found) = self.lookup(namespace, key)? else { return Ok(None) };
        if found.item.ty == T_U8 { Ok(Some(found.item.data[0])) } else { Err(Error::TypeMismatch) }
    }

    /// The length in bytes of the blob at `namespace`/`key`, from its header only (the data CRC is checked by [`Self::get_blob`]).
    ///
    /// # Errors
    /// [`Error::Flash`] or [`Error::TypeMismatch`].
    pub fn blob_len(&mut self, namespace: &str, key: &str) -> Result<Option<usize>, Error<F::Error>> {
        let Some(found) = self.lookup(namespace, key)? else { return Ok(None) };
        match found.item.ty {
            T_BLOB => Ok(Some(found.item.var_len())),
            T_BLOB_IDX => Ok(Some(le32(&found.item.data[0..4]) as usize)),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Copy the blob at `namespace`/`key` into `out` and return its length. `Ok(None)` if absent. Every byte returned has passed its
    /// CRC-32 check.
    ///
    /// # Errors
    /// [`Error::TooSmall`] if `out` is shorter than the blob, [`Error::Corrupt`] if its data fails verification,
    /// [`Error::TypeMismatch`] or [`Error::Flash`].
    pub fn get_blob(&mut self, namespace: &str, key: &str, out: &mut [u8]) -> Result<Option<usize>, Error<F::Error>> {
        let Some(found) = self.lookup(namespace, key)? else { return Ok(None) };
        match found.item.ty {
            T_BLOB => {
                let len = found.item.var_len();
                let dst = out.get_mut(..len).ok_or(Error::TooSmall)?;
                self.read_verified(found.data_at, dst, found.item.var_crc())?;
                Ok(Some(len))
            }
            T_BLOB_IDX => {
                let total = le32(&found.item.data[0..4]) as usize;
                let (count, start) = (found.item.data[4], found.item.data[5]);
                if total > out.len() {
                    return Err(Error::TooSmall);
                }
                if (start != 0 && start != 0x80) || count > 127 || (count == 0 && total != 0) {
                    return Err(Error::Corrupt);
                }
                let ns = found.item.ns;
                let key = key.as_bytes();
                let mut done = 0usize;
                for i in 0..count {
                    let chunk = self.find(ns, key, Want::Chunk(start + i))?.ok_or(Error::Corrupt)?;
                    let len = chunk.item.var_len();
                    let end = done.checked_add(len).filter(|&e| e <= total).ok_or(Error::Corrupt)?;
                    let dst = out.get_mut(done..end).ok_or(Error::Corrupt)?;
                    self.read_verified(chunk.data_at, dst, chunk.item.var_crc())?;
                    done = end;
                }
                if done == total { Ok(Some(total)) } else { Err(Error::Corrupt) }
            }
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Whether a string exists at `namespace`/`key` and its data passes its CRC-32 check (the string itself is not returned: callers
    /// of this reader only need to know that one is saved).
    ///
    /// # Errors
    /// [`Error::Corrupt`] if the data CRC fails, [`Error::TypeMismatch`] if the newest item is not a string, [`Error::Flash`].
    pub fn has_str(&mut self, namespace: &str, key: &str) -> Result<bool, Error<F::Error>> {
        let Some(found) = self.lookup(namespace, key)? else { return Ok(false) };
        if found.item.ty != T_SZ {
            return Err(Error::TypeMismatch);
        }
        let (mut crc, mut at, mut left) = (0xffff_ffff, found.data_at, found.item.var_len());
        let mut buf = [0u8; ENTRY_SIZE];
        while left > 0 {
            let n = left.min(ENTRY_SIZE);
            self.flash.read(at, &mut buf[..n]).map_err(Error::Flash)?;
            crc = crc32(crc, &buf[..n]);
            at += ENTRY_SIZE as u32;
            left -= n;
        }
        if crc == found.item.var_crc() { Ok(true) } else { Err(Error::Corrupt) }
    }

    fn lookup(&mut self, namespace: &str, key: &str) -> Result<Option<Found>, Error<F::Error>> {
        let (ns, key) = (namespace.as_bytes(), key.as_bytes());
        if key.is_empty() || key.len() > MAX_KEY || ns.is_empty() || ns.len() > MAX_KEY {
            return Ok(None);
        }
        let Some(entry) = self.find(0, ns, Want::Primary)? else { return Ok(None) };
        let index = entry.item.data[0];
        if entry.item.ty != T_U8 || index == 0 || index == 0xff {
            return Ok(None);
        }
        self.find(index, key, Want::Primary)
    }

    /// The newest valid item with this namespace index and key: highest page sequence number, then highest page, then highest entry.
    fn find(&mut self, ns: u8, key: &[u8], want: Want) -> Result<Option<Found>, Error<F::Error>> {
        let mut best: Option<((u32, u32, usize), Found)> = None;
        for page in 0..self.pages {
            let base = page * PAGE_SIZE;
            let Some(seq) = self.page_seq(base)? else { continue };
            let mut bitmap = [0u8; 32];
            self.flash.read(base + 32, &mut bitmap).map_err(Error::Flash)?;
            let mut i = 0;
            while i < ENTRY_COUNT {
                if (bitmap[i / 4] >> ((i % 4) * 2)) & 3 != 2 {
                    i += 1;
                    continue;
                }
                let at = base + FIRST_ENTRY + (i * ENTRY_SIZE) as u32;
                let mut raw = [0u8; ENTRY_SIZE];
                self.flash.read(at, &mut raw).map_err(Error::Flash)?;
                let Some(item) = Item::parse(&raw, i) else {
                    i += 1;
                    continue;
                };
                let wanted = item.ns == ns
                    && item.key_is(key)
                    && match want {
                        Want::Primary => item.ty != T_BLOB_DATA,
                        Want::Chunk(c) => item.ty == T_BLOB_DATA && item.chunk == c,
                    };
                let rank = (seq, page, i);
                if wanted && best.as_ref().is_none_or(|(r, _)| rank > *r) {
                    best = Some((rank, Found { item, data_at: at + ENTRY_SIZE as u32 }));
                }
                i += usize::from(item.span).max(1);
            }
        }
        Ok(best.map(|(_, f)| f))
    }

    /// The sequence number of the page at `base` if it is a usable page: ACTIVE, FULL or FREEING state, v1 or v2, header CRC good.
    fn page_seq(&self, base: u32) -> Result<Option<u32>, Error<F::Error>> {
        let mut h = [0u8; ENTRY_SIZE];
        self.flash.read(base, &mut h).map_err(Error::Flash)?;
        let state_ok = matches!(le32(&h[0..4]), 0xffff_fffe | 0xffff_fffc | 0xffff_fff8);
        let version_ok = h[8] == 0xff || h[8] == 0xfe;
        let crc_ok = crc32(0xffff_ffff, &h[4..28]) == le32(&h[28..32]);
        Ok((state_ok && version_ok && crc_ok).then(|| le32(&h[4..8])))
    }

    fn read_verified(&self, at: u32, dst: &mut [u8], crc: u32) -> Result<(), Error<F::Error>> {
        self.flash.read(at, dst).map_err(Error::Flash)?;
        if crc32(0xffff_ffff, dst) == crc { Ok(()) } else { Err(Error::Corrupt) }
    }
}
