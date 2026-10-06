//! A writer for the ESP-IDF NVS on-flash format (v2, ESP-IDF v5.5), for `no_std` firmware that shares its `nvs` partition with the C
//! firmware (and with ESP-IDF's own `nvs_flash`, `nvs_partition_gen.py` and `nvs_parser.py`).
//!
//! * [`Nvs`] is the storage engine: it mounts a partition the way `nvs::PageManager::load` and `nvs::Storage::init` do (page classification,
//!   sequence numbers, interrupted-write and interrupted-page-move recovery, blob orphan clean-up) and writes the way `nvs::Storage` does:
//!   namespaces, primitives, strings, single-page `BLOB` reads, multi-chunk `BLOB_DATA` + `BLOB_IDX` writes with the version toggle, "write the
//!   new item, then mark the old one erased", entry-state bits, page states `ACTIVE` / `FULL` / `FREEING`, and page compaction that keeps one
//!   spare page. Every flash write is word aligned and only clears bits (NOR semantics), in the same order IDF uses, so a power cut at any
//!   byte leaves a state that ESP-IDF's C code, [`tdongle-nvs-read`] and this crate's own mount all accept.
//! * [`Store`] is what the firmware calls: `load_all`, `save_profiles`, `save_display`, `save_mode`, `factory_reset`, `import_legacy`, with
//!   the same key names, blob layouts and write order as the C (`wifi_save_with`, `display_save`, `tdongle_mode_save`, `wifi_factory_reset`).
//! * [`Flash`] is the one trait the firmware implements (over `esp-storage` and the partition offset). Feature `sim` adds [`SimFlash`], an
//!   in-memory flash with power-loss injection.
//!
//! No allocation, no unsafe code. The working set is a few 32-byte buffers on the stack plus [`Nvs`] itself (about 0.5 KiB).
//!
//! # Atomicity
//!
//! `nvs_commit` of the C is a no-op for the storage engine (every set is on flash when it returns) and so is [`Nvs::commit`]. The unit of
//! atomicity is one item: a power cut during `set_blob` leaves either the old value or the new one, never a mixture, and no other key is
//! affected. Two items written one after the other (`wifi_meta` then `wifi_profiles`) are two commits, exactly as in C; see
//! [`Store::save_profiles`] for what a cut between them leaves.
//!
//! [`tdongle-nvs-read`]: https://docs.rs/tdongle-nvs-read

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "sim")]
extern crate std;

mod crc;
#[cfg(feature = "embedded-storage")]
mod nor;
mod nvs;
#[cfg(feature = "sim")]
mod sim;
mod store;

use core::fmt;

pub use crc::crc32;
#[cfg(feature = "embedded-storage")]
pub use nor::NorPartition;
pub use nvs::{Cursor, ENTRY_COUNT, ENTRY_SIZE, ItemInfo, Kind, MAX_PAGES, MIN_PAGES, Nvs, PAGE_SIZE, Stats};
#[cfg(feature = "sim")]
pub use sim::{SimError, SimFlash, Tear};
pub use store::{LoadError, NS_ADAPTER, NS_SETTINGS, Settings, Store};

/// The NVS partition as the engine sees it. Offsets are relative to the start of the partition (the firmware adds `0x9000`).
///
/// NOR semantics: a sector erases to `0xFF`; a write can only clear bits (`new = old & data`). The engine never relies on a write setting a
/// bit, and always writes at 4-byte aligned offsets in multiples of 4 bytes (the alignment `esp-storage` requires on the ESP32-S3), so
/// the implementation can pass them straight to the driver. A write that is cut by a power loss may leave any prefix of the bytes
/// programmed (and the last byte partly); an erase that is cut may leave the sector in any state between old and blank. The engine
/// is built for exactly that.
pub trait Flash {
    /// The error of a failed operation.
    type Error: fmt::Debug;

    /// Fill `buf` with the bytes at `offset`.
    ///
    /// # Errors
    /// Whatever the driver reports.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Program `data` at `offset` (4-byte aligned, a multiple of 4 bytes long). Bits only go from 1 to 0.
    ///
    /// # Errors
    /// Whatever the driver reports.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;

    /// Erase the 4096-byte sector number `sector` of the partition (offset `sector * 4096`) to `0xFF`.
    ///
    /// # Errors
    /// Whatever the driver reports.
    fn erase_sector(&mut self, sector: u32) -> Result<(), Self::Error>;
}

/// Why an operation failed. After [`Error::Flash`] (or any error that is not a plain refusal) the in-RAM view may be stale: the engine
/// refuses everything with [`Error::Broken`] until [`Nvs::mount`] succeeds again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// The [`Flash`] driver failed.
    Flash(E),
    /// No such namespace or key (`ESP_ERR_NVS_NOT_FOUND`).
    NotFound,
    /// The key exists with another type than the getter asks for (`ESP_ERR_NVS_TYPE_MISMATCH`).
    TypeMismatch,
    /// A key or namespace name that is empty, longer than 15 bytes or contains a NUL (`ESP_ERR_NVS_KEY_TOO_LONG` and friends).
    InvalidKey,
    /// A string or blob that does not fit (`ESP_ERR_NVS_VALUE_TOO_LONG`).
    ValueTooLong,
    /// The caller's buffer is shorter than the value (`ESP_ERR_NVS_INVALID_LENGTH`).
    TooSmall,
    /// Not enough free space even after compaction (`ESP_ERR_NVS_NOT_ENOUGH_SPACE`).
    NoSpace,
    /// The partition has no free page after loading, so it cannot be written (`ESP_ERR_NVS_NO_FREE_PAGES`): the caller decides whether to
    /// erase it.
    NoFreePages,
    /// A page was written by a newer format than this crate knows (`ESP_ERR_NVS_NEW_VERSION_FOUND`).
    NewVersion,
    /// The stored data failed its CRC. The damaged item has been erased, as IDF does, so a second read says [`Error::NotFound`].
    Corrupt,
    /// An argument that cannot be stored (a primitive wider than 8 bytes, a partition smaller than [`MIN_PAGES`] or larger than [`MAX_PAGES`]).
    InvalidArg,
    /// The engine is not mounted, or a previous operation failed in the middle: mount again.
    Broken,
    /// Internal: the current page cannot take this item. Never returned by the public operations.
    PageFull,
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flash(e) => write!(f, "flash failed: {e:?}"),
            Self::NotFound => f.write_str("not found"),
            Self::TypeMismatch => f.write_str("type mismatch"),
            Self::InvalidKey => f.write_str("invalid key or namespace name"),
            Self::ValueTooLong => f.write_str("value too long"),
            Self::TooSmall => f.write_str("buffer too small"),
            Self::NoSpace => f.write_str("not enough space"),
            Self::NoFreePages => f.write_str("no free page"),
            Self::NewVersion => f.write_str("newer NVS format"),
            Self::Corrupt => f.write_str("stored data is corrupt"),
            Self::InvalidArg => f.write_str("invalid argument"),
            Self::Broken => f.write_str("storage needs to be mounted again"),
            Self::PageFull => f.write_str("page full"),
        }
    }
}

impl<E: fmt::Debug> core::error::Error for Error<E> {}
