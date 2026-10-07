//! The peer directory's flash: the `peerstore` partition (`0x420000`, 4 MB, the C's FAT volume; here raw) behind [`DirFlash`].
//!
//! The settings task owns the NVS's `FlashStorage`; the directory has one of its own, made on first use from the peripheral (`esp-storage` takes its own lock around every
//! command to the chip, so two instances cannot interleave one). A sector erase masks interrupts for its ~45 ms, one call at a
//! time (the loop of a commit gives the radio and USB their turns between sectors).

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use esp_storage::{FlashStorage, FlashStorageError};
use tdongle_tailnet_engine::flashdir::{DirFlash, SECTOR};

/// Start of the `peerstore` partition.
pub const PEERSTORE_OFFSET: u32 = 0x42_0000;
/// Size of the `peerstore` partition.
pub const PEERSTORE_SIZE: usize = 0x40_0000;

struct Chip(RefCell<Option<FlashStorage<'static>>>);
// SAFETY: the directory is used only under the tailnet runtime's `TaskLock` (tasks of the one thread executor, never concurrently), and `mount` runs before any of them.
unsafe impl Sync for Chip {}
static FLASH: Chip = Chip(RefCell::new(None));

/// Flash operations that failed, and the last failure: `op` 1 read, 2 erase, 3 write; the error's name; the partition offset; the ROM's code for `Other`.
pub static ERRS: AtomicU32 = AtomicU32::new(0);
/// Flash operations that succeeded (erase and write).
pub static OKS: AtomicU32 = AtomicU32::new(0);
static LAST_OP: AtomicU32 = AtomicU32::new(0);
static LAST_ERR: AtomicU32 = AtomicU32::new(0);
static LAST_OFF: AtomicU32 = AtomicU32::new(0);
static LAST_RC: AtomicU32 = AtomicU32::new(0);

fn note(op: u32, off: usize, r: Result<(), FlashStorageError>) -> bool {
    match r {
        Ok(()) => {
            OKS.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(e) => {
            ERRS.fetch_add(1, Ordering::Relaxed);
            LAST_OP.store(op, Ordering::Relaxed);
            LAST_OFF.store(off as u32, Ordering::Relaxed);
            let (code, rc) = match e {
                FlashStorageError::IoError => (1, 0),
                FlashStorageError::IoTimeout => (2, 0),
                FlashStorageError::CantUnlock => (3, 0),
                FlashStorageError::NotAligned => (4, 0),
                FlashStorageError::OutOfBounds => (5, 0),
                FlashStorageError::NotSupported => (6, 0),
                FlashStorageError::OtherCoreRunning => (7, 0),
                FlashStorageError::Other(n) => (8, n),
                #[allow(unreachable_patterns)]
                _ => (255, 0),
            };
            LAST_ERR.store(code, Ordering::Relaxed);
            LAST_RC.store(rc as u32, Ordering::Relaxed);
            false
        }
    }
}

/// `tn_dir` console line: how many flash operations the directory did, and the last failure.
pub fn report(out: &mut impl core::fmt::Write) {
    let name = match LAST_ERR.load(Ordering::Relaxed) {
        0 => "none",
        1 => "IoError",
        2 => "IoTimeout",
        3 => "CantUnlock",
        4 => "NotAligned",
        5 => "OutOfBounds",
        6 => "NotSupported",
        7 => "OtherCoreRunning",
        8 => "Other",
        _ => "unknown",
    };
    let op = match LAST_OP.load(Ordering::Relaxed) {
        1 => "read",
        2 => "erase",
        3 => "write",
        _ => "-",
    };
    let _ = write!(
        out,
        "tn_dir ok={} errs={} last_op={} last_err={} rc={} offset=0x{:x} partition=0x{:x}+0x{:x}\r\n",
        OKS.load(Ordering::Relaxed),
        ERRS.load(Ordering::Relaxed),
        op,
        name,
        LAST_RC.load(Ordering::Relaxed) as i32,
        LAST_OFF.load(Ordering::Relaxed),
        PEERSTORE_OFFSET,
        PEERSTORE_SIZE
    );
}

/// The directory's flash: a unit value, the chip is behind a static.
#[derive(Clone, Copy, Debug, Default)]
pub struct EspDirFlash;

fn with<R>(f: impl FnOnce(&mut FlashStorage<'static>) -> R) -> R {
    {
        let mut g = FLASH.0.borrow_mut();
        // SAFETY: the flash peripheral is a zero-sized token; `esp-storage` serialises every command to the chip with its own lock, and the directory's region is
        // disjoint from the NVS partition's.
        let fl = g.get_or_insert_with(|| FlashStorage::new(unsafe { esp_hal::peripherals::FLASH::steal() }));
        f(fl)
    }
}

impl DirFlash for EspDirFlash {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> bool {
        with(|f| note(1, offset, f.read(PEERSTORE_OFFSET + offset as u32, buf)))
    }
    fn erase_sector(&mut self, sector: usize) -> bool {
        let from = PEERSTORE_OFFSET + (sector * SECTOR) as u32;
        crate::guard::op("dir_erase");
        let r = with(|f| note(2, sector * SECTOR, f.erase(from, from + SECTOR as u32)));
        crate::guard::op("");
        r
    }
    fn write(&mut self, offset: usize, data: &[u8]) -> bool {
        // word-aligned programming; a short tail is padded with 0xFF (programming 1s changes nothing)
        if !offset.is_multiple_of(4) {
            note(3, offset, Err(FlashStorageError::NotAligned));
            return false;
        }
        let at = PEERSTORE_OFFSET + offset as u32;
        let body = data.len() & !3;
        if body > 0 && !with(|f| note(3, offset, f.write_nor(at, &data[..body]))) {
            return false;
        }
        if body < data.len() {
            let mut w = [0xFFu8; 4];
            w[..data.len() - body].copy_from_slice(&data[body..]);
            return with(|f| note(3, offset + body, f.write_nor(at + body as u32, &w)));
        }
        true
    }
    fn size(&self) -> usize {
        PEERSTORE_SIZE
    }
}
