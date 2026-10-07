//! The peer directory's flash: the `peerstore` partition (`0x420000`, 4 MB, the C's FAT volume; here raw) behind [`DirFlash`].
//!
//! The settings task owns the NVS's `FlashStorage`; the directory has one of its own, made on first use from the peripheral (`esp-storage` takes its own lock around every
//! command to the chip, so two instances cannot interleave one). A sector erase masks interrupts for its ~45 ms, one call at a
//! time (the loop of a commit gives the radio and USB their turns between sectors).

use core::cell::RefCell;
use esp_storage::FlashStorage;
use tdongle_tailnet_engine::flashdir::{DirFlash, SECTOR};

/// Start of the `peerstore` partition.
pub const PEERSTORE_OFFSET: u32 = 0x42_0000;
/// Size of the `peerstore` partition.
pub const PEERSTORE_SIZE: usize = 0x40_0000;

struct Chip(RefCell<Option<FlashStorage<'static>>>);
// SAFETY: the directory is used only under the tailnet runtime's `TaskLock` (tasks of the one thread executor, never concurrently), and `mount` runs before any of them.
unsafe impl Sync for Chip {}
static FLASH: Chip = Chip(RefCell::new(None));

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
        with(|f| f.read(PEERSTORE_OFFSET + offset as u32, buf).is_ok())
    }
    fn erase_sector(&mut self, sector: usize) -> bool {
        let from = PEERSTORE_OFFSET + (sector * SECTOR) as u32;
        crate::guard::op("dir_erase");
        let r = with(|f| f.erase(from, from + SECTOR as u32).is_ok());
        crate::guard::op("");
        r
    }
    fn write(&mut self, offset: usize, data: &[u8]) -> bool {
        // word-aligned programming; a short tail is padded with 0xFF (programming 1s changes nothing)
        if !offset.is_multiple_of(4) {
            return false;
        }
        let at = PEERSTORE_OFFSET + offset as u32;
        let body = data.len() & !3;
        if body > 0 && !with(|f| f.write_nor(at, &data[..body]).is_ok()) {
            return false;
        }
        if body < data.len() {
            let mut w = [0xFFu8; 4];
            w[..data.len() - body].copy_from_slice(&data[body..]);
            return with(|f| f.write_nor(at + body as u32, &w).is_ok());
        }
        true
    }
    fn size(&self) -> usize {
        PEERSTORE_SIZE
    }
}
