//! `NorPartition` over a strict `embedded-storage` NOR flash (word-aligned reads, word-aligned writes, sector erases, like esp-storage's
//! `NorFlash` implementation), at the partition offset 0x9000 inside a larger flash.
mod common;

use common::*;
use embedded_storage::nor_flash::{ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash};
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_write::{Flash, NorPartition, SimFlash, Store};

#[derive(Debug)]
struct Misuse;

impl NorFlashError for Misuse {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::NotAligned
    }
}

/// A 1 MiB flash that refuses what esp-storage's NorFlash refuses.
struct Strict {
    cells: SimFlash,
    reads: u32,
}

impl ErrorType for Strict {
    type Error = Misuse;
}

impl ReadNorFlash for Strict {
    const READ_SIZE: usize = 4;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Misuse> {
        if !offset.is_multiple_of(4) || !bytes.len().is_multiple_of(4) {
            return Err(Misuse);
        }
        self.reads += 1;
        self.cells.read(offset, bytes).map_err(|_| Misuse)
    }

    fn capacity(&self) -> usize {
        self.cells.data.len()
    }
}

impl NorFlash for Strict {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Misuse> {
        if !from.is_multiple_of(4096) || !to.is_multiple_of(4096) {
            return Err(Misuse);
        }
        for s in from / 4096..to / 4096 {
            self.cells.erase_sector(s).map_err(|_| Misuse)?;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Misuse> {
        if !offset.is_multiple_of(4) || !bytes.len().is_multiple_of(4) {
            return Err(Misuse);
        }
        self.cells.write(offset, bytes).map_err(|_| Misuse)
    }
}

#[test]
fn the_engine_runs_over_a_strict_nor_flash_at_an_offset() {
    let flash = Strict { cells: SimFlash::new(0x100000), reads: 0 };
    let mut a = Store::mount(NorPartition::new(flash, 0x9000), SIZE).unwrap();
    let mut b = Store::mount(SimFlash::new(SIZE as usize), SIZE).unwrap();
    for i in 0..60u8 {
        let mut saved = tdongle_nvs_format::wifi_profiles::SavedNetworks::default();
        saved.profiles[0].ssid[..4].copy_from_slice(b"Home");
        saved.profiles[0].password[0] = i;
        saved.count = 1;
        let meta = tdongle_nvs_format::wifi_meta::MetaSet::defaults(&saved.ssids()[..1]);
        a.save_profiles(&saved, &meta).unwrap();
        b.save_profiles(&saved, &meta).unwrap();
        a.save_display(&UiSettings { brightness: 10 + i, ..UiSettings::default() }).unwrap();
        b.save_display(&UiSettings { brightness: 10 + i, ..UiSettings::default() }).unwrap();
        a.save_mode(Mode::TailnetGateway).unwrap();
        b.save_mode(Mode::TailnetGateway).unwrap();
        a.nvs().set_blob("tailnet", "identity", &pattern(300 + usize::from(i) * 50, 1)).unwrap();
        b.nvs().set_blob("tailnet", "identity", &pattern(300 + usize::from(i) * 50, 1)).unwrap();
    }
    assert!(b.nvs().flash().erases > 0, "the run compacted pages");
    let part = a.into_nvs().into_flash();
    assert_eq!(&part.inner.cells.data[..0x9000], &vec![0xff; 0x9000][..], "nothing outside the partition was touched");
    assert_eq!(&part.inner.cells.data[0x9000 + SIZE as usize..], &vec![0xff; 0x100000 - 0x9000 - SIZE as usize][..]);
    assert_eq!(&part.inner.cells.data[0x9000..0x9000 + SIZE as usize], &b.nvs().flash().data[..], "same bytes as the plain flash");
}
