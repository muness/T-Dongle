//! Saved Wi-Fi networks for the no_std spikes: the flash adapter around `tdongle_saved` (the C load order, ranking and fixtures live there, host-tested). Read-only: this
//! module has no write or erase path. Included with `#[path = "../../common/saved.rs"] mod saved;`.
#![allow(dead_code)]

use core::cell::RefCell;

use esp_storage::FlashStorage;
use tdongle_nvs_format::load::Loaded;
use tdongle_nvs_read::{Flash, Nvs};

/// The C package's layout (`partitions.csv`): `nvs, data, nvs, 0x9000, 0x10000`.
pub const NVS_OFFSET: u32 = 0x9000;
/// Size of the `nvs` partition.
pub const NVS_SIZE: u32 = 0x1_0000;

/// `Flash` over the SPI flash at the NVS partition's offset; reads only.
struct NvsFlash<'a>(RefCell<&'a mut FlashStorage<'static>>);

impl Flash for NvsFlash<'_> {
    type Error = ();
    fn read(&self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
        self.0.borrow_mut().read(NVS_OFFSET + offset, buf).map_err(|_| ())
    }
}

/// Why nothing was loaded.
pub type LoadError = tdongle_saved::LoadError<()>;

/// Read the saved networks (`wifi_load_profiles`).
pub fn load(flash: &mut FlashStorage<'static>) -> Result<Loaded, LoadError> {
    tdongle_saved::load(&mut Nvs::new(NvsFlash(RefCell::new(flash)), NVS_SIZE))
}
