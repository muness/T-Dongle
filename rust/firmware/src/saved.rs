//! Saved Wi-Fi networks and the stored settings: the flash adapter around `tdongle_saved` (the C load order, ranking and fixtures live there, host-tested). Read-only: this
//! module has no write or erase path.
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

/// What the other `tn_settings` keys hold: the mode (C `tdongle_mode_load`) and the display settings (C `ui_settings_load`; invalid or absent = defaults).
#[derive(Clone, Copy, Debug)]
pub struct Stored {
    /// The stored mode, `Err(raw)` for a value the C firmware refuses.
    pub mode: Result<tdongle_nvs_format::mode::Mode, u8>,
    /// The display settings.
    pub display: tdongle_nvs_format::ui_settings::UiSettings,
}

/// Read the mode and the display settings.
pub fn load_stored(flash: &mut FlashStorage<'static>) -> Stored {
    use tdongle_nvs_format::{mode::Mode, ui_settings::UiSettings};
    let mut nvs = Nvs::new(NvsFlash(RefCell::new(flash)), NVS_SIZE);
    let stored = nvs.get_u8("tn_settings", "mode").ok().flatten();
    let members = nvs.has_str("tn_settings", "members").unwrap_or(false);
    let mode = Mode::load(stored, members).map_err(|e| match e {
        tdongle_nvs_format::mode::ModeError::InvalidStored(v) => v,
    });
    let mut blob = [0u8; tdongle_nvs_format::ui_settings::BLOB_LEN + 4];
    let display = match nvs.get_blob("tn_settings", "display", &mut blob) {
        Ok(Some(n)) => UiSettings::from_bytes(&blob[..n]).unwrap_or_default(),
        _ => UiSettings::default(),
    };
    Stored { mode, display }
}
