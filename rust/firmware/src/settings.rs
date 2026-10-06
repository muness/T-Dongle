//! The device's saved settings, read at boot from the NVS the C firmware (and the v0.1.x bridge firmware before it) wrote.
//!
//! Phase 1 of the port **only reads**: the namespaces `tn_settings` (`mode`, `members`, `wifi_profiles`, `wifi_meta`, `display`, `wifi`) and
//! `adapter` (`config`, the v0.1.x blob) are opened read-only, so a board can be flashed back and forth between the C and the Rust image without
//! either one touching what the other saved. The byte layouts, their validation and the rules that combine them are `tdongle-nvs-format`
//! (golden-tested against the C structs); this file is the NVS I/O around it, mirroring `start_settings` and `app_main`'s early look.

use esp_idf_svc::sys;
use tdongle_nvs_format::load::{LoadInputs, display_load, load_wifi_profiles};
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_meta::MetaSet;
use tdongle_nvs_format::wifi_profiles::{BLOB_LEN as PROFILES_LEN, SavedNetworks};

use crate::sys::nvs::{self, Error, ReadOnly};

/// What the boot found in flash.
#[derive(Debug)]
pub struct Settings {
    /// The routing mode the device is configured for (`tdongle_mode_load`): Wi-Fi bridge unless a stored mode or pre-existing tailnet memberships
    /// say otherwise.
    pub mode: Mode,
    /// The saved networks, in slot order.
    pub saved: SavedNetworks,
    /// Their names, priorities and the preferred network.
    pub meta: MetaSet,
    /// The display settings (brightness, rotation, dim time).
    pub display: UiSettings,
    /// The storage could be read. `false`: a storage or settings error that the C firmware also treats as "settings stage failed": the Wi-Fi
    /// stage does not start and management stays available over USB (`status` says so).
    pub ok: bool,
}

impl Settings {
    /// What a device with nothing saved (or unreadable storage) runs with: Wi-Fi bridge, no networks, the default display.
    pub fn empty(ok: bool) -> Self {
        Self { mode: Mode::WifiBridge, saved: SavedNetworks::default(), meta: MetaSet::defaults(&[]), display: UiSettings::default(), ok }
    }
}

/// Read one optional blob into `buffer`: `Ok(None)` when the key does not exist.
fn blob<'b>(store: Option<&ReadOnly>, key: &core::ffi::CStr, buffer: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
    let Some(store) = store else { return Ok(None) };
    match store.get_blob(key, buffer) {
        Ok(length) => Ok(Some(&buffer[..length])),
        Err(Error::NotFound) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Open a namespace read-only; a namespace that does not exist is "nothing saved there", not an error.
fn open(namespace: &core::ffi::CStr) -> Result<Option<ReadOnly>, Error> {
    match ReadOnly::open(namespace) {
        Ok(store) => Ok(Some(store)),
        Err(Error::NotFound) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Load everything. Never writes, never erases.
pub fn load() -> Settings {
    if let Err(error) = nvs::init() {
        log::error!("NVS could not be initialised ({error}): running without saved settings");
        return Settings::empty(false);
    }
    match read_all() {
        Ok(settings) => settings,
        Err(error) => {
            log::error!("saved settings could not be read ({error}): the Wi-Fi stage does not start");
            Settings::empty(false)
        }
    }
}

fn read_all() -> Result<Settings, Error> {
    let tn = open(c"tn_settings")?;
    let adapter = open(c"adapter")?;

    // The mode: the stored value, else "tailnet gateway" when the install predates the mode switch and already holds memberships.
    let stored_mode = match &tn {
        Some(store) => match store.get_u8(c"mode") {
            Ok(value) => Some(value),
            Err(Error::NotFound) => None,
            Err(other) => return Err(other),
        },
        None => None,
    };
    let members_present = match &tn {
        Some(store) => store.has_str(c"members")?,
        None => false,
    };
    let mode = Mode::load(stored_mode, members_present).map_err(|_| Error::Esp(sys::ESP_ERR_INVALID_STATE))?;

    let mut profiles_buffer = [0u8; PROFILES_LEN];
    let mut meta_buffer = [0u8; tdongle_nvs_format::wifi_meta::BLOB_LEN];
    let mut legacy_buffer = [0u8; tdongle_nvs_format::legacy::BLOB_LEN];
    let mut display_buffer = [0u8; tdongle_nvs_format::ui_settings::BLOB_LEN];
    // The single network an even older build kept as a wifi_config_t: it must be exactly the size of that struct, or it is not one.
    let mut older_buffer = [0u8; core::mem::size_of::<sys::wifi_config_t>()];

    // The list itself is strict: a read error or a blob of the wrong size fails the settings stage, as in C. The metadata, the display settings and the
    // v0.1.x blob are best effort: any failure to read them means "not there" (C: `nvs_get_blob(...) == ESP_OK && ...decode`).
    let profiles = blob(tn.as_ref(), c"wifi_profiles", &mut profiles_buffer)?;
    let meta = blob(tn.as_ref(), c"wifi_meta", &mut meta_buffer).ok().flatten();
    let display_blob = blob(tn.as_ref(), c"display", &mut display_buffer).ok().flatten();
    let legacy = blob(adapter.as_ref(), c"config", &mut legacy_buffer).ok().flatten();
    let older_size = older_buffer.len();
    let older = match blob(tn.as_ref(), c"wifi", &mut older_buffer)? {
        Some(bytes) if bytes.len() == older_size => Some((&bytes[..32], &bytes[32..96])),
        Some(_) => return Err(Error::Esp(sys::ESP_ERR_INVALID_STATE)),
        None => None,
    };

    let loaded = load_wifi_profiles(&LoadInputs { profiles, meta, legacy, older }).map_err(|_| Error::Esp(sys::ESP_ERR_INVALID_STATE))?;
    let display = display_load(display_blob, legacy);
    Ok(Settings { mode, saved: loaded.saved, meta: loaded.meta, display, ok: true })
}
