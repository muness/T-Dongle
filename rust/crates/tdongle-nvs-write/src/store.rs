//! The firmware's view of the NVS partition: the keys the C firmware keeps in `tn_settings` and `adapter`, with the same write order.
//!
//! | C | Here |
//! |---|---|
//! | `wifi_load_profiles`, `display_load`, `tdongle_mode_load` | [`Store::load_all`] |
//! | `wifi_save_with` (`nvs_set_blob wifi_meta`, `nvs_set_blob wifi_profiles`, `nvs_commit`, roll back the metadata on failure) | [`Store::save_profiles`] |
//! | `wifi_set_preferred` | [`Store::save_meta`] |
//! | `display_save` | [`Store::save_display`] |
//! | `tdongle_mode_save` | [`Store::save_mode`] |
//! | `wifi_factory_reset` | [`Store::factory_reset`] |
//! | the v0.1.1 import (`wifi_read_legacy` + the lazy persist of the next explicit save) | [`Store::import_legacy`] |
//!
//! `adapter/config`, the v0.1.1 blob, is never written here: v0.1.1 can still read it after any amount of Rust or v0.3.x use. Only
//! [`Store::factory_reset`] erases it (every key of the `adapter` namespace, as the C does), so the old settings are not imported again.

use tdongle_nvs_format::legacy::LegacyImport;
use tdongle_nvs_format::load::{LoadInputs, Loaded, display_load, load_wifi_profiles};
use tdongle_nvs_format::mode::{MEMBERS_KEY, MODE_KEY, Mode, ModeError};
use tdongle_nvs_format::ui_settings::{self, UiSettings};
use tdongle_nvs_format::wifi_meta::{self, MetaBlob, MetaSet};
use tdongle_nvs_format::wifi_profiles::{self, SavedNetworks, SavedNetworksError};

use crate::{Error, Flash, Nvs};

/// The namespace of the unified firmware (`nvs_open("tn_settings")`).
pub const NS_SETTINGS: &str = "tn_settings";
/// The namespace of the v0.1.x bridge firmware (`nvs_open("adapter")`), holding the `config` blob.
pub const NS_ADAPTER: &str = "adapter";

const KEY_PROFILES: &str = "wifi_profiles";
const KEY_META: &str = "wifi_meta";
const KEY_DISPLAY: &str = "display";
const KEY_OLDER: &str = "wifi";
const KEY_LEGACY: &str = "config";
/// `sizeof(wifi_config_t)` in ESP-IDF v5.5.5, the blob of the `wifi` key of the first unified builds.
const WIFI_CONFIG_LEN: usize = 184;

/// What a boot reads from the NVS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The saved networks and their metadata (`wifi_saved`, `wifi_meta`).
    pub networks: Loaded,
    /// The display settings (`display_settings`).
    pub display: UiSettings,
    /// The routing mode, or the stored value the firmware refuses.
    pub mode: Result<Mode, ModeError>,
}

/// Why [`Store::load_all`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError<E> {
    /// The storage engine failed.
    Storage(Error<E>),
    /// A `wifi_profiles` blob exists and is invalid. The caller must not overwrite it (C: `wifi_load_profiles` returns false).
    Profiles(SavedNetworksError),
    /// The `wifi` blob is not a `wifi_config_t` (C refuses to start: `ESP_ERR_INVALID_STATE`).
    WifiConfigSize,
}

impl<E> From<Error<E>> for LoadError<E> {
    fn from(e: Error<E>) -> Self {
        Self::Storage(e)
    }
}

/// The settings store over an [`Nvs`].
#[derive(Debug)]
pub struct Store<F: Flash> {
    nvs: Nvs<F>,
}

type R<T, F> = Result<T, Error<<F as Flash>::Error>>;

/// A blob read for [`load_wifi_profiles`]: `None` when absent or erased as corrupt, an empty slice when the key has another type (never
/// valid), the bytes otherwise. One that does not fit the buffer is returned as the whole buffer, which is longer than the real layout.
fn read_blob<'b, F: Flash>(nvs: &mut Nvs<F>, ns: &str, key: &str, buf: &'b mut [u8]) -> R<Option<&'b [u8]>, F> {
    match nvs.get_blob(ns, key, buf) {
        Ok(Some(n)) => Ok(Some(&buf[..n])),
        Ok(None) | Err(Error::Corrupt) => Ok(None),
        Err(Error::TooSmall) => Ok(Some(&buf[..])),
        Err(Error::TypeMismatch) => Ok(Some(&[])),
        Err(e) => Err(e),
    }
}

impl<F: Flash> Store<F> {
    /// Mount the partition (see [`Nvs::mount`]).
    ///
    /// # Errors
    /// See [`Nvs::mount`].
    pub fn mount(flash: F, size: u32) -> R<Self, F> {
        Ok(Self { nvs: Nvs::open(flash, size)? })
    }

    /// Wrap an engine that is already mounted.
    pub fn new(nvs: Nvs<F>) -> Self {
        Self { nvs }
    }

    /// The engine, for keys this type does not know (tailnet memberships and identities).
    pub fn nvs(&mut self) -> &mut Nvs<F> {
        &mut self.nvs
    }

    /// Give the engine back.
    pub fn into_nvs(self) -> Nvs<F> {
        self.nvs
    }

    /// Everything a boot needs, exactly as the C builds it: `wifi_load_profiles` (a `wifi_profiles` blob, or the single `wifi` network
    /// plus the v0.1.x networks of `adapter/config` on a fresh install; metadata from defaults, the v0.1.x names and priorities, then
    /// the stored `wifi_meta`), `display_load` and `tdongle_mode_load`. **Writes nothing**, as in C: the imported list and metadata
    /// persist on the next explicit save, or on [`Store::import_legacy`]. A stored blob that fails its CRC is erased by the engine (as
    /// `nvs_get_blob` does) and counts as absent.
    ///
    /// # Errors
    /// [`LoadError::Profiles`] for an invalid `wifi_profiles` blob, [`LoadError::WifiConfigSize`], [`LoadError::Storage`].
    pub fn load_all(&mut self) -> Result<Settings, LoadError<F::Error>> {
        let mut profiles = [0u8; wifi_profiles::BLOB_LEN + 1];
        let mut meta = [0u8; wifi_meta::BLOB_LEN + 1];
        let mut legacy = [0u8; tdongle_nvs_format::legacy::BLOB_LEN + 1];
        let mut display = [0u8; ui_settings::BLOB_LEN + 1];
        let mut older = [0u8; WIFI_CONFIG_LEN + 1];
        let profiles = read_blob(&mut self.nvs, NS_SETTINGS, KEY_PROFILES, &mut profiles)?;
        let meta = read_blob(&mut self.nvs, NS_SETTINGS, KEY_META, &mut meta)?;
        let legacy = read_blob(&mut self.nvs, NS_ADAPTER, KEY_LEGACY, &mut legacy)?;
        let display = read_blob(&mut self.nvs, NS_SETTINGS, KEY_DISPLAY, &mut display)?;
        let older = match read_blob(&mut self.nvs, NS_SETTINGS, KEY_OLDER, &mut older)? {
            None => None,
            Some(b) if b.len() == WIFI_CONFIG_LEN => Some((&b[..32], &b[32..96])),
            Some(_) => return Err(LoadError::WifiConfigSize),
        };
        let networks = load_wifi_profiles(&LoadInputs { profiles, meta, legacy, older }).map_err(LoadError::Profiles)?;
        let display = display_load(display, legacy);
        let stored = self.nvs.get_u8(NS_SETTINGS, MODE_KEY)?;
        let members = self.nvs.contains(NS_SETTINGS, MEMBERS_KEY)?;
        Ok(Settings { networks, display, mode: Mode::load(stored, members) })
    }

    /// `wifi_save_with` after the list and metadata are computed: the metadata blob first, then the list, then the commit. The two are
    /// two items, as in C ("nvs_set_blob writes at once; the one commit does not make them one transaction"). A failed list write puts
    /// the previous metadata back (best effort). A power cut between the two writes leaves the new metadata beside the old list; because
    /// the metadata is keyed by SSID that cannot attach a priority to another network (an entry for a network not in the list is
    /// ignored, a network without an entry gets the defaults); the worst outcome is a stale priority or preference on the same network,
    /// fixed by the next save. Each blob is replaced atomically (old or new, never a mixture) and nothing else is touched.
    ///
    /// # Errors
    /// The engine's error of the first failing write.
    pub fn save_profiles(&mut self, list: &SavedNetworks, meta: &MetaSet) -> R<(), F> {
        let ssids = list.ssids();
        let next = MetaBlob::encode(&ssids[..list.count], meta).to_bytes();
        let blob = list.to_bytes();
        let mut previous = [0u8; wifi_meta::BLOB_LEN];
        let had_meta = matches!(self.nvs.get_blob(NS_SETTINGS, KEY_META, &mut previous), Ok(Some(wifi_meta::BLOB_LEN)));
        self.nvs.set_blob(NS_SETTINGS, KEY_META, &next)?;
        if let Err(e) = self.nvs.set_blob(NS_SETTINGS, KEY_PROFILES, &blob) {
            if had_meta {
                let _ = self.nvs.set_blob(NS_SETTINGS, KEY_META, &previous);
            }
            return Err(e);
        }
        self.nvs.commit()
    }

    /// `wifi_set_preferred`: only the metadata blob, then the commit.
    ///
    /// # Errors
    /// The engine's error.
    pub fn save_meta(&mut self, list: &SavedNetworks, meta: &MetaSet) -> R<(), F> {
        let ssids = list.ssids();
        let blob = MetaBlob::encode(&ssids[..list.count], meta).to_bytes();
        self.nvs.set_blob(NS_SETTINGS, KEY_META, &blob)?;
        self.nvs.commit()
    }

    /// `display_save`: the 8-byte `display` blob, then the commit.
    ///
    /// # Errors
    /// The engine's error.
    pub fn save_display(&mut self, settings: &UiSettings) -> R<(), F> {
        self.nvs.set_blob(NS_SETTINGS, KEY_DISPLAY, &settings.to_bytes())?;
        self.nvs.commit()
    }

    /// `tdongle_mode_save`: the `mode` `u8`, then the commit.
    ///
    /// # Errors
    /// The engine's error.
    pub fn save_mode(&mut self, mode: Mode) -> R<(), F> {
        self.nvs.set_u8(NS_SETTINGS, MODE_KEY, mode.to_u8())?;
        self.nvs.commit()
    }

    /// `wifi_factory_reset`: erase `wifi_profiles`, `wifi_meta`, `display` and `wifi` of `tn_settings` (a missing key is fine), commit,
    /// then erase every key of the `adapter` namespace so the v0.1.x settings are not imported again. The mode, the memberships and the
    /// identities are kept. Every erase is attempted; the first error is returned, and the caller must not restart into a half-reset state.
    ///
    /// # Errors
    /// The first engine error.
    pub fn factory_reset(&mut self) -> R<(), F> {
        let mut first = None;
        for key in [KEY_PROFILES, KEY_META, KEY_DISPLAY, KEY_OLDER] {
            match self.nvs.erase_key(NS_SETTINGS, key) {
                Ok(()) | Err(Error::NotFound) => {}
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        if let Err(e) = self.nvs.commit() {
            first.get_or_insert(e);
        }
        if let Err(e) = self.nvs.erase_namespace(NS_ADAPTER) {
            first.get_or_insert(e);
        }
        match first {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// Persist what [`Store::load_all`] imported from the v0.1.x `adapter/config` (and the single `wifi` network), the way the C does it on
    /// its next explicit save: when there is no `wifi_profiles` blob and something was imported, write `wifi_meta` then `wifi_profiles`;
    /// when there is no `display` blob and the old settings carry valid display values, write `display`. `adapter/config` is **not**
    /// touched, so v0.1.1 still finds its settings after a downgrade. Returns whether anything was written.
    ///
    /// # Errors
    /// [`LoadError`] as [`Store::load_all`], or the engine's error of a write.
    pub fn import_legacy(&mut self) -> Result<bool, LoadError<F::Error>> {
        let settings = self.load_all()?;
        let mut wrote = false;
        if !self.nvs.contains(NS_SETTINGS, KEY_PROFILES)? && settings.networks.saved.count > 0 {
            self.save_profiles(&settings.networks.saved, &settings.networks.meta)?;
            wrote = true;
        }
        if !self.nvs.contains(NS_SETTINGS, KEY_DISPLAY)? {
            let mut old = [0u8; tdongle_nvs_format::legacy::BLOB_LEN + 1];
            if let Some(blob) = read_blob(&mut self.nvs, NS_ADAPTER, KEY_LEGACY, &mut old)? {
                if LegacyImport::decode(blob).is_ok_and(|l| l.display.is_some()) {
                    self.save_display(&settings.display)?;
                    wrote = true;
                }
            }
        }
        Ok(wrote)
    }
}
