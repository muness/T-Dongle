//! Saved Wi-Fi networks for the no_std spikes: read the C firmware's `tn_settings/wifi_profiles` (+ `wifi_meta`, `adapter/config`) from the
//! existing NVS partition, **read-only** (this module has no write or erase path), and pick the strongest visible network the way C does
//! (`tdongle_wifi_policy::pick_ranked`). Included with `#[path = "../../common/saved.rs"] mod saved;`.
#![allow(dead_code)]

use core::cell::RefCell;

use esp_storage::FlashStorage;
use tdongle_nvs_format::load::{Loaded, LoadInputs, load_wifi_profiles};
use tdongle_nvs_format::wifi_meta;
use tdongle_nvs_format::wifi_profiles::{self, SavedNetworks};
use tdongle_nvs_read::{Flash, Nvs};
use tdongle_wifi_policy::rank::{NOT_SEEN_DBM, PROFILE_LIMIT, Rank, pick_ranked};

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
#[derive(Debug)]
pub enum LoadError {
    /// The NVS partition could not be read or parsed.
    Nvs,
    /// A saved list exists but is invalid (the C firmware refuses it too and never overwrites it).
    Invalid(wifi_profiles::SavedNetworksError),
}

/// Read the saved networks. Mirrors the firmware's `settings::read_all` (blob sizes, keys, optional blobs best effort).
pub fn load(flash: &mut FlashStorage<'static>) -> Result<Loaded, LoadError> {
    let mut nvs = Nvs::new(NvsFlash(RefCell::new(flash)), NVS_SIZE);
    let mut profiles = [0u8; wifi_profiles::BLOB_LEN];
    let mut meta = [0u8; wifi_meta::BLOB_LEN];
    let mut legacy = [0u8; tdongle_nvs_format::legacy::BLOB_LEN];
    let profiles_len = nvs.get_blob("tn_settings", "wifi_profiles", &mut profiles).map_err(|_| LoadError::Nvs)?;
    let meta_len = nvs.get_blob("tn_settings", "wifi_meta", &mut meta).ok().flatten();
    let legacy_len = nvs.get_blob("adapter", "config", &mut legacy).ok().flatten();
    load_wifi_profiles(&LoadInputs {
        profiles: profiles_len.map(|n| &profiles[..n]),
        meta: meta_len.map(|n| &meta[..n]),
        legacy: legacy_len.map(|n| &legacy[..n]),
        older: None,
    })
    .map_err(LoadError::Invalid)
}

/// The rank (priority + preferred network) of the saved list, as `wifi_meta` stored it.
pub fn rank(loaded: &Loaded) -> Rank {
    let mut priority = [0u8; PROFILE_LIMIT];
    for (p, slot) in priority.iter_mut().zip(loaded.meta.slot.iter()) {
        *p = slot.priority;
    }
    Rank { priority: Some(priority), preferred: loaded.meta.preferred }
}

/// The saved network to join: the best-ranked one that a scan saw. `scan` yields `(ssid, rssi_dbm)` for every access point; `None` when no
/// saved SSID was seen (the caller then tries the saved list in order, which also finds hidden networks by directed probe).
pub fn choose<'a>(loaded: &Loaded, scan: impl Iterator<Item = (&'a str, i8)>) -> Option<usize> {
    let mut signal = [NOT_SEEN_DBM; PROFILE_LIMIT];
    for (ssid, rssi) in scan {
        for (slot, p) in loaded.saved.list().iter().enumerate() {
            if p.ssid_bytes() == ssid.as_bytes() && i16::from(rssi) > signal[slot] {
                signal[slot] = i16::from(rssi);
            }
        }
    }
    pick_ranked(&signal, loaded.saved.list().len(), None, false, &rank(loaded))
}

/// Saved networks as the radio's station config wants them: UTF-8 SSID and password (a password that is not UTF-8 cannot be passed on and
/// the slot is skipped).
pub fn credentials(saved: &SavedNetworks, slot: usize) -> Option<(&str, &str)> {
    let p = saved.list().get(slot)?;
    Some((core::str::from_utf8(p.ssid_bytes()).ok()?, core::str::from_utf8(p.password_bytes()).ok()?))
}
