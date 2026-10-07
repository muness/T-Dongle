//! The saved Wi-Fi networks of a board, read the way the C firmware reads them, for the no_std images that have no ESP-IDF NVS: the NVS keys (read-only), the
//! sources and their order (`wifi_load_profiles`), and the choice of the network to join (`wifi_ranked_candidate`). Pure: the flash is a `tdongle_nvs_read::Flash`.
//!
//! The C rules, all of which a first version of the spike got wrong or left out (a board with three saved networks showed one):
//!
//! * `tn_settings/wifi_profiles` (784 B) is the list when it exists; it is *strict*: a blob that is present but invalid is an error, never "nothing saved".
//! * With no such key the list is built from **two** sources: the single network of `tn_settings/wifi` (a `wifi_config_t`, [`WIFI_CONFIG_T_LEN`] bytes: SSID in
//!   the first 32, password in the next 64), then every usable network of the v0.1.x blob `adapter/config`, without repeating an SSID, up to 8.
//! * `tn_settings/wifi_meta` (names, priorities, the preferred network) is laid over the v0.1.x values, which are laid over the defaults.
//! * The network to join is the best-ranked one the scan saw: priority first, signal as the tie-break and within the hysteresis, a preferred network first.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use tdongle_nvs_format::load::{LoadInputs, Loaded, load_wifi_profiles};
use tdongle_nvs_format::wifi_meta;
use tdongle_nvs_format::wifi_profiles::{self, SavedNetworks, SavedNetworksError};
use tdongle_nvs_read::{Error, Flash, Nvs};
use tdongle_wifi_policy::rank::{NOT_SEEN_DBM, PROFILE_LIMIT, Rank, pick_ranked};

/// `sizeof(wifi_config_t)` in ESP-IDF v5.5.5 (the union is as large as `wifi_sta_config_t`: 184 bytes on Xtensa). The C firmware refuses a `tn_settings/wifi` blob of
/// any other size, and so does this reader.
pub const WIFI_CONFIG_T_LEN: usize = 184;

/// Why nothing was loaded.
#[derive(Debug, PartialEq, Eq)]
pub enum LoadError<E> {
    /// The NVS partition could not be read, or a blob the C code reads strictly is damaged.
    Nvs(Error<E>),
    /// `tn_settings/wifi` exists but is not a `wifi_config_t`.
    BadWifiConfig,
    /// `tn_settings/wifi_profiles` exists but is invalid (the C firmware refuses it and never overwrites it).
    Invalid(SavedNetworksError),
}

/// Read the saved networks: C `wifi_load_profiles` over the NVS.
///
/// # Errors
/// [`LoadError`]; a missing key is not one (it means nothing saved there).
pub fn load<F: Flash>(nvs: &mut Nvs<F>) -> Result<Loaded, LoadError<F::Error>> {
    let mut profiles = [0u8; wifi_profiles::BLOB_LEN];
    let mut meta = [0u8; wifi_meta::BLOB_LEN];
    let mut legacy = [0u8; tdongle_nvs_format::legacy::BLOB_LEN];
    let mut config = [0u8; WIFI_CONFIG_T_LEN];

    // Strict, like C: a read error or a blob that does not fit is a failed settings stage.
    let profiles_len = nvs.get_blob("tn_settings", "wifi_profiles", &mut profiles).map_err(LoadError::Nvs)?;
    // Best effort, like C: any failure to read them means "not there".
    let meta_len = nvs.get_blob("tn_settings", "wifi_meta", &mut meta).ok().flatten();
    let legacy_len = nvs.get_blob("adapter", "config", &mut legacy).ok().flatten();
    // `wifi_config`, loaded at start-up: absent is fine, any other size is an error (`gateway_main.c`).
    let older = match nvs.blob_len("tn_settings", "wifi").map_err(LoadError::Nvs)? {
        None => None,
        Some(WIFI_CONFIG_T_LEN) => {
            nvs.get_blob("tn_settings", "wifi", &mut config).map_err(LoadError::Nvs)?;
            Some((&config[..32], &config[32..96]))
        }
        Some(_) => return Err(LoadError::BadWifiConfig),
    };
    load_wifi_profiles(&LoadInputs {
        profiles: profiles_len.map(|n| &profiles[..n]),
        meta: meta_len.map(|n| &meta[..n]),
        legacy: legacy_len.map(|n| &legacy[..n]),
        older,
    })
    .map_err(LoadError::Invalid)
}

/// The rank (priority of each slot, preferred network) of a loaded list.
#[must_use]
pub fn rank(loaded: &Loaded) -> Rank {
    let mut priority = [0u8; PROFILE_LIMIT];
    for (p, slot) in priority.iter_mut().zip(loaded.meta.slot.iter()) {
        *p = slot.priority;
    }
    Rank { priority: Some(priority), preferred: loaded.meta.preferred }
}

/// The strongest reading per saved slot from a scan: `scan` yields `(ssid, rssi_dbm)` for every access point; a slot not seen is [`NOT_SEEN_DBM`].
#[must_use]
pub fn signals<'a>(saved: &SavedNetworks, scan: impl Iterator<Item = (&'a [u8], i8)>) -> [i16; PROFILE_LIMIT] {
    let mut signal = [NOT_SEEN_DBM; PROFILE_LIMIT];
    for (ssid, rssi) in scan {
        for (slot, p) in saved.list().iter().enumerate() {
            if p.ssid_bytes() == ssid && i16::from(rssi) > signal[slot] {
                signal[slot] = i16::from(rssi);
            }
        }
    }
    signal
}

/// The saved network to join: the best-ranked one that a scan saw (`pick_ranked` with nothing current). `None` when no saved SSID was seen: the caller then
/// tries the list in order, which also finds hidden networks by directed probe.
#[must_use]
pub fn choose(loaded: &Loaded, signal: &[i16; PROFILE_LIMIT]) -> Option<usize> {
    pick_ranked(signal, loaded.saved.list().len(), None, false, &rank(loaded))
}

/// The credentials of slot `slot` as the radio's station config wants them: UTF-8 SSID and password. A password that is not UTF-8 cannot be passed on, and the
/// slot is skipped (`None`).
#[must_use]
pub fn credentials(saved: &SavedNetworks, slot: usize) -> Option<(&str, &str)> {
    let p = saved.list().get(slot)?;
    Some((core::str::from_utf8(p.ssid_bytes()).ok()?, core::str::from_utf8(p.password_bytes()).ok()?))
}

/// One access point as a scan reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bss {
    /// The BSSID.
    pub bssid: [u8; 6],
    /// The primary channel.
    pub channel: u8,
    /// Signal in dBm.
    pub rssi: i8,
}

impl Bss {
    /// Usable by the C rule (`USABLE_DBM`, -85 dBm), judged on this access point, not on its SSID: one SSID is often several access points, and a far one must not
    /// make the network look usable (or a near one look unusable).
    #[must_use]
    pub const fn usable(&self) -> bool {
        self.rssi as i16 >= tdongle_wifi_policy::rank::USABLE_DBM
    }
}

/// The strongest access point of `ssid` in a scan (`scan` yields `(ssid, bssid, channel, rssi)` for every access point): the one the driver joins with `WIFI_ALL_CHANNEL_SCAN`
/// and `WIFI_CONNECT_AP_BY_SIGNAL` (the C station configuration). Ties keep the first. `None` if the SSID was not seen.
#[must_use]
pub fn strongest_bss<'a>(ssid: &[u8], scan: impl Iterator<Item = (&'a [u8], [u8; 6], u8, i8)>) -> Option<Bss> {
    let mut best: Option<Bss> = None;
    for (s, bssid, channel, rssi) in scan {
        if s == ssid && best.is_none_or(|b| rssi > b.rssi) {
            best = Some(Bss { bssid, channel, rssi });
        }
    }
    best
}

pub mod edit;
