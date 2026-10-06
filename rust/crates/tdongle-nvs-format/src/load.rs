//! Loading the saved networks and the display settings at boot.
//!
//! Pure ports of `wifi_load_profiles()` and `display_load()` of `alternative/tailnet/main/wifi_profiles.inc` and `device_ui.inc`, with the
//! NVS reads replaced by byte slices (`None` is "key not found"). Failing *reads* (an NVS error other than not-found) are the caller's to
//! report; here a missing key and a blob that fails validation are the two cases C distinguishes.

use crate::cstr::{c_str, copy_str};
use crate::legacy::LegacyImport;
use crate::ui_settings::UiSettings;
use crate::wifi_meta::{MetaSet, SLOTS};
use crate::wifi_profiles::{LIMIT, SavedNetworks, SavedNetworksError, SavedProfile};

/// Everything `wifi_load_profiles` reads. All fields are optional: `None` means the key does not exist.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoadInputs<'a> {
    /// NVS `tn_settings/wifi_profiles`.
    pub profiles: Option<&'a [u8]>,
    /// NVS `tn_settings/wifi_meta`. A blob that fails validation is ignored, as in C.
    pub meta: Option<&'a [u8]>,
    /// NVS `adapter/config`, the v0.1.x blob. One that is not a v0.1.x blob (size, version) is treated as absent, as in C.
    pub legacy: Option<&'a [u8]>,
    /// The single network an even older build kept in `wifi_config` (SSID, password), used only when there is no `profiles` blob.
    /// C copies 32 SSID and 63 password bytes of the driver config; here each is cut at its first NUL and at 32 / 63 bytes.
    pub older: Option<(&'a [u8], &'a [u8])>,
}

/// The in-memory result of a load (C `wifi_saved` and `wifi_meta`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded {
    /// The saved list.
    pub saved: SavedNetworks,
    /// Names, priorities and the preferred network, parallel to `saved`.
    pub meta: MetaSet,
}

/// C `wifi_apply_legacy_meta`: attach the v0.1.x name, priority and preferred slot to the networks already in the list, by SSID.
fn apply_legacy_meta(saved: &SavedNetworks, meta: &mut MetaSet, legacy: &LegacyImport) {
    let nets = &legacy.net[..legacy.count];
    for (slot, p) in meta.slot.iter_mut().zip(saved.list()) {
        if let Some(n) = nets.iter().find(|n| c_str(&n.ssid) == p.ssid_bytes()) {
            *slot = n.meta;
        }
    }
    if let Some(preferred) = legacy.preferred {
        for (i, p) in saved.list().iter().enumerate() {
            if p.ssid_bytes() == c_str(&legacy.net[preferred].ssid) {
                meta.preferred = Some(i);
            }
        }
    }
}

/// C `wifi_load_profiles`.
///
/// * No `profiles` blob (fresh install, or one that only has v0.1.x data): the list starts with the `older` network, if any, then every
///   usable v0.1.x network that does not repeat an SSID, up to 8. Metadata starts at the defaults, then the v0.1.x names, priorities and
///   preferred network by SSID, then the stored `wifi_meta` blob on top of both (it exists only because the user acted).
/// * A `profiles` blob: validated, and refused as a whole when invalid (the caller must not overwrite it). Metadata is built the same way,
///   so a list saved by a build that predates the metadata still picks up its v0.1.x priorities.
///
/// # Errors
/// [`SavedNetworksError`] when an existing `profiles` blob is invalid. Nothing else can fail.
pub fn load_wifi_profiles(inputs: &LoadInputs<'_>) -> Result<Loaded, SavedNetworksError> {
    let legacy = inputs.legacy.and_then(|blob| LegacyImport::decode(blob).ok());
    let saved = match inputs.profiles {
        Some(blob) => SavedNetworks::from_bytes(blob)?,
        None => import_fresh(inputs.older, legacy.as_ref()),
    };
    let ssids = saved.ssids();
    let mut meta = MetaSet::defaults(&ssids[..saved.count]);
    if let Some(legacy) = &legacy {
        apply_legacy_meta(&saved, &mut meta, legacy);
    }
    if let Some(blob) = inputs.meta {
        // An invalid stored blob leaves the metadata as it was, exactly like C ignoring wifi_meta_overlay's result.
        let _ = meta.overlay(blob, &ssids[..saved.count]);
    }
    Ok(Loaded { saved, meta })
}

/// The list of an install with no `wifi_profiles` key yet.
fn import_fresh(older: Option<(&[u8], &[u8])>, legacy: Option<&LegacyImport>) -> SavedNetworks {
    let mut saved = SavedNetworks::default();
    if let Some((ssid, password)) = older.filter(|(ssid, _)| !c_str(ssid).is_empty()) {
        copy_str(&mut saved.profiles[0].ssid[..32], ssid);
        copy_str(&mut saved.profiles[0].password[..63], password);
        saved.count = 1;
    }
    for net in legacy.into_iter().flat_map(|l| &l.net[..l.count]) {
        if saved.count >= LIMIT {
            break;
        }
        if saved.list().iter().any(|p| p.ssid_bytes() == c_str(&net.ssid)) {
            continue;
        }
        let mut profile = SavedProfile::EMPTY;
        copy_str(&mut profile.ssid[..32], &net.ssid);
        copy_str(&mut profile.password[..63], &net.password);
        saved.profiles[saved.count] = profile;
        saved.count += 1;
    }
    saved
}

/// C `display_load`: the `tn_settings/display` blob when it is valid, else the display settings of the v0.1.x blob when it holds
/// in-range values, else the defaults. A damaged display blob falls back to the old settings, never to garbage.
#[must_use]
pub fn display_load(display: Option<&[u8]>, legacy: Option<&[u8]>) -> UiSettings {
    display
        .and_then(|blob| UiSettings::from_bytes(blob).ok())
        .or_else(|| legacy.and_then(|blob| LegacyImport::decode(blob).ok()).and_then(|import| import.display))
        .unwrap_or_default()
}

const _: () = assert!(LIMIT == SLOTS, "saved-network metadata must have a slot for every saved network");
