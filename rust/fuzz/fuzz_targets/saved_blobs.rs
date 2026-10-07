//! Every NVS blob decoder on arbitrary bytes (a corrupted or foreign flash must be refused, never trusted or panicked on).
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_nvs_format::legacy::LegacyImport;
use tdongle_nvs_format::load::{LoadInputs, display_load, load_wifi_profiles};
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_meta::MetaBlob;
use tdongle_nvs_format::wifi_profiles::SavedNetworks;

fuzz_target!(|data: &[u8]| {
    let _ = SavedNetworks::from_bytes(data);
    let _ = MetaBlob::from_bytes(data);
    let _ = UiSettings::from_bytes(data);
    let _ = UiSettings::parse(data);
    let _ = LegacyImport::decode(data);
    let _ = display_load(Some(data), Some(data));
    let _ = load_wifi_profiles(&LoadInputs { profiles: Some(data), meta: Some(data), legacy: Some(data), older: None });
});
