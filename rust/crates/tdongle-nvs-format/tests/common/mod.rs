//! Helpers shared by the integration tests.
#![allow(dead_code)]

use tdongle_nvs_format::legacy::{LegacyImport, LegacyProfile};
use tdongle_nvs_format::load::Loaded;
use tdongle_nvs_format::wifi_meta::MetaSet;

/// A C string in a zero-padded `[u8; N]` (like `strcpy` into a zeroed array). `text` may fill the whole array (unterminated).
pub fn fixed<const N: usize>(text: &str) -> [u8; N] {
    assert!(text.len() <= N, "{text:?} does not fit in {N} bytes");
    let mut out = [0u8; N];
    out[..text.len()].copy_from_slice(text.as_bytes());
    out
}

pub const SSIDS: [&[u8]; 8] = [b"Home", b"Phone", b"Office", b"Cafe", b"Car", b"Hotel", b"Lab", b"Shed"];

/// The legacy profile `strcpy`ed the way `tests/test_legacy_import.c` does.
pub fn legacy_profile(name: &str, ssid: &str, pass: &str, priority: u8) -> LegacyProfile {
    LegacyProfile { name: fixed(name), ssid: fixed(ssid), pass: fixed(pass), priority }
}

/// Canonical dump of a meta set, as written by `tools/gen_golden.c` (`dump_meta`).
pub fn dump_meta(set: &MetaSet) -> Vec<u8> {
    let mut out = Vec::new();
    let preferred: i32 = set.preferred.map_or(-1, |p| p as i32);
    out.extend_from_slice(&preferred.to_le_bytes());
    for slot in &set.slot {
        out.extend_from_slice(&slot.name);
        out.push(slot.priority);
    }
    assert_eq!(out.len(), 212);
    out
}

/// Canonical dump of a legacy import (`dump_import`).
pub fn dump_import(import: &LegacyImport) -> Vec<u8> {
    let mut out = vec![0u8; 1000];
    out[0..4].copy_from_slice(&(import.count as u32).to_le_bytes());
    out[4..8].copy_from_slice(&import.preferred.map_or(-1i32, |p| p as i32).to_le_bytes());
    if let Some(d) = import.display {
        out[8] = 1;
        out[9] = d.brightness;
        out[10] = d.rotation;
        out[12..14].copy_from_slice(&d.dim_seconds.to_le_bytes());
    }
    for (i, n) in import.net[..import.count].iter().enumerate() {
        let at = 16 + i * 123;
        out[at..at + 33].copy_from_slice(&n.ssid);
        out[at + 33..at + 97].copy_from_slice(&n.password);
        out[at + 97..at + 122].copy_from_slice(&n.meta.name);
        out[at + 122] = n.meta.priority;
    }
    out
}

/// Canonical dump of a load result (`load_case`), or the "refused" status.
pub fn dump_load(result: &Result<Loaded, tdongle_nvs_format::wifi_profiles::SavedNetworksError>) -> Vec<u8> {
    let mut out = vec![0u8; 993];
    let Ok(loaded) = result else {
        out[0] = 1;
        return out;
    };
    out[1..5].copy_from_slice(&(loaded.saved.count as u32).to_le_bytes());
    for (i, p) in loaded.saved.list().iter().enumerate() {
        let at = 5 + i * 97;
        out[at..at + 33].copy_from_slice(&p.ssid);
        out[at + 33..at + 97].copy_from_slice(&p.password);
    }
    out[5 + 776..].copy_from_slice(&dump_meta(&loaded.meta));
    out
}
