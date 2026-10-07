//! Golden blobs written by the REAL C firmware code (`tools/gen_golden.c`, `tools/regen.sh`): decode(golden) must equal what C decoded
//! and encode(decode(golden)) must be the golden bytes, so a device flashed alternately with the C and Rust images shares its NVS.
mod common;
use common::{SSIDS, dump_import, dump_load, dump_meta, fixed, legacy_profile};
use tdongle_nvs_format::legacy::{CFG_VERSION, LegacyError, LegacyImport, LegacyProfile, LegacySettings};
use tdongle_nvs_format::load::{LoadInputs, load_wifi_profiles};
use tdongle_nvs_format::ui_settings::{UiSettings, UiSettingsError};
use tdongle_nvs_format::wifi_meta::{MetaBlob, MetaBlobError, MetaSet};
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedNetworksError, SavedProfile};

type Bytes<'a> = &'a [u8];
type List<'a> = &'a [&'a [u8]];

macro_rules! golden {
    ($name:literal) => {
        &include_bytes!(concat!("golden/", $name))[..]
    };
}

/// Overlay as the firmware does it: defaults for the list, then the blob.
fn overlaid(blob: &[u8], list: &[&[u8]]) -> MetaSet {
    let mut set = MetaSet::defaults(list);
    set.overlay(blob, list).unwrap();
    set
}

#[test]
fn sizes_match_the_c_structs() {
    assert_eq!(golden!("meta_empty.bin").len(), 516);
    assert_eq!(golden!("display_default.bin").len(), 8);
    assert_eq!(golden!("legacy_empty.bin").len(), 1004);
    assert_eq!(golden!("profiles_empty.bin").len(), 784);
}

// ---- wifi_meta ----

#[test]
fn meta_blobs_round_trip_and_match_the_c_encoder() {
    let eight_names = ["Home", "Phone hotspot", "Office (5 GHz)", "123456789012345678901234", "Car", "a", "Lab bench", "Shed"];
    let eight_prio = [50, 90, 100, 0, 10, 50, 77, 1];
    let mut eight = MetaSet::defaults(&SSIDS);
    for i in 0..8 {
        eight.slot[i].name = fixed(eight_names[i]);
        eight.slot[i].priority = eight_prio[i];
    }
    eight.preferred = Some(5);
    let mut nopref = eight;
    nopref.preferred = None;
    let mut one = MetaSet::defaults(&SSIDS[..1]);
    one.slot[0].name = fixed("Home sweet");
    one.slot[0].priority = 70;
    one.preferred = Some(0);
    let long: [&[u8]; 2] = [b"abcdefghijklmnopqrstuvwxyz012345", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"];
    let mut long_set = MetaSet::defaults(&long);
    long_set.preferred = Some(1);
    let cases: [(Bytes<'_>, List<'_>, &MetaSet); 5] = [
        (golden!("meta_empty.bin"), &SSIDS[..0], &MetaSet::defaults(&[])),
        (golden!("meta_one.bin"), &SSIDS[..1], &one),
        (golden!("meta_eight.bin"), &SSIDS, &eight),
        (golden!("meta_eight_nopref.bin"), &SSIDS, &nopref),
        (golden!("meta_long_ssid.bin"), &long, &long_set),
    ];
    for (bytes, list, set) in cases {
        let blob = MetaBlob::from_bytes(bytes).unwrap();
        assert_eq!(blob.to_bytes(), bytes, "decode then encode");
        assert_eq!(MetaBlob::encode(list, set).to_bytes(), bytes, "encode from the in-memory set");
        // And what the firmware ends up with is the set the blob was made from.
        assert_eq!(overlaid(bytes, list), *set);
    }
}

#[test]
fn meta_overlay_results_match_c() {
    let edited: [&[u8]; 4] = [b"Shed", b"Newcomer", b"Home", b"Lab"];
    let long: [&[u8]; 2] = [b"abcdefghijklmnopqrstuvwxyz012345", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"];
    let cases: [(Bytes<'_>, List<'_>, Bytes<'_>); 9] = [
        (golden!("meta_eight.bin"), &SSIDS, golden!("meta_eight.same.result.bin")),
        (golden!("meta_eight.bin"), &edited, golden!("meta_eight.edited.result.bin")),
        (golden!("meta_eight.bin"), &SSIDS[..2], golden!("meta_eight.two.result.bin")),
        (golden!("meta_one.bin"), &SSIDS[..1], golden!("meta_one.same.result.bin")),
        (golden!("meta_one.bin"), &SSIDS[..3], golden!("meta_one.three.result.bin")),
        (golden!("meta_empty.bin"), &SSIDS[..3], golden!("meta_empty.three.result.bin")),
        (golden!("meta_badname.bin"), &SSIDS[..2], golden!("meta_badname.same.result.bin")),
        (golden!("meta_garbage_tail.bin"), &SSIDS[..2], golden!("meta_garbage_tail.same.result.bin")),
        (golden!("meta_long_ssid.bin"), &long, golden!("meta_long_ssid.same.result.bin")),
    ];
    for (i, (blob, list, expected)) in cases.into_iter().enumerate() {
        assert_eq!(dump_meta(&overlaid(blob, list)), expected, "case {i}");
    }
}

#[test]
fn hostile_meta_blobs_are_refused_like_c() {
    let refused: [(&[u8], MetaBlobError); 6] = [
        (golden!("meta_bad_schema.bin"), MetaBlobError::BadSchema),
        (golden!("meta_bad_count.bin"), MetaBlobError::BadCount),
        (golden!("meta_bad_priority.bin"), MetaBlobError::BadPriority),
        (golden!("meta_name_unterminated.bin"), MetaBlobError::Unterminated),
        (golden!("meta_ssid_unterminated.bin"), MetaBlobError::Unterminated),
        (golden!("meta_preferred_unterminated.bin"), MetaBlobError::Unterminated),
    ];
    for (bytes, why) in refused {
        assert_eq!(MetaBlob::from_bytes(bytes), Err(why));
    }
    assert_eq!(MetaBlob::from_bytes(golden!("meta_priority_255.bin")), Err(MetaBlobError::BadPriority));
    // Accepted by C although it holds garbage: entries beyond count and bytes after terminators, preserved on re-encode.
    let g = golden!("meta_garbage_tail.bin");
    assert_eq!(MetaBlob::from_bytes(g).unwrap().to_bytes(), g);
    assert!(MetaBlob::from_bytes(golden!("meta_badname.bin")).is_ok());
}

// ---- display ----

#[test]
fn display_blobs() {
    let ok: [(&[u8], UiSettings); 4] = [
        (golden!("display_default.bin"), UiSettings { brightness: 60, rotation: 0, dim_seconds: 60 }),
        (golden!("display_custom.bin"), UiSettings { brightness: 33, rotation: 1, dim_seconds: 900 }),
        (golden!("display_max.bin"), UiSettings { brightness: 100, rotation: 0, dim_seconds: 3600 }),
        (golden!("display_min.bin"), UiSettings { brightness: 5, rotation: 1, dim_seconds: 10 }),
    ];
    for (bytes, expected) in ok {
        assert_eq!(UiSettings::from_bytes(bytes), Ok(expected));
        assert_eq!(expected.to_bytes(), bytes);
    }
    assert_eq!(UiSettings::from_bytes(golden!("display_bad_schema.bin")), Err(UiSettingsError::BadSchema));
    for bad in [golden!("display_bad_brightness.bin"), golden!("display_bad_rotation.bin"), golden!("display_bad_dim.bin")] {
        assert_eq!(UiSettings::from_bytes(bad), Err(UiSettingsError::OutOfRange));
    }
}

// ---- legacy adapter/config ----

fn blank() -> LegacySettings {
    LegacySettings { version: CFG_VERSION, p: [LegacyProfile::EMPTY; 8], preferred: 0, brightness: 60, rotation: 0, dim_seconds: 60 }
}

#[test]
fn legacy_blobs_decode_like_c_and_round_trip() {
    let cases: [(&[u8], &[u8]); 10] = [
        (golden!("legacy_empty.bin"), golden!("legacy_empty.import.bin")),
        (golden!("legacy_carried.bin"), golden!("legacy_carried.import.bin")),
        (golden!("legacy_one.bin"), golden!("legacy_one.import.bin")),
        (golden!("legacy_eight.bin"), golden!("legacy_eight.import.bin")),
        (golden!("legacy_messy.bin"), golden!("legacy_messy.import.bin")),
        (golden!("legacy_preferred_skipped.bin"), golden!("legacy_preferred_skipped.import.bin")),
        (golden!("legacy_preferred_out_of_range.bin"), golden!("legacy_preferred_out_of_range.import.bin")),
        (golden!("legacy_display_max.bin"), golden!("legacy_display_max.import.bin")),
        (golden!("legacy_inbetween.bin"), golden!("legacy_inbetween.import.bin")),
        (golden!("legacy_bad_version.bin"), &[]),
    ];
    for (i, (blob, expected)) in cases.into_iter().enumerate() {
        assert_eq!(LegacySettings::from_bytes(blob).unwrap().to_bytes(), blob, "case {i} round trip");
        match LegacyImport::decode(blob) {
            Ok(import) => assert_eq!(dump_import(&import), expected, "case {i}"),
            Err(e) => assert!(expected.is_empty() && e == LegacyError::WrongVersion, "case {i}: {e:?}"),
        }
    }
}

#[test]
fn legacy_blobs_match_the_c_encoder_when_built_in_rust() {
    let mut s = blank();
    s.p[0] = legacy_profile("Home", "HomeNet", "correct-horse", 50);
    s.p[1] = legacy_profile("Phone", "Pixel hotspot", "", 90);
    s.p[4] = legacy_profile("Car", "CarWifi", "12345678", 10);
    s.preferred = 4;
    s.brightness = 85;
    s.rotation = 1;
    s.dim_seconds = 300;
    assert_eq!(s.to_bytes(), golden!("legacy_carried.bin"));
    let mut one = blank();
    one.p[0] = legacy_profile("Home", "HomeNet", "pass1234", 50);
    assert_eq!(one.to_bytes(), golden!("legacy_one.bin"));
    assert_eq!(blank().to_bytes(), golden!("legacy_empty.bin"));
    let mut bad = one;
    bad.version = 2;
    assert_eq!(LegacyImport::decode(&bad.to_bytes()), Err(LegacyError::WrongVersion));
    let mut eight = blank();
    for i in 0..8 {
        let n = format!("net{i}");
        eight.p[i] = legacy_profile(&n, &n, "password", 10 + i as u8);
    }
    eight.preferred = 7;
    assert_eq!(eight.to_bytes(), golden!("legacy_eight.bin"));
}

// ---- wifi_profiles ----

fn saved(entries: &[(&str, &str)]) -> SavedNetworks {
    let mut l = SavedNetworks::default();
    for (i, (ssid, pass)) in entries.iter().enumerate() {
        l.profiles[i] = SavedProfile { ssid: fixed(ssid), password: fixed(pass) };
    }
    l.count = entries.len();
    l
}

#[test]
fn profiles_blobs_round_trip() {
    let eight: Vec<(String, String)> = (0..8).map(|i| (format!("network{i}"), if i == 3 { String::new() } else { format!("key-{i}") })).collect();
    let eight_refs: Vec<(&str, &str)> = eight.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let widest = ("abcdefghijklmnopqrstuvwxyz012345".to_string(), "p".repeat(62));
    let cases: [(&[u8], SavedNetworks); 6] = [
        (golden!("profiles_empty.bin"), saved(&[])),
        (golden!("profiles_one.bin"), saved(&[("HomeNet", "pass1234")])),
        (golden!("profiles_eight.bin"), saved(&eight_refs)),
        (golden!("profiles_widest.bin"), saved(&[(&widest.0, &widest.1)])),
        (golden!("profiles_inbetween.bin"), saved(&[("WorkNet", "pass5678"), ("HomeNet", "pass1234")])),
        (golden!("profiles_garbage_tail.bin"), SavedNetworks::from_bytes(golden!("profiles_garbage_tail.bin")).unwrap()),
    ];
    for (bytes, expected) in cases {
        let parsed = SavedNetworks::from_bytes(bytes).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(expected.to_bytes(), bytes);
    }
    let garbage = SavedNetworks::from_bytes(golden!("profiles_garbage_tail.bin")).unwrap();
    assert_eq!((garbage.count, garbage.list()[0].ssid_bytes(), garbage.profiles[3].ssid), (1, &b"HomeNet"[..], [0xA5; 33]));
}

#[test]
fn invalid_profiles_blobs_are_refused_like_c() {
    let refused: [(&[u8], SavedNetworksError); 5] = [
        (golden!("profiles_bad_schema.bin"), SavedNetworksError::BadSchema),
        (golden!("profiles_bad_count.bin"), SavedNetworksError::BadCount),
        (golden!("profiles_ssid_unterminated.bin"), SavedNetworksError::SsidUnterminated),
        (golden!("profiles_password_unterminated.bin"), SavedNetworksError::PasswordUnterminated),
        (golden!("profiles_empty_ssid.bin"), SavedNetworksError::EmptySsid),
    ];
    for (bytes, why) in refused {
        assert_eq!(SavedNetworks::from_bytes(bytes), Err(why));
    }
}

// ---- wifi_load_profiles ----

/// The same table as `load_case(...)` calls in `tools/gen_golden.c`.
#[test]
fn load_results_match_c() {
    let p_eight = golden!("profiles_eight.bin");
    let p_one = golden!("profiles_one.bin");
    let p_ib = golden!("profiles_inbetween.bin");
    let l_carried = golden!("legacy_carried.bin");
    let l_eight = golden!("legacy_eight.bin");
    let l_ib = golden!("legacy_inbetween.bin");
    let m_eight = golden!("meta_eight.bin");
    let m_one = golden!("meta_one.bin");
    let li = LoadInputs::default();
    let cases: Vec<(&str, &[u8], LoadInputs<'_>)> = vec![
        ("fresh_nothing", golden!("load_fresh_nothing.bin"), li),
        ("fresh_older", golden!("load_fresh_older.bin"), LoadInputs { older: Some((b"legacy", b"secret")), ..li }),
        ("fresh_legacy_carried", golden!("load_fresh_legacy_carried.bin"), LoadInputs { legacy: Some(l_carried), ..li }),
        ("fresh_legacy_messy", golden!("load_fresh_legacy_messy.bin"), LoadInputs { legacy: Some(golden!("legacy_messy.bin")), ..li }),
        ("fresh_legacy_empty", golden!("load_fresh_legacy_empty.bin"), LoadInputs { legacy: Some(golden!("legacy_empty.bin")), ..li }),
        (
            "fresh_older_and_legacy_eight",
            golden!("load_fresh_older_and_legacy_eight.bin"),
            LoadInputs { legacy: Some(l_eight), older: Some((b"net3", b"oldpass1")), ..li },
        ),
        ("fresh_legacy_stored_meta", golden!("load_fresh_legacy_stored_meta.bin"), LoadInputs { meta: Some(m_eight), legacy: Some(l_eight), ..li }),
        (
            "fresh_stored_meta_names_none",
            golden!("load_fresh_stored_meta_names_none.bin"),
            LoadInputs { meta: Some(golden!("meta_empty.bin")), legacy: Some(l_carried), ..li },
        ),
        (
            "fresh_stored_meta_over_older",
            golden!("load_fresh_stored_meta_over_older.bin"),
            LoadInputs { meta: Some(m_one), older: Some((b"Home", b"pw")), ..li },
        ),
        (
            "fresh_invalid_meta_ignored",
            golden!("load_fresh_invalid_meta_ignored.bin"),
            LoadInputs { meta: Some(golden!("meta_bad_schema.bin")), legacy: Some(golden!("legacy_one.bin")), ..li },
        ),
        (
            "fresh_invalid_legacy_ignored",
            golden!("load_fresh_invalid_legacy_ignored.bin"),
            LoadInputs { legacy: Some(golden!("legacy_bad_version.bin")), older: Some((b"legacy", b"secret")), ..li },
        ),
        ("existing_eight", golden!("load_existing_eight.bin"), LoadInputs { profiles: Some(p_eight), ..li }),
        ("existing_eight_with_meta", golden!("load_existing_eight_with_meta.bin"), LoadInputs { profiles: Some(p_eight), meta: Some(m_eight), ..li }),
        ("existing_ignores_older", golden!("load_existing_ignores_older.bin"), LoadInputs { profiles: Some(p_one), older: Some((b"other", b"pw")), ..li }),
        ("existing_legacy_by_ssid", golden!("load_existing_legacy_by_ssid.bin"), LoadInputs { profiles: Some(p_ib), legacy: Some(l_ib), ..li }),
        (
            "existing_legacy_then_meta",
            golden!("load_existing_legacy_then_meta.bin"),
            LoadInputs { profiles: Some(p_ib), meta: Some(m_one), legacy: Some(l_ib), ..li },
        ),
        ("existing_garbage_tail", golden!("load_existing_garbage_tail.bin"), LoadInputs { profiles: Some(golden!("profiles_garbage_tail.bin")), ..li }),
        ("existing_widest", golden!("load_existing_widest.bin"), LoadInputs { profiles: Some(golden!("profiles_widest.bin")), ..li }),
        (
            "existing_empty_list",
            golden!("load_existing_empty_list.bin"),
            LoadInputs { profiles: Some(golden!("profiles_empty.bin")), meta: Some(m_eight), legacy: Some(l_carried), ..li },
        ),
        ("existing_bad_schema", golden!("load_existing_bad_schema.bin"), LoadInputs { profiles: Some(golden!("profiles_bad_schema.bin")), ..li }),
        ("existing_bad_count", golden!("load_existing_bad_count.bin"), LoadInputs { profiles: Some(golden!("profiles_bad_count.bin")), ..li }),
        (
            "existing_ssid_unterminated",
            golden!("load_existing_ssid_unterminated.bin"),
            LoadInputs { profiles: Some(golden!("profiles_ssid_unterminated.bin")), ..li },
        ),
        (
            "existing_password_unterminated",
            golden!("load_existing_password_unterminated.bin"),
            LoadInputs { profiles: Some(golden!("profiles_password_unterminated.bin")), ..li },
        ),
        ("existing_empty_ssid", golden!("load_existing_empty_ssid.bin"), LoadInputs { profiles: Some(golden!("profiles_empty_ssid.bin")), ..li }),
        ("existing_wrong_length", golden!("load_existing_wrong_length.bin"), LoadInputs { profiles: Some(&p_one[..783]), ..li }),
        ("existing_empty_blob", golden!("load_existing_empty_blob.bin"), LoadInputs { profiles: Some(&p_one[..0]), ..li }),
    ];
    let mut refused = 0;
    for (name, expected, inputs) in &cases {
        let got = load_wifi_profiles(inputs);
        refused += usize::from(got.is_err());
        assert_eq!(&dump_load(&got), expected, "{name}");
    }
    assert_eq!(refused, 7);
}
