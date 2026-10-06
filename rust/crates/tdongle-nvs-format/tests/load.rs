//! The load logic of `wifi_load_profiles()` and `display_load()`, ported from the scenarios of `alternative/tailnet/tests/test_wifi_profiles.c`.
mod common;
use common::{fixed, legacy_profile};
use tdongle_nvs_format::legacy::{CFG_VERSION, LegacyProfile, LegacySettings};
use tdongle_nvs_format::load::{LoadInputs, Loaded, display_load, load_wifi_profiles};
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_meta::{MetaBlob, MetaSet};
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedNetworksError, SavedProfile};

fn legacy(entries: &[(&str, &str, &str, u8)], preferred: u8) -> LegacySettings {
    let mut s = LegacySettings {
        version: CFG_VERSION,
        p: [LegacyProfile::EMPTY; 8],
        preferred,
        brightness: 60,
        rotation: 0,
        dim_seconds: 60,
    };
    for (i, (name, ssid, pass, prio)) in entries.iter().enumerate() {
        s.p[i] = legacy_profile(name, ssid, pass, *prio);
    }
    s
}

fn saved(entries: &[(&str, &str)]) -> SavedNetworks {
    let mut l = SavedNetworks::default();
    for (i, (ssid, pass)) in entries.iter().enumerate() {
        l.profiles[i] = SavedProfile {
            ssid: fixed(ssid),
            password: fixed(pass),
        };
    }
    l.count = entries.len();
    l
}

fn ssids(l: &Loaded) -> Vec<&[u8]> {
    l.saved
        .list()
        .iter()
        .map(SavedProfile::ssid_bytes)
        .collect()
}

fn meta_blob(list: &[&str], f: impl FnOnce(&mut MetaSet)) -> [u8; 516] {
    let ssids: Vec<&[u8]> = list.iter().map(|s| s.as_bytes()).collect();
    let mut set = MetaSet::defaults(&ssids);
    f(&mut set);
    MetaBlob::encode(&ssids, &set).to_bytes()
}

#[test]
fn nothing_stored_is_an_empty_list() {
    let l = load_wifi_profiles(&LoadInputs::default()).unwrap();
    assert_eq!(l.saved, SavedNetworks::default());
    assert_eq!(l.meta, MetaSet::defaults(&[]));
}

#[test]
fn a_v011_install_imports_its_only_network() {
    let blob = legacy(&[("", "bridge", "secret", 0)], 0).to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        legacy: Some(&blob),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(ssids(&l), [b"bridge"]);
    assert_eq!(l.saved.list()[0].password_bytes(), b"secret");
    assert_eq!(l.meta.slot[0].name_bytes(), b"bridge"); // no usable name: the SSID
}

#[test]
fn the_older_single_network_is_the_first() {
    let l = load_wifi_profiles(&LoadInputs {
        older: Some((b"legacy", b"secret")),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(ssids(&l), [b"legacy"]);
    assert_eq!(l.saved.list()[0].password_bytes(), b"secret");
    // An empty SSID is no network; an over-long one is cut at 32, the password at 63.
    let l = load_wifi_profiles(&LoadInputs {
        older: Some((b"", b"secret")),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.saved.count, 0);
    let l = load_wifi_profiles(&LoadInputs {
        older: Some((&[b's'; 40], &[b'p'; 70])),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.saved.list()[0].ssid_bytes(), &[b's'; 32]);
    assert_eq!(l.saved.list()[0].password_bytes(), &[b'p'; 63]);
}

#[test]
fn upgrade_is_lossless() {
    let mut old = legacy(
        &[
            ("Home", "HomeNet", "correct-horse", 50),
            ("Phone", "Pixel hotspot", "", 90),
        ],
        4,
    );
    old.p[4] = legacy_profile("Car", "CarWifi", "12345678", 10);
    old.brightness = 85;
    old.rotation = 1;
    old.dim_seconds = 300;
    let blob = old.to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        legacy: Some(&blob),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(ssids(&l), [&b"HomeNet"[..], b"Pixel hotspot", b"CarWifi"]);
    assert_eq!(l.saved.list()[0].password_bytes(), b"correct-horse");
    assert_eq!(l.saved.list()[1].password_bytes(), b"");
    let names: Vec<_> = (0..3)
        .map(|i| (l.meta.slot[i].name_bytes(), l.meta.slot[i].priority))
        .collect();
    assert_eq!(names, [(&b"Home"[..], 50), (b"Phone", 90), (b"Car", 10)]);
    assert_eq!(l.meta.preferred, Some(2)); // the preferred slot followed its network through the compaction
    assert_eq!(
        display_load(None, Some(&blob)),
        UiSettings {
            brightness: 85,
            rotation: 1,
            dim_seconds: 300
        }
    );
    // Until the first explicit save the import repeats at every boot, so it must give the same answer.
    assert_eq!(
        load_wifi_profiles(&LoadInputs {
            legacy: Some(&blob),
            ..Default::default()
        }),
        Ok(l)
    );
}

#[test]
fn fresh_import_dedupes_against_the_older_network() {
    let entries: Vec<(String, String, String, u8)> = (0..8)
        .map(|i| {
            (
                format!("n{i}"),
                format!("net{i}"),
                "password".into(),
                10 + i as u8,
            )
        })
        .collect();
    let refs: Vec<(&str, &str, &str, u8)> = entries
        .iter()
        .map(|(a, b, c, d)| (a.as_str(), b.as_str(), c.as_str(), *d))
        .collect();
    let blob = legacy(&refs, 7).to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        legacy: Some(&blob),
        older: Some((b"net3", b"oldpass1")),
        ..Default::default()
    })
    .unwrap();
    // The older network takes slot 0 with its own password; net3 of the v0.1.x list repeats it and is skipped; eight networks fit.
    assert_eq!(l.saved.count, 8);
    assert_eq!(ssids(&l)[..4], [&b"net3"[..], b"net0", b"net1", b"net2"]);
    assert_eq!(l.saved.list()[0].password_bytes(), b"oldpass1");
    // The v0.1.x metadata is applied to the older network too, by SSID: net3 keeps priority 13 and the name n3.
    assert_eq!(
        (l.meta.slot[0].name_bytes(), l.meta.slot[0].priority),
        (&b"n3"[..], 13)
    );
    assert_eq!(l.meta.preferred, Some(7));
    // Nine usable networks cannot happen (eight source slots) but the list never exceeds eight: older + 8 distinct would be cut.
    let blob = legacy(&refs, 0).to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        legacy: Some(&blob),
        older: Some((b"extra", b"")),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.saved.count, 8);
    assert_eq!(l.saved.list()[7].ssid_bytes(), b"net6");
    assert_eq!(l.meta.preferred, Some(1)); // net0, the old preferred slot, is now slot 1
}

#[test]
fn in_between_build_keeps_priorities_by_ssid() {
    // The first unified build saved networks without metadata and re-ordered them; the v0.1.x priorities are still in the old namespace.
    let old = legacy(
        &[
            ("Home", "HomeNet", "pass1234", 30),
            ("Work", "WorkNet", "pass5678", 80),
        ],
        1,
    )
    .to_bytes();
    let list = saved(&[("WorkNet", "pass5678"), ("HomeNet", "pass1234")]).to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        profiles: Some(&list),
        legacy: Some(&old),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.saved.count, 2);
    assert_eq!(
        (l.meta.slot[0].priority, l.meta.slot[0].name_bytes()),
        (80, &b"Work"[..])
    );
    assert_eq!(l.meta.slot[1].priority, 30);
    assert_eq!(l.meta.preferred, Some(0)); // matched by SSID, not by position
    // Once metadata exists it wins over the old namespace.
    let meta = meta_blob(&["WorkNet", "HomeNet"], |m| m.slot[0].priority = 10);
    let l = load_wifi_profiles(&LoadInputs {
        profiles: Some(&list),
        meta: Some(&meta),
        legacy: Some(&old),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.meta.slot[0].priority, 10);
}

#[test]
fn use_after_upgrade_survives_a_restart() {
    // `use 3` right after an upgrade writes only the metadata; the v0.1.x priorities must still apply to networks it does not name.
    let old = legacy(
        &[
            ("Home", "HomeNet", "pass1234", 30),
            ("Work", "WorkNet", "pass5678", 80),
            ("Cafe", "CafeNet", "pass9999", 10),
        ],
        0,
    )
    .to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        legacy: Some(&old),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.meta.preferred, Some(0));
    let ssids: Vec<&[u8]> = l
        .saved
        .list()
        .iter()
        .map(SavedProfile::ssid_bytes)
        .collect();
    let mut changed = l.meta;
    changed.preferred = Some(2);
    let meta = MetaBlob::encode(&ssids, &changed).to_bytes();
    let again = load_wifi_profiles(&LoadInputs {
        meta: Some(&meta),
        legacy: Some(&old),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(again.meta.preferred, Some(2)); // the new preference, not the v0.1.x one
    assert_eq!(
        [
            again.meta.slot[0].priority,
            again.meta.slot[1].priority,
            again.meta.slot[2].priority
        ],
        [30, 80, 10]
    );
    assert_eq!(again.meta.slot[1].name_bytes(), b"Work");
    // "No preference" is a choice too.
    changed.preferred = None;
    let meta = MetaBlob::encode(&ssids, &changed).to_bytes();
    let none = load_wifi_profiles(&LoadInputs {
        meta: Some(&meta),
        legacy: Some(&old),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(none.meta.preferred, None);
}

#[test]
fn a_list_edited_by_an_older_build_keeps_its_metadata() {
    // profile_blob_format_is_frozen: metadata for Home, then a build that knows nothing of it appends a network.
    let meta = meta_blob(&["Home"], |m| {
        m.slot[0].name = fixed("Home sweet");
        m.slot[0].priority = 70;
    });
    let list = saved(&[("Home", "pass1234"), ("Added", "pass5678")]).to_bytes();
    let l = load_wifi_profiles(&LoadInputs {
        profiles: Some(&list),
        meta: Some(&meta),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        (
            l.meta.slot[0].name_bytes(),
            l.meta.slot[0].priority,
            l.meta.slot[1].priority
        ),
        (&b"Home sweet"[..], 70, 50)
    );
}

#[test]
fn an_invalid_list_is_refused_and_invalid_side_blobs_are_ignored() {
    let mut list = saved(&[("Home", "pass1234")]).to_bytes();
    list[0] = 0xE7; // schema 999
    list[1] = 0x03;
    assert_eq!(
        load_wifi_profiles(&LoadInputs {
            profiles: Some(&list),
            ..Default::default()
        }),
        Err(SavedNetworksError::BadSchema)
    );
    // An invalid meta blob or legacy blob is ignored, not an error.
    let good = saved(&[("Home", "pass1234")]).to_bytes();
    let mut meta = meta_blob(&["Home"], |m| m.slot[0].priority = 99);
    meta[0] = 9;
    let l = load_wifi_profiles(&LoadInputs {
        profiles: Some(&good),
        meta: Some(&meta),
        legacy: Some(&[1, 2, 3]),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.meta.slot[0].priority, 50);
    // An empty stored blob (zero length) is a wrong size, i.e. refused, not "not found".
    assert_eq!(
        load_wifi_profiles(&LoadInputs {
            profiles: Some(&[]),
            ..Default::default()
        }),
        Err(SavedNetworksError::WrongSize)
    );
}

#[test]
fn display_precedence() {
    let old = {
        let mut s = legacy(&[], 0);
        s.brightness = 85;
        s.to_bytes()
    };
    let mine = UiSettings {
        brightness: 40,
        rotation: 0,
        dim_seconds: 120,
    };
    assert_eq!(display_load(None, None), UiSettings::default());
    assert_eq!(
        display_load(None, Some(&old)),
        UiSettings {
            brightness: 85,
            rotation: 0,
            dim_seconds: 60
        }
    );
    assert_eq!(display_load(Some(&mine.to_bytes()), Some(&old)), mine);
    // A damaged display blob falls back to the old settings, never to garbage.
    let mut damaged = mine.to_bytes();
    damaged[0] = 7;
    assert_eq!(display_load(Some(&damaged), Some(&old)).brightness, 85);
    assert_eq!(display_load(Some(&damaged), None), UiSettings::default());
    // Old settings out of range are not used.
    let mut s = legacy(&[], 0);
    s.rotation = 7;
    assert_eq!(
        display_load(None, Some(&s.to_bytes())),
        UiSettings::default()
    );
    // Not a v0.1.x blob at all.
    assert_eq!(display_load(None, Some(&[0; 10])), UiSettings::default());
}
