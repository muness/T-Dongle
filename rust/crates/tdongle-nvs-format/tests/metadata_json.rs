//! `metadata JSON` against the companion C firmware's own test (`tests/test_profile_json.c`, branch `codex/test-firmware`) and the line the
//! Android app sends (`ManagementClient.metadata`).

use tdongle_nvs_format::metadata_json::{MetadataJsonError as E, metadata_parse_json};
use tdongle_nvs_format::wifi_meta::{MetaSet, MetaSlot};
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedProfile};

fn list(ssids: &[&[u8]]) -> (SavedNetworks, MetaSet) {
    let mut l = SavedNetworks::default();
    for (i, s) in ssids.iter().enumerate() {
        let mut p = SavedProfile::EMPTY;
        p.ssid[..s.len()].copy_from_slice(s);
        p.password[..15].copy_from_slice(b"secret-password");
        l.profiles[i] = p;
    }
    l.count = ssids.len();
    (l, MetaSet::defaults(ssids))
}

fn named(meta: &mut MetaSet, slot: usize, name: &[u8], priority: u8) {
    let mut s = MetaSlot::EMPTY;
    s.name[..name.len()].copy_from_slice(name);
    s.priority = priority;
    meta.slot[slot] = s;
}

const C_TEST: &str =
    "{\"slot\":1,\"expectedName\":\"Home\",\"expectedSsid\":\"WiFi\",\"expectedPriority\":50,\"name\":\"Renamed\",\"priority\":80,\"preferred\":true}";

#[test]
fn the_c_test_case() {
    let edit = metadata_parse_json(C_TEST.as_bytes()).unwrap();
    let (l, mut m) = list(&[b"WiFi"]);
    named(&mut m, 0, b"Home", 50);
    m.preferred = None;
    let after = edit.apply(&l, &m).unwrap();
    assert_eq!(after.slot[0].name_bytes(), b"Renamed");
    assert_eq!(after.slot[0].priority, 80);
    assert_eq!(after.preferred, Some(0));
    // the list (SSID, password) is not an output at all; applying the same edit again fails: the identity changed
    assert_eq!(edit.apply(&l, &after), None);
    assert!(metadata_parse_json(b"{}").is_err());
    assert_eq!(metadata_parse_json(b"{\"slot\":1,\"slot\":2}"), Err(E::BadKey));
    assert_eq!(metadata_parse_json(b"{\"name\":\"bad\\u0000name\"}"), Err(E::EscapeNotAllowed));
}

/// The exact line `ManagementClient.metadata` builds (`Profile.quote` escapes `"` and `\`).
fn app_line(slot: u32, en: &str, es: &str, ep: u32, name: &str, p: u32, preferred: bool) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    format!(
        "{{\"slot\":{slot},\"expectedName\":{},\"expectedSsid\":{},\"expectedPriority\":{ep},\"name\":{},\"priority\":{p},\"preferred\":{preferred}}}",
        q(en),
        q(es),
        q(name)
    )
}

#[test]
fn the_app_line_parses_and_applies_without_touching_the_preference_when_false() {
    let (l, mut m) = list(&[b"Office", b"Cafe \"Q\""]);
    m.preferred = Some(0);
    let line = app_line(2, "Cafe \"Q\"", "Cafe \"Q\"", 50, "Back\\room", 7, false);
    let edit = metadata_parse_json(line.as_bytes()).unwrap();
    let after = edit.apply(&l, &m).unwrap();
    assert_eq!(after.slot[1].name_bytes(), b"Back\\room");
    assert_eq!(after.slot[1].priority, 7);
    assert_eq!(after.preferred, Some(0), "preferred=false keeps the existing preference");
    assert_eq!(after.slot[0], m.slot[0]);
}

#[test]
fn identity_mismatches_and_missing_slots_change_nothing() {
    let (l, m) = list(&[b"Office"]);
    for line in [
        app_line(1, "Other", "Office", 50, "X", 1, true),
        app_line(1, "Office", "Office2", 50, "X", 1, true),
        app_line(1, "Office", "Office", 49, "X", 1, true),
        app_line(2, "Office", "Office", 50, "X", 1, true),
    ] {
        assert_eq!(metadata_parse_json(line.as_bytes()).unwrap().apply(&l, &m), None, "{line}");
    }
}

#[test]
fn field_rules() {
    let ok = app_line(1, "a", "b", 0, "c", 100, true);
    assert!(metadata_parse_json(ok.as_bytes()).is_ok());
    for (line, why) in [
        (app_line(0, "a", "b", 0, "c", 1, true), E::BadValue),
        (app_line(9, "a", "b", 0, "c", 1, true), E::BadValue),
        (app_line(1, "a", "b", 101, "c", 1, true), E::BadValue),
        (app_line(1, "a", "b", 0, "c", 101, true), E::BadValue),
        (app_line(1, "a", "b", 0, &"n".repeat(25), 1, true), E::BadValue),
        (app_line(1, "a", &"s".repeat(33), 0, "c", 1, true), E::BadValue),
        (app_line(1, "a", "b", 0, "", 1, true), E::InvalidText),
        (app_line(1, "", "b", 0, "c", 1, true), E::InvalidText),
        (app_line(1, "a", "", 0, "c", 1, true), E::InvalidText),
        (app_line(1, "a", "b", 0, "x ssid=y", 1, true), E::InvalidText),
        (app_line(1, "a", "b", 0, "tab\there", 1, true), E::InvalidText),
        (ok.replace("true", "1"), E::Malformed),
        (ok.replace("true", "null"), E::Malformed),
        (ok.replace(",\"preferred\":true", ""), E::MissingKey),
        (ok.replace("\"preferred\"", "\"Preferred\""), E::BadKey),
        (format!("{ok} x"), E::Malformed),
        (format!("{ok:<501}"), E::TooLong),
    ] {
        assert_eq!(metadata_parse_json(line.as_bytes()), Err(why), "{line}");
    }
    // cJSON numbers: 1.0 and 1e0 are the integer 1; trailing white space is fine
    assert!(metadata_parse_json(ok.replace("\"slot\":1", "\"slot\":1.0").as_bytes()).is_ok());
    assert!(metadata_parse_json(format!(" {ok} \r\n").as_bytes()).is_ok());
    assert_eq!(metadata_parse_json(ok.replace("\"slot\":1", "\"slot\":1.5").as_bytes()), Err(E::BadValue));
}
