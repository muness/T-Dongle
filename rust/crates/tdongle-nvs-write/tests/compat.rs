//! Compatibility with the C firmware: the 88 golden blobs written by the C code (`tdongle-nvs-format/tests/golden`) go through the writer
//! and come back byte-equal; what the Rust side writes loads the same list through the C loader logic (`tdongle-nvs-format::load`) as
//! through `Store::load_all`; v0.1.1's `adapter/config` is never touched except by factory reset; v0.1.1-era and v0.3.0-era images load.
mod common;

use std::path::Path;

use common::*;
use tdongle_nvs_format::legacy::LegacyImport;
use tdongle_nvs_format::load::{LoadInputs, load_wifi_profiles};
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_meta::MetaSet;
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedProfile};
use tdongle_nvs_read::{Nvs as Reader, SliceFlash};
use tdongle_nvs_write::{Nvs, SimFlash, Store};

fn golden() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tdongle-nvs-format/tests/golden");
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "bin"))
        .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(&p).unwrap()))
        .collect();
    v.sort();
    v
}

#[test]
fn the_88_golden_blobs_round_trip_byte_equal_through_the_writer() {
    let blobs = golden();
    assert_eq!(blobs.len(), 88);
    let mut nvs = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
    for (i, (name, data)) in blobs.iter().enumerate() {
        // as the key the C would use for this size, so single-chunk and multi-chunk paths both run in their real namespace
        let (ns, key) = match data.len() {
            784 => ("tn_settings", "wifi_profiles"),
            516 => ("tn_settings", "wifi_meta"),
            8 => ("tn_settings", "display"),
            1004 => ("adapter", "config"),
            _ => ("golden", "other"),
        };
        if data.len() > 40_000 {
            // the JSON corpus of the `profile` command tests is not an NVS blob
            assert_eq!(nvs.set_blob(ns, key, data), Err(tdongle_nvs_write::Error::ValueTooLong), "{name}");
            continue;
        }
        nvs.set_blob(ns, key, data).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let mut out = vec![0u8; data.len()];
        assert_eq!(nvs.get_blob(ns, key, &mut out).unwrap(), Some(data.len()), "{name}");
        assert_eq!(&out, data, "{name}: engine read-back");
        let img = nvs.flash().data.clone();
        let mut r = Reader::new(SliceFlash(&img), SIZE);
        let mut out2 = vec![0u8; data.len()];
        assert_eq!(r.get_blob(ns, key, &mut out2).unwrap(), Some(data.len()), "{name}");
        assert_eq!(&out2, data, "{name}: reader read-back");
        if i % 11 == 0 {
            // a cold mount sees the same bytes too
            let mut again = Nvs::open(SimFlash::from_image(img), SIZE).unwrap();
            let mut out3 = vec![0u8; data.len()];
            again.get_blob(ns, key, &mut out3).unwrap();
            assert_eq!(&out3, data, "{name}: after remount");
        }
    }
    assert_eq!(nvs.flash().violations, 0);
    let d = dump(&mut nvs);
    let img = nvs.flash().data.clone();
    verify_with_idf("golden_blobs", &img, &d, true);
}

fn net(i: usize, tag: u8) -> SavedProfile {
    let mut p = SavedProfile::EMPTY;
    let ssid = format!("Home{tag}-{i}");
    let pw = if i.is_multiple_of(3) { String::new() } else { format!("pw{i}{}", "y".repeat(i * 7)) };
    p.ssid[..ssid.len()].copy_from_slice(ssid.as_bytes());
    p.password[..pw.len()].copy_from_slice(pw.as_bytes());
    p
}

fn list(n: usize, tag: u8) -> (SavedNetworks, MetaSet) {
    let mut saved = SavedNetworks::default();
    for i in 0..n {
        saved.profiles[i] = net(i, tag);
    }
    saved.count = n;
    let mut meta = MetaSet::defaults(&saved.ssids()[..n]);
    for i in 0..n {
        meta.slot[i].priority = (20 + 11 * i as u8) % 101;
        if i % 2 == 1 {
            meta.slot[i].name = [0; 25];
            meta.slot[i].name[..4].copy_from_slice(b"Nick");
        }
    }
    meta.preferred = (n > 2).then(|| n - 1);
    (saved, meta)
}

/// The C loader logic fed with what the *reader* finds in the image (what the C firmware would read from flash).
fn c_loader(image: &[u8]) -> tdongle_nvs_format::load::Loaded {
    let mut r = Reader::new(SliceFlash(image), SIZE);
    let get = |r: &mut Reader<SliceFlash<'_>>, ns: &str, key: &str, cap: usize| -> Option<Vec<u8>> {
        let n = r.blob_len(ns, key).unwrap()?;
        let mut b = vec![0u8; n.max(cap)];
        let n = r.get_blob(ns, key, &mut b).unwrap()?;
        b.truncate(n);
        Some(b)
    };
    let profiles = get(&mut r, "tn_settings", "wifi_profiles", 0);
    let meta = get(&mut r, "tn_settings", "wifi_meta", 0);
    let legacy = get(&mut r, "adapter", "config", 0);
    load_wifi_profiles(&LoadInputs { profiles: profiles.as_deref(), meta: meta.as_deref(), legacy: legacy.as_deref(), older: None }).unwrap()
}

#[test]
fn what_rust_wrote_loads_the_same_through_the_c_loader() {
    for n in 0..=8 {
        for tag in [1u8, 2, 3] {
            let (l, m) = list(n, tag);
            let mut s = Store::mount(SimFlash::new(SIZE as usize), SIZE).unwrap();
            // an earlier, different list was saved first: the new one must win everywhere
            let (l0, m0) = list(8 - n, tag + 10);
            s.save_profiles(&l0, &m0).unwrap();
            s.save_profiles(&l, &m).unwrap();
            let image = s.nvs().flash().data.clone();
            let c = c_loader(&image);
            let ours = s.load_all().unwrap();
            assert_eq!(ours.networks, c, "n={n} tag={tag}: Store::load_all and the C loader disagree");
            assert_eq!(c.saved, l, "n={n}");
            assert_eq!(c.meta.preferred, m.preferred, "n={n}");
            for i in 0..n {
                assert_eq!(c.meta.slot[i], m.slot[i], "n={n} slot {i}");
            }
            // and a cold mount of the image reads the same
            let mut cold = Store::mount(SimFlash::from_image(image), SIZE).unwrap();
            assert_eq!(cold.load_all().unwrap(), ours);
        }
    }
}

#[test]
fn display_and_mode_are_the_blob_and_the_u8_the_c_reads() {
    let mut s = Store::mount(SimFlash::new(SIZE as usize), SIZE).unwrap();
    let ui = UiSettings { brightness: 77, rotation: 1, dim_seconds: 321 };
    s.save_display(&ui).unwrap();
    s.save_mode(Mode::TailnetGateway).unwrap();
    let img = s.nvs().flash().data.clone();
    let mut r = Reader::new(SliceFlash(&img), SIZE);
    let mut b = [0u8; 8];
    assert_eq!(r.get_blob("tn_settings", "display", &mut b).unwrap(), Some(8));
    assert_eq!(b, ui.to_bytes());
    assert_eq!(r.get_u8("tn_settings", "mode").unwrap(), Some(1));
    let loaded = s.load_all().unwrap();
    assert_eq!(loaded.display, ui);
    assert_eq!(loaded.mode, Ok(Mode::TailnetGateway));
}

/// A v0.1.1 install: `adapter/config` and nothing else. The Rust side may load it, import it, save over it, but must not rewrite it.
fn v011_image() -> (Vec<u8>, Vec<u8>) {
    let blob = golden().into_iter().find(|(n, _)| n == "legacy_carried.bin").unwrap().1;
    assert_eq!(blob.len(), 1004);
    let mut nvs = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
    nvs.set_blob("adapter", "config", &blob).unwrap();
    (nvs.into_flash().data, blob)
}

fn position(image: &[u8], needle: &[u8]) -> Vec<usize> {
    image.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i).collect()
}

#[test]
fn adapter_config_is_never_rewritten_by_saves_or_imports() {
    let (image, blob) = v011_image();
    let at = position(&image, &blob);
    assert_eq!(at.len(), 1);
    let mut s = Store::mount(SimFlash::from_image(image), SIZE).unwrap();
    let before = s.load_all().unwrap();
    assert!(before.networks.saved.count > 0, "the legacy networks are imported in RAM");
    // loading wrote nothing
    assert_eq!(s.nvs().flash().spent, 0);
    // the import persists them, and the old blob is where it was, byte for byte
    assert!(s.import_legacy().unwrap());
    assert!(!s.import_legacy().unwrap(), "a second import has nothing to do");
    let after = s.load_all().unwrap();
    assert_eq!(after.networks, before.networks, "importing must not change what the device sees");
    assert_eq!(after.display, before.display);
    for step in 0..6u8 {
        let (l, m) = list(1 + usize::from(step), step);
        s.save_profiles(&l, &m).unwrap();
        s.save_display(&UiSettings { brightness: 10 + step, rotation: step % 2, dim_seconds: 60 + u16::from(step) }).unwrap();
        s.save_mode(if step % 2 == 0 { Mode::WifiBridge } else { Mode::TailnetGateway }).unwrap();
        let img = s.nvs().flash().data.clone();
        if s.nvs().flash().erases == 0 {
            assert_eq!(position(&img, &blob), at, "step {step}: adapter/config moved or was rewritten");
        }
        let mut r = Reader::new(SliceFlash(&img), SIZE);
        let mut got = vec![0u8; 1004];
        assert_eq!(r.get_blob("adapter", "config", &mut got).unwrap(), Some(1004));
        assert_eq!(got, blob, "step {step}: v0.1.1 would read different settings");
        // v0.1.1 only needs the old namespace; its own keys are all still there and typed as before
        assert!(LegacyImport::decode(&got).is_ok());
    }
}

#[test]
fn adapter_config_survives_compaction_byte_equal() {
    let (image, blob) = v011_image();
    let mut s = Store::mount(SimFlash::from_image(image), SIZE).unwrap();
    for i in 0..400u32 {
        let (l, m) = list(1 + (i as usize % 8), (i % 200) as u8);
        s.save_profiles(&l, &m).unwrap();
    }
    assert!(s.nvs().flash().erases > 0, "pages were compacted");
    let img = s.nvs().flash().data.clone();
    let mut r = Reader::new(SliceFlash(&img), SIZE);
    let mut got = vec![0u8; 1004];
    assert_eq!(r.get_blob("adapter", "config", &mut got).unwrap(), Some(1004));
    assert_eq!(got, blob);
}

#[test]
fn factory_reset_forgets_v011_data_and_keeps_the_rest() {
    let (image, _) = v011_image();
    let mut s = Store::mount(SimFlash::from_image(image), SIZE).unwrap();
    let (l, m) = list(3, 1);
    s.save_profiles(&l, &m).unwrap();
    s.save_display(&UiSettings::default()).unwrap();
    s.save_mode(Mode::TailnetGateway).unwrap();
    s.nvs().set_str("tn_settings", "members", "a,b").unwrap();
    s.nvs().set_blob("tn_settings", "wifi", &[0u8; 184]).unwrap();
    s.nvs().set_blob("tailnet", "identity", &pattern(300, 4)).unwrap();
    s.factory_reset().unwrap();
    let d = dump(s.nvs());
    let keys: Vec<_> = d.keys().map(|(a, b)| format!("{a}/{b}")).collect();
    assert_eq!(keys, ["tailnet/identity", "tn_settings/members", "tn_settings/mode"], "{keys:?}");
    let loaded = s.load_all().unwrap();
    assert_eq!(loaded.networks.saved.count, 0, "nothing is imported again");
    assert_eq!(loaded.display, UiSettings::default());
    assert_eq!(loaded.mode, Ok(Mode::TailnetGateway));
    // idempotent
    s.factory_reset().unwrap();
    assert_eq!(dump(s.nvs()), d);
}

#[test]
fn generator_made_board_images_load_like_the_c_loader_and_import_cleanly() {
    macro_rules! img {
        ($n:literal) => {
            include_bytes!(concat!("../../tdongle-nvs-read/tests/fixtures/", $n, ".bin")).to_vec()
        };
    }
    for (name, image) in [("board_v01", img!("board_v01")), ("board_v03", img!("board_v03"))] {
        let mut s = Store::mount(SimFlash::from_image(image.clone()), SIZE).unwrap();
        let loaded = s.load_all().unwrap();
        assert_eq!(s.nvs().flash().spent, 0, "{name}: loading must not write");
        if name == "board_v03" {
            assert_eq!(c_loader(&image), loaded.networks, "{name}");
            assert_eq!(loaded.networks.saved.count, 3);
            assert_eq!(loaded.mode, Ok(Mode::TailnetGateway));
        } else {
            // no list stored: the single `wifi` network, then the v0.1.x ones
            assert_eq!(loaded.networks.saved.count, 3, "{name}");
            let wrote = s.import_legacy().unwrap();
            assert!(wrote);
            let again = s.load_all().unwrap();
            assert_eq!(again.networks, loaded.networks, "{name}: persisted import must load the same");
            let img = s.nvs().flash().data.clone();
            let d = dump(s.nvs());
            verify_with_idf(&format!("compat_{name}_imported"), &img, &d, true);
        }
    }
}
