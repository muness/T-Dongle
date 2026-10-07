//! Images written by this crate, committed (`tests/fixtures`): the on-flash result of fixed sequences is part of the contract with the C
//! firmware, so any change of what the writer puts on flash shows up as a diff here. Each `X.bin` has an `X.tsv` (`namespace key type length
//! hex`, what ESP-IDF's own parser and C++ engine must read from it). `NVS_REGEN_FIXTURES=1 cargo test -p tdongle-nvs-write --test fixtures`
//! rewrites them; the committed files are also what `tools/verify_with_idf.py tests/fixtures` checks.
mod common;

use std::path::{Path, PathBuf};

use common::harness::*;
use common::*;
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_write::{Nvs, SimFlash, Store, Tear};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// (name, image, whether it is a clean image that ESP-IDF's integrity checker must accept)
fn images() -> Vec<(&'static str, Vec<u8>, bool)> {
    let mut out = Vec::new();
    // 1. a device as the firmware leaves it: list, metadata, display, mode, the v0.1.1 blob, members, a tailnet identity
    out.push(("rust_board", board().into_nvs().into_flash().data, true));
    // 2. a 4-page partition after 60 saves: pages compacted over and over, one spare page always kept
    {
        let mut s = Store::mount(SimFlash::new(4 * 4096), 4 * 4096).unwrap();
        for i in 0..60u8 {
            let (l, m) = list(1 + usize::from(i) % 8, i);
            s.save_profiles(&l, &m).unwrap();
            if i % 7 == 0 {
                s.save_display(&UiSettings { brightness: 10 + i, rotation: i % 2, dim_seconds: 60 + u16::from(i) }).unwrap();
            }
        }
        s.save_mode(Mode::TailnetGateway).unwrap();
        out.push(("rust_gc_4_pages", s.into_nvs().into_flash().data, true));
    }
    // 3. a blob that spans three pages of a 6-page partition, replaced once (version 0 chunks, then version 1)
    {
        let mut nvs = Nvs::open(SimFlash::new(6 * 4096), 6 * 4096).unwrap();
        nvs.set_blob("tailnet", "directory", &pattern(9000, 1)).unwrap();
        nvs.set_u8("tailnet", "n", 3).unwrap();
        nvs.set_blob("tailnet", "directory", &pattern(9500, 2)).unwrap();
        out.push(("rust_multipage_6_pages", nvs.into_flash().data, true));
    }
    // 4. the power went out after the new chunk of `display` was complete and before its index: the old value must still be there
    {
        let mut s = board();
        let before = s.nvs().flash().spent;
        s.nvs().flash_mut().arm(72, Tear::Prefix);
        let _ = s.save_display(&UiSettings { brightness: 100, rotation: 0, dim_seconds: 10 });
        assert!(s.nvs().flash().spent > before);
        out.push(("rust_cut_before_index", s.nvs().flash().data.clone(), false));
    }
    out
}

/// What a cold start must find: the dump of the image after this crate's mount.
fn expected(image: &[u8]) -> Dump {
    dump_image(image)
}

#[test]
fn committed_images_are_what_the_writer_produces() {
    let regen = std::env::var_os("NVS_REGEN_FIXTURES").is_some();
    for (name, image, _) in images() {
        let bin = dir().join(format!("{name}.bin"));
        let tsv_path = dir().join(format!("{name}.tsv"));
        if regen {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&bin, &image).unwrap();
            std::fs::write(&tsv_path, tsv(&expected(&image))).unwrap();
            continue;
        }
        let committed =
            std::fs::read(&bin).unwrap_or_else(|_| panic!("{name}: missing; run NVS_REGEN_FIXTURES=1 cargo test -p tdongle-nvs-write --test fixtures"));
        assert!(committed == image, "{name}: the writer now produces different bytes (NVS_REGEN_FIXTURES=1 rewrites the fixtures if that is intended)");
        assert_eq!(std::fs::read_to_string(&tsv_path).unwrap(), tsv(&expected(&image)), "{name}: key/values changed");
    }
}

#[test]
fn committed_images_are_accepted_by_esp_idf() {
    for (name, _, clean) in images() {
        let image = std::fs::read(dir().join(format!("{name}.bin"))).unwrap_or_default();
        if image.is_empty() {
            continue; // being regenerated
        }
        let want = expected(&image);
        // this crate's mount, the read-only parser, and ESP-IDF's python tools and C++ engine all agree (the crash image only after the repair)
        assert_same(name, &dump_image(&image), &want);
        if clean {
            let mut nvs = Nvs::open(SimFlash::from_image(image.clone()), image.len() as u32).unwrap();
            assert_eq!(nvs.flash().spent, 0, "{name}: a clean image must mount without writing");
            let bad = check_with_reader(&image, &want);
            assert!(bad.is_empty(), "{name}: {bad:?}");
            let _ = nvs.stats().unwrap();
            verify_with_idf(&format!("fixture_{name}"), &image, &want, true);
        } else {
            let mut nvs = Nvs::open(SimFlash::from_image(image.clone()), image.len() as u32).unwrap();
            let repaired = nvs.flash().data.clone();
            let _ = nvs.scrub();
            let bad = check_with_reader(&repaired, &want);
            assert!(bad.is_empty(), "{name}: {bad:?}");
            verify_with_idf(&format!("fixture_{name}_repaired"), &nvs.flash().data.clone(), &want, true);
        }
    }
}

/// A characterisation of ESP-IDF, not of this crate: its own mount of the raw cut image (power lost after a chunk, before the index)
/// destroys the key, because of the "check that last item is not duplicate" quirk described at `idf_hazard`. This crate's mount does not.
/// If a later ESP-IDF fixes the quirk this test says so.
#[test]
fn esp_idfs_own_mount_of_the_cut_image_has_a_known_quirk_this_crates_mount_does_not() {
    let image = std::fs::read(dir().join("rust_cut_before_index.bin")).unwrap_or_default();
    if image.is_empty() {
        return;
    }
    let want = expected(&image);
    let key = ("tn_settings".to_string(), "display".to_string());
    assert_eq!(idf_hazard(&image), vec![key.clone()]);
    assert!(want.contains_key(&key), "this crate's mount keeps the old display settings");
    let Some(runs) = idf_c_run(&[image], false) else { return };
    let r = &runs[0];
    assert_eq!(r.mount, 0);
    let mut others = want.clone();
    others.remove(&key);
    let mut got = r.rows.clone();
    let idf_display = got.remove(&key);
    assert_same("ESP-IDF's view of every other key", &got, &others);
    assert_eq!(idf_display, None, "ESP-IDF lost `display` (if this fails, ESP-IDF fixed its mount: drop `idf_hazard` and its allowances)");
}
