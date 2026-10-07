//! The power-loss model. Every operation sequence the firmware performs is run with the flash failing after N units of programming for
//! every N (one unit per byte written, 4096 per sector erased), under two tear models (a clean prefix; a half-programmed last byte and a
//! half-erased sector with stray bits). The image the power cut leaves is then checked:
//!
//! 1. the read-only parser (no repair) sees, for every key, the value from before or the value from after the operation in progress,
//!    never an error and never a third value, and no key the operation did not touch changes;
//! 2. the engine mounts it (repairing it), and sees the same (and for keys written two at a time, only the combinations the C allows);
//! 3. the mounted image is still a working partition: running the whole sequence again reaches exactly the final state;
//! 4. a power cut *during* that mounting repair also leaves a mountable image with the same content;
//! 5. a sample of the repaired images is accepted by ESP-IDF's own parser and integrity checker.
mod common;

use common::harness::*;
use common::*;
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;

// ---- the scenarios --------------------------------------------------------------------------------------------------------------------

#[test]
fn save_profiles_two_saves() {
    sweep(
        Scenario {
            name: "save_profiles",
            base: board().into_nvs().into_flash().data,
            steps: vec![save(4, 2), save(2, 3)],
            pair: Some(("tn_settings", "wifi_meta", "wifi_profiles")),
            rerun: true,
            churn: 17,
        },
        1,
    );
}

#[test]
fn save_profiles_on_a_fresh_partition() {
    sweep(
        Scenario {
            name: "save_fresh",
            base: fresh_store().into_nvs().into_flash().data,
            steps: vec![save(1, 1), save(8, 2)],
            pair: Some(("tn_settings", "wifi_meta", "wifi_profiles")),
            rerun: true,
            churn: 17,
        },
        1,
    );
}

#[test]
fn display_and_mode() {
    let steps: Vec<Step> = vec![
        Box::new(|s: &mut St| s.save_display(&UiSettings { brightness: 100, rotation: 0, dim_seconds: 10 })),
        Box::new(|s: &mut St| s.save_mode(Mode::WifiBridge)),
        Box::new(|s: &mut St| s.save_display(&UiSettings { brightness: 5, rotation: 1, dim_seconds: 3600 })),
    ];
    sweep(Scenario { name: "display_mode", base: board().into_nvs().into_flash().data, steps, pair: None, rerun: true, churn: 17 }, 1);
}

#[test]
fn factory_reset() {
    let steps: Vec<Step> = vec![Box::new(|s: &mut St| s.factory_reset())];
    sweep(Scenario { name: "factory_reset", base: board().into_nvs().into_flash().data, steps, pair: None, rerun: true, churn: 17 }, 1);
}

#[test]
fn import_legacy() {
    let mut s = fresh_store();
    s.nvs().set_blob("adapter", "config", &legacy_blob()).unwrap();
    let mut single = vec![0u8; 184];
    single[..6].copy_from_slice(b"217IoT");
    single[32..32 + 8].copy_from_slice(b"iotpass!");
    s.nvs().set_blob("tn_settings", "wifi", &single).unwrap();
    let steps: Vec<Step> = vec![Box::new(|s: &mut St| {
        s.import_legacy().map(|_| ()).map_err(|e| match e {
            tdongle_nvs_write::LoadError::Storage(e) => e,
            other => panic!("{other:?}"),
        })
    })];
    sweep(
        Scenario {
            name: "import_legacy",
            base: s.into_nvs().into_flash().data,
            steps,
            pair: Some(("tn_settings", "wifi_meta", "wifi_profiles")),
            rerun: true,
            churn: 17,
        },
        1,
    );
}

#[test]
fn multi_page_blob_replace_and_strings() {
    let mut s = board();
    s.nvs().set_blob("tailnet", "directory", &pattern(9000, 1)).unwrap();
    let steps: Vec<Step> = vec![
        Box::new(|s: &mut St| s.nvs().set_blob("tailnet", "directory", &pattern(9000, 2))),
        Box::new(|s: &mut St| s.nvs().set_blob("tailnet", "directory", &pattern(4100, 3))),
        Box::new(|s: &mut St| s.nvs().set_str("tn_settings", "members", "carol")),
        Box::new(|s: &mut St| s.nvs().erase_key("tailnet", "directory")),
        Box::new(|s: &mut St| s.nvs().set_str("tn_settings", "long", &"L".repeat(200))),
    ];
    sweep(Scenario { name: "multipage", base: s.into_nvs().into_flash().data, steps, pair: None, rerun: true, churn: 17 }, 3);
}

#[test]
fn erase_namespace() {
    let mut s = board();
    s.nvs().set_blob("adapter", "big", &pattern(6000, 1)).unwrap();
    s.nvs().set_u8("adapter", "n", 1).unwrap();
    let steps: Vec<Step> = vec![Box::new(|s: &mut St| s.nvs().erase_namespace("adapter"))];
    sweep(Scenario { name: "erase_ns", base: s.into_nvs().into_flash().data, steps, pair: None, rerun: true, churn: 17 }, 1);
}

#[test]
fn compaction_during_save_profiles() {
    let base = base_before_compaction(board(), |t| save(1 + (t as usize % 8), t), save(5, 77));
    sweep(Scenario { name: "gc_save", base, steps: vec![save(5, 77)], pair: Some(("tn_settings", "wifi_meta", "wifi_profiles")), rerun: true, churn: 17 }, 5);
}

#[test]
fn compaction_during_a_multi_page_blob() {
    let mut s = board();
    s.nvs().set_blob("tailnet", "directory", &pattern(9000, 1)).unwrap();
    let probe: Step = Box::new(|s: &mut St| s.nvs().set_blob("tailnet", "directory", &pattern(9000, 2)));
    let base = base_before_compaction(s, |t| save(1 + (t as usize % 8), t), probe);
    let steps: Vec<Step> = vec![Box::new(|s: &mut St| s.nvs().set_blob("tailnet", "directory", &pattern(9000, 2)))];
    sweep(Scenario { name: "gc_multipage", base, steps, pair: None, rerun: true, churn: 17 }, 11);
}

#[test]
fn a_key_that_changes_type() {
    // A u8 over a chunked blob and a blob over the u8: after any cut exactly one of the two lives, and the engine's view survives
    // compaction (a duplicate of another type left behind would come back to life when its page is moved).
    let mut s = board();
    s.nvs().set_blob("tn_settings", "shape", &pattern(5000, 1)).unwrap();
    // fill the page the old index is on, so the new item lands on a later page (a duplicate inside one page is a different code path)
    s.nvs().set_blob("tn_settings", "filler", &pattern(3900, 5)).unwrap();
    s.nvs().set_blob("tn_settings", "filler2", &pattern(3900, 6)).unwrap();
    let steps: Vec<Step> = vec![
        Box::new(|s: &mut St| s.nvs().set_u8("tn_settings", "shape", 7)),
        Box::new(|s: &mut St| s.nvs().set_blob("tn_settings", "shape", &pattern(900, 2))),
        Box::new(|s: &mut St| s.nvs().set_str("tn_settings", "shape", "now text")),
        Box::new(|s: &mut St| s.nvs().set_u32("tn_settings", "shape", 99)),
    ];
    sweep(Scenario { name: "type_change", base: s.into_nvs().into_flash().data, steps, pair: None, rerun: true, churn: 1 }, 1);
}
