//! Images written by the engine, parsed by ESP-IDF's own tooling (`tools/verify_with_idf.py`: `nvs_parser.py` + `nvs_check.py`) and by
//! `tdongle-nvs-read`; and images made by ESP-IDF's `nvs_partition_gen.py` (fixtures of `tdongle-nvs-read`), modified by the engine and
//! parsed again. Without IDF's python environment the IDF half is skipped (`TDONGLE_REQUIRE_IDF=1` makes that a failure).
mod common;

use common::*;
use tdongle_nvs_write::{Nvs, SimFlash};

fn fresh() -> Nvs<SimFlash> {
    Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap()
}

/// Run `ops` on `nvs` and the model; after every `every` operations (and at the end) compare engine, model, reader and IDF.
fn run(name: &str, nvs: &mut Nvs<SimFlash>, model: &mut Dump, ops: &[Op], every: usize) {
    for (i, op) in ops.iter().enumerate() {
        apply(nvs, op).unwrap_or_else(|e| panic!("{name} op {i} {op:?}: {e:?}"));
        apply_model(model, op);
        if (i + 1) % every == 0 || i + 1 == ops.len() {
            let got = dump(nvs);
            assert_same(&format!("{name} after op {i}"), &got, model);
            let image = nvs.flash().data.clone();
            let bad = check_with_reader(&image, model);
            assert!(bad.is_empty(), "{name} after op {i}: {bad:?}");
            verify_with_idf(&format!("{name}_{i:03}"), &image, model, true);
        }
    }
    assert_eq!(nvs.flash().violations, 0, "a write tried to set a bit");
    assert_eq!(nvs.flash().misaligned, 0);
}

#[test]
fn firmware_keys_from_scratch() {
    let mut nvs = fresh();
    let mut model = Dump::new();
    let ops = vec![
        Op::U8("tn_settings", "mode", 1),
        Op::Str("tn_settings", "members", "alice,bob,carol".into()),
        Op::Blob("tn_settings", "wifi_profiles", pattern(784, 1)),
        Op::Blob("tn_settings", "wifi_meta", pattern(516, 2)),
        Op::Blob("tn_settings", "display", pattern(8, 3)),
        Op::Blob("adapter", "config", pattern(1004, 4)),
        Op::Blob("tn_settings", "wifi_profiles", pattern(784, 5)),
        Op::Blob("tn_settings", "wifi_meta", pattern(516, 6)),
        Op::U8("tn_settings", "mode", 0),
        Op::Erase("tn_settings", "wifi_profiles"),
        Op::Erase("tn_settings", "wifi_meta"),
        Op::Erase("tn_settings", "display"),
        Op::EraseNs("adapter"),
        Op::U32("other", "counter", 7),
        Op::I32("other", "neg", -123456),
    ];
    run("scratch", &mut nvs, &mut model, &ops, 1);
}

#[test]
fn multi_page_blobs_and_version_toggle() {
    let mut nvs = fresh();
    let mut model = Dump::new();
    let mut ops = Vec::new();
    for (i, len) in [100usize, 4001, 5000, 8000, 3999, 4000, 12000, 784, 20000, 6000].into_iter().enumerate() {
        ops.push(Op::Blob("big", "blob", pattern(len, i as u32)));
        ops.push(Op::Blob("big", "other", pattern(len / 2 + 1, 99 + i as u32)));
    }
    ops.push(Op::Erase("big", "blob"));
    ops.push(Op::Blob("big", "blob", pattern(30000, 7)));
    run("multipage", &mut nvs, &mut model, &ops, 1);
}

#[test]
fn many_small_keys_and_strings() {
    let mut nvs = fresh();
    let mut model = Dump::new();
    let mut ops = Vec::new();
    for i in 0..150 {
        ops.push(Op::U32("many", Box::leak(format!("k{i}").into_boxed_str()), i * 65537));
        if i % 7 == 0 {
            ops.push(Op::Str("many", Box::leak(format!("s{i}").into_boxed_str()), format!("value {i} {}", "z".repeat((i as usize * 13) % 120))));
        }
    }
    for i in 0..150 {
        if i % 3 == 0 {
            ops.push(Op::Erase("many", Box::leak(format!("k{i}").into_boxed_str())));
        }
    }
    run("many", &mut nvs, &mut model, &ops, 40);
}

#[test]
fn a_long_string_and_type_changes() {
    let mut nvs = fresh();
    let mut model = Dump::new();
    let ops = vec![
        Op::Str("s", "long", "q".repeat(3999)),
        Op::Str("s", "long", "r".repeat(100)),
        Op::U8("s", "long", 5),
        Op::Blob("s", "long", pattern(5000, 1)),
        Op::Str("s", "long", "back to a string".into()),
        Op::Str("s", "mid", "m".repeat(70)),
        Op::Str("s", "mid", "m".repeat(70)),
        Op::Str("s", "mid", "n".repeat(200)),
    ];
    run("strings", &mut nvs, &mut model, &ops, 1);
}

/// Wear: thousands of updates compact pages many times; IDF must still accept the image at the end (and at intervals).
#[test]
fn heavily_rewritten_image_is_accepted_by_idf() {
    let mut nvs = fresh();
    let mut model = Dump::new();
    let mut ops = Vec::new();
    for i in 0..600u32 {
        ops.push(Op::Blob("tn_settings", "wifi_profiles", pattern(784, i)));
        ops.push(Op::Blob("tn_settings", "wifi_meta", pattern(516, i + 1000)));
        if i % 5 == 0 {
            ops.push(Op::U8("tn_settings", "mode", (i % 2) as u8));
        }
    }
    run("worn", &mut nvs, &mut model, &ops, 400);
    assert!(nvs.flash().erases > 20, "the sequence should have compacted pages, erases: {}", nvs.flash().erases);
}

// ---- the other direction: images made by nvs_partition_gen.py, modified by the engine -----------------------------------------------

macro_rules! fixture {
    ($n:literal) => {
        (
            include_bytes!(concat!("../../tdongle-nvs-read/tests/fixtures/", $n, ".bin")).to_vec(),
            include_str!(concat!("../../tdongle-nvs-read/tests/fixtures/", $n, ".expected")),
        )
    };
}

fn modify_generated(name: &str, (image, expected): (Vec<u8>, &str), ops: Vec<Op>) {
    let mut nvs = Nvs::open(SimFlash::from_image(image.clone()), image.len() as u32).unwrap_or_else(|e| panic!("{name}: mount {e:?}"));
    let mut model = parse_expected(expected);
    // The engine sees the generated image exactly as the generator's own parser did.
    assert_same(&format!("{name} initial"), &dump(&mut nvs), &model);
    run(&format!("gen_{name}"), &mut nvs, &mut model, &ops, 1);
    // and the untouched keys are still readable with the read-only parser
}

#[test]
fn generated_main_v2_modified() {
    modify_generated(
        "main_v2",
        fixture!("main_v2"),
        vec![
            Op::U8("tn_settings", "mode", 0),
            Op::Blob("tn_settings", "wifi_profiles", pattern(784, 9)),
            Op::Str("tn_settings", "members", "x".into()),
            Op::Erase("tn_settings", "display"),
            Op::Blob("adapter", "config", pattern(1004, 3)),
            Op::U32("tn_settings", "new_key", 1),
            Op::Erase("tn_settings", "wifi_meta"),
        ],
    );
}

#[test]
fn generated_main_v1_old_pages_modified() {
    modify_generated(
        "main_v1",
        fixture!("main_v1"),
        vec![
            Op::Blob("tn_settings", "wifi_profiles", pattern(784, 10)),
            Op::Blob("tn_settings", "wifi_meta", pattern(516, 11)),
            Op::U8("tn_settings", "mode", 1),
            Op::Erase("adapter", "config"),
        ],
    );
}

#[test]
fn generated_big_v2_modified() {
    modify_generated(
        "big_v2",
        fixture!("big_v2"),
        vec![
            Op::Blob("big", "blob6000", pattern(6500, 1)),
            Op::Erase("big", "blob8000"),
            Op::Blob("big", "blob4000", pattern(100, 2)),
            Op::Blob("big", "blob8000", pattern(9000, 3)),
            Op::EraseNs("big"),
            Op::Blob("tn_settings", "wifi_profiles", pattern(784, 12)),
        ],
    );
}

#[test]
fn generated_many_and_prims_modified() {
    modify_generated(
        "many_v2",
        fixture!("many_v2"),
        vec![Op::U32("many", "k1", 99), Op::Erase("many", "k2"), Op::Blob("second", "b", pattern(1500, 4)), Op::Str("many", "s10", "short".into())],
    );
    modify_generated(
        "prims",
        fixture!("prims"),
        vec![Op::U8("prims", "u8", 1), Op::I32("prims", "i32", -1), Op::Str("prims", "str", "z".into()), Op::U32("prims", "u32", 5)],
    );
}

#[test]
fn generated_board_images_are_accepted_unchanged_by_mount_and_idf() {
    // Images with a few namespaces (the board images of the reader's fixtures) and a one-page image padded to a three-page partition.
    // (The generator's `overwrite_*` fixtures hold the same blob key twice with equal chunk indices, a state ESP-IDF's own mount
    // resolves by erasing the key, so they are not a valid starting point for a writer.)
    for (name, (mut image, expected)) in
        [("board_v03", fixture!("board_v03")), ("board_v01", fixture!("board_v01")), ("tiny_v2", fixture!("tiny_v2")), ("main_v2", fixture!("main_v2"))]
    {
        image.resize(image.len().max(3 * 4096), 0xff);
        let model = parse_expected(expected);
        let mut nvs = Nvs::open(SimFlash::from_image(image.clone()), image.len() as u32).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_same(name, &dump(&mut nvs), &model);
        assert_eq!(nvs.flash().spent, 0, "{name}: mounting a clean image must not write");
        verify_with_idf(&format!("mounted_{name}"), &nvs.flash().data.clone(), &model, true);
    }
}
