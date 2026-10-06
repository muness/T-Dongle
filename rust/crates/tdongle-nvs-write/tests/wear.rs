//! Wear and compaction: thousands of save cycles never corrupt the partition, never exhaust its pages, spread the erases over all
//! sectors, and a full partition refuses a write cleanly.
mod common;

use common::*;
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_meta::MetaSet;
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedProfile};
use tdongle_nvs_write::{Error, Nvs, SimFlash, Store};

fn list(n: usize, tag: u32) -> (SavedNetworks, MetaSet) {
    let mut saved = SavedNetworks::default();
    for i in 0..n {
        let mut p = SavedProfile::EMPTY;
        let ssid = format!("N{tag}-{i}");
        let pw = format!("pw{tag}{i}");
        p.ssid[..ssid.len()].copy_from_slice(ssid.as_bytes());
        p.password[..pw.len()].copy_from_slice(pw.as_bytes());
        saved.profiles[i] = p;
    }
    saved.count = n;
    let mut meta = MetaSet::defaults(&saved.ssids()[..n]);
    meta.preferred = (n > 0).then(|| (tag as usize) % n);
    if n > 0 {
        meta.slot[0].priority = (tag % 101) as u8;
    }
    (saved, meta)
}

#[test]
fn ten_thousand_save_cycles_stay_consistent_and_wear_evenly() {
    let mut store = Store::mount(SimFlash::new(SIZE as usize), SIZE).unwrap();
    store.nvs().set_str("tn_settings", "members", "alice,bob,carol").unwrap();
    store.nvs().set_blob("tailnet", "identity", &pattern(300, 1)).unwrap();
    store.nvs().set_blob("adapter", "config", &pattern(1004, 2)).unwrap();
    let fixed: Dump = dump(store.nvs());
    let mut rng = XorShift(0x5eed);
    let mut last: Option<(SavedNetworks, MetaSet)> = None;
    let mut mode = Mode::WifiBridge;
    for i in 0..10_000u32 {
        match rng.below(10) {
            0..=5 => {
                let (l, m) = list(rng.below(9) as usize, i);
                store.save_profiles(&l, &m).unwrap_or_else(|e| panic!("cycle {i}: {e:?}"));
                last = Some((l, m));
            }
            6 | 7 => {
                let display = UiSettings { brightness: 5 + rng.below(96) as u8, rotation: rng.below(2) as u8, dim_seconds: 10 + rng.below(3000) as u16 };
                store.save_display(&display).unwrap();
            }
            8 => {
                mode = if rng.below(2) == 0 { Mode::WifiBridge } else { Mode::TailnetGateway };
                store.save_mode(mode).unwrap();
            }
            _ => {
                // a reboot
                let flash = store.into_nvs().into_flash();
                store = Store::mount(flash, SIZE).unwrap_or_else(|e| panic!("cycle {i}: remount {e:?}"));
            }
        }
        let s = store.nvs().stats().unwrap();
        assert!(s.free_pages >= 1, "cycle {i}: no spare page left");
        if i % 250 == 0 || i == 9_999 {
            let loaded = store.load_all().unwrap_or_else(|e| panic!("cycle {i}: {e:?}"));
            if let Some((l, m)) = &last {
                assert_eq!(loaded.networks.saved, *l, "cycle {i}");
                assert_eq!(loaded.networks.meta.preferred, m.preferred, "cycle {i}");
            }
            if i > 100 {
                assert_eq!(loaded.mode.ok().map(|m| m.to_u8()).unwrap_or(9), mode.to_u8(), "cycle {i}");
            }
            let d = dump(store.nvs());
            for (k, v) in &fixed {
                assert_eq!(d.get(k), Some(v), "cycle {i}: {k:?} changed");
            }
        }
    }
    let image = store.nvs().flash().data.clone();
    let erases = store.nvs().flash().sector_erases.clone();
    let total: u32 = erases.iter().sum();
    // Pages holding data that never changes are never moved (no static wear levelling, as in IDF): at most the pages of the three
    // static keys. All the others take the erases in turn.
    let static_pages = erases.iter().filter(|&&e| e == 0).count();
    assert!(static_pages <= 2, "{erases:?}");
    let cycling: Vec<u32> = erases.iter().copied().filter(|&e| e > 0).collect();
    let (min, max) = (*cycling.iter().min().unwrap(), *cycling.iter().max().unwrap());
    eprintln!("10000 cycles: {total} sector erases over 16 sectors, min {min} max {max}");
    assert!(total > 100, "compaction must have run");
    assert!(max - min <= 5, "wear is uneven: {erases:?}");
    assert_eq!(store.nvs().flash().violations, 0);
    let d = dump(store.nvs());
    verify_with_idf("wear_10000", &image, &d, true);
}

#[test]
fn a_full_partition_refuses_cleanly_and_recovers_when_space_is_freed() {
    let mut nvs = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
    let mut model = Dump::new();
    let mut n = 0;
    // fill with 3 KB blobs until the engine says no
    let err = loop {
        let data = pattern(3000, n);
        let key = format!("blob{n}");
        match nvs.set_blob("fill", &key, &data) {
            Ok(()) => {
                model.insert(("fill".into(), key), ("blob".into(), data));
                n += 1;
            }
            Err(e) => break e,
        }
        assert!(n < 100);
    };
    assert_eq!(err, Error::NoSpace);
    assert!(n >= 14, "only {n} blobs fit");
    // nothing was damaged by the refusal
    assert_same("after the refusal", &dump(&mut nvs), &model);
    let image = nvs.flash().data.clone();
    assert!(check_with_reader(&image, &model).is_empty());
    // replacing an existing value with a same-size one may need the space it frees: either it works or it fails cleanly
    let r = nvs.set_blob("fill", "blob0", &pattern(3000, 999));
    if r.is_ok() {
        model.insert(("fill".into(), "blob0".into()), ("blob".into(), pattern(3000, 999)));
    }
    assert_same("after the replace attempt", &dump(&mut nvs), &model);
    // free two blobs, and writes work again
    for k in ["blob1", "blob2"] {
        nvs.erase_key("fill", k).unwrap();
        model.remove(&("fill".to_string(), k.to_string()));
    }
    nvs.set_blob("fill", "again", &pattern(3000, 5)).unwrap();
    model.insert(("fill".into(), "again".into()), ("blob".into(), pattern(3000, 5)));
    assert_same("after freeing", &dump(&mut nvs), &model);
    // and a remount keeps all of it
    let flash = nvs.into_flash();
    let mut again = Nvs::open(flash, SIZE).unwrap();
    assert_same("after remount", &dump(&mut again), &model);
    assert_eq!(again.flash().violations, 0);
}

#[test]
fn one_value_rewritten_forever_compacts_in_place() {
    let mut nvs = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
    for i in 0..3000u32 {
        nvs.set_u32("n", "counter", i).unwrap();
        nvs.set_blob("n", "blob", &pattern(100, i)).unwrap();
        if i % 500 == 0 {
            let flash = nvs.into_flash();
            nvs = Nvs::open(flash, SIZE).unwrap();
        }
    }
    assert_eq!(nvs.get_u32("n", "counter").unwrap(), Some(2999));
    let mut b = vec![0u8; 100];
    nvs.get_blob("n", "blob", &mut b).unwrap();
    assert_eq!(b, pattern(100, 2999));
    let used = nvs.stats().unwrap();
    assert!(used.used_entries < 20, "{used:?}");
}
