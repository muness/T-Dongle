//! Basic behaviour of the engine on a fresh image, cross-checked with `tdongle-nvs-read`.
use tdongle_nvs_read::{Nvs as Reader, SliceFlash};
use tdongle_nvs_write::{Error, Nvs, SimFlash};

const SIZE: u32 = 0x10000;

fn fresh() -> Nvs<SimFlash> {
    Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap()
}

fn reader(nvs: &Nvs<SimFlash>) -> Reader<SliceFlash<'_>> {
    Reader::new(SliceFlash(&nvs.flash().data), SIZE)
}

fn pattern(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
            (x >> 16) as u8
        })
        .collect()
}

#[test]
fn fresh_partition_mounts_and_is_empty() {
    let mut nvs = fresh();
    assert_eq!(nvs.get_u8("a", "b").unwrap(), None);
    let s = nvs.stats().unwrap();
    assert_eq!((s.pages, s.free_pages, s.used_entries), (16, 15, 0));
}

#[test]
fn primitives_round_trip_and_read_back_with_the_reader() {
    let mut nvs = fresh();
    nvs.set_u8("tn_settings", "mode", 1).unwrap();
    nvs.set_u32("tn_settings", "big", 0xdead_beef).unwrap();
    nvs.set_i32("other", "neg", -5).unwrap();
    assert_eq!(nvs.get_u8("tn_settings", "mode").unwrap(), Some(1));
    assert_eq!(nvs.get_u32("tn_settings", "big").unwrap(), Some(0xdead_beef));
    assert_eq!(nvs.get_i32("other", "neg").unwrap(), Some(-5));
    assert_eq!(nvs.get_u8("tn_settings", "big"), Err(Error::TypeMismatch));
    let mut r = reader(&nvs);
    assert_eq!(r.get_u8("tn_settings", "mode").unwrap(), Some(1));
    assert_eq!(r.get_u8("other", "neg"), Err(tdongle_nvs_read::Error::TypeMismatch));
}

#[test]
fn updating_a_key_replaces_it_and_same_value_writes_nothing() {
    let mut nvs = fresh();
    nvs.set_u8("n", "k", 1).unwrap();
    let before = nvs.flash().spent;
    nvs.set_u8("n", "k", 1).unwrap();
    assert_eq!(nvs.flash().spent, before, "an equal value must not touch the flash");
    nvs.set_u8("n", "k", 2).unwrap();
    assert_eq!(nvs.get_u8("n", "k").unwrap(), Some(2));
    assert_eq!(reader(&nvs).get_u8("n", "k").unwrap(), Some(2));
    // the type can change too
    nvs.set_str("n", "k", "now a string").unwrap();
    let mut out = [0u8; 40];
    assert_eq!(nvs.get_str("n", "k", &mut out).unwrap(), Some(12));
    assert_eq!(&out[..12], b"now a string");
    assert_eq!(nvs.get_u8("n", "k"), Err(Error::TypeMismatch));
    assert!(reader(&nvs).has_str("n", "k").unwrap());
}

#[test]
fn blobs_of_every_size_round_trip_through_both_readers() {
    let mut nvs = fresh();
    for (i, len) in [0usize, 1, 31, 32, 33, 784, 3999, 4000, 4001, 8000, 12345, 40000].into_iter().enumerate() {
        let data = pattern(len, i as u32);
        let key = format!("b{i}");
        nvs.set_blob("big", &key, &data).unwrap();
        let mut out = vec![0u8; len];
        assert_eq!(nvs.get_blob("big", &key, &mut out).unwrap(), Some(len), "len {len}");
        assert_eq!(out, data, "len {len}");
        let mut r = reader(&nvs);
        assert_eq!(r.blob_len("big", &key).unwrap(), Some(len));
        let mut out2 = vec![0u8; len];
        assert_eq!(r.get_blob("big", &key, &mut out2).unwrap(), Some(len));
        assert_eq!(out2, data, "reader, len {len}");
        // free the space again so the next size fits
        nvs.erase_key("big", &key).unwrap();
        assert_eq!(nvs.get_blob("big", &key, &mut out).unwrap(), None);
    }
    assert_eq!(nvs.flash().violations, 0);
    assert_eq!(nvs.flash().misaligned, 0);
}

#[test]
fn blob_larger_than_the_partition_is_refused() {
    let mut nvs = fresh();
    let data = vec![7u8; 15 * 4000 + 1];
    assert_eq!(nvs.set_blob("n", "k", &data), Err(Error::ValueTooLong));
    nvs.set_blob("n", "k", &data[..15 * 4000 - 3000]).unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn erase_key_and_namespace() {
    let mut nvs = fresh();
    nvs.set_u8("a", "x", 1).unwrap();
    nvs.set_blob("a", "blob", &pattern(5000, 3)).unwrap();
    nvs.set_u8("b", "x", 2).unwrap();
    nvs.erase_key("a", "x").unwrap();
    assert_eq!(nvs.erase_key("a", "x"), Err(Error::NotFound));
    assert_eq!(nvs.get_u8("a", "x").unwrap(), None);
    nvs.erase_namespace("a").unwrap();
    assert_eq!(nvs.value_len("a", "blob").unwrap(), None);
    assert_eq!(nvs.get_u8("b", "x").unwrap(), Some(2));
    assert_eq!(reader(&nvs).blob_len("a", "blob").unwrap(), None);
    // the namespace is still there and can be reused
    nvs.set_u8("a", "x", 9).unwrap();
    assert_eq!(nvs.get_u8("a", "x").unwrap(), Some(9));
}

#[test]
fn remount_sees_the_same_data() {
    let mut nvs = fresh();
    nvs.set_blob("tn_settings", "wifi_profiles", &pattern(784, 1)).unwrap();
    nvs.set_str("tn_settings", "members", "alice,bob").unwrap();
    nvs.set_u8("tn_settings", "mode", 1).unwrap();
    let flash = nvs.into_flash();
    let mut again = Nvs::open(flash, SIZE).unwrap();
    let mut out = [0u8; 784];
    assert_eq!(again.get_blob("tn_settings", "wifi_profiles", &mut out).unwrap(), Some(784));
    assert_eq!(&out[..], &pattern(784, 1)[..]);
    assert_eq!(again.get_u8("tn_settings", "mode").unwrap(), Some(1));
}

#[test]
fn bad_names_are_refused() {
    let mut nvs = fresh();
    assert_eq!(nvs.set_u8("n", "", 1), Err(Error::InvalidKey));
    assert_eq!(nvs.set_u8("n", "0123456789abcdef", 1), Err(Error::InvalidKey));
    nvs.set_u8("n", "0123456789abcde", 1).unwrap();
    assert_eq!(nvs.set_u8("0123456789abcdef", "k", 1), Err(Error::InvalidKey));
}
