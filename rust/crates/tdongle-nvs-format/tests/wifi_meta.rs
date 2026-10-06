//! Ports of `tests/test_wifi_meta.c`, plus byte-layout checks.
mod common;
use common::{SSIDS, fixed};
use tdongle_nvs_format::wifi_meta::{
    BLOB_LEN, MetaBlob, MetaBlobError, MetaSet, MetaSlot, NAME_MAX,
};

/// What the firmware does with a stored blob: defaults for the list, the blob laid over them.
fn decode(data: &[u8], ssids: &[&[u8]]) -> Result<MetaSet, MetaBlobError> {
    let mut set = MetaSet::defaults(ssids);
    set.overlay(data, ssids)?;
    Ok(set)
}

fn name(slot: &MetaSlot) -> &[u8] {
    slot.name_bytes()
}

#[test]
fn defaults() {
    let s = MetaSet::defaults(&SSIDS[..3]);
    assert!(s.preferred.is_none() && name(&s.slot[0]) == b"Home" && s.slot[2].priority == 50);
    assert!(name(&s.slot[3]).is_empty() && s.slot[3].priority == 0);
    let long =
        MetaSlot::default_for(b"A very long network name that exceeds twenty-four characters");
    assert_eq!(name(&long), b"A very long network name");
    assert_eq!(name(&long).len(), 24);
    let odd = MetaSlot::default_for(b"caf\xc3\xa9\x01");
    assert_eq!(name(&odd), b"caf???");
    assert!(MetaSlot::name_valid(&odd.name));
}

#[test]
fn name_validity() {
    for ok in [&b"Home"[..], b"a", b"123456789012345678901234", b" ~"] {
        assert!(MetaSlot::name_valid(ok), "{ok:?}");
    }
    for bad in [
        &b""[..],
        b"1234567890123456789012345",
        b"tab\there",
        b"caf\xc3\xa9",
        b"\x7f",
        b"\x1f",
        b"\0abc",
    ] {
        assert!(!MetaSlot::name_valid(bad), "{bad:?}");
    }
    // A name array that fills all 25 bytes has no terminator inside 24 characters: invalid, as in C.
    assert!(!MetaSlot::name_valid(&[b'x'; 25]));
    // Characters after the terminator are not part of the name.
    assert!(MetaSlot::name_valid(b"ok\0\xff\xff"));
}

#[test]
fn default_slot_is_zero_padded() {
    let s = MetaSlot::default_for(b"Home");
    assert_eq!(s.name, fixed::<25>("Home"));
    assert_eq!(MetaSlot::default_for(&[b'z'; 40]).name[24], 0);
}

#[test]
fn round_trip() {
    let mut s = MetaSet::defaults(&SSIDS[..4]);
    s.slot[1].name = fixed("Phone hotspot");
    s.slot[1].priority = 90;
    s.slot[3].priority = 0;
    s.preferred = Some(2);
    let blob = MetaBlob::encode(&SSIDS[..4], &s);
    assert_eq!((blob.schema, blob.count), (1, 4));
    assert_eq!(&blob.preferred_ssid[..7], b"Office\0");
    let out = decode(&blob.to_bytes(), &SSIDS[..4]).unwrap();
    assert_eq!(out.preferred, Some(2));
    assert_eq!(name(&out.slot[1]), b"Phone hotspot");
    assert_eq!(
        (
            out.slot[1].priority,
            out.slot[3].priority,
            out.slot[0].priority
        ),
        (90, 0, 50)
    );
    assert_eq!(out, s);
}

#[test]
fn keyed_by_ssid_not_slot() {
    let mut s = MetaSet::defaults(&SSIDS[..4]);
    for (i, p) in [10, 20, 30, 40].into_iter().enumerate() {
        s.slot[i].priority = p;
    }
    s.preferred = Some(3);
    let bytes = MetaBlob::encode(&SSIDS[..4], &s).to_bytes();
    // The list was edited without the metadata: Home moved to the end, Office was deleted, a newcomer appeared.
    let edited: [&[u8]; 4] = [b"Phone", b"Cafe", b"Home", b"Newcomer"];
    let out = decode(&bytes, &edited).unwrap();
    assert_eq!(
        [
            out.slot[0].priority,
            out.slot[1].priority,
            out.slot[2].priority,
            out.slot[3].priority
        ],
        [20, 40, 10, 50]
    );
    assert_eq!(name(&out.slot[3]), b"Newcomer");
    assert_eq!(out.preferred, Some(1)); // Cafe is still preferred wherever it sits
    let without: [&[u8]; 2] = [b"Phone", b"Home"];
    assert_eq!(decode(&bytes, &without).unwrap().preferred, None); // the preferred network is gone
}

#[test]
fn overlay_keeps_what_the_blob_does_not_name() {
    // The v0.1.x values for three networks; the user then set one priority and made one network preferred (a blob with one entry).
    let list: [&[u8]; 3] = [b"Home", b"Phone", b"Office"];
    let mut old = MetaSet::defaults(&list);
    old.slot[0].priority = 10;
    old.slot[1].priority = 20;
    old.slot[2].priority = 30;
    old.preferred = Some(0);
    old.slot[1].name = fixed("Phone hotspot");
    let only: [&[u8]; 1] = [b"Office"];
    let mut one = MetaSet::defaults(&only);
    one.slot[0].priority = 99;
    one.preferred = Some(0);
    let bytes = MetaBlob::encode(&only, &one).to_bytes();
    let mut out = old;
    out.overlay(&bytes, &list).unwrap();
    assert_eq!((out.slot[0].priority, out.slot[1].priority), (10, 20));
    assert_eq!(name(&out.slot[1]), b"Phone hotspot"); // untouched
    assert_eq!(out.slot[2].priority, 99);
    assert_eq!(out.preferred, Some(2)); // the blob's entry and preference win
    // A blob that says "no preferred network" is the user's choice too: it clears the v0.1.x preference.
    let mut none = MetaSet::defaults(&list);
    none.preferred = None;
    let bytes = MetaBlob::encode(&list, &none).to_bytes();
    let mut out = old;
    out.overlay(&bytes, &list).unwrap();
    assert_eq!((out.preferred, out.slot[0].priority), (None, 50));
    // An invalid blob changes nothing.
    let mut bad = bytes;
    bad[0] = 7;
    let mut out = old;
    assert_eq!(out.overlay(&bad, &list), Err(MetaBlobError::BadSchema));
    assert_eq!(out, old);
}

#[test]
fn removal() {
    let mut s = MetaSet::defaults(&SSIDS[..4]);
    for (i, slot) in s.slot.iter_mut().take(4).enumerate() {
        slot.priority = 10 * (i as u8 + 1);
    }
    s.preferred = Some(2);
    s.remove(4, 0); // before the preferred one: it moves up and stays preferred
    assert_eq!(s.preferred, Some(1));
    assert_eq!(
        [s.slot[0].priority, s.slot[1].priority, s.slot[2].priority],
        [20, 30, 40]
    );
    assert!(name(&s.slot[3]).is_empty() && s.slot[3].priority == 0);
    s.remove(3, 2); // after it: untouched
    assert_eq!(s.preferred, Some(1));
    assert_eq!(s.slot[2].priority, 0);
    s.remove(2, 1); // the preferred one: forgotten
    assert_eq!(s.preferred, None);
    assert_eq!((s.slot[0].priority, s.slot[1].priority), (20, 0));
    let before = s;
    s.remove(1, 1);
    s.remove(9, 0); // out of range: nothing
    assert_eq!(s, before);
}

#[test]
fn hostile_blobs() {
    let s = MetaSet::defaults(&SSIDS[..2]);
    let good = MetaBlob::encode(&SSIDS[..2], &s).to_bytes();
    let list = &SSIDS[..2];
    let with = |f: &dyn Fn(&mut [u8; BLOB_LEN])| {
        let mut b = good;
        f(&mut b);
        decode(&b, list)
    };
    assert_eq!(with(&|b| b[0] = 2), Err(MetaBlobError::BadSchema));
    assert_eq!(with(&|b| b[4] = 9), Err(MetaBlobError::BadCount));
    assert_eq!(
        with(&|b| b[4..8].copy_from_slice(&0x1_0000u32.to_le_bytes())),
        Err(MetaBlobError::BadCount)
    );
    assert_eq!(with(&|b| b[41 + 58] = 101), Err(MetaBlobError::BadPriority));
    assert_eq!(
        with(&|b| b[41 + 59 + 33..41 + 59 + 58].fill(b'x')),
        Err(MetaBlobError::Unterminated)
    ); // name of entry 1
    assert_eq!(
        with(&|b| b[41 + 59..41 + 59 + 33].fill(b'x')),
        Err(MetaBlobError::Unterminated)
    ); // ssid of entry 1
    assert_eq!(
        with(&|b| b[8..41].fill(b'x')),
        Err(MetaBlobError::Unterminated)
    ); // preferred ssid
    assert_eq!(
        decode(&good[..BLOB_LEN - 1], list),
        Err(MetaBlobError::WrongSize)
    );
    assert_eq!(
        decode(&[good.as_slice(), &[0]].concat(), list),
        Err(MetaBlobError::WrongSize)
    );
    assert_eq!(decode(&[], list), Err(MetaBlobError::WrongSize));
    let nine: [&[u8]; 9] = [b"a"; 9];
    assert_eq!(decode(&good, &nine), Err(MetaBlobError::WrongSize)); // count > WIFI_META_SLOTS
    // Entries beyond count are not looked at, and neither are bytes after a terminator.
    assert!(with(&|b| b[41 + 5 * 59..41 + 6 * 59].fill(0xAA)).is_ok());
    // An invalid stored name only costs that network its name.
    let out = with(&|b| {
        b[41 + 33..41 + 33 + 8].copy_from_slice(b"bad\tname");
        b[41 + 58] = 77;
    })
    .unwrap();
    assert_eq!(
        (name(&out.slot[0]), out.slot[0].priority),
        (&b"Home"[..], 77)
    );
    // Eight networks and a preferred one at the last slot.
    let mut set = MetaSet::defaults(&SSIDS);
    set.preferred = Some(7);
    let blob = MetaBlob::encode(&SSIDS, &set);
    assert_eq!(blob.count, 8);
    assert_eq!(&blob.preferred_ssid[..5], b"Shed\0");
    // More than eight SSIDs are clipped, a preferred index beyond the count is dropped.
    let nine: [&[u8]; 9] = [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i"];
    let mut set = MetaSet::defaults(&nine);
    set.preferred = Some(8);
    let blob = MetaBlob::encode(&nine, &set);
    assert_eq!(blob.count, 8);
    assert_eq!(blob.preferred_ssid, [0; 33]);
}

#[test]
fn name_is_cut_at_24_and_ssid_at_32() {
    let ssid = [b's'; 40];
    let list: [&[u8]; 1] = [&ssid];
    let mut set = MetaSet::defaults(&list);
    set.slot[0].name = [b'n'; 25]; // a (corrupt) unterminated in-memory name
    set.preferred = Some(0);
    let blob = MetaBlob::encode(&list, &set);
    assert_eq!(blob.entry[0].ssid[..32], [b's'; 32]);
    assert_eq!(blob.entry[0].ssid[32], 0);
    assert_eq!(blob.entry[0].name[..24], [b'n'; 24]);
    assert_eq!(blob.entry[0].name[24], 0);
    assert_eq!(blob.preferred_ssid[..32], [b's'; 32]);
    assert_eq!(blob.preferred_ssid[32], 0);
    assert_eq!(NAME_MAX, 24);
}

#[test]
fn byte_layout_is_the_c_layout() {
    // sizeof(wifi_meta_blob) == 516; schema@0 count@4 preferred_ssid@8 entry@41 stride 59 (ssid@+0 name@+33 priority@+58); tail 513..516.
    let mut set = MetaSet::defaults(&SSIDS[..2]);
    set.slot[1].name = fixed("Phone!");
    set.slot[1].priority = 91;
    set.preferred = Some(1);
    let b = MetaBlob::encode(&SSIDS[..2], &set).to_bytes();
    assert_eq!(b.len(), 516);
    assert_eq!(&b[0..8], &[1, 0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(&b[8..14], b"Phone\0");
    assert_eq!(&b[41..46], b"Home\0");
    assert_eq!(&b[41 + 33..41 + 38], b"Home\0");
    assert_eq!(b[41 + 58], 50);
    assert_eq!(&b[100..106], b"Phone\0");
    assert_eq!(&b[100 + 33..100 + 40], b"Phone!\0");
    assert_eq!(b[100 + 58], 91);
    assert!(b[41 + 2 * 59..].iter().all(|&x| x == 0)); // unused entries and the tail padding are zero
}
