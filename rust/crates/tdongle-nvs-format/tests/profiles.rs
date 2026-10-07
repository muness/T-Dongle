//! The `wifi_profiles` blob layout and validation (`alternative/tailnet/main/wifi_profiles.inc`).
mod common;
use common::fixed;
use tdongle_nvs_format::wifi_profiles::{BLOB_LEN, SavedNetworks, SavedNetworksError, SavedProfile};

fn list(entries: &[(&str, &str)]) -> SavedNetworks {
    let mut l = SavedNetworks::default();
    for (i, (ssid, pass)) in entries.iter().enumerate() {
        l.profiles[i] = SavedProfile { ssid: fixed(ssid), password: fixed(pass) };
    }
    l.count = entries.len();
    l
}

#[test]
fn layout_is_frozen() {
    assert_eq!(BLOB_LEN, 8 + 8 * 97);
    assert_eq!(BLOB_LEN, 784);
    let b = list(&[("Home", "pass1234"), ("Work", "")]).to_bytes();
    assert_eq!(b.len(), 784);
    assert_eq!(&b[0..8], &[1, 0, 0, 0, 2, 0, 0, 0]); // schema, count
    assert_eq!(&b[8..13], b"Home\0");
    assert_eq!(&b[8 + 33..8 + 33 + 9], b"pass1234\0");
    assert_eq!(&b[8 + 97..8 + 97 + 5], b"Work\0");
    assert!(b[8 + 97 + 33..].iter().all(|&x| x == 0));
}

#[test]
fn round_trip_keeps_every_byte() {
    let mut l = list(&[("Home", "pass1234")]);
    l.profiles[0].ssid[10] = 0x77; // after the terminator
    l.profiles[3] = SavedProfile { ssid: [0xA5; 33], password: [0xA5; 64] }; // unused entry
    let b = l.to_bytes();
    assert_eq!(SavedNetworks::from_bytes(&b), Ok(l));
}

#[test]
fn validation() {
    let good = list(&[("Home", "pass1234")]).to_bytes();
    assert!(SavedNetworks::from_bytes(&good).is_ok());
    let with = |f: &dyn Fn(&mut [u8; BLOB_LEN])| {
        let mut b = good;
        f(&mut b);
        SavedNetworks::from_bytes(&b)
    };
    assert_eq!(with(&|b| b[0] = 2), Err(SavedNetworksError::BadSchema));
    assert_eq!(with(&|b| b[4] = 9), Err(SavedNetworksError::BadCount));
    assert_eq!(with(&|b| b[4] = 8), Err(SavedNetworksError::EmptySsid)); // entries 1..8 are empty but now in use
    assert_eq!(with(&|b| b[8..41].fill(b'x')), Err(SavedNetworksError::SsidUnterminated));
    assert_eq!(with(&|b| b[8 + 33..8 + 97].fill(b'x')), Err(SavedNetworksError::PasswordUnterminated));
    assert_eq!(with(&|b| b[8] = 0), Err(SavedNetworksError::EmptySsid));
    assert_eq!(SavedNetworks::from_bytes(&good[..BLOB_LEN - 1]), Err(SavedNetworksError::WrongSize));
    assert_eq!(SavedNetworks::from_bytes(&[]), Err(SavedNetworksError::WrongSize));
    // Unused entries are never looked at.
    assert!(with(&|b| b[8 + 97 * 4..8 + 97 * 5].fill(0xFF)).is_ok());
    // A 32 character SSID and a 63 character password are the longest allowed.
    let l = list(&[(&"s".repeat(32), &"p".repeat(63))]);
    assert_eq!(SavedNetworks::from_bytes(&l.to_bytes()), Ok(l));
}

#[test]
fn ssid_list_is_empty_beyond_count() {
    let l = list(&[("a", ""), ("b", "")]);
    let ssids = l.ssids();
    assert_eq!(&ssids[..3], &[&b"a"[..], b"b", b""]);
    assert_eq!(l.list().len(), 2);
    assert_eq!(l.list()[0].password_bytes(), b"");
}
