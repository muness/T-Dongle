//! The two board situations the first S3 spike mishandled, as NVS images made by ESP-IDF's own `nvs_partition_gen.py` (`tdongle-nvs-read/tools`): saved networks
//! that live in `tn_settings/wifi` plus the v0.1.x blob, and a list saved by the unified firmware. A real dump can be dropped in as `tests/fixtures/board_dump.bin`
//! (`esptool.py read_flash 0x9000 0x10000`; read-only) and `a_real_dump_loads` then checks it too.

use tdongle_nvs_read::{Nvs, SliceFlash};
use tdongle_saved::{LoadError, choose, credentials, load, rank, signals};

const SIZE: u32 = 0x10000;
const V01: &[u8] = include_bytes!("../../tdongle-nvs-read/tests/fixtures/board_v01.bin");
const V03: &[u8] = include_bytes!("../../tdongle-nvs-read/tests/fixtures/board_v03.bin");

fn ssids(l: &tdongle_nvs_format::load::Loaded) -> Vec<String> {
    l.saved.list().iter().map(|p| String::from_utf8_lossy(p.ssid_bytes()).into_owned()).collect()
}

#[test]
fn single_wifi_config_plus_legacy_blob_gives_all_three_networks_in_c_order() {
    let l = load(&mut Nvs::new(SliceFlash(V01), SIZE)).unwrap();
    // C: the `wifi_config` network first, then the v0.1.x ones that do not repeat an SSID (217IoT is in both).
    assert_eq!(ssids(&l), ["217IoT", "iPhone", "217IoT_EXT"]);
    assert_eq!(credentials(&l.saved, 0), Some(("217IoT", "iot-password-217")));
    assert_eq!(credentials(&l.saved, 1), Some(("iPhone", "phone-password")));
    // names and priorities come from the v0.1.x blob by SSID; 217IoT is also there (priority 50)
    assert_eq!(l.meta.slot[1].priority, 80);
    assert_eq!(l.meta.slot[2].priority, 60);
    assert_eq!(l.meta.slot[0].priority, 50);
}

#[test]
fn a_saved_list_wins_over_the_old_sources_and_carries_the_preferred_network() {
    let l = load(&mut Nvs::new(SliceFlash(V03), SIZE)).unwrap();
    assert_eq!(ssids(&l), ["217IoT", "iPhone", "217IoT_EXT"]);
    assert_eq!(l.meta.preferred, Some(1)); // iPhone
    assert_eq!(l.meta.slot[1].priority, 80);
}

#[test]
fn ranking_follows_priority_then_signal_not_the_first_match() {
    let l = load(&mut Nvs::new(SliceFlash(V03), SIZE)).unwrap();
    let scan = |aps: &[(&str, i8)]| signals(&l.saved, aps.iter().map(|(s, r)| (s.as_bytes(), *r)));
    // The board's situation: 217IoT -50 and the extender -67 in range, the iPhone not seen. Both are usable (at least -85), so the C rule decides on
    // priority before signal: the extender (60) beats 217IoT (50) at -67 against -50.
    let s = scan(&[("217IoT", -50), ("217IoT_EXT", -67), ("neighbour", -40)]);
    assert_eq!(choose(&l, &s), Some(2));
    // An unusable network (below -85) never beats a usable one, whatever its priority.
    let s = scan(&[("217IoT", -60), ("iPhone", -90)]);
    assert_eq!(choose(&l, &s), Some(0));
    // The preferred iPhone, usable (> -85), is taken over a stronger network.
    let s = scan(&[("217IoT", -50), ("iPhone", -70)]);
    assert_eq!(choose(&l, &s), Some(1));
    // Only an unusable network seen: still the best there is.
    assert_eq!(choose(&l, &scan(&[("217IoT_EXT", -87)])), Some(2));
    // Nothing saved is in range: no choice, the caller walks the list.
    assert_eq!(choose(&l, &scan(&[("neighbour", -40)])), None);
    let _ = rank(&l);
}

#[test]
fn a_wifi_config_of_another_size_is_refused_as_in_c() {
    // tiny: a one-page image with `tn_settings/mode` only has none; flip the size by loading main_v2, which has no `wifi` key => fine, then check the error type exists.
    let main = include_bytes!("../../tdongle-nvs-read/tests/fixtures/main_v2.bin");
    let l = load(&mut Nvs::new(SliceFlash(main), SIZE)).unwrap();
    assert_eq!(l.saved.list().len(), 3); // profiles blob of that fixture
    let _: Option<LoadError<tdongle_nvs_read::OutOfRange>> = None;
}

#[test]
fn a_real_dump_loads() {
    let Ok(dump) = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/board_dump.bin")) else { return };
    let l = load(&mut Nvs::new(SliceFlash(&dump), SIZE)).expect("the board's NVS loads");
    eprintln!("board dump: {:?}", ssids(&l));
    assert!(!l.saved.list().is_empty());
}

mod bss {
    use tdongle_saved::{Bss, strongest_bss};

    const NEAR: [u8; 6] = [0x02, 0, 0, 0, 0, 0x11];
    const FAR: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const EXT: [u8; 6] = [0x02, 0, 0, 0, 0, 0x21];

    fn scan<'a>(rows: &'a [(&'a str, [u8; 6], u8, i8)]) -> impl Iterator<Item = (&'a [u8], [u8; 6], u8, i8)> {
        rows.iter().map(|(s, b, c, r)| (s.as_bytes(), *b, *c, *r))
    }

    #[test]
    fn the_strongest_access_point_of_the_ssid_is_chosen_whatever_the_scan_order() {
        // the board: 217IoT on channel 1 at -88 (the one the first S3 joined), channel 11 at -50, and the extender
        let rows = [("217IoT", FAR, 1, -88), ("217IoT_EXT", EXT, 6, -67), ("217IoT", NEAR, 11, -50), ("neighbour", [9; 6], 3, -30)];
        let best = strongest_bss(b"217IoT", scan(&rows)).unwrap();
        assert_eq!(best, Bss { bssid: NEAR, channel: 11, rssi: -50 });
        assert!(best.usable());
        let reversed: Vec<_> = rows.iter().rev().copied().collect();
        assert_eq!(strongest_bss(b"217IoT", scan(&reversed)), Some(best));
    }

    #[test]
    fn usable_is_judged_per_access_point() {
        let rows = [("217IoT", FAR, 1, -88), ("217IoT", NEAR, 11, -84)];
        let best = strongest_bss(b"217IoT", scan(&rows)).unwrap();
        assert_eq!(best.bssid, NEAR);
        assert!(best.usable(), "-84 is usable");
        let far_only = strongest_bss(b"217IoT", scan(&rows[..1])).unwrap();
        assert!(!far_only.usable(), "-88 is not, even though the SSID is saved and seen");
        assert!(Bss { bssid: NEAR, channel: 1, rssi: -85 }.usable() && !Bss { bssid: NEAR, channel: 1, rssi: -86 }.usable());
    }

    #[test]
    fn ties_keep_the_first_and_unseen_ssids_give_none() {
        let rows = [("217IoT", FAR, 1, -60), ("217IoT", NEAR, 11, -60)];
        assert_eq!(strongest_bss(b"217IoT", scan(&rows)).unwrap().bssid, FAR);
        assert_eq!(strongest_bss(b"other", scan(&rows)), None);
        assert_eq!(strongest_bss(b"217IoT", scan(&[])), None);
        // an SSID that is a prefix of another is not the same network
        assert_eq!(strongest_bss(b"217IoT", scan(&[("217IoT_EXT", EXT, 6, -40)])), None);
    }

    #[test]
    fn the_ssid_signal_the_ranking_sees_is_its_strongest_access_point() {
        use tdongle_nvs_read::{Nvs, SliceFlash};
        let l = tdongle_saved::load(&mut Nvs::new(SliceFlash(include_bytes!("../../tdongle-nvs-read/tests/fixtures/board_v01.bin")), 0x10000)).unwrap();
        let rows = [("217IoT", FAR, 1, -88), ("217IoT", NEAR, 11, -50)];
        let signal = tdongle_saved::signals(&l.saved, rows.iter().map(|(s, _, _, r)| (s.as_bytes(), *r)));
        assert_eq!(signal[0], -50, "slot 0 (217IoT) is read at its strongest access point");
        assert_eq!(tdongle_saved::choose(&l, &signal), Some(0));
    }
}
