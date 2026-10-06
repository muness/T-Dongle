//! Ports of `tests/test_legacy_import.c` and the `profile_valid` / `settings_valid` cases of `tests/test_core.c`.
mod common;
use common::{fixed, legacy_profile};
use tdongle_nvs_format::cstr::c_str;
use tdongle_nvs_format::legacy::{
    BLOB_LEN, CFG_VERSION, LegacyError, LegacyImport, LegacyProfile, LegacySettings,
};

fn blank() -> LegacySettings {
    LegacySettings {
        version: CFG_VERSION,
        p: [LegacyProfile::EMPTY; 8],
        preferred: 0,
        brightness: 60,
        rotation: 0,
        dim_seconds: 60,
    }
}

fn set(s: &mut LegacySettings, slot: usize, name: &str, ssid: &str, pass: &str, priority: u8) {
    s.p[slot] = legacy_profile(name, ssid, pass, priority);
}

fn import(s: &LegacySettings) -> LegacyImport {
    LegacyImport::decode(&s.to_bytes()).unwrap()
}

fn net_ssid(i: &LegacyImport, n: usize) -> &[u8] {
    c_str(&i.net[n].ssid)
}

#[test]
fn layout_is_the_v011_layout() {
    // sizeof(settings_t) == 1004, sizeof(profile_t) == 124; p@4 preferred@996 brightness@997 rotation@998 dim_seconds@1000.
    let mut s = blank();
    set(&mut s, 1, "NAME", "SSID", "PASSWORD", 77);
    s.preferred = 3;
    s.brightness = 85;
    s.rotation = 1;
    s.dim_seconds = 0x0123;
    let b = s.to_bytes();
    assert_eq!(b.len(), BLOB_LEN);
    assert_eq!(BLOB_LEN, 1004);
    assert_eq!(&b[0..4], &[1, 0, 0, 0]);
    let p1 = 4 + 124; // profile 1: name@0 ssid@25 pass@58 priority@123
    assert_eq!(&b[p1..p1 + 5], b"NAME\0");
    assert_eq!(&b[p1 + 25..p1 + 30], b"SSID\0");
    assert_eq!(&b[p1 + 58..p1 + 67], b"PASSWORD\0");
    assert_eq!(b[p1 + 123], 77);
    assert_eq!(&b[996..1004], &[3, 85, 1, 0, 0x23, 0x01, 0, 0]);
    assert_eq!(LegacySettings::from_bytes(&b), Ok(s));
    assert_eq!(
        LegacySettings::from_bytes(&b[..1003]),
        Err(LegacyError::WrongSize)
    );
}

#[test]
fn padding_is_not_preserved() {
    let mut b = blank().to_bytes();
    b[999] = 0xAA;
    b[1002] = 0xBB;
    b[1003] = 0xCC;
    let s = LegacySettings::from_bytes(&b).unwrap();
    assert_eq!(s, blank());
    assert_eq!(s.to_bytes()[999], 0);
}

#[test]
fn everything_is_carried() {
    let mut s = blank();
    set(&mut s, 0, "Home", "HomeNet", "correct-horse", 50);
    set(&mut s, 1, "Phone", "Pixel hotspot", "", 90); // an open network
    set(&mut s, 4, "Car", "CarWifi", "12345678", 10); // gaps before it: slots 3 to 5 were deleted
    s.preferred = 4;
    s.brightness = 85;
    s.rotation = 1;
    s.dim_seconds = 300;
    let i = import(&s);
    assert_eq!((i.count, i.preferred), (3, Some(2)));
    assert_eq!(
        (
            net_ssid(&i, 0),
            c_str(&i.net[0].password),
            i.net[0].meta.name_bytes(),
            i.net[0].meta.priority
        ),
        (&b"HomeNet"[..], &b"correct-horse"[..], &b"Home"[..], 50)
    );
    assert_eq!(
        (
            net_ssid(&i, 1),
            c_str(&i.net[1].password),
            i.net[1].meta.name_bytes(),
            i.net[1].meta.priority
        ),
        (&b"Pixel hotspot"[..], &b""[..], &b"Phone"[..], 90)
    );
    assert_eq!(
        (
            net_ssid(&i, 2),
            i.net[2].meta.name_bytes(),
            i.net[2].meta.priority
        ),
        (&b"CarWifi"[..], &b"Car"[..], 10)
    );
    let d = i.display.unwrap();
    assert_eq!((d.brightness, d.rotation, d.dim_seconds), (85, 1, 300));
}

#[test]
fn v011_defaults() {
    // A v0.1.1 install that never touched anything: preferred is slot 0 (the zeroed default), which is how v0.1.1 chose.
    let mut s = blank();
    set(&mut s, 0, "Home", "HomeNet", "pass1234", 50);
    set(&mut s, 1, "Work", "WorkNet", "pass5678", 50);
    let i = import(&s);
    assert_eq!((i.count, i.preferred), (2, Some(0)));
    let d = i.display.unwrap();
    assert_eq!((d.brightness, d.dim_seconds, d.rotation), (60, 60, 0));
    // Nothing saved at all.
    let i = import(&blank());
    assert_eq!((i.count, i.preferred), (0, None));
}

#[test]
fn preferred_follows_the_network() {
    let mut s = blank();
    set(&mut s, 0, "A", "same", "aaaaaaaa", 20);
    set(&mut s, 1, "B", "other", "bbbbbbbb", 30);
    set(&mut s, 2, "C", "same", "cccccccc", 99); // the SSID again: the unified store keys by SSID, the first slot stands
    s.preferred = 2;
    let i = import(&s);
    assert_eq!((i.count, i.preferred), (2, Some(0)));
    assert_eq!(
        (c_str(&i.net[0].password), i.net[0].meta.priority),
        (&b"aaaaaaaa"[..], 20)
    );
    s.preferred = 3; // an empty slot
    assert_eq!(import(&s).preferred, None);
    s.preferred = 200; // out of range
    assert_eq!(import(&s).preferred, None);
    let mut s = blank();
    set(&mut s, 0, "Bad", "bad", "x", 50);
    s.p[0].ssid = [b'x'; 33]; // an unterminated SSID is skipped
    set(&mut s, 1, "Good", "good", "gggggggg", 50);
    s.preferred = 0;
    let i = import(&s);
    assert_eq!(
        (i.count, net_ssid(&i, 0), i.preferred),
        (1, &b"good"[..], None)
    );
}

#[test]
fn eight_networks() {
    let mut s = blank();
    for i in 0..8 {
        let n = format!("net{i}");
        set(&mut s, i, &n, &n, "password", 10 + i as u8);
    }
    s.preferred = 7;
    let i = import(&s);
    assert_eq!(
        (
            i.count,
            i.preferred,
            i.net[7].meta.priority,
            net_ssid(&i, 7)
        ),
        (8, Some(7), 17, &b"net7"[..])
    );
}

#[test]
fn damaged_fields_do_not_cost_the_network() {
    let mut s = blank();
    set(&mut s, 0, "bad\tname", "net0", "password", 200); // control character in the name, priority out of range
    set(&mut s, 1, "", "net1", "password", 50); // empty name
    set(&mut s, 2, "x", "net2", "password", 50);
    s.p[2].name = [b'n'; 25]; // unterminated name
    set(&mut s, 3, "long", "net3", "password", 50);
    s.p[3].pass = [b'p'; 65];
    s.p[3].pass[64] = 0; // a 64 character password cannot be used
    s.brightness = 3;
    s.rotation = 7;
    s.dim_seconds = 5;
    let i = import(&s);
    assert_eq!(i.count, 3);
    assert_eq!(
        (
            net_ssid(&i, 0),
            i.net[0].meta.name_bytes(),
            i.net[0].meta.priority
        ),
        (&b"net0"[..], &b"net0"[..], 50)
    );
    assert_eq!(
        (i.net[1].meta.name_bytes(), i.net[2].meta.name_bytes()),
        (&b"net1"[..], &b"net2"[..])
    );
    assert_eq!(i.display, None);
}

#[test]
fn passwords_of_63_and_64_bytes() {
    let mut s = blank();
    set(&mut s, 0, "ok", "net0", "x", 50);
    s.p[0].pass = [b'p'; 65];
    s.p[0].pass[63] = 0; // 63 characters: usable, kept whole
    let i = import(&s);
    assert_eq!(i.count, 1);
    assert_eq!(&i.net[0].password[..63], &[b'p'; 63]);
    assert_eq!(i.net[0].password[63], 0);
    s.p[0].pass = [b'p'; 65];
    s.p[0].pass[64] = 0; // 64 characters: skipped
    assert_eq!(import(&s).count, 0);
}

#[test]
fn not_a_v011_blob() {
    let mut s = blank();
    set(&mut s, 0, "Home", "HomeNet", "pass1234", 50);
    let b = s.to_bytes();
    assert_eq!(
        LegacyImport::decode(&b[..BLOB_LEN - 1]),
        Err(LegacyError::WrongSize)
    );
    assert_eq!(
        LegacyImport::decode(&[&b[..], &[0; 4]].concat()),
        Err(LegacyError::WrongSize)
    );
    assert_eq!(LegacyImport::decode(&[]), Err(LegacyError::WrongSize));
    s.version = 2;
    assert_eq!(
        LegacyImport::decode(&s.to_bytes()),
        Err(LegacyError::WrongVersion)
    );
}

#[test]
fn profile_and_settings_validity() {
    // tests/test_core.c, profiles().
    let mut s = blank();
    assert!(s.valid());
    s.p[0] = legacy_profile("Home", "test", "12345678", 20);
    s.p[1] = legacy_profile("Phone", "hotspot", "", 99);
    assert!(s.p[0].valid() && s.p[1].valid());
    s.p[0].pass = fixed("short");
    assert!(!s.p[0].valid());
    s.p[0].pass = fixed("12345678");
    s.p[0].ssid = [b'x'; 33];
    assert!(!s.p[0].valid());
    s.p[0].ssid = fixed("test");
    s.preferred = 8;
    assert!(!s.valid());
    s.preferred = 7;
    assert!(s.valid());
    // The rest of the rule.
    let p = |name: &str, ssid: &str, pass: &str, prio: u8| {
        legacy_profile(name, ssid, pass, prio).valid()
    };
    assert!(p("n", "s", "", 0) && p("n", "s", "12345678", 100) && !p("n", "s", "12345678", 101));
    assert!(!p("", "s", "", 0) && !p("n", "", "", 0));
    assert!(p(&"n".repeat(24), &"s".repeat(32), &"p".repeat(63), 50));
    assert!(!p(&"n".repeat(25), "s", "", 50)); // unterminated name
    assert!(!p("n", &"s".repeat(33), "", 50));
    assert!(!p("n", "s", &"p".repeat(64), 50));
    assert!(!p("n", "s", "1234567", 50) && p("n", "s", "12345678", 50));
    assert!(
        !p("n\t", "s", "", 50) && !p("n", "s\u{e9}", "", 50) && !p("n", "s", "pass\u{7f}word", 50)
    );
    // settings_valid: version, display ranges, every non-empty slot.
    let mut s = blank();
    s.version = 2;
    assert!(!s.valid());
    s = blank();
    s.brightness = 4;
    assert!(!s.valid());
    s = blank();
    s.rotation = 2;
    assert!(!s.valid());
    s = blank();
    s.dim_seconds = 9;
    assert!(!s.valid());
    s = blank();
    s.p[2] = legacy_profile("n", "s", "short", 50);
    assert!(!s.valid());
    s.p[2].ssid = [0; 33]; // an empty slot is never checked
    assert!(s.valid());
}
