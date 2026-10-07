//! Reply texts against the real C: help, capabilities, unknown command, greeting, list, display, scan, `use`/`profile` replies, `pm`,
//! and the set of fixed `mgmt_write("...")` literals.

mod common;

use common::*;
use std::collections::BTreeSet;
use tdongle_serial::console::write_greeting;
use tdongle_serial::pm_report::{self, Lock, Power};
use tdongle_serial::reply::{self, ListLine};

#[test]
fn help_capabilities_unknown_and_greeting_match_both_images() {
    let texts = golden("texts.golden");
    assert_eq!(texts.len(), 16);
    for diag in [false, true] {
        let image = if diag { "diagnostics" } else { "release" };
        let (commands, feature) = if diag { (reply::MEMORY_COMMANDS_DIAGNOSTICS, reply::MEMORY_FEATURE_DIAGNOSTICS) } else { ("", "") };
        for tailnet in [false, true] {
            let mode = if tailnet { "tailnet" } else { "bridge" };
            let want = |what: &str| String::from_utf8(entry(&texts, &format!("{what}/{mode}/{image}")).to_vec()).expect("utf8");
            assert_eq!(render(|w| reply::write_help(w, tailnet, commands)), want("help"), "help {mode} {image}");
            assert_eq!(render(|w| reply::write_capabilities(w, tailnet, feature)), want("capabilities"), "capabilities {mode} {image}");
            assert_eq!(render(|w| reply::write_unknown(w, tailnet)), want("unknown"), "unknown {mode} {image}");
            assert_eq!(render(|w| write_greeting(w, tailnet, "1.2.3-golden")), want("greeting"), "greeting {mode} {image}");
            if !diag {
                // The release-image constants are the same bytes.
                assert_eq!(if tailnet { reply::HELP_TAILNET } else { reply::HELP_BRIDGE }, want("help"));
                assert_eq!(if tailnet { reply::CAPABILITIES_TAILNET } else { reply::CAPABILITIES_BRIDGE }, want("capabilities"));
                assert_eq!(reply::unknown_command(tailnet), want("unknown"));
            }
        }
    }
}

#[test]
fn list_lines_match_the_c_format() {
    let all = scenarios();
    let golden = golden("replies.golden");
    for sc in all["list"].as_array().expect("list") {
        let name = sc["name"].as_str().expect("name");
        let current = sc["current"].as_i64().expect("current");
        let mut got = Vec::new();
        for (i, n) in sc["networks"].as_array().expect("networks").iter().enumerate() {
            let line = ListLine::new(
                u32::try_from(i).expect("index"),
                current == i64::try_from(i).expect("index"),
                &hex(n["name_hex"].as_str().expect("name")),
                &hex(n["ssid_hex"].as_str().expect("ssid")),
                u8::try_from(n["priority"].as_u64().expect("priority")).expect("u8"),
            );
            got.extend_from_slice(line.as_bytes());
        }
        assert_eq!(got, entry(&golden, &format!("list/{name}")), "list scenario {name}");
    }
}

#[test]
fn list_line_cuts_a_name_at_24_bytes_and_a_line_at_159() {
    let long_name = [b'n'; 40];
    let line = ListLine::new(0, false, &long_name, b"ssid", 5);
    assert_eq!(line.as_bytes(), format!("1 name={} ssid=ssid priority=5\r\n", "n".repeat(24)).as_bytes());
    // C strings stop at their NUL.
    assert_eq!(ListLine::new(1, true, b"ab\0cd", b"s\0t", 0).as_bytes(), b"2* name=ab ssid=s priority=0\r\n");
    // Cannot happen with the real arrays (24 + 32 bytes) but the buffer is the C one: 160 bytes, 159 kept.
    let long_ssid = [b's'; 200];
    let cut = ListLine::new(0, false, b"x", &long_ssid, 255);
    assert_eq!(cut.as_bytes().len(), 159);
    assert!(cut.as_bytes().starts_with(b"1 name=x ssid=sss"));
}

#[test]
fn display_reply_matches_the_c_format() {
    let all = scenarios();
    let golden = golden("replies.golden");
    for sc in all["display"].as_array().expect("display") {
        let name = sc["name"].as_str().expect("name");
        let got = render(|w| reply::write_display(w, u8_of(sc, "brightness"), u8_of(sc, "rotation"), u16::try_from(u32_of(sc, "dim_seconds")).expect("u16")));
        assert_eq!(got.as_bytes(), entry(&golden, &format!("display/{name}")), "{name}");
    }
}

#[test]
fn scan_lines_match_the_c_format_including_the_question_marks() {
    let all = scenarios();
    let golden = golden("replies.golden");
    for sc in all["scan"].as_array().expect("scan") {
        let name = sc["name"].as_str().expect("name");
        let ssid: [u8; 32] = hex(sc["ssid_hex"].as_str().expect("ssid")).try_into().expect("32 bytes");
        let got = render(|w| reply::write_scan_line(w, &ssid, i8_of(sc, "rssi"), i32_of(sc, "auth")));
        assert_eq!(got.as_bytes(), entry(&golden, &format!("scan/{name}")), "{name}");
    }
}

#[test]
fn profile_saved_and_use_replies_match_the_c_formats() {
    let golden = golden("replies.golden");
    for slot in [0, 1, 2, 7, 8, 9, 100, -1, 2_147_483_646] {
        assert_eq!(render(|w| reply::write_profile_saved(w, slot)).as_bytes(), entry(&golden, &format!("saved/{slot}")), "slot {slot}");
    }
    for slot in [0, 1, 2, 8, 9, -3, i32::MAX, i32::MIN, 12345] {
        for kept in [true, false] {
            let name = format!("switching/{slot}/{}", u8::from(kept));
            assert_eq!(render(|w| reply::write_use_ok(w, slot, kept)).as_bytes(), entry(&golden, &name), "{name}");
        }
    }
}

#[test]
fn pm_report_matches_the_c_function() {
    let all = scenarios();
    let golden = golden("pm.golden");
    for sc in all["pm"].as_array().expect("pm") {
        let name = sc["name"].as_str().expect("name");
        let p = &sc["power"];
        let power = Power {
            scaling: flag(p, "scaling"),
            configure_error: i32_of(p, "configure_error"),
            cpu_mhz: u32_of(p, "cpu_mhz"),
            max_mhz: u32_of(p, "max_mhz"),
            min_mhz: u32_of(p, "min_mhz"),
            lock_create_failures: u32_of(p, "lock_create_failures"),
        };
        let locks: Vec<Lock<'_>> = sc["locks"]
            .as_array()
            .expect("locks")
            .iter()
            .map(|b| Lock {
                name: b["name"].as_str().expect("name"),
                depth: u32_of(b, "depth"),
                acquires: u32_of(b, "acquires"),
                releases: u32_of(b, "releases"),
                held_us: u32_of(b, "held_us"),
                max_depth: u32_of(b, "max_depth"),
                underflows: u32_of(b, "underflows"),
                forced_releases: u32_of(b, "forced_releases"),
                backend_failures: u32_of(b, "backend_failures"),
                isr_rejects: u32_of(b, "isr_rejects"),
            })
            .collect();
        let dump = sc["dump"].as_str();
        let got = render(|w| pm_report::write_report(w, &power, &locks, dump));
        assert_eq!(got.as_bytes(), entry(&golden, name), "pm scenario {name}\n{got}");
    }
}

#[test]
fn every_fixed_c_reply_has_a_constant_and_every_constant_is_in_the_c() {
    let c: BTreeSet<Vec<u8>> = golden("fixed_replies.golden").into_iter().map(|(_, body)| body).collect();
    let rust: BTreeSet<Vec<u8>> = reply::ALL_FIXED.iter().map(|s| s.as_bytes().to_vec()).collect();
    // `boot-status` ends with a bare CRLF after the boot report (a terminator, not a reply of its own).
    let mut c = c;
    assert!(c.remove(b"\r\n".as_slice()));
    let missing: Vec<_> = c.difference(&rust).map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    let extra: Vec<_> = rust.difference(&c).map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    assert!(missing.is_empty(), "C replies without a constant: {missing:?}");
    assert!(extra.is_empty(), "constants that are in no C file: {extra:?}");
    assert!(rust.len() >= 30, "{}", rust.len());
}

#[test]
fn constants_match_the_c_headers() {
    let text = String::from_utf8(std::fs::read(golden_dir().join("constants.golden")).expect("constants")).expect("utf8");
    let get =
        |key: &str| -> usize { text.lines().find_map(|l| l.strip_prefix(&format!("{key}="))).unwrap_or_else(|| panic!("{key}")).parse().expect("number") };
    assert_eq!(get("GW_CLOCK_SERVERS"), tdongle_serial::clock::SERVERS);
    assert_eq!(get("GW_CLOCK_FIRST_RETRY_MS"), tdongle_serial::clock::FIRST_RETRY_MS as usize);
    assert_eq!(get("GW_CLOCK_MAX_RETRY_MS"), tdongle_serial::clock::MAX_RETRY_MS as usize);
    assert_eq!(get("WIFI_LINK_JSON_MAX"), tdongle_serial::wifi_link::JSON_MAX);
    assert_eq!(get("WIFI_LINK_LINE_MAX"), tdongle_serial::wifi_link::LINE_MAX);
    assert_eq!(get("BRIDGE_LINE_MAX"), tdongle_serial::bridge_report::LINE_MAX);
    assert_eq!(get("CONSOLE_LINE"), tdongle_serial::console::LINE_MAX);
    assert_eq!(get("MGMT_CHUNK_MAX"), tdongle_serial::console::MGMT_CHUNK_MAX);
    assert_eq!(get("STATUS_REPLY"), tdongle_serial::status::REPLY_MAX);
    assert_eq!(get("WIFI_META_SLOTS"), tdongle_serial::command::SETUP_SLOT_MAX);
    assert_eq!(get("TDONGLE_TEMPERATURE_STEP_TENTHS"), usize::try_from(tdongle_serial::status::TEMPERATURE_STEP_TENTHS).expect("positive"));
    for (name, value) in [
        ("WIFI_LINK_PHY_LR", tdongle_serial::wifi_link::PHY_LR),
        ("WIFI_LINK_PHY_11B", tdongle_serial::wifi_link::PHY_11B),
        ("WIFI_LINK_PHY_11G", tdongle_serial::wifi_link::PHY_11G),
        ("WIFI_LINK_PHY_11A", tdongle_serial::wifi_link::PHY_11A),
        ("WIFI_LINK_PHY_HT20", tdongle_serial::wifi_link::PHY_HT20),
        ("WIFI_LINK_PHY_HT40", tdongle_serial::wifi_link::PHY_HT40),
        ("WIFI_LINK_PHY_HE20", tdongle_serial::wifi_link::PHY_HE20),
        ("WIFI_LINK_PHY_VHT20", tdongle_serial::wifi_link::PHY_VHT20),
        ("WIFI_LINK_PHY_UNKNOWN", tdongle_serial::wifi_link::PHY_UNKNOWN),
        ("WIFI_LINK_PS_UNKNOWN", tdongle_serial::wifi_link::PS_UNKNOWN),
        ("WIFI_LINK_SECOND_UNKNOWN", tdongle_serial::wifi_link::SECOND_UNKNOWN),
        ("WIFI_LINK_AP_B", tdongle_serial::wifi_link::AP_B),
        ("WIFI_LINK_AP_G", tdongle_serial::wifi_link::AP_G),
        ("WIFI_LINK_AP_N", tdongle_serial::wifi_link::AP_N),
        ("WIFI_LINK_AP_AX", tdongle_serial::wifi_link::AP_AX),
    ] {
        assert_eq!(get(name), usize::from(value), "{name}");
    }
    assert_eq!(get("WIFI_LINK_REASON_BEACON_TIMEOUT"), tdongle_serial::wifi_link::REASON_BEACON_TIMEOUT as usize);
}
