//! `write_status` against `serial_status()` of the real C source (golden/status.golden), and the Android contract of the report.

mod common;

use common::*;
use serde_json::Value;
use tdongle_serial::clock::Clock;
use tdongle_serial::memory_log::Record;
use tdongle_serial::status::{DisplayState, Mode, Prefs, Snapshot, Traffic, write_status};
use tdongle_traffic::Reading;

/// Run `f` with the `Snapshot` of a scenario (the borrowed pieces live in this function).
fn with_snapshot<R>(sc: &Value, f: impl FnOnce(&Snapshot<'_>) -> R) -> R {
    let records: Vec<Record> = sc["memory"].as_array().expect("memory").iter().map(record).collect();
    let records: &[Record] = &records;
    let p = &sc["prefs"];
    let priorities: Vec<u8> = p["priorities"].as_array().expect("priorities").iter().map(|v| u8::try_from(v.as_u64().expect("u8")).expect("u8")).collect();
    let preferred = i64::from(i32_of(p, "preferred"));
    let d = &sc["display"];
    let t = &sc["traffic"];
    let setup_active = flag(sc, "setup_active");
    let mode = if setup_active {
        Mode::Setup
    } else if flag(sc, "tailnet") {
        Mode::Tailnet
    } else {
        Mode::Adapter
    };
    let snapshot = Snapshot {
        mode,
        wifi_current: i32_of(sc, "wifi_current"),
        online: flag(sc, "online"),
        firmware: sc["version"].as_str().expect("version"),
        usb_mounted: flag(sc, "usb_mounted"),
        usb_ready: flag(sc, "usb_ready"),
        uptime_ms: sc["uptime_ms"].as_u64().expect("uptime"),
        free_heap: u32_of(sc, "free_heap"),
        temperature: temperature(&sc["temperature"]),
        clock: clock(&sc["clock"]),
        clock_valid: flag(sc, "clock_valid"),
        link: link(&sc["link"]),
        events: events(&sc["events"]),
        prefs: Prefs {
            saved: u32_of(p, "saved"),
            preferred: u32::try_from(preferred).ok(),
            priorities: &priorities,
            roaming_assist: flag(p, "roaming_assist"),
        },
        display: DisplayState {
            brightness: u8_of(d, "brightness"),
            rotation: u8_of(d, "rotation"),
            dim_seconds: u16::try_from(u32_of(d, "dim_seconds")).expect("u16"),
            page: u32_of(d, "page"),
        },
        setup_ap_name: sc["setup"]["ap_name"].as_str().expect("ap"),
        setup_seconds_left: u32_of(&sc["setup"], "seconds_left"),
        traffic: Traffic {
            counters: Reading {
                down_bytes: u32_of(t, "down_bytes"),
                up_bytes: u32_of(t, "up_bytes"),
                down_frames: u32_of(t, "down_frames"),
                up_frames: u32_of(t, "up_frames"),
            },
            down_kbps: u32_of(t, "down_kbps"),
            up_kbps: u32_of(t, "up_kbps"),
            usb_resets: u32_of(t, "usb_resets"),
            control_stack_free_bytes: u32_of(t, "control_stack_free"),
        },
        memory: &records,
    };
    f(&snapshot)
}

fn rust_status(sc: &Value) -> String {
    with_snapshot(sc, |s| render(|w| write_status(w, s)))
}

#[test]
fn every_scenario_matches_the_c_output_byte_for_byte() {
    let all = scenarios();
    let list = all["status"].as_array().expect("status scenarios");
    let golden = golden("status.golden");
    assert_eq!(list.len(), golden.len(), "scenario table and golden file disagree (run tools/regen.sh)");
    assert!(list.len() >= 150, "the table is the evidence: keep it broad");
    for (sc, (name, expected)) in list.iter().zip(&golden) {
        assert_eq!(sc["name"].as_str().expect("name"), name);
        let got = rust_status(sc);
        assert_eq!(got.as_bytes(), &expected[..], "scenario {name}\n--- rust ---\n{got}\n--- c ---\n{}", String::from_utf8_lossy(expected));
    }
}

#[test]
fn the_scenario_table_covers_what_the_task_requires() {
    let all = scenarios();
    let list = all["status"].as_array().expect("status scenarios");
    let has = |pred: &dyn Fn(&Value) -> bool| list.iter().any(pred);
    assert!(
        has(&|s| flag(s, "setup_active"))
            && has(&|s| flag(s, "tailnet") && !flag(s, "setup_active"))
            && has(&|s| !flag(s, "tailnet") && !flag(s, "setup_active"))
    );
    assert!(has(&|s| flag(s, "online")) && has(&|s| !flag(s, "online")));
    assert!(
        has(&|s| flag(&s["link"], "connected") && flag(&s["link"], "rssi_valid")) && has(&|s| flag(&s["link"], "connected") && !flag(&s["link"], "rssi_valid"))
    );
    assert!(has(&|s| !flag(&s["link"], "connected")));
    for saved in 0..=8 {
        assert!(has(&|s| u32_of(&s["prefs"], "saved") == saved), "{saved} saved networks");
    }
    for preferred in -1..8 {
        assert!(has(&|s| i32_of(&s["prefs"], "preferred") == preferred && u32_of(&s["prefs"], "saved") == 8), "preferred {preferred}");
    }
    assert!(has(&|s| !flag(&s["temperature"], "valid")) && has(&|s| flag(&s["temperature"], "valid")));
    assert!(has(&|s| i32_of(&s["temperature"], "current_tenths") < 0));
    assert!(has(&|s| u32_of(&s["temperature"], "age_ms") == u32::MAX));
    assert!(has(&|s| s["uptime_ms"].as_u64().is_some_and(|u| u > u64::from(u32::MAX))));
    assert!(has(&|s| u32_of(s, "free_heap") == 0) && has(&|s| u32_of(s, "free_heap") == u32::MAX));
    for n in 0..=16 {
        assert!(has(&|s| s["memory"].as_array().is_some_and(|m| m.len() == n)), "{n} memory records");
    }
}

fn status_outputs() -> Vec<(String, Value, String)> {
    let all = scenarios();
    all["status"].as_array().expect("status").iter().map(|sc| (sc["name"].as_str().expect("name").to_string(), sc.clone(), rust_status(sc))).collect()
}

/// `tools/check-android-status.py`: Android end-anchors the `chip_temperature` line after `errors=`, so nothing may ever be appended to it,
/// and its regex is `^chip_temperature valid=[01] current_tenths=\d+ peak_tenths=\d+ sampled_uptime_ms=\d+ errors=\d+\r$` (multi-line mode).
fn android_chip_temperature_matches(report: &str) -> bool {
    fn digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }
    report.split('\n').any(|line| {
        let Some(line) = line.strip_suffix('\r') else { return false };
        let f: Vec<&str> = line.split(' ').collect();
        f.len() == 6
            && f[0] == "chip_temperature"
            && matches!(f[1], "valid=0" | "valid=1")
            && f[2].strip_prefix("current_tenths=").is_some_and(digits)
            && f[3].strip_prefix("peak_tenths=").is_some_and(digits)
            && f[4].strip_prefix("sampled_uptime_ms=").is_some_and(digits)
            && f[5].strip_prefix("errors=").is_some_and(digits)
    })
}

#[test]
fn the_android_chip_temperature_regex_holds_for_non_negative_values_and_nothing_is_appended() {
    let mut checked = 0;
    for (name, sc, text) in status_outputs() {
        let t = &sc["temperature"];
        let non_negative = i32_of(t, "current_tenths") >= 0 && i32_of(t, "peak_tenths") >= 0;
        if name == "long_version_cuts_first_block" {
            continue;
        }
        assert_eq!(android_chip_temperature_matches(&text), non_negative, "scenario {name}:\n{text}");
        if non_negative {
            checked += 1;
            // The detail fields live on their own line right after it.
            let line = text.lines().find(|l| l.starts_with("chip_temperature ")).expect("line");
            assert!(line.ends_with(&format!("errors={}", u32_of(t, "errors"))), "{name}: {line}");
            assert!(text.contains("\r\nchip_temperature_detail age_ms="), "{name}");
        }
    }
    assert!(checked > 100);
}

#[test]
fn the_first_line_keeps_the_documented_field_order() {
    let order = ["mode", "trial", "active", "wifi", "rssi", "usb_enumerated", "usb_transport_ready", "host_interface_ready", "internet"];
    for (name, _, text) in status_outputs() {
        if name == "long_version_cuts_first_block" {
            continue;
        }
        let first = text.lines().next().expect("first line");
        let keys: Vec<&str> = first.split(' ').map(|f| f.split('=').next().expect("key")).collect();
        assert_eq!(keys, order, "{name}");
        assert!(first.contains(" host_interface_ready=unknown internet=not_checked") && first.contains(" trial=0 "), "{name}");
        // Android's rssi pattern: (?:unknown|-?\d+)
        let rssi = first.split(' ').find_map(|f| f.strip_prefix("rssi=")).expect("rssi");
        assert!(rssi == "unknown" || rssi.strip_prefix('-').unwrap_or(rssi).bytes().all(|b| b.is_ascii_digit()), "{name}: {rssi}");
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert!(lines[1].starts_with("firmware=") && lines[2].starts_with("uptime_ms=") && lines[3].starts_with("chip_temperature valid="), "{name}");
        assert!(lines[4].starts_with("chip_temperature_detail ") && lines[5].starts_with("clock="), "{name}");
    }
}

#[test]
fn every_line_ends_with_crlf_and_the_blocks_follow_in_order() {
    let blocks = ["clock=", "wifi_link ", "wifi_prefs ", "display ", "setup ", "traffic ", "memory_pressure "];
    for (name, _, text) in status_outputs() {
        if name == "long_version_cuts_first_block" {
            continue;
        }
        assert!(text.ends_with("\r\n") && !text.replace("\r\n", "").contains(['\r', '\n']), "{name}");
        let mut at = 0;
        for block in blocks {
            if let Some(i) = text[at..].find(&format!("\r\n{block}")) {
                at += i + 2;
            } else {
                assert!(block == "memory_pressure ", "{name}: block {block} missing or out of order");
            }
        }
    }
}

#[test]
fn a_very_long_version_cuts_the_first_block_at_447_bytes_like_snprintf() {
    let all = scenarios();
    let sc = all["status"].as_array().expect("status").iter().find(|s| s["name"] == "long_version_cuts_first_block").expect("scenario");
    let text = rust_status(sc);
    let clock_at = text.find("clock=").expect("clock line follows");
    assert_eq!(clock_at, 447, "the block is cut at sizeof(reply) - 1 and the next line follows without a line end");
    assert!(text[..clock_at].ends_with("chip"));
}

#[test]
fn clock_is_copy_so_snapshots_are_cheap_to_take() {
    fn is_copy<T: Copy>() {}
    is_copy::<Clock>();
    is_copy::<Snapshot<'static>>();
}
