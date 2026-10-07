//! The Android app's parsers, replayed against the Rust firmware's replies.
//!
//! Each regex below is copied from the app (`tdongle-android`, `core/src/main/java/com/muness/tdongle/core/`, branch
//! `codex/integration-multi-tailnet`) with the Java file and method named; `Matcher.matches()` is a whole-text match (`\A...\z` here),
//! `find()` a search. The replies come from the same functions the firmware's dispatcher (`handle` in `rust/firmware/src/main.rs`) calls,
//! so Web Serial and `POST /serial` carry exactly these bytes.
//!
//! The app's real classes are also run against these replies by `rust/tools/android_replay.sh` (it compiles the app's `core` sources with
//! a fake serial transport); with `TDONGLE_ANDROID_REPLAY_OUT=<dir>` this test writes the fixtures that script reads.

use regex::Regex;
use std::collections::BTreeMap;
use tdongle_nvs_format::metadata_json::metadata_parse_json;
use tdongle_nvs_format::wifi_meta::{MetaSet, MetaSlot};
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedProfile};
use tdongle_serial::clock::Clock;
use tdongle_serial::command::Command;
use tdongle_serial::memory_log::MemoryLog;
use tdongle_serial::reply::{self, ListLine};
use tdongle_serial::status::{DisplayState, Mode, Prefs, Snapshot, Temperature, Traffic, write_status};
use tdongle_serial::wifi_link::{Events, Info};

fn whole(re: &str) -> Regex {
    Regex::new(&format!(r"\A(?:{re})\z")).unwrap()
}

/// `ManagementClient.identify`.
fn identifies(help: &str) -> bool {
    let tailnet = help.contains("T-Dongle tailnet gateway protocol=1\r\n") && help.contains("Commands: status, list, capabilities, reboot, bootloader.");
    tailnet || (help.contains("Commands: status, list, scan, use N, del N, profile ") && help.contains("Profiles validate by association") && help.contains("bootloader"))
}

/// `Capabilities.parse`: the feature set, or why it is refused.
fn capabilities(reply: &str) -> Result<Vec<String>, &'static str> {
    if reply.len() > 2048 {
        return Err("too large");
    }
    let line_re = whole("capabilities schema=[0-9]{1,3} features=[a-z0-9_,.-]{0,512}");
    let mut descriptor = None;
    for line in Regex::new(r"\r?\n").unwrap().split(reply) {
        if line.is_empty() || line == "done>" {
            continue;
        }
        if descriptor.is_some() || !line_re.is_match(line) {
            return Err("unsupported");
        }
        descriptor = Some(line);
    }
    let d = descriptor.ok_or("missing")?;
    let schema: u32 = d["capabilities schema=".len()..d.find(" features=").unwrap()].parse().unwrap();
    assert_eq!(schema, 1, "schema 1, or the app falls back to legacy");
    let values = &d[d.find(" features=").unwrap() + 10..];
    let mut out: Vec<String> = Vec::new();
    for v in values.split(',') {
        if v.is_empty() || out.iter().any(|o| o == v) {
            return Err("ambiguous");
        }
        out.push(v.to_string());
    }
    Ok(out)
}

fn help(tailnet: bool) -> String {
    let mut s = String::new();
    reply::write_help_firmware(&mut s, tailnet, ", mode wifi_bridge|tailnet_gateway").unwrap();
    s
}

fn caps(tailnet_running: bool, mode_switch: bool) -> String {
    let mut s = String::new();
    reply::write_capabilities_firmware(&mut s, tailnet_running, mode_switch).unwrap();
    s
}

#[test]
fn help_identifies_as_supported_firmware_in_both_modes() {
    for tailnet in [false, true] {
        let h = help(tailnet);
        assert!(identifies(&h), "{h}");
        // the app turns on `capabilities` only if help names it
        assert!(h.contains("capabilities"));
        assert!(h.starts_with(if tailnet { "T-Dongle tailnet gateway protocol=1\r\n" } else { "T-Dongle Wi-Fi bridge protocol=1\r\n" }));
        assert!(h.len() < 16384);
    }
}

#[test]
fn capabilities_parse_and_cover_every_feature_the_app_gates_on() {
    for (tailnet, mode_switch) in [(false, false), (false, true), (true, true)] {
        let f = capabilities(&caps(tailnet, mode_switch)).unwrap();
        // ManagementClient.requireCapability / DongleController.supports
        for needed in ["boot_diagnostics", "display_readback", "metadata", "chip_temperature", "automatic_display"] {
            assert!(f.iter().any(|x| x == needed), "{needed} missing from {f:?}");
        }
        assert_eq!(f.iter().any(|x| x == "mode_switch"), mode_switch);
        assert_eq!(f.iter().any(|x| x == "tailnet_gateway"), tailnet);
        assert_eq!(f.iter().any(|x| x == "roaming_assist"), !tailnet);
        // every one is something the unified C or the companion C advertises: no invented names
        for x in &f {
            assert!(
                [
                    "tailnet_gateway",
                    "boot_diagnostics",
                    "mode_switch",
                    "chip_temperature",
                    "automatic_display",
                    "power_report",
                    "setup_ap",
                    "button_menu",
                    "factory_reset",
                    "status_led",
                    "display_pages",
                    "display_settings",
                    "roaming_assist",
                    "metadata",
                    "display_readback"
                ]
                .contains(&x.as_str()),
                "{x}"
            );
        }
    }
    // the C unified bridge line is a prefix of ours (same order), with the companion's two after it
    assert_eq!(
        caps(false, true),
        "capabilities schema=1 features=boot_diagnostics,mode_switch,chip_temperature,automatic_display,power_report,setup_ap,button_menu,\
         factory_reset,status_led,display_pages,display_settings,roaming_assist,metadata,display_readback\r\n"
    );
    assert_eq!(
        caps(true, true),
        "capabilities schema=1 features=tailnet_gateway,boot_diagnostics,mode_switch,chip_temperature,automatic_display,power_report,setup_ap,\
         button_menu,factory_reset,status_led,display_pages,display_settings,metadata,display_readback\r\n"
    );
}

#[test]
fn the_new_commands_parse() {
    assert_eq!(Command::parse("display-settings"), Command::DisplaySettings);
    assert_eq!(Command::parse("preference"), Command::Preference);
    assert_eq!(Command::parse("metadata {}"), Command::Metadata("{}"));
    assert_eq!(Command::parse("retry-startup"), Command::RetryStartup);
    // strcmp / strncmp: no trailing space, the space after `metadata` is required
    assert_eq!(Command::parse("preference "), Command::Unknown);
    assert_eq!(Command::parse("metadata"), Command::Unknown);
    assert_eq!(Command::parse("display-settings x"), Command::Unknown);
}

/// `DisplaySettings.parse`.
#[test]
fn display_settings_reply() {
    let re = whole(r"display-settings brightness=([0-9]{1,3}) rotation=([01]) dim_seconds=([0-9]{1,4})(?:\r?\n(?:done>\r?\n)?)?");
    for (b, r, d) in [(5, 0, 10), (60, 1, 60), (100, 1, 3600)] {
        let mut s = String::new();
        reply::write_display_settings(&mut s, b, r, d).unwrap();
        let m = re.captures(&s).unwrap_or_else(|| panic!("{s:?}"));
        assert_eq!((&m[1], &m[2], &m[3]), (b.to_string().as_str(), r.to_string().as_str(), d.to_string().as_str()));
        assert!(re.is_match(&format!("{s}done>\r\n")));
    }
}

/// `ManagementClient.preferred`.
#[test]
fn preference_reply() {
    let re = whole(r"preferred=([0-8])(?:\r?\n(?:done>\r?\n)?)?");
    for (p, count, want) in [(None, 3, "0"), (Some(0), 3, "1"), (Some(2), 3, "3"), (Some(3), 3, "0"), (Some(7), 8, "8")] {
        let mut s = String::new();
        reply::write_preference(&mut s, p, count).unwrap();
        assert_eq!(&re.captures(&s).unwrap()[1], want);
    }
}

#[test]
fn acknowledgements_the_app_checks_with_starts_with() {
    assert!(reply::METADATA_SAVED.starts_with("OK metadata saved; association unchanged")); // ManagementClient.metadata
    assert!(reply::RETRY_STARTUP_OK.starts_with("OK restarting services")); // ManagementClient.retryStartup
    assert!(reply::MODE_SAVED.starts_with("OK mode saved; restarting")); // ManagementClient.routingMode
    assert!(reply::BOOTLOADER_OK.contains("OK rebooting into ROM download mode")); // ManagementClient.enterBootloader
    // every refusal starts with ERR, which `command()` turns into an error without retrying
    for e in [reply::METADATA_INVALID, reply::METADATA_NOT_SAVED, reply::METADATA_UNAVAILABLE, reply::RETRY_STARTUP_FAILED] {
        assert!(e.starts_with("ERR"), "{e}");
    }
}

fn saved(networks: &[(&[u8], &[u8], u8)]) -> (SavedNetworks, MetaSet) {
    let mut l = SavedNetworks::default();
    let mut m = MetaSet::defaults(&[]);
    for (i, (ssid, name, priority)) in networks.iter().enumerate() {
        let mut p = SavedProfile::EMPTY;
        p.ssid[..ssid.len()].copy_from_slice(ssid);
        l.profiles[i] = p;
        let mut s = MetaSlot::EMPTY;
        s.name[..name.len()].copy_from_slice(name);
        s.priority = *priority;
        m.slot[i] = s;
    }
    l.count = networks.len();
    m.preferred = Some(0);
    (l, m)
}

fn list_text(l: &SavedNetworks, m: &MetaSet, current: Option<usize>) -> String {
    let mut s = String::new();
    for (i, p) in l.list().iter().enumerate() {
        s.push_str(std::str::from_utf8(ListLine::new(i as u32, current == Some(i), m.slot[i].name_bytes(), p.ssid_bytes(), m.slot[i].priority).as_bytes()).unwrap());
    }
    s
}

/// `SavedNetwork.parse` (slot, name, ssid, priority).
fn parse_list(reply: &str) -> Vec<(u32, String, String, u32)> {
    let re = Regex::new(r"^([1-8])(\*)? name=(.{1,24}) ssid=(.{1,32}) priority=(\d{1,3})$").unwrap();
    let mut out = Vec::new();
    for line in Regex::new(r"\r?\n").unwrap().split(reply) {
        if line.trim().is_empty() || line == "tdongle>" || line == "done>" {
            continue;
        }
        let c = re.captures(line).unwrap_or_else(|| panic!("list row rejected: {line:?}"));
        out.push((c[1].parse().unwrap(), c[3].to_string(), c[4].to_string(), c[5].parse().unwrap()));
    }
    out
}

/// `ManagementClient.metadata`: the line it sends, the acknowledgement, then the read-back of `list` and `preference` it insists on.
#[test]
fn metadata_round_trip_as_the_app_does_it() {
    let (l, m) = saved(&[(b"Office", b"Office", 50), (b"Cafe", b"Corner cafe", 40)]);
    let before = parse_list(&list_text(&l, &m, Some(0)));
    assert_eq!(before[1], (2, "Corner cafe".into(), "Cafe".into(), 40));
    let line = "metadata {\"slot\":2,\"expectedName\":\"Corner cafe\",\"expectedSsid\":\"Cafe\",\"expectedPriority\":40,\"name\":\"Cafe 2\",\"priority\":90,\"preferred\":true}";
    let Command::Metadata(json) = Command::parse(line) else { panic!() };
    let after_meta = metadata_parse_json(json.as_bytes()).unwrap().apply(&l, &m).unwrap();
    let after = parse_list(&list_text(&l, &after_meta, Some(0)));
    assert_eq!(after[1], (2, "Cafe 2".into(), "Cafe".into(), 90));
    assert_eq!(after[0], before[0]);
    let mut p = String::new();
    reply::write_preference(&mut p, after_meta.preferred, l.count).unwrap();
    assert_eq!(p, "preferred=2\r\n");
    // the same write again is a stale identity: refused, and nothing changes
    assert_eq!(metadata_parse_json(json.as_bytes()).unwrap().apply(&l, &after_meta), None);
}

fn status(t: Temperature) -> String {
    let log = MemoryLog::new();
    let s = Snapshot {
        mode: Mode::Adapter,
        wifi_current: 0,
        online: true,
        firmware: "0.3.0-dev",
        usb_mounted: true,
        usb_ready: true,
        uptime_ms: 60_000,
        free_heap: 100_000,
        temperature: t,
        clock: Clock::default(),
        clock_valid: false,
        link: Info::default(),
        events: Events::default(),
        prefs: Prefs { saved: 1, preferred: Some(0), priorities: &[50], roaming_assist: true },
        display: DisplayState { brightness: 60, rotation: 0, dim_seconds: 60, page: 0 },
        setup_ap_name: "-",
        setup_seconds_left: 0,
        traffic: Traffic::default(),
        memory: &log,
    };
    let mut out = String::new();
    write_status(&mut out, &s).unwrap();
    out
}

fn temperature(current: i32, peak: i32) -> Temperature {
    Temperature { valid: true, current_tenths: current, peak_tenths: peak, sampled_at_ms: 50_000, errors: 0, samples: 3, changed_at_ms: 40_000, age_ms: 10_000 }
}

/// The app's `DongleStatus` temperature pattern, before and after the fix that accepts a reading below zero.
const TEMPERATURE_APP: &str = r"(?m)^chip_temperature valid=1 current_tenths=([0-9]{1,4}) peak_tenths=([0-9]{1,4}) sampled_uptime_ms=[0-9]+ errors=[0-9]+\r?$";
const TEMPERATURE_APP_FIXED: &str = r"(?m)^chip_temperature valid=1 current_tenths=(-?[0-9]{1,4}) peak_tenths=(-?[0-9]{1,4}) sampled_uptime_ms=[0-9]+ errors=[0-9]+\r?$";

#[test]
fn status_first_line_and_chip_temperature() {
    let first = Regex::new(
        r"(?m)^mode=(adapter|setup|tailnet) trial=([01]) active=([0-8]) wifi=(up|joining|AP not found|auth failed) rssi=(?:unknown|-?\d+) usb_enumerated=([01]) usb_transport_ready=([01]) host_interface_ready=unknown internet=not_checked(?: firmware=[0-9A-Za-z][0-9A-Za-z.+_-]{0,63})?\r?$",
    )
    .unwrap();
    let warm = status(temperature(553, 600));
    let c = first.captures(&warm).expect("DongleStatus.parse");
    assert_eq!((&c[1], &c[2], &c[3]), ("adapter", "0", "1"));
    let t = Regex::new(TEMPERATURE_APP).unwrap().captures(&warm).expect("a valid reading is shown");
    assert_eq!((&t[1], &t[2]), ("553", "600"));
    // a reading below zero (a cold start outdoors): only the fixed pattern shows it
    let cold = status(temperature(-52, 15));
    assert!(Regex::new(TEMPERATURE_APP).unwrap().captures(&cold).is_none());
    let t = Regex::new(TEMPERATURE_APP_FIXED).unwrap().captures(&cold).unwrap();
    assert_eq!((&t[1], &t[2]), ("-52", "15"));
    // not sampled yet: valid=0, the app shows "unavailable"
    let none = status(Temperature::default());
    assert!(Regex::new(TEMPERATURE_APP_FIXED).unwrap().captures(&none).is_none());
}

/// `ScanNetwork.parse`: the C line (`ssid=%s rssi=%d auth=%d`), at most 20 rows; nothing else may be on a line.
#[test]
fn scan_lines() {
    let re = whole(r"ssid=(.{0,32}) rssi=(-?[0-9]{1,3}) auth=([0-9]{1,2})");
    let mut s = String::new();
    let mut ssid = [0u8; 32];
    ssid[..4].copy_from_slice(b"Cafe");
    reply::write_scan_line(&mut s, &ssid, -50, 3).unwrap();
    let mut bad = [0u8; 32];
    bad[..3].copy_from_slice(&[b'a', 0x07, 0xff]);
    reply::write_scan_line(&mut s, &bad, -90, 0).unwrap();
    for line in s.lines() {
        assert!(re.is_match(line), "{line:?}");
    }
    assert!(s.contains("ssid=a?? rssi=-90 auth=0"));
}

/// Writes the fixtures `rust/tools/android_replay.sh` feeds to the app's own classes, when asked.
#[test]
fn write_replay_fixtures() {
    let Some(dir) = std::env::var_os("TDONGLE_ANDROID_REPLAY_OUT") else { return };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (l, m) = saved(&[(b"Office", b"Office", 50), (b"Cafe", b"Corner cafe", 40)]);
    let edit_line = "metadata {\"slot\":2,\"expectedName\":\"Corner cafe\",\"expectedSsid\":\"Cafe\",\"expectedPriority\":40,\"name\":\"Cafe 2\",\"priority\":90,\"preferred\":true}";
    let Command::Metadata(json) = Command::parse(edit_line) else { panic!() };
    let m2 = metadata_parse_json(json.as_bytes()).unwrap().apply(&l, &m).unwrap();
    let pref = |m: &MetaSet| {
        let mut s = String::new();
        reply::write_preference(&mut s, m.preferred, l.count).unwrap();
        s
    };
    let ds = |b, r, d| {
        let mut s = String::new();
        reply::write_display_settings(&mut s, b, r, d).unwrap();
        s
    };
    let mut scan = String::new();
    for (name, rssi, auth) in [(&b"Cafe"[..], -50i8, 3), (&b"Office"[..], -61, 4)] {
        let mut ssid = [0u8; 32];
        ssid[..name.len()].copy_from_slice(name);
        reply::write_scan_line(&mut scan, &ssid, rssi, auth).unwrap();
    }
    // state "base"; the fake switches to the state named after a write that changes something
    let mut fx: BTreeMap<(String, String), String> = BTreeMap::new();
    for tailnet in [false, true] {
        let mode = if tailnet { "tailnet" } else { "bridge" };
        let mut put = |state: &str, line: &str, reply: String| {
            fx.insert((format!("{mode}/{state}"), line.to_string()), reply);
        };
        put("base", "help", help(tailnet));
        put("base", "capabilities", caps(tailnet, true));
        put("base", "status", status(temperature(-52, 615)));
        put("base", "list", list_text(&l, &m, Some(0)));
        put("base", "preference", pref(&m));
        put("base", "display-settings", ds(60, 0, 60));
        put("base", "scan", scan.clone());
        put("base", edit_line, String::from(reply::METADATA_SAVED));
        put("base", "display 80 1 120", String::from(reply::DISPLAY_SAVED));
        put("base", "retry-startup", String::from(reply::RETRY_STARTUP_OK));
        put("metadata", "status", status(temperature(-52, 615)));
        put("metadata", "list", list_text(&l, &m2, Some(0)));
        put("metadata", "preference", pref(&m2));
        put("display", "display-settings", ds(80, 1, 120));
        put("display", "status", status(temperature(-52, 615)));
    }
    let mut out = Vec::new();
    for ((state, line), reply) in &fx {
        out.extend_from_slice(format!("@@@@ {state} LEN {} LINE {line}\n", reply.len()).as_bytes());
        out.extend_from_slice(reply.as_bytes());
    }
    std::fs::write(dir.join("replies.fixture"), out).unwrap();
}
