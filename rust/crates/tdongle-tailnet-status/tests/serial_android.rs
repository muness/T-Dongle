//! The serial `status` text of the tailnet mode against what the Android app parses (tools/check-android-status.py of the C tree).
//!
//! The text comes from tdongle-serial (the port of `serial_status()`): this proves the integration the way the C proves its own, with the same 16
//! mode / uplink / USB combinations, the same parameters, and the same rule that nothing may be appended to the `chip_temperature` line.
//!   * the first block equals, byte for byte, what the C formatter prints (tests/golden/android_responses.txt is the `responses.txt` of the real
//!     check-android-status.py run);
//!   * the end-anchored `chip_temperature` rule holds on the whole report;
//!   * when a JDK 17 and the Android tree are available (JAVA_HOME or ~/.local/share/mise/installs/java/temurin-17; TDONGLE_ANDROID or
//!     ~/src/tdongle-android/.worktrees/multi-tailnet) the real `DongleStatus.parse` accepts every reply.

use tdongle_serial::clock::Clock;
use tdongle_serial::memory_log::MemoryLog;
use tdongle_serial::status::{DisplayState, Mode, Prefs, Snapshot, Temperature, Traffic, write_status};
use tdongle_serial::wifi_link::{Events, Info};

fn reply(i: usize, memory: &MemoryLog) -> String {
    let (tailnet, online, mounted, ready) = (i >= 8, (i % 8) >= 4, (i & 2) != 0, (i & 1) != 0);
    let s = Snapshot {
        mode: if tailnet { Mode::Tailnet } else { Mode::Adapter },
        wifi_current: 0,
        online,
        firmware: "0.0.0-host",
        usb_mounted: mounted,
        usb_ready: ready,
        uptime_ms: 1234,
        free_heap: 219_640,
        temperature: Temperature { valid: true, current_tenths: 553, peak_tenths: 600, ..Temperature::default() },
        clock: Clock::default(),
        clock_valid: online,
        link: Info { connected: online, rssi_valid: online, rssi: -61, ..Info::default() },
        events: Events::default(),
        prefs: Prefs { saved: 0, preferred: None, priorities: &[], roaming_assist: false },
        display: DisplayState { brightness: 60, rotation: 0, dim_seconds: 60, page: 0 },
        setup_ap_name: "",
        setup_seconds_left: 0,
        traffic: Traffic::default(),
        memory,
    };
    let mut out = String::new();
    write_status(&mut out, &s).unwrap();
    out
}

fn replies() -> Vec<String> {
    let log = MemoryLog::new();
    (0..16).map(|i| reply(i, &log)).collect()
}

/// The first block of a reply: through the `chip_temperature_detail` line (the C script's formatter is exactly that one snprintf).
fn first_block(r: &str) -> &str {
    let end = r.find("chip_temperature_detail").unwrap();
    let eol = r[end..].find("\r\n").unwrap() + end + 2;
    &r[..eol]
}

#[test]
fn first_block_equals_the_c_formatter_output() {
    let golden = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/android_responses.txt")).unwrap();
    let want: Vec<&str> = golden.split('\u{c}').filter(|s| !s.is_empty()).collect();
    assert_eq!(want.len(), 16);
    for (i, (r, w)) in replies().iter().zip(want).enumerate() {
        // C: reply + "done>\r\n" + "\f"; the first mode/wifi/usb fields differ per combination, so compare the whole first block.
        assert_eq!(format!("{}done>\r\n", first_block(r)), w, "combination {i}");
    }
}

#[test]
fn chip_temperature_line_is_end_anchored_and_nothing_follows_errors() {
    for (i, r) in replies().iter().enumerate() {
        let line = r.split("\r\n").find(|l| l.starts_with("chip_temperature ")).unwrap_or_else(|| panic!("combination {i}"));
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 6, "{line}");
        let names = ["chip_temperature", "valid=", "current_tenths=", "peak_tenths=", "sampled_uptime_ms=", "errors="];
        assert_eq!(f[0], names[0]);
        for (k, n) in names.iter().enumerate().skip(1) {
            let v = f[k].strip_prefix(n).unwrap_or_else(|| panic!("{line}"));
            assert!(!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()), "{line}");
        }
        assert!(r.contains("\r\nchip_temperature_detail age_ms="));
    }
}

#[test]
fn android_production_parser_accepts_every_reply() {
    let home = std::env::var("HOME").unwrap_or_default();
    let java_home = std::env::var("JAVA_HOME").unwrap_or_else(|_| format!("{home}/.local/share/mise/installs/java/temurin-17"));
    let android = std::env::var("TDONGLE_ANDROID").unwrap_or_else(|_| format!("{home}/src/tdongle-android/.worktrees/multi-tailnet"));
    let javac = format!("{java_home}/bin/javac");
    let source = format!("{android}/core/src/main/java/com/muness/tdongle/core");
    if !std::path::Path::new(&javac).exists() || !std::path::Path::new(&format!("{source}/DongleStatus.java")).exists() {
        eprintln!("skipped: no JDK ({javac}) or Android tree ({source})");
        return;
    }
    let dir = std::env::temp_dir().join(format!("tdongle-status-contract-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let responses: String = replies().iter().map(|r| format!("{}done>\r\n\u{c}", first_block(r))).collect();
    std::fs::write(dir.join("responses.txt"), responses).unwrap();
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tools/StatusContract.java"), dir.join("StatusContract.java")).unwrap();
    let compile = std::process::Command::new(&javac)
        .args([
            "-d",
            dir.to_str().unwrap(),
            &format!("{source}/DongleStatus.java"),
            &format!("{source}/Telemetry.java"),
            dir.join("StatusContract.java").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
    let run = std::process::Command::new(format!("{java_home}/bin/java"))
        .args(["-cp", dir.to_str().unwrap(), "StatusContract", dir.join("responses.txt").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(run.status.success(), "{}{}", String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr));
    std::fs::remove_dir_all(&dir).ok();
}
