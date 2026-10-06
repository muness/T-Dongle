//! Helpers shared by the integration tests: the golden container, the scenario tables, and the JSON to struct conversions.
#![allow(dead_code)]

use serde_json::Value;
use std::path::PathBuf;
use tdongle_serial::clock::Clock;
use tdongle_serial::memory_log::Record;
use tdongle_serial::status::Temperature;
use tdongle_serial::wifi_link::{Events, Info};

pub fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// The entries of a `*.golden` container file: `@@@@ SCENARIO <name> LEN <n> @@@@\n<n bytes>\n@@@@ END @@@@\n`.
pub fn golden(file: &str) -> Vec<(String, Vec<u8>)> {
    let data = std::fs::read(golden_dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e} (run tools/regen.sh)"));
    let mut entries = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let rest = &data[at..];
        let newline = rest.iter().position(|&b| b == b'\n').expect("header line");
        let header = std::str::from_utf8(&rest[..newline]).expect("header utf8");
        let words: Vec<&str> = header.split(' ').collect();
        assert!(words.len() == 6 && words[0] == "@@@@" && words[1] == "SCENARIO" && words[3] == "LEN" && words[5] == "@@@@", "{file}: bad header {header:?}");
        let len: usize = words[4].parse().expect("length");
        let body_start = newline + 1;
        let body = rest[body_start..body_start + len].to_vec();
        let trailer = b"\n@@@@ END @@@@\n";
        assert_eq!(&rest[body_start + len..body_start + len + trailer.len()], trailer, "{file}: entry {} not terminated", words[2]);
        entries.push((words[2].to_string(), body));
        at += body_start + len + trailer.len();
    }
    entries
}

pub fn scenarios() -> Value {
    let text = std::fs::read_to_string(golden_dir().join("scenarios.json")).expect("scenarios.json (run tools/regen.sh)");
    serde_json::from_str(&text).expect("scenarios.json parses")
}

pub fn u32_of(v: &Value, key: &str) -> u32 {
    let n = v[key].as_u64().unwrap_or_else(|| panic!("{key} missing in {v}"));
    u32::try_from(n).unwrap_or_else(|_| panic!("{key}={n} not u32"))
}

pub fn i32_of(v: &Value, key: &str) -> i32 {
    let n = v[key].as_i64().unwrap_or_else(|| panic!("{key} missing in {v}"));
    i32::try_from(n).unwrap_or_else(|_| panic!("{key}={n} not i32"))
}

pub fn u8_of(v: &Value, key: &str) -> u8 {
    u8::try_from(u32_of(v, key)).unwrap_or_else(|_| panic!("{key} not u8"))
}

pub fn i8_of(v: &Value, key: &str) -> i8 {
    i8::try_from(i32_of(v, key)).unwrap_or_else(|_| panic!("{key} not i8"))
}

pub fn flag(v: &Value, key: &str) -> bool {
    match &v[key] {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64() != Some(0),
        other => panic!("{key}: {other}"),
    }
}

pub fn link(v: &Value) -> Info {
    Info {
        connected: flag(v, "connected"),
        rssi_valid: flag(v, "rssi_valid"),
        rssi: i8_of(v, "rssi"),
        channel: u8_of(v, "channel"),
        secondary: u8_of(v, "secondary"),
        phy: u8_of(v, "phy"),
        bw_cfg_mhz: u8_of(v, "bw_cfg_mhz"),
        ap_bw_mhz: u8_of(v, "ap_bw_mhz"),
        ap_modes: u8_of(v, "ap_modes"),
        ps: u8_of(v, "ps"),
        tx_power_valid: flag(v, "tx_power_valid"),
        tx_power_qdbm: i8_of(v, "tx_power_qdbm"),
        selected_slot: u8_of(v, "selected_slot"),
        pinned: flag(v, "pinned"),
        pin_failed_slot: u8_of(v, "pin_failed_slot"),
    }
}

pub fn events(v: &Value) -> Events {
    Events {
        connects: u32_of(v, "connects"),
        disconnects: u32_of(v, "disconnects"),
        beacon_timeouts: u32_of(v, "beacon_timeouts"),
        last_disconnect_ms: u32_of(v, "last_disconnect_ms"),
        last_reason: u16::try_from(u32_of(v, "last_reason")).expect("u16"),
        last_disconnect_rssi: i8_of(v, "last_disconnect_rssi"),
        roams: u32_of(v, "roams"),
        ..Events::default()
    }
}

pub fn temperature(v: &Value) -> Temperature {
    Temperature {
        valid: flag(v, "valid"),
        current_tenths: i32_of(v, "current_tenths"),
        peak_tenths: i32_of(v, "peak_tenths"),
        sampled_at_ms: u32_of(v, "sampled_at_ms"),
        errors: u32_of(v, "errors"),
        samples: u32_of(v, "samples"),
        changed_at_ms: u32_of(v, "changed_at_ms"),
        age_ms: u32_of(v, "age_ms"),
    }
}

pub fn clock(v: &Value) -> Clock {
    Clock {
        synced: flag(v, "synced"),
        server: u8_of(v, "server"),
        restarts: u32_of(v, "restarts"),
        backoff_ms: u32_of(v, "backoff_ms"),
        next_retry_ms: v["next_retry_ms"].as_u64().expect("next_retry_ms"),
        retry_in_ms: u32_of(v, "retry_in_ms"),
    }
}

pub fn record(v: &Value) -> Record {
    Record {
        uptime_ms: u32_of(v, "uptime_ms"),
        operation: u32_of(v, "operation"),
        requested: u32_of(v, "requested"),
        free_bytes: u32_of(v, "free_bytes"),
        minimum_bytes: u32_of(v, "minimum_bytes"),
        largest_bytes: u32_of(v, "largest_bytes"),
        failed: u32_of(v, "failed"),
    }
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

/// A `fmt::Write` sink collecting into a `String` (std is fine in tests).
pub fn render(f: impl FnOnce(&mut String) -> core::fmt::Result) -> String {
    let mut s = String::new();
    f(&mut s).expect("write");
    s
}

/// The text of an entry, or a panic naming the missing one.
pub fn entry<'a>(entries: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
    &entries.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("golden entry {name} missing")).1
}
