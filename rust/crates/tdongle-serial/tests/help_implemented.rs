//! `help` must list exactly what an image implements: every listed command parses to a real command, and the text carries all of them and nothing else.

use tdongle_serial::command::Command;
use tdongle_serial::reply::{PHASE1_FIRMWARE_COMMANDS, SPIKE_S3_COMMANDS, write_capabilities_implemented, write_help_implemented};

/// A concrete line for a help entry: `use N` -> `use 1`, `heap [on|off]` -> `heap`.
fn example(entry: &str) -> String {
    entry.replace(" N", " 1").split(" [").next().unwrap().split(" RATE").next().unwrap().replace(" bridge|sink|source", "").to_string()
}

#[test]
fn every_firmware_command_in_help_is_parsed_and_the_text_has_no_extras() {
    for entry in PHASE1_FIRMWARE_COMMANDS.iter().filter(|e| !e.starts_with("selftest")) {
        let line = example(entry);
        assert_ne!(Command::parse(&line), Command::Unknown, "`{entry}` is in help but parses as unknown ({line})");
    }
    let mut text = String::new();
    write_help_implemented(&mut text, "T-Dongle Wi-Fi bridge", PHASE1_FIRMWARE_COMMANDS).unwrap();
    assert_eq!(text.lines().count(), 2);
    let listed: Vec<&str> = text.lines().nth(1).unwrap().strip_prefix("Commands: ").unwrap().split(", ").collect();
    assert_eq!(listed, PHASE1_FIRMWARE_COMMANDS);
    for unimplemented in ["scan", "profile", "del N", "setup", "cancel", "reset", "confirm-reset"] {
        assert!(!listed.contains(&unimplemented), "{unimplemented} is not implemented and must not be advertised");
    }
}

#[test]
fn the_spike_help_lists_list_and_what_the_spike_has() {
    assert!(SPIKE_S3_COMMANDS.contains(&"list"));
    for entry in SPIKE_S3_COMMANDS.iter().filter(|e| ["status", "list", "scan", "capabilities", "boot-status", "bootloader", "help"].contains(e)) {
        assert_ne!(Command::parse(entry), Command::Unknown, "{entry}");
    }
    let mut text = String::new();
    write_capabilities_implemented(&mut text, &["boot_diagnostics"]).unwrap();
    assert_eq!(text, "capabilities schema=1 features=boot_diagnostics\r\n");
}
