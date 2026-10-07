//! `help` must list exactly what an image implements: every listed command parses to a real command, and the text carries all of them and nothing else.

use tdongle_serial::command::Command;
use tdongle_serial::reply::{FIRMWARE_EXTENSIONS, IDENTITY_COMMAND_FORMS, SPIKE_S3_COMMANDS, write_capabilities_implemented, write_help_firmware};

/// A concrete line for a help entry: `use N` -> `use 1`, `heap [on|off]` -> `heap`.
fn example(entry: &str) -> String {
    let e = entry.replace(" N", " 1").replace("BRIGHTNESS ROTATION DIM_SECONDS", "60 0 60").replace(" JSON", " {}").replace("wifi_bridge|tailnet_gateway", "wifi_bridge");
    e.split(" [").next().unwrap().split(" RATE").next().unwrap().replace(" bridge|sink|source", "").to_string()
}

#[test]
fn every_firmware_command_in_help_is_parsed_and_the_text_has_no_extras() {
    let forms = IDENTITY_COMMAND_FORMS.iter().chain(FIRMWARE_EXTENSIONS).chain(MODE);
    for entry in forms {
        let line = example(entry);
        assert_ne!(Command::parse(&line), Command::Unknown, "`{entry}` is in help but parses as unknown ({line})");
    }
    for tailnet in [false, true] {
        let mut text = String::new();
        write_help_firmware(&mut text, tailnet, ", mode wifi_bridge|tailnet_gateway").unwrap();
        assert_eq!(text.lines().count(), 2);
        let listed = text.lines().nth(1).unwrap().split("Extensions: ").nth(1).unwrap().strip_suffix('.').unwrap();
        let listed: Vec<&str> = listed.split(", ").collect();
        assert_eq!(listed, FIRMWARE_EXTENSIONS.iter().chain(MODE).copied().collect::<Vec<_>>());
        assert!(!text.contains("crypto bench"), "not implemented, must not be advertised");
        assert_eq!(tdongle_serial::reply::EXTENSIONS, FIRMWARE_EXTENSIONS.join(", "));
        // the identity part names exactly the forms of IDENTITY_COMMAND_FORMS (the `profile` example stands for `profile JSON`)
        for form in IDENTITY_COMMAND_FORMS {
            let word = form.split(' ').next().unwrap();
            assert!(text.contains(word), "{form}");
        }
    }
}

const MODE: &[&str] = &["mode wifi_bridge|tailnet_gateway"];

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
