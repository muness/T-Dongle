//! `Command::parse`: the dispatch of `command_task` and `gateway_serial_command`, including the exact matching rules.

use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_serial::command::{Command, Diagnostic, DisplayArgs, SetupArg, SlotArg, strtol, strtoul};

fn parse(line: &str) -> Command<'_> {
    Command::parse(line)
}

#[test]
fn whole_line_commands_match_exactly() {
    assert_eq!(parse("help"), Command::Help);
    assert_eq!(parse("capabilities"), Command::Capabilities);
    assert_eq!(parse("pm"), Command::Pm);
    assert_eq!(parse("status"), Command::Status);
    assert_eq!(parse("boot-status"), Command::BootStatus);
    assert_eq!(parse("retry-startup"), Command::RetryStartup);
    assert_eq!(parse("crypto bench"), Command::CryptoBench);
    assert_eq!(parse("scan"), Command::Scan);
    assert_eq!(parse("cancel"), Command::Cancel);
    assert_eq!(parse("reset"), Command::Reset);
    assert_eq!(parse("confirm-reset"), Command::ConfirmReset);
    assert_eq!(parse("list"), Command::List);
    assert_eq!(parse("reboot"), Command::Reboot);
    assert_eq!(parse("bootloader"), Command::Bootloader);
}

#[test]
fn strcmp_commands_reject_any_extra_character() {
    for line in [
        "",
        " ",
        "help ",
        " help",
        "Help",
        "HELP",
        "helpx",
        "status ",
        "list ",
        "list x",
        "scan ",
        "scan x",
        "cancelled",
        "cancel ",
        "resetx",
        "reset ",
        "reset now",
        "confirm-reset ",
        "confirm-resetx",
        "pm ",
        "pm x",
        "reboot ",
        "reboot now",
        "bootloader ",
        "crypto",
        "crypto bench ",
        "crypto  bench",
        "boot-status ",
        "retry-startup x",
        "capabilities ",
        "setupx",
        "nonsense",
        "mode",
        "use",
        "del",
        "profile",
        "displays",
        "displayX 1 2 3",
    ] {
        assert_eq!(parse(line), Command::Unknown, "{line:?}");
    }
}

#[test]
fn a_cr_or_nul_inside_the_line_is_not_whitespace() {
    assert_eq!(parse("help\r"), Command::Unknown);
    assert_eq!(parse("help\0junk"), Command::Help, "C strings end at the NUL");
    assert_eq!(parse("\0help"), Command::Unknown);
}

#[test]
fn mode_needs_the_trailing_space() {
    assert_eq!(parse("mode wifi_bridge"), Command::Mode(Some(Mode::WifiBridge)));
    assert_eq!(parse("mode tailnet_gateway"), Command::Mode(Some(Mode::TailnetGateway)));
    assert_eq!(parse("mode "), Command::Mode(None));
    assert_eq!(parse("mode bridge"), Command::Mode(None));
    assert_eq!(parse("mode  wifi_bridge"), Command::Mode(None), "a second space is part of the name");
    assert_eq!(parse("mode wifi_bridge "), Command::Mode(None));
    assert_eq!(parse("mode Wifi_bridge"), Command::Mode(None));
    assert_eq!(parse("mode"), Command::Unknown);
    assert_eq!(parse("modex wifi_bridge"), Command::Unknown);
}

#[test]
fn display_is_the_word_alone_or_the_word_a_space_and_anything() {
    assert_eq!(parse("display"), Command::Display(DisplayArgs::Show));
    assert_eq!(parse("display 85 1 300"), Command::Display(DisplayArgs::Set(UiSettings { brightness: 85, rotation: 1, dim_seconds: 300 })));
    assert_eq!(parse("display 5 0 10"), Command::Display(DisplayArgs::Set(UiSettings { brightness: 5, rotation: 0, dim_seconds: 10 })));
    assert_eq!(parse("display 100 1 3600"), Command::Display(DisplayArgs::Set(UiSettings { brightness: 100, rotation: 1, dim_seconds: 3600 })));
    // The bad list of tests/test_serial_commands.c `display_command`.
    for bad in [
        "display 4 0 60",
        "display 101 0 60",
        "display 60 2 60",
        "display 60 0 9",
        "display 60 0 3601",
        "display 60",
        "display 60 0",
        "display 60 0 60 1",
        "display x 0 60",
        "display 60 0 60x",
        "display  ",
        "display -5 0 60",
        "display ",
    ] {
        assert_eq!(parse(bad), Command::Display(DisplayArgs::Invalid), "{bad:?}");
    }
    assert_eq!(parse("displays"), Command::Unknown);
    assert_eq!(parse("displayX 1 2 3"), Command::Unknown);
    assert_eq!(parse("display\t60 0 60"), Command::Unknown);
}

#[test]
fn setup_takes_an_optional_saved_network_number() {
    assert_eq!(parse("setup"), Command::Setup(SetupArg::Open));
    assert_eq!(parse("setup 3"), Command::Setup(SetupArg::Slot(3)));
    assert_eq!(parse("setup 1"), Command::Setup(SetupArg::Slot(1)));
    assert_eq!(parse("setup 8"), Command::Setup(SetupArg::Slot(8)));
    // tests/test_serial_commands.c `setup_command`: the bad list, plus a few strtol forms.
    for bad in ["setup 0", "setup 9", "setup x", "setup 2x", "setup -1", "setup ", "setup 3 ", "setup 99999999999", "setup  9", "setup +0", "setup 1.5"] {
        assert_eq!(parse(bad), Command::Setup(SetupArg::Invalid), "{bad:?}");
    }
    // strtol forms that C accepts: leading white space and a plus sign.
    assert_eq!(parse("setup  3"), Command::Setup(SetupArg::Slot(3)));
    assert_eq!(parse("setup +3"), Command::Setup(SetupArg::Slot(3)));
    assert_eq!(parse("setup 03"), Command::Setup(SetupArg::Slot(3)));
    assert_eq!(parse("setupx"), Command::Unknown);
    assert_eq!(parse("setup\t3"), Command::Unknown);
}

#[test]
fn use_and_del_read_their_number_with_strtol() {
    assert_eq!(parse("use 2"), Command::Use(SlotArg::Number(2)));
    assert_eq!(parse("del 2"), Command::Del(SlotArg::Number(2)));
    assert_eq!(parse("use  2"), Command::Use(SlotArg::Number(2)), "leading white space");
    assert_eq!(parse("use +2"), Command::Use(SlotArg::Number(2)), "plus sign");
    assert_eq!(parse("use \t 2"), Command::Use(SlotArg::Number(2)));
    assert_eq!(parse("use -1"), Command::Use(SlotArg::Number(-1)));
    assert_eq!(parse("use 0"), Command::Use(SlotArg::Number(0)));
    assert_eq!(parse("use 007"), Command::Use(SlotArg::Number(7)));
    assert_eq!(parse("use "), Command::Use(SlotArg::Number(0)), "no digits reads as 0 with nothing left over");
    assert_eq!(parse("del "), Command::Del(SlotArg::Number(0)));
    // Anything left over, even a space, makes the argument invalid.
    for garbage in ["use 1x", "use x", "use 2 ", "use 1 2", "use +", "use -", "use 0x10", "use 1.5", "del 1x", "del 2 "] {
        let command = parse(garbage);
        assert!(matches!(command, Command::Use(SlotArg::TrailingGarbage) | Command::Del(SlotArg::TrailingGarbage)), "{garbage:?} -> {command:?}");
    }
    // 32 bit `long`: saturates.
    assert_eq!(parse("use 99999999999"), Command::Use(SlotArg::Number(i32::MAX)));
    assert_eq!(parse("use -99999999999"), Command::Use(SlotArg::Number(i32::MIN)));
    assert_eq!(parse("use"), Command::Unknown);
    assert_eq!(parse("user 2"), Command::Unknown);
}

#[test]
fn profile_keeps_the_text_after_the_space() {
    assert_eq!(parse("profile {\"slot\":1}"), Command::Profile("{\"slot\":1}"));
    assert_eq!(parse("profile "), Command::Profile(""));
    assert_eq!(parse("profile  x"), Command::Profile(" x"));
    assert_eq!(parse("profile"), Command::Unknown);
    assert_eq!(parse("profiles x"), Command::Unknown);
}

#[test]
fn the_diagnostics_commands_exist_only_in_the_diagnostics_image() {
    let d = Command::parse_with_diagnostics;
    for line in [
        "memory",
        "bridge",
        "bridgetune",
        "bridgetune q=3",
        "memory low",
        "wifistats",
        "wifistats reset",
        "wifistats dump",
        "cpu",
        "wgperf",
        "wgperf reset",
        "wgperf logbench",
        "route",
        "inbound",
        "members",
        "memory locks",
        "memory bench",
        "memory guard",
        "memory guard 100",
    ] {
        assert_eq!(Command::parse(line), Command::Unknown, "release: {line:?}");
        assert!(matches!(d(line), Command::Diagnostic(_)), "diagnostics: {line:?}");
    }
    assert_eq!(d("memory"), Command::Diagnostic(Diagnostic::Memory));
    assert_eq!(d("bridgetune"), Command::Diagnostic(Diagnostic::BridgeTune("")));
    assert_eq!(d("bridgetune q=3 resume=1"), Command::Diagnostic(Diagnostic::BridgeTune(" q=3 resume=1")));
    assert_eq!(d("bridgetunex"), Command::Unknown);
    assert_eq!(d("memory guard 0"), Command::Diagnostic(Diagnostic::MemoryGuard(Some(0))));
    assert_eq!(d("memory guard 65536"), Command::Diagnostic(Diagnostic::MemoryGuard(Some(65536))));
    for bad in ["memory guard", "memory guard ", "memory guard 65537", "memory guard x", "memory guard 5x", "memory guard -1", "memory guard 5 "] {
        assert_eq!(d(bad), Command::Diagnostic(Diagnostic::MemoryGuard(None)), "{bad:?}");
    }
    // strtoul accepts "-0" (modular negation) and a leading plus.
    assert_eq!(d("memory guard -0"), Command::Diagnostic(Diagnostic::MemoryGuard(Some(0))));
    assert_eq!(d("memory guard +7"), Command::Diagnostic(Diagnostic::MemoryGuard(Some(7))));
    assert_eq!(d("memory guardx"), Command::Unknown);
    // The serial set and `reboot`/`bootloader` keep their order relative to the diagnostics set.
    assert_eq!(d("reboot"), Command::Reboot);
    assert_eq!(d("status"), Command::Status);
    assert_eq!(d("pm"), Command::Pm);
}

#[test]
fn strtol_follows_the_c_library() {
    assert_eq!(strtol("42"), (42, ""));
    assert_eq!(strtol("42abc"), (42, "abc"));
    assert_eq!(strtol("  \t\n\u{b}\u{c}\r-7 rest"), (-7, " rest"));
    assert_eq!(strtol("+5"), (5, ""));
    assert_eq!(strtol(""), (0, ""));
    assert_eq!(strtol("abc"), (0, "abc"));
    assert_eq!(strtol("  abc"), (0, "  abc"), "no digits: end is the start of the input");
    assert_eq!(strtol("-"), (0, "-"));
    assert_eq!(strtol("+ 1"), (0, "+ 1"));
    assert_eq!(strtol("- 1"), (0, "- 1"));
    assert_eq!(strtol("--1"), (0, "--1"));
    assert_eq!(strtol("2147483647"), (i32::MAX, ""));
    assert_eq!(strtol("2147483648"), (i32::MAX, ""));
    assert_eq!(strtol("-2147483648"), (i32::MIN, ""));
    assert_eq!(strtol("-2147483649"), (i32::MIN, ""));
    assert_eq!(strtol("99999999999999999999999999"), (i32::MAX, ""));
    assert_eq!(strtol("0x1f"), (0, "x1f"), "base 10: the 0 is the number");
    assert_eq!(strtol("1e3"), (1, "e3"));
}

#[test]
fn strtoul_follows_the_c_library_on_a_32_bit_long() {
    assert_eq!(strtoul("42"), (42, ""));
    assert_eq!(strtoul("-1"), (u32::MAX, ""), "negation wraps");
    assert_eq!(strtoul("-0"), (0, ""));
    assert_eq!(strtoul("4294967295"), (u32::MAX, ""));
    assert_eq!(strtoul("4294967296"), (u32::MAX, ""), "saturates");
    assert_eq!(strtoul("-4294967296"), (u32::MAX, ""), "out of range is ULONG_MAX whatever the sign");
    assert_eq!(strtoul("-4294967295"), (1, ""));
    assert_eq!(strtoul("  +9x"), (9, "x"));
    assert_eq!(strtoul("x"), (0, "x"));
    assert_eq!(strtoul(""), (0, ""));
}

#[test]
fn commands_do_not_overlap_in_the_dispatch_order() {
    // `status` is handled by command_task before gateway_serial_command: still Status.
    assert_eq!(parse("status"), Command::Status);
    // Prefix commands keep their space: "use" alone is unknown, "use 1" is use.
    assert_eq!(parse("use 1"), Command::Use(SlotArg::Number(1)));
    assert_eq!(parse("del 1"), Command::Del(SlotArg::Number(1)));
    // The line the console delivers is a `&str`: a long one parses like a short one.
    let long = format!("profile {}", "x".repeat(500));
    assert!(matches!(parse(&long), Command::Profile(j) if j.len() == 500));
}
