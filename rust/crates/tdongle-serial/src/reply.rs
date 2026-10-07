//! Every reply text of the serial console, byte for byte, except the three big reports (`status`, `bridge_*`, `wifi_link`) that have
//! their own modules.
//!
//! Sources: `control.c` (`command_task`), `serial_setup.inc` (`gateway_serial_command` and its helpers). The constants are the literals of
//! those files; the tests compile the real C statements and compare (`tools/gen_golden.py`).
//!
//! `done>\r\n` ([`DONE`]) ends every command in `command_task` *except* the replies that already contain it (the restarting ones) and
//! the commands that never return (`reboot`, `bootloader`, `retry-startup`, `mode`, `setup`, `cancel` in setup, `confirm-reset`): those
//! constants carry their own `done>`.

use crate::text::{ByteLine, emit};
use core::fmt;

/// Ends the reply of a command.
pub const DONE: &str = "done>\r\n";

/// `MEMORY_COMMANDS` of a diagnostics image (`CONFIG_TDONGLE_MEMORY_DIAGNOSTICS`); a release image has `""`.
pub const MEMORY_COMMANDS_DIAGNOSTICS: &str = "memory [guard N|bench], members, cpu, wifistats [reset|dump], ";
/// `MEMORY_FEATURE` of a diagnostics image; a release image has `""`.
pub const MEMORY_FEATURE_DIAGNOSTICS: &str = ",memory_diagnostics,wifi_stats";

macro_rules! commands_common {
    () => {
        "Commands: status, list, use N, del N, scan, profile JSON, display BRIGHTNESS ROTATION DIM_SECONDS, setup [N], cancel, reset, confirm-reset, \
         mode wifi_bridge|tailnet_gateway, capabilities, pm, "
    };
}
macro_rules! help_bridge_head {
    () => {
        concat!("T-Dongle Wi-Fi bridge protocol=1\r\n", commands_common!())
    };
}
macro_rules! help_bridge_tail {
    () => {
        "reboot, bootloader. Add Wi-Fi: hold the button for the setup access point (TDongle-XXXXXX), or profile \
         {\"slot\":N,\"priority\":50,\"name\":\"X\",\"ssid\":\"X\",\"password\":\"X\"}, or muness.com/T-Dongle\r\n"
    };
}
macro_rules! help_tailnet_head {
    () => {
        concat!("T-Dongle tailnet gateway protocol=1\r\n", commands_common!())
    };
}
macro_rules! help_tailnet_tail {
    () => {
        "reboot, bootloader. Setup: http://192.168.77.1/ or the button menu (setup access point)\r\n"
    };
}
macro_rules! caps_bridge {
    () => {
        "capabilities schema=1 features=boot_diagnostics,mode_switch,chip_temperature,automatic_display,power_report,setup_ap,button_menu,\
         factory_reset,status_led,display_pages,display_settings,roaming_assist"
    };
}
macro_rules! caps_tailnet {
    () => {
        "capabilities schema=1 features=tailnet_gateway,boot_diagnostics,mode_switch,chip_temperature,automatic_display,power_report,setup_ap,\
         button_menu,factory_reset,status_led,display_pages,display_settings"
    };
}

/// `help` of the Wi-Fi bridge (release image: `MEMORY_COMMANDS` is empty).
pub const HELP_BRIDGE: &str = concat!(help_bridge_head!(), help_bridge_tail!());
/// `help` of the tailnet gateway (release image).
pub const HELP_TAILNET: &str = concat!(help_tailnet_head!(), help_tailnet_tail!());
/// `capabilities` of the Wi-Fi bridge (release image: `MEMORY_FEATURE` is empty).
pub const CAPABILITIES_BRIDGE: &str = concat!(caps_bridge!(), "\r\n");
/// `capabilities` of the tailnet gateway (release image).
pub const CAPABILITIES_TAILNET: &str = concat!(caps_tailnet!(), "\r\n");
/// Unknown command, Wi-Fi bridge.
pub const UNKNOWN_BRIDGE: &str = "ERR Unknown command; type help\r\n";
/// Unknown command, tailnet gateway.
pub const UNKNOWN_TAILNET: &str = "ERR Unknown command; type help. USB setup: http://192.168.77.1/\r\n";

/// `help`: the C ternary on `gateway_tailnet_mode()`, with `MEMORY_COMMANDS` as a parameter (pass `""` for the release image or
/// [`MEMORY_COMMANDS_DIAGNOSTICS`]).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_help<W: fmt::Write>(w: &mut W, tailnet: bool, memory_commands: &str) -> fmt::Result {
    if tailnet {
        w.write_str(help_tailnet_head!())?;
        w.write_str(memory_commands)?;
        w.write_str(help_tailnet_tail!())
    } else {
        w.write_str(help_bridge_head!())?;
        w.write_str(memory_commands)?;
        w.write_str(help_bridge_tail!())
    }
}

/// The commands the phase 1 firmware implements, in the form `help` prints them. Every one parses (`Command::parse`) to something other than `Unknown`; a test keeps
/// that true. The C `help` lists commands phase 1 answers with "not available yet", which a client reads as a promise.
pub const PHASE1_FIRMWARE_COMMANDS: &[&str] = &[
    "status",
    "list",
    "use N",
    "del N",
    "profile JSON",
    "scan",
    "display [B R D]",
    "setup [N]",
    "cancel",
    "reset",
    "confirm-reset",
    "mode wifi_bridge",
    "capabilities",
    "pm",
    "boot-status",
    "reboot",
    "bootloader",
    "selftest spin|irqoff|panic|console|usb",
    "help",
];

/// The commands of the S3 spike (`status` and `list` are the C replies; the rest are spike tools).
pub const SPIKE_S3_COMMANDS: &[&str] =
    &["status", "list", "capabilities", "boot-status", "bootloader", "init", "normal", "heap [on|off]", "usb bridge|sink|source RATE_KBPS|max", "help"];

/// `help` listing exactly `commands` (and nothing the image does not implement), in the C layout: the product line, then `Commands: a, b, c`.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_help_implemented<W: fmt::Write>(w: &mut W, product: &str, commands: &[&str]) -> fmt::Result {
    write!(w, "{product} protocol=1\r\nCommands: ")?;
    for (i, c) in commands.iter().enumerate() {
        if i != 0 {
            w.write_str(", ")?;
        }
        w.write_str(c)?;
    }
    w.write_str("\r\n")
}

/// `capabilities` listing exactly `features`.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_capabilities_implemented<W: fmt::Write>(w: &mut W, features: &[&str]) -> fmt::Result {
    w.write_str("capabilities schema=1 features=")?;
    for (i, f) in features.iter().enumerate() {
        if i != 0 {
            w.write_str(",")?;
        }
        w.write_str(f)?;
    }
    w.write_str("\r\n")
}

/// `capabilities`, with `MEMORY_FEATURE` as a parameter (pass `""` for the release image or [`MEMORY_FEATURE_DIAGNOSTICS`]).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_capabilities<W: fmt::Write>(w: &mut W, tailnet: bool, memory_feature: &str) -> fmt::Result {
    w.write_str(if tailnet { caps_tailnet!() } else { caps_bridge!() })?;
    w.write_str(memory_feature)?;
    w.write_str("\r\n")
}

/// The reply to an unknown command (before the `done>`).
#[must_use]
pub const fn unknown_command(tailnet: bool) -> &'static str {
    if tailnet { UNKNOWN_TAILNET } else { UNKNOWN_BRIDGE }
}

/// Write [`unknown_command`].
///
/// # Errors
/// Whatever the sink returns.
pub fn write_unknown<W: fmt::Write>(w: &mut W, tailnet: bool) -> fmt::Result {
    w.write_str(unknown_command(tailnet))
}

// ---- control.c ----
/// `reboot`: sent, then the firmware waits 200 ms and restarts.
pub const REBOOT_OK: &str = "OK rebooting\r\ndone>\r\n";
/// `bootloader`: sent, then the firmware waits 200 ms and resets into ROM download mode.
pub const BOOTLOADER_OK: &str = "OK rebooting into ROM download mode\r\ndone>\r\n";
/// `retry-startup` when the crash evidence or the recovery guard could not be handled.
pub const RETRY_STARTUP_FAILED: &str = "ERR Could not preserve crash evidence or reset recovery guard\r\n";
/// `retry-startup` accepted: sent, then the firmware waits 300 ms and restarts.
pub const RETRY_STARTUP_OK: &str = "OK restarting services\r\ndone>\r\n";
/// The header line before the lines of `esp_pm_dump_locks` in `pm`.
pub const PM_DUMP_HEADER: &str = "esp_pm_dump_locks:\r\n";

// ---- serial_setup.inc ----
/// A lock (`members_lock`) could not be taken in time.
pub const SETTINGS_BUSY: &str = "ERR Settings busy\r\n";
/// `mode X` with an unknown mode name.
pub const MODE_INVALID: &str = "ERR Invalid mode\r\n";
/// `mode X` accepted but the store refused it.
pub const MODE_NOT_SAVED: &str = "ERR Mode was not saved\r\n";
/// `mode X` saved: sent, then the firmware waits 300 ms and restarts.
pub const MODE_SAVED: &str = "OK mode saved; restarting\r\ndone>\r\n";
/// `scan` while the radio is not ready or another scan runs.
pub const SCAN_BUSY: &str = "ERR Scan busy\r\n";
/// `scan` whose driver call failed.
pub const SCAN_FAILED: &str = "ERR Scan failed; retry shortly\r\n";
/// `display ...` with arguments `ui_settings_parse` refuses.
pub const DISPLAY_USAGE: &str = "ERR display: brightness 5..100 rotation 0|1 dim 10..3600 seconds\r\n";
/// `display B R D` valid but not stored.
pub const STORAGE_SAVE_FAILED: &str = "ERR Storage save failed\r\n";
/// `display B R D` stored.
pub const DISPLAY_SAVED: &str = "OK display saved\r\n";
/// `setup` with a bad argument.
pub const SETUP_USAGE: &str = "ERR setup: optionally a saved network number 1 to 8\r\n";
/// `setup` in recovery mode.
pub const SETUP_RECOVERY: &str = "ERR Setup is not available in recovery mode; use retry-startup\r\n";
/// `setup` while the setup access point is already up.
pub const SETUP_ALREADY_OPEN: &str = "OK setup already open\r\n";
/// `setup` accepted: sent, then the firmware waits 300 ms and restarts into setup.
pub const SETUP_RESTARTING: &str = "OK restarting into setup\r\ndone>\r\n";
/// `cancel` during setup: sent, then the firmware waits 300 ms and restarts.
pub const CANCEL_LEAVING: &str = "OK leaving setup; restarting\r\ndone>\r\n";
/// `cancel` outside setup (a no-op clients send after `profile`).
pub const CANCEL_NOOP: &str = "OK setup saved\r\n";
/// `reset`: step one of the factory reset.
pub const RESET_ARMED: &str = "Confirm within 10 seconds: confirm-reset\r\n";
/// `confirm-reset` when not armed or too late.
pub const RESET_EXPIRED: &str = "ERR reset confirmation expired\r\n";
/// `confirm-reset` whose erase failed.
pub const RESET_FAILED: &str = "ERR Factory reset failed; storage could not be erased\r\n";
/// `confirm-reset` done: sent, then the firmware waits 300 ms and restarts into setup.
pub const RESET_DONE: &str = "OK factory reset; restarting into setup\r\ndone>\r\n";
/// `profile JSON` that does not parse or names a slot beyond the end of the list.
pub const PROFILE_REFRESH: &str = "ERR Refresh saved networks before editing\r\n";
/// `profile JSON` that could not be stored.
pub const PROFILE_SAVE_FAILED: &str = "ERR Wi-Fi could not be saved\r\n";
/// `use N` when the Wi-Fi driver refused the network.
pub const USE_DRIVER_REFUSED: &str = "ERR Wi-Fi driver refused the network; previous setting kept\r\n";
/// `use N` during a setup boot.
pub const USE_SETUP_OPEN: &str = "ERR Not available while setup is open; finish with Done or cancel first\r\n";
/// `use N` with a bad number (also any other failure of the join request).
pub const USE_INVALID: &str = "ERR Invalid saved network\r\n";
/// `del N` that failed (bad number or store refused).
pub const DEL_FAILED: &str = "ERR Saved network could not be removed\r\n";
/// `del N` done.
pub const DEL_OK: &str = "OK deleted\r\n";
/// `memory guard` with a missing or out-of-range argument (diagnostics image).
pub const MEMORY_GUARD_USAGE: &str = "ERR memory guard takes 0-65536 bytes\r\n";

/// Every fixed (argument free) reply above, for tests that compare the set against the C sources.
pub const ALL_FIXED: &[&str] = &[
    REBOOT_OK,
    BOOTLOADER_OK,
    RETRY_STARTUP_FAILED,
    RETRY_STARTUP_OK,
    PM_DUMP_HEADER,
    SETTINGS_BUSY,
    MODE_INVALID,
    MODE_NOT_SAVED,
    MODE_SAVED,
    SCAN_BUSY,
    SCAN_FAILED,
    DISPLAY_USAGE,
    STORAGE_SAVE_FAILED,
    DISPLAY_SAVED,
    SETUP_USAGE,
    SETUP_RECOVERY,
    SETUP_ALREADY_OPEN,
    SETUP_RESTARTING,
    CANCEL_LEAVING,
    CANCEL_NOOP,
    RESET_ARMED,
    RESET_EXPIRED,
    RESET_FAILED,
    RESET_DONE,
    PROFILE_REFRESH,
    PROFILE_SAVE_FAILED,
    USE_DRIVER_REFUSED,
    USE_SETUP_OPEN,
    USE_INVALID,
    DEL_FAILED,
    DEL_OK,
    MEMORY_GUARD_USAGE,
    DONE,
    crate::console::PROMPT,
    crate::console::OVERFLOW_REPLY,
    crate::console::QUEUE_FULL_REPLY,
];

/// `profile JSON` stored: `OK saved to slot %d; setup stays open`, where `%d` is the 1-based slot (C prints `slot + 1` of its 0-based variable).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_profile_saved<W: fmt::Write>(w: &mut W, slot_zero_based: i32) -> fmt::Result {
    emit(w, &mut [0; 64], format_args!("OK saved to slot {}; setup stays open\r\n", slot_zero_based.wrapping_add(1)))
}

/// `use N` accepted: `OK switching to %ld`, with ` (preference not saved)` when `kept` is false (the join is under way either way).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_use_ok<W: fmt::Write>(w: &mut W, slot: i32, preference_kept: bool) -> fmt::Result {
    let note = if preference_kept { "" } else { " (preference not saved)" };
    emit(w, &mut [0; 160], format_args!("OK switching to {slot}{note}\r\n"))
}

/// The reply of `display` without arguments: `display brightness=%u rotation=%u dim_seconds=%u`.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_display<W: fmt::Write>(w: &mut W, brightness: u8, rotation: u8, dim_seconds: u16) -> fmt::Result {
    emit(w, &mut [0; 96], format_args!("display brightness={brightness} rotation={rotation} dim_seconds={dim_seconds}\r\n"))
}

/// One line of `scan`: `ssid=%s rssi=%d auth=%d`, the SSID cut at its first NUL and every byte outside 32..=126 shown as `?`.
///
/// `ssid` is the 32 byte field of `wifi_ap_record_t` (the C code copies 32 bytes and terminates at 33).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_scan_line<W: fmt::Write>(w: &mut W, ssid: &[u8; 32], rssi: i8, auth_mode: i32) -> fmt::Result {
    let mut line = ByteLine::<128>::new();
    line.put(b"ssid=");
    for &b in ssid.iter().take_while(|&&b| b != 0) {
        line.put(&[if (32..=126).contains(&b) { b } else { b'?' }]);
    }
    // Everything above is ASCII.
    fmt::Write::write_fmt(&mut line, format_args!(" rssi={rssi} auth={auth_mode}\r\n"))?;
    w.write_str(core::str::from_utf8(line.as_bytes()).unwrap_or(""))
}

/// The longest `list` line: `char reply[160]` leaves 159 bytes.
pub const LIST_LINE_CAP: usize = 160;

/// One line of `list`: `"%u%s name=%.24s ssid=%s priority=%u\r\n"`, rendered into the 160 byte buffer the C code uses (a longer line is
/// cut at 159 bytes, the CRLF being what is lost first).
///
/// Name and SSID are raw bytes: an SSID is any 0 to 32 bytes, not necessarily UTF-8, and the C code prints it as is.
#[derive(Clone, Debug)]
pub struct ListLine {
    line: ByteLine<LIST_LINE_CAP>,
}

impl ListLine {
    /// Render the line of saved network `index` (0-based; printed 1-based). `current` adds the `*`. `name` and `ssid` are C strings: they
    /// stop at the first NUL; the name is cut at 24 bytes (`%.24s`).
    #[must_use]
    pub fn new(index: u32, current: bool, name: &[u8], ssid: &[u8], priority: u8) -> Self {
        let cstr = |b: &[u8]| -> usize { b.iter().position(|&x| x == 0).unwrap_or(b.len()) };
        let name = &name[..cstr(name).min(24)];
        let ssid = &ssid[..cstr(ssid)];
        let mut line = ByteLine::<LIST_LINE_CAP>::new();
        // `index + 1` is `unsigned` arithmetic in C.
        let _ = fmt::Write::write_fmt(&mut line, format_args!("{}{}", index.wrapping_add(1), if current { "*" } else { "" }));
        line.put(b" name=");
        line.put(name);
        line.put(b" ssid=");
        line.put(ssid);
        let _ = fmt::Write::write_fmt(&mut line, format_args!(" priority={priority}\r\n"));
        Self { line }
    }

    /// The bytes to send.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.line.as_bytes()
    }
}
