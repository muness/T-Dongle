//! Command lines: the dispatch of `control.c` `command_task` and `serial_setup.inc` `gateway_serial_command`, as one pure parser.
//!
//! [`Command::parse`] returns what the C code would *decide to do* for a line; carrying it out (queues, NVS, restarts) is the firmware's
//! job. The order of the C tests is kept because it decides overlaps:
//!
//! 1. `command_task`: `help`, `capabilities`, `pm`, `status`, `boot-status`, `retry-startup`, `crypto bench` (all `strcmp`: the whole line)
//! 2. `gateway_serial_command`: `status` (step 1's `status` branch calls it, then appends the `bridge_*` lines), `mode ` (`strncmp`, 5), `scan`, `display` (`display` alone or
//!    `display ` + anything), `setup` / `setup ` + anything, `cancel`, `reset`, `confirm-reset`, then the network commands `list`
//!    (`strcmp`), `profile ` / `del ` / `use ` (`strncmp` with the trailing space)
//! 3. `gateway_memory_command` (diagnostics image only, see [`Command::parse_with_diagnostics`])
//! 4. `reboot`, `bootloader`
//! 5. anything else: unknown
//!
//! # C string semantics kept on purpose
//!
//! * The C line is a NUL terminated `char[]`: text after a NUL byte is invisible. The parser cuts the line at the first NUL.
//! * `strcmp` matches the whole line: no trailing space or CR is tolerated (`"help "` is unknown).
//! * `use N` / `del N` / `setup N` read their number with `strtol(.., 10)` ([`strtol`]): leading white space and one `+` or `-` sign are
//!   accepted (`"use  +2"` is slot 2), a missing number reads as 0, and anything left over after the digits (even a space) makes the
//!   argument invalid. A value outside the 32 bit `long` of the Xtensa target saturates (the C `long` is 32 bits on the dongle).

use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_profiles;

/// Most saved networks, and the largest `setup N` argument (`WIFI_PROFILE_LIMIT`).
pub const SETUP_SLOT_MAX: usize = wifi_profiles::LIMIT;

/// The result of C `strtol(text, &end, 10)` on a 32 bit `long`: the value and the unparsed rest (`end`).
///
/// Skips leading C white space (space, `\t`, `\n`, `\v`, `\f`, `\r`), accepts one `+` or `-`, then decimal digits. With no digits the value
/// is 0 and the rest is the *whole* input (C leaves `end` at the start). A value beyond `i32` saturates (C: `LONG_MAX` / `LONG_MIN`).
#[must_use]
pub fn strtol(text: &str) -> (i32, &str) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')) {
        i += 1;
    }
    let negative = match bytes.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let digits_start = i;
    let mut magnitude: u64 = 0;
    while let Some(d) = bytes.get(i).filter(|b| b.is_ascii_digit()) {
        // Saturate far above i32 so later digits cannot wrap: the clamp below is what the caller sees.
        magnitude = (magnitude * 10 + u64::from(d - b'0')).min(u64::from(u32::MAX) * 4);
        i += 1;
    }
    if i == digits_start {
        return (0, text);
    }
    let value =
        if negative { i32::try_from(-i64::try_from(magnitude).unwrap_or(i64::MAX)).unwrap_or(i32::MIN) } else { i32::try_from(magnitude).unwrap_or(i32::MAX) };
    (value, &text[i..])
}

/// The result of C `strtoul(text, &end, 10)` on a 32 bit `unsigned long`: value and unparsed rest.
///
/// Like [`strtol`], plus the C quirk that a `-` negates modulo 2^32 (`"-1"` reads as 4294967295, `"-0"` as 0); a magnitude beyond `u32::MAX`
/// is `u32::MAX` whatever the sign (C: `ULONG_MAX`).
#[must_use]
pub fn strtoul(text: &str) -> (u32, &str) {
    let (negative, digits_text) = {
        let trimmed = text.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
        match trimmed.as_bytes().first() {
            Some(b'-') => (true, &trimmed[1..]),
            Some(b'+') => (false, &trimmed[1..]),
            _ => (false, trimmed),
        }
    };
    let digits = digits_text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return (0, text);
    }
    let mut magnitude: u64 = 0;
    for d in digits_text.bytes().take(digits) {
        magnitude = (magnitude * 10 + u64::from(d - b'0')).min(u64::from(u32::MAX) * 4);
    }
    // C: a value out of range is `ULONG_MAX` whatever the sign; in range, `-` negates modulo 2^32.
    let value = match u32::try_from(magnitude) {
        Err(_) => u32::MAX,
        Ok(m) if negative => m.wrapping_neg(),
        Ok(m) => m,
    };
    (value, &digits_text[digits..])
}

/// The number of `use N` and `del N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotArg {
    /// `strtol` consumed everything: the (1-based) saved network number. May be 0, negative or too large; the firmware rejects those with
    /// its own range check.
    Number(i32),
    /// Text was left after the number (`*end != 0`): the C code treats this as an invalid network without looking at the value.
    TrailingGarbage,
}

impl SlotArg {
    fn parse(text: &str) -> Self {
        let (value, rest) = strtol(text);
        if rest.is_empty() { Self::Number(value) } else { Self::TrailingGarbage }
    }
}

/// The argument of `setup`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupArg {
    /// `setup`: no saved network offered for replacement (`slot = 0`).
    Open,
    /// `setup N`, N in 1..=[`SETUP_SLOT_MAX`]: offer saved network N for replacement.
    Slot(u8),
    /// `setup` followed by anything that is not such a number: reply [`crate::reply::SETUP_USAGE`].
    Invalid,
}

/// The arguments of `display`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayArgs {
    /// `display` alone: report the current values.
    Show,
    /// `display B R D` with valid values.
    Set(UiSettings),
    /// `display ` followed by something `ui_settings_parse` refuses (including nothing): reply [`crate::reply::DISPLAY_USAGE`].
    Invalid,
}

/// A command of the diagnostics image (`gateway_memory_command`), recognised only by [`Command::parse_with_diagnostics`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Diagnostic<'a> {
    /// `memory`
    Memory,
    /// `bridge`
    Bridge,
    /// `bridgetune` (alone or followed by a space): the text after the command word (starts with the space, if any).
    BridgeTune(&'a str),
    /// `memory low`
    MemoryLow,
    /// `wifistats`
    WifiStats,
    /// `wifistats reset`
    WifiStatsReset,
    /// `wifistats dump`
    WifiStatsDump,
    /// `cpu`
    Cpu,
    /// `wgperf`
    WgPerf,
    /// `wgperf reset`
    WgPerfReset,
    /// `wgperf logbench`
    WgPerfLogbench,
    /// `route`
    Route,
    /// `inbound`
    Inbound,
    /// `members`
    Members,
    /// `memory locks`
    MemoryLocks,
    /// `memory bench`
    MemoryBench,
    /// `memory guard [BYTES]`: `Some(bytes)` for a valid argument (0..=65536), `None` for a missing or invalid one
    /// (reply [`crate::reply::MEMORY_GUARD_USAGE`]).
    MemoryGuard(Option<u32>),
}

/// What a command line asks for. Borrows the line for the arguments the firmware parses further.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// `help`
    Help,
    /// `capabilities`
    Capabilities,
    /// `pm`
    Pm,
    /// `status` (plus, in bridge mode, the `bridge_*` lines after it)
    Status,
    /// `boot-status`
    BootStatus,
    /// `retry-startup`
    RetryStartup,
    /// `crypto bench`
    CryptoBench,
    /// `mode NAME` (the trailing space is part of the command: `mode` alone is unknown). `None`: not a mode name (reply
    /// [`crate::reply::MODE_INVALID`]).
    Mode(Option<Mode>),
    /// `scan`
    Scan,
    /// `display ...`
    Display(DisplayArgs),
    /// `setup [N]`
    Setup(SetupArg),
    /// `cancel`
    Cancel,
    /// `reset` (step one of the factory reset)
    Reset,
    /// `confirm-reset`
    ConfirmReset,
    /// `list`
    List,
    /// `profile JSON`: the text after `profile ` (parse with `tdongle_nvs_format::profile_json`).
    Profile(&'a str),
    /// `use N`
    Use(SlotArg),
    /// `del N`
    Del(SlotArg),
    /// A diagnostics-image command (only from [`Command::parse_with_diagnostics`]).
    Diagnostic(Diagnostic<'a>),
    /// `reboot`
    Reboot,
    /// `bootloader`
    Bootloader,
    /// Anything else: reply with [`crate::reply::write_unknown`].
    Unknown,
}

impl<'a> Command<'a> {
    /// Parse a line of the release image (no diagnostics commands).
    #[must_use]
    pub fn parse(line: &'a str) -> Self {
        Self::parse_inner(line, false)
    }

    /// Parse a line of the diagnostics image (`CONFIG_TDONGLE_MEMORY_DIAGNOSTICS`): `gateway_memory_command` is tried after the serial
    /// set and before `reboot`.
    #[must_use]
    pub fn parse_with_diagnostics(line: &'a str) -> Self {
        Self::parse_inner(line, true)
    }

    fn parse_inner(line: &'a str, diagnostics: bool) -> Self {
        let line = line.split('\0').next().unwrap_or("");
        match line {
            "help" => return Self::Help,
            "capabilities" => return Self::Capabilities,
            "pm" => return Self::Pm,
            "status" => return Self::Status,
            "boot-status" => return Self::BootStatus,
            "retry-startup" => return Self::RetryStartup,
            "crypto bench" => return Self::CryptoBench,
            _ => {}
        }
        if let Some(command) = Self::parse_serial(line) {
            return command;
        }
        if diagnostics && let Some(command) = Diagnostic::parse(line) {
            return Self::Diagnostic(command);
        }
        match line {
            "reboot" => Self::Reboot,
            "bootloader" => Self::Bootloader,
            _ => Self::Unknown,
        }
    }

    /// `gateway_serial_command`, in its order.
    fn parse_serial(line: &'a str) -> Option<Self> {
        if let Some(name) = line.strip_prefix("mode ") {
            return Some(Self::Mode(Mode::parse(name)));
        }
        if line == "scan" {
            return Some(Self::Scan);
        }
        if line == "display" {
            return Some(Self::Display(DisplayArgs::Show));
        }
        if let Some(args) = line.strip_prefix("display ") {
            let parsed = UiSettings::parse(args.as_bytes());
            return Some(Self::Display(parsed.map_or(DisplayArgs::Invalid, DisplayArgs::Set)));
        }
        if line == "setup" {
            return Some(Self::Setup(SetupArg::Open));
        }
        if let Some(number) = line.strip_prefix("setup ") {
            let (n, rest) = strtol(number);
            let slot = u8::try_from(n).ok().filter(|&n| n >= 1 && usize::from(n) <= SETUP_SLOT_MAX);
            return Some(Self::Setup(match slot {
                Some(slot) if rest.is_empty() => SetupArg::Slot(slot),
                _ => SetupArg::Invalid,
            }));
        }
        match line {
            "cancel" => return Some(Self::Cancel),
            "reset" => return Some(Self::Reset),
            "confirm-reset" => return Some(Self::ConfirmReset),
            "list" => return Some(Self::List),
            _ => {}
        }
        if let Some(json) = line.strip_prefix("profile ") {
            return Some(Self::Profile(json));
        }
        if let Some(number) = line.strip_prefix("use ") {
            return Some(Self::Use(SlotArg::parse(number)));
        }
        if let Some(number) = line.strip_prefix("del ") {
            return Some(Self::Del(SlotArg::parse(number)));
        }
        None
    }
}

impl<'a> Diagnostic<'a> {
    /// `gateway_memory_command`'s chain, in its order.
    fn parse(line: &'a str) -> Option<Self> {
        match line {
            "memory" => return Some(Self::Memory),
            "bridge" => return Some(Self::Bridge),
            _ => {}
        }
        if let Some(rest) = line.strip_prefix("bridgetune")
            && (rest.is_empty() || rest.starts_with(' '))
        {
            return Some(Self::BridgeTune(rest));
        }
        match line {
            "memory low" => return Some(Self::MemoryLow),
            "wifistats" => return Some(Self::WifiStats),
            "wifistats reset" => return Some(Self::WifiStatsReset),
            "wifistats dump" => return Some(Self::WifiStatsDump),
            "cpu" => return Some(Self::Cpu),
            "wgperf" => return Some(Self::WgPerf),
            "wgperf reset" => return Some(Self::WgPerfReset),
            "wgperf logbench" => return Some(Self::WgPerfLogbench),
            "route" => return Some(Self::Route),
            "inbound" => return Some(Self::Inbound),
            "members" => return Some(Self::Members),
            "memory locks" => return Some(Self::MemoryLocks),
            "memory bench" => return Some(Self::MemoryBench),
            _ => {}
        }
        if let Some(rest) = line.strip_prefix("memory guard")
            && (rest.is_empty() || rest.starts_with(' '))
        {
            // C: `bytes = line[12] ? strtoul(line + 13) : 0; error if !line[12] || !line[13] || *end || bytes > 65536`.
            let argument = rest.get(1..).filter(|a| !a.is_empty());
            let bytes = argument.and_then(|a| {
                let (value, end) = strtoul(a);
                (end.is_empty() && value <= 65536).then_some(value)
            });
            return Some(Self::MemoryGuard(bytes));
        }
        None
    }
}
