//! The `boot-status` JSON of the Rust images: the fields of the C firmware's `gateway_boot_report` that a flashing tool uses (`schema`, `firmware`, `elf`,
//! `recovery`, `stage`, `previous_stage`, `reset_reason`) plus what the guard adds (`previous_panic`, `safe_mode`, `unstable_boots`).

use core::fmt::{self, Write};

/// Everything `boot-status` prints.
#[derive(Clone, Copy, Debug)]
pub struct BootStatus<'a> {
    /// Firmware version.
    pub firmware: &'a str,
    /// SHA-256 of the running ELF (`esp_app_desc_t.app_elf_sha256`).
    pub elf: &'a [u8; 32],
    /// Why the chip last reset, as the HAL names it.
    pub reset_reason: &'a str,
    /// The step running now.
    pub stage: &'a str,
    /// The step the previous boot ended in (`none` if unknown).
    pub previous_stage: &'a str,
    /// The previous panic, `""` if none.
    pub previous_panic: &'a str,
    /// This is a safe-mode boot.
    pub safe_mode: bool,
    /// Consecutive unstable boots before this one.
    pub unstable_boots: u8,
    /// Milliseconds since boot.
    pub uptime_ms: u64,
    /// Free heap in bytes, if the image can tell.
    pub free_heap: Option<u32>,
}

fn json_str<W: Write>(w: &mut W, s: &str) -> fmt::Result {
    w.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => w.write_str("\\\"")?,
            '\\' => w.write_str("\\\\")?,
            c if (c as u32) < 0x20 || c as u32 == 0x7f => write!(w, "\\u{:04x}", c as u32)?,
            c => w.write_char(c)?,
        }
    }
    w.write_char('"')
}

/// Write one line of JSON, without a line ending.
///
/// # Errors
/// What the writer returns.
pub fn write_boot_status<W: Write>(w: &mut W, s: &BootStatus<'_>) -> fmt::Result {
    w.write_str("{\"schema\":1,\"firmware\":")?;
    json_str(w, s.firmware)?;
    w.write_str(",\"elf\":\"")?;
    for b in s.elf {
        write!(w, "{b:02x}")?;
    }
    w.write_str("\",\"recovery\":")?;
    w.write_str(if s.safe_mode { "true" } else { "false" })?;
    w.write_str(",\"stage\":")?;
    json_str(w, s.stage)?;
    w.write_str(",\"previous_stage\":")?;
    json_str(w, s.previous_stage)?;
    w.write_str(",\"reset_reason\":")?;
    json_str(w, s.reset_reason)?;
    w.write_str(",\"previous_panic\":")?;
    json_str(w, s.previous_panic)?;
    write!(w, ",\"safe_mode\":{},\"unstable_boots\":{},\"uptime_ms\":{}", s.safe_mode, s.unstable_boots, s.uptime_ms)?;
    if let Some(free) = s.free_heap {
        write!(w, ",\"free_memory\":{free}")?;
    }
    w.write_str(",\"rust_port\":1}")
}
