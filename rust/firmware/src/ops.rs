//! Console operations every spike must answer so the coordinator's `tools/flash_wait.py` can reflash without the BOOT button (USB-Serial-JTAG is
//! gone once the OTG peripheral starts): `bootloader` (ROM download mode) and `boot-status` (the running ELF's SHA-256). Included with
//! `#[path = "../../common/ops.rs"] mod ops;` so no spike depends on another.
#![allow(dead_code)]

use core::fmt::Write;

/// Hex of the 12-digit chip MAC used as the USB serial (uppercase, same as the C firmware).
pub fn mac_hex(mac: &[u8; 6]) -> [u8; 12] {
    let mut hex = [0u8; 12];
    for (i, b) in mac.iter().enumerate() {
        hex[2 * i] = b"0123456789ABCDEF"[(b >> 4) as usize];
        hex[2 * i + 1] = b"0123456789ABCDEF"[(b & 15) as usize];
    }
    hex
}

/// What C does for `bootloader`: set RTC_CNTL_FORCE_DOWNLOAD_BOOT (OPTION1 bit 0), then reset; the ROM then enters download mode.
pub fn enter_bootloader() -> ! {
    const RTC_CNTL_OPTION1_REG: *mut u32 = (0x6000_8000usize + 0x12C) as *mut u32;
    // SAFETY: fixed, always-mapped RTC_CNTL register on the ESP32-S3 (TRM RTC_CNTL_OPTION1_REG); read-modify-write of one bit, single task.
    unsafe { RTC_CNTL_OPTION1_REG.write_volatile(RTC_CNTL_OPTION1_REG.read_volatile() | 1) };
    tdongle_rescue::disarm();
    esp_hal::system::software_reset()
}

/// `boot-status`: JSON on one line; `elf` is the 64-hex-digit SHA-256 from `esp_app_desc_t.app_elf_sha256` (offset 144), as in C.
pub fn boot_status<W: Write>(w: &mut W, firmware: &str, elf: &[u8; 32], up_ms: u64) {
    let _ = write!(w, "{{\"schema\":1,\"firmware\":\"{firmware}\",\"elf\":\"");
    for b in elf {
        let _ = write!(w, "{b:02x}");
    }
    let _ = write!(w, "\",\"recovery\":false,\"stage\":\"complete\",\"uptime_ms\":{up_ms},\"rust_spike\":true}}");
}
