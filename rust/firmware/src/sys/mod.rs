//! The thin, audited unsafe layer between the firmware and ESP-IDF/FreeRTOS: everything the rest of the crate needs from the C world that
//! has no safe wrapper in `esp-idf-svc`/`esp-idf-hal` (or whose wrapper does something the C firmware deliberately does not, see `nvs`).
//!
//! The rule for this module: each function is a few lines, each `unsafe` block states why the call is sound, and nothing here knows about
//! the bridge, USB or Wi-Fi policy.

pub mod critical;
pub mod heap;
pub mod nvs;
pub mod single;
pub mod task;

use esp_idf_svc::sys;

/// The low 32 bits of the microsecond clock (`esp_timer_get_time`): wraps every 71.6 minutes, every use is a wrapping difference.
#[inline]
pub fn now_us() -> u32 {
    // SAFETY: a read of the always-running system timer; callable from any context.
    unsafe { sys::esp_timer_get_time() as u32 }
}

/// The 64 bit microsecond clock.
#[inline]
pub fn now_us64() -> u64 {
    // SAFETY: as `now_us`.
    unsafe { sys::esp_timer_get_time() as u64 }
}

/// Milliseconds since boot, wrapping at 2^32 (the C firmware's `(uint32_t)(esp_timer_get_time() / 1000)`).
#[inline]
pub fn now_ms() -> u32 {
    (now_us64() / 1000) as u32
}

/// `esp_restart`: never returns.
pub fn restart() -> ! {
    // SAFETY: `esp_restart` has no preconditions.
    unsafe { sys::esp_restart() }
}

/// Reboot into the ROM download mode (`REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT); esp_rom_software_reset_system()`), the
/// serial `bootloader` command: how `tools/flash.sh` gets a board without the button.
pub fn reboot_to_rom_download() -> ! {
    // SAFETY: RTC_CNTL_OPTION1_REG is a valid, always-mapped RTC control register on the ESP32-S3; setting FORCE_DOWNLOAD_BOOT only changes
    // what the next software reset boots into, and the reset follows immediately.
    unsafe {
        let register = sys::RTC_CNTL_OPTION1_REG as *mut u32;
        register.write_volatile(register.read_volatile() | (1 << sys::RTC_CNTL_FORCE_DOWNLOAD_BOOT_S));
        sys::esp_rom_software_reset_system();
    }
    // esp_rom_software_reset_system returns on some silicon revisions only after the reset is pending.
    loop {
        core::hint::spin_loop();
    }
}

/// The station MAC (`esp_read_mac(ESP_MAC_WIFI_STA)`): the address the host speaks with, the USB serial string and the NCM MAC.
pub fn read_sta_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    // SAFETY: `mac` is six writable bytes, the size `esp_read_mac` writes for a 48-bit MAC type.
    let result = unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_WIFI_STA) };
    debug_assert_eq!(result, sys::ESP_OK);
    mac
}
