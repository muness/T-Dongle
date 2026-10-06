//! The TinyUSB descriptor callbacks (`tud_descriptor_*_cb`) over the byte-exact tables of `tdongle-usb-descriptors`.

use core::cell::UnsafeCell;
use std::sync::OnceLock;

use tdongle_usb_descriptors::{CONFIG_FS, DEVICE, STRING_UNITS_MAX, Strings, mac_text, string_descriptor};

use super::Identity;

/// The strings that depend on the device, built once at boot before the stack starts.
struct Texts {
    product: &'static str,
    serial: [u8; 12],
}

static TEXTS: OnceLock<Texts> = OnceLock::new();

/// Keep the descriptors in DRAM-independent flash constants (as the C `const` tables are) and remember the device's strings.
pub fn install(identity: Identity) {
    let serial = mac_text(identity.station_mac);
    // In bridge mode the NCM MAC the host adopts is the station MAC itself, so the serial and the MAC string are the same twelve digits.
    let _ = TEXTS.set(Texts { product: identity.product, serial });
}

/// The one buffer `tud_descriptor_string_cb` returns a pointer into. TinyUSB reads it after the callback returns, until the transfer is
/// done, and only the TinyUSB task calls the callback, so a single static is enough (as in esp_tinyusb).
struct StringBuffer(UnsafeCell<[u16; STRING_UNITS_MAX]>);

// SAFETY: written only by `tud_descriptor_string_cb`, which TinyUSB calls from its own task only; never read concurrently.
unsafe impl Sync for StringBuffer {}

static STRING: StringBuffer = StringBuffer(UnsafeCell::new([0; STRING_UNITS_MAX]));

/// `tud_descriptor_device_cb`: the device descriptor.
#[unsafe(no_mangle)]
pub extern "C" fn tud_descriptor_device_cb() -> *const u8 {
    DEVICE.as_ptr()
}

/// `tud_descriptor_configuration_cb`: the single full-speed configuration.
#[unsafe(no_mangle)]
pub extern "C" fn tud_descriptor_configuration_cb(_index: u8) -> *const u8 {
    CONFIG_FS.as_ptr()
}

/// `tud_descriptor_string_cb`: UTF-16 string descriptors; null stalls the request (an index with no string).
#[unsafe(no_mangle)]
pub extern "C" fn tud_descriptor_string_cb(index: u8, _language: u16) -> *const u16 {
    let Some(texts) = TEXTS.get() else {
        return core::ptr::null();
    };
    let serial = core::str::from_utf8(&texts.serial).unwrap_or(""); // always ASCII hex from `mac_text`
    let strings = Strings { product: texts.product, serial, mac: serial };
    // SAFETY: only the TinyUSB task calls this callback (see `StringBuffer`), so nothing else holds a reference to the buffer.
    let buffer = unsafe { &mut *STRING.0.get() };
    match string_descriptor(index, &strings, buffer) {
        Ok(_) => buffer.as_ptr(),
        Err(_) => core::ptr::null(),
    }
}
