//! Read-only access to the device's NVS (the settings the C firmware and the v0.1.x bridge firmware left in flash).
//!
//! Why not `esp_idf_svc::nvs`: its `EspNvsPartition::take()` initialises NVS and, on `ESP_ERR_NVS_NO_FREE_PAGES` or a new NVS version,
//! **erases the partition** and tries again. The C firmware's rule (`start_settings`) is the opposite: "Never erase identities on a storage
//! error". A storage error here is reported and nothing is written. Phase 1 of the port opens every namespace read-only, so alternating the C and
//! Rust images on one board cannot corrupt what the other one saved.

use core::ffi::CStr;

use esp_idf_svc::sys;

/// An NVS error code (`esp_err_t`), or "not found", which is not an error for a settings store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `ESP_ERR_NVS_NOT_FOUND`: the namespace or key does not exist.
    NotFound,
    /// Any other failure, with the `esp_err_t`.
    Esp(i32),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::Esp(code) => write!(f, "esp_err {code:#x}"),
        }
    }
}

impl std::error::Error for Error {}

fn check(code: sys::esp_err_t) -> Result<(), Error> {
    match code {
        sys::ESP_OK => Ok(()),
        sys::ESP_ERR_NVS_NOT_FOUND => Err(Error::NotFound),
        other => Err(Error::Esp(other)),
    }
}

/// `nvs_flash_init()` and nothing else: no erase, whatever it answers.
///
/// # Errors
/// The `esp_err_t` of a storage that could not be initialised; the firmware then runs without saved settings and says so in `status`.
pub fn init() -> Result<(), Error> {
    // SAFETY: no preconditions; idempotent.
    check(unsafe { sys::nvs_flash_init() })
}

/// A namespace opened `NVS_READONLY`.
#[derive(Debug)]
pub struct ReadOnly {
    handle: sys::nvs_handle_t,
}

impl ReadOnly {
    /// Open `namespace` read-only. [`Error::NotFound`] when the namespace does not exist (a fresh install, or an upgrade from firmware that
    /// never created it).
    pub fn open(namespace: &CStr) -> Result<Self, Error> {
        let mut handle: sys::nvs_handle_t = 0;
        // SAFETY: `namespace` is NUL terminated; `handle` is a valid out pointer.
        check(unsafe { sys::nvs_open(namespace.as_ptr(), sys::nvs_open_mode_t_NVS_READONLY, &mut handle) })?;
        Ok(Self { handle })
    }

    /// Read the blob stored under `key` into `buffer`, returning the bytes that were stored. A blob larger than the buffer is an error (the
    /// driver reports `ESP_ERR_NVS_INVALID_LENGTH`) rather than a truncated read: a settings blob of the wrong size is not a settings blob.
    pub fn get_blob(&self, key: &CStr, buffer: &mut [u8]) -> Result<usize, Error> {
        let mut length = buffer.len();
        // SAFETY: `buffer` is `length` writable bytes; the driver writes at most `length` and updates it to the stored size.
        check(unsafe { sys::nvs_get_blob(self.handle, key.as_ptr(), buffer.as_mut_ptr().cast(), &mut length) })?;
        Ok(length)
    }

    /// A `u8` value.
    pub fn get_u8(&self, key: &CStr) -> Result<u8, Error> {
        let mut value = 0u8;
        // SAFETY: `value` is a valid out pointer.
        check(unsafe { sys::nvs_get_u8(self.handle, key.as_ptr(), &mut value) })?;
        Ok(value)
    }

    /// Whether a string value exists under `key` (the C firmware asks the length of `members` to tell an install that predates the mode
    /// switch from a fresh one).
    pub fn has_str(&self, key: &CStr) -> Result<bool, Error> {
        let mut length = 0usize;
        // SAFETY: a null data pointer asks only for the length.
        match check(unsafe { sys::nvs_get_str(self.handle, key.as_ptr(), core::ptr::null_mut(), &mut length) }) {
            Ok(()) => Ok(true),
            Err(Error::NotFound) => Ok(false),
            Err(other) => Err(other),
        }
    }
}

impl Drop for ReadOnly {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful `nvs_open` and is closed exactly once.
        unsafe { sys::nvs_close(self.handle) }
    }
}

/// Store one `u8` under `namespace`/`key` and commit. The **only write** phase 1 makes: the serial `mode wifi_bridge` command, which in the C
/// firmware is the same `nvs_set_u8` + `nvs_commit` on `tn_settings`/`mode`. It lets a board that was last in tailnet mode be put back to bridge
/// mode without the C image.
pub fn write_u8(namespace: &CStr, key: &CStr, value: u8) -> Result<(), Error> {
    let mut handle: sys::nvs_handle_t = 0;
    // SAFETY: `namespace` is NUL terminated and `handle` is a valid out pointer.
    check(unsafe { sys::nvs_open(namespace.as_ptr(), sys::nvs_open_mode_t_NVS_READWRITE, &mut handle) })?;
    // SAFETY: `handle` is open read-write; it is closed exactly once below.
    let result = check(unsafe { sys::nvs_set_u8(handle, key.as_ptr(), value) }).and_then(|()| check(unsafe { sys::nvs_commit(handle) }));
    // SAFETY: closes the handle opened above.
    unsafe { sys::nvs_close(handle) };
    result
}
