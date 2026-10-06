//! The unified saved-networks blob `tn_settings/wifi_profiles`.
//!
//! Layout of `alternative/tailnet/main/wifi_profiles.inc`: `struct { u32 schema, count; wifi_profile profiles[8]; }` with
//! `wifi_profile { char ssid[33], password[64]; }`, 784 bytes, no padding. The format is frozen: a downgrade to an older unified build must
//! still read it, so the display name, priority and preferred network live in [`crate::wifi_meta`] instead.

use crate::cstr::{c_str, is_terminated, read_u32};

/// Schema of the blob.
pub const SCHEMA: u32 = 1;
/// Most saved networks (C `WIFI_PROFILE_LIMIT`).
pub const LIMIT: usize = 8;
/// `sizeof(wifi_profile)`: `ssid[33]` +0, `password[64]` +33.
pub const PROFILE_LEN: usize = 97;
/// `sizeof` the blob: 8 + 8 * 97.
pub const BLOB_LEN: usize = 8 + LIMIT * PROFILE_LEN;

/// One saved network (C `wifi_profile`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedProfile {
    /// SSID, `char ssid[33]`; byte 32 is 0 in a used entry.
    pub ssid: [u8; 33],
    /// Password, `char password[64]`; byte 63 is 0 in a used entry; empty for an open network.
    pub password: [u8; 64],
}

impl SavedProfile {
    /// An all-zero entry.
    pub const EMPTY: Self = Self {
        ssid: [0; 33],
        password: [0; 64],
    };

    /// The SSID without its terminator.
    #[must_use]
    pub fn ssid_bytes(&self) -> &[u8] {
        c_str(&self.ssid)
    }

    /// The password without its terminator.
    #[must_use]
    pub fn password_bytes(&self) -> &[u8] {
        c_str(&self.password)
    }
}

/// Why a stored list is refused (C `wifi_load_profiles` setting `ok = false`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedNetworksError {
    /// The blob is not [`BLOB_LEN`] bytes.
    WrongSize,
    /// Schema other than 1, for example one written by a newer build: refused, never overwritten.
    BadSchema,
    /// `count` above [`LIMIT`].
    BadCount,
    /// A used entry (index below `count`) has an empty SSID.
    EmptySsid,
    /// A used entry's SSID fills all 33 bytes, so byte 32 is not the terminator.
    SsidUnterminated,
    /// A used entry's password fills all 64 bytes, so byte 63 is not the terminator.
    PasswordUnterminated,
}

/// The saved list (C `wifi_saved`): schema is always 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedNetworks {
    /// Number of used entries, at most [`LIMIT`].
    pub count: usize,
    /// All eight entries as stored; only the first `count` are meaningful. A list parsed from a blob keeps whatever bytes the unused
    /// entries and the bytes after each terminator held, so [`SavedNetworks::to_bytes`] returns the input.
    pub profiles: [SavedProfile; LIMIT],
}

impl Default for SavedNetworks {
    /// An empty list (C: `memset(&wifi_saved, 0, ...)` and `schema = 1`).
    fn default() -> Self {
        Self {
            count: 0,
            profiles: [SavedProfile::EMPTY; LIMIT],
        }
    }
}

impl SavedNetworks {
    /// The used entries.
    #[must_use]
    pub fn list(&self) -> &[SavedProfile] {
        &self.profiles[..self.count]
    }

    /// The SSID of every slot as a C string, `""` beyond `count` (C `wifi_ssid_list`).
    #[must_use]
    pub fn ssids(&self) -> [&[u8]; LIMIT] {
        let mut out: [&[u8]; LIMIT] = [&[]; LIMIT];
        for (dst, p) in out.iter_mut().zip(self.list()) {
            *dst = p.ssid_bytes();
        }
        out
    }

    /// Parse and validate a stored list exactly as C: length 784, schema 1, `count <= 8`, and for each used entry a non-empty SSID with
    /// `ssid[32] == 0` and `password[63] == 0`. Unused entries are not validated.
    ///
    /// # Errors
    /// The first failed rule as a [`SavedNetworksError`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, SavedNetworksError> {
        if data.len() != BLOB_LEN {
            return Err(SavedNetworksError::WrongSize);
        }
        if read_u32(data, 0) != SCHEMA {
            return Err(SavedNetworksError::BadSchema);
        }
        let count = read_u32(data, 4) as usize;
        if count > LIMIT {
            return Err(SavedNetworksError::BadCount);
        }
        let mut list = Self {
            count,
            profiles: [SavedProfile::EMPTY; LIMIT],
        };
        for (i, p) in list.profiles.iter_mut().enumerate() {
            let at = 8 + i * PROFILE_LEN;
            p.ssid.copy_from_slice(&data[at..at + 33]);
            p.password.copy_from_slice(&data[at + 33..at + PROFILE_LEN]);
        }
        for p in list.list() {
            if p.ssid[0] == 0 {
                return Err(SavedNetworksError::EmptySsid);
            }
            if p.ssid[32] != 0 {
                return Err(SavedNetworksError::SsidUnterminated);
            }
            if p.password[63] != 0 {
                return Err(SavedNetworksError::PasswordUnterminated);
            }
        }
        debug_assert!(list.list().iter().all(|p| is_terminated(&p.ssid)));
        Ok(list)
    }

    /// The 784 bytes C stores for this list.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLOB_LEN] {
        let mut out = [0u8; BLOB_LEN];
        out[0..4].copy_from_slice(&SCHEMA.to_le_bytes());
        out[4..8].copy_from_slice(&(self.count as u32).to_le_bytes());
        for (i, p) in self.profiles.iter().enumerate() {
            let at = 8 + i * PROFILE_LEN;
            out[at..at + 33].copy_from_slice(&p.ssid);
            out[at + 33..at + PROFILE_LEN].copy_from_slice(&p.password);
        }
        out
    }
}
