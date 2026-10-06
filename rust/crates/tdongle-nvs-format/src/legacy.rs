//! The v0.1.x bridge firmware's settings blob (`adapter/config`) and its import into the unified stores.
//!
//! Port of `main/core.h` (`settings_t`, `profile_t`), the validators of `main/core.c` and `main/legacy_import.{h,c}` (tested by
//! `tests/test_legacy_import.c` and the profile cases of `tests/test_core.c`). The unified firmware only ever *reads* this blob.

use crate::cstr::{c_len, c_str, copy_str, is_printable, is_terminated, read_u32};
use crate::ui_settings::UiSettings;
use crate::wifi_meta::MetaSlot;

/// Number of profile slots (C `PROFILE_MAX`).
pub const PROFILE_MAX: usize = 8;
/// Version of the blob (C `CFG_VERSION`).
pub const CFG_VERSION: u32 = 1;
/// `sizeof(settings_t)`: version u32 at 0, eight profiles from 4, then `preferred` at 996, `brightness` 997, `rotation` 998, one
/// padding byte, `dim_seconds` u16 at 1000 and two bytes of tail padding.
pub const BLOB_LEN: usize = 1004;
/// `sizeof(profile_t)`: `name[25]` +0, `ssid[33]` +25, `pass[65]` +58, `priority` +123.
pub const PROFILE_LEN: usize = 124;

const PROFILES_AT: usize = 4;
const PREFERRED_AT: usize = PROFILES_AT + PROFILE_MAX * PROFILE_LEN;
const _: () = assert!(PREFERRED_AT == 996);

/// One saved network of the v0.1.x firmware (C `profile_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyProfile {
    /// Display name, `char name[25]`.
    pub name: [u8; 25],
    /// SSID, `char ssid[33]`; an empty SSID is an empty slot.
    pub ssid: [u8; 33],
    /// Password, `char pass[65]`.
    pub pass: [u8; 65],
    /// Priority.
    pub priority: u8,
}

impl LegacyProfile {
    /// An all-zero (empty) slot.
    pub const EMPTY: Self = Self { name: [0; 25], ssid: [0; 33], pass: [0; 65], priority: 0 };

    /// C `printable(s, max, min)` of `main/core.c`: the C string in `s` is `min` to `max` characters long, all printable ASCII, and is
    /// terminated within the first `max + 1` bytes.
    fn printable(s: &[u8], max: usize, min: usize) -> bool {
        let window = &s[..s.len().min(max + 1)];
        let n = c_len(window);
        window[..n].iter().all(|&b| is_printable(b)) && n >= min && n <= max
    }

    /// C `profile_valid`: name 1 to 24 and SSID 1 to 32 printable characters, priority at most 100, password empty or 8 to 63 printable
    /// characters.
    #[must_use]
    pub fn valid(&self) -> bool {
        if !Self::printable(&self.name, 24, 1) || !Self::printable(&self.ssid, 32, 1) || self.priority > 100 {
            return false;
        }
        let n = c_len(&self.pass);
        (n == 0 || (8..=63).contains(&n)) && Self::printable(&self.pass, 63, 0)
    }

    fn from_bytes(b: &[u8]) -> Self {
        let mut p = Self::EMPTY;
        p.name.copy_from_slice(&b[0..25]);
        p.ssid.copy_from_slice(&b[25..58]);
        p.pass.copy_from_slice(&b[58..123]);
        p.priority = b[123];
        p
    }

    fn write(&self, out: &mut [u8]) {
        out[0..25].copy_from_slice(&self.name);
        out[25..58].copy_from_slice(&self.ssid);
        out[58..123].copy_from_slice(&self.pass);
        out[123] = self.priority;
    }
}

/// The whole v0.1.x settings blob (C `settings_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacySettings {
    /// [`CFG_VERSION`] in a blob this firmware understands.
    pub version: u32,
    /// The eight profile slots.
    pub p: [LegacyProfile; PROFILE_MAX],
    /// Preferred slot (0-based); at least [`PROFILE_MAX`] means none usable.
    pub preferred: u8,
    /// Brightness percent.
    pub brightness: u8,
    /// Rotation, 0 or 1.
    pub rotation: u8,
    /// Idle seconds before dimming.
    pub dim_seconds: u16,
}

/// Why a legacy blob is not imported (C `legacy_import_decode` returning false).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyError {
    /// The blob is not [`BLOB_LEN`] bytes.
    WrongSize,
    /// Version other than [`CFG_VERSION`].
    WrongVersion,
}

impl LegacySettings {
    /// Read the blob layout. Only the length is checked; the version is left to the caller ([`LegacyImport::decode`] checks it).
    ///
    /// # Errors
    /// [`LegacyError::WrongSize`] unless `data` is exactly [`BLOB_LEN`] bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, LegacyError> {
        if data.len() != BLOB_LEN {
            return Err(LegacyError::WrongSize);
        }
        let mut s = Self {
            version: read_u32(data, 0),
            p: [LegacyProfile::EMPTY; PROFILE_MAX],
            preferred: data[PREFERRED_AT],
            brightness: data[PREFERRED_AT + 1],
            rotation: data[PREFERRED_AT + 2],
            dim_seconds: u16::from_le_bytes([data[1000], data[1001]]),
        };
        for (i, p) in s.p.iter_mut().enumerate() {
            let at = PROFILES_AT + i * PROFILE_LEN;
            *p = LegacyProfile::from_bytes(&data[at..at + PROFILE_LEN]);
        }
        Ok(s)
    }

    /// The bytes the v0.1.x firmware stores. The padding bytes (999, 1002, 1003) are written as zero; [`LegacySettings::from_bytes`] ignores
    /// them, so a blob whose padding is not zero does not round trip (the C firmware zero-fills `settings_t` before saving).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLOB_LEN] {
        let mut out = [0u8; BLOB_LEN];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        for (i, p) in self.p.iter().enumerate() {
            let at = PROFILES_AT + i * PROFILE_LEN;
            p.write(&mut out[at..at + PROFILE_LEN]);
        }
        out[PREFERRED_AT] = self.preferred;
        out[PREFERRED_AT + 1] = self.brightness;
        out[PREFERRED_AT + 2] = self.rotation;
        out[1000..1002].copy_from_slice(&self.dim_seconds.to_le_bytes());
        out
    }

    /// The three display values as [`UiSettings`] (not validated).
    #[must_use]
    pub fn display(&self) -> UiSettings {
        UiSettings { brightness: self.brightness, rotation: self.rotation, dim_seconds: self.dim_seconds }
    }

    /// C `settings_valid`: version 1, `preferred < 8`, display values in range and every non-empty slot a valid profile. The unified
    /// firmware does *not* use this on import (it salvages what it can, see [`LegacyImport::decode`]); it is the v0.1.x acceptance rule.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.version == CFG_VERSION && usize::from(self.preferred) < PROFILE_MAX && self.display().valid() && self.p.iter().all(|p| p.ssid[0] == 0 || p.valid())
    }
}

/// One network the import carries over (C `legacy_network`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyNetwork {
    /// SSID, `char ssid[33]`.
    pub ssid: [u8; 33],
    /// Password, `char password[64]`; its last byte is always 0.
    pub password: [u8; 64],
    /// Name and priority, with the fallbacks applied.
    pub meta: MetaSlot,
}

/// What the v0.1.x blob contributes to the unified stores (C `legacy_import`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyImport {
    /// Number of usable networks, at most 8, in the old slot order with empty and unusable slots skipped.
    pub count: usize,
    /// The networks; entries from `count` on are zero.
    pub net: [LegacyNetwork; 8],
    /// Index into `net` of the old preferred slot (C: `int preferred`, -1 for none).
    pub preferred: Option<usize>,
    /// The old display settings when all three were in range (C: `display_valid` + `display`).
    pub display: Option<UiSettings>,
}

impl LegacyImport {
    /// C `legacy_import_decode`. Fails only for a blob that is not a v0.1.x one (wrong size or version): nothing is imported then.
    /// A network that cannot be used (empty or unterminated SSID, unterminated password or one longer than 63) is skipped; a network
    /// repeating an SSID that is already imported is skipped too, and a preferred slot that pointed at it follows the first one. A bad name
    /// or priority falls back to the SSID or 50 for that network, and bad display settings only leave `display` empty.
    ///
    /// # Errors
    /// [`LegacyError::WrongSize`] or [`LegacyError::WrongVersion`].
    pub fn decode(blob: &[u8]) -> Result<Self, LegacyError> {
        let old = LegacySettings::from_bytes(blob)?;
        if old.version != CFG_VERSION {
            return Err(LegacyError::WrongVersion);
        }
        Ok(Self::from_settings(&old))
    }

    /// The import of an already parsed blob; [`LegacyImport::decode`] without the size and version checks.
    #[must_use]
    pub fn from_settings(old: &LegacySettings) -> Self {
        const NET: LegacyNetwork = LegacyNetwork { ssid: [0; 33], password: [0; 64], meta: MetaSlot::EMPTY };
        let mut out = Self { count: 0, net: [NET; 8], preferred: None, display: None };
        let mut mapped = [None::<usize>; PROFILE_MAX];
        for (slot, p) in mapped.iter_mut().zip(&old.p) {
            if p.ssid[0] == 0 || !is_terminated(&p.ssid) || !is_terminated(&p.pass) || c_len(&p.pass) > 63 {
                continue;
            }
            let ssid = c_str(&p.ssid);
            if let Some(existing) = out.net[..out.count].iter().rposition(|n| c_str(&n.ssid) == ssid) {
                *slot = Some(existing); // the same network again: the first slot's data stands
                continue;
            }
            if out.count == 8 {
                continue; // unreachable with eight source slots; kept as in C
            }
            let n = &mut out.net[out.count];
            n.ssid = p.ssid;
            n.password.copy_from_slice(&p.pass[..64]);
            n.password[63] = 0;
            n.meta = MetaSlot::default_for(&n.ssid);
            if is_terminated(&p.name) && MetaSlot::name_valid(&p.name) {
                n.meta.name = [0; 25];
                copy_str(&mut n.meta.name, &p.name);
            }
            if p.priority <= 100 {
                n.meta.priority = p.priority;
            }
            *slot = Some(out.count);
            out.count += 1;
        }
        out.preferred = mapped.get(usize::from(old.preferred)).copied().flatten();
        let display = old.display();
        out.display = display.valid().then_some(display);
        out
    }
}
