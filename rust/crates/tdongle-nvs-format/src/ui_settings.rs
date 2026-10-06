//! Display settings: backlight percentage, 180 degree rotation and idle dim time.
//!
//! Port of `main/ui_settings.{h,c}` (tested by `tests/test_ui_settings.c`). Persisted in NVS `tn_settings/display` as an 8-byte blob
//! ([`UiSettings::to_bytes`]); the v0.1.x firmware kept the same three values inside `adapter/config` (see [`crate::legacy`]).

use crate::cstr::{c_str, read_u32};

/// Lowest accepted brightness percent (C `UI_BRIGHTNESS_MIN`).
pub const BRIGHTNESS_MIN: u8 = 5;
/// Highest accepted brightness percent (C `UI_BRIGHTNESS_MAX`).
pub const BRIGHTNESS_MAX: u8 = 100;
/// Default brightness (C `UI_BRIGHTNESS_DEFAULT`).
pub const BRIGHTNESS_DEFAULT: u8 = 60;
/// Shortest idle time before dimming (C `UI_DIM_SECONDS_MIN`).
pub const DIM_SECONDS_MIN: u16 = 10;
/// Longest idle time before dimming (C `UI_DIM_SECONDS_MAX`).
pub const DIM_SECONDS_MAX: u16 = 3600;
/// Default idle time (C `UI_DIM_SECONDS_DEFAULT`).
pub const DIM_SECONDS_DEFAULT: u16 = 60;
/// Backlight percent while dimmed (C `UI_DIM_PERCENT`).
pub const DIM_PERCENT: u8 = 5;
/// Highest rotation value; 1 is 180 degrees (C `UI_ROTATION_MAX`).
pub const ROTATION_MAX: u8 = 1;
/// Schema of the persisted blob (C `UI_SETTINGS_SCHEMA`).
pub const SCHEMA: u32 = 1;
/// Size of the persisted blob (C `sizeof(ui_settings_blob)`): schema u32 at 0, brightness u8 at 4, rotation u8 at 5, dim_seconds u16 at 6.
pub const BLOB_LEN: usize = 8;

/// Display settings (C `ui_settings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiSettings {
    /// Percent, [`BRIGHTNESS_MIN`] to [`BRIGHTNESS_MAX`].
    pub brightness: u8,
    /// 0, or 1 for 180 degrees.
    pub rotation: u8,
    /// [`DIM_SECONDS_MIN`] to [`DIM_SECONDS_MAX`].
    pub dim_seconds: u16,
}

/// Why a command line or stored blob is not valid display settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiSettingsError {
    /// Not exactly three blank-separated unsigned decimal integers of at most five digits.
    Malformed,
    /// A value outside its range.
    OutOfRange,
    /// A stored blob that is not [`BLOB_LEN`] bytes.
    WrongSize,
    /// A stored blob with a schema other than [`SCHEMA`].
    BadSchema,
}

impl Default for UiSettings {
    /// C `ui_settings_defaults`.
    fn default() -> Self {
        Self { brightness: BRIGHTNESS_DEFAULT, rotation: 0, dim_seconds: DIM_SECONDS_DEFAULT }
    }
}

impl UiSettings {
    /// C `ui_settings_valid`.
    #[must_use]
    pub fn valid(&self) -> bool {
        (BRIGHTNESS_MIN..=BRIGHTNESS_MAX).contains(&self.brightness)
            && self.rotation <= ROTATION_MAX
            && (DIM_SECONDS_MIN..=DIM_SECONDS_MAX).contains(&self.dim_seconds)
    }

    /// C `ui_settings_parse`: `"BRIGHTNESS ROTATION DIM_SECONDS"`, three unsigned decimal integers (no sign, at most five digits each, leading
    /// zeros allowed) separated by one or more spaces (only U+0020: a tab is refused), with optional spaces before the first and after the
    /// last. Text after the first NUL byte is ignored, as in C.
    ///
    /// # Errors
    /// [`UiSettingsError::Malformed`] or [`UiSettingsError::OutOfRange`].
    pub fn parse(args: &[u8]) -> Result<Self, UiSettingsError> {
        let mut p = c_str(args);
        let mut v = [0u32; 3];
        for (i, value) in v.iter_mut().enumerate() {
            while let [b' ', rest @ ..] = p {
                p = rest;
            }
            let digits = p.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 || digits > 5 {
                return Err(UiSettingsError::Malformed);
            }
            *value = p[..digits].iter().fold(0, |acc, &d| acc * 10 + u32::from(d - b'0'));
            p = &p[digits..];
            if i < 2 && p.first() != Some(&b' ') {
                return Err(UiSettingsError::Malformed);
            }
        }
        while let [b' ', rest @ ..] = p {
            p = rest;
        }
        if !p.is_empty() {
            return Err(UiSettingsError::Malformed);
        }
        let candidate = Self { brightness: v[0].min(255) as u8, rotation: v[1].min(255) as u8, dim_seconds: v[2].min(65535) as u16 };
        if candidate.valid() { Ok(candidate) } else { Err(UiSettingsError::OutOfRange) }
    }

    /// C `ui_settings_backlight_percent`: [`DIM_PERCENT`] while dimmed, never above the configured brightness.
    #[must_use]
    pub fn backlight_percent(&self, dimmed: bool) -> u8 {
        if dimmed && self.brightness > DIM_PERCENT { DIM_PERCENT } else { self.brightness }
    }

    /// C `ui_settings_backlight_duty`: LEDC duty (8-bit) of an active-low backlight at `percent`; percentages above 100 are clamped.
    #[must_use]
    pub fn backlight_duty(percent: u32) -> u32 {
        255 - percent.min(100) * 255 / 100
    }

    /// C `ui_settings_encode`: the 8 bytes stored in `tn_settings/display`, padding zero.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLOB_LEN] {
        let mut out = [0u8; BLOB_LEN];
        out[0..4].copy_from_slice(&SCHEMA.to_le_bytes());
        out[4] = self.brightness;
        out[5] = self.rotation;
        out[6..8].copy_from_slice(&self.dim_seconds.to_le_bytes());
        out
    }

    /// C `ui_settings_decode`: only a blob of exactly [`BLOB_LEN`] bytes with schema 1 and in-range values.
    ///
    /// # Errors
    /// [`UiSettingsError::WrongSize`], [`UiSettingsError::BadSchema`] or [`UiSettingsError::OutOfRange`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, UiSettingsError> {
        if data.len() != BLOB_LEN {
            return Err(UiSettingsError::WrongSize);
        }
        let candidate = Self { brightness: data[4], rotation: data[5], dim_seconds: u16::from_le_bytes([data[6], data[7]]) };
        if read_u32(data, 0) != SCHEMA {
            return Err(UiSettingsError::BadSchema);
        }
        if candidate.valid() { Ok(candidate) } else { Err(UiSettingsError::OutOfRange) }
    }
}
