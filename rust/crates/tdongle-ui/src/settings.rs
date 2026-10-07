//! Display settings (v0.1.1 `display BRIGHTNESS ROTATION DIM_SECONDS`): backlight percentage, 180 degree rotation and the idle time after which the
//! backlight drops to [`DIM_PERCENT`]. Port of `main/ui_settings.{h,c}` (test: `tests/test_ui_settings.c`).
//!
//! Persistence: NVS namespace `tn_settings`, key `display`, a fixed 8 byte blob ([`Settings::encode`]). **When it is saved**: only by the serial `display`
//! command (`serial_display`: parse, then `display_save`: write the blob, commit, then adopt the new value; the UI poll applies it within one draw). The
//! button menu and the UI poll never write the display settings. When no `display` key exists the firmware falls back to the v0.1.1 `adapter/config`
//! blob and writes nothing.

/// Lowest brightness percent.
pub const BRIGHTNESS_MIN: u8 = 5;
/// Highest brightness percent.
pub const BRIGHTNESS_MAX: u8 = 100;
/// Default brightness percent.
pub const BRIGHTNESS_DEFAULT: u8 = 60;
/// Shortest dim time.
pub const DIM_SECONDS_MIN: u16 = 10;
/// Longest dim time.
pub const DIM_SECONDS_MAX: u16 = 3600;
/// Default dim time.
pub const DIM_SECONDS_DEFAULT: u16 = 60;
/// Backlight percent while dimmed.
pub const DIM_PERCENT: u32 = 5;
/// Highest rotation value (1 = 180 degrees).
pub const ROTATION_MAX: u8 = 1;
/// Blob schema.
pub const SCHEMA: u32 = 1;
/// Blob size.
pub const BLOB_LEN: usize = 8;

/// The three settings (`ui_settings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Percent, 5 to 100.
    pub brightness: u8,
    /// 0, or 1 for 180 degrees.
    pub rotation: u8,
    /// Seconds idle before dimming, 10 to 3600.
    pub dim_seconds: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { brightness: BRIGHTNESS_DEFAULT, rotation: 0, dim_seconds: DIM_SECONDS_DEFAULT }
    }
}

impl Settings {
    /// In range?
    pub fn valid(&self) -> bool {
        (BRIGHTNESS_MIN..=BRIGHTNESS_MAX).contains(&self.brightness)
            && self.rotation <= ROTATION_MAX
            && (DIM_SECONDS_MIN..=DIM_SECONDS_MAX).contains(&self.dim_seconds)
    }

    /// `"BRIGHTNESS ROTATION DIM_SECONDS"`: three unsigned decimal integers separated by blanks and nothing else; out of range or malformed is `None`.
    pub fn parse(args: &str) -> Option<Settings> {
        let b = args.as_bytes();
        let mut p = 0usize;
        let mut v = [0u64; 3];
        for (i, slot) in v.iter_mut().enumerate() {
            while p < b.len() && b[p] == b' ' {
                p += 1;
            }
            if p >= b.len() || !b[p].is_ascii_digit() {
                return None;
            }
            let mut value = 0u64;
            let mut digits = 0;
            while p < b.len() && b[p].is_ascii_digit() {
                digits += 1;
                if digits > 5 {
                    return None;
                }
                value = value * 10 + (b[p] - b'0') as u64;
                p += 1;
            }
            *slot = value;
            if i < 2 && !(p < b.len() && b[p] == b' ') {
                return None;
            }
        }
        while p < b.len() && b[p] == b' ' {
            p += 1;
        }
        if p != b.len() {
            return None;
        }
        let s = Settings { brightness: v[0].min(255) as u8, rotation: v[1].min(255) as u8, dim_seconds: v[2].min(65535) as u16 };
        s.valid().then_some(s)
    }

    /// Backlight percent in force: [`DIM_PERCENT`] while dimmed, never above the configured brightness.
    pub fn backlight_percent(&self, dimmed: bool) -> u32 {
        if dimmed && self.brightness as u32 > DIM_PERCENT { DIM_PERCENT } else { self.brightness as u32 }
    }

    /// The stored blob: schema (u32 LE), brightness, rotation, dim seconds (u16 LE).
    pub fn encode(&self) -> [u8; BLOB_LEN] {
        let mut o = [0u8; BLOB_LEN];
        o[..4].copy_from_slice(&SCHEMA.to_le_bytes());
        o[4] = self.brightness;
        o[5] = self.rotation;
        o[6..8].copy_from_slice(&self.dim_seconds.to_le_bytes());
        o
    }

    /// `None` unless the blob has exactly the right size, schema and in-range values.
    pub fn decode(data: &[u8]) -> Option<Settings> {
        if data.len() != BLOB_LEN {
            return None;
        }
        let schema = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let s = Settings { brightness: data[4], rotation: data[5], dim_seconds: u16::from_le_bytes([data[6], data[7]]) };
        (schema == SCHEMA && s.valid()).then_some(s)
    }
}

/// The LEDC duty for an active-low backlight at `percent`, 8 bit resolution (full brightness is duty 0).
pub fn backlight_duty(percent: u32) -> u32 {
    255 - percent.min(100) * 255 / 100
}
