//! Routing mode of the dongle.
//!
//! Port of `components/tdongle_runtime/mode_store.c` and `include/tdongle_mode*.h` (tested by `tests/test_mode_store.c`). The mode is the
//! NVS `tn_settings/mode` key, a single `u8`; the load rule also looks at whether the `members` string key exists.

/// NVS key holding the mode (`u8`).
pub const MODE_KEY: &str = "mode";
/// NVS key whose mere existence marks an install that predates the mode switch and already ran the tailnet gateway.
pub const MEMBERS_KEY: &str = "members";

/// C `tdongle_mode`, with the same stored values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// `TDONGLE_WIFI_BRIDGE`, stored as 0.
    WifiBridge = 0,
    /// `TDONGLE_TAILNET_GATEWAY`, stored as 1.
    TailnetGateway = 1,
}

/// A stored mode value the firmware refuses (C: `ESP_ERR_INVALID_STATE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeError {
    /// The stored `u8` is neither 0 nor 1. Never silently corrected: the caller must not guess a mode.
    InvalidStored(u8),
}

impl Mode {
    /// C `tdongle_mode_name`: `"wifi_bridge"` or `"tailnet_gateway"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::WifiBridge => "wifi_bridge",
            Self::TailnetGateway => "tailnet_gateway",
        }
    }

    /// C `tdongle_mode_parse`: exactly one of the two names, case sensitive.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "wifi_bridge" => Some(Self::WifiBridge),
            "tailnet_gateway" => Some(Self::TailnetGateway),
            _ => None,
        }
    }

    /// The `u8` stored under [`MODE_KEY`] (what `tdongle_mode_save` writes).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// The mode for a stored `u8`, `None` above 1.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::WifiBridge),
            1 => Some(Self::TailnetGateway),
            _ => None,
        }
    }

    /// C `tdongle_mode_load` as a pure function of what the store holds. `stored` is the `mode` key (`None`: not found) and
    /// `members_present` whether the `members` string key exists.
    ///
    /// A saved mode always wins (a value above 1 is an error). Without one, an install that holds tailnet memberships keeps running the
    /// gateway, and everything else, a fresh install or an upgrade from v0.1.x, boots in Wi-Fi bridge mode. A *failing* read of either key
    /// is a storage error the caller reports as is; it is never mapped to a mode here.
    ///
    /// # Errors
    /// [`ModeError::InvalidStored`] for a stored value above 1.
    pub const fn load(stored: Option<u8>, members_present: bool) -> Result<Self, ModeError> {
        match stored {
            Some(value) => match Self::from_u8(value) {
                Some(mode) => Ok(mode),
                None => Err(ModeError::InvalidStored(value)),
            },
            None if members_present => Ok(Self::TailnetGateway),
            None => Ok(Self::WifiBridge),
        }
    }
}
