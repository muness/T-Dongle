//! The setup access point as a boot mode (`main/setup_boot.c`, ADR 0024 decision 1) and its typestate (ADR 0001 rule 3).
//!
//! # No USB network in a setup boot
//!
//! The HIGH finding of ADR 0024 was a stage that created the USB netif in a boot that must not have one. Here the capability to bring up
//! the USB network, [`UsbNetwork`], has a crate-private constructor that only [`BridgeBoot::usb_network`] and [`TailnetBoot::usb_network`]
//! call. [`SetupBoot`] has no such method, and a [`SetupBoot`] can be obtained only from [`SetupBoot::decide`], so a setup boot cannot
//! hand the bridge or the tailnet a USB network:
//!
//! ```compile_fail
//! let boot = tdongle_setup::boot::SetupBoot::decide(false, 0, 0, 0, false, true).unwrap();
//! let _usb = boot.usb_network(); // no such method
//! ```
//!
//! ```compile_fail
//! let _ = tdongle_setup::boot::UsbNetwork(()); // private constructor
//! ```

use core::convert::Infallible;

/// `SETUP_BOOT_MAGIC`: "TDM1".
pub const MAGIC: u32 = 0x5444_4d31;
/// `SETUP_SESSION_MS`: ten minutes. Nothing extends it (the C has no extension: not a request, not a page action, not a client joining).
pub const SESSION_MS: u32 = 600_000;
/// `SETUP_AP_GRACE_MS`: a setup boot whose access point is not up this long after the boot began restarts into normal mode.
pub const AP_GRACE_MS: u32 = 30_000;
/// `SETUP_SLOTS`.
pub const SLOTS: u32 = 8;

/// `setup_request`: what the previous run left in the RTC words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// 0
    None = 0,
    /// 1: restart into setup.
    Enter = 1,
    /// 2: restart out of setup (never loops back in even with nothing saved).
    Leave = 2,
}

/// Proof that this boot may own the USB network. Not `Clone`, not `Copy`; only the bridge and tailnet boots produce one.
#[derive(Debug)]
pub struct UsbNetwork(pub(crate) ());

/// The setup access point and nothing else: no bridge, no tailnet runtime, **no USB network**.
#[derive(Debug)]
pub struct SetupBoot {
    preselect: u8,
}

/// The transparent Wi-Fi bridge.
#[derive(Debug)]
pub struct BridgeBoot(());

/// The tailnet gateway: uninhabited until the tailnet port wires it.
#[derive(Debug)]
pub struct TailnetBoot(Infallible);

/// What this boot is.
#[derive(Debug)]
pub enum Boot {
    /// See [`SetupBoot`].
    Setup(SetupBoot),
    /// See [`BridgeBoot`].
    Bridge(BridgeBoot),
    /// See [`TailnetBoot`] (never produced here).
    Tailnet(TailnetBoot),
}

impl SetupBoot {
    /// `setup_boot_decide`: `Some` when this boot runs setup. A request counts only after a software reset with the magic intact; without
    /// one, setup starts only when no network is saved and the store is readable, never after a LEAVE request.
    #[must_use]
    pub fn decide(software_reset: bool, magic: u32, next: u32, slot: u32, networks_saved: bool, store_ok: bool) -> Option<Self> {
        let request = if software_reset && magic == MAGIC { next } else { Request::None as u32 };
        if request == Request::Enter as u32 {
            let preselect = if (1..=SLOTS).contains(&slot) { slot as u8 } else { 0 };
            Some(Self { preselect })
        } else if request != Request::Leave as u32 && !networks_saved && store_ok {
            Some(Self { preselect: 0 })
        } else {
            None
        }
    }

    /// The saved network (1 to 8) the page offers to replace, 0 for "add a new one".
    #[must_use]
    pub const fn preselect(&self) -> u8 {
        self.preselect
    }

    /// Start the ten minute session (the clock starts when the boot decides, not when the access point comes up).
    #[must_use]
    pub const fn session(&self, now_ms: u32) -> Session {
        Session { started_ms: now_ms, active: true }
    }
}

impl Boot {
    /// The boot decision. `setup` is the result of [`SetupBoot::decide`] (already outranked by recovery: pass `None` then);
    /// `tailnet_stored` is accepted so the caller documents that a stored tailnet mode still boots the bridge until the tailnet port lands.
    #[must_use]
    pub fn decide(setup: Option<SetupBoot>, _tailnet_stored: bool) -> Self {
        match setup {
            Some(s) => Self::Setup(s),
            None => Self::Bridge(BridgeBoot(())),
        }
    }
}

impl BridgeBoot {
    /// The bridge owns the USB network.
    #[must_use]
    pub fn usb_network(&self) -> UsbNetwork {
        UsbNetwork(())
    }
}

impl TailnetBoot {
    /// The tailnet gateway owns the USB network (its lwIP netif).
    #[must_use]
    pub fn usb_network(&self) -> UsbNetwork {
        match self.0 {}
    }
}

/// `setup_boot_request`: the three RTC words for the next boot, `(magic, next, slot)`.
#[must_use]
pub fn request_words(request: Request, preselect: u32) -> (u32, u32, u32) {
    let slot = if request == Request::Enter && (1..=SLOTS).contains(&preselect) { preselect } else { 0 };
    (MAGIC, request as u32, slot)
}

/// `setup_session`: times are `esp_timer` milliseconds truncated to 32 bits; comparisons are wrap safe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Session {
    started_ms: u32,
    active: bool,
}

impl Session {
    /// An inactive session (a normal boot): never expires, nothing to force.
    pub const INACTIVE: Self = Self { started_ms: 0, active: false };

    /// `setup_session_expired`.
    #[must_use]
    pub const fn expired(&self, now_ms: u32) -> bool {
        self.active && now_ms.wrapping_sub(self.started_ms) >= SESSION_MS
    }

    /// `setup_session_seconds_left`: what the LCD and `status` (`setup active=1 ... seconds_left=`) show, rounded up.
    #[must_use]
    pub const fn seconds_left(&self, now_ms: u32) -> u32 {
        if !self.active {
            return 0;
        }
        let elapsed = now_ms.wrapping_sub(self.started_ms);
        if elapsed >= SESSION_MS { 0 } else { (SESSION_MS - elapsed).div_ceil(1000) }
    }

    /// `setup_session_should_end`: time to restart into normal mode (the session is over, or the access point is still not up
    /// [`AP_GRACE_MS`] after the boot began).
    #[must_use]
    pub const fn should_end(&self, now_ms: u32, access_point_up: bool) -> bool {
        if !self.active {
            return false;
        }
        self.expired(now_ms) || (!access_point_up && now_ms.wrapping_sub(self.started_ms) >= AP_GRACE_MS)
    }

    /// `setup_session_failsafe_delay_ms`: milliseconds until the next moment setup could have to end; 0 when it must end now.
    #[must_use]
    pub const fn failsafe_delay_ms(&self, now_ms: u32, access_point_up: bool) -> u32 {
        if !self.active || self.should_end(now_ms, access_point_up) {
            return 0;
        }
        let elapsed = now_ms.wrapping_sub(self.started_ms);
        let mut next = SESSION_MS - elapsed;
        if !access_point_up && AP_GRACE_MS - elapsed < next {
            next = AP_GRACE_MS - elapsed;
        }
        if next == 0 { 1 } else { next }
    }
}

/// The access point name length, `TDongle-XXXXXX`.
pub const SSID_LEN: usize = 14;

/// `setup_ap_ssid` into a buffer with `snprintf` semantics: at most `out.len() - 1` characters then a NUL; returns the characters written.
pub fn ap_ssid_into(out: &mut [u8], mac: &[u8; 6]) -> usize {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut full = *b"TDongle-000000";
    for (i, b) in mac[3..].iter().enumerate() {
        full[8 + 2 * i] = HEX[usize::from(b >> 4)];
        full[9 + 2 * i] = HEX[usize::from(b & 15)];
    }
    let Some(room) = out.len().checked_sub(1) else { return 0 };
    let n = room.min(SSID_LEN);
    out[..n].copy_from_slice(&full[..n]);
    out[n] = 0;
    n
}

/// The access point name from the station MAC (last three bytes).
#[must_use]
pub fn ap_ssid(mac: &[u8; 6]) -> [u8; SSID_LEN] {
    let mut out = [0u8; SSID_LEN + 1];
    ap_ssid_into(&mut out, mac);
    let mut name = [0u8; SSID_LEN];
    name.copy_from_slice(&out[..SSID_LEN]);
    name
}
