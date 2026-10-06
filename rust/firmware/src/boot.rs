//! Boot modes as types (rule 3 of ADR 0001).
//!
//! The C firmware decides the mode with booleans (`setup_active`, `gateway_tailnet_mode()`) that every later stage re-reads. The HIGH finding of
//! ADR 0024, "the open setup access point was routed to the USB host", was a stage that created the USB netif in a boot that must not have one.
//! Here the decision is a value of one of three types, and the **capability to bring up the USB network** ([`UsbNetwork`]) can be obtained only
//! from the boot types that may have it: there is no method on [`SetupBoot`] that returns one, so a setup boot cannot start the bridge or a
//! USB netif, whatever a later edit does.

use crate::settings::Settings;
use tdongle_nvs_format::mode::Mode;

/// Proof that this boot may own the USB network (the bridge's frames, and in tailnet mode the lwIP USB netif). Only [`BridgeBoot`] and
/// [`TailnetBoot`] can produce one; it is not `Clone` or `Copy`.
#[derive(Debug)]
pub struct UsbNetwork(());

/// The setup access point and nothing else: no bridge, no tailnet runtime, **no USB network** (ADR 0024). Phase 2.
#[derive(Debug)]
pub struct SetupBoot(());

/// The transparent Wi-Fi bridge.
#[derive(Debug)]
pub struct BridgeBoot(());

/// The tailnet gateway. Phase 3: unconstructible until then (an uninhabited field).
#[derive(Debug)]
pub struct TailnetBoot(core::convert::Infallible);

/// What this boot is. The setup and tailnet variants exist so the type is matched exhaustively from the start; their phases construct them.
#[derive(Debug)]
#[allow(dead_code)]
pub enum Boot {
    /// See [`SetupBoot`].
    Setup(SetupBoot),
    /// See [`BridgeBoot`].
    Bridge(BridgeBoot),
    /// See [`TailnetBoot`].
    Tailnet(TailnetBoot),
}

impl Boot {
    /// The boot decision (`setup_boot_early` and the stored mode). Phase 1 knows only the bridge: a stored tailnet mode still boots the bridge
    /// (and `status` says `stored_mode=tailnet_gateway running=wifi_bridge`), because the tailnet gateway is not in this image.
    #[must_use]
    pub fn decide(settings: &Settings) -> Self {
        match settings.mode {
            Mode::WifiBridge | Mode::TailnetGateway => Self::Bridge(BridgeBoot(())),
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

impl SetupBoot {
    /// Setup boots exist so the type can be matched on; they never hand out a [`UsbNetwork`]. (Deliberately no `usb_network` method.)
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

impl Default for SetupBoot {
    fn default() -> Self {
        Self::new()
    }
}
