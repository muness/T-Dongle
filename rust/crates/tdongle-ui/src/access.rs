//! Who may ask the setup HTTP server for what: port of `main/setup_access.{h,c}` (test: `tests/test_setup_access.c`).
//!
//! Two kinds of client: USB (192.168.77.0/24, everything) and the open setup access point (192.168.4.0/24, only during a setup boot, only the Wi-Fi pages).
//! Anything else is denied.

const USB_SUBNET: u32 = 0xc0a8_4d00; // 192.168.77.0
const AP_SUBNET: u32 = 0xc0a8_0400; // 192.168.4.0

/// Length of the per-boot setup token (hex digits).
pub const TOKEN_LENGTH: usize = 32;

/// Who is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Refused.
    Denied,
    /// The host on the USB link.
    Usb,
    /// A client of the setup access point.
    SetupAp,
}

/// Pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `/`
    Home,
    /// status
    Status,
    /// diagnostics
    Diagnostics,
    /// Wi-Fi scan
    WifiScan,
    /// saved networks
    WifiSaved,
    /// command
    Command,
    /// boot status
    BootStatus,
}

/// POST actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// `mode`
    Mode,
    /// `wifi`
    Wifi,
    /// `wifi_remove`
    WifiRemove,
    /// `add`
    Add,
    /// `remove`
    Remove,
    /// `enable`
    Enable,
    /// `setup_done`
    SetupDone,
    /// Anything else.
    Unknown,
}

/// All endpoints (for exhaustive tests).
pub const ENDPOINTS: [Endpoint; 7] =
    [Endpoint::Home, Endpoint::Status, Endpoint::Diagnostics, Endpoint::WifiScan, Endpoint::WifiSaved, Endpoint::Command, Endpoint::BootStatus];
/// All real actions.
pub const ACTIONS: [Action; 7] = [Action::Mode, Action::Wifi, Action::WifiRemove, Action::Add, Action::Remove, Action::Enable, Action::SetupDone];

fn one_of(v: Option<&str>, a: &str, b: &str) -> bool {
    matches!(v, Some(s) if s == a || s == b)
}

/// Classify a request from the facts the handler reads. `local_ipv4` is the address the client connected TO; a client of a subnet must have reached the
/// dongle's own address on that subnet, and Host / Origin must be canonical (the captive-portal DNS hijack makes phones send arbitrary Host names).
pub fn classify(peer_ipv4: Option<u32>, local_ipv4: Option<u32>, setup_active: bool, host: Option<&str>, origin: Option<&str>) -> Origin {
    let (Some(peer), Some(local)) = (peer_ipv4, local_ipv4) else { return Origin::Denied };
    if peer & 0xffff_ff00 == USB_SUBNET {
        if local != USB_SUBNET + 1 || !one_of(host, "192.168.77.1", "192.168.77.1:80") {
            return Origin::Denied;
        }
        if origin.is_some() && !one_of(origin, "http://192.168.77.1", "http://192.168.77.1:80") {
            return Origin::Denied;
        }
        return Origin::Usb;
    }
    if setup_active && peer & 0xffff_ff00 == AP_SUBNET {
        if local != AP_SUBNET + 1 || !one_of(host, "192.168.4.1", "192.168.4.1:80") {
            return Origin::Denied;
        }
        if origin.is_some() && !one_of(origin, "http://192.168.4.1", "http://192.168.4.1:80") {
            return Origin::Denied;
        }
        return Origin::SetupAp;
    }
    Origin::Denied
}

/// A client on the setup access point's subnet, whatever it asked for (captive-portal probes are redirected instead of answered 403).
pub fn in_setup_subnet(peer_ipv4: u32) -> bool {
    peer_ipv4 & 0xffff_ff00 == AP_SUBNET
}

/// May this origin fetch this page?
pub fn endpoint_allowed(origin: Origin, e: Endpoint) -> bool {
    match origin {
        Origin::Usb => true,
        Origin::SetupAp => matches!(e, Endpoint::Home | Endpoint::WifiScan | Endpoint::WifiSaved | Endpoint::Command),
        Origin::Denied => false,
    }
}

/// May this origin perform this action?
pub fn action_allowed(origin: Origin, a: Action) -> bool {
    if a == Action::Unknown {
        return false;
    }
    match origin {
        Origin::Usb => true,
        Origin::SetupAp => matches!(a, Action::Wifi | Action::WifiRemove | Action::SetupDone),
        Origin::Denied => false,
    }
}

/// Parse an action name (exact, case sensitive).
pub fn action_parse(name: Option<&str>) -> Action {
    match name {
        Some("mode") => Action::Mode,
        Some("wifi") => Action::Wifi,
        Some("wifi_remove") => Action::WifiRemove,
        Some("add") => Action::Add,
        Some("remove") => Action::Remove,
        Some("enable") => Action::Enable,
        Some("setup_done") => Action::SetupDone,
        _ => Action::Unknown,
    }
}

/// The open network may add a network but not set priority or name.
pub fn may_set_metadata(origin: Origin) -> bool {
    origin == Origin::Usb
}

/// ... and may not replace a saved network.
pub fn may_replace(origin: Origin) -> bool {
    origin == Origin::Usb
}

/// Constant time over the expected length; an empty expected token matches nothing.
pub fn token_equal(supplied: Option<&str>, expected: Option<&str>) -> bool {
    let (Some(s), Some(e)) = (supplied, expected) else { return false };
    let (s, e) = (s.as_bytes(), e.as_bytes());
    if e.is_empty() || s.len() != e.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..e.len() {
        diff |= s[i] ^ e[i];
    }
    diff == 0
}

/// [`TOKEN_LENGTH`] lowercase hex digits from 16 random bytes.
pub fn token_format(random: &[u8; 16]) -> [u8; TOKEN_LENGTH] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut t = [0u8; TOKEN_LENGTH];
    for (i, &b) in random.iter().enumerate() {
        t[2 * i] = HEX[(b >> 4) as usize];
        t[2 * i + 1] = HEX[(b & 15) as usize];
    }
    t
}
