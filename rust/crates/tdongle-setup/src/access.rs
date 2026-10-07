//! Who may ask the setup HTTP server for what (`main/setup_access.c`, ADR 0024 "AP-origin restrictions").
//!
//! Pure decisions from facts the socket layer reads: peer and local address, `Host`, `Origin`. A request that is neither from the USB
//! host nor from the setup network is [`Origin::Denied`].

const USB_SUBNET: u32 = 0xc0a8_4d00; // 192.168.77.0
const AP_SUBNET: u32 = 0xc0a8_0400; // 192.168.4.0
const MASK: u32 = 0xffff_ff00;

/// `ACCESS_TOKEN_LENGTH`.
pub const TOKEN_LENGTH: usize = 32;

/// Who is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Neither: refused.
    Denied,
    /// The USB host, 192.168.77.1 (tailnet mode; never present in a setup boot, which has no USB netif).
    Usb,
    /// A phone or laptop on the open setup access point.
    SetupAp,
}

/// `access_endpoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `/`
    Home,
    /// `/status`
    Status,
    /// `/diagnostics`
    Diagnostics,
    /// `/wifi-scan`
    WifiScan,
    /// `/wifi-saved`
    WifiSaved,
    /// `/command`
    Command,
    /// `/boot-status`
    BootStatus,
}

/// `access_action`.
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
    /// anything else (or no action string)
    Unknown,
}

fn one_of(value: Option<&[u8]>, a: &[u8], b: &[u8]) -> bool {
    value.is_some_and(|v| v == a || v == b)
}

/// The facts of one request, as the handler reads them.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    /// The client's IPv4 address (host byte order), `None` when it could not be read (or is not IPv4 / IPv4-mapped).
    pub peer: Option<u32>,
    /// The address the client connected to (`getsockname`), `None` when unreadable.
    pub local: Option<u32>,
    /// This boot is a setup boot.
    pub setup_active: bool,
    /// The `Host` header, `None` when absent or too long for the C buffer.
    pub host: Option<&'a [u8]>,
    /// The `Origin` header, `None` when absent (an empty header counts as absent).
    pub origin: Option<&'a [u8]>,
}

/// `access_classify`.
#[must_use]
pub fn classify(f: &Facts<'_>) -> Origin {
    let (Some(peer), Some(local)) = (f.peer, f.local) else { return Origin::Denied };
    if peer & MASK == USB_SUBNET {
        if local != USB_SUBNET + 1 || !one_of(f.host, b"192.168.77.1", b"192.168.77.1:80") {
            return Origin::Denied;
        }
        if f.origin.is_some() && !one_of(f.origin, b"http://192.168.77.1", b"http://192.168.77.1:80") {
            return Origin::Denied;
        }
        return Origin::Usb;
    }
    if f.setup_active && peer & MASK == AP_SUBNET {
        if local != AP_SUBNET + 1 || !one_of(f.host, b"192.168.4.1", b"192.168.4.1:80") {
            return Origin::Denied;
        }
        if f.origin.is_some() && !one_of(f.origin, b"http://192.168.4.1", b"http://192.168.4.1:80") {
            return Origin::Denied;
        }
        return Origin::SetupAp;
    }
    Origin::Denied
}

/// `access_in_setup_subnet`.
#[must_use]
pub const fn in_setup_subnet(peer: u32) -> bool {
    peer & MASK == AP_SUBNET
}

/// `access_endpoint_allowed`.
#[must_use]
pub const fn endpoint_allowed(origin: Origin, endpoint: Endpoint) -> bool {
    match origin {
        Origin::Usb => true,
        Origin::SetupAp => matches!(endpoint, Endpoint::Home | Endpoint::WifiScan | Endpoint::WifiSaved | Endpoint::Command),
        Origin::Denied => false,
    }
}

/// `access_action_allowed`.
#[must_use]
pub const fn action_allowed(origin: Origin, action: Action) -> bool {
    if matches!(action, Action::Unknown) {
        return false;
    }
    match origin {
        Origin::Usb => true,
        Origin::SetupAp => matches!(action, Action::Wifi | Action::WifiRemove | Action::SetupDone),
        Origin::Denied => false,
    }
}

/// `access_action_parse` (exact, case sensitive).
#[must_use]
pub fn parse_action(name: Option<&[u8]>) -> Action {
    match name {
        Some(b"mode") => Action::Mode,
        Some(b"wifi") => Action::Wifi,
        Some(b"wifi_remove") => Action::WifiRemove,
        Some(b"add") => Action::Add,
        Some(b"remove") => Action::Remove,
        Some(b"enable") => Action::Enable,
        Some(b"setup_done") => Action::SetupDone,
        _ => Action::Unknown,
    }
}

/// `access_may_set_metadata`: a name or a priority.
#[must_use]
pub const fn may_set_metadata(origin: Origin) -> bool {
    matches!(origin, Origin::Usb)
}

/// `access_may_replace`: overwrite a saved network.
#[must_use]
pub const fn may_replace(origin: Origin) -> bool {
    matches!(origin, Origin::Usb)
}

/// `access_token_equal`: constant time over the expected length; an empty expected token matches nothing.
#[must_use]
pub fn token_equal(supplied: Option<&[u8]>, expected: &[u8]) -> bool {
    let Some(supplied) = supplied else { return false };
    if expected.is_empty() || supplied.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in supplied.iter().zip(expected) {
        difference |= a ^ b;
    }
    core::hint::black_box(difference) == 0
}

/// `access_token_format`: 32 lowercase hex digits from 16 random bytes.
#[must_use]
pub fn token_format(random: &[u8; 16]) -> [u8; TOKEN_LENGTH] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut t = [0u8; TOKEN_LENGTH];
    for (i, b) in random.iter().enumerate() {
        t[2 * i] = HEX[usize::from(b >> 4)];
        t[2 * i + 1] = HEX[usize::from(b & 15)];
    }
    t
}

/// `peer_ipv4`: the IPv4 address of an IPv6 socket address, accepted only for an IPv4-mapped one (`::ffff:a.b.c.d`).
#[must_use]
pub fn ipv4_from_ipv6(bytes: &[u8; 16]) -> Option<u32> {
    const MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    (bytes[..12] == MAPPED).then(|| u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]))
}
