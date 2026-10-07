//! The peer record the control plane hands to the WireGuard task and the flash directory stores (`ml_peer_update_t`, `microlink_internal.h`).

use tdongle_tailnet_types::FixedStr;

/// A public key (WireGuard or DISCO). Public data: plain bytes, `Copy`, compared without constant-time machinery.
pub type PubKey = [u8; 32];

/// `ML_MAX_ENDPOINTS`.
pub const ML_MAX_ENDPOINTS: usize = 8;
/// `MICROLINK_MAX_PEER_ROUTES`.
pub const MICROLINK_MAX_PEER_ROUTES: usize = 8;
/// Hostname capacity of a record (`hostname[64]`).
pub const HOSTNAME_BYTES: usize = 64;

/// One candidate endpoint of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Endpoint {
    /// IPv4 address, network byte order as the C keeps it.
    pub ip: u32,
    /// UDP port.
    pub port: u16,
    /// The address is IPv6 (the 4-byte `ip` is then not meaningful).
    pub is_ipv6: bool,
}

impl Endpoint {
    /// All zero (`const`, so state built from it can live in a `static`).
    pub const fn new() -> Self {
        Self { ip: 0, port: 0, is_ipv6: false }
    }
}

/// A subnet route a peer advertises (`microlink_route_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Route {
    /// Network address, host byte order.
    pub network: u32,
    /// CIDR prefix length, 0..=32.
    pub prefix_len: u8,
}

impl Route {
    /// All zero (`const`, so state built from it can live in a `static`).
    pub const fn new() -> Self {
        Self { network: 0, prefix_len: 0 }
    }
}

/// What the directory says about one peer (`ml_peer_update_t` without the action).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirRecord {
    /// The peer's tailnet IPv4 address. Zero marks an empty directory slot.
    pub vpn_ip: u32,
    /// WireGuard public key.
    pub public_key: PubKey,
    /// DISCO public key.
    pub disco_key: PubKey,
    /// Hostname (the FQDN truncated to 64 bytes).
    pub hostname: FixedStr<HOSTNAME_BYTES>,
    /// Home DERP region, 0 = unknown.
    pub derp_region: u16,
    /// Endpoints; only the first `endpoint_count` are valid.
    pub endpoints: [Endpoint; ML_MAX_ENDPOINTS],
    /// The C's `int endpoint_count`: negative means "not carried by this update" (UPDATE_ENDPOINT only).
    pub endpoint_count: i32,
    /// The peer advertises 0.0.0.0/0.
    pub is_exit_node: bool,
    /// Advertised subnet routes; only the first `subnet_route_count` are valid.
    pub subnet_routes: [Route; MICROLINK_MAX_PEER_ROUTES],
    /// Number of valid routes.
    pub subnet_route_count: u8,
    /// `Node.Online` was carried by the update.
    pub has_online: bool,
    /// `Node.Online`, valid when `has_online`.
    pub online: bool,
    /// `node_id` was parsed.
    pub has_node_id: bool,
    /// Tailscale NodeID.
    pub node_id: u64,
}

impl DirRecord {
    /// All zero (`const`, so state built from it can live in a `static`).
    pub const fn new() -> Self {
        Self {
            vpn_ip: 0,
            public_key: [0; 32],
            disco_key: [0; 32],
            hostname: FixedStr::<HOSTNAME_BYTES>::new(),
            derp_region: 0,
            endpoints: [const { Endpoint::new() }; ML_MAX_ENDPOINTS],
            endpoint_count: 0,
            is_exit_node: false,
            subnet_routes: [const { Route::new() }; MICROLINK_MAX_PEER_ROUTES],
            subnet_route_count: 0,
            has_online: false,
            online: false,
            has_node_id: false,
            node_id: 0,
        }
    }
}

impl DirRecord {
    /// `sizeof` of the in-RAM record.
    pub const STATE_BYTES: usize = core::mem::size_of::<DirRecord>();
}

/// What a directory update does (`ml_peer_update_t.action`, the three values the directory handles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    /// Insert or replace.
    Add = 0,
    /// Remove.
    Remove = 1,
    /// Merge endpoint / key / region / online fields into the existing record.
    UpdateEndpoint = 2,
}
