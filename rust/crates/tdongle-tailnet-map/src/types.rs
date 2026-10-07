//! The typed records a projected MapResponse is made of, and their bounds.
//!
//! Every record is a plain fixed-size value. Strings are [`FixedStr`]s cut at the C's lengths (`ml_peer_update_t.hostname[64]`, `ml_derp_region_t.code[8]` ...),
//! lists are arrays with a count, and what does not fit is dropped *and counted* ([`crate::MapStats`]).

use tdongle_tailnet_types::{FixedStr, Key32};

use crate::derp_cert::DerpCert;

/// `ML_MAX_PEERS` of the shipped firmware (`sdkconfig.defaults: CONFIG_ML_MAX_PEERS=8`): the live WireGuard working set, and in the RAM staging mode the
/// number of entries one MapResponse section may carry.
pub const ML_MAX_PEERS: usize = 8;
/// `ML_MAX_ENDPOINTS`: endpoints kept per peer.
pub const MAX_ENDPOINTS: usize = 8;
/// `MICROLINK_MAX_PEER_ROUTES`: subnet routes kept per peer.
pub const MAX_PEER_ROUTES: usize = 8;
/// `ML_MAX_DERP_REGIONS`: DERP regions kept (the preferred region always survives).
pub const MAX_DERP_REGIONS: usize = 4;
/// `ML_MAX_DERP_NODES`: nodes kept per DERP region.
pub const MAX_DERP_NODES: usize = 2;
/// Longest peer host name (`char hostname[64]` minus the NUL).
pub const HOSTNAME_MAX: usize = 63;
/// Longest self MagicDNS name (`ML_PUBLISHED_NAME_MAX` 128 minus the NUL; a longer name is ignored).
pub const SELF_NAME_MAX: usize = 127;
/// DNS resolvers kept in a [`DnsConfig`] (default list and per route).
pub const MAX_DNS_RESOLVERS: usize = 4;
/// Split-DNS routes kept.
pub const MAX_DNS_ROUTES: usize = 4;
/// Resolvers kept per split-DNS route.
pub const MAX_ROUTE_RESOLVERS: usize = 2;
/// Search domains / cert domains kept.
pub const MAX_DNS_DOMAINS: usize = 4;
/// Longest DNS name or suffix kept.
pub const DNS_NAME_MAX: usize = 63;
/// Longest resolver address kept (`1.1.1.1`, `[2606:4700::1111]:53`, `https://dns.google/dns-query`).
pub const DNS_ADDR_MAX: usize = 47;

/// What a peer record asks the directory to do (the C's `ML_PEER_ADD`, `ML_PEER_REMOVE`, `ML_PEER_UPDATE_ENDPOINT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAction {
    /// Insert or replace the whole record.
    Add,
    /// Delete the peer (matched by node id, else by node key).
    Remove,
    /// Merge the present fields of a `PeersChangedPatch` / `OnlineChange` entry into the existing record (see [`crate::directory::merge_update`]).
    Patch,
}

/// Which MapResponse section a record came from. The values are the C's `kind` numbers (`gateway_stage_event`), which `ml_directory_stage(group, ...)` stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Group {
    /// `Peers`: a full list. Its presence makes the map *authoritative*: every peer it omits is revoked.
    Peers = 2,
    /// `PeersRemoved`: node ids (or, as a fallback, node keys) to delete.
    Removed = 3,
    /// `PeersChangedPatch`: field-level updates.
    Patch = 4,
    /// `PeersChanged`: incremental full records. Ignored by the C when the same map carries `Peers`.
    Changed = 6,
    /// `OnlineChange`: `{"<NodeID>": bool}` liveness updates (not read by the C; staged as patches).
    OnlineChange = 7,
}

/// One IPv4 endpoint (`ip:port`) of a peer. IPv6 endpoints are dropped (the C's `sscanf("%u.%u.%u.%u:%u")` cannot read them; counted).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// Host byte order, `a.b.c.d` = `a<<24 | b<<16 | c<<8 | d`.
    pub ip: u32,
    /// Port.
    pub port: u16,
}

/// A subnet route a peer advertises in `AllowedIPs`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Route {
    /// Network address, host byte order.
    pub network: u32,
    /// Prefix length 0..=32.
    pub prefix_len: u8,
}

/// One peer update: the typed form of a `tailcfg.Node` (or `PeerChange`, or a removal) after projection. The C's `ml_peer_update_t`, plus the fields the C's
/// projector dropped and the port keeps (`machine_key`, `key_expiry`, `tag_count`, `cap`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// What to do with it.
    pub action: PeerAction,
    /// The section it came from.
    pub group: Group,
    /// `Node.ID` (`PeerChange.NodeID`, a removal's number); `None` when the document had none.
    pub node_id: Option<u64>,
    /// First address when it is IPv4 (`Addresses[0]`), host byte order; 0 when absent. A record with `vpn_ip == 0` is an empty slot to the directory.
    pub vpn_ip: u32,
    /// `Node.Key` (`nodekey:` + 64 hex); all zero when absent or malformed.
    pub node_key: Key32,
    /// `Node.DiscoKey`; zero when absent.
    pub disco_key: Key32,
    /// `Node.Machine` (`mkey:`); zero when absent. Not kept by the C.
    pub machine_key: Key32,
    /// `Node.Name` without the trailing dot, cut at [`HOSTNAME_MAX`].
    pub name: FixedStr<HOSTNAME_MAX>,
    /// Home DERP region (`HomeDERP`, else the legacy `DERP` string `127.3.3.40:N`; `DERPRegion` in a patch); 0 = unknown / unchanged.
    pub home_derp: u16,
    /// Endpoints; the first `endpoint_count`.
    pub endpoints: [Endpoint; MAX_ENDPOINTS],
    /// Number of valid `endpoints`.
    pub endpoint_count: u8,
    /// False in a patch that carried no `Endpoints` array: the existing endpoints stay (the C's `endpoint_count == -1`). Always true in a full record.
    pub endpoints_present: bool,
    /// `AllowedIPs` contains `0.0.0.0/0`: the peer offers to be an exit node.
    pub is_exit_node: bool,
    /// Subnet routes (non-CGNAT, not `0.0.0.0/0`); the first `route_count`.
    pub routes: [Route; MAX_PEER_ROUTES],
    /// Number of valid `routes`.
    pub route_count: u8,
    /// `Node.Online`: `None` = the document did not say (keep the current value).
    pub online: Option<bool>,
    /// `Node.KeyExpiry` as seconds since the Unix epoch; 0 = does not expire / absent. Not kept by the C.
    pub key_expiry: i64,
    /// `Node.Cap` (capability version); 0 = absent. Not kept by the C.
    pub cap: u32,
    /// Number of `Node.Tags`; the tag names are not kept. Not kept by the C.
    pub tag_count: u8,
}

impl PeerRecord {
    /// `size_of::<PeerRecord>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<PeerRecord>();

    /// An empty record for `action` / `group`.
    pub fn new(action: PeerAction, group: Group) -> Self {
        Self {
            action,
            group,
            node_id: None,
            vpn_ip: 0,
            node_key: Key32::ZERO,
            disco_key: Key32::ZERO,
            machine_key: Key32::ZERO,
            name: FixedStr::new(),
            home_derp: 0,
            endpoints: [Endpoint { ip: 0, port: 0 }; MAX_ENDPOINTS],
            endpoint_count: 0,
            endpoints_present: !matches!(action, PeerAction::Patch),
            is_exit_node: false,
            routes: [Route { network: 0, prefix_len: 0 }; MAX_PEER_ROUTES],
            route_count: 0,
            online: None,
            key_expiry: 0,
            cap: 0,
            tag_count: 0,
        }
    }

    /// The valid endpoints.
    pub fn endpoint_list(&self) -> &[Endpoint] {
        &self.endpoints[..self.endpoint_count as usize]
    }

    /// The valid subnet routes.
    pub fn route_list(&self) -> &[Route] {
        &self.routes[..self.route_count as usize]
    }
}

/// This node's own record (`MapResponse.Node`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfNode {
    /// `Node.Name` (MagicDNS FQDN, trailing dot kept as sent); `None` when absent or too long (>= 128 bytes, ignored like the C).
    pub name: Option<FixedStr<SELF_NAME_MAX>>,
    /// `Addresses[0]` when it is IPv4, host byte order (the C's `ml->vpn_ip`).
    pub vpn_ip: Option<u32>,
    /// `Node.Expired`: the node key is expired; the C then applies nothing but the "authorization_expired" state.
    pub expired: bool,
    /// `Node.ID`.
    pub node_id: Option<u64>,
    /// `Node.Key`; zero when absent.
    pub node_key: Key32,
    /// `Node.DiscoKey`; zero when absent.
    pub disco_key: Key32,
    /// `Node.Machine`; zero when absent.
    pub machine_key: Key32,
    /// `Node.HomeDERP`; 0 when absent.
    pub home_derp: u16,
    /// `Node.KeyExpiry` (Unix seconds); 0 = none.
    pub key_expiry: i64,
    /// `Node.Cap`.
    pub cap: u32,
    /// Number of `Node.Tags`.
    pub tag_count: u8,
}

impl SelfNode {
    /// `size_of::<SelfNode>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<SelfNode>();

    /// An empty self record.
    pub fn new() -> Self {
        Self {
            name: None,
            vpn_ip: None,
            expired: false,
            node_id: None,
            node_key: Key32::ZERO,
            disco_key: Key32::ZERO,
            machine_key: Key32::ZERO,
            home_derp: 0,
            key_expiry: 0,
            cap: 0,
            tag_count: 0,
        }
    }
}

impl Default for SelfNode {
    fn default() -> Self {
        Self::new()
    }
}

/// One DERP server of a region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpNode {
    /// `HostName` (cut at 63).
    pub hostname: FixedStr<HOSTNAME_MAX>,
    /// `IPv4` when it parses; the C kept the string.
    pub ipv4: Option<[u8; 4]>,
    /// `IPv6` when it parses.
    pub ipv6: Option<[u8; 16]>,
    /// `STUNPort`; 0 = default 3478.
    pub stun_port: u16,
    /// `DERPPort`; 0 = default 443.
    pub derp_port: u16,
    /// `STUNOnly`: serves STUN, not DERP.
    pub stun_only: bool,
    /// `CanPort80` (not kept by the C).
    pub can_port80: bool,
    /// How to authenticate the TLS server (`CertName`).
    pub cert: DerpCert,
}

impl DerpNode {
    pub(crate) fn empty() -> Self {
        Self { hostname: FixedStr::new(), ipv4: None, ipv6: None, stun_port: 0, derp_port: 0, stun_only: false, can_port80: false, cert: DerpCert::Invalid }
    }
}

/// One DERP region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpRegion {
    /// `RegionID` (the C casts the JSON number to 16 bits).
    pub region_id: u16,
    /// `RegionCode`, cut at 7.
    pub code: FixedStr<7>,
    /// `RegionName`, cut at 23.
    pub name: FixedStr<23>,
    /// Servers; the first `node_count`.
    pub nodes: [DerpNode; MAX_DERP_NODES],
    /// Number of valid `nodes`.
    pub node_count: u8,
    /// `Avoid`.
    pub avoid: bool,
}

impl DerpRegion {
    /// `size_of::<DerpRegion>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<DerpRegion>();

    pub(crate) fn empty() -> Self {
        Self { region_id: 0, code: FixedStr::new(), name: FixedStr::new(), nodes: [DerpNode::empty(), DerpNode::empty()], node_count: 0, avoid: false }
    }

    /// The valid servers.
    pub fn node_list(&self) -> &[DerpNode] {
        &self.nodes[..self.node_count as usize]
    }
}

/// The DERP map: at most [`MAX_DERP_REGIONS`] regions, the preferred one always among them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpMap {
    /// Regions; the first `count`.
    pub regions: [DerpRegion; MAX_DERP_REGIONS],
    /// Number of valid `regions` (may be 0: an explicitly empty `Regions`).
    pub count: u8,
}

impl DerpMap {
    /// `size_of::<DerpMap>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<DerpMap>();

    pub(crate) fn empty() -> Self {
        Self { regions: [DerpRegion::empty(), DerpRegion::empty(), DerpRegion::empty(), DerpRegion::empty()], count: 0 }
    }

    /// The valid regions.
    pub fn region_list(&self) -> &[DerpRegion] {
        &self.regions[..self.count as usize]
    }
}

/// Regions the compact index of the DERP map keeps (Tailscale's public map has about thirty).
pub const MAX_DERP_INDEX: usize = 32;
/// Longest host name the compact index keeps (a longer one is left out and counted).
pub const DERP_INDEX_HOST_MAX: usize = 32;
/// Pinned leaf certificates the index can hold (public regions use the default policy; a self-hosted map pins at most a region or two).
pub const DERP_INDEX_PINS: usize = 2;

/// How a region's relay is authenticated, as far as the index keeps it: the default (verify against the host name), a pinned leaf, or never connect. A `CertName`
/// that is a different DNS name is kept as the unusable `Invalid` (public Tailscale regions use the default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexCert {
    /// Verify against the host name.
    Hostname,
    /// The leaf must hash to this SHA-256.
    Pin([u8; 32]),
    /// Do not connect.
    Invalid,
}

/// One region of the DERP map, reduced to what a link to it needs: the id, the first usable node's host and port, how to authenticate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpEntry {
    /// `RegionID`.
    pub region_id: u16,
    /// `DERPPort`; 0 = 443.
    pub port: u16,
    /// The node's `HostName`.
    pub host: FixedStr<DERP_INDEX_HOST_MAX>,
    /// 0: verify against the host name; 1: never connect; 2 and up: the leaf must hash to `pins[kind - 2]` of the index.
    kind: u8,
}

/// Every region of the DERP map in compact form, whether or not the 4 full regions kept for the netcheck include it: a peer may be homed on any region, and a link to it
/// needs only this much. About 1.3 KB for 32 regions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpIndex {
    /// Entries; the first `count`.
    pub entries: [DerpEntry; MAX_DERP_INDEX],
    /// Pinned leaf hashes the entries refer to; the first `pin_count`.
    pins: [[u8; 32]; DERP_INDEX_PINS],
    /// Number of valid `entries`.
    pub count: u8,
    pin_count: u8,
}

impl DerpIndex {
    /// `size_of::<DerpIndex>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<DerpIndex>();

    /// No regions.
    pub const fn empty() -> Self {
        Self {
            entries: [const { DerpEntry { region_id: 0, port: 0, host: FixedStr::new(), kind: 0 } }; MAX_DERP_INDEX],
            pins: [[0; 32]; DERP_INDEX_PINS],
            count: 0,
            pin_count: 0,
        }
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.count = 0;
        self.pin_count = 0;
    }

    /// The valid entries.
    pub fn list(&self) -> &[DerpEntry] {
        &self.entries[..self.count as usize]
    }

    /// The entry of `region`.
    pub fn find(&self, region: u16) -> Option<&DerpEntry> {
        self.list().iter().find(|e| e.region_id == region)
    }

    /// How `e` is authenticated.
    pub fn cert_of(&self, e: &DerpEntry) -> IndexCert {
        match e.kind {
            0 => IndexCert::Hostname,
            1 => IndexCert::Invalid,
            k => self.pins.get(usize::from(k) - 2).map_or(IndexCert::Invalid, |p| IndexCert::Pin(*p)),
        }
    }

    /// Add a region. False (nothing added) if the index is full, the id is a duplicate, or a pin has no room.
    pub fn push(&mut self, region_id: u16, port: u16, host: &str, cert: IndexCert) -> bool {
        let i = self.count as usize;
        if i >= MAX_DERP_INDEX || self.find(region_id).is_some() {
            return false;
        }
        let kind = match cert {
            IndexCert::Hostname => 0,
            IndexCert::Invalid => 1,
            IndexCert::Pin(p) => match self.pins[..self.pin_count as usize].iter().position(|q| *q == p) {
                Some(k) => k as u8 + 2,
                None if (self.pin_count as usize) < DERP_INDEX_PINS => {
                    self.pins[self.pin_count as usize] = p;
                    self.pin_count += 1;
                    self.pin_count - 1 + 2
                }
                None => return false,
            },
        };
        let e = &mut self.entries[i];
        e.region_id = region_id;
        e.port = port;
        e.host.set(host);
        e.kind = kind;
        self.count += 1;
        true
    }
}

/// A DNS resolver (`dnstype.Resolver`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsResolver {
    /// `Addr`: an IP, `ip:port`, or a DoH URL.
    pub addr: FixedStr<DNS_ADDR_MAX>,
    /// `UseWithExitNode`.
    pub use_with_exit_node: bool,
}

/// A split-DNS route: names under `suffix` go to these resolvers (none = the system's).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsRoute {
    /// The DNS suffix (key of `DNSConfig.Routes`).
    pub suffix: FixedStr<DNS_NAME_MAX>,
    /// Resolvers; the first `resolver_count`.
    pub resolvers: [DnsResolver; MAX_ROUTE_RESOLVERS],
    /// Number of valid `resolvers`.
    pub resolver_count: u8,
}

/// `MapResponse.DNSConfig`, bounded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsConfig {
    /// `Resolvers` (and the legacy `Nameservers`).
    pub resolvers: [DnsResolver; MAX_DNS_RESOLVERS],
    /// Number of valid `resolvers`.
    pub resolver_count: u8,
    /// `Routes`.
    pub routes: [DnsRoute; MAX_DNS_ROUTES],
    /// Number of valid `routes`.
    pub route_count: u8,
    /// `Domains` (search domains).
    pub domains: [FixedStr<DNS_NAME_MAX>; MAX_DNS_DOMAINS],
    /// Number of valid `domains`.
    pub domain_count: u8,
    /// `CertDomains`.
    pub cert_domains: [FixedStr<DNS_NAME_MAX>; MAX_DNS_DOMAINS],
    /// Number of valid `cert_domains`.
    pub cert_domain_count: u8,
    /// `Proxied`: MagicDNS names are answered by this node.
    pub proxied: bool,
}

impl DnsConfig {
    /// `size_of::<DnsConfig>()` on the compiling target.
    pub const SIZE: usize = core::mem::size_of::<DnsConfig>();

    /// The valid resolvers.
    pub fn resolver_list(&self) -> &[DnsResolver] {
        &self.resolvers[..self.resolver_count as usize]
    }
    /// The valid routes.
    pub fn route_list(&self) -> &[DnsRoute] {
        &self.routes[..self.route_count as usize]
    }
    /// The valid search domains.
    pub fn domain_list(&self) -> &[FixedStr<DNS_NAME_MAX>] {
        &self.domains[..self.domain_count as usize]
    }
    /// The valid cert domains.
    pub fn cert_domain_list(&self) -> &[FixedStr<DNS_NAME_MAX>] {
        &self.cert_domains[..self.cert_domain_count as usize]
    }
}
