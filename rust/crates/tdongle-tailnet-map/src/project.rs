//! The MapResponse projector: a [`TokenSink`] that turns the token stream into typed [`MapEvent`]s.
//!
//! This is the C's `gateway_project*.inc` + `gateway_stage.inc` + the semantic parts of `ml_coord.c` (`parse_peers_from_map_response`,
//! `decode_derp_regions`) as one state machine over [`Event`]s, with a fixed-size state ([`MapProjector::STATE_BYTES`]) and no allocation.
//!
//! # Contract with the sink
//!
//! * [`MapEvent::Peer`] and [`MapEvent::PeerSeen`] are **staged**: they arrive while the map is still being validated. A sink must buffer them (the C
//!   writes them to a one-record scratch and a journal, `ml_directory_stage`) and apply nothing until [`MapEvent::Commit`]. The first staged event is the
//!   "begin" (the C opens its transaction lazily, so a keep-alive map costs nothing).
//! * Everything else ([`MapEvent::SelfNode`], [`MapEvent::Derp`], [`MapEvent::Dns`], ...) is delivered **only at the end of a map that validated
//!   completely**, immediately before [`MapEvent::Commit`].
//! * A map that fails anywhere (malformed JSON, a bound exceeded, a refusal by the sink) ends with exactly one [`MapEvent::Abort`] and nothing is
//!   committed: "invalid late input must apply nothing".
//! * At `Commit` the sink applies the staged records in three passes (adds, removals, patches; [`crate::directory::commit_pass`]), skipping
//!   [`Group::Changed`] records when [`MapSummary::authoritative`] ([`crate::directory::is_effective`]), and, when the map is authoritative, revokes
//!   every stored peer the `Peers` list omitted. When [`MapSummary::self_expired`] the C applies no peer batch and no DERP map.
//!
//! # What is kept and what is dropped
//!
//! The C's projection keeps these members and discards the rest (still validating them): at the root `Node`, `Peers`/`peers`, `PeersChanged`,
//! `PeersChangedPatch`, `PeersRemoved`, `DERPMap`; in a node `ID`, `NodeID`, `Name`, `Key`, `DiscoKey`, `Addresses`, `AllowedIPs`, `HomeDERP`, `DERP`,
//! `DERPRegion`, `Endpoints`, `Online`, `Expired`; in a DERP region `RegionID`, `RegionCode`, `RegionName`, `Avoid`, `Nodes`; in a DERP node `HostName`,
//! `IPv4`, `IPv6`, `STUNPort`, `DERPPort`, `STUNOnly`, `CertName`. The port additionally *reads* `Machine`, `KeyExpiry`, `Tags`, `Cap`, `CanPort80`,
//! `KeepAlive`, `ControlTime`, `Domain`, `DNSConfig`, `PeerSeenChange`, `OnlineChange`, `CollectServices` and notes `PacketFilter(s)`; those do not count
//! against the C's per-record bounds, so a map the C accepts is accepted here. Member names match ASCII case-insensitively (as `cJSON_GetObjectItem`
//! does); when a member occurs twice in one object the first wins, except the root control fields, where a repeat fails the map (as in the C).
//!
//! The C's per-record bounds are kept, because they decide which maps fail: a captured record (the self `Node`, one peer, one removal, one DERP region)
//! may project to at most [`RECORD_RAW_MAX`] bytes, hold at most [`RECORD_NODES_MAX`] values and [`RECORD_STRINGS_MAX`] decoded string bytes (keys
//! included), and its retained strings must be clean text (no NUL, no lone surrogate; the port also refuses invalid UTF-8). In the RAM staging mode a
//! section may carry at most [`ML_MAX_PEERS`] entries ([`MapLimits::RAM`]); with a flash directory it is unbounded ([`MapLimits::FLASH`]).

use tdongle_tailnet_types::{Counter, FixedStr, Key32};

use crate::derp_cert::{self, DerpCert};
use crate::json::{self, Event, JsonError, MAX_DEPTH, ParseError, Policy, Text, TokenSink, Tokenizer};
use crate::types::*;
use crate::util;

/// A captured record may project to at most this many bytes (`char record[4096]` minus the NUL).
pub const RECORD_RAW_MAX: u32 = 4095;
/// A captured record may hold at most this many JSON values (`cJSON nodes[128]`).
pub const RECORD_NODES_MAX: u32 = 128;
/// A captured record may decode to at most this many string bytes, one NUL per string and key included (`char strings[4096]`).
pub const RECORD_STRINGS_MAX: u32 = 4096;

/// Bounds of one map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapLimits {
    /// Entries one section (`Peers`, `PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `OnlineChange`) may carry; `None` = unbounded.
    pub section_entries: Option<u16>,
}

impl MapLimits {
    /// The C without a flash directory: [`ML_MAX_PEERS`] entries per section, then "Map peer update section exceeds configured capacity".
    pub const RAM: MapLimits = MapLimits { section_entries: Some(ML_MAX_PEERS as u16) };
    /// The C with the flash directory (the shipped firmware): sections are unbounded, the directory is the store.
    pub const FLASH: MapLimits = MapLimits { section_entries: None };
}

/// Configuration of one projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapConfig {
    /// The preferred DERP region (`ml->derp_region_default`): always kept when the map has more than [`MAX_DERP_REGIONS`] regions.
    pub home_derp: u16,
    /// Section bounds.
    pub limits: MapLimits,
}

impl MapConfig {
    /// RAM staging limits ([`MapLimits::RAM`]) and `home_derp` as the preferred region.
    pub const fn new(home_derp: u16) -> Self {
        Self { home_derp, limits: MapLimits::RAM }
    }
    /// The same with the flash directory's unbounded sections.
    pub const fn with_flash_directory(mut self) -> Self {
        self.limits = MapLimits::FLASH;
        self
    }
}

/// Why a map was rejected. Nothing of a rejected map is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// Not valid JSON, or beyond the tokenizer's bounds (depth 32, key 126, scalar 95).
    Json(JsonError),
    /// The document is valid JSON but not an object.
    RootNotObject,
    /// A root control field (`Node`, `Peers`, `PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `DERPMap`, ...) occurs twice.
    DuplicateControlField,
    /// `Node` is neither an object nor null.
    BadSelfNode,
    /// `DERPMap` is neither an object nor null, `Regions` is not an object (or occurs twice), or a region is not an object.
    BadDerpMap,
    /// A record projects to more than [`RECORD_RAW_MAX`] bytes ("Map record exceeds 4 KiB capacity").
    RecordTooLarge,
    /// A record has more than [`RECORD_NODES_MAX`] values or [`RECORD_STRINGS_MAX`] string bytes, or retains text that is not clean.
    RecordDecode,
    /// A section has more entries than [`MapLimits::section_entries`].
    SectionFull(Group),
    /// The sink refused a staged record ("Peer flash staging failed; previous directory retained").
    SinkRefused,
    /// The sink refused the commit ("Map batch admission failed; no map applied").
    CommitRefused,
    /// [`MapProjector::finish`] before the document was complete.
    Incomplete,
}

impl MapError {
    /// The C's `ml->map_error` code (`gateway_map_fail`): 6 capacity, 8 malformed / unsupported, 9 commit.
    pub fn code(&self) -> u32 {
        match self {
            MapError::RecordTooLarge | MapError::SectionFull(_) => 6,
            MapError::SinkRefused | MapError::CommitRefused => 9,
            _ => 8,
        }
    }

    /// The C's message (`ml->transport_error`).
    pub fn message(&self) -> &'static str {
        match self {
            MapError::Json(_) | MapError::RootNotObject | MapError::BadSelfNode | MapError::BadDerpMap => "Map JSON exceeds parser bounds or is malformed",
            MapError::DuplicateControlField => "Map contains duplicate control fields",
            MapError::RecordTooLarge => "Map record exceeds 4 KiB capacity",
            MapError::RecordDecode => "Map record exceeds decoding bounds or contains unsupported text",
            MapError::SectionFull(_) => "Map peer update section exceeds configured capacity",
            MapError::SinkRefused => "Peer flash staging failed; previous directory retained",
            MapError::CommitRefused => "Map batch admission failed; no map applied",
            MapError::Incomplete => "Incomplete or unsupported semantic map",
        }
    }
}

/// A sink's refusal of an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkError;

/// What the projector tells the system.
#[derive(Clone, Copy, Debug)]
pub enum MapEvent<'a> {
    /// A staged peer update (see the module contract).
    Peer(&'a PeerRecord),
    /// A staged `PeerSeenChange` entry: the peer was (not) seen recently. Not read by the C.
    PeerSeen {
        /// The peer's node id.
        node_id: u64,
        /// The reported value.
        seen: bool,
    },
    /// The self `Node`, at commit time (only when the map carried one).
    SelfNode(&'a SelfNode),
    /// The DERP regions, at commit time (only when the map carried `DERPMap.Regions`; `count` may be 0).
    Derp(&'a DerpMap),
    /// `DNSConfig`, at commit time.
    Dns(&'a DnsConfig),
    /// `Domain` (the tailnet's MagicDNS domain), at commit time.
    Domain(&'a str),
    /// `ControlTime` (Unix seconds and nanoseconds), at commit time.
    ControlTime {
        /// Seconds since the epoch.
        secs: i64,
        /// Nanoseconds.
        nanos: u32,
    },
    /// `CollectServices`, at commit time.
    CollectServices(bool),
    /// The map was a `KeepAlive`, at commit time.
    KeepAlive,
    /// The map validated: apply the staged records (last event).
    Commit(&'a MapSummary),
    /// The map was rejected: discard the staged records (last event).
    Abort(MapError),
}

/// Receives the events of one map.
pub trait MapSink {
    /// One event. Refusing a staged event or the commit fails the map ([`MapError::SinkRefused`] / [`MapError::CommitRefused`]).
    fn event(&mut self, event: MapEvent<'_>) -> Result<(), SinkError>;
}

/// Every drop, refusal and bound hit while projecting, one counter per reason (the C's `map_*` statistics, and the counters the C did not have).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MapStats {
    /// Raw bytes fed (`ml->map_bytes`).
    pub bytes_in: u32,
    /// Bytes of the records the C's projector kept (`ml->map_projected_bytes`).
    pub projected_bytes: u32,
    /// `Peers` / `PeersChanged` entries staged.
    pub peers_staged: Counter,
    /// Removals staged.
    pub removals_staged: Counter,
    /// Patches staged (`PeersChangedPatch` and `OnlineChange`).
    pub patches_staged: Counter,
    /// `PeerSeenChange` entries staged.
    pub seen_staged: Counter,
    /// A `Peers` / `PeersChanged` element that is not an object (the C stages an empty record; dropped here).
    pub peer_not_object: Counter,
    /// A `PeersChangedPatch` element that is not an object (skipped, as in the C).
    pub patch_not_object: Counter,
    /// A `PeersRemoved` element that is neither a number nor a valid node key (skipped, as in the C).
    pub removed_bad_element: Counter,
    /// Endpoints beyond [`MAX_ENDPOINTS`] (the C stops reading at the 8th valid one).
    pub endpoints_over_cap: Counter,
    /// Endpoints that are not an IPv4 `ip:port` (IPv6 endpoints included).
    pub endpoints_bad: Counter,
    /// Subnet routes beyond [`MAX_PEER_ROUTES`].
    pub routes_over_cap: Counter,
    /// `AllowedIPs` entries that are not an IPv4 CIDR (IPv6 included).
    pub routes_bad: Counter,
    /// CGNAT (`100.64.0.0/10`) `AllowedIPs` entries skipped: the peers' own addresses.
    pub routes_cgnat_skipped: Counter,
    /// `Addresses` after the first (the C reads only `Addresses[0]`).
    pub addresses_ignored: Counter,
    /// `Addresses[0]` that is not an IPv4 address.
    pub addresses_bad: Counter,
    /// A key that is not 64 hex digits (the field stays all zero, as in the C).
    pub keys_bad: Counter,
    /// A self `Name` of 128 bytes or more (ignored, as in the C).
    pub self_name_ignored: Counter,
    /// A peer `Name` longer than 63 bytes (cut).
    pub names_cut: Counter,
    /// A number outside the range of its field.
    pub numbers_bad: Counter,
    /// A node-table member that this record kind does not use.
    pub fields_ignored: Counter,
    /// A member name the projection does not know (its value is validated and dropped).
    pub fields_skipped: Counter,
    /// A member repeated inside one object (the first wins).
    pub fields_duplicate: Counter,
    /// Non-home DERP regions dropped because [`MAX_DERP_REGIONS`] were already kept.
    pub derp_regions_dropped: Counter,
    /// A kept region replaced by the preferred one arriving late.
    pub derp_regions_replaced: Counter,
    /// DERP nodes beyond [`MAX_DERP_NODES`] per region.
    pub derp_nodes_over_cap: Counter,
    /// A DERP `Nodes` element that is not an object.
    pub derp_nodes_bad: Counter,
    /// A DERP `IPv4`/`IPv6` that does not parse.
    pub derp_ips_bad: Counter,
    /// A DERP node whose `CertName` is unusable ([`DerpCert::Invalid`]).
    pub derp_certs_invalid: Counter,
    /// A DNS resolver, route or domain beyond the bounds of [`DnsConfig`].
    pub dns_over_cap: Counter,
    /// A DNS name or address cut to fit.
    pub dns_text_cut: Counter,
    /// A `PeerSeenChange` / `OnlineChange` key that is not a node id.
    pub seen_keys_bad: Counter,
    /// A time stamp that is not RFC 3339.
    pub times_bad: Counter,
}

/// What the commit applies, delivered with [`MapEvent::Commit`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MapSummary {
    /// The map carried a `Peers` list: it is the whole truth, peers it omits are revoked and `PeersChanged` is superseded.
    pub authoritative: bool,
    /// The self node is expired (`Node.Expired`): the C applies nothing but "authorization_expired".
    pub self_expired: bool,
    /// The map carried a self `Node`.
    pub has_self: bool,
    /// The map carried `DERPMap.Regions`.
    pub derp_present: bool,
    /// The map carried `PacketFilter` or `PacketFilters` (read by nobody yet; validated and dropped).
    pub packet_filter_seen: bool,
    /// Entries per section ([`Group`] value as index: 2 `Peers`, 3 `Removed`, 4 `Patch`, 6 `Changed`, 7 `OnlineChange`).
    pub section_entries: [u32; 8],
    /// The statistics so far (the same as [`MapProjector::stats`]).
    pub stats: MapStats,
}

// ---- the state machine -------------------------------------------------------------------------------------------------------------------------------

/// The C's `gp_scope`: what the projection keeps under a value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Gp {
    Drop,
    Any,
    Root,
    Node,
    Derp,
    Regions,
    Region,
    DNode,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Skip,
    Root,
    SelfNode,
    List(Group),
    Peer(Group),
    Addresses,
    Endpoints,
    Aips,
    Tags,
    DerpMap,
    Regions,
    Region,
    Nodes,
    DNode,
    Dns,
    Resolvers,
    Nameservers,
    Resolver,
    Routes,
    Route,
    DnsStrs(bool),
    SeenMap(bool),
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    role: Role,
    gp: Gp,
    object: bool,
    first: bool,
}

const NO_FRAME: Frame = Frame { role: Role::Skip, gp: Gp::Drop, object: false, first: true };

/// Member names the projector reads (all contexts; at most 64 so a per-record `u64` can mark the ones seen).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum F {
    None,
    Elem,
    RNode,
    RPeers,
    RChanged,
    RRemoved,
    RPatch,
    RDerpMap,
    RKeepAlive,
    RControlTime,
    RDomain,
    RDns,
    RSeen,
    ROnline,
    RCollect,
    RPacketFilter,
    RPacketFilters,
    NId,
    NNodeId,
    NName,
    NKey,
    NDisco,
    NMachine,
    NAddresses,
    NAllowed,
    NHome,
    NLegacy,
    NDerpRegion,
    NEndpoints,
    NOnline,
    NExpired,
    NKeyExpiry,
    NTags,
    NCap,
    DRegions,
    RgId,
    RgCode,
    RgName,
    RgAvoid,
    RgNodes,
    DnHost,
    DnV4,
    DnV6,
    DnStun,
    DnDerp,
    DnStunOnly,
    DnCertName,
    DnCanPort80,
    DResolvers,
    DRoutes,
    DDomains,
    DProxied,
    DCertDomains,
    DNameservers,
    ResAddr,
    ResExit,
}

enum Val<'a> {
    Obj,
    Arr,
    Str(Text<'a>),
    Num(&'a [u8]),
    Bool(bool),
    Null,
}

impl Val<'_> {
    fn is_container(&self) -> bool {
        matches!(self, Val::Obj | Val::Arr)
    }
}

#[derive(Clone, Copy, Default, Debug)]
struct Budget {
    raw: u32,
    nodes: u32,
    strs: u32,
}

#[derive(Clone, Debug)]
struct PeerBuild {
    seen: u64,
    addr_idx: u8,
    has_ip: bool,
    modern: u16,
    legacy: u16,
    expired: bool,
    self_name: Option<FixedStr<SELF_NAME_MAX>>,
}

#[derive(Clone, Debug)]
struct RegionBuild {
    seen: u64,
    rid: Option<i32>,
}

#[derive(Clone, Debug)]
struct NodeBuild {
    seen: u64,
    host_whole: bool,
    cn_present: bool,
    cn_is_str: bool,
    cn_overlong: bool,
    cn: FixedStr<96>,
}

/// The mutable state minus the tokenizer.
#[derive(Clone, Debug)]
struct State {
    cfg: MapConfig,
    failed: Option<MapError>,
    done: bool,
    depth: u8,
    frames: [Frame; MAX_DEPTH],
    // the member name whose value comes next
    key_f: F,
    key_gp: Gp,
    key_dup: bool,
    key_raw: u32,
    key_dec: u32,
    key_unclean: bool,
    key_text: FixedStr<DNS_NAME_MAX>,
    key_text_ok: bool,
    // captured record
    capture: Option<u8>,
    budget: Budget,
    // root bookkeeping
    seen_root: u64,
    authoritative: bool,
    packet_filter_seen: bool,
    section: [u32; 8],
    keep_alive: bool,
    control_time: Option<(i64, u32)>,
    collect_services: Option<bool>,
    domain: Option<FixedStr<127>>,
    stats: MapStats,
    // self node / peer builder
    peer: PeerRecord,
    pb: PeerBuild,
    self_node: Option<SelfNode>,
    // DERP
    derp_present: bool,
    derp: DerpMap,
    region: DerpRegion,
    rb: RegionBuild,
    region_keys: u8,
    node: DerpNode,
    nb: NodeBuild,
    // DNS
    dns_present: bool,
    dns: DnsConfig,
    dns_seen: u64,
    res: DnsResolver,
    res_seen: u64,
    res_in_route: bool,
}

impl State {
    fn new(cfg: MapConfig) -> Self {
        Self {
            cfg,
            failed: None,
            done: false,
            depth: 0,
            frames: [NO_FRAME; MAX_DEPTH],
            key_f: F::None,
            key_gp: Gp::Drop,
            key_dup: false,
            key_raw: 0,
            key_dec: 0,
            key_unclean: false,
            key_text: FixedStr::new(),
            key_text_ok: false,
            capture: None,
            budget: Budget { raw: 0, nodes: 0, strs: 0 },
            seen_root: 0,
            authoritative: false,
            packet_filter_seen: false,
            section: [0; 8],
            keep_alive: false,
            control_time: None,
            collect_services: None,
            domain: None,
            stats: MapStats::default(),
            peer: PeerRecord::new(PeerAction::Add, Group::Peers),
            pb: PeerBuild { seen: 0, addr_idx: 0, has_ip: false, modern: 0, legacy: 0, expired: false, self_name: None },
            self_node: None,
            derp_present: false,
            derp: DerpMap::empty(),
            region: DerpRegion::empty(),
            rb: RegionBuild { seen: 0, rid: None },
            region_keys: 0,
            node: DerpNode::empty(),
            nb: NodeBuild { seen: 0, host_whole: false, cn_present: false, cn_is_str: false, cn_overlong: false, cn: FixedStr::new() },
            dns_present: false,
            dns: DnsConfig::default(),
            dns_seen: 0,
            res: DnsResolver::default(),
            res_seen: 0,
            res_in_route: false,
        }
    }
}

fn kw(t: &Text<'_>, name: &str) -> bool {
    t.eq_ignore_ascii_case(name)
}

/// The C's `gp_field`: the projection scope of a member of a `parent` scope.
fn gp_field(parent: Gp, t: &Text<'_>) -> Gp {
    match parent {
        Gp::Any => Gp::Any,
        Gp::Root => {
            if ["Node", "Peers", "PeersChanged", "PeersChangedPatch"].iter().any(|k| kw(t, k)) {
                Gp::Node
            } else if kw(t, "PeersRemoved") {
                Gp::Any
            } else if kw(t, "DERPMap") {
                Gp::Derp
            } else {
                Gp::Drop
            }
        }
        Gp::Node => {
            const KEPT: [&str; 13] =
                ["ID", "NodeID", "Name", "Key", "DiscoKey", "Addresses", "AllowedIPs", "HomeDERP", "DERP", "DERPRegion", "Endpoints", "Online", "Expired"];
            if KEPT.iter().any(|k| kw(t, k)) { Gp::Any } else { Gp::Drop }
        }
        Gp::Derp => {
            if kw(t, "Regions") {
                Gp::Regions
            } else {
                Gp::Drop
            }
        }
        Gp::Regions => Gp::Region,
        Gp::Region => {
            if kw(t, "Nodes") {
                Gp::DNode
            } else if ["RegionID", "RegionCode", "RegionName", "Avoid"].iter().any(|k| kw(t, k)) {
                Gp::Any
            } else {
                Gp::Drop
            }
        }
        Gp::DNode => {
            const KEPT: [&str; 7] = ["HostName", "IPv4", "IPv6", "STUNPort", "DERPPort", "STUNOnly", "CertName"];
            if KEPT.iter().any(|k| kw(t, k)) { Gp::Any } else { Gp::Drop }
        }
        Gp::Drop => Gp::Drop,
    }
}

fn field_lookup(role: Role, t: &Text<'_>) -> F {
    let table: &[(&str, F)] = match role {
        Role::Root => &[
            ("Node", F::RNode),
            ("Peers", F::RPeers),
            ("PeersChanged", F::RChanged),
            ("PeersRemoved", F::RRemoved),
            ("PeersChangedPatch", F::RPatch),
            ("DERPMap", F::RDerpMap),
            ("KeepAlive", F::RKeepAlive),
            ("ControlTime", F::RControlTime),
            ("Domain", F::RDomain),
            ("DNSConfig", F::RDns),
            ("PeerSeenChange", F::RSeen),
            ("OnlineChange", F::ROnline),
            ("CollectServices", F::RCollect),
            ("PacketFilter", F::RPacketFilter),
            ("PacketFilters", F::RPacketFilters),
        ],
        Role::SelfNode | Role::Peer(_) => &[
            ("ID", F::NId),
            ("NodeID", F::NNodeId),
            ("Name", F::NName),
            ("Key", F::NKey),
            ("DiscoKey", F::NDisco),
            ("Machine", F::NMachine),
            ("Addresses", F::NAddresses),
            ("AllowedIPs", F::NAllowed),
            ("HomeDERP", F::NHome),
            ("DERP", F::NLegacy),
            ("DERPRegion", F::NDerpRegion),
            ("Endpoints", F::NEndpoints),
            ("Online", F::NOnline),
            ("Expired", F::NExpired),
            ("KeyExpiry", F::NKeyExpiry),
            ("Tags", F::NTags),
            ("Cap", F::NCap),
        ],
        Role::DerpMap => &[("Regions", F::DRegions)],
        Role::Region => &[("RegionID", F::RgId), ("RegionCode", F::RgCode), ("RegionName", F::RgName), ("Avoid", F::RgAvoid), ("Nodes", F::RgNodes)],
        Role::DNode => &[
            ("HostName", F::DnHost),
            ("IPv4", F::DnV4),
            ("IPv6", F::DnV6),
            ("STUNPort", F::DnStun),
            ("DERPPort", F::DnDerp),
            ("STUNOnly", F::DnStunOnly),
            ("CertName", F::DnCertName),
            ("CanPort80", F::DnCanPort80),
        ],
        Role::Dns => &[
            ("Resolvers", F::DResolvers),
            ("Routes", F::DRoutes),
            ("Domains", F::DDomains),
            ("Proxied", F::DProxied),
            ("CertDomains", F::DCertDomains),
            ("Nameservers", F::DNameservers),
        ],
        Role::Resolver => &[("Addr", F::ResAddr), ("UseWithExitNode", F::ResExit)],
        _ => &[],
    };
    table.iter().find(|(name, _)| kw(t, name)).map(|(_, f)| *f).unwrap_or(F::None)
}

fn node_id_of(n: &[u8]) -> Option<u64> {
    json::number_i64(n).map(|v| v as u64).or_else(|| json::number_f64(n).filter(|f| f.is_finite()).map(|f| (f as i64) as u64))
}

fn int_of(n: &[u8]) -> Option<i32> {
    json::number_f64(n).filter(|f| f.is_finite()).map(|f| f as i32)
}

fn cut<const N: usize>(dst: &mut FixedStr<N>, t: &Text<'_>) -> bool {
    match t.as_str() {
        Some(s) => {
            let was_cut = dst.set(s);
            was_cut || t.is_truncated()
        }
        None => false,
    }
}

impl State {
    fn pop_frame(&mut self) -> Option<Frame> {
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        Some(self.frames[self.depth as usize])
    }

    fn push(&mut self, role: Role, gp: Gp, object: bool) -> Result<(), MapError> {
        let slot = self.frames.get_mut(self.depth as usize).ok_or(MapError::Json(JsonError::Depth))?;
        *slot = Frame { role, gp, object, first: true };
        self.depth += 1;
        Ok(())
    }

    fn on_key(&mut self, t: Text<'_>) -> Result<(), MapError> {
        let Some(top) = self.depth.checked_sub(1).map(|i| self.frames[i as usize]) else {
            return Err(MapError::Json(JsonError::Unexpected(b'"')));
        };
        self.key_raw = t.raw_len;
        self.key_dec = t.decoded_len;
        self.key_unclean = !t.is_clean();
        self.key_f = field_lookup(top.role, &t);
        let mut gp = gp_field(top.gp, &t);
        if top.gp == Gp::Regions && gp != Gp::Drop {
            // The C keeps the first MAX_DERP_REGIONS regions and, after that, only the preferred one (matched by the key's text).
            let mut digits = [0u8; 5];
            let n = u32_digits(self.cfg.home_derp as u32, &mut digits);
            let is_home = !t.is_truncated() && t.bytes == &digits[..n];
            if self.region_keys as usize >= MAX_DERP_REGIONS && !is_home {
                gp = Gp::Drop;
                self.stats.derp_regions_dropped.bump();
            }
            if gp != Gp::Drop {
                self.region_keys = self.region_keys.saturating_add(1);
            }
        }
        self.key_gp = gp;
        self.key_dup = false;
        if self.key_f != F::None {
            let bit = 1u64 << (self.key_f as u8);
            let mask = match top.role {
                Role::Root => Some(&mut self.seen_root),
                Role::SelfNode | Role::Peer(_) => Some(&mut self.pb.seen),
                Role::Region => Some(&mut self.rb.seen),
                Role::DNode => Some(&mut self.nb.seen),
                Role::Dns => Some(&mut self.dns_seen),
                Role::Resolver => Some(&mut self.res_seen),
                _ => None,
            };
            if let Some(m) = mask {
                self.key_dup = *m & bit != 0;
                *m |= bit;
            }
        } else if matches!(top.role, Role::Root | Role::SelfNode | Role::Peer(_) | Role::DerpMap | Role::Region | Role::DNode | Role::Dns | Role::Resolver) {
            self.stats.fields_skipped.bump();
        }
        if matches!(top.role, Role::Routes | Role::SeenMap(_)) {
            self.key_text_ok = t.as_str().is_some();
            let was_cut = cut(&mut self.key_text, &t);
            if !self.key_text_ok {
                self.key_text.set("");
            }
            if was_cut && matches!(top.role, Role::Routes) {
                self.stats.dns_text_cut.bump();
            }
        }
        Ok(())
    }

    /// Charge one retained token to the open record's budget.
    fn charge(&mut self, parent: usize, start: bool, val: &Val<'_>) -> Result<(), MapError> {
        let b = &mut self.budget;
        if !start {
            let f = &mut self.frames[parent];
            if !f.first {
                b.raw += 1;
            }
            f.first = false;
            if f.object {
                b.raw = b.raw.saturating_add(self.key_raw).saturating_add(1);
                b.strs = b.strs.saturating_add(self.key_dec).saturating_add(1);
                if self.key_unclean {
                    return Err(MapError::RecordDecode);
                }
            }
        }
        b.nodes += 1;
        match val {
            Val::Obj | Val::Arr => b.raw += 1,
            Val::Str(t) => {
                b.raw = b.raw.saturating_add(t.raw_len);
                b.strs = b.strs.saturating_add(t.decoded_len).saturating_add(1);
                if !t.is_clean() {
                    return Err(MapError::RecordDecode);
                }
            }
            Val::Num(n) => b.raw += n.len() as u32,
            Val::Bool(true) | Val::Null => b.raw += 4,
            Val::Bool(false) => b.raw += 5,
        }
        self.check_budget()
    }

    fn check_budget(&self) -> Result<(), MapError> {
        if self.budget.raw > RECORD_RAW_MAX {
            Err(MapError::RecordTooLarge)
        } else if self.budget.nodes > RECORD_NODES_MAX || self.budget.strs > RECORD_STRINGS_MAX {
            Err(MapError::RecordDecode)
        } else {
            Ok(())
        }
    }

    fn end_capture(&mut self) {
        self.stats.projected_bytes = self.stats.projected_bytes.saturating_add(self.budget.raw);
        self.capture = None;
    }

    fn section_enter(&mut self, g: Group) -> Result<(), MapError> {
        let c = &mut self.section[g as usize];
        *c = c.saturating_add(1);
        match self.cfg.limits.section_entries {
            Some(max) if *c > max as u32 => Err(MapError::SectionFull(g)),
            _ => Ok(()),
        }
    }

    fn stage<S: MapSink>(&mut self, sink: &mut S) -> Result<(), MapError> {
        sink.event(MapEvent::Peer(&self.peer)).map_err(|_| MapError::SinkRefused)
    }

    fn begin_peer(&mut self, g: Group) {
        let action = match g {
            Group::Removed => PeerAction::Remove,
            Group::Patch | Group::OnlineChange => PeerAction::Patch,
            _ => PeerAction::Add,
        };
        self.peer = PeerRecord::new(action, g);
        self.pb = PeerBuild { seen: 0, addr_idx: 0, has_ip: false, modern: 0, legacy: 0, expired: false, self_name: None };
    }

    fn on_value<S: MapSink>(&mut self, val: Val<'_>, sink: &mut S) -> Result<(), MapError> {
        if self.depth == 0 {
            return match val {
                Val::Obj => self.push(Role::Root, Gp::Root, true),
                _ => Err(MapError::RootNotObject),
            };
        }
        let pi = self.depth as usize - 1;
        let parent = self.frames[pi];
        let (field, gp, dup) = if parent.object { (self.key_f, self.key_gp, self.key_dup) } else { (F::Elem, parent.gp, false) };

        let starts_capture = self.capture.is_none()
            && match parent.role {
                Role::Root => field == F::RNode && matches!(val, Val::Obj),
                Role::List(_) => true,
                Role::Regions => gp != Gp::Drop,
                _ => false,
            };
        if starts_capture {
            self.budget = Budget::default();
            self.capture = Some(self.depth);
        }
        if self.capture.is_some() && gp != Gp::Drop {
            self.charge(pi, starts_capture, &val)?;
        }

        if val.is_container() {
            let object = matches!(val, Val::Obj);
            let role = self.child_role(parent.role, field, gp, dup, object)?;
            self.push(role, gp, object)
        } else {
            self.scalar(parent.role, field, gp, dup, &val, sink)?;
            if starts_capture {
                self.end_capture();
            }
            Ok(())
        }
    }

    /// The role of a container that starts under `parent`; performs the side effects of entering it.
    fn child_role(&mut self, parent: Role, field: F, gp: Gp, dup: bool, object: bool) -> Result<Role, MapError> {
        if dup && !matches!(parent, Role::Root) {
            self.stats.fields_duplicate.bump();
            return Ok(Role::Skip);
        }
        Ok(match parent {
            Role::Root => {
                if dup && field != F::None {
                    return Err(MapError::DuplicateControlField);
                }
                match (field, object) {
                    (F::RNode, true) => {
                        self.begin_peer(Group::Peers);
                        Role::SelfNode
                    }
                    (F::RNode, false) => return Err(MapError::BadSelfNode),
                    (F::RPeers, false) => {
                        self.authoritative = true;
                        Role::List(Group::Peers)
                    }
                    (F::RChanged, false) => Role::List(Group::Changed),
                    (F::RRemoved, false) => Role::List(Group::Removed),
                    (F::RPatch, false) => Role::List(Group::Patch),
                    (F::RDerpMap, true) => Role::DerpMap,
                    (F::RDerpMap, false) => return Err(MapError::BadDerpMap),
                    (F::RDns, true) => {
                        self.dns_present = true;
                        self.dns = DnsConfig::default();
                        self.dns_seen = 0;
                        Role::Dns
                    }
                    (F::RSeen, true) => Role::SeenMap(false),
                    (F::ROnline, true) => Role::SeenMap(true),
                    (F::RPacketFilter | F::RPacketFilters, _) => {
                        self.packet_filter_seen = true;
                        Role::Skip
                    }
                    _ => Role::Skip,
                }
            }
            Role::List(g) => {
                self.section_enter(g)?;
                match (g, object) {
                    (Group::Removed, _) => {
                        self.stats.removed_bad_element.bump();
                        Role::Skip
                    }
                    (Group::Patch, true) => {
                        self.begin_peer(Group::Patch);
                        Role::Peer(Group::Patch)
                    }
                    (Group::Patch, false) => {
                        self.stats.patch_not_object.bump();
                        Role::Skip
                    }
                    (_, true) => {
                        self.begin_peer(g);
                        Role::Peer(g)
                    }
                    (_, false) => {
                        self.stats.peer_not_object.bump();
                        Role::Skip
                    }
                }
            }
            Role::SelfNode | Role::Peer(_) => {
                let patch = matches!(parent, Role::Peer(Group::Patch));
                let is_self = matches!(parent, Role::SelfNode);
                match (field, object) {
                    (F::NAddresses, false) if !patch => {
                        self.pb.addr_idx = 0;
                        Role::Addresses
                    }
                    (F::NAllowed, false) if !patch && !is_self => Role::Aips,
                    (F::NEndpoints, false) if !is_self => {
                        self.peer.endpoints_present = true;
                        self.peer.endpoint_count = 0;
                        Role::Endpoints
                    }
                    (F::NTags, false) if !patch => Role::Tags,
                    _ => Role::Skip,
                }
            }
            Role::DerpMap => match (field, object) {
                (F::DRegions, true) if !self.derp_present => {
                    self.derp_present = true;
                    self.derp.count = 0;
                    self.region_keys = 0;
                    Role::Regions
                }
                (F::DRegions, _) => return Err(MapError::BadDerpMap),
                _ => Role::Skip,
            },
            Role::Regions => {
                if gp == Gp::Drop {
                    Role::Skip
                } else if object {
                    self.region = DerpRegion::empty();
                    self.rb = RegionBuild { seen: 0, rid: None };
                    Role::Region
                } else {
                    return Err(MapError::BadDerpMap);
                }
            }
            Role::Region => match (field, object) {
                (F::RgNodes, false) => Role::Nodes,
                _ => Role::Skip,
            },
            Role::Nodes => {
                if !object {
                    self.stats.derp_nodes_bad.bump();
                    Role::Skip
                } else if self.region.node_count as usize >= MAX_DERP_NODES {
                    self.stats.derp_nodes_over_cap.bump();
                    Role::Skip
                } else {
                    self.node = DerpNode::empty();
                    self.nb = NodeBuild { seen: 0, host_whole: false, cn_present: false, cn_is_str: false, cn_overlong: false, cn: FixedStr::new() };
                    Role::DNode
                }
            }
            Role::DNode => {
                if field == F::DnCertName {
                    self.nb.cn_present = true;
                    self.nb.cn_is_str = false;
                }
                Role::Skip
            }
            Role::Dns => match (field, object) {
                (F::DResolvers, false) => Role::Resolvers,
                (F::DNameservers, false) => Role::Nameservers,
                (F::DRoutes, true) => Role::Routes,
                (F::DDomains, false) => Role::DnsStrs(false),
                (F::DCertDomains, false) => Role::DnsStrs(true),
                _ => Role::Skip,
            },
            Role::Resolvers => {
                if object && (self.dns.resolver_count as usize) < MAX_DNS_RESOLVERS {
                    self.res = DnsResolver::default();
                    self.res_seen = 0;
                    self.res_in_route = false;
                    Role::Resolver
                } else {
                    self.stats.dns_over_cap.bump();
                    Role::Skip
                }
            }
            Role::Routes => {
                if !object && (self.dns.route_count as usize) < MAX_DNS_ROUTES {
                    self.start_route();
                    Role::Route
                } else {
                    if !object {
                        self.stats.dns_over_cap.bump();
                    }
                    Role::Skip
                }
            }
            Role::Route => {
                let n = (self.dns.route_count as usize).saturating_sub(1);
                if object && (self.dns.routes[n].resolver_count as usize) < MAX_ROUTE_RESOLVERS {
                    self.res = DnsResolver::default();
                    self.res_seen = 0;
                    self.res_in_route = true;
                    Role::Resolver
                } else {
                    self.stats.dns_over_cap.bump();
                    Role::Skip
                }
            }
            Role::Addresses | Role::Endpoints | Role::Aips | Role::Tags => {
                match parent {
                    Role::Endpoints => self.stats.endpoints_bad.bump(),
                    Role::Aips => self.stats.routes_bad.bump(),
                    _ => {}
                }
                Role::Skip
            }
            Role::Nameservers | Role::Resolver | Role::DnsStrs(_) | Role::SeenMap(_) | Role::Skip => {
                let _ = gp;
                Role::Skip
            }
        })
    }

    fn start_route(&mut self) {
        let n = self.dns.route_count as usize;
        self.dns.routes[n] = DnsRoute::default();
        let suffix = self.key_text.clone();
        self.dns.routes[n].suffix = suffix;
        self.dns.route_count += 1;
    }

    fn scalar<S: MapSink>(&mut self, parent: Role, field: F, gp: Gp, dup: bool, val: &Val<'_>, sink: &mut S) -> Result<(), MapError> {
        if dup && !matches!(parent, Role::Root) {
            self.stats.fields_duplicate.bump();
            return Ok(());
        }
        match parent {
            Role::Root => {
                if dup && field != F::None {
                    return Err(MapError::DuplicateControlField);
                }
                match (field, val) {
                    (F::RNode, Val::Null) | (F::RDerpMap, Val::Null) => {}
                    (F::RNode, _) => return Err(MapError::BadSelfNode),
                    (F::RDerpMap, _) => return Err(MapError::BadDerpMap),
                    (F::RKeepAlive, Val::Bool(b)) => self.keep_alive = *b,
                    (F::RCollect, Val::Bool(b)) => self.collect_services = Some(*b),
                    (F::RControlTime, Val::Str(t)) => match t.as_str().and_then(|s| util::rfc3339(s.as_bytes())) {
                        Some(v) => self.control_time = Some(v),
                        None => self.stats.times_bad.bump(),
                    },
                    (F::RDomain, Val::Str(t)) => {
                        let mut d = FixedStr::new();
                        if cut(&mut d, t) {
                            self.stats.dns_text_cut.bump();
                        }
                        self.domain = Some(d);
                    }
                    (F::RPacketFilter | F::RPacketFilters, _) => self.packet_filter_seen = true,
                    _ => {}
                }
            }
            Role::List(g) => {
                self.section_enter(g)?;
                match (g, val) {
                    (Group::Removed, Val::Num(n)) => {
                        self.begin_peer(Group::Removed);
                        self.peer.node_id = node_id_of(n);
                        self.stats.removals_staged.bump();
                        self.stage(sink)?;
                    }
                    (Group::Removed, Val::Str(t)) => match t.as_str().and_then(|s| util::key_hex(s, "nodekey:")) {
                        Some(k) => {
                            self.begin_peer(Group::Removed);
                            self.peer.node_key = k;
                            self.stats.removals_staged.bump();
                            self.stage(sink)?;
                        }
                        None => self.stats.removed_bad_element.bump(),
                    },
                    (Group::Removed, _) => self.stats.removed_bad_element.bump(),
                    (Group::Patch, _) => self.stats.patch_not_object.bump(),
                    _ => self.stats.peer_not_object.bump(),
                }
            }
            Role::SelfNode | Role::Peer(_) => self.node_scalar(parent, field, val),
            Role::Addresses => {
                let idx = self.pb.addr_idx;
                self.pb.addr_idx = idx.saturating_add(1);
                if idx > 0 {
                    self.stats.addresses_ignored.bump();
                } else if let Val::Str(t) = val {
                    match t.as_str().and_then(|s| util::address_v4(s.as_bytes())) {
                        Some(ip) => {
                            self.peer.vpn_ip = ip;
                            self.pb.has_ip = true;
                        }
                        None => self.stats.addresses_bad.bump(),
                    }
                }
            }
            Role::Endpoints => {
                if self.peer.endpoint_count as usize >= MAX_ENDPOINTS {
                    self.stats.endpoints_over_cap.bump();
                } else if let Val::Str(t) = val {
                    match t.as_str().and_then(|s| util::endpoint_v4(s.as_bytes())) {
                        Some((ip, port)) => {
                            self.peer.endpoints[self.peer.endpoint_count as usize] = Endpoint { ip, port };
                            self.peer.endpoint_count += 1;
                        }
                        None => self.stats.endpoints_bad.bump(),
                    }
                } else {
                    self.stats.endpoints_bad.bump();
                }
            }
            Role::Aips => {
                if let Val::Str(t) = val {
                    let s = t.as_str().unwrap_or("");
                    if s == "0.0.0.0/0" {
                        self.peer.is_exit_node = true;
                    } else if let Some((net, len)) = util::cidr_v4(s.as_bytes()) {
                        if net & 0xffc0_0000 == 0x6440_0000 {
                            self.stats.routes_cgnat_skipped.bump();
                        } else if (self.peer.route_count as usize) < MAX_PEER_ROUTES {
                            self.peer.routes[self.peer.route_count as usize] = Route { network: net, prefix_len: len };
                            self.peer.route_count += 1;
                        } else {
                            self.stats.routes_over_cap.bump();
                        }
                    } else {
                        self.stats.routes_bad.bump();
                    }
                }
            }
            Role::Tags => {
                if matches!(val, Val::Str(_)) {
                    self.peer.tag_count = self.peer.tag_count.saturating_add(1);
                }
            }
            Role::DerpMap => {
                if field == F::DRegions {
                    return Err(MapError::BadDerpMap);
                }
            }
            Role::Regions => {
                if gp != Gp::Drop {
                    return Err(MapError::BadDerpMap);
                }
            }
            Role::Region => self.region_scalar(field, val),
            Role::Nodes => self.stats.derp_nodes_bad.bump(),
            Role::DNode => self.dnode_scalar(field, val),
            Role::Dns => {
                if let (F::DProxied, Val::Bool(b)) = (field, val) {
                    self.dns.proxied = *b;
                }
            }
            Role::Nameservers => {
                if let Val::Str(t) = val {
                    if (self.dns.resolver_count as usize) < MAX_DNS_RESOLVERS {
                        let n = self.dns.resolver_count as usize;
                        if cut(&mut self.dns.resolvers[n].addr, t) {
                            self.stats.dns_text_cut.bump();
                        }
                        self.dns.resolver_count += 1;
                    } else {
                        self.stats.dns_over_cap.bump();
                    }
                }
            }
            Role::Resolvers | Role::Route => {
                if let (Role::Resolvers, Val::Str(t)) = (parent, val) {
                    // `Resolvers` as plain address strings (not what Go sends, but harmless).
                    if (self.dns.resolver_count as usize) < MAX_DNS_RESOLVERS {
                        let n = self.dns.resolver_count as usize;
                        if cut(&mut self.dns.resolvers[n].addr, t) {
                            self.stats.dns_text_cut.bump();
                        }
                        self.dns.resolver_count += 1;
                    } else {
                        self.stats.dns_over_cap.bump();
                    }
                }
            }
            Role::Resolver => match (field, val) {
                (F::ResAddr, Val::Str(t)) => {
                    if cut(&mut self.res.addr, t) {
                        self.stats.dns_text_cut.bump();
                    }
                }
                (F::ResExit, Val::Bool(b)) => self.res.use_with_exit_node = *b,
                _ => {}
            },
            Role::DnsStrs(cert) => {
                if let Val::Str(t) = val {
                    let (list, count) =
                        if cert { (&mut self.dns.cert_domains, &mut self.dns.cert_domain_count) } else { (&mut self.dns.domains, &mut self.dns.domain_count) };
                    if (*count as usize) < MAX_DNS_DOMAINS {
                        if cut(&mut list[*count as usize], t) {
                            self.stats.dns_text_cut.bump();
                        }
                        *count += 1;
                    } else {
                        self.stats.dns_over_cap.bump();
                    }
                }
            }
            Role::SeenMap(online) => {
                if let Val::Bool(b) = val {
                    self.section_enter(Group::OnlineChange)?;
                    let id = if self.key_text_ok { util::decimal_u64(self.key_text.as_str().as_bytes()) } else { None };
                    match id {
                        Some(id) if online => {
                            self.begin_peer(Group::OnlineChange);
                            self.peer.node_id = Some(id);
                            self.peer.online = Some(*b);
                            self.stats.patches_staged.bump();
                            self.stage(sink)?;
                        }
                        Some(id) => {
                            self.stats.seen_staged.bump();
                            sink.event(MapEvent::PeerSeen { node_id: id, seen: *b }).map_err(|_| MapError::SinkRefused)?;
                        }
                        None => self.stats.seen_keys_bad.bump(),
                    }
                }
            }
            Role::Routes => {
                // `"suffix": null` is Go's nil slice: a route with no resolvers of its own (names under it use the system's).
                if matches!(val, Val::Null) {
                    if (self.dns.route_count as usize) < MAX_DNS_ROUTES {
                        self.start_route();
                    } else {
                        self.stats.dns_over_cap.bump();
                    }
                }
            }
            Role::Skip => {}
        }
        Ok(())
    }

    fn parse_key(&mut self, t: &Text<'_>, prefix: &str) -> Key32 {
        match t.as_str().filter(|_| !t.is_truncated()).and_then(|s| util::key_hex(s, prefix)) {
            Some(k) => k,
            None => {
                self.stats.keys_bad.bump();
                Key32::ZERO
            }
        }
    }

    fn node_scalar(&mut self, role: Role, field: F, val: &Val<'_>) {
        let patch = matches!(role, Role::Peer(Group::Patch));
        let is_self = matches!(role, Role::SelfNode);
        match (field, val) {
            (F::NId, Val::Num(n)) if !patch => self.peer.node_id = node_id_of(n),
            (F::NNodeId, Val::Num(n)) if patch => self.peer.node_id = node_id_of(n),
            (F::NName, Val::Str(t)) if !patch => {
                if is_self {
                    // A name of 128 bytes or more is ignored (the C's `strlen < sizeof(dns)`).
                    match t.as_str() {
                        Some(s) if !t.is_truncated() && s.len() < 128 => {
                            let mut n = FixedStr::new();
                            n.set(s);
                            self.pb.self_name = Some(n);
                        }
                        _ => self.stats.self_name_ignored.bump(),
                    }
                } else if let Some(s) = t.as_str() {
                    let mut end = s.len().min(HOSTNAME_MAX);
                    while !s.is_char_boundary(end) {
                        end -= 1;
                    }
                    if end < s.len() || t.is_truncated() {
                        self.stats.names_cut.bump();
                    }
                    let name = &s[..end];
                    self.peer.name.set(name.strip_suffix('.').unwrap_or(name));
                }
            }
            (F::NKey, Val::Str(t)) => self.peer.node_key = self.parse_key(t, "nodekey:"),
            (F::NDisco, Val::Str(t)) => self.peer.disco_key = self.parse_key(t, "discokey:"),
            (F::NMachine, Val::Str(t)) if !patch => self.peer.machine_key = self.parse_key(t, "mkey:"),
            (F::NHome, Val::Num(n)) if !patch => match int_of(n) {
                Some(v) if v > 0 => match u16::try_from(v) {
                    Ok(v) => self.pb.modern = v,
                    Err(_) => self.stats.numbers_bad.bump(),
                },
                _ => {}
            },
            (F::NLegacy, Val::Str(t)) if !patch && !is_self => {
                if let Some(r) = t.as_str().and_then(|s| util::legacy_derp(s.as_bytes())) {
                    self.pb.legacy = r;
                }
            }
            (F::NDerpRegion, Val::Num(n)) if patch => match int_of(n) {
                Some(v) if v > 0 => match u16::try_from(v) {
                    Ok(v) => self.peer.home_derp = v,
                    Err(_) => self.stats.numbers_bad.bump(),
                },
                _ => {}
            },
            (F::NOnline, Val::Bool(b)) => self.peer.online = Some(*b),
            (F::NExpired, Val::Bool(true)) if !patch => self.pb.expired = true,
            (F::NKeyExpiry, Val::Str(t)) => match t.as_str().and_then(|s| util::rfc3339(s.as_bytes())) {
                Some((secs, _)) => self.peer.key_expiry = secs,
                None => {
                    // Go's zero time ("0001-01-01T00:00:00Z") means "does not expire": not an error.
                    if !t.as_str().is_some_and(|s| s.starts_with("0001-")) {
                        self.stats.times_bad.bump();
                    }
                }
            },
            (F::NCap, Val::Num(n)) => match json::number_i64(n).and_then(|v| u32::try_from(v).ok()) {
                Some(v) => self.peer.cap = v,
                None => self.stats.numbers_bad.bump(),
            },
            (F::None, _) | (F::Elem, _) => {}
            (F::NAddresses | F::NAllowed | F::NEndpoints | F::NTags, _) => {}
            _ => self.stats.fields_ignored.bump(),
        }
    }

    fn region_scalar(&mut self, field: F, val: &Val<'_>) {
        match (field, val) {
            (F::RgId, Val::Num(n)) => {
                self.rb.rid = int_of(n);
                match json::number_f64(n).filter(|f| (0.0..=65535.0).contains(f)) {
                    Some(f) => self.region.region_id = f as u16,
                    None => self.stats.numbers_bad.bump(),
                }
            }
            (F::RgCode, Val::Str(t)) => {
                if cut(&mut self.region.code, t) {
                    self.stats.dns_text_cut.bump();
                }
            }
            (F::RgName, Val::Str(t)) => {
                if cut(&mut self.region.name, t) {
                    self.stats.dns_text_cut.bump();
                }
            }
            (F::RgAvoid, Val::Bool(b)) => self.region.avoid = *b,
            _ => {}
        }
    }

    fn dnode_scalar(&mut self, field: F, val: &Val<'_>) {
        match (field, val) {
            (F::DnHost, Val::Str(t)) => {
                self.nb.host_whole = !t.is_truncated() && t.decoded_len < 64;
                let _ = cut(&mut self.node.hostname, t);
            }
            (F::DnV4, Val::Str(t)) => match t.as_str().and_then(|s| s.parse::<core::net::Ipv4Addr>().ok()) {
                Some(a) => self.node.ipv4 = Some(a.octets()),
                None => self.stats.derp_ips_bad.bump(),
            },
            (F::DnV6, Val::Str(t)) => match t.as_str().and_then(|s| s.parse::<core::net::Ipv6Addr>().ok()) {
                Some(a) => self.node.ipv6 = Some(a.octets()),
                None => self.stats.derp_ips_bad.bump(),
            },
            (F::DnStun, Val::Num(n)) => match json::number_f64(n).filter(|f| (0.0..=65535.0).contains(f)) {
                Some(f) => self.node.stun_port = f as u16,
                None => self.stats.numbers_bad.bump(),
            },
            (F::DnDerp, Val::Num(n)) => match json::number_f64(n).filter(|f| (0.0..=65535.0).contains(f)) {
                Some(f) => self.node.derp_port = f as u16,
                None => self.stats.numbers_bad.bump(),
            },
            (F::DnStunOnly, Val::Bool(b)) => self.node.stun_only = *b,
            (F::DnCanPort80, Val::Bool(b)) => self.node.can_port80 = *b,
            (F::DnCertName, v) => {
                self.nb.cn_present = true;
                if let Val::Str(t) = v {
                    self.nb.cn_is_str = true;
                    self.nb.cn_overlong = t.is_truncated() || t.decoded_len > 96;
                    if !self.nb.cn_overlong {
                        self.nb.cn.set(t.as_str().unwrap_or(""));
                    }
                } else {
                    self.nb.cn_is_str = false;
                }
            }
            _ => {}
        }
    }

    fn on_end<S: MapSink>(&mut self, sink: &mut S) -> Result<(), MapError> {
        let Some(f) = self.pop_frame() else {
            return Err(MapError::Json(JsonError::Unexpected(b'}')));
        };
        if self.capture.is_some() && f.gp != Gp::Drop {
            self.budget.raw += 1;
            self.check_budget()?;
        }
        match f.role {
            Role::Peer(g) => {
                self.peer.home_derp = if g == Group::Patch {
                    self.peer.home_derp
                } else if self.pb.modern > 0 {
                    self.pb.modern
                } else {
                    self.pb.legacy
                };
                if g != Group::Patch && self.pb.expired {
                    self.peer.action = PeerAction::Remove;
                }
                match g {
                    Group::Patch => self.stats.patches_staged.bump(),
                    Group::Removed => self.stats.removals_staged.bump(),
                    _ => self.stats.peers_staged.bump(),
                }
                self.stage(sink)?;
            }
            Role::SelfNode => {
                let p = &self.peer;
                self.self_node = Some(SelfNode {
                    name: self.pb.self_name.clone(),
                    vpn_ip: self.pb.has_ip.then_some(p.vpn_ip),
                    expired: self.pb.expired,
                    node_id: p.node_id,
                    node_key: p.node_key.clone(),
                    disco_key: p.disco_key.clone(),
                    machine_key: p.machine_key.clone(),
                    home_derp: if self.pb.modern > 0 { self.pb.modern } else { p.home_derp },
                    key_expiry: p.key_expiry,
                    cap: p.cap,
                    tag_count: p.tag_count,
                });
            }
            Role::Region => {
                // `decode_derp_regions`: past MAX_DERP_REGIONS only the preferred region is kept, replacing the last one.
                let home = self.rb.rid == Some(self.cfg.home_derp as i32);
                let mut keep = true;
                if self.derp.count as usize >= MAX_DERP_REGIONS {
                    if home {
                        self.derp.count -= 1;
                        self.stats.derp_regions_replaced.bump();
                    } else {
                        self.stats.derp_regions_dropped.bump();
                        keep = false;
                    }
                }
                if keep {
                    let r = core::mem::replace(&mut self.region, DerpRegion::empty());
                    self.derp.regions[self.derp.count as usize] = r;
                    self.derp.count += 1;
                }
            }
            Role::DNode => {
                let nb = &self.nb;
                let cert = if !nb.host_whole || (nb.cn_present && !nb.cn_is_str) || nb.cn_overlong {
                    DerpCert::Invalid
                } else {
                    derp_cert::cert_parse(self.node.hostname.as_str(), nb.cn_is_str.then(|| nb.cn.as_str()))
                };
                if cert == DerpCert::Invalid {
                    self.stats.derp_certs_invalid.bump();
                }
                self.node.cert = cert;
                let n = self.region.node_count as usize;
                self.region.nodes[n] = core::mem::replace(&mut self.node, DerpNode::empty());
                self.region.node_count += 1;
            }
            Role::Resolver => {
                let r = core::mem::take(&mut self.res);
                if self.res_in_route {
                    let n = (self.dns.route_count as usize).saturating_sub(1);
                    let route = &mut self.dns.routes[n];
                    route.resolvers[route.resolver_count as usize] = r;
                    route.resolver_count += 1;
                } else {
                    self.dns.resolvers[self.dns.resolver_count as usize] = r;
                    self.dns.resolver_count += 1;
                }
            }
            _ => {}
        }
        if self.capture == Some(self.depth) {
            self.end_capture();
        }
        Ok(())
    }

    fn on_event<S: MapSink>(&mut self, ev: Event<'_>, sink: &mut S) -> Result<(), MapError> {
        match ev {
            Event::Key(t) => self.on_key(t),
            Event::StartObject => self.on_value(Val::Obj, sink),
            Event::StartArray => self.on_value(Val::Arr, sink),
            Event::EndObject | Event::EndArray => self.on_end(sink),
            Event::Str(t) => self.on_value(Val::Str(t), sink),
            Event::Number(n) => self.on_value(Val::Num(n), sink),
            Event::Bool(b) => self.on_value(Val::Bool(b), sink),
            Event::Null => self.on_value(Val::Null, sink),
        }
    }
}

fn u32_digits(mut v: u32, out: &mut [u8; 5]) -> usize {
    let mut tmp = [0u8; 5];
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 || n == 5 {
            break;
        }
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

struct Adapter<'a, S: MapSink> {
    st: &'a mut State,
    sink: &'a mut S,
}

impl<S: MapSink> TokenSink for Adapter<'_, S> {
    type Error = MapError;
    fn event(&mut self, ev: Event<'_>) -> Result<(), MapError> {
        self.st.on_event(ev, self.sink)
    }
}

/// The streaming MapResponse projector. Feed it the bytes of ONE map in chunks of any size, then [`MapProjector::finish`]; events go to the sink.
#[derive(Clone, Debug)]
pub struct MapProjector {
    tok: Tokenizer,
    st: State,
}

impl MapProjector {
    /// `size_of::<MapProjector>()` on the compiling target: all the memory a projection uses (the C's `gs_parser` is 5000 bytes plus the 23,992-byte stage).
    pub const STATE_BYTES: usize = core::mem::size_of::<MapProjector>();

    /// A projector for one map.
    pub fn new(cfg: MapConfig) -> Self {
        Self { tok: Tokenizer::new(Policy::CCompat), st: State::new(cfg) }
    }

    /// Start a new map (the statistics restart too).
    pub fn reset(&mut self, cfg: MapConfig) {
        self.tok.reset();
        self.st = State::new(cfg);
    }

    /// The statistics of the current map.
    pub fn stats(&self) -> &MapStats {
        &self.st.stats
    }

    /// The error the map failed with, if it did.
    pub fn failure(&self) -> Option<MapError> {
        self.st.failed
    }

    /// True after a successful [`MapProjector::finish`].
    pub fn is_done(&self) -> bool {
        self.st.done
    }

    fn fail<S: MapSink>(&mut self, e: MapError, sink: &mut S) -> MapError {
        self.st.failed = Some(e);
        // The sink learns once; it cannot make a rejected map worse, so its answer to Abort is ignored.
        let _ = sink.event(MapEvent::Abort(e));
        e
    }

    /// Consume the next bytes of the map. Any split of the same bytes gives the same events. After an error (an `Abort` event was sent) every call returns
    /// that error.
    pub fn feed<S: MapSink>(&mut self, chunk: &[u8], sink: &mut S) -> Result<(), MapError> {
        if let Some(e) = self.st.failed {
            return Err(e);
        }
        if self.st.done {
            return if chunk.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) { Ok(()) } else { Err(MapError::Json(JsonError::TrailingData)) };
        }
        let r = self.tok.feed(chunk, &mut Adapter { st: &mut self.st, sink: &mut *sink });
        // Bytes up to and including the one that failed, so the figure does not depend on how the input was cut into chunks.
        self.st.stats.bytes_in = u32::try_from(self.tok.consumed()).unwrap_or(u32::MAX);
        match r {
            Ok(()) => Ok(()),
            Err(ParseError::Json(e)) => Err(self.fail(MapError::Json(e), sink)),
            Err(ParseError::Sink(e)) => Err(self.fail(e, sink)),
        }
    }

    /// End of the map: validates completeness, delivers the commit-time events and [`MapEvent::Commit`].
    pub fn finish<S: MapSink>(&mut self, sink: &mut S) -> Result<(), MapError> {
        if let Some(e) = self.st.failed {
            return Err(e);
        }
        if self.st.done {
            return Ok(());
        }
        let r = self.tok.finish(&mut Adapter { st: &mut self.st, sink: &mut *sink });
        match r {
            Ok(()) => {}
            Err(ParseError::Json(JsonError::Incomplete)) => return Err(self.fail(MapError::Incomplete, sink)),
            Err(ParseError::Json(e)) => return Err(self.fail(MapError::Json(e), sink)),
            Err(ParseError::Sink(e)) => return Err(self.fail(e, sink)),
        }
        if self.st.depth != 0 {
            return Err(self.fail(MapError::Incomplete, sink));
        }
        let st = &mut self.st;
        let expired = st.self_node.as_ref().is_some_and(|n| n.expired);
        let refused = |_: SinkError| MapError::SinkRefused;
        let r: Result<(), MapError> = (|| {
            if let Some(n) = &st.self_node {
                sink.event(MapEvent::SelfNode(n)).map_err(refused)?;
            }
            if !expired {
                if st.derp_present {
                    sink.event(MapEvent::Derp(&st.derp)).map_err(refused)?;
                }
                if st.dns_present {
                    sink.event(MapEvent::Dns(&st.dns)).map_err(refused)?;
                }
            }
            if let Some(d) = &st.domain {
                sink.event(MapEvent::Domain(d.as_str())).map_err(refused)?;
            }
            if let Some((secs, nanos)) = st.control_time {
                sink.event(MapEvent::ControlTime { secs, nanos }).map_err(refused)?;
            }
            if let Some(c) = st.collect_services {
                sink.event(MapEvent::CollectServices(c)).map_err(refused)?;
            }
            if st.keep_alive {
                sink.event(MapEvent::KeepAlive).map_err(refused)?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            return Err(self.fail(e, sink));
        }
        let summary = MapSummary {
            authoritative: st.authoritative,
            self_expired: expired,
            has_self: st.self_node.is_some(),
            derp_present: st.derp_present,
            packet_filter_seen: st.packet_filter_seen,
            section_entries: st.section,
            stats: st.stats.clone(),
        };
        if sink.event(MapEvent::Commit(&summary)).is_err() {
            // No Abort after a refused commit: the sink already knows it refused.
            st.failed = Some(MapError::CommitRefused);
            return Err(MapError::CommitRefused);
        }
        st.done = true;
        Ok(())
    }

    /// Convenience: project a whole map from one slice.
    pub fn project<S: MapSink>(cfg: MapConfig, map: &[u8], sink: &mut S) -> Result<MapStats, MapError> {
        let mut p = MapProjector::new(cfg);
        p.feed(map, sink)?;
        p.finish(sink)?;
        Ok(p.st.stats.clone())
    }
}
