//! One membership's state inside the engine (the C's `microlink_t` minus the control connection, the DERP socket and the tasks).

use crate::io::{LABEL_MAX, MemberConfig, MemberId};
use crate::jit::ParkQueue;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::envelope::RxCounters;
use tdongle_tailnet_disco::netcheck::Netcheck;
use tdongle_tailnet_disco::path::{AddBurst, PathCounters, PathState, ProbeTable};
use tdongle_tailnet_disco::stun_sched::{StunConfig, StunScheduler};
use tdongle_tailnet_map::DerpCert;
use tdongle_tailnet_map::types::{DerpMap, DerpNode, DerpRegion};
use tdongle_tailnet_peers::membership::Membership;
use tdongle_tailnet_types::{FixedStr, Key32, Millis};
use tdongle_tailnet_wg::{CookieChecker, DropCounters, Identity};

/// Local UDP endpoints kept for CallMeMaybe (LAN addresses; the STUN-learned public one is separate).
pub const LOCAL_EPS: usize = 4;
/// Regions the netcheck probes (`MAX_DERP_REGIONS`).
pub const NETCHECK_REGIONS: usize = 4;

/// Where a membership is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Created, not started.
    Stopped,
    /// Running.
    Running,
}

/// Everything of a membership except the peer table (which the activation rules borrow separately).
pub struct Rt<const P: usize> {
    /// The membership id (the router's, the control plane's).
    pub id: MemberId,
    /// Pool owner and directory index: the engine slot.
    pub slot: u8,
    /// Life cycle.
    pub phase: Phase,
    /// Identity: node key pair and the derived MAC keys.
    pub identity: Identity,
    /// Our node public key.
    pub node_pub: Key32,
    /// DISCO private key.
    pub disco_priv: Key32,
    /// DISCO public key.
    pub disco_pub: Key32,
    /// Responder cookie secret.
    pub cookie: CookieChecker,
    /// DNS label.
    pub label: FixedStr<LABEL_MAX>,
    /// Persistent keepalive for every peer, seconds.
    pub persistent_keepalive_s: u16,
    /// The table index -> pool slot mirror (the activation rules only see the table index).
    pub slot_of: [Option<u8>; P],
    /// The tailnet address of the peer at each table index (0 = free): what the table forgets when it removes an entry.
    pub ip_of: [u32; P],
    /// Until when a failed initiation keeps the peer's handshake timer quiet.
    pub hs_backoff: [Millis; P],
    /// Authenticated data bytes per table index: `[sent, received]` (status only; reset when the peer leaves).
    pub wg_bytes: [[u32; 2]; P],
    /// Per-peer DISCO path state, by table index.
    pub paths: [PathState<8>; P],
    /// Outstanding pings (`pending_probes[32]` in the C; sixteen here).
    pub probes: ProbeTable<16>,
    /// DISCO path counters.
    pub pcounters: PathCounters,
    /// DISCO receive outcomes.
    pub disco_rx: RxCounters,
    /// WireGuard receive drops.
    pub wg_drops: DropCounters,
    /// Burst budget for peers added at once.
    pub burst: AddBurst,
    /// Parked packets.
    pub park: ParkQueue,
    /// The self node's tailnet address (0 until a map says).
    pub self_ip: u32,
    /// The self node's name.
    pub self_name: FixedStr<127>,
    /// MagicDNS domain from the map (`Domain` or the first search domain).
    pub domain: FixedStr<63>,
    /// DERP map.
    pub derp_map: DerpMap,
    /// Every region of the map in compact form: where a link to the region a peer is homed on is dialled.
    pub derp_index: tdongle_tailnet_map::types::DerpIndex,
    /// The DERP region we are homed on (0 = none yet).
    pub home_derp: u16,
    /// The node key expired.
    pub key_expired: bool,
    /// The DERP link is ready to relay.
    pub derp_ready: bool,
    /// Router publication state.
    pub ready: bool,
    /// The wall clock reading the map gave: (unix secs, nanos, engine time of the reading).
    pub wall: Option<(u64, u32, Millis)>,
    /// STUN schedule.
    pub stun: StunScheduler,
    /// STUN has been started (first map with a server).
    pub stun_started: bool,
    /// When the STUN schedule must next be polled.
    pub stun_next: Millis,
    /// Netcheck.
    pub netcheck: Netcheck<NETCHECK_REGIONS>,
    /// Netcheck is running or wanted.
    pub netcheck_wanted: bool,
    /// When netcheck must next be polled.
    pub netcheck_next: Millis,
    /// Local endpoints.
    pub local_eps: [Ep; LOCAL_EPS],
    /// How many.
    pub local_n: usize,
    /// STUN-learned public endpoint.
    pub public_ep: Option<Ep>,
    /// When the DISCO tick runs next.
    pub next_disco_tick: Millis,
    /// Start of the current one-second window of handshake initiations and how many it saw (the under-load rule).
    pub init_window: (Millis, u16),
    /// Bumped by every table change (the C's `peer_generation`).
    pub generation: u32,
    /// The directory generation the resident peers last followed (a directory may apply a commit later, in its background upkeep).
    pub dir_generation: u32,
}

/// A membership.
pub struct Member<const P: usize> {
    /// The peer working set, trial and counters (borrowed by the activation rules).
    pub mship: Membership<P>,
    /// Everything else.
    pub rt: Rt<P>,
}

impl<const P: usize> Member<P> {
    /// Build a membership from its configuration; `None` for an all-zero or small-order private key.
    #[inline(always)]
    pub fn new(cfg: &MemberConfig, slot: u8) -> Option<Self> {
        let identity = Identity::new(&cfg.node_private)?;
        let node_pub = identity.public().clone();
        let disco_pub = x25519::public(&cfg.disco_private);
        if cfg.disco_private.is_zero() {
            return None;
        }
        let mut mship = Membership::new();
        mship.priority_peer_ip = cfg.priority_peer_ip;
        Some(Self {
            mship,
            rt: Rt {
                id: cfg.id,
                slot,
                phase: Phase::Stopped,
                identity,
                node_pub,
                disco_priv: cfg.disco_private.clone(),
                disco_pub,
                cookie: CookieChecker::new(),
                label: cfg.label.clone(),
                persistent_keepalive_s: cfg.persistent_keepalive_s,
                slot_of: [None; P],
                ip_of: [0; P],
                hs_backoff: [0; P],
                wg_bytes: [[0; 2]; P],
                paths: core::array::from_fn(|_| PathState::new()),
                probes: ProbeTable::new(),
                pcounters: PathCounters::default(),
                disco_rx: RxCounters::new(),
                wg_drops: DropCounters::new(),
                burst: AddBurst::new(),
                park: ParkQueue::new(),
                self_ip: 0,
                self_name: FixedStr::new(),
                domain: FixedStr::new(),
                derp_map: empty_derp_map(),
                derp_index: tdongle_tailnet_map::types::DerpIndex::empty(),
                home_derp: 0,
                key_expired: false,
                derp_ready: false,
                ready: false,
                wall: None,
                stun: StunScheduler::new(StunConfig::DEFAULT),
                stun_started: false,
                stun_next: 0,
                netcheck: Netcheck::new(),
                netcheck_wanted: false,
                netcheck_next: 0,
                local_eps: [Ep::NONE; LOCAL_EPS],
                local_n: 0,
                public_ep: None,
                next_disco_tick: 0,
                init_window: (0, 0),
                generation: 0,
                dir_generation: 0,
            },
        })
    }

    /// Bytes of one membership's state in this engine (host size).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
}

fn empty_derp_map() -> DerpMap {
    let node = || DerpNode {
        hostname: FixedStr::new(),
        ipv4: None,
        ipv6: None,
        stun_port: 0,
        derp_port: 0,
        stun_only: false,
        can_port80: false,
        cert: DerpCert::Invalid,
    };
    let region = || DerpRegion { region_id: 0, code: FixedStr::new(), name: FixedStr::new(), nodes: [node(), node()], node_count: 0, avoid: false };
    DerpMap { regions: [region(), region(), region(), region()], count: 0 }
}

impl<const P: usize> core::fmt::Debug for Rt<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Rt(id={}, {:?}, ready={}, derp_ready={})", self.id, self.phase, self.ready, self.derp_ready)
    }
}

impl<const P: usize> core::fmt::Debug for Member<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Member({:?}, {} peers)", self.rt, self.mship.table.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_derp_map_is_empty() {
        assert_eq!(empty_derp_map().count, 0);
    }
}
