//! One membership's working set of peers (`ml_peer_t peers[ML_MAX_PEERS]`, ADR 0012: eight).
//!
//! Map discovery does not populate it: the directory (flash) holds every peer of the tailnet; a peer becomes resident when traffic activates it and
//! stays while it is used. The table keeps the C's fields, grouped so that what a later change may move to flash is visible: [`PeerMeta`] is
//! everything the directory record can restore (names, endpoints, routes, flags); the rest is live state.
//!
//! Lookups are bounded scans over at most `N` (eight) entries: by node key, tailnet IP, disco key, node id and WireGuard slot. A hash index would
//! cost more than the eight comparisons it saves.

use crate::Millis;
use crate::policy::VictimCandidate;
use crate::record::{DirRecord, Endpoint, HOSTNAME_BYTES, MICROLINK_MAX_PEER_ROUTES, ML_MAX_ENDPOINTS, PubKey, Route};
use tdongle_tailnet_types::FixedStr;
use zeroize::Zeroize;

/// `ML_MAX_PEERS` (`sdkconfig.defaults`).
pub const ML_MAX_PEERS: usize = 8;

/// What the directory record can restore: cold metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerMeta {
    /// Hostname.
    pub hostname: FixedStr<HOSTNAME_BYTES>,
    /// Known endpoints.
    pub endpoints: [Endpoint; ML_MAX_ENDPOINTS],
    /// Number of valid endpoints.
    pub endpoint_count: u8,
    /// Home DERP region.
    pub derp_region: u16,
    /// Advertised subnet routes.
    pub subnet_routes: [Route; MICROLINK_MAX_PEER_ROUTES],
    /// Number of valid routes.
    pub subnet_route_count: u8,
    /// Carries 0.0.0.0/0.
    pub is_exit_node: bool,
    /// Control-plane liveness (`Node.Online`); true on insertion.
    pub online: bool,
}

/// DISCO rate-limit state and the derived shared secret (`ml_peer_t`'s DISCO block).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct DiscoState {
    /// Last ping we sent.
    pub last_ping_sent_ms: Millis,
    /// Last pong we received.
    pub last_pong_recv_ms: Millis,
    /// Direct path trusted until.
    pub trust_until_ms: Millis,
    /// Last data sent to this peer.
    pub last_send_ms: Millis,
    /// Last path upgrade attempt.
    pub last_upgrade_ms: Millis,
    /// Last CallMeMaybe-triggered ping burst.
    pub last_cmm_rx_ms: Millis,
    /// Last direct pong from `best_ip:best_port` itself.
    pub best_last_pong_ms: Millis,
    /// `NaCl box beforenm(our disco private, peer disco)`, derived once.
    pub shared: [u8; 32],
    /// The disco key `shared` was derived from (a rotation re-derives).
    pub shared_for: PubKey,
    /// `shared` is valid.
    pub shared_valid: bool,
}

impl core::fmt::Debug for DiscoState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The derived shared secret never appears in logs.
        f.debug_struct("DiscoState").field("shared_valid", &self.shared_valid).field("last_pong_recv_ms", &self.last_pong_recv_ms).finish_non_exhaustive()
    }
}

/// One resident peer (`ml_peer_t`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Peer {
    /// Slot in use.
    pub active: bool,
    /// Activated on an unauthenticated claim and not yet confirmed (holds the membership's single trial slot).
    pub unconfirmed: bool,
    /// Last time the peer carried (or was activated for) traffic.
    pub jit_used_ms: Millis,
    /// Tailnet IPv4 address.
    pub vpn_ip: u32,
    /// WireGuard public key.
    pub public_key: PubKey,
    /// DISCO public key.
    pub disco_key: PubKey,
    /// Tailscale NodeID, 0 = not seen yet.
    pub node_id: u64,
    /// The peer's slot index in the WireGuard pool (the device-local peer index), `None` = holds no slot.
    pub wg_slot: Option<u8>,
    /// Best direct path.
    pub best_ip: u32,
    /// Best direct path port.
    pub best_port: u16,
    /// A direct path is known.
    pub has_direct_path: bool,
    /// Last on-demand handshake attempt (retried after `INITIAL_HANDSHAKE_RETRY_MS`).
    pub last_init_handshake_ms: Millis,
    /// When the peer entered our state.
    pub peer_added_ms: Millis,
    /// Endpoint forced to DERP.
    pub derp_fallback_active: bool,
    /// Last DERP fallback retry.
    pub last_derp_attempt_ms: Millis,
    /// DISCO state.
    pub disco: DiscoState,
    /// Cold metadata.
    pub meta: PeerMeta,
}

impl Peer {
    /// `size_of::<Peer>()`.
    pub const STATE_BYTES: usize = core::mem::size_of::<Peer>();

    /// A resident peer made from a directory record (`add_peer`): activated, online until the next map says otherwise, no slot yet.
    #[must_use]
    pub fn from_record(r: &DirRecord, now: Millis) -> Peer {
        let mut meta = PeerMeta {
            derp_region: r.derp_region,
            subnet_routes: r.subnet_routes,
            subnet_route_count: r.subnet_route_count.min(MICROLINK_MAX_PEER_ROUTES as u8),
            is_exit_node: r.is_exit_node,
            online: if r.has_online { r.online } else { true },
            ..PeerMeta::default()
        };
        meta.hostname.set(r.hostname.as_str());
        meta.endpoint_count = r.endpoint_count.clamp(0, ML_MAX_ENDPOINTS as i32) as u8;
        meta.endpoints = r.endpoints;
        Peer {
            active: true,
            vpn_ip: r.vpn_ip,
            public_key: r.public_key,
            disco_key: r.disco_key,
            node_id: if r.has_node_id { r.node_id } else { 0 },
            peer_added_ms: now,
            meta,
            ..Peer::default()
        }
    }
}

/// One membership's peers.
#[derive(Debug, Clone)]
pub struct PeerTable<const N: usize = ML_MAX_PEERS> {
    peers: [Peer; N],
}

impl<const N: usize> Default for PeerTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerTable<N> {
    /// Bytes of one table.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// Empty.
    #[must_use]
    pub fn new() -> Self {
        Self { peers: core::array::from_fn(|_| Peer::default()) }
    }

    /// The peer at table index `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&Peer> {
        self.peers.get(i).filter(|p| p.active)
    }
    /// Mutable access to an active peer.
    pub fn get_mut(&mut self, i: usize) -> Option<&mut Peer> {
        self.peers.get_mut(i).filter(|p| p.active)
    }
    /// Active peers.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &Peer)> {
        self.peers.iter().enumerate().filter(|(_, p)| p.active)
    }
    /// Number of active peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.iter().filter(|p| p.active).count()
    }
    /// No peer is active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Every entry is in use.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.peers.iter().all(|p| p.active)
    }
    /// Peers that hold a WireGuard slot (what the pool arbitration counts).
    #[must_use]
    pub fn residents(&self) -> usize {
        self.peers.iter().filter(|p| p.active && p.wg_slot.is_some()).count()
    }

    /// `find_peer_by_key`.
    #[must_use]
    pub fn by_key(&self, key: &PubKey) -> Option<usize> {
        self.peers.iter().position(|p| p.active && p.public_key == *key)
    }
    /// Lookup by tailnet IPv4 address (`find_peer_by_ip`).
    #[must_use]
    pub fn by_ip(&self, ip: u32) -> Option<usize> {
        self.peers.iter().position(|p| p.active && p.vpn_ip == ip)
    }
    /// `find_peer_by_disco_key`.
    #[must_use]
    pub fn by_disco_key(&self, key: &PubKey) -> Option<usize> {
        self.peers.iter().position(|p| p.active && p.disco_key == *key)
    }
    /// Lookup by Tailscale NodeID (non-zero ids only).
    #[must_use]
    pub fn by_node_id(&self, id: u64) -> Option<usize> {
        if id == 0 {
            return None;
        }
        self.peers.iter().position(|p| p.active && p.node_id == id)
    }
    /// Lookup by the WireGuard device-local peer index (the pool's per-owner index): the step after
    /// `Pool::lookup_by_receiver` turns a receiver index into a slot index.
    #[must_use]
    pub fn by_wg_slot(&self, slot: u8) -> Option<usize> {
        self.peers.iter().position(|p| p.active && p.wg_slot == Some(slot))
    }

    /// Insert at the first free entry (`add_peer`). `None` when the table is full.
    pub fn insert(&mut self, r: &DirRecord, now: Millis) -> Option<usize> {
        let i = self.peers.iter().position(|p| !p.active)?;
        self.peers[i] = Peer::from_record(r, now);
        Some(i)
    }

    /// Remove the peer at `i` (`remove_peer`): the entry is cleared. Returns the removed peer's WireGuard slot, for the caller to release.
    pub fn remove(&mut self, i: usize) -> Option<Option<u8>> {
        let p = self.peers.get_mut(i).filter(|p| p.active)?;
        let slot = p.wg_slot;
        p.disco.shared.zeroize();
        *p = Peer::default();
        Some(slot)
    }

    /// The victim inside this membership's own table when it is full (`directory_activate_idle`): the least recently used peer idle for at
    /// least `idle_ms` that is not the priority peer (`priority_ip`, 0 = none). Ties resolve to the first entry.
    #[must_use]
    pub fn pick_own_victim(&self, now: Millis, idle_ms: Millis, priority_ip: u32) -> Option<usize> {
        let mut victim = None;
        let mut oldest = u64::MAX;
        for (i, p) in self.peers.iter().enumerate() {
            let used = p.jit_used_ms;
            if p.active && now.saturating_sub(used) >= idle_ms && used < oldest && p.vpn_ip != priority_ip {
                oldest = used;
                victim = Some(i);
            }
        }
        victim
    }

    /// Candidates for the pool-wide eviction (`scan_member_peers`): the peers that hold a WireGuard slot (evicting any other frees nothing).
    /// `f(table index, candidate)` is called for each.
    pub fn candidates(&self, priority_ip: u32, mut f: impl FnMut(usize, VictimCandidate)) {
        let residents = self.residents() as u32;
        for (i, p) in self.peers.iter().enumerate() {
            if !p.active || p.wg_slot.is_none() {
                continue;
            }
            f(
                i,
                VictimCandidate {
                    last_used_ms: p.jit_used_ms,
                    owner_slots: residents,
                    pinned: priority_ip != 0 && p.vpn_ip == priority_ip,
                    trial: p.unconfirmed,
                },
            );
        }
    }
}
