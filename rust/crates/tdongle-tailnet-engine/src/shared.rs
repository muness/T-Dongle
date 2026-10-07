//! The parts of the engine that every membership shares (the C's globals: the WireGuard pool, the router, the DNS responder, the heap budget, the
//! scratch buffers of the I/O tasks), and the helpers that need nothing but those.

use crate::alias::AliasBook;
use crate::dir::PeerDirectory;
use crate::io::{Out, Output};
use crate::jit::JitStore;
use crate::member::{Member, Rt};
use crate::slot::WgSlot;
use crate::stats::{ParkEnd, Stats};
use tdongle_tailnet_admission::heap::{HbRefused, HbSite, hb_ok};
use tdongle_tailnet_admission::probe::HeapSnapshot;
use tdongle_tailnet_admission::wg_rx::Budget as RxBudget;
use tdongle_tailnet_disco::path::{PathConfig, PathState, Route};
use tdongle_tailnet_dns::Responder;
use tdongle_tailnet_peers::arbiter::{Arbiter, Resident};
use tdongle_tailnet_peers::membership::{Host, Room};
use tdongle_tailnet_peers::policy::VictimCandidate;
use tdongle_tailnet_peers::pool::{OwnerId, Pool};
use tdongle_tailnet_peers::record::{DirRecord, PubKey};
use tdongle_tailnet_router::Router;
use tdongle_tailnet_types::{Entropy, Millis};
use tdongle_tailnet_wg::WallClock;

/// Bytes of the transmit scratch: `[16 B header][1400 B plaintext padded to 16][16 B tag]` with room to spare.
pub const TX_BUF: usize = 1536;
/// Bytes of the control scratch (handshake messages, DISCO, STUN, cookie replies).
pub const CTL_BUF: usize = 512;
/// Bytes of the DNS answer buffer.
pub const DNS_BUF: usize = 1500;
/// Handshake initiations per second beyond which the responder answers only to a valid cookie (the engine's "under load" rule, see the crate docs).
pub const UNDER_LOAD_INITIATIONS: u16 = 8;

/// The per-call context: time, entropy, outputs.
pub struct Cx<'a> {
    /// Monotonic now.
    pub now: Millis,
    /// Entropy.
    pub rng: &'a mut dyn Entropy,
    /// Where outputs go.
    pub out: &'a mut dyn Output,
}

impl core::fmt::Debug for Cx<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cx(now={})", self.now)
    }
}

/// How a datagram left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// Over UDP.
    Direct,
    /// Through the relay.
    Derp,
    /// Nowhere to send it.
    NoRoute,
    /// The heap floor refused the relay copy.
    HeapRefused,
    /// The output refused.
    Refused,
}

/// Send `data` along `route` (free function: the caller passes disjoint fields, so `data` may borrow a scratch buffer of the same struct).
#[allow(clippy::too_many_arguments)]
pub fn emit_route(
    st: &mut Stats,
    hb: &HbRefused,
    heap: &HeapSnapshot,
    cx: &mut Cx<'_>,
    member: u32,
    derp_ready: bool,
    route: Route,
    dst_key: &[u8; 32],
    data: &[u8],
) -> Sent {
    match route {
        Route::Direct(ep) => {
            if cx.out.emit(Out::SendUdp { member, dst: ep, data }) {
                st.udp_tx.bump();
                Sent::Direct
            } else {
                st.out_refused.bump();
                Sent::Refused
            }
        }
        Route::Derp => {
            if !derp_ready {
                return Sent::NoRoute;
            }
            if !hb_ok(heap.free, data.len()) {
                hb.refuse(HbSite::DerpTx);
                return Sent::HeapRefused;
            }
            if cx.out.emit(Out::DerpSend { member, dst: dst_key, data }) {
                st.derp_tx.bump();
                Sent::Derp
            } else {
                st.out_refused.bump();
                Sent::Refused
            }
        }
    }
}

/// Everything shared. Fields are `pub(crate)`: the engine's files are one module in spirit.
pub struct Shared<D, const M: usize, const K: usize, const A: usize, const F: usize, const JB: usize> {
    pub(crate) pool: Pool<WgSlot, K>,
    pub(crate) arbiter: Arbiter,
    pub(crate) router: Router<M, A, F>,
    pub(crate) responder: Responder,
    pub(crate) dir: D,
    pub(crate) store: JitStore<JB>,
    pub(crate) book: AliasBook,
    pub(crate) stats: Stats,
    pub(crate) hb: HbRefused,
    pub(crate) rx_budget: RxBudget,
    pub(crate) heap: HeapSnapshot,
    pub(crate) path_cfg: PathConfig,
    pub(crate) tx: [u8; TX_BUF],
    pub(crate) ctl: [u8; CTL_BUF],
    pub(crate) dns: [u8; DNS_BUF],
    pub(crate) dns_upstream: Option<u32>,
    pub(crate) dns_deadline: Option<Millis>,
    pub(crate) clock_valid: bool,
    pub(crate) pending_evict: Option<(u8, u8)>,
    pub(crate) last_wake: Option<Millis>,
}

impl<D, const M: usize, const K: usize, const A: usize, const F: usize, const JB: usize> core::fmt::Debug for Shared<D, M, K, A, F, JB> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Shared")
    }
}

impl<D, const K: usize, const P: usize, const JB: usize> core::fmt::Debug for ActHost<'_, D, K, P, JB> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ActHost")
    }
}

impl<D: PeerDirectory, const M: usize, const K: usize, const A: usize, const F: usize, const JB: usize> Shared<D, M, K, A, F, JB> {
    pub(crate) const fn new(dir: D) -> Self {
        Self {
            pool: Pool::new(),
            arbiter: Arbiter::new(),
            router: Router::new(),
            responder: Responder::new(),
            dir,
            store: JitStore::new(),
            book: AliasBook::new(),
            stats: Stats::new(),
            hb: HbRefused::new(),
            rx_budget: RxBudget::new(),
            heap: HeapSnapshot { free: usize::MAX / 2, largest: usize::MAX / 2, minimum: usize::MAX / 2 },
            path_cfg: PathConfig::DEFAULT,
            tx: [0; TX_BUF],
            ctl: [0; CTL_BUF],
            dns: [0; DNS_BUF],
            dns_upstream: None,
            dns_deadline: None,
            clock_valid: false,
            pending_evict: None,
            last_wake: None,
        }
    }
}

/// The wall clock the engine stamps handshake initiations with: the control plane's last reading advanced by the time since, or (before any map) the
/// uptime, which never goes backwards and is replaced by a larger value as soon as a map arrives.
pub fn wall_clock<const P: usize>(rt: &Rt<P>, now: Millis) -> WallClock {
    match rt.wall {
        Some((secs, nanos, at)) => {
            let el = now.saturating_sub(at);
            let total_ns = u64::from(nanos) + (el % 1000) * 1_000_000;
            WallClock { unix_secs: secs + el / 1000 + total_ns / 1_000_000_000, nanos: (total_ns % 1_000_000_000) as u32 }
        }
        None => WallClock { unix_secs: now / 1000, nanos: ((now % 1000) * 1_000_000) as u32 },
    }
}

/// May `src` be the source address of a packet from this peer (WireGuard's AllowedIPs: its address, its subnet routes, everything for an exit node)?
pub fn src_allowed(p: &tdongle_tailnet_peers::table::Peer, src: u32) -> bool {
    if src == p.vpn_ip || p.meta.is_exit_node {
        return true;
    }
    p.meta.subnet_routes[..usize::from(p.meta.subnet_route_count).min(p.meta.subnet_routes.len())].iter().any(|r| {
        let mask = if r.prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(r.prefix_len.min(32))) };
        src & mask == r.network & mask
    })
}

/// The activation rules' view of the rest of the gateway (`struct Host` of the peers crate): what the C reaches into `microlink_t` and the pool for.
pub struct ActHost<'a, D, const K: usize, const P: usize, const JB: usize> {
    pub(crate) dir: &'a mut D,
    pub(crate) dslot: usize,
    pub(crate) pool: &'a mut Pool<WgSlot, K>,
    pub(crate) arbiter: &'a mut Arbiter,
    pub(crate) others: &'a [Resident],
    pub(crate) requester: u8,
    pub(crate) now: Millis,
    pub(crate) rt: &'a mut Rt<P>,
    pub(crate) store: &'a mut JitStore<JB>,
    pub(crate) stats: &'a mut Stats,
    pub(crate) pending: &'a mut Option<(u8, u8)>,
    pub(crate) plausible: bool,
}

impl<D: PeerDirectory, const K: usize, const P: usize, const JB: usize> Host for ActHost<'_, D, K, P, JB> {
    fn directory_by_key(&mut self, key: &PubKey) -> Option<DirRecord> {
        self.dir.find_by_key(self.dslot, key)
    }
    fn directory_by_disco(&mut self, key: &PubKey) -> Option<DirRecord> {
        self.dir.find_by_disco(self.dslot, key)
    }
    fn pool_reserve(&mut self, idle_ms: Millis, own: &[(u8, VictimCandidate)]) -> Room {
        const MAX: usize = tdongle_tailnet_peers::policy::ML_POLICY_MAX_CANDIDATES;
        let mut all = [Resident { member: 0, peer: 0, cand: VictimCandidate::default() }; MAX];
        let mut n = 0;
        for r in self.others.iter().take(MAX) {
            all[n] = *r;
            n += 1;
        }
        for &(peer, cand) in own {
            if n < MAX {
                all[n] = Resident { member: self.requester, peer, cand };
                n += 1;
            }
        }
        Arbiter::with_owner_slots(&mut all[..n]);
        let used = self.pool.used();
        match self.arbiter.reserve(used, K, self.requester, self.now, idle_ms, &all[..n]) {
            tdongle_tailnet_peers::arbiter::Reservation::Free => Room::Free,
            tdongle_tailnet_peers::arbiter::Reservation::Evict { member, peer } if member == self.requester => {
                self.stats.evict_own.bump();
                Room::EvictOwn { peer }
            }
            tdongle_tailnet_peers::arbiter::Reservation::Evict { member, peer } => {
                // The victim belongs to another membership: the engine removes it right after this call returns (it holds the other table), before
                // the new peer's slot is taken.
                self.stats.evict_other.bump();
                *self.pending = Some((member, peer));
                Room::Free
            }
            tdongle_tailnet_peers::arbiter::Reservation::Refused => Room::Refused,
        }
    }
    fn peer_removed(&mut self, table_index: usize, wg_slot: Option<u8>) {
        release_peer_state(self.rt, self.pool, self.store, self.stats, table_index, wg_slot);
    }
    fn wg_authenticated(&mut self, table_index: usize) -> bool {
        let owner = OwnerId(self.rt.slot);
        self.rt.slot_of.get(table_index).copied().flatten().and_then(|s| self.pool.get(owner, s)).is_some_and(|sl| sl.hot.last_handshake().is_some())
    }
    fn initiation_plausible(&mut self) -> bool {
        self.plausible
    }
    fn disco_authenticates(&mut self, _sender_disco_key: &PubKey, _nonce: &[u8; 24], _ciphertext_len: usize) -> bool {
        // DISCO is authenticated by the engine's own receive path (open the box first, activate second); this hook is never the way in.
        false
    }
}

/// What leaving the table costs a peer: its pool slot (wiped), its path and probes, its parked packets.
pub fn release_peer_state<const P: usize, const K: usize, const JB: usize>(
    rt: &mut Rt<P>,
    pool: &mut Pool<WgSlot, K>,
    store: &mut JitStore<JB>,
    stats: &mut Stats,
    idx: usize,
    wg_slot: Option<u8>,
) {
    let owner = OwnerId(rt.slot);
    if let Some(s) = wg_slot.or(rt.slot_of.get(idx).copied().flatten()) {
        pool.release(owner, s);
    }
    if idx < P {
        rt.slot_of[idx] = None;
        rt.paths[idx] = PathState::new();
        rt.probes.forget_peer(idx as u8);
        rt.hs_backoff[idx] = 0;
        let ip = core::mem::take(&mut rt.ip_of[idx]);
        if ip != 0 {
            for _ in 0..rt.park.drop_peer(store, ip) {
                stats.park(ParkEnd::PeerGone);
            }
        }
    }
    rt.generation = rt.generation.wrapping_add(1);
}

/// Resident peers (those holding a pool slot) of every membership except `except`, for the pool arbiter.
pub fn residents_of_others<const P: usize, const M: usize>(members: &[Option<Member<P>>; M], except: usize, out: &mut [Resident]) -> usize {
    let mut n = 0;
    for (slot, m) in members.iter().enumerate() {
        let Some(m) = m else { continue };
        if slot == except {
            continue;
        }
        m.mship.table.candidates(m.mship.priority_peer_ip, |i, c| {
            if n < out.len() {
                out[n] = Resident { member: slot as u8, peer: i as u8, cand: c };
                n += 1;
            }
        });
    }
    n
}
