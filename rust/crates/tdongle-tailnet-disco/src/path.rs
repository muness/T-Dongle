//! Per-peer path selection: which of a peer's UDP endpoints (or DERP) carries its traffic, and when to probe, trust, distrust and fall back.
//!
//! This is the DISCO half of `ml_wg_mgr.c` (`disco_send_ping_to_peer`, `process_disco_ping/pong`, the CallMeMaybe handler, `disco_periodic_probes`)
//! written as a state machine that never touches a socket, a clock or an entropy source. Time is a [`Millis`] argument, entropy an `&mut dyn Entropy`,
//! and every decision comes out as an [`Action`] pushed into an [`ActionSink`]; the runtime builds the packets ([`crate::envelope::seal_ping`] and
//! friends) and sends them where the action says.
//!
//! **State.** [`PathState`] is one peer (its candidate endpoints, the best direct path with its trust deadline, and a handful of timestamps).
//! [`ProbeTable`] is the membership's outstanding pings (the C's `pending_probes[32]`), shared by its peers and bounded per peer. [`PathCounters`] is the
//! membership's account of what happened. None of it stores a packet.
//!
//! **Rules kept from the C** (constants in [`PathConfig`]): ping at most every 5 s unless forced; heartbeat a direct path every 3 s but only while a
//! WireGuard session sits behind it; trust a direct path 60 s after its last pong; a pong from another address does not move the best address while the
//! best one answered within 6.5 s; keep the endpoint when trust lapses but data still flows (WireGuard `last_rx` under 30 s) and fall back to DERP only
//! when it does not; probe for an upgrade every 15 s while on DERP, two peers per tick; one CallMeMaybe-triggered ping burst per peer per 2.5 s; never
//! answer a ping with a ping or a CallMeMaybe with a CallMeMaybe; a peer that is new gets a CallMeMaybe and, within a 5-per-second budget, a forced ping;
//! a session-less peer is handshaken over DERP at most every 30 s.
//!
//! **Changes from the C**, each counted: one transaction id *per probe* (the C sent one packet, one txid, to every endpoint, so the second pong was
//! "unmatched" and the winner was whoever answered first; Go uses one txid per probe and so does this); a probe is not sent if it cannot be registered;
//! a pong must come back from the peer that the probe was sent for and within the ping timeout; the stored WireGuard endpoint is only re-set when the
//! best address changes; answering pings is rate limited per peer; the stale best address is probed again after trust lapses (the C skipped it in
//! the endpoint loop because it still equalled `best_ip`).

use crate::addr::{DERP_MAGIC_V4, Ep};
use crate::msg::{Endpoints, TXID_LEN};
use tdongle_tailnet_types::{Counter, Entropy, Millis};

/// A transaction id.
pub type TxId = [u8; TXID_LEN];
/// A peer slot number (the C's index into `ml->peers`).
pub type PeerId = u8;

/// Timers and limits. [`PathConfig::DEFAULT`] holds the C's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathConfig {
    /// Minimum spacing of non-forced pings to one peer (`ML_DISCO_PING_INTERVAL_MS`, Go `discoPingInterval`).
    pub ping_interval_ms: u64,
    /// Heartbeat period on a direct path behind a WireGuard session (`ML_DISCO_HEARTBEAT_MS`, Go `heartbeatInterval`).
    pub heartbeat_ms: u64,
    /// How long a direct path is trusted after its last pong (`ML_DISCO_TRUST_DURATION_MS`; Go trusts 6.5 s, the C raised it to 60 s because pings
    /// starve before data does under radio contention).
    pub trust_ms: u64,
    /// How long a ping waits for its pong (`ML_DISCO_PING_TIMEOUT_MS`, Go `pingTimeoutDuration`).
    pub ping_timeout_ms: u64,
    /// Upgrade probe period for a peer that is on DERP (`ML_DISCO_UPGRADE_INTERVAL_MS`).
    pub upgrade_interval_ms: u64,
    /// Peers probed for an upgrade per tick (`DISCO_PROBES_PER_TICK`).
    pub upgrades_per_tick: u8,
    /// Minimum spacing of CallMeMaybe-triggered ping bursts per peer (`ML_DISCO_CMM_BURST_FLOOR_MS`).
    pub cmm_burst_floor_ms: u64,
    /// The best address is kept while it answered this recently (`ML_DISCO_BEST_STICKY_MS`, Go `trustUDPAddrDuration`).
    pub best_sticky_ms: u64,
    /// WireGuard receive younger than this counts as "data is flowing" and keeps a direct endpoint whose pings went quiet (30 s in the C).
    pub data_flowing_ms: u64,
    /// A peer with no session gets a DERP handshake no sooner than this after it was added, and then at this interval (30 s in the C).
    pub derp_handshake_ms: u64,
    /// A direct handshake is retried at this interval while pongs keep arriving and there is no session (`INITIAL_HANDSHAKE_RETRY_MS`).
    pub direct_handshake_retry_ms: u64,
    /// New peers that may get an immediate forced ping per [`AddBurst`] window (5 in the C).
    pub add_burst: u8,
    /// The [`AddBurst`] window (1 s in the C).
    pub add_burst_window_ms: u64,
    /// Endpoints of a CallMeMaybe probed (the C stopped at `ML_MAX_ENDPOINTS`, 8).
    pub max_cmm_probes: usize,
    /// Outstanding probes one peer may hold in the [`ProbeTable`] (one full round: every endpoint plus DERP).
    pub max_outstanding_per_peer: usize,
    /// Probe and accept IPv6 endpoints. Off: the device has one IPv4 DISCO socket (ADR 0023 socket budget) and the C ignores IPv6 endpoints for probing.
    pub allow_v6: bool,
    /// Pongs one peer may elicit in a burst ([`PathState::on_ping`]). Not in the C.
    pub pong_burst: u8,
    /// One pong token comes back per this many milliseconds. Not in the C.
    pub pong_refill_ms: u64,
    /// Let a pong from another address take over the best path inside the sticky window when Go's `betterAddr` says it is better (private over public,
    /// more than a point of latency). The C does not; off by default.
    pub latency_switch: bool,
}

impl PathConfig {
    /// The C's values.
    pub const DEFAULT: PathConfig = PathConfig {
        ping_interval_ms: 5_000,
        heartbeat_ms: 3_000,
        trust_ms: 60_000,
        ping_timeout_ms: 5_000,
        upgrade_interval_ms: 15_000,
        upgrades_per_tick: 2,
        cmm_burst_floor_ms: 2_500,
        best_sticky_ms: 6_500,
        data_flowing_ms: 30_000,
        derp_handshake_ms: 30_000,
        direct_handshake_retry_ms: 30_000,
        add_burst: 5,
        add_burst_window_ms: 1_000,
        max_cmm_probes: 8,
        max_outstanding_per_peer: 9,
        allow_v6: false,
        pong_burst: 16,
        pong_refill_ms: 100,
        latency_switch: false,
    };
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A time stamp where zero means "never" (the C's `last_*_ms == 0`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Stamp(u64);

impl Stamp {
    const NEVER: Stamp = Stamp(0);
    fn at(now: Millis) -> Stamp {
        Stamp(now.max(1))
    }
    fn is_never(self) -> bool {
        self.0 == 0
    }
    /// Milliseconds since, or `None` if never.
    fn age(self, now: Millis) -> Option<u64> {
        if self.is_never() { None } else { Some(now.saturating_sub(self.0)) }
    }
    /// Never, or at least `interval` ago.
    fn due(self, now: Millis, interval: u64) -> bool {
        self.age(now).is_none_or(|a| a >= interval)
    }
}

/// Why a ping was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PingKind {
    /// Discovery of endpoints.
    Discovery = 0,
    /// Keeping a working direct path trusted.
    Heartbeat = 1,
    /// An endpoint a peer's CallMeMaybe named.
    CallMeMaybe = 2,
    /// Probing for a better path while on DERP.
    Upgrade = 3,
}

impl PingKind {
    fn from_u8(v: u8) -> PingKind {
        match v {
            1 => PingKind::Heartbeat,
            2 => PingKind::CallMeMaybe,
            3 => PingKind::Upgrade,
            _ => PingKind::Discovery,
        }
    }
}

/// Where to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// UDP to this endpoint, from the DISCO socket.
    Direct(Ep),
    /// Through the peer's DERP home.
    Derp,
}

/// Where a ping or pong arrived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxFrom {
    /// The DISCO UDP socket, from this source address.
    Direct(Ep),
    /// A DERP relay, region number.
    Derp(u16),
}

/// What the runtime must do. The sink may be bounded; what does not fit is counted in [`PathCounters::actions_dropped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send a DISCO ping with this transaction id (already registered in the probe table).
    SendPing {
        /// Where.
        via: Via,
        /// The id to put in it.
        txid: TxId,
        /// Why.
        kind: PingKind,
    },
    /// Answer a ping with a pong: the pong carries `src` and `txid`.
    SendPong {
        /// Where: back to where the ping came from.
        via: Via,
        /// The ping's id.
        txid: TxId,
        /// The ping's source address (the DERP magic address and region for a DERP ping).
        src: Ep,
        /// A direct pong whose send fails is sent over DERP instead.
        derp_if_direct_fails: bool,
    },
    /// Send a CallMeMaybe over DERP carrying our endpoints ([`local_endpoints`]).
    SendCallMeMaybe,
    /// The best direct address changed: re-point the WireGuard endpoint (no handshake is forced; WireGuard roams by design).
    WgSetEndpoint(Ep),
    /// A direct path was found and there is no WireGuard session: send a handshake initiation to the endpoint.
    WgDirectHandshake {
        /// Not the first one for this peer.
        retry: bool,
    },
    /// No session after a while: send a handshake initiation through DERP.
    WgDerpHandshake {
        /// Not the first one for this peer.
        retry: bool,
    },
    /// The direct path is dead (no pongs, no data) behind a live session: zero the WireGuard endpoint so traffic goes through DERP.
    RevertToDerp,
}

/// Where actions go.
pub trait ActionSink {
    /// Take an action; false if the sink is full (the action is lost and counted).
    fn push(&mut self, a: Action) -> bool;
}

impl<F: FnMut(Action)> ActionSink for F {
    fn push(&mut self, a: Action) -> bool {
        self(a);
        true
    }
}

/// A fixed-capacity [`ActionSink`].
#[derive(Debug, Clone)]
pub struct ActionBuf<const N: usize> {
    items: [Option<Action>; N],
    len: usize,
}

impl<const N: usize> Default for ActionBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ActionBuf<N> {
    /// Empty.
    pub const fn new() -> Self {
        ActionBuf { items: [None; N], len: 0 }
    }
    /// The collected actions in order.
    pub fn iter(&self) -> impl Iterator<Item = Action> + '_ {
        self.items[..self.len].iter().flatten().copied()
    }
    /// Number collected.
    pub fn len(&self) -> usize {
        self.len
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Forget everything.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> ActionSink for ActionBuf<N> {
    fn push(&mut self, a: Action) -> bool {
        if self.len == N {
            return false;
        }
        self.items[self.len] = Some(a);
        self.len += 1;
        true
    }
}

/// Every outcome of the path machinery, per membership.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathCounters {
    /// Pings handed out for direct UDP.
    pub ping_direct: Counter,
    /// Pings handed out for DERP.
    pub ping_derp: Counter,
    /// A non-forced ping skipped by the 5 s limit.
    pub ping_rate_limited: Counter,
    /// A probe not sent: the probe table was full (the C sent it anyway and could not match the pong).
    pub probe_table_full: Counter,
    /// A probe not sent: this peer already holds its share of the table.
    pub probe_peer_cap: Counter,
    /// An IPv6 endpoint not probed.
    pub endpoint_v6_skipped: Counter,
    /// Candidate endpoints dropped (unusable, duplicate, or over capacity).
    pub endpoint_dropped: Counter,
    /// Pings received.
    pub ping_rx: Counter,
    /// A ping not answered: the peer is over its pong budget.
    pub pong_rate_limited: Counter,
    /// A direct ping with an unusable source address, not answered.
    pub ping_bad_src: Counter,
    /// Pongs handed out.
    pub pong_tx: Counter,
    /// Pongs that matched a probe.
    pub pong_matched: Counter,
    /// Pongs whose id matches no outstanding probe (late duplicates of an already answered probe, forgeries, expired).
    pub pong_unmatched: Counter,
    /// Pongs whose id belongs to a probe sent for a different peer.
    pub pong_wrong_peer: Counter,
    /// Pongs that arrived after the ping timeout.
    pub pong_late: Counter,
    /// Pongs that came over DERP (liveness only; they never make a direct path).
    pub pong_via_derp: Counter,
    /// Direct pongs from an address that cannot be a path.
    pub pong_bad_src: Counter,
    /// The best direct address changed.
    pub best_changed: Counter,
    /// A pong from another address did not move the best (it answered within the sticky window).
    pub best_kept: Counter,
    /// Trust lapsed but data flows: endpoint kept, one re-probe.
    pub trust_lapsed_data_flowing: Counter,
    /// Trust lapsed, no data, session up: reverted to DERP.
    pub trust_lapsed_reverted: Counter,
    /// Trust lapsed on a peer with no session: re-probe only.
    pub trust_lapsed_no_session: Counter,
    /// CallMeMaybes received.
    pub cmm_rx: Counter,
    /// CallMeMaybe bursts suppressed by the 2.5 s floor.
    pub cmm_suppressed: Counter,
    /// CallMeMaybe endpoints not probed (IPv6, unusable, beyond the cap).
    pub cmm_endpoint_skipped: Counter,
    /// Upgrade rounds started.
    pub upgrade_probes: Counter,
    /// An upgrade due but the tick's budget was spent.
    pub upgrade_deferred: Counter,
    /// Heartbeats sent.
    pub heartbeats: Counter,
    /// DERP handshakes requested.
    pub derp_handshakes: Counter,
    /// Direct handshakes requested.
    pub direct_handshakes: Counter,
    /// Probes expired without a pong.
    pub probe_expired: Counter,
    /// Actions that did not fit the sink.
    pub actions_dropped: Counter,
}

/// An outstanding probe: 18 bytes. The destination is deliberately not stored: a pong is attributed to the address it arrived from, as the C does.
#[derive(Clone, Copy)]
struct Slot {
    txid: TxId,
    sent: u32,
    peer: u8,
    kind: u8,
}

const FREE: u8 = 0xff;

/// What happened to a pong's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    /// No such outstanding probe.
    NotFound,
    /// The probe belongs to another peer; it stays outstanding.
    WrongPeer,
    /// The probe is older than the timeout; it was freed.
    Late,
    /// Matched and freed.
    Hit {
        /// Why the probe was sent.
        kind: PingKind,
        /// Round trip in milliseconds.
        rtt_ms: u32,
    },
}

/// Outstanding pings of a membership (the C's `pending_probes`): `N` slots of 20 bytes, 16 by default (the C had 32).
#[derive(Clone)]
pub struct ProbeTable<const N: usize = 16> {
    slots: [Slot; N],
}

impl<const N: usize> Default for ProbeTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::fmt::Debug for ProbeTable<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProbeTable<{N}>(in use {})", self.len())
    }
}

impl<const N: usize> ProbeTable<N> {
    /// Bytes of state.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Empty.
    pub const fn new() -> Self {
        ProbeTable { slots: [Slot { txid: [0; TXID_LEN], sent: 0, peer: FREE, kind: 0 }; N] }
    }
    /// Outstanding probes.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.peer != FREE).count()
    }
    /// True when none are outstanding.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Outstanding probes of one peer.
    pub fn outstanding(&self, peer: PeerId) -> usize {
        self.slots.iter().filter(|s| s.peer == peer).count()
    }
    /// Record a probe. `false`: no free slot (or `peer` is the reserved 0xff).
    pub fn register(&mut self, txid: TxId, peer: PeerId, kind: PingKind, now: Millis) -> bool {
        if peer == FREE {
            return false;
        }
        match self.slots.iter_mut().find(|s| s.peer == FREE) {
            Some(s) => {
                *s = Slot { txid, sent: now as u32, peer, kind: kind as u8 };
                true
            }
            None => false,
        }
    }
    /// Match a pong's id for `peer` and free the slot (see [`Take`]).
    pub fn take(&mut self, txid: &TxId, peer: PeerId, now: Millis, timeout_ms: u64) -> Take {
        let Some(s) = self.slots.iter_mut().find(|s| s.peer != FREE && s.txid == *txid) else {
            return Take::NotFound;
        };
        if s.peer != peer {
            return Take::WrongPeer;
        }
        let age = u64::from((now as u32).wrapping_sub(s.sent));
        let kind = PingKind::from_u8(s.kind);
        s.peer = FREE;
        if age > timeout_ms { Take::Late } else { Take::Hit { kind, rtt_ms: age as u32 } }
    }
    /// Free probes older than `timeout_ms`; returns how many.
    pub fn expire(&mut self, now: Millis, timeout_ms: u64) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut().filter(|s| s.peer != FREE) {
            if u64::from((now as u32).wrapping_sub(s.sent)) > timeout_ms {
                s.peer = FREE;
                n += 1;
            }
        }
        n
    }
    /// Forget everything a peer has outstanding (the peer was removed or its slot reused).
    pub fn forget_peer(&mut self, peer: PeerId) {
        for s in self.slots.iter_mut().filter(|s| s.peer == peer) {
            s.peer = FREE;
        }
    }
}

/// How many new peers may be pinged at once: the C's `burst_count < 5` per second, shared by the membership.
#[derive(Debug, Clone, Copy, Default)]
pub struct AddBurst {
    window: u64,
    count: u8,
}

impl AddBurst {
    /// Fresh.
    pub const fn new() -> Self {
        AddBurst { window: 0, count: 0 }
    }
    /// May another peer be pinged now?
    pub fn allow(&mut self, now: Millis, cfg: &PathConfig) -> bool {
        if self.window == 0 || now.saturating_sub(self.window) > cfg.add_burst_window_ms {
            self.count = 0;
            self.window = now.max(1);
        }
        if self.count < cfg.add_burst {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

/// Upgrade probes still allowed in this tick (`DISCO_PROBES_PER_TICK`). Make one per pass over the peers.
#[derive(Debug, Clone, Copy)]
pub struct TickBudget {
    upgrades_left: u8,
}

impl TickBudget {
    /// A fresh budget for one tick.
    pub const fn new(cfg: &PathConfig) -> Self {
        TickBudget { upgrades_left: cfg.upgrades_per_tick }
    }
}

/// What the runtime knows that the path machine cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickInput {
    /// The netmap does not say the peer is offline (offline peers are not probed for upgrades).
    pub online: bool,
    /// The peer allowlist lets us talk to it (pings from it are still answered; nothing is sent to it otherwise).
    pub allowed: bool,
    /// Direct UDP is possible at all (false on the cellular AT-socket path, and while there is no DISCO socket).
    pub udp_ok: bool,
    /// A WireGuard session is up for the peer.
    pub session_up: bool,
    /// The peer has a WireGuard slot at all (the DERP handshake needs one).
    pub wg_present: bool,
    /// Age of the last authenticated WireGuard receive from the peer; `None` if never.
    pub data_age_ms: Option<u64>,
}

/// Shared mutable context of every call.
pub struct Env<'a, const N: usize> {
    /// Timers.
    pub cfg: &'a PathConfig,
    /// Outstanding probes.
    pub probes: &'a mut ProbeTable<N>,
    /// Randomness for transaction ids.
    pub rng: &'a mut dyn Entropy,
    /// Counters.
    pub counters: &'a mut PathCounters,
}

impl<const N: usize> core::fmt::Debug for Env<'_, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Env")
    }
}

/// The result of a pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PongOutcome {
    /// No such probe (counted).
    Unmatched,
    /// Probe of another peer (counted).
    WrongPeer,
    /// After the timeout (counted).
    Late,
    /// Over DERP: the peer is alive, nothing about the path changes.
    ViaDerp {
        /// Round trip.
        rtt_ms: u32,
    },
    /// Direct from an address that cannot be a path (port 0, unspecified, multicast).
    BadSource,
    /// Direct: the best address is now this one.
    NewBest {
        /// The address.
        ep: Ep,
        /// Round trip.
        rtt_ms: u32,
    },
    /// Direct from the best address: trust renewed.
    Refreshed {
        /// Round trip.
        rtt_ms: u32,
    },
    /// Direct from another address while the best one is still answering: best kept.
    KeptBest {
        /// Round trip.
        rtt_ms: u32,
    },
}

/// The result of a ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingOutcome {
    /// A pong was queued.
    Answered,
    /// Over the peer's pong budget: nothing was sent.
    RateLimited,
    /// Direct ping whose source cannot be answered.
    BadSource,
}

/// The result of a CallMeMaybe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmmOutcome {
    /// The probes ran (false: inside the 2.5 s floor).
    pub burst: bool,
    /// Pings queued for the endpoints it named.
    pub probes: u8,
}

/// Best address by Go's `betterAddr` (endpoint.go): points are the percentage by which the other is slower, plus 50/30/20 for loopback/link-local/private
/// and 10 for IPv6; the candidate needs more points than the incumbent, and a gain of more than one point unless the incumbent has some.
pub fn better_addr(a: Ep, a_ms: u32, b: Ep, b_ms: u32) -> bool {
    if a == b {
        return false;
    }
    if b == Ep::NONE {
        return true;
    }
    if a == Ep::NONE {
        return false;
    }
    let (mut ap, mut bp) = (0u32, 0u32);
    if a_ms > b_ms
        && let Some(q) = b_ms.saturating_mul(100).checked_div(a_ms)
    {
        bp = 100 - q.min(100);
    } else if let Some(q) = a_ms.saturating_mul(100).checked_div(b_ms) {
        ap = 100 - q.min(100);
    }
    ap += a.preference_points();
    bp += b.preference_points();
    if ap <= 1 && bp == 0 {
        return false;
    }
    ap > bp
}

/// Our own endpoints for a CallMeMaybe, as the C builds them: the LAN address first (when the DISCO socket's port is known), then the STUN-mapped public
/// IPv4 address (its port, or the local port if STUN did not report one). Returns how many were written.
pub fn local_endpoints(lan_ip: Option<[u8; 4]>, local_port: u16, stun_public: Option<Ep>, out: &mut [Ep; 2]) -> usize {
    let mut n = 0;
    if let Some(ip) = lan_ip.filter(|ip| *ip != [0; 4] && local_port != 0) {
        out[n] = Ep::v4(ip, local_port);
        n += 1;
    }
    if let Some(o) = stun_public.and_then(|p| p.v4_octets().filter(|o| *o != [0; 4]).map(|o| (o, p.port()))) {
        let port = if o.1 != 0 { o.1 } else { local_port };
        if port != 0 {
            out[n] = Ep::v4(o.0, port);
            n += 1;
        }
    }
    n
}

/// A snapshot for status output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStatus {
    /// A trusted direct path exists.
    pub has_direct: bool,
    /// A DERP handshake has been fired for this peer (the C's `derp_fallback_active`).
    pub derp_fallback_active: bool,
    /// The best direct address (stale if `has_direct` is false).
    pub best: Ep,
    /// Round trip of the best address; `None` if unknown.
    pub best_rtt_ms: Option<u16>,
    /// Milliseconds of trust left.
    pub trust_left_ms: u64,
    /// Candidate endpoints held.
    pub endpoints: u8,
}

/// Where traffic to a peer should go according to DISCO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// This trusted direct address.
    Direct(Ep),
    /// DERP.
    Derp,
}

const NO_RTT: u16 = u16::MAX;

/// `trust_until` value that marks a kept endpoint (see [`PathState::keeps_endpoint`]).
const KEEP_ENDPOINT: u64 = u64::MAX;

/// One peer's path state. `E` is the number of candidate endpoints kept (the C keeps 8).
#[derive(Clone)]
pub struct PathState<const E: usize = 8> {
    endpoints: [Ep; E],
    best: Ep,
    best_last_pong: Stamp,
    trust_until: u64,
    last_ping: Stamp,
    last_pong: Stamp,
    last_cmm_rx: Stamp,
    last_upgrade: Stamp,
    last_derp_attempt: Stamp,
    last_direct_handshake: Stamp,
    peer_added: Stamp,
    pong_refill: Stamp,
    best_rtt: u16,
    n_eps: u8,
    pong_tokens: u8,
    has_direct: bool,
    derp_fallback_active: bool,
}

impl<const E: usize> core::fmt::Debug for PathState<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PathState").field("has_direct", &self.has_direct).field("best", &self.best).field("endpoints", &self.n_eps).finish()
    }
}

impl<const E: usize> Default for PathState<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const E: usize> PathState<E> {
    /// Bytes of state.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// A peer that has just been added: no endpoints, no path. Call [`PathState::on_added`] too.
    pub const fn new() -> Self {
        PathState {
            endpoints: [Ep::NONE; E],
            best: Ep::NONE,
            best_last_pong: Stamp::NEVER,
            trust_until: 0,
            last_ping: Stamp::NEVER,
            last_pong: Stamp::NEVER,
            last_cmm_rx: Stamp::NEVER,
            last_upgrade: Stamp::NEVER,
            last_derp_attempt: Stamp::NEVER,
            last_direct_handshake: Stamp::NEVER,
            peer_added: Stamp::NEVER,
            pong_refill: Stamp::NEVER,
            best_rtt: NO_RTT,
            n_eps: 0,
            pong_tokens: 0,
            has_direct: false,
            derp_fallback_active: false,
        }
    }

    /// The candidate endpoints.
    pub fn endpoints(&self) -> &[Ep] {
        &self.endpoints[..usize::from(self.n_eps)]
    }

    /// Replace the candidate endpoints with those a netmap names: unusable and duplicate entries and IPv6 ones (unless allowed) are dropped, and
    /// so is everything beyond `E`; each drop is counted. Returns how many are held.
    pub fn set_endpoints(&mut self, eps: &[Ep], cfg: &PathConfig, c: &mut PathCounters) -> usize {
        let mut n = 0usize;
        for &ep in eps {
            let ok = ep.is_usable() && (ep.is_v4() || cfg.allow_v6) && !self.endpoints[..n].contains(&ep) && n < E;
            if ok {
                self.endpoints[n] = ep;
                n += 1;
            } else {
                c.endpoint_dropped.bump();
            }
        }
        self.n_eps = n as u8;
        n
    }

    /// The C keeps the direct endpoint after the trust lapses while encrypted data still arrives on it (`ml_wg_mgr.c`: "PING-stale but data flowing - keeping endpoint"), so a
    /// starved ping does not push a working flow onto the relay. Marked by `trust_until == KEEP_ENDPOINT` (no field: the state size is budgeted); a pong, `reset_path` and the
    /// data stopping (here, not in the C) end it.
    fn keeps_endpoint(&self) -> bool {
        !self.has_direct && self.trust_until == KEEP_ENDPOINT && self.best != Ep::NONE
    }

    /// A WireGuard packet of the peer came in through the relay: an endpoint kept past the trust lapse (while data still arrived on it) is given up, because the data now
    /// comes another way and answering on a path that may be dead would lose it. A trusted path is left alone (the peer may use both).
    pub fn on_derp_data(&mut self) {
        if self.keeps_endpoint() {
            self.trust_until = 0;
        }
    }

    /// DISCO's choice for this peer now.
    pub fn route(&self, now: Millis) -> Route {
        if (self.has_direct && now <= self.trust_until) || self.keeps_endpoint() { Route::Direct(self.best) } else { Route::Derp }
    }

    /// Snapshot for status.
    pub fn status(&self, now: Millis) -> PathStatus {
        PathStatus {
            has_direct: self.has_direct,
            derp_fallback_active: self.derp_fallback_active,
            best: self.best,
            best_rtt_ms: (self.best_rtt != NO_RTT).then_some(self.best_rtt),
            trust_left_ms: self.trust_until.saturating_sub(now),
            endpoints: self.n_eps,
        }
    }

    /// Age of the last pong of any kind; `None` if none yet.
    pub fn last_pong_age(&self, now: Millis) -> Option<u64> {
        self.last_pong.age(now)
    }

    /// Forget the learned path (the peer's disco key or endpoints changed): back to DERP, rediscover. Candidate endpoints are kept.
    pub fn reset_path(&mut self) {
        self.has_direct = false;
        self.best = Ep::NONE;
        self.best_rtt = NO_RTT;
        self.best_last_pong = Stamp::NEVER;
        self.trust_until = 0;
        self.last_ping = Stamp::NEVER;
        self.last_upgrade = Stamp::NEVER;
    }

    fn push(c: &mut PathCounters, out: &mut dyn ActionSink, a: Action) {
        if !out.push(a) {
            c.actions_dropped.bump();
        }
    }

    /// Register and queue one ping. False if it could not be sent.
    fn emit_ping<const N: usize>(&mut self, id: PeerId, via: Via, kind: PingKind, now: Millis, env: &mut Env<'_, N>, out: &mut dyn ActionSink) -> bool {
        if env.probes.outstanding(id) >= env.cfg.max_outstanding_per_peer {
            env.counters.probe_peer_cap.bump();
            return false;
        }
        let mut txid = [0u8; TXID_LEN];
        env.rng.fill(&mut txid);
        if !env.probes.register(txid, id, kind, now) {
            env.counters.probe_table_full.bump();
            return false;
        }
        match via {
            Via::Direct(_) => env.counters.ping_direct.bump(),
            Via::Derp => env.counters.ping_derp.bump(),
        }
        Self::push(env.counters, out, Action::SendPing { via, txid, kind });
        true
    }

    /// `disco_send_ping_to_peer`: probe the best direct address, every known endpoint, and DERP unless a direct path already carries the heartbeat.
    /// Not forced: at most one round per `ping_interval_ms`. Returns whether a round was made.
    #[allow(clippy::too_many_arguments)]
    pub fn send_pings<const N: usize>(
        &mut self,
        id: PeerId,
        now: Millis,
        force: bool,
        udp_ok: bool,
        kind: PingKind,
        env: &mut Env<'_, N>,
        out: &mut dyn ActionSink,
    ) -> bool {
        if !force && !self.last_ping.due(now, env.cfg.ping_interval_ms) {
            env.counters.ping_rate_limited.bump();
            return false;
        }
        let had_direct = self.has_direct;
        let mut direct_sent = false;
        if udp_ok {
            // The working path first: a heartbeat answered over DERP would not renew trust.
            if had_direct && self.best.is_usable() {
                direct_sent |= self.emit_ping(id, Via::Direct(self.best), kind, now, env, out);
            }
            for i in 0..usize::from(self.n_eps) {
                let ep = self.endpoints[i];
                if !ep.is_v4() && !env.cfg.allow_v6 {
                    env.counters.endpoint_v6_skipped.bump();
                    continue;
                }
                if had_direct && ep == self.best {
                    continue;
                }
                direct_sent |= self.emit_ping(id, Via::Direct(ep), kind, now, env, out);
            }
        }
        if !had_direct || !direct_sent {
            self.emit_ping(id, Via::Derp, kind, now, env, out);
        }
        self.last_ping = Stamp::at(now);
        true
    }

    /// A peer was added to the table: remember when, send a CallMeMaybe (so the peer opens its firewall towards us) and, within the membership's
    /// [`AddBurst`] budget, probe at once. Nothing on a path without UDP.
    pub fn on_added<const N: usize>(&mut self, id: PeerId, now: Millis, udp_ok: bool, burst: &mut AddBurst, env: &mut Env<'_, N>, out: &mut dyn ActionSink) {
        self.peer_added = Stamp::at(now);
        if !udp_ok {
            return;
        }
        Self::push(env.counters, out, Action::SendCallMeMaybe);
        if burst.allow(now, env.cfg) {
            self.send_pings(id, now, true, udp_ok, PingKind::Discovery, env, out);
        }
    }

    /// A ping arrived: answer it with one pong to where it came from. Never pings back (two nodes would chase each other).
    pub fn on_ping<const N: usize>(&mut self, now: Millis, from: RxFrom, txid: TxId, env: &mut Env<'_, N>, out: &mut dyn ActionSink) -> PingOutcome {
        env.counters.ping_rx.bump();
        let (via, src, derp_if_direct_fails) = match from {
            RxFrom::Direct(ep) if ep.is_usable() => (Via::Direct(ep), ep, true),
            RxFrom::Direct(_) => {
                env.counters.ping_bad_src.bump();
                return PingOutcome::BadSource;
            }
            RxFrom::Derp(region) => (Via::Derp, Ep::v4(DERP_MAGIC_V4, region), false),
        };
        let cfg = env.cfg;
        let step = cfg.pong_refill_ms.max(1);
        match self.pong_refill.age(now) {
            None => {
                self.pong_tokens = cfg.pong_burst;
                self.pong_refill = Stamp::at(now);
            }
            Some(age) if age >= step => {
                let gained = age / step;
                self.pong_tokens = u64::from(self.pong_tokens).saturating_add(gained).min(u64::from(cfg.pong_burst)) as u8;
                self.pong_refill = Stamp::at(self.pong_refill.0.saturating_add(gained.saturating_mul(step)).min(now));
            }
            Some(_) => {}
        }
        if self.pong_tokens == 0 {
            env.counters.pong_rate_limited.bump();
            return PingOutcome::RateLimited;
        }
        self.pong_tokens -= 1;
        env.counters.pong_tx.bump();
        Self::push(env.counters, out, Action::SendPong { via, txid, src, derp_if_direct_fails });
        PingOutcome::Answered
    }

    /// A pong arrived from this peer. Matches its id against the outstanding probes and, if it came directly, may make its source the best path.
    #[allow(clippy::too_many_arguments)]
    pub fn on_pong<const N: usize>(
        &mut self,
        id: PeerId,
        now: Millis,
        from: RxFrom,
        txid: &TxId,
        session_up: bool,
        env: &mut Env<'_, N>,
        out: &mut dyn ActionSink,
    ) -> PongOutcome {
        let rtt_ms = match env.probes.take(txid, id, now, env.cfg.ping_timeout_ms) {
            Take::NotFound => {
                env.counters.pong_unmatched.bump();
                return PongOutcome::Unmatched;
            }
            Take::WrongPeer => {
                env.counters.pong_wrong_peer.bump();
                return PongOutcome::WrongPeer;
            }
            Take::Late => {
                env.counters.pong_late.bump();
                return PongOutcome::Late;
            }
            Take::Hit { rtt_ms, .. } => rtt_ms,
        };
        env.counters.pong_matched.bump();
        self.last_pong = Stamp::at(now);
        let ep = match from {
            RxFrom::Derp(_) => {
                env.counters.pong_via_derp.bump();
                return PongOutcome::ViaDerp { rtt_ms };
            }
            RxFrom::Direct(ep) if ep.is_usable() && (ep.is_v4() || env.cfg.allow_v6) => ep,
            RxFrom::Direct(_) => {
                env.counters.pong_bad_src.bump();
                return PongOutcome::BadSource;
            }
        };
        let cfg = env.cfg;
        // A peer can answer from two addresses (its LAN address and its NAT mapping are both in the netmap). Following every pong made the best
        // address flap, and every flap cost a handshake: stay on the best while it still answers.
        let sticky = self.has_direct && self.best != ep && self.best_last_pong.age(now).is_some_and(|a| a < cfg.best_sticky_ms);
        if sticky {
            let better = cfg.latency_switch && better_addr(ep, rtt_ms, self.best, u32::from(self.best_rtt));
            if !better {
                env.counters.best_kept.bump();
                return PongOutcome::KeptBest { rtt_ms };
            }
        }
        let changed = !self.has_direct || self.best != ep;
        self.best = ep;
        self.best_rtt = rtt_ms.min(u32::from(NO_RTT - 1)) as u16;
        self.best_last_pong = Stamp::at(now);
        self.has_direct = true;
        self.trust_until = now.saturating_add(cfg.trust_ms);
        self.derp_fallback_active = false;
        if changed {
            env.counters.best_changed.bump();
            Self::push(env.counters, out, Action::WgSetEndpoint(ep));
        }
        if !session_up {
            // A direct path and no session: fire one handshake at it, and again every 30 s while pongs keep coming and nothing answers.
            let first = self.last_direct_handshake.is_never();
            if first || self.last_direct_handshake.due(now, cfg.direct_handshake_retry_ms) {
                self.last_direct_handshake = Stamp::at(now);
                env.counters.direct_handshakes.bump();
                Self::push(env.counters, out, Action::WgDirectHandshake { retry: !first });
            }
        }
        if changed { PongOutcome::NewBest { ep, rtt_ms } } else { PongOutcome::Refreshed { rtt_ms } }
    }

    /// A CallMeMaybe arrived over DERP: the peer says it has just sent to us and its firewall should be open. Probe each IPv4 endpoint it names and
    /// then the endpoints we already know, once per `cmm_burst_floor_ms`. Never answers with a CallMeMaybe of our own (esphome-tailscale#46).
    pub fn on_call_me_maybe<const N: usize>(
        &mut self,
        id: PeerId,
        now: Millis,
        eps: Endpoints<'_>,
        udp_ok: bool,
        env: &mut Env<'_, N>,
        out: &mut dyn ActionSink,
    ) -> CmmOutcome {
        env.counters.cmm_rx.bump();
        let burst = self.last_cmm_rx.due(now, env.cfg.cmm_burst_floor_ms);
        if !burst {
            env.counters.cmm_suppressed.bump();
            return CmmOutcome { burst: false, probes: 0 };
        }
        self.last_cmm_rx = Stamp::at(now);
        let mut probes = 0u8;
        if udp_ok {
            for (i, ep) in eps.iter().enumerate() {
                if i >= env.cfg.max_cmm_probes || !ep.is_usable() || !(ep.is_v4() || env.cfg.allow_v6) {
                    env.counters.cmm_endpoint_skipped.bump();
                    continue;
                }
                if self.emit_ping(id, Via::Direct(ep), PingKind::CallMeMaybe, now, env, out) {
                    probes += 1;
                }
            }
        }
        self.send_pings(id, now, true, udp_ok, PingKind::Discovery, env, out);
        CmmOutcome { burst: true, probes }
    }

    /// The periodic pass for one peer (the C's per-peer body of `disco_periodic_probes`, every second): trust expiry, DERP handshake retry, upgrade
    /// probe, heartbeat. `budget` is shared by the peers of one tick.
    pub fn tick<const N: usize>(
        &mut self,
        id: PeerId,
        now: Millis,
        input: &TickInput,
        budget: &mut TickBudget,
        env: &mut Env<'_, N>,
        out: &mut dyn ActionSink,
    ) {
        let cfg = env.cfg;
        if self.has_direct && now > self.trust_until {
            // Pings went quiet. They starve before data does under radio contention, so look at the data before giving up the endpoint.
            self.has_direct = false;
            if input.allowed {
                let flowing = input.data_age_ms.is_some_and(|a| a < cfg.data_flowing_ms);
                if flowing {
                    self.trust_until = KEEP_ENDPOINT;
                    env.counters.trust_lapsed_data_flowing.bump();
                } else if input.session_up {
                    env.counters.trust_lapsed_reverted.bump();
                    Self::push(env.counters, out, Action::RevertToDerp);
                } else {
                    env.counters.trust_lapsed_no_session.bump();
                }
                if input.udp_ok {
                    self.send_pings(id, now, true, true, PingKind::Discovery, env, out);
                }
            }
        }
        if self.keeps_endpoint() && !input.data_age_ms.is_some_and(|a| a < cfg.data_flowing_ms) {
            // the endpoint was kept because data still arrived on it; the data has stopped too, so the path is dead (the C leaves this to its 30 s handshake retry)
            self.trust_until = 0;
            env.counters.trust_lapsed_reverted.bump();
        }
        if !input.allowed {
            return;
        }
        // A session-less peer never initiates against us through DERP: do it for it, at most every 30 s. Gate on the data plane, not on whether pongs
        // arrive (exit-node-after-roam wedge, 2026-05-30).
        if input.wg_present && input.online && self.peer_added.age(now).is_some_and(|a| a > cfg.derp_handshake_ms) && !input.session_up {
            let attempt_due = self.last_derp_attempt.is_never() || self.last_derp_attempt.age(now).is_some_and(|a| a > cfg.derp_handshake_ms);
            if attempt_due {
                let retry = self.derp_fallback_active;
                self.derp_fallback_active = true;
                self.last_derp_attempt = Stamp::at(now);
                env.counters.derp_handshakes.bump();
                Self::push(env.counters, out, Action::WgDerpHandshake { retry });
            }
        }
        // Look for a direct path from DERP, every 15 s, two peers a tick; never towards a peer the netmap says is offline.
        if input.udp_ok && !self.has_direct && input.online && self.last_upgrade.due(now, cfg.upgrade_interval_ms) {
            if budget.upgrades_left > 0 {
                budget.upgrades_left -= 1;
                env.counters.upgrade_probes.bump();
                self.send_pings(id, now, false, true, PingKind::Upgrade, env, out);
                self.last_upgrade = Stamp::at(now);
            } else {
                env.counters.upgrade_deferred.bump();
            }
        }
        // Heartbeat only behind a session: a peer that never handshook gets its address refreshed by the trust-expiry re-probe once a minute.
        if self.has_direct && input.session_up && self.last_ping.age(now).is_some_and(|a| a > cfg.heartbeat_ms) {
            env.counters.heartbeats.bump();
            self.send_pings(id, now, true, input.udp_ok, PingKind::Heartbeat, env, out);
        }
    }
}

/// End of a tick: free expired probes (the C's last loop of `disco_periodic_probes`). Call it with a fresh `now`, after the peers.
pub fn expire_probes<const N: usize>(probes: &mut ProbeTable<N>, now: Millis, cfg: &PathConfig, c: &mut PathCounters) -> usize {
    let n = probes.expire(now, cfg.ping_timeout_ms);
    for _ in 0..n {
        c.probe_expired.bump();
    }
    n
}

/// Index of the first peer of the next tick's rotation (`ml->disco_probe_start_idx`): the passes advance by `per_tick` so every peer gets a turn at the
/// limited upgrade budget.
pub const fn next_rotation(start: usize, per_tick: usize, peer_count: usize) -> usize {
    (start + per_tick) % if peer_count > 0 { peer_count } else { 1 }
}
