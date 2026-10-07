//! [`Shared`]: everything static the runtime owns, in one value the firmware puts in a `static` (through `StaticCell::init_with` or the like) and passes to
//! [`crate::run`] as `&'static Shared`.
//!
//! * the **engine**, one value behind a blocking mutex. Every producer (the UDP, DERP, USB and control tasks, the timer) calls [`Shared::feed`], which
//!   locks it, hands it the heap reading and the clock, runs `Engine::handle` and unlocks. The engine's [`Output`] is [`OutSink`]: it only copies into the
//!   bounded [`ByteQueue`]s and cells below and never waits, never calls back into the engine, never touches a socket (see `queue.rs`);
//! * the **slots**, one per membership the engine can run ([`MAX_RUN`]): run state, identity, queues, the control workspace, status;
//! * the gateway-wide queues (host, DNS upstream), the one wake-up of the engine, the negotiation token, the shared TLS record lease, the registry.
//!
//! # Locking
//!
//! One rule: **a lock is never held across an `.await` and never taken while the engine lock is held, except by [`OutSink`] on the cells and queues it
//! writes** (leaf locks that never call anything). So the order is `engine -> leaf`, and nothing else nests.

use crate::queue::ByteQueue;
use crate::token::Token;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use tdongle_tailnet_control::requests::AUTH_URL_BYTES;
use tdongle_tailnet_ctl::{Bulk, BulkLease, SessionBuf, SessionStats};
use tdongle_tailnet_pool::{Charge, Class, Mem, Pool};
use tdongle_tailnet_derp::link::{State as LinkState, Stats as LinkStats};
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{GatewayEngine, Handled, Input, NetmapEvent, Out, Output, PeerDirectory};
use tdongle_tailnet_fw::{Platform, Storage};
use tdongle_tailnet_map::DerpCert as MapCert;
use tdongle_tailnet_map::types::DerpMap;
use tdongle_tailnet_members::{CText, MemberRegistry};
use tdongle_tailnet_tls::DerpCert;
use tdongle_tailnet_tls::lease::LeasePool;
use tdongle_tailnet_types::{Entropy, FixedStr, Key32, Millis};
use zeroize::Zeroize;

/// Memberships that can run at once (the engine's `M`). The registry may hold more saved ones ([`tdongle_tailnet_members::MAX_MEMBERS`]); a saved membership
/// without a free slot waits in the supervisor's list with the error "Cannot allocate another membership".
pub const MAX_RUN: usize = tdongle_tailnet_engine::GATEWAY_M;
/// Capacity of a slot's UDP egress queue (DISCO, STUN, WireGuard datagrams: records of up to 1,536 + 21 bytes; one full packet always fits an empty queue; two and a half of them in a burst: `out_refused` on the board was this queue full).
pub const UDP_Q: usize = 4096;
/// Capacity of a slot's DERP egress queue (one full relay packet: 3-byte header, 32-byte key, 1,500 bytes; the link has its own transmit ring behind it).
pub const DERP_Q: usize = 2560;
/// Bytes of the one scratch buffer every task shares: a datagram with its endpoint record (UDP and DNS ingress and egress, a DERP packet on its way into the
/// engine), the USB side's two frame buffers, the registry's JSON. It is held only inside synchronous code (never across an `.await`), so tasks never
/// contend for it in a single-executor image; the order of locks is registry, scratch, engine, leaf queues.
pub const SCRATCH: usize = REGISTRY_SCRATCH;
/// The pool's byte cap: what the runtime may hold at once as socket windows, TLS records and control workspaces. The heap floor is the real governor (every
/// allocation must leave `ML_HB_FLOOR` free); this is the bound a test or a misbehaving peer cannot argue with: three memberships' windows (3 x 22.7 KB), a
/// control workspace, a few TLS records.
pub const POOL_CAP: usize = 3 * 23_552 + 2 * 17_744 + 4 * 16_640;
/// Capacity of the queue towards the USB host (tunnel packets and DNS answers).
pub const HOST_Q: usize = 10240;
/// Capacity of the queue of DNS queries for the upstream resolver.
pub const DNS_Q: usize = 1024;

/// What the supervisor tells a slot's tasks. `id == 0` means stopped; a new `epoch` with the same id restarts the membership's sessions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotRun {
    /// Changes on every start and every stop.
    pub epoch: u32,
    /// The membership id (registry id), 0 when the slot is stopped.
    pub id: u32,
}

/// The life of a slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SlotState {
    /// No membership.
    #[default]
    Free,
    /// Admitted, identity loaded, tasks starting.
    Starting,
    /// Tasks running.
    Running,
    /// Stop requested, tasks winding down.
    Stopping,
}

/// What the engine asks of a slot's DERP task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerpCmd {
    /// Dial this node (the engine's `DerpConnect`).
    Connect {
        /// Region id.
        region: u16,
        /// Host name (the DNS name, the SNI and the `Host:` header).
        host: FixedStr<64>,
        /// TCP port.
        port: u16,
    },
    /// Close the relay and stop wanting one.
    Close,
}

/// One membership's secrets and names, copied out of the registry and the identity blob when it starts, zeroed when it stops.
#[derive(Clone)]
pub struct Ident {
    /// Registry id.
    pub id: u32,
    /// Label (the DNS label).
    pub label: CText<20>,
    /// Tailnet hostname (`tdongle-<label>-<id>`).
    pub hostname: CText<47>,
    /// Pre-auth key; emptied after the first successful join.
    pub auth_key: CText<159>,
    /// Noise machine key.
    pub machine: Key32,
    /// WireGuard (node) key.
    pub wg: Key32,
    /// DISCO key.
    pub disco: Key32,
}

impl Ident {
    /// An unused identity.
    pub const fn empty() -> Self {
        Ident { id: 0, label: CText::new(), hostname: CText::new(), auth_key: CText::new(), machine: Key32::ZERO, wg: Key32::ZERO, disco: Key32::ZERO }
    }
    /// Zero everything.
    pub fn wipe(&mut self) {
        self.label.zeroize();
        self.hostname.zeroize();
        self.auth_key.zeroize();
        *self = Ident::empty();
    }
}

impl core::fmt::Debug for Ident {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ident(id={})", self.id)
    }
}

/// How one membership's DERP regions authenticate (the map's `CertName`s), so that `DerpConnect` can find the certificate policy of the region it names.
/// Only the first node of each region is kept: it is the one the engine dials.
#[derive(Clone, Debug)]
pub struct CertBook {
    entries: [Option<(u16, DerpCert)>; 4],
}

impl CertBook {
    /// Empty.
    #[inline(always)]
    pub const fn new() -> Self {
        CertBook { entries: [None, None, None, None] }
    }
    /// Replace the book with the regions of `map`.
    pub fn load(&mut self, map: &DerpMap) {
        self.entries = [None, None, None, None];
        for (i, r) in map.region_list().iter().take(4).enumerate() {
            if let Some(n) = r.node_list().first() {
                let cert = match &n.cert {
                    MapCert::Hostname => DerpCert::Hostname,
                    MapCert::Name(s) => DerpCert::Name(s.clone()),
                    MapCert::Pin(p) => DerpCert::Pin(*p),
                    MapCert::Invalid => DerpCert::Invalid,
                };
                self.entries[i] = Some((r.region_id, cert));
            }
        }
    }
    /// The certificate policy of a region (the default, `Hostname`, if the region is unknown).
    pub fn of(&self, region: u16) -> DerpCert {
        self.entries.iter().flatten().find(|(r, _)| *r == region).map_or(DerpCert::Hostname, |(_, c)| c.clone())
    }
}

impl Default for CertBook {
    fn default() -> Self {
        Self::new()
    }
}

/// What the tasks of a slot publish for `/status`, the serial commands and the supervisor. Copy out under the lock, use outside it.
#[derive(Clone, Debug)]
pub struct SlotStatus {
    /// Life of the slot.
    pub state: SlotState,
    /// The membership id (0 when free).
    pub id: u32,
    /// The C's `control_stage` of the latest session (1 connect .. 6 map, 7 streaming).
    pub control_stage: u32,
    /// A session has applied its first map and is still up: control is connected.
    pub connected: bool,
    /// The first map was ever applied since the slot started (the provisioning key may be dropped).
    pub joined: bool,
    /// Sessions started.
    pub sessions: u32,
    /// Consecutive failed sessions (the backoff exponent).
    pub attempts: u32,
    /// Counters of the latest session.
    pub ctl: SessionStats,
    /// `noise_error` / `map_error` of the latest failed session (the C's fields).
    pub noise_error: u32,
    /// See `noise_error`.
    pub map_error: u32,
    /// The interactive-login URL the control plane asked for (empty if none).
    pub auth_url: FixedStr<AUTH_URL_BYTES>,
    /// The key expired (`Node.Expired`): the membership needs a new auth key.
    pub key_expired: bool,
    /// The control session's last failure as text (`protocol_error` in `/status`).
    pub last_error: FixedStr<96>,
    /// How the last control session ended, as the driver's own `Debug` (stage and failure): what `last_error`'s fixed C text leaves out (the `tn_ctl` console line).
    pub last_end: crate::util::Buf<120>,
    /// The last map's sections (see [`MapSummary`]).
    pub map: MapSummary,
    /// The relay link's state.
    pub derp_state: LinkState,
    /// The relay link's counters.
    pub derp: LinkStats,
    /// DERP TLS handshakes refused by the trust policy / deferred for the clock.
    pub tls_untrusted: u32,
    /// See `tls_untrusted`.
    pub tls_deferred: u32,
    /// Handshakes that completed.
    pub tls_ok: u32,
    /// The router published the membership as ready.
    pub ready: bool,
    /// The local UDP port (0 until bound).
    pub udp_port: u16,
    /// The datagrams the UDP task sent / received / failed to send.
    pub udp_tx: u32,
    /// See `udp_tx`.
    pub udp_rx: u32,
    /// See `udp_tx`.
    pub udp_tx_err: u32,
    /// Local endpoints reported to the engine and the control plane.
    pub local_eps: [Option<Ep>; 2],
    /// The STUN-learned public endpoint.
    pub learned_ep: Option<Ep>,
    /// Bumped whenever the endpoints the control plane should know changed.
    pub eps_gen: u32,
    /// The DERP region the engine homed on (0 = not yet).
    pub home_derp: u16,
    /// The certificate policies of the regions of the latest DERP map.
    pub certs: CertBook,
}

impl SlotStatus {
    /// A free slot.
    #[inline(always)]
    pub const fn new() -> Self {
        SlotStatus {
            state: SlotState::Free,
            id: 0,
            control_stage: 0,
            connected: false,
            joined: false,
            sessions: 0,
            attempts: 0,
            ctl: SessionStats::new(),
            noise_error: 0,
            map_error: 0,
            auth_url: FixedStr::new(),
            key_expired: false,
            last_error: FixedStr::new(),
            last_end: crate::util::Buf::new(),
            map: MapSummary { maps: 0, authoritative: false, peers_add: 0, peers_removed: 0, peers_patch: 0, derp_regions: 0, dns: 0, dir_peers: 0, dir_overflow: 0, stage_dropped: 0 },
            derp_state: LinkState::Idle,
            derp: LinkStats::new(),
            tls_untrusted: 0,
            tls_deferred: 0,
            tls_ok: 0,
            ready: false,
            udp_port: 0,
            udp_tx: 0,
            udp_rx: 0,
            udp_tx_err: 0,
            local_eps: [None, None],
            learned_ep: None,
            eps_gen: 0,
            home_derp: 0,
            certs: CertBook::new(),
        }
    }
    /// Reset for a new run of the membership.
    pub fn reset(&mut self, state: SlotState, id: u32) {
        *self = SlotStatus::new();
        self.state = state;
        self.id = id;
    }
}

impl Default for SlotStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl RtStats {
    /// All counters zero (`const`, so the shared state can be built at compile time).
    pub const fn new() -> Self {
        Self {
            usb_rx: AtomicU32::new(0),
            usb_tx: AtomicU32::new(0),
            usb_tx_refused: AtomicU32::new(0),
            to_engine: AtomicU32::new(0),
            napt_forwarded: AtomicU32::new(0),
            napt_refused: AtomicU32::new(0),
            wifi_refused: AtomicU32::new(0),
            local_other: AtomicU32::new(0),
            dns_in: AtomicU32::new(0),
            dns_fwd: AtomicU32::new(0),
            dns_replies: AtomicU32::new(0),
            out_refused: AtomicU32::new(0),
            rx_heap_refused: AtomicU32::new(0),
            rx_budget_refused: AtomicU32::new(0),
            ticks: AtomicU32::new(0),
            link_changes: AtomicU32::new(0),
            admission_refused: AtomicU32::new(0),
            admitted: AtomicU32::new(0),
            identities_generated: AtomicU32::new(0),
            identities_loaded: AtomicU32::new(0),
            storage_failures: AtomicU32::new(0),
            neg_now: AtomicU32::new(0),
            neg_max: AtomicU32::new(0),
        }
    }
}

impl Default for RtStats {
    fn default() -> Self {
        Self::new()
    }
}

/// What the last map that was applied (or aborted) carried, as the runtime saw it through the sink (the `tn_map` console line): the sections a real tailnet
/// makes big, and what the directory had no room for. Overflow is counted, never a failed map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MapSummary {
    /// Maps applied so far.
    pub maps: u32,
    /// The last map carried the whole peer list.
    pub authoritative: bool,
    /// Peer additions / full records in the last map.
    pub peers_add: u32,
    /// Peer removals.
    pub peers_removed: u32,
    /// Field-level patches (and online changes).
    pub peers_patch: u32,
    /// DERP regions kept (the C keeps [`tdongle_tailnet_map::types::MAX_DERP_REGIONS`], its home region first).
    pub derp_regions: u32,
    /// DNS configurations seen.
    pub dns: u32,
    /// Peers the directory held after the commit.
    pub dir_peers: u32,
    /// Peers the commit had no room for.
    pub dir_overflow: u32,
    /// Updates dropped because staging was full.
    pub stage_dropped: u32,
}

/// One membership slot.
pub struct Slot<R: RawMutex> {
    /// Run state for the slot's tasks (control, DERP, UDP; one receiver each, one spare).
    pub run: Watch<R, SlotRun, 4>,
    /// Bit per task that is currently working for the membership (`ALIVE_*`): the supervisor waits for 0 before it destroys the membership.
    pub alive: AtomicU8,
    /// The membership id of the running slot (0 free). Lock-free lookup for the engine's outputs.
    pub id: AtomicU32,
    /// Secrets and names of the membership.
    pub ident: Mutex<R, RefCell<Ident>>,
    /// The control session's own state (input buffer, counters: about 1.1 KiB). The big buffers are leased from [`Shared::bulk`].
    pub ws: AsyncMutex<R, SessionBuf>,
    /// DISCO / STUN / WireGuard datagrams to send (record = `[ep: 18][data]`, kind 0 = datagram, 1 = STUN).
    pub udp_q: ByteQueue<R, UDP_Q>,
    /// DERP packets to relay (record = `[dst key: 32][data]`).
    pub derp_q: ByteQueue<R, DERP_Q>,
    /// The latest connect / close the engine asked of the DERP link.
    pub derp_cmd: Signal<R, DerpCmd>,
    /// Published state.
    pub st: Mutex<R, RefCell<SlotStatus>>,
    /// Wakes the control task when something it polls changed (the endpoints, the home DERP region).
    pub ctl_kick: Signal<R, ()>,
}

impl<R: RawMutex> core::fmt::Debug for Slot<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Slot(id {})", self.id.load(Ordering::Relaxed))
    }
}

/// Bit of [`Slot::alive`]: the control task.
pub const ALIVE_CONTROL: u8 = 1;
/// Bit of [`Slot::alive`]: the DERP task.
pub const ALIVE_DERP: u8 = 2;
/// Bit of [`Slot::alive`]: the UDP task.
pub const ALIVE_UDP: u8 = 4;

impl<R: RawMutex> Slot<R> {
    #[inline(always)]
    const fn new() -> Self {
        Slot {
            run: Watch::new(),
            alive: AtomicU8::new(0),
            id: AtomicU32::new(0),
            ident: Mutex::new(RefCell::new(Ident::empty())),
            ws: AsyncMutex::new(SessionBuf::new()),
            udp_q: ByteQueue::new(),
            derp_q: ByteQueue::new(),
            derp_cmd: Signal::new(),
            st: Mutex::new(RefCell::new(SlotStatus::new())),
            ctl_kick: Signal::new(),
        }
    }
    /// Read the published state.
    pub fn status(&self) -> SlotStatus {
        self.st.lock(|s| s.borrow().clone())
    }
    /// Change the published state.
    pub fn update<T>(&self, f: impl FnOnce(&mut SlotStatus) -> T) -> T {
        self.st.lock(|s| f(&mut s.borrow_mut()))
    }
}

/// The station link as the tasks see it (published by the link watcher).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkView {
    /// `Net::link_generation`.
    pub generation: u32,
    /// `Net::link_up`.
    pub up: bool,
    /// `Net::ipv4`.
    pub v4: Option<crate::net::NetV4>,
}

/// Counters of the runtime itself (everything that is not the engine's or a protocol crate's own). All atomic: any task bumps them.
#[derive(Debug)]
pub struct RtStats {
    /// Frames received from the USB host.
    pub usb_rx: AtomicU32,
    /// Frames queued for the host.
    pub usb_tx: AtomicU32,
    /// Frames for the host that `UsbFrames::send` refused.
    pub usb_tx_refused: AtomicU32,
    /// Host IPv4 packets handed to the engine (alias traffic).
    pub to_engine: AtomicU32,
    /// Host packets the NAT forwarded to Wi-Fi.
    pub napt_forwarded: AtomicU32,
    /// ... refused by the NAT (an ICMP error went back or the packet was dropped).
    pub napt_refused: AtomicU32,
    /// ... that the Wi-Fi side refused (queue full, no link).
    pub wifi_refused: AtomicU32,
    /// Packets for the local stack (192.168.77.1) that are none of the runtime's business and went to the image's hook (or were counted and dropped).
    pub local_other: AtomicU32,
    /// DNS queries received from the host / forwarded upstream / upstream replies.
    pub dns_in: AtomicU32,
    /// See `dns_in`.
    pub dns_fwd: AtomicU32,
    /// See `dns_in`.
    pub dns_replies: AtomicU32,
    /// Output records the engine produced that no queue could take, by queue.
    pub out_refused: AtomicU32,
    /// Datagrams dropped because the heap was below the floor (the engine counts the site too).
    pub rx_heap_refused: AtomicU32,
    /// Datagrams dropped because the receive budget was full.
    pub rx_budget_refused: AtomicU32,
    /// Engine timer firings.
    pub ticks: AtomicU32,
    /// Times the link generation changed.
    pub link_changes: AtomicU32,
    /// Admission refusals (budget, largest block, no slot).
    pub admission_refused: AtomicU32,
    /// Admissions granted.
    pub admitted: AtomicU32,
    /// Identity blobs generated / loaded.
    pub identities_generated: AtomicU32,
    /// See `identities_generated`.
    pub identities_loaded: AtomicU32,
    /// Storage writes that failed.
    pub storage_failures: AtomicU32,
    /// Negotiations in flight now: a control session between "token granted" and "first map applied or failed", and a DERP TLS handshake. The token
    /// makes more than one impossible; the counter is how the tests (and the board) can see that the runtime kept to it.
    pub neg_now: AtomicU32,
    /// The most negotiations ever in flight at once (the invariant is 1).
    pub neg_max: AtomicU32,
}

/// Counts a negotiation as in flight while it exists.
#[derive(Debug)]
pub struct NegGuard<'a>(&'a RtStats);

impl RtStats {
    /// A negotiation begins; it ends when the guard drops.
    pub fn negotiation(&self) -> NegGuard<'_> {
        let n = self.neg_now.fetch_add(1, Ordering::SeqCst) + 1;
        self.neg_max.fetch_max(n, Ordering::SeqCst);
        NegGuard(self)
    }
}

impl Drop for NegGuard<'_> {
    fn drop(&mut self) {
        self.0.neg_now.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RtStats {
    /// Bump a counter.
    pub fn bump(c: &AtomicU32) {
        c.fetch_add(1, Ordering::Relaxed);
    }
    /// Read a counter.
    pub fn get(c: &AtomicU32) -> u32 {
        c.load(Ordering::Relaxed)
    }
}

/// Where a USB-bound record comes from.
pub const HOST_IP: u8 = 0;
/// A DNS answer for a host (meta: client address u32, port u16).
pub const HOST_DNS: u8 = 1;

/// What the image gives the runtime at construction, beyond the traits.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The control server's host name (`controlplane.tailscale.com`).
    pub control_host: &'static str,
    /// Its port (443 with TLS, the default of a bare host; 80 for an explicit `http://`).
    pub control_port: u16,
    /// The control connection (the `/key` fetch and the ts2021 upgrade) runs over verified TLS (`control_url`: no scheme or `https://`).
    pub control_tls: bool,
    /// The control server's Noise public key; `None` fetches it with `GET /key` on every session.
    pub control_pub: Option<[u8; 32]>,
    /// The first UDP port a membership binds (slot n binds `udp_port_base + n`; 0 lets the stack choose).
    pub udp_port_base: u16,
    /// The USB netif's Ethernet address; `None` derives one from the station MAC.
    pub usb_mac: Option<[u8; 6]>,
    /// The firmware version string for `/status`.
    pub firmware: &'static str,
    /// Control session time budgets.
    pub timeouts: tdongle_tailnet_ctl::Timeouts,
    /// Charge the runtime's own static bytes per membership in the admission arithmetic (`Params::rust`). Off by default: those bytes are in `.bss`,
    /// not in the heap the admission compares with, so charging them would count them twice (see the crate docs).
    pub charge_static_bytes: bool,
}

impl Config {
    /// The C's defaults: `controlplane.tailscale.com:80`, key fetched, ports 41641...
    pub const fn tailscale() -> Config {
        Config {
            control_host: "controlplane.tailscale.com",
            control_port: 443,
            control_tls: true,
            control_pub: None,
            udp_port_base: 41641,
            usb_mac: None,
            firmware: "tdongle-rs",
            timeouts: tdongle_tailnet_ctl::Timeouts { io_ms: 10_000, first_map_ms: 30_000, idle_ms: 30_000, lease_stall_ms: 5_000 },
            charge_static_bytes: false,
        }
    }
}

/// The counters of the control sessions' big buffers (a [`BulkLease`] through [`BulkSource`]). The buffers themselves ([`Bulk`], 17.7 KB) are taken from the
/// pool for the time a session needs them and given back after: nothing of them is static.
#[derive(Debug, Default)]
pub struct SharedBulk {
    holders: AtomicU8,
    max_holders: AtomicU8,
    leases: AtomicU32,
}

impl SharedBulk {
    /// No leases yet.
    #[inline(always)]
    pub const fn new() -> Self {
        Self { holders: AtomicU8::new(0), max_holders: AtomicU8::new(0), leases: AtomicU32::new(0) }
    }
    /// Holders now.
    pub fn holders(&self) -> u8 {
        self.holders.load(Ordering::Relaxed)
    }
    /// The most holders ever at once (the token admits one join at a time; a streaming membership's per-message lease may overlap it when the heap allows).
    pub fn max_holders(&self) -> u8 {
        self.max_holders.load(Ordering::Relaxed)
    }
    /// Leases taken.
    pub fn leases(&self) -> u32 {
        self.leases.load(Ordering::Relaxed)
    }
}

/// Control workspaces held now (all memberships), for the firmware's heap sampler: the minimum free heap while none is held is the margin the elastic consumers really have.
pub static NEG_HOLDERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Leases that waited for a lull of the relay (count, milliseconds waited in all): the workspace is allowed below the floor, and every other elastic consumer, the relay's
/// own included, is refused for as long as it is held.
pub static NEG_DEFERRED: [core::sync::atomic::AtomicU32; 2] = [const { core::sync::atomic::AtomicU32::new(0) }; 2];

/// One session's way to get a [`Bulk`]: from the pool, as a [`Class::Negotiation`] allocation (the join's peak, which the heap floor reserves), waiting when the
/// pool says no.
#[derive(Debug)]
pub struct BulkSource<'a> {
    /// The counters.
    pub stats: &'a SharedBulk,
    /// The pool and the heap probe.
    pub mem: Mem<'a>,
}

/// A held lease on a [`Bulk`]; its bytes go back to the pool on drop.
pub struct BulkGuard<'a> {
    bulk: alloc::boxed::Box<Bulk>,
    stats: &'a SharedBulk,
    _charge: Charge<'a>,
}

impl core::fmt::Debug for BulkGuard<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BulkGuard")
    }
}

impl core::ops::Deref for BulkGuard<'_> {
    type Target = Bulk;
    fn deref(&self) -> &Bulk {
        &self.bulk
    }
}

impl core::ops::DerefMut for BulkGuard<'_> {
    fn deref_mut(&mut self) -> &mut Bulk {
        &mut self.bulk
    }
}

impl Drop for BulkGuard<'_> {
    fn drop(&mut self) {
        NEG_HOLDERS.fetch_sub(1, Ordering::Relaxed);
        self.stats.holders.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A fresh workspace on the heap, or `None` (a plain function, so the value is never part of the caller's future).
#[inline(never)]
fn box_bulk() -> Option<alloc::boxed::Box<Bulk>> {
    crate::fallible::try_box_with(Bulk::new)
}

impl<'a> BulkLease for BulkSource<'a> {
    type Guard<'g>
        = BulkGuard<'a>
    where
        Self: 'g;
    async fn lease(&self) -> BulkGuard<'a> {
        // While the relay carries data and the margin over the floor is thinner than the workspace, this waits for a lull (at most 8 s): the workspace may take the heap
        // below the floor (it is what the floor reserves), and while it is held every other elastic consumer, the relay's frames included, is refused.
        if crate::derp::relay_busy() && self.mem.heap.free() < tdongle_tailnet_admission::heap::ML_HB_FLOOR + core::mem::size_of::<Bulk>() {
            let t0 = embassy_time::Instant::now();
            NEG_DEFERRED[0].fetch_add(1, Ordering::Relaxed);
            while crate::derp::relay_busy()
                && self.mem.heap.free() < tdongle_tailnet_admission::heap::ML_HB_FLOOR + core::mem::size_of::<Bulk>()
                && t0.elapsed() < embassy_time::Duration::from_secs(8)
            {
                embassy_time::Timer::after_millis(200).await;
            }
            NEG_DEFERRED[1].fetch_add(t0.elapsed().as_millis() as u32, Ordering::Relaxed);
        }
        // admitted and counted first (this waits for memory), and proven servable by the allocator with a block of exactly this size, which is freed again
        // just before the box takes its place: `Box::new` then does not reach the allocator's out-of-memory handler
        // ... and boxed fallibly: an allocation from the interrupt executor (the console) or the radio between the proof and the box may take the block, and then
        // this waits and tries again rather than reaching the out-of-memory handler
        let (charge, bulk) = loop {
            let charge = self.mem.alloc_wait(Class::Negotiation, core::mem::size_of::<Bulk>()).await.into_charge();
            // the refused value (17 KB) is dropped here, never held across the wait below: it would become part of this future's state
            if let Some(b) = box_bulk() {
                break (charge, b);
            }
            drop(charge);
            embassy_time::Timer::after_millis(200).await;
        };
        NEG_HOLDERS.fetch_add(1, Ordering::Relaxed);
        let n = self.stats.holders.fetch_add(1, Ordering::Relaxed) + 1;
        self.stats.max_holders.fetch_max(n, Ordering::Relaxed);
        self.stats.leases.fetch_add(1, Ordering::Relaxed);
        BulkGuard { bulk, stats: self.stats, _charge: charge }
    }
}

/// The registry together with the scratch buffer its JSON is loaded and saved through (one lock, so a save never interleaves with a load).
pub struct RegistryCell {
    /// The saved memberships.
    pub reg: MemberRegistry,
    /// The registry was loaded from storage (or storage had none).
    pub loaded: bool,
    /// Loading failed: tailnet access is disabled and the setup page says so (`ROUTING_DAMAGED`-style recovery text).
    pub damaged: bool,
}

impl core::fmt::Debug for RegistryCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RegistryCell({} members, loaded {}, damaged {})", self.reg.len(), self.loaded, self.damaged)
    }
}

/// Bytes of the registry's JSON scratch (the shared [`SCRATCH`], zeroed after every use): eight memberships of the longest label and key encode to about
/// 2 KiB; the C allows 16 KiB (heap, transient).
pub const REGISTRY_SCRATCH: usize = 4096;

/// The shared state. `R` is the raw mutex (a critical section, or a spin lock that does not mask interrupts: engine calls take milliseconds when a
/// handshake runs), `P` the platform, `S` storage, `D` the engine's peer directory.
pub struct Shared<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    /// The image's platform.
    pub platform: P,
    /// Construction parameters.
    pub cfg: Config,
    /// NVS.
    pub storage: Mutex<R, RefCell<S>>,
    engine: Mutex<R, RefCell<GatewayEngine<D>>>,
    /// The slots.
    pub slots: [Slot<R>; MAX_RUN],
    /// Saved memberships.
    pub registry: Mutex<R, RefCell<RegistryCell>>,
    /// Records for the USB host.
    pub host_q: ByteQueue<R, HOST_Q>,
    /// DNS queries for the upstream resolver (record = `[upstream: 4]` + query; kind 1 = reopen the socket first).
    pub dns_q: ByteQueue<R, DNS_Q>,
    /// The negotiation token.
    pub token: Token<R>,
    /// The one 16,640-byte TLS record buffer all DERP connections share.
    pub lease: LeasePool,
    /// The dynamic buffer pool: socket windows, TLS records and the control session's [`Bulk`] are taken from it while they are needed (ADR 0002, "RAM fit").
    pub pool: Pool,
    /// The shared scratch buffer (see [`SCRATCH`]); take it with [`Shared::with_scratch`].
    scratch: Mutex<R, RefCell<[u8; SCRATCH]>>,
    /// The one set of big control-session buffers (record reader, sealed record, JSON, projector) every membership's control task leases.
    pub bulk: SharedBulk,
    /// The next time the engine must be ticked.
    pub wake_at: Mutex<R, Cell<Option<Millis>>>,
    /// Re-arms the engine timer.
    pub wake: Signal<R, ()>,
    /// The Wi-Fi link as last seen.
    pub link: Watch<R, LinkView, 12>,
    /// Wakes the supervisor (a member action, a state change).
    pub supervisor_kick: Signal<R, ()>,
    /// Wakes the USB task when the carrier should be re-evaluated.
    pub carrier_kick: Signal<R, ()>,
    /// Memberships the router published as ready.
    pub ready_count: AtomicU8,
    /// The wall clock is plausibly set (as last told to the engine and the links).
    pub clock_valid: AtomicBool,
    /// Runtime counters.
    pub stats: RtStats,
    /// Heap floor crossings seen in the heap readings fed to the engine (a reading below `ML_HB_FLOOR` while a membership was running).
    pub heap_low_events: AtomicU32,
    /// The lowest free-heap reading fed to the engine.
    pub heap_min_seen: AtomicU32,
    /// The next run epoch (see [`SlotRun`]).
    pub epoch: AtomicU32,
    /// `size_of_val` of the runtime's top-level futures, set by [`crate::run`] before it polls anything (index: `crate::sizes::FUT_*`).
    pub fut_bytes: [AtomicU32; crate::sizes::FUTURES],
    /// Bytes of socket buffers the `Net` keeps per membership.
    pub net_member_bytes: AtomicU32,
    /// The per-owner ledger of what the runtime holds for running memberships (charged at start, given back when the stop finishes).
    pub ledger: tdongle_tailnet_admission::ledger::Ledger,
    /// The last admission decisions (`members` serial report).
    pub adm_log: Mutex<R, RefCell<AdmLog>>,
}

/// A ring of the last admission decisions.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdmLog {
    /// Newest last.
    pub recs: [tdongle_tailnet_status::diag::AdmissionRecord; 8],
    /// Decisions recorded in all.
    pub n: u32,
}

impl AdmLog {
    /// Record one.
    pub fn push(&mut self, r: tdongle_tailnet_status::diag::AdmissionRecord) {
        let i = (self.n % 8) as usize;
        self.recs[i] = r;
        self.n = self.n.wrapping_add(1);
    }
    /// The records, oldest first.
    pub fn ordered(&self, out: &mut [tdongle_tailnet_status::diag::AdmissionRecord; 8]) -> usize {
        let n = self.n.min(8) as usize;
        let start = if self.n > 8 { (self.n % 8) as usize } else { 0 };
        for (k, o) in out.iter_mut().enumerate().take(n) {
            *o = self.recs[(start + k) % 8];
        }
        n
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> core::fmt::Debug for Shared<R, P, S, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Shared")
    }
}

/// Entropy from the platform.
#[derive(Debug)]
pub struct PlatformRng<'a, P: Platform + ?Sized>(pub &'a P);

impl<P: Platform + ?Sized> Entropy for PlatformRng<'_, P> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill_random(buf);
    }
}

/// What one running membership holds, by ledger owner (host-independent figures: the statics a slot pins while it runs). `Noise` is the control session's
/// workspace, `Packet` the two egress queues, `WireGuard` the engine's per-membership record, `Other` the slot's identity and status.
pub fn member_charges<D: PeerDirectory>() -> [(tdongle_tailnet_admission::ledger::Owner, usize); 4] {
    use tdongle_tailnet_admission::ledger::Owner;
    [
        (Owner::Noise, core::mem::size_of::<SessionBuf>()),
        (Owner::Packet, UDP_Q + DERP_Q),
        (Owner::WireGuard, GatewayEngine::<D>::per_member_bytes().in_engine),
        (Owner::Other, core::mem::size_of::<Ident>() + core::mem::size_of::<SlotStatus>()),
    ]
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Shared<R, P, S, D> {
    /// Run `f` on the shared scratch buffer. **Synchronous only** (a lock is never held across an `.await`): the closure may feed the engine (the order is
    /// scratch, then engine) but must not take the scratch again.
    pub fn with_scratch<T>(&self, f: impl FnOnce(&mut [u8; SCRATCH]) -> T) -> T {
        self.scratch.lock(|s| f(&mut s.borrow_mut()))
    }

    /// The pool with the platform's heap probe: what a task takes buffers with.
    pub fn mem(&self) -> Mem<'_> {
        Mem { pool: &self.pool, heap: self.platform.heap() }
    }

    /// Build the shared state around the image's platform, storage and the engine's peer directory. Nothing runs until [`crate::run`].
    ///
    /// Not `const`: the control workspace contains the map projector, whose constructor is not `const` in `tdongle-tailnet-map`. Build it in place with
    /// `StaticCell::init_with(|| Shared::new(..))`.
    #[inline(always)]
    pub const fn new(cfg: Config, platform: P, storage: S, dir: D) -> Self {
        Shared {
            platform,
            cfg,
            storage: Mutex::new(RefCell::new(storage)),
            engine: Mutex::new(RefCell::new(GatewayEngine::new(dir))),
            slots: [const { Slot::new() }; MAX_RUN],
            registry: Mutex::new(RefCell::new(RegistryCell { reg: MemberRegistry::new(), loaded: false, damaged: false })),
            host_q: ByteQueue::new(),
            dns_q: ByteQueue::new(),
            token: Token::new(),
            lease: LeasePool::new(),
            pool: Pool::new(POOL_CAP),
            bulk: SharedBulk::new(),
            scratch: Mutex::new(RefCell::new([0; SCRATCH])),
            wake_at: Mutex::new(Cell::new(None)),
            wake: Signal::new(),
            link: Watch::new(),
            supervisor_kick: Signal::new(),
            carrier_kick: Signal::new(),
            ready_count: AtomicU8::new(0),
            clock_valid: AtomicBool::new(false),
            stats: RtStats::new(),
            heap_low_events: AtomicU32::new(0),
            heap_min_seen: AtomicU32::new(u32::MAX),
            epoch: AtomicU32::new(1),
            fut_bytes: [const { AtomicU32::new(0) }; crate::sizes::FUTURES],
            net_member_bytes: AtomicU32::new(0),
            ledger: tdongle_tailnet_admission::ledger::Ledger::new(),
            adm_log: Mutex::new(RefCell::new(AdmLog {
                recs: [tdongle_tailnet_status::diag::AdmissionRecord {
                    uptime_ms: 0,
                    member_id: 0,
                    free_bytes: 0,
                    largest_bytes: 0,
                    budget_bytes: 0,
                    sockets_open: 0,
                    sockets_limit: 0,
                    active: 0,
                    verdict: 0,
                }; 8],
                n: 0,
            })),
        }
    }

    /// Now, milliseconds since boot.
    pub fn now(&self) -> Millis {
        self.platform.now_ms()
    }

    /// The slot running membership `id`.
    pub fn slot_of(&self, id: u32) -> Option<(usize, &Slot<R>)> {
        if id == 0 {
            return None;
        }
        self.slots.iter().enumerate().find(|(_, s)| s.id.load(Ordering::Acquire) == id)
    }

    /// A free slot index (no membership, not stopping).
    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.st.lock(|st| st.borrow().state == SlotState::Free))
    }

    /// Feed one input to the engine and return what it did with it. The heap reading is taken first and handed over (ADR 0022: the engine's elastic
    /// sites refuse below the floor); the outputs go to the queues by [`OutSink`].
    pub fn feed(&self, input: Input<'_>) -> Handled {
        let now = self.now();
        let heap = self.platform.heap().snapshot();
        self.note_heap(heap.free);
        let mut rng = PlatformRng(&self.platform);
        let mut sink = OutSink { sh: self, now };
        self.engine.lock(|e| {
            let mut e = e.borrow_mut();
            e.set_heap(heap);
            e.handle(now, input, &mut rng, &mut sink)
        })
    }

    /// The engine, mutably (boot-time loading only).
    pub(crate) fn with_engine_mut<T>(&self, f: impl FnOnce(&mut GatewayEngine<D>) -> T) -> T {
        self.engine.lock(|e| f(&mut e.borrow_mut()))
    }

    /// Read the engine (status, counters). Do not call from inside an engine callback; it takes the engine lock.
    pub fn with_engine<T>(&self, f: impl FnOnce(&GatewayEngine<D>, Millis) -> T) -> T {
        let now = self.now();
        self.engine.lock(|e| f(&e.borrow(), now))
    }

    /// Admit a datagram of `len` bytes to the engine's receive budget; the caller calls [`Shared::rx_done`] when it has handled it.
    pub fn rx_admit(&self, len: usize) -> bool {
        use tdongle_tailnet_admission::wg_rx::Verdict;
        let heap = self.platform.heap().snapshot();
        self.note_heap(heap.free);
        let v = self.engine.lock(|e| {
            let mut e = e.borrow_mut();
            e.set_heap(heap);
            e.rx_enqueue(len)
        });
        match v {
            Verdict::Ok => true,
            Verdict::Heap => {
                RtStats::bump(&self.stats.rx_heap_refused);
                false
            }
            Verdict::Bytes => {
                RtStats::bump(&self.stats.rx_budget_refused);
                false
            }
        }
    }

    /// A datagram admitted by [`Shared::rx_admit`] has been handled.
    pub fn rx_done(&self, len: usize) {
        self.with_engine(|e, _| e.rx_dequeue(len));
    }

    fn note_heap(&self, free: usize) {
        let f = free.min(u32::MAX as usize) as u32;
        self.heap_min_seen.fetch_min(f, Ordering::Relaxed);
        if f < tdongle_tailnet_admission::heap::ML_HB_FLOOR as u32 && self.ready_count.load(Ordering::Relaxed) != 0 {
            self.heap_low_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Publish a new engine wake time and re-arm the timer if it changed.
    fn set_wake(&self, w: Option<Millis>) {
        let old = self.wake_at.lock(|c| c.replace(w));
        if old != w {
            self.wake.signal(());
        }
    }

    /// The next engine wake time.
    pub fn wake_at(&self) -> Option<Millis> {
        self.wake_at.lock(Cell::get)
    }
}

/// The engine's output: copies into queues and cells, nothing else.
pub struct OutSink<'a, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    #[allow(dead_code)]
    now: Millis,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> core::fmt::Debug for OutSink<'_, R, P, S, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OutSink")
    }
}

/// Meta of a UDP egress record: the destination as 16 address bytes and the port.
pub fn ep_meta(ep: &Ep) -> [u8; 18] {
    let mut m = [0u8; 18];
    m[..16].copy_from_slice(ep.ip16());
    m[16..].copy_from_slice(&ep.port().to_be_bytes());
    m
}

/// The inverse of [`ep_meta`].
pub fn ep_from_meta(m: &[u8]) -> Option<Ep> {
    let ip: [u8; 16] = m.get(..16)?.try_into().ok()?;
    let port = u16::from_be_bytes([*m.get(16)?, *m.get(17)?]);
    Some(Ep::v6(ip, port))
}

/// Kind of a UDP egress record: a datagram (DISCO, WireGuard).
pub const UDP_DATAGRAM: u8 = 0;
/// Kind of a UDP egress record: a STUN request.
pub const UDP_STUN: u8 = 1;

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Output for OutSink<'_, R, P, S, D> {
    fn emit(&mut self, o: Out<'_>) -> bool {
        let sh = self.sh;
        let ok = match o {
            Out::SendUdp { member, dst, data } => sh.slot_of(member).is_some_and(|(_, s)| s.udp_q.push(UDP_DATAGRAM, &ep_meta(&dst), data)),
            Out::SendStun { member, dst, data, .. } => sh.slot_of(member).is_some_and(|(_, s)| s.udp_q.push(UDP_STUN, &ep_meta(&dst), data)),
            // the record's meta is the peer's key and its home region (0 = not known): the member's home link sends what is homed with it and hands the rest to its other links
            Out::DerpSend { member, dst, region, data } => sh.slot_of(member).is_some_and(|(_, s)| {
                let mut meta = [0u8; 34];
                meta[..32].copy_from_slice(dst);
                meta[32..].copy_from_slice(&region.to_be_bytes());
                s.derp_q.push(0, &meta, data)
            }),
            Out::HostPacket { data } => sh.host_q.push(HOST_IP, &[], data),
            Out::DnsAnswer { client, data } => {
                let mut meta = [0u8; 6];
                meta[..4].copy_from_slice(&client.addr.to_be_bytes());
                meta[4..].copy_from_slice(&client.port.to_be_bytes());
                sh.host_q.push(HOST_DNS, &meta, data)
            }
            Out::DnsForward { upstream, data, reset_socket } => sh.dns_q.push(u8::from(reset_socket), &upstream.to_be_bytes(), data),
            Out::DerpConnect { member, region, host, port } => {
                if let Some((_, s)) = sh.slot_of(member) {
                    let mut h = FixedStr::<64>::new();
                    h.set(host);
                    s.derp_cmd.signal(DerpCmd::Connect { region, host: h, port });
                }
                true
            }
            Out::DerpClose { member } => {
                if let Some((_, s)) = sh.slot_of(member) {
                    s.derp_cmd.signal(DerpCmd::Close);
                }
                true
            }
            Out::HomeDerp { member, region } => {
                if let Some((_, s)) = sh.slot_of(member) {
                    // while the link visits a region the home we tell the control plane is that region (see `derp::derp_extra`); the engine's own is restored when the visit ends
                    let visiting = crate::derp::VISITING.load(core::sync::atomic::Ordering::Relaxed) != 0;
                    s.update(|st| {
                        if !visiting && st.home_derp != region {
                            st.home_derp = region;
                            st.eps_gen = st.eps_gen.wrapping_add(1);
                        }
                    });
                    s.ctl_kick.signal(());
                }
                true
            }
            Out::EndpointLearned { member, ep } => {
                if let Some((_, s)) = sh.slot_of(member) {
                    s.update(|st| {
                        if st.learned_ep != Some(ep) {
                            st.learned_ep = Some(ep);
                            st.eps_gen = st.eps_gen.wrapping_add(1);
                        }
                    });
                    s.ctl_kick.signal(());
                }
                true
            }
            // the links belong to the DERP tasks, which take the token themselves
            Out::WantToken { .. } | Out::ReleaseToken { .. } => true,
            Out::MemberReady { member, ready } => {
                if let Some((_, s)) = sh.slot_of(member) {
                    let was = s.update(|st| core::mem::replace(&mut st.ready, ready));
                    if was != ready {
                        if ready {
                            sh.ready_count.fetch_add(1, Ordering::AcqRel);
                        } else {
                            sh.ready_count.fetch_sub(1, Ordering::AcqRel);
                        }
                        sh.carrier_kick.signal(());
                    }
                }
                true
            }
            Out::MemberGone { .. } => {
                sh.supervisor_kick.signal(());
                true
            }
            Out::Wake(w) => {
                sh.set_wake(w);
                true
            }
        };
        if !ok {
            RtStats::bump(&sh.stats.out_refused);
        }
        ok
    }
}

/// Forward a map event of membership `member` to the engine (the control task's `NetmapTarget`), and keep the DERP certificate book of the slot.
pub struct MapTee<'a, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    /// The shared state.
    pub sh: &'a Shared<R, P, S, D>,
    /// The slot whose map this is.
    pub slot: usize,
    /// The membership id.
    pub member: u32,
    /// The map committed with `key_expired` set.
    pub expired: bool,
    /// What the map in flight carries so far.
    pub cur: MapSummary,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> core::fmt::Debug for MapTee<'_, R, P, S, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MapTee({})", self.member)
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> tdongle_tailnet_engine::NetmapTarget for MapTee<'_, R, P, S, D> {
    fn netmap(&mut self, ev: NetmapEvent) -> bool {
        match &ev {
            NetmapEvent::Derp(map) => {
                self.cur.derp_regions = u32::from(map.count);
                self.sh.slots[self.slot].update(|st| st.certs.load(map));
            }
            NetmapEvent::Peer(r) => match r.action {
                tdongle_tailnet_map::types::PeerAction::Add => self.cur.peers_add += 1,
                tdongle_tailnet_map::types::PeerAction::Remove => self.cur.peers_removed += 1,
                tdongle_tailnet_map::types::PeerAction::Patch => self.cur.peers_patch += 1,
            },
            NetmapEvent::Dns(_) => self.cur.dns += 1,
            NetmapEvent::Commit { self_expired, authoritative } => {
                self.expired = *self_expired;
                self.cur.authoritative = *authoritative;
                self.sh.slots[self.slot].update(|st| st.key_expired = *self_expired);
            }
            _ => {}
        }
        let ok = self.sh.feed(Input::Netmap { member: self.member, event: &ev }) != Handled::Refused;
        if matches!(ev, NetmapEvent::Commit { .. } | NetmapEvent::Abort) {
            let (slot, committed) = (self.slot, matches!(ev, NetmapEvent::Commit { .. }) && ok);
            let (peers, over) = self.sh.with_engine(|e, _| (e.dir().count(slot) as u32, e.dir().overflow(slot)));
            let mut m = core::mem::take(&mut self.cur);
            m.dir_peers = peers;
            m.dir_overflow = over.0;
            m.stage_dropped = over.1;
            self.sh.slots[self.slot].update(|st| {
                m.maps = st.map.maps + u32::from(committed);
                st.map = m;
            });
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::shared;
    use tdongle_tailnet_dns::Client;
    use tdongle_tailnet_engine::{Out, Output};

    #[test]
    fn ep_meta_round_trips_v4_and_v6() {
        for ep in [Ep::v4([1, 2, 3, 4], 5), Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443), Ep::NONE] {
            assert_eq!(ep_from_meta(&ep_meta(&ep)), Some(ep));
        }
        assert_eq!(ep_from_meta(&[0; 17]), None);
    }

    #[test]
    fn the_adm_log_keeps_the_last_eight_oldest_first() {
        let mut l = AdmLog::default();
        for i in 1..=11u32 {
            l.push(tdongle_tailnet_status::diag::AdmissionRecord { member_id: i, ..Default::default() });
        }
        let mut out = [Default::default(); 8];
        assert_eq!(l.ordered(&mut out), 8);
        assert_eq!(out.iter().map(|r| r.member_id).collect::<std::vec::Vec<_>>(), [4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn the_out_sink_only_enqueues_and_refuses_what_has_no_home() {
        let sh = shared();
        let mut sink = OutSink { sh: &sh, now: 0 };
        // no membership 7: its datagrams and relay packets are refused (the engine counts them), nothing blocks
        assert!(!sink.emit(Out::SendUdp { member: 7, dst: Ep::v4([1, 1, 1, 1], 1), data: b"x" }));
        assert!(!sink.emit(Out::DerpSend { member: 7, dst: &[9; 32], region: 0, data: b"x" }));
        // a membership in slot 1
        sh.slots[1].id.store(7, Ordering::SeqCst);
        assert!(sink.emit(Out::SendUdp { member: 7, dst: Ep::v4([1, 1, 1, 1], 1), data: b"disco" }));
        assert!(sink.emit(Out::SendStun {
            member: 7,
            dst: Ep::v4([2, 2, 2, 2], 3478),
            data: &[0; 20],
            sock: tdongle_tailnet_disco::stun_sched::SockKind::Disco4
        }));
        assert!(sink.emit(Out::DerpSend { member: 7, dst: &[9; 32], region: 0, data: b"relay" }));
        let mut buf = [0u8; 64];
        let (k, n) = sh.slots[1].udp_q.try_pop(&mut buf).unwrap();
        assert_eq!((k, ep_from_meta(&buf[..n]), &buf[18..n]), (UDP_DATAGRAM, Some(Ep::v4([1, 1, 1, 1], 1)), &b"disco"[..]));
        assert_eq!(sh.slots[1].udp_q.try_pop(&mut buf).unwrap().0, UDP_STUN);
        let (_, n) = sh.slots[1].derp_q.try_pop(&mut buf).unwrap();
        assert_eq!((&buf[..32], u16::from_be_bytes([buf[32], buf[33]]), &buf[34..n]), (&[9u8; 32][..], 0, &b"relay"[..]));
        // host packets and DNS
        assert!(sink.emit(Out::HostPacket { data: &[0x45; 28] }));
        assert!(sink.emit(Out::DnsAnswer { client: Client { addr: 0xc0a8_4d02, port: 5353 }, data: b"answer" }));
        assert!(sink.emit(Out::DnsForward { upstream: 0x0808_0808, data: b"query", reset_socket: true }));
        let (k, _) = sh.host_q.try_pop(&mut buf).unwrap();
        assert_eq!(k, HOST_IP);
        let (k, n) = sh.host_q.try_pop(&mut buf).unwrap();
        assert_eq!((k, &buf[..4], u16::from_be_bytes([buf[4], buf[5]]), &buf[6..n]), (HOST_DNS, &[0xc0, 0xa8, 0x4d, 0x02][..], 5353, &b"answer"[..]));
        let (k, n) = sh.dns_q.try_pop(&mut buf).unwrap();
        assert_eq!((k, &buf[..4], &buf[4..n]), (1, &[8, 8, 8, 8][..], &b"query"[..]));
        // commands and notes: cells, no I/O
        assert!(sink.emit(Out::DerpConnect { member: 7, region: 900, host: "derp.example", port: 443 }));
        assert_eq!(
            sh.slots[1].derp_cmd.try_take(),
            Some(DerpCmd::Connect {
                region: 900,
                host: {
                    let mut h = FixedStr::new();
                    h.set("derp.example");
                    h
                },
                port: 443
            })
        );
        assert!(sink.emit(Out::DerpClose { member: 7 }));
        assert_eq!(sh.slots[1].derp_cmd.try_take(), Some(DerpCmd::Close));
        assert!(sink.emit(Out::EndpointLearned { member: 7, ep: Ep::v4([9, 9, 9, 9], 9) }));
        assert!(sink.emit(Out::HomeDerp { member: 7, region: 3 }));
        let st = sh.slots[1].status();
        assert_eq!((st.learned_ep, st.home_derp, st.eps_gen), (Some(Ep::v4([9, 9, 9, 9], 9)), 3, 2));
        // readiness is counted once per change and the carrier follows it
        assert!(sink.emit(Out::MemberReady { member: 7, ready: true }));
        assert!(sink.emit(Out::MemberReady { member: 7, ready: true }));
        assert_eq!(sh.ready_count.load(Ordering::SeqCst), 1);
        assert!(sink.emit(Out::MemberReady { member: 7, ready: false }));
        assert_eq!(sh.ready_count.load(Ordering::SeqCst), 0);
        // the one wake: published, re-arms only on change
        assert!(sink.emit(Out::Wake(Some(1234))));
        assert_eq!(sh.wake_at(), Some(1234));
        assert!(sh.wake.signaled());
        // full queues refuse and count
        for _ in 0..40 {
            let _ = sink.emit(Out::HostPacket { data: &[0u8; 1500] });
        }
        assert!(RtStats::get(&sh.stats.out_refused) >= 30);
    }

    #[test]
    fn member_charges_are_a_fixed_sum_per_membership() {
        let c = member_charges::<crate::testutil::Dir>();
        assert_eq!(c.len(), 4);
        assert!(c.iter().all(|(_, b)| *b > 0));
    }
}

/// The shared state must stay constructible at compile time: the firmware keeps it as a `const` item and copies it from flash into a heap block, because a value of
/// that size built at run time is a stack frame the board does not have (`rust/tools/check_stack.py`). A constructor that stops being `const` fails here, on the host.
#[cfg(test)]
mod const_build {
    use super::*;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use tdongle_tailnet_engine::RamDirectory;
    use tdongle_tailnet_fw::{HeapProbe, Platform, Storage, StorageError};

    struct Heap;
    impl HeapProbe for Heap {
        fn free(&self) -> usize {
            100_000
        }
        fn largest_block(&self) -> usize {
            24_576
        }
        fn minimum_free(&self) -> usize {
            100_000
        }
    }
    struct Plat;
    impl Platform for Plat {
        fn now_ms(&self) -> Millis {
            0
        }
        fn unix_seconds(&self) -> Option<u64> {
            None
        }
        fn fill_random(&self, buf: &mut [u8]) {
            buf.fill(0)
        }
        fn sta_mac(&self) -> [u8; 6] {
            [0; 6]
        }
        fn heap(&self) -> &dyn HeapProbe {
            &Heap
        }
        fn console_line(&self, _: &str) {}
    }
    struct Store;
    impl Storage for Store {
        fn get(&mut self, _: &str, _: &str, _: &mut [u8]) -> Result<usize, StorageError> {
            Err(StorageError::NotFound)
        }
        fn set(&mut self, _: &str, _: &str, _: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        fn erase_namespace(&mut self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
    }
    type Sh = Shared<CriticalSectionRawMutex, Plat, Store, RamDirectory<MAX_RUN, 24, 32>>;

    #[allow(clippy::declare_interior_mutable_const)]
    const BUILT_AT_COMPILE_TIME: Sh = Shared::new(Config::tailscale(), Plat, Store, RamDirectory::new());

    #[test]
    fn the_shared_state_is_a_compile_time_value_and_starts_empty() {
        let sh: std::boxed::Box<Sh> = std::boxed::Box::new(BUILT_AT_COMPILE_TIME);
        assert_eq!(sh.pool.in_use(), 0);
        assert!(sh.slots.iter().all(|s| s.status().state == SlotState::Free));
        assert_eq!(sh.registry.lock(|r| r.borrow().reg.len()), 0);
    }
}
