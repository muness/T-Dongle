//! What the engine reports: a plain snapshot of its counters and per-membership state, and the memory ledger of one membership.

use crate::engine::Engine;
use crate::io::MemberId;
use crate::jit::{JIT_BLOCK, ParkQueue};
use crate::member::{LOCAL_EPS, Member, NETCHECK_REGIONS, Phase};
use crate::slot::WgSlot;
use tdongle_tailnet_derp::Link;
use tdongle_tailnet_disco::netcheck::Netcheck;
use tdongle_tailnet_disco::path::{PathCounters, PathState, ProbeTable};
use tdongle_tailnet_disco::stun_sched::StunScheduler;
use tdongle_tailnet_map::types::DerpMap;
use tdongle_tailnet_peers::membership::Membership;
use tdongle_tailnet_router::Member as RouterMember;
use tdongle_tailnet_types::{FixedStr, Millis};

/// Transmit-ring bytes of a DERP link in the reference configuration (the runtime owns the links; this is the figure the ledger charges).
pub const DERP_TXQ: usize = 4096;

/// Bytes of state one membership costs on top of the shared parts, split as ADR 0013 / the Rust port ADR want it (host sizes; the xtensa figures are
/// the same except where a `u64` or pointer shrinks, see `tests/sizes.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberBytes {
    /// The netmap parts and the resident-peer table: `Membership<P>`, the DERP map, names, mirrors.
    pub netmap_and_peers: usize,
    /// WireGuard hot slots one membership can have resident (`P` slots of the pool; the pool is shared, `K` caps the sum over memberships).
    pub wg_slots_resident: usize,
    /// DISCO: per-peer paths, probe table, counters, STUN schedule, netcheck, local endpoints.
    pub disco: usize,
    /// The DERP link (owned by the runtime): reader, transmit ring, control buffer.
    pub derp_link: usize,
    /// The router's per-membership share: its published record plus an equal share of the flow and alias tables.
    pub router_share: usize,
    /// Queues: the parked-packet bookkeeping and an equal share of the packet arena.
    pub queues: usize,
    /// Identity, cookie checker, counters and everything else in `Member<P>` that the lines above do not name.
    pub other: usize,
    /// `size_of::<Member<P>>()`: the whole in-engine record (the lines above minus the parts that live elsewhere).
    pub in_engine: usize,
}

impl MemberBytes {
    /// Compute for `P` peers per membership.
    pub const fn of<const P: usize>() -> Self {
        let netmap_and_peers = core::mem::size_of::<Membership<P>>()
            + core::mem::size_of::<DerpMap>()
            + core::mem::size_of::<FixedStr<127>>()
            + core::mem::size_of::<FixedStr<63>>()
            + core::mem::size_of::<FixedStr<31>>()
            + P * (core::mem::size_of::<Option<u8>>() + core::mem::size_of::<u32>());
        let disco = P * core::mem::size_of::<PathState<8>>()
            + core::mem::size_of::<ProbeTable<16>>()
            + core::mem::size_of::<PathCounters>()
            + core::mem::size_of::<StunScheduler>()
            + core::mem::size_of::<Netcheck<NETCHECK_REGIONS>>()
            + LOCAL_EPS * 18;
        let in_engine = core::mem::size_of::<Member<P>>();
        let queues = core::mem::size_of::<ParkQueue>();
        let known = netmap_and_peers + disco + queues;
        Self {
            netmap_and_peers,
            wg_slots_resident: P * WgSlot::BYTES,
            disco,
            derp_link: Link::<DERP_TXQ>::STATE_BYTES,
            router_share: core::mem::size_of::<Option<RouterMember>>(),
            queues,
            other: in_engine.saturating_sub(known),
            in_engine,
        }
    }
    /// Bytes of the shared arena per membership for `JB` blocks and `M` memberships (added to `queues` for the worst case).
    pub const fn arena_share(jb: usize, m: usize) -> usize {
        jb * JIT_BLOCK / m
    }
}

/// One membership in a snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberStatus {
    /// Router id.
    pub id: MemberId,
    /// Running.
    pub running: bool,
    /// Published as ready to the router.
    pub ready: bool,
    /// The node's tailnet address.
    pub self_ip: u32,
    /// The DERP region we are homed on.
    pub home_derp: u16,
    /// The relay link is ready.
    pub derp_ready: bool,
    /// Resident peers.
    pub peers_resident: u8,
    /// Resident peers with a WireGuard session.
    pub sessions: u8,
    /// Resident peers on a trusted direct path.
    pub direct_paths: u8,
    /// Parked packets.
    pub parked: u8,
    /// Peers in the directory.
    pub directory_peers: u32,
    /// Activations that hit / missed / evicted / were rejected.
    pub activation: (u32, u32, u32, u32),
    /// Trial counters: started, confirmed, expired, refused.
    pub trial: (u32, u32, u32, u32),
    /// The STUN-learned public endpoint is known.
    pub has_public_ep: bool,
    /// Directory generation.
    pub generation: u32,
}

/// A snapshot of the engine for `/status` (the `status_map` module, behind the `status` feature, maps it onto the status crate's inputs).
#[derive(Clone, Debug)]
pub struct StatusSnapshot<const M: usize> {
    /// Per membership slot.
    pub members: [Option<MemberStatus>; M],
    /// Pool: slots live, capacity, peak, refusals (full, heap, largest, device-full), commits refused.
    pub pool: PoolStatus,
    /// Pool arbitration: own evictions, other evictions, refused.
    pub arbiter: (u32, u32, u32),
    /// Elastic-site refusals in `HbSite` order: Jit, DerpTx, RxCtrl, DerpRx, WgCopy.
    pub heap_refused: [u32; 5],
    /// The router's counters in `Stat::ALL` order.
    pub router: [u32; tdongle_tailnet_router::Stat::COUNT],
    /// Aliases allocated.
    pub aliases: usize,
    /// Arena blocks in use / peak.
    pub arena: (usize, usize),
    /// The wake the runtime was last told.
    pub wake: Option<Millis>,
    /// The wall clock is plausibly set.
    pub clock_valid: bool,
}

/// The pool's numbers in a snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStatus {
    /// Live slots.
    pub used: u32,
    /// Capacity.
    pub capacity: u32,
    /// High-water mark.
    pub peak: u32,
    /// Refused: full.
    pub refused_full: u32,
    /// Refused: heap floor.
    pub refused_heap: u32,
    /// Refused: largest block.
    pub refused_largest: u32,
    /// Refused: the owner's table full.
    pub refused_device_full: u32,
}

impl<D: crate::dir::PeerDirectory, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize>
    Engine<D, M, P, K, A, F, JB>
{
    /// A snapshot of the counters and per-membership state.
    pub fn status(&self, now: Millis) -> StatusSnapshot<M> {
        use tdongle_tailnet_admission::heap::HbSite;
        let ps = self.sh.pool.stats();
        let a = self.sh.arbiter.stats();
        let mut members = [None; M];
        for (slot, m) in self.members.iter().enumerate() {
            let Some(m) = m else { continue };
            let owner = tdongle_tailnet_peers::pool::OwnerId(m.rt.slot);
            let mut sessions = 0;
            let mut direct = 0;
            for (idx, _) in m.mship.table.iter() {
                if m.rt.slot_of[idx].and_then(|s| self.sh.pool.get(owner, s)).is_some_and(|sl| sl.hot.has_session()) {
                    sessions += 1;
                }
                if m.rt.paths[idx].status(now).has_direct {
                    direct += 1;
                }
            }
            let s = &m.mship.stats;
            let t = &m.mship.trial;
            members[slot] = Some(MemberStatus {
                id: m.rt.id,
                running: m.rt.phase == Phase::Running,
                ready: m.rt.ready,
                self_ip: m.rt.self_ip,
                home_derp: m.rt.home_derp,
                derp_ready: m.rt.derp_ready,
                peers_resident: m.mship.table.len() as u8,
                sessions,
                direct_paths: direct,
                parked: m.rt.park.len() as u8,
                directory_peers: self.sh.dir.count(slot) as u32,
                activation: (s.hits, s.misses, s.evictions, s.rejected),
                trial: (t.started, t.confirmed, t.expired, t.refused),
                has_public_ep: m.rt.public_ep.is_some(),
                generation: self.sh.dir.generation(slot),
            });
        }
        StatusSnapshot {
            members,
            pool: PoolStatus {
                used: ps.used,
                capacity: ps.capacity,
                peak: ps.peak_used,
                refused_full: ps.refused_full,
                refused_heap: ps.refused_heap,
                refused_largest: ps.refused_largest,
                refused_device_full: ps.refused_device_full,
            },
            arbiter: (a.evictions_own, a.evictions_other, a.refused),
            heap_refused: [HbSite::Jit, HbSite::DerpTx, HbSite::RxCtrl, HbSite::DerpRx, HbSite::WgCopy].map(|s| self.sh.hb.get(s)),
            router: *self.sh.router.stats().as_array(),
            aliases: self.sh.book.len(),
            arena: (self.sh.store.used_blocks(), self.sh.store.peak_blocks()),
            wake: self.sh.last_wake,
            clock_valid: self.sh.clock_valid,
        }
    }
}
