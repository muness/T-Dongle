//! The two bounded O(1) tables: the alias cache and the NAT flow table. Behaviour is the C's `route_table.c` (same hashes, same CLOCK
//! replacement, same slot reclaim order so mapped ports are identical), parameterised by const generics.

use crate::{FLOW_IDLE_MS, MAPPED_BASE, MAPPED_GENERATIONS_MAX};
use tdongle_tailnet_types::Millis;

/// An alias binding: membership `id`, tailnet address `peer`, and the 198.18.0.0/15 address `alias` the USB host uses for it. Never reassigned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AliasRecord {
    /// Membership id (nonzero).
    pub id: u32,
    /// The peer's tailnet IPv4 address.
    pub peer: u32,
    /// The alias address (nonzero).
    pub alias: u32,
}

#[derive(Clone, Copy, Default)]
struct AliasSlot {
    rec: AliasRecord,
    next: u16,
    referenced: bool,
    used: bool,
}

/// Cache of the append-only alias record: `N` entries (power of two, at most 1024), chained hash on the sequentially allocated alias (its low
/// bits are a perfect hash) and CLOCK replacement. A miss is answered by a background fill, never by I/O on the forwarding path.
#[derive(Clone)]
pub struct AliasCache<const N: usize> {
    slot: [AliasSlot; N],
    head: [u16; N],
    hand: usize,
}

impl<const N: usize> Default for AliasCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AliasCache<N> {
    const OK: () = assert!(N.is_power_of_two() && N <= 1024, "alias cache size must be a power of two <= 1024");
    /// Empty cache.
    pub const fn new() -> Self {
        let () = Self::OK;
        Self { slot: [AliasSlot { rec: AliasRecord { id: 0, peer: 0, alias: 0 }, next: 0, referenced: false, used: false }; N], head: [0; N], hand: 0 }
    }
    #[inline]
    fn bucket(alias: u32) -> usize {
        alias as usize & (N - 1)
    }
    fn unlink(&mut self, index: usize) {
        let b = Self::bucket(self.slot[index].rec.alias);
        let mut link = self.head[b];
        let mut prev: Option<usize> = None;
        while link != 0 && usize::from(link) - 1 != index {
            prev = Some(usize::from(link) - 1);
            link = self.slot[usize::from(link) - 1].next;
        }
        if link != 0 {
            let next = self.slot[index].next;
            match prev {
                Some(p) => self.slot[p].next = next,
                None => self.head[b] = next,
            }
        }
        self.slot[index] = AliasSlot::default();
    }
    /// Look up by alias address (the forwarding path). Marks the entry recently used.
    pub fn find(&mut self, alias: u32) -> Option<AliasRecord> {
        let mut i = self.head[Self::bucket(alias)];
        while i != 0 {
            let s = &mut self.slot[usize::from(i) - 1];
            if s.rec.alias == alias {
                s.referenced = true;
                return Some(s.rec);
            }
            i = s.next;
        }
        None
    }
    /// Look up by (membership, peer): a linear scan, control path only.
    pub fn find_key(&mut self, id: u32, peer: u32) -> Option<u32> {
        self.slot.iter_mut().find(|s| s.used && s.rec.id == id && s.rec.peer == peer).map(|s| {
            s.referenced = true;
            s.rec.alias
        })
    }
    /// Insert a record. Idempotent; an existing binding is never changed: a conflicting insert (same alias for another owner, or the same
    /// (id, peer) under another alias) returns `false`. A full cache evicts by CLOCK (second chance); two sweeps always find a victim.
    pub fn insert(&mut self, r: AliasRecord) -> bool {
        if r.alias == 0 || r.id == 0 {
            return false;
        }
        let mut i = self.head[Self::bucket(r.alias)];
        while i != 0 {
            let s = &mut self.slot[usize::from(i) - 1];
            if s.rec.alias == r.alias {
                s.referenced = true;
                return s.rec.id == r.id && s.rec.peer == r.peer;
            }
            i = s.next;
        }
        if self.slot.iter().any(|s| s.used && s.rec.id == r.id && s.rec.peer == r.peer) {
            return false;
        }
        let mut victim = self.slot.iter().position(|s| !s.used);
        let mut n = 0;
        while victim.is_none() && n < 2 * N {
            let i = self.hand % N;
            self.hand = self.hand.wrapping_add(1);
            if self.slot[i].referenced {
                self.slot[i].referenced = false;
            } else {
                victim = Some(i);
            }
            n += 1;
        }
        let victim = victim.unwrap_or_else(|| {
            let i = self.hand % N;
            self.hand = self.hand.wrapping_add(1);
            i
        });
        if self.slot[victim].used {
            self.unlink(victim);
        }
        let b = Self::bucket(r.alias);
        self.slot[victim] = AliasSlot { rec: r, next: self.head[b], referenced: false, used: true };
        self.head[b] = victim as u16 + 1;
        true
    }
    /// Drop every entry of membership `id` from the cache (the flash record stays). Returns how many.
    pub fn forget(&mut self, id: u32) -> usize {
        let mut n = 0;
        for i in 0..N {
            if self.slot[i].used && self.slot[i].rec.id == id {
                self.unlink(i);
                n += 1;
            }
        }
        n
    }
    /// Entries in use.
    pub fn len(&self) -> usize {
        self.slot.iter().filter(|s| s.used).count()
    }
    /// True when no entry is in use.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One NAT flow as a lookup returns it: the USB side (`host`, `local`) talking through `alias` to `peer` of membership `id`, seen by the peer as
/// the tailnet address of `id` with source port `mapped`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    /// Membership id.
    pub id: u32,
    /// Peer tailnet address.
    pub peer: u32,
    /// Alias the host addressed.
    pub alias: u32,
    /// The USB host's address.
    pub host: u32,
    /// The host's source port.
    pub local: u16,
    /// The peer's port.
    pub remote: u16,
    /// Source port the tunnel side sees; encodes the slot and the USB link generation.
    pub mapped: u16,
    /// IP protocol (6 or 17).
    pub proto: u8,
}

#[derive(Clone, Copy, Default)]
struct FlowSlot {
    flow: Flow,
    generation: u32,
    touched: Millis,
    next: u16,
    used: bool,
}

/// Why a tunnel reply found no flow (checked in this order, as the C's `rt_flow_in_why`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowInReject {
    /// Destination port outside the mapped range.
    Range,
    /// The slot it indexes is empty.
    NoFlow,
    /// The flow belongs to an earlier USB link generation.
    Generation,
    /// Peer, port, protocol or membership do not match the flow's owner.
    Owner,
    /// The flow was idle for 120 s or more.
    Idle,
}

/// The NAT flow table: `N` slots (power of two, at most 1024). Outbound lookups walk a short hash chain on (alias, host, ports, protocol); the
/// mapped source port encodes the slot, so a reply is a direct index plus an exact tuple comparison and ownership is enforced, never inferred.
#[derive(Clone)]
pub struct FlowTable<const N: usize> {
    slot: [FlowSlot; N],
    head: [u16; N],
}

impl<const N: usize> Default for FlowTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FlowTable<N> {
    const OK: () = assert!(N.is_power_of_two() && N <= 1024, "flow table size must be a power of two <= 1024");
    /// Number of USB link generations a mapped port can encode before the range wraps: at most 300, fewer for a larger table so that
    /// `MAPPED_BASE + N * GENERATIONS` stays below 65536.
    pub const GENERATIONS: u32 = {
        let fit = (65536 - MAPPED_BASE as u32) / N as u32;
        if fit < MAPPED_GENERATIONS_MAX { fit } else { MAPPED_GENERATIONS_MAX }
    };
    /// Empty table.
    pub const fn new() -> Self {
        let () = Self::OK;
        Self {
            slot: [FlowSlot {
                flow: Flow { id: 0, peer: 0, alias: 0, host: 0, local: 0, remote: 0, mapped: 0, proto: 0 },
                generation: 0,
                touched: 0,
                next: 0,
                used: false,
            }; N],
            head: [0; N],
        }
    }
    fn bucket(alias: u32, host: u32, local: u16, remote: u16, proto: u8) -> usize {
        let mut h = host.wrapping_mul(0x9e37_79b1);
        h ^= alias.wrapping_mul(0x85eb_ca6b);
        h ^= ((u32::from(local) << 16) | u32::from(remote)).wrapping_mul(0xc2b2_ae35);
        h ^= u32::from(proto);
        h ^= h >> 15;
        h = h.wrapping_mul(0x2c1b_3c6d);
        (h >> 20) as usize & (N - 1)
    }
    fn bucket_of(f: &Flow) -> usize {
        Self::bucket(f.alias, f.host, f.local, f.remote, f.proto)
    }
    fn unlink(&mut self, index: usize) {
        let b = Self::bucket_of(&self.slot[index].flow);
        let mut link = self.head[b];
        let mut prev: Option<usize> = None;
        while link != 0 && usize::from(link) - 1 != index {
            prev = Some(usize::from(link) - 1);
            link = self.slot[usize::from(link) - 1].next;
        }
        if link != 0 {
            let next = self.slot[index].next;
            match prev {
                Some(p) => self.slot[p].next = next,
                None => self.head[b] = next,
            }
        }
        self.slot[index] = FlowSlot::default();
    }
    fn matching(&self, alias: u32, host: u32, local: u16, remote: u16, proto: u8, generation: u32) -> Option<usize> {
        let mut i = self.head[Self::bucket(alias, host, local, remote, proto)];
        while i != 0 {
            let f = &self.slot[usize::from(i) - 1];
            if f.generation == generation
                && f.flow.alias == alias
                && f.flow.host == host
                && f.flow.local == local
                && f.flow.remote == remote
                && f.flow.proto == proto
            {
                return Some(usize::from(i) - 1);
            }
            i = f.next;
        }
        None
    }
    /// USB to tunnel lookup. Does not refresh the idle timer: only a packet that is actually forwarded keeps a flow alive ([`Self::touch`]).
    pub fn lookup_out(&self, alias: u32, host: u32, local: u16, remote: u16, proto: u8, generation: u32) -> Option<Flow> {
        self.matching(alias, host, local, remote, proto, generation).map(|i| self.slot[i].flow)
    }
    /// Refresh the idle timer of `flow` if it is still the same flow (same owner and mapped port).
    pub fn touch(&mut self, flow: &Flow, generation: u32, now: Millis) {
        if let Some(i) = self.matching(flow.alias, flow.host, flow.local, flow.remote, flow.proto, generation) {
            let s = &mut self.slot[i];
            if s.flow.id == flow.id && s.flow.mapped == flow.mapped {
                s.touched = now;
            }
        }
    }
    /// Find or create the flow for `key` (its `mapped` is ignored). A new flow takes the first slot that is free, of an earlier generation or
    /// idle for more than 120 s (the C's linear policy, so mapped ports are identical); `None` when every slot is live.
    pub fn create(&mut self, key: &Flow, generation: u32, now: Millis) -> Option<Flow> {
        if let Some(i) = self.matching(key.alias, key.host, key.local, key.remote, key.proto, generation) {
            self.slot[i].touched = now;
            return Some(self.slot[i].flow);
        }
        for i in 0..N {
            let s = &self.slot[i];
            if s.used && s.generation == generation && now.saturating_sub(s.touched) <= FLOW_IDLE_MS {
                continue;
            }
            if s.used {
                self.unlink(i);
            }
            let b = Self::bucket_of(key);
            let mut flow = *key;
            flow.mapped = MAPPED_BASE + i as u16 + (N as u32 * (generation.wrapping_sub(1) % Self::GENERATIONS)) as u16;
            self.slot[i] = FlowSlot { flow, generation, touched: now, next: self.head[b], used: true };
            self.head[b] = i as u16 + 1;
            return Some(flow);
        }
        None
    }
    /// Tunnel reply from `peer` (source port `remote`, destination port `mapped`) for membership `id`: exact tuple or a reason. Refreshes the
    /// idle timer on success.
    #[allow(clippy::too_many_arguments)] // the C's rt_flow_in signature: the tuple of a reply plus the clock
    pub fn lookup_in(&mut self, id: u32, peer: u32, remote: u16, mapped: u16, proto: u8, generation: u32, now: Millis) -> Result<Flow, FlowInReject> {
        let m = u32::from(mapped);
        if m < MAPPED_BASE as u32 || m >= MAPPED_BASE as u32 + N as u32 * Self::GENERATIONS {
            return Err(FlowInReject::Range);
        }
        let f = &mut self.slot[(m - MAPPED_BASE as u32) as usize & (N - 1)];
        if !f.used {
            Err(FlowInReject::NoFlow)
        } else if f.generation != generation {
            Err(FlowInReject::Generation)
        } else if !(f.flow.id == id && f.flow.peer == peer && f.flow.remote == remote && f.flow.mapped == mapped && f.flow.proto == proto) {
            Err(FlowInReject::Owner)
        } else if now.saturating_sub(f.touched) >= FLOW_IDLE_MS {
            Err(FlowInReject::Idle)
        } else {
            f.touched = now;
            Ok(f.flow)
        }
    }
    /// Drop every flow of membership `id`. Returns how many.
    pub fn forget(&mut self, id: u32) -> usize {
        let mut n = 0;
        for i in 0..N {
            if self.slot[i].used && self.slot[i].flow.id == id {
                self.unlink(i);
                n += 1;
            }
        }
        n
    }
    /// Slot contents for inspection: (flow, generation, last touched) or `None` for a free slot.
    pub fn slots(&self) -> impl Iterator<Item = Option<(Flow, u32, Millis)>> + '_ {
        self.slot.iter().map(|s| s.used.then_some((s.flow, s.generation, s.touched)))
    }
    /// Flows in use.
    pub fn len(&self) -> usize {
        self.slot.iter().filter(|s| s.used).count()
    }
    /// True when no flow is in use.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<const N: usize> core::fmt::Debug for AliasCache<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AliasCache").field("capacity", &N).field("len", &self.len()).finish()
    }
}

impl<const N: usize> core::fmt::Debug for FlowTable<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlowTable").field("capacity", &N).field("len", &self.len()).finish()
    }
}
