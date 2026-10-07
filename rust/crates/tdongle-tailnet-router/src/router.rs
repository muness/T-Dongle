//! The forwarding engine. See the crate documentation for the model and the concurrency contract.

use crate::csum::{self, rd16, rd32, wr16, wr32};
use crate::outcome::{Dir, HostDrop, HostOutcome, TunnelDrop, TunnelOutcome};
use crate::packet::{self, is_alias, is_usb_host};
use crate::stats::{Extra, Stat, Stats};
use crate::tables::{AliasCache, AliasRecord, Flow, FlowTable};
use crate::{ALIAS_BASE, FILL_NEGATIVE_MS, FILL_SLOTS, FILL_SPACING_MS, HOLD_BYTES, HOLD_MS, HOLD_SLOTS, ICMP_SPACING_MS, ROUTE_MTU};
use tdongle_tailnet_types::Millis;

/// A published membership as the router sees it: an immutable record in a [`MemberSet`] snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    /// Membership id (nonzero, never reused).
    pub id: u32,
    /// The membership's own tailnet address (the NAT source of everything it carries).
    pub vpn_ip: u32,
    /// Connected, enabled, key valid, no error: the C's `member_ready`. A not-ready member still receives replies to its flows but accepts no
    /// new USB traffic.
    pub ready: bool,
}

/// An immutable snapshot of the published memberships (at most `M`), built by the runtime and installed with [`Router::publish`]. This is the
/// Rust replacement for the C's `member_slot[]` + two-bucket RCU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberSet<const M: usize> {
    slot: [Option<Member>; M],
}

impl<const M: usize> Default for MemberSet<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const M: usize> MemberSet<M> {
    /// No memberships.
    pub const fn new() -> Self {
        Self { slot: [None; M] }
    }
    /// Add a membership (replacing one with the same id). `false` when all `M` slots are taken.
    pub fn insert(&mut self, m: Member) -> bool {
        if let Some(s) = self.slot.iter_mut().flatten().find(|s| s.id == m.id) {
            *s = m;
            return true;
        }
        match self.slot.iter_mut().find(|s| s.is_none()) {
            Some(s) => {
                *s = Some(m);
                true
            }
            None => false,
        }
    }
    /// Remove a membership. `true` when it was present.
    pub fn remove(&mut self, id: u32) -> bool {
        match self.slot.iter_mut().find(|s| s.is_some_and(|m| m.id == id)) {
            Some(s) => {
                *s = None;
                true
            }
            None => false,
        }
    }
    /// The membership with this id.
    pub fn by_id(&self, id: u32) -> Option<&Member> {
        self.slot.iter().flatten().find(|m| m.id == id)
    }
    /// Published memberships.
    pub fn iter(&self) -> impl Iterator<Item = &Member> {
        self.slot.iter().flatten()
    }
}

#[derive(Clone, Copy, Default)]
struct HoldMeta {
    dest: u32,
    len: u16,
    generation: u32,
    expires: Millis,
}

/// Bounded cache-miss hold: up to `HOLD_SLOTS` packets, `HOLD_BYTES` in all, in one arena, in arrival order.
#[derive(Clone)]
struct Hold {
    arena: [u8; HOLD_BYTES],
    meta: [HoldMeta; HOLD_SLOTS],
    count: usize,
    bytes: usize,
}

impl Hold {
    const fn new() -> Self {
        Self { arena: [0; HOLD_BYTES], meta: [HoldMeta { dest: 0, len: 0, generation: 0, expires: 0 }; HOLD_SLOTS], count: 0, bytes: 0 }
    }
    fn add(&mut self, pkt: &[u8], dest: u32, generation: u32, now: Millis) -> bool {
        if self.count == HOLD_SLOTS || self.bytes + pkt.len() > HOLD_BYTES {
            return false;
        }
        self.arena[self.bytes..self.bytes + pkt.len()].copy_from_slice(pkt);
        self.meta[self.count] = HoldMeta { dest, len: pkt.len() as u16, generation, expires: now + HOLD_MS };
        self.count += 1;
        self.bytes += pkt.len();
        true
    }
    fn offset(&self, i: usize) -> usize {
        self.meta[..i].iter().map(|m| usize::from(m.len)).sum()
    }
    /// Remove entry `i`, closing the gap in the arena.
    fn remove(&mut self, i: usize) {
        let start = self.offset(i);
        let len = usize::from(self.meta[i].len);
        self.arena.copy_within(start + len..self.bytes, start);
        self.meta.copy_within(i + 1..self.count, i);
        self.count -= 1;
        self.bytes -= len;
    }
}

/// The USB <-> tunnel router: alias cache (`A` entries), flow table (`F` slots), published memberships (`M`), counters, the alias-fill
/// request state and the cache-miss hold. All storage is inline; nothing allocates; nothing reads a clock (time is an argument).
///
/// A single `Router` has a single owner (`&mut self` everywhere): the runtime puts it behind one short critical section (or owns it from one task
/// and feeds it through a channel). A call never blocks and takes microseconds (the work is bounded by the packet length: one copy-free in-place
/// rewrite). See the crate docs for why that replaces the C's RCU.
#[derive(Clone)]
pub struct Router<const M: usize, const A: usize, const F: usize> {
    members: MemberSet<M>,
    aliases: AliasCache<A>,
    flows: FlowTable<F>,
    stats: Stats,
    usb_generation: u32,
    alias_limit: u32,
    fill_request: [u32; FILL_SLOTS],
    fill_negative: [u32; FILL_SLOTS],
    fill_negative_until: [Millis; FILL_SLOTS],
    last_fill: Option<Millis>,
    last_icmp: Option<Millis>,
    hold: Hold,
    bad: BadLog,
}

/// What the router remembers about packets it called invalid: a count per reason and the first bytes of the last one.
#[derive(Clone, Copy, Debug)]
pub struct BadLog {
    /// Per [`packet::Invalid`] (host direction first, then tunnel direction).
    pub host: [u32; 10],
    /// Tunnel direction.
    pub tunnel: [u32; 10],
    /// Every host-direction drop by [`HostDrop::ALL`] index.
    pub drops: [u32; 14],
    /// Source and destination of the packet the router looked at last (host direction).
    pub last_src: u32,
    /// Destination of the packet looked at last.
    pub last_dst: u32,
    /// Reason of the last bad packet (host direction), as an index into [`packet::Invalid::ALL`].
    pub last_why: u8,
    /// Bytes kept of the last bad host packet (at most 64).
    pub last_len: u8,
    /// Its total length as handed to the router.
    pub last_total: u16,
    /// Its first bytes.
    pub last: [u8; 64],
}

impl BadLog {
    const fn new() -> Self {
        Self { host: [0; 10], tunnel: [0; 10], drops: [0; 14], last_src: 0, last_dst: 0, last_why: 0, last_len: 0, last_total: 0, last: [0; 64] }
    }
}

/// The production configuration: 16 memberships, 64 cached aliases, 64 flows (the C's `ROUTE_MEMBERS`, `RT_ALIASES`, `RT_FLOWS`).
pub type GatewayRouter = Router<16, 64, 64>;

impl<const M: usize, const A: usize, const F: usize> Default for Router<M, A, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const M: usize, const A: usize, const F: usize> Router<M, A, F> {
    /// Bytes of one router (host size; the firmware's xtensa size is smaller where fields are 32-bit aligned).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// A router with no memberships, no aliases, USB generation 1 and the first 64 aliases (`ALIAS_BASE + 0..64`) considered allocated, as
    /// the C boots (`alias_limit = RT_ALIAS_BASE + 64`).
    pub const fn new() -> Self {
        Self {
            members: MemberSet::new(),
            aliases: AliasCache::new(),
            flows: FlowTable::new(),
            stats: Stats::new(),
            usb_generation: 1,
            alias_limit: ALIAS_BASE + 64,
            fill_request: [0; FILL_SLOTS],
            fill_negative: [0; FILL_SLOTS],
            fill_negative_until: [0; FILL_SLOTS],
            last_fill: None,
            last_icmp: None,
            hold: Hold::new(),
            bad: BadLog::new(),
        }
    }
    /// Aliases in the cache.
    pub fn alias_cached(&self) -> usize {
        self.aliases.len()
    }
    /// Flows in use.
    pub fn flows_used(&self) -> usize {
        self.flows.len()
    }
    /// The invalid-packet log.
    pub fn bad(&self) -> &BadLog {
        &self.bad
    }

    // ---- control plane --------------------------------------------------------------------------------------------------------------

    /// Install a new membership snapshot and return the previous one. Flows of memberships that are in the old snapshot but not in the new one
    /// are forgotten (the C's `gateway_suspend`). Because the router is `&mut`, no packet is in flight while this runs: the grace period the C
    /// needs RCU for is the borrow checker's.
    pub fn publish(&mut self, set: MemberSet<M>) -> MemberSet<M> {
        let old = self.members;
        for m in old.iter() {
            if set.by_id(m.id).is_none() {
                self.flows.forget(m.id);
            }
        }
        core::mem::replace(&mut self.members, set)
    }
    /// The currently published snapshot (copy it, edit it, [`Self::publish`] it back).
    pub fn members(&self) -> &MemberSet<M> {
        &self.members
    }
    /// Unpublish a membership and forget its flows (restart or disable). Its aliases stay cached.
    pub fn suspend(&mut self, id: u32) {
        self.members.remove(id);
        self.flows.forget(id);
    }
    /// The membership is gone for good: unpublish, forget flows and cached aliases. Its flash alias records stay allocated, never reassigned.
    pub fn forget(&mut self, id: u32) {
        self.suspend(id);
        self.aliases.forget(id);
    }
    /// The USB link went away (detach/reconfigure): every flow and queued or held packet of the old link becomes stale at once.
    pub fn usb_detach(&mut self) {
        self.usb_generation = self.usb_generation.wrapping_add(1).max(1);
    }
    /// The current USB link generation (stamp it on a packet when it is queued and pass it back to [`Self::host_packet`]).
    pub fn usb_generation(&self) -> u32 {
        self.usb_generation
    }
    /// Cache an alias record (from the directory: boot preload, DNS allocation, background fill). Idempotent; `false` for a conflicting record.
    /// Raises the allocation limit so the alias is known to exist.
    pub fn alias_insert(&mut self, rec: AliasRecord) -> bool {
        let ok = self.aliases.insert(rec);
        self.alias_limit_raise(rec.alias);
        ok
    }
    /// Declare that aliases up to and including `alias` may exist (a persistent counter advanced). Addresses beyond the limit are dropped without
    /// asking for a fill, so scanning 198.18.0.0/15 cannot cause directory reads.
    pub fn alias_limit_raise(&mut self, alias: u32) {
        if alias >= self.alias_limit {
            self.alias_limit = alias + 1;
        }
    }
    /// The first alias address that has never been allocated.
    pub fn alias_limit(&self) -> u32 {
        self.alias_limit
    }
    /// Alias of (membership, peer) if cached (control path).
    pub fn alias_find_key(&mut self, id: u32, peer: u32) -> Option<u32> {
        self.aliases.find_key(id, peer)
    }
    pub(crate) fn stats_mut(&mut self) -> &mut Stats {
        &mut self.stats
    }
    /// The counters.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
    /// Count an event the runtime owns (`QueueFull`, `TunnelNomem`, `UsbTx`, `UsbTxErr`).
    pub fn note(&mut self, s: Stat) {
        self.stats.bump(s);
    }
    /// Report the outcome of emitting a [`HostOutcome::Forwarded`] (`ToTunnel`) or a [`TunnelOutcome::ToHost`] (`ToHost`): counts
    /// `forwarded_out`/`tunnel_reject` or `forwarded_in`/`tx_fail`, as the C does at the emit.
    pub fn tx_result(&mut self, dir: Dir, ok: bool) {
        self.stats.bump(match (dir, ok) {
            (Dir::ToTunnel, true) => Stat::ForwardedOut,
            (Dir::ToTunnel, false) => Stat::TunnelReject,
            (Dir::ToHost, true) => Stat::ForwardedIn,
            (Dir::ToHost, false) => Stat::TxFail,
        });
    }
    /// The flow table (inspection, tests).
    pub fn flows(&self) -> &FlowTable<F> {
        &self.flows
    }
    /// The alias cache (inspection, tests).
    pub fn aliases(&self) -> &AliasCache<A> {
        &self.aliases
    }
    /// Bytes currently parked in the hold, to charge against the ingress queue budget ([`crate::IngressGate`]).
    pub fn held_bytes(&self) -> usize {
        self.hold.bytes
    }
    /// Packets currently parked in the hold.
    pub fn held_count(&self) -> usize {
        self.hold.count
    }

    // ---- alias fills ----------------------------------------------------------------------------------------------------------------

    /// True when an alias fill has been requested and not completed.
    pub fn fill_pending(&self) -> bool {
        self.fill_request.iter().any(|&a| a != 0)
    }
    fn fill_requested(&self, alias: u32) -> bool {
        self.fill_request.contains(&alias)
    }
    /// The runtime calls this when its route queue is empty. Returns the alias to read from the directory if a fill is due (one per 20 ms),
    /// then reports the result with [`Self::fill_done`].
    pub fn begin_fill(&mut self, now: Millis) -> Option<u32> {
        if self.last_fill.is_some_and(|t| now.saturating_sub(t) < FILL_SPACING_MS) {
            return None;
        }
        let alias = self.fill_request.iter().copied().find(|&a| a != 0)?;
        self.last_fill = Some(now);
        Some(alias)
    }
    /// Complete a fill started by [`Self::begin_fill`]: `Some(record)` caches it, `None` remembers the alias as absent for 10 s.
    pub fn fill_done(&mut self, alias: u32, record: Option<AliasRecord>, now: Millis) {
        let Some(i) = self.fill_request.iter().position(|&a| a == alias) else { return };
        match record {
            Some(r) => {
                self.aliases.insert(r);
                self.stats.bump(Stat::AliasFill);
            }
            None => {
                self.fill_negative[i] = alias;
                self.fill_negative_until[i] = now + FILL_NEGATIVE_MS;
            }
        }
        self.fill_request[i] = 0;
    }
    /// When the runtime should next wake for the router with nothing else to do: the earliest of the hold expiry and the next due fill.
    pub fn next_deadline(&self, now: Millis) -> Option<Millis> {
        let mut t: Option<Millis> = None;
        let mut take = |v: Millis| t = Some(t.map_or(v, |x| x.min(v)));
        if self.hold.count > 0 {
            take(self.hold.meta[0].expires);
        }
        if self.fill_pending() {
            take(self.last_fill.map_or(now, |l| l + FILL_SPACING_MS));
        }
        t
    }
    /// True when the alias is not cached but a fill is pending (the packet may wait for it).
    fn alias_miss(&mut self, alias: u32, now: Millis) -> bool {
        self.stats.bump(Stat::AliasMiss);
        if alias < ALIAS_BASE || alias >= self.alias_limit {
            self.stats.bump(Stat::AliasUnknown);
            return false;
        }
        for i in 0..FILL_SLOTS {
            if self.fill_request[i] == alias {
                return true;
            }
            if self.fill_negative[i] == alias && now < self.fill_negative_until[i] {
                return false;
            }
        }
        if let Some(s) = self.fill_request.iter_mut().find(|a| **a == 0) {
            *s = alias;
            return true;
        }
        false
    }

    // ---- USB -> tunnel --------------------------------------------------------------------------------------------------------------

    /// Route one packet that came from the USB host. `pkt` is the whole IPv4 packet and is rewritten in place; `queued_generation` is the
    /// value of [`Self::usb_generation`] when it was queued. Packets the hook should have left to the IP stack come back as
    /// [`HostOutcome::PassThrough`]. See [`Router::ingress`] for the ingress-hook side.
    pub fn host_packet(&mut self, pkt: &mut [u8], now: Millis, queued_generation: u32) -> HostOutcome {
        if queued_generation != self.usb_generation {
            return self.drop_host(HostDrop::StaleGeneration);
        }
        if pkt.len() < 20 {
            return HostOutcome::PassThrough;
        }
        let dest = rd32(pkt, 16);
        if !is_alias(dest) {
            return HostOutcome::PassThrough;
        }
        if pkt.len() > ROUTE_MTU {
            return self.oversize(pkt, dest, now);
        }
        self.route_outbound(pkt, dest, now, true)
    }

    /// Record a drop whose counters the caller already moved.
    fn note_drop(&mut self, d: HostDrop) -> HostOutcome {
        self.bad.drops[HostDrop::ALL.iter().position(|x| *x == d).unwrap_or(0)] += 1;
        HostOutcome::Dropped(d)
    }

    fn drop_host(&mut self, d: HostDrop) -> HostOutcome {
        self.bad.drops[HostDrop::ALL.iter().position(|x| *x == d).unwrap_or(0)] += 1;
        for &s in d.counters() {
            self.stats.bump(s);
        }
        if let Some(x) = d.extra() {
            self.stats.bump_extra(x);
        }
        HostOutcome::Dropped(d)
    }

    fn route_outbound(&mut self, b: &mut [u8], dest: u32, now: Millis, may_hold: bool) -> HostOutcome {
        if b.len() >= 20 {
            self.bad.last_src = rd32(b, 12);
            self.bad.last_dst = dest;
        }
        let h = match packet::check(b) {
            Ok(h) => h,
            Err(why) => {
                self.bad.host[why as usize] = self.bad.host[why as usize].saturating_add(1);
                let n = b.len().min(64);
                self.bad.last[..n].copy_from_slice(&b[..n]);
                self.bad.last_len = n as u8;
                self.bad.last_total = b.len().min(u16::MAX as usize) as u16;
                self.bad.last_why = why as u8;
                return self.drop_host(HostDrop::Invalid);
            }
        };
        if !packet::clamp_mss(b, h) {
            return self.drop_host(HostDrop::BadTcpOptions);
        }
        if b[8] < 2 {
            return self.drop_host(HostDrop::TtlExpired);
        }
        let host = rd32(b, 12);
        if !is_usb_host(host) {
            return self.drop_host(HostDrop::BadSource);
        }
        let generation = self.usb_generation;
        let local = rd16(b, h);
        let remote = rd16(b, h + 2);
        let proto = b[9];
        let found = self.flows.lookup_out(dest, host, local, remote, proto, generation);
        let (id, peer) = match found {
            Some(f) => (f.id, f.peer),
            None => match self.aliases.find(dest) {
                Some(a) => (a.id, a.peer),
                None => {
                    let waiting = self.alias_miss(dest, now);
                    if !waiting {
                        // alias_miss already counted AliasMiss (and AliasUnknown); record the drop reason without double counting.
                        let unknown = dest < ALIAS_BASE || dest >= self.alias_limit;
                        return self.note_drop(if unknown { HostDrop::AliasUnknown } else { HostDrop::AliasMiss });
                    }
                    if may_hold {
                        if self.hold.add(b, dest, generation, now) {
                            self.stats.bump(Stat::Held);
                            return HostOutcome::Held;
                        }
                        self.stats.bump_extra(Extra::HoldFull);
                        return self.note_drop(HostDrop::HoldFull);
                    }
                    return self.note_drop(HostDrop::AliasMiss);
                }
            },
        };
        let Some(m) = self.members.by_id(id).copied() else { return self.drop_host(HostDrop::NoMember) };
        if !m.ready {
            return self.drop_host(HostDrop::MemberDown);
        }
        let flow = match found {
            Some(f) => {
                self.flows.touch(&f, generation, now);
                f
            }
            None => {
                let key = Flow { id, peer, alias: dest, host, local, remote, mapped: 0, proto };
                match self.flows.create(&key, generation, now) {
                    Some(f) => f,
                    None => return self.drop_host(HostDrop::FlowFull),
                }
            }
        };
        packet::nat_rewrite(b, h, m.vpn_ip, peer, 0, flow.mapped);
        packet::ttl_decrement(b);
        HostOutcome::Forwarded { member: id, peer, len: b.len() }
    }

    /// Release held packets whose alias has arrived, one per call (call until `None`). `out` receives the packet (it must hold
    /// [`ROUTE_MTU`] bytes); the returned outcome describes `out`. Packets that expired, whose fill found no record, or that outlived their USB
    /// link are dropped and counted (`held_dropped`) as the scan passes them.
    pub fn hold_service(&mut self, now: Millis, out: &mut [u8]) -> Option<HostOutcome> {
        let mut i = 0;
        while i < self.hold.count {
            let m = self.hold.meta[i];
            if m.generation != self.usb_generation || now >= m.expires || usize::from(m.len) > out.len() {
                self.stats.bump(Stat::HeldDropped);
                self.hold.remove(i);
            } else if self.aliases.find(m.dest).is_some() {
                let start = self.hold.offset(i);
                let len = usize::from(m.len);
                out[..len].copy_from_slice(&self.hold.arena[start..start + len]);
                self.hold.remove(i);
                self.stats.bump(Stat::HeldReleased);
                // a second miss drops: no second wait
                return Some(self.route_outbound(&mut out[..len], m.dest, now, false));
            } else if !self.fill_requested(m.dest) {
                self.stats.bump(Stat::HeldDropped);
                self.hold.remove(i);
            } else {
                i += 1;
            }
        }
        None
    }
    /// Drop everything held (USB link torn down).
    pub fn hold_flush(&mut self) {
        while self.hold.count > 0 {
            self.stats.bump(Stat::HeldDropped);
            self.hold.remove(0);
        }
    }

    /// The tunnel cannot carry more than [`ROUTE_MTU`] and the router never fragments. A DF packet gets the standard ICMP "fragmentation
    /// needed" (RFC 1191) with the next-hop MTU so path-MTU discovery works; one without DF is dropped (the host could only fragment it and
    /// fragments are rejected). Replies are rate limited (one per 50 ms) and only go to a validated USB host.
    fn oversize(&mut self, p: &mut [u8], dest: u32, now: Millis) -> HostOutcome {
        let n = p.len();
        let h = usize::from(p[0] & 15) * 4;
        // n > ROUTE_MTU >= 68 here
        let host = rd32(p, 12);
        if p[0] >> 4 != 4
            || !(20..=60).contains(&h)
            || usize::from(rd16(p, 2)) != n
            || rd16(p, 6) & 0x3fff != 0
            || (p[9] != packet::TCP && p[9] != packet::UDP)
            || !csum::header_ok(p, h)
            || !is_usb_host(host)
        {
            return self.drop_host(HostDrop::OversizeInvalid);
        }
        if rd16(p, 6) & 0x4000 == 0 {
            return self.drop_host(HostDrop::OversizeNoDf);
        }
        if self.last_icmp.is_some_and(|t| now.saturating_sub(t) < ICMP_SPACING_MS) {
            return self.drop_host(HostDrop::IcmpSuppressed);
        }
        self.last_icmp = Some(now);
        let len = build_frag_needed(p, h, dest, host);
        self.stats.bump(Stat::OversizeIcmp);
        HostOutcome::Reply { host, len }
    }

    // ---- tunnel -> USB --------------------------------------------------------------------------------------------------------------

    /// Route one packet decrypted from the WireGuard device of membership `from`. WireGuard already authenticated the sender and checked its
    /// AllowedIPs; this accepts only exact replies to a USB-origin flow of the same membership. `pkt` may carry encryption padding past the IPv4
    /// total length (it is discarded; USB-side packets get no such tolerance).
    pub fn tunnel_packet(&mut self, from: u32, pkt: &mut [u8], now: Millis) -> TunnelOutcome {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 || usize::from(rd16(pkt, 2)) > pkt.len() || rd16(pkt, 2) < 20 {
            return self.drop_tunnel(TunnelDrop::Malformed);
        }
        let n = usize::from(rd16(pkt, 2));
        let b = &mut pkt[..n];
        let h = match packet::check(b) {
            Ok(h) => h,
            Err(why) => {
                self.bad.tunnel[why as usize] = self.bad.tunnel[why as usize].saturating_add(1);
                return self.drop_tunnel(TunnelDrop::Invalid);
            }
        };
        if !packet::clamp_mss(b, h) {
            return self.drop_tunnel(TunnelDrop::Invalid);
        }
        let Some(m) = self.members.by_id(from).copied() else { return self.drop_tunnel(TunnelDrop::NoMember) };
        if m.vpn_ip != rd32(b, 16) {
            return self.drop_tunnel(TunnelDrop::NotUs);
        }
        let generation = self.usb_generation;
        match self.flows.lookup_in(m.id, rd32(b, 12), rd16(b, h), rd16(b, h + 2), b[9], generation, now) {
            Err(why) => self.drop_tunnel(TunnelDrop::Flow(why)),
            Ok(f) => {
                packet::nat_rewrite(b, h, f.alias, f.host, 2, f.local);
                TunnelOutcome::ToHost { host: f.host, len: n }
            }
        }
    }

    /// A batch of packets one WireGuard wake decrypted, handled in arrival order (which keeps one peer's packets in order). Equivalent to
    /// calling [`Self::tunnel_packet`] for each; `out[i]` receives the outcome of `pkts[i]`. At most `min(pkts.len(), out.len())` are handled.
    pub fn tunnel_batch(&mut self, from: u32, pkts: &mut [&mut [u8]], now: Millis, out: &mut [TunnelOutcome]) -> usize {
        let k = pkts.len().min(out.len());
        for i in 0..k {
            out[i] = self.tunnel_packet(from, pkts[i], now);
        }
        k
    }

    fn drop_tunnel(&mut self, d: TunnelDrop) -> TunnelOutcome {
        for &s in d.counters() {
            self.stats.bump(s);
        }
        TunnelOutcome::Dropped(d)
    }
}

/// Build the ICMP "fragmentation needed" for the oversized packet at `p` (IPv4 header length `h`) into `p[..len]`, from the alias `dest` to the
/// USB `host`: IPv4 header (DF, TTL 64, protocol 1, ID 0), type 3 code 4, next-hop MTU [`ROUTE_MTU`], quoting the original header plus 8 bytes.
/// Returns the reply length (`28 + h + 8`, at most 96). `p` must hold at least `h + 8` bytes of the original, and is overwritten.
fn build_frag_needed(p: &mut [u8], h: usize, dest: u32, host: u32) -> usize {
    let quote = h + 8;
    let total = 20 + 8 + quote;
    let mut q = [0u8; 68];
    q[..quote].copy_from_slice(&p[..quote]);
    let r = &mut p[..total];
    r.fill(0);
    r[0] = 0x45;
    wr16(r, 2, total as u16);
    wr16(r, 6, 0x4000);
    r[8] = 64;
    r[9] = 1;
    wr32(r, 12, dest);
    wr32(r, 16, host);
    let c = csum::finish(csum::sum(&r[..20], 0));
    wr16(r, 10, c);
    r[20] = 3;
    r[21] = 4;
    wr16(r, 26, ROUTE_MTU as u16);
    r[28..28 + quote].copy_from_slice(&q[..quote]);
    let c = csum::finish(csum::sum(&r[20..], 0));
    wr16(r, 22, c);
    total
}

impl<const M: usize, const A: usize, const F: usize> core::fmt::Debug for Router<M, A, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Router")
            .field("members", &self.members.iter().count())
            .field("aliases", &self.aliases.len())
            .field("flows", &self.flows.len())
            .field("held", &self.hold.count)
            .field("usb_generation", &self.usb_generation)
            .finish()
    }
}
