//! The engine: state, the `handle` entry point, the membership life cycle, the netmap, DNS and the one wake deadline.

use crate::alias::AliasBook;
use crate::dir::PeerDirectory;
use crate::io::{DerpNote, Input, MemberConfig, MemberId, NetmapEvent, Out, Output};
use crate::member::{Member, NETCHECK_REGIONS, Phase};
use crate::rx::From;
use crate::shared::{ActHost, Cx, Shared, residents_of_others};
use crate::stats::{HostFate, IdentityError, ParkEnd, RxFate, Stats, TxFate};
use tdongle_tailnet_admission::probe::HeapSnapshot;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::netcheck::NetcheckPoll;
use tdongle_tailnet_disco::stun_sched::Servers;
use tdongle_tailnet_dns::{Action as DnsAction, Client, Directory, MemberView, PeerView};
use tdongle_tailnet_peers::arbiter::Resident;
use tdongle_tailnet_peers::pool::OwnerId;
use tdongle_tailnet_peers::record::DirRecord;
use tdongle_tailnet_peers::trial::ACTIVATE_IDLE_MS;
use tdongle_tailnet_router::{AliasRecord, Dir, HostOutcome, Member as RMember, MemberSet, ROUTE_MTU};
use tdongle_tailnet_types::{Entropy, Millis};

/// What `handle` did with its input, for the caller that needs more than the outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handled {
    /// A host packet and its fate (`PassThrough`: the caller owns the packet again and gives it to the Internet NAT).
    Host(HostFate),
    /// A datagram and its fate.
    Rx(RxFate),
    /// A netmap event the engine refused (staging full, unknown membership): the map fails.
    Refused,
    /// Anything else.
    Done,
}

/// Why a directory peer could not be made resident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActFail {
    /// Activation rejected (the table is full of recent peers, the pool refused to evict, or the session is not valid yet).
    Rejected,
    /// The WireGuard slot could not be had.
    NoSlot,
}

/// The gateway engine. See the crate documentation.
///
/// Const generics: `M` memberships, `P` resident peers per membership, `K` pool slots, `A` alias-cache entries of the router, `F` flow-table slots,
/// `JB` parked-packet arena blocks of 256 bytes. The firmware's configuration is [`GatewayEngine`].
pub struct Engine<D, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> {
    pub(crate) members: [Option<Member<P>>; M],
    pub(crate) sh: Shared<D, M, K, A, F, JB>,
}

impl<D, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> core::fmt::Debug for Engine<D, M, P, K, A, F, JB> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Engine({} members, pool {}/{})", self.members.iter().flatten().count(), self.sh.pool.used(), K)
    }
}

/// The firmware's configuration: three memberships, eight resident peers each, a twelve-slot WireGuard pool, 64 aliases, 64 flows, 24 arena blocks.
pub type GatewayEngine<D> = Engine<D, 3, 8, 12, 64, 64, 24>;

impl<D: PeerDirectory, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> Engine<D, M, P, K, A, F, JB> {
    /// Bytes of the engine (host size) without its directory; see also [`Self::per_member_bytes`].
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>() - core::mem::size_of::<D>();

    /// A new engine over `dir`.
    pub fn new(dir: D) -> Self {
        Self { members: core::array::from_fn(|_| None), sh: Shared::new(dir) }
    }

    /// The heap the runtime measured (call it whenever it changes, or before each `handle`): the elastic sites refuse below the floor (ADR 0022).
    pub fn set_heap(&mut self, h: HeapSnapshot) {
        self.sh.heap = h;
    }
    /// The byte budget of datagrams waiting for the engine (`ml_wg_rx_budget.h`, ADR 0020): ONE counter across all memberships. The runtime's
    /// receive queue calls [`Engine::rx_enqueue`] when it copies a datagram out of the driver and [`Engine::rx_dequeue`] when it has handled it.
    pub fn rx_budget(&self) -> &tdongle_tailnet_admission::wg_rx::Budget {
        &self.sh.rx_budget
    }
    /// Admit a datagram of `len` bytes into the runtime's receive queue: refused (`Heap`, counted at the `WgCopy` site; `Bytes`, the queue is full)
    /// or accepted (`Ok`: the caller must call [`Engine::rx_dequeue`] with the same length when done).
    pub fn rx_enqueue(&self, len: usize) -> tdongle_tailnet_admission::wg_rx::Verdict {
        use tdongle_tailnet_admission::wg_rx::Verdict;
        let v = self.sh.rx_budget.admit(len, self.sh.heap.free);
        if v == Verdict::Heap {
            self.sh.hb.refuse(tdongle_tailnet_admission::heap::HbSite::WgCopy);
        }
        v
    }
    /// A queued datagram of `len` bytes left the receive queue.
    pub fn rx_dequeue(&self, len: usize) {
        self.sh.rx_budget.release(len);
    }
    /// The counters.
    pub fn stats(&self) -> &Stats {
        &self.sh.stats
    }
    /// The router (counters, flows, aliases).
    pub fn router(&self) -> &tdongle_tailnet_router::Router<M, A, F> {
        &self.sh.router
    }
    /// The WireGuard pool.
    pub fn pool(&self) -> &tdongle_tailnet_peers::pool::Pool<crate::slot::WgSlot, K> {
        &self.sh.pool
    }
    /// The elastic-site refusals (`HbSite`).
    pub fn heap_refusals(&self) -> &tdongle_tailnet_admission::heap::HbRefused {
        &self.sh.hb
    }
    /// The pool arbiter's counters.
    pub fn arbiter_stats(&self) -> tdongle_tailnet_peers::arbiter::ArbiterStats {
        self.sh.arbiter.stats()
    }
    /// The directory.
    pub fn dir(&self) -> &D {
        &self.sh.dir
    }
    /// The directory, mutably (tests and boot-time loading).
    pub fn dir_mut(&mut self) -> &mut D {
        &mut self.sh.dir
    }
    /// The alias book.
    pub fn aliases(&self) -> &AliasBook {
        &self.sh.book
    }
    /// The parked-packet arena.
    pub fn jit_store(&self) -> &crate::jit::JitStore<JB> {
        &self.sh.store
    }
    /// Membership by id.
    pub fn member(&self, id: MemberId) -> Option<&Member<P>> {
        self.members.iter().flatten().find(|m| m.rt.id == id)
    }
    /// The ids of the memberships.
    pub fn members_ids(&self) -> impl Iterator<Item = MemberId> + '_ {
        self.members.iter().flatten().map(|m| m.rt.id)
    }
    /// Number of memberships.
    pub fn member_count(&self) -> usize {
        self.members.iter().flatten().count()
    }
    /// Bytes of state per membership on top of the shared parts, split as the ADR wants it. See [`crate::status::MemberBytes`].
    pub const fn per_member_bytes() -> crate::status::MemberBytes {
        crate::status::MemberBytes::of::<P>()
    }

    fn slot_by_id(&self, id: MemberId) -> Option<usize> {
        self.members.iter().position(|m| m.as_ref().is_some_and(|m| m.rt.id == id))
    }

    /// Feed one input. `now` is the monotonic clock in milliseconds. The last output of every call is [`Out::Wake`].
    pub fn handle(&mut self, now: Millis, input: Input<'_>, rng: &mut dyn Entropy, out: &mut dyn Output) -> Handled {
        let mut cx = Cx { now, rng, out };
        let h = match input {
            Input::HostPacket { buf, len } => Handled::Host(self.on_host_packet(&mut cx, buf, len)),
            Input::Udp { member, src, data } => Handled::Rx(self.on_rx(&mut cx, member, From::Udp(src), data, false)),
            Input::DerpPacket { member, src, data } => Handled::Rx(self.on_rx(&mut cx, member, From::Derp(src), data, true)),
            Input::DerpLinkEvent { member, event } => {
                self.on_derp_event(&mut cx, member, event);
                Handled::Done
            }
            Input::Netmap { member, event } => {
                if self.on_netmap(&mut cx, member, event) {
                    Handled::Done
                } else {
                    self.sh.stats.netmap_refused.bump();
                    Handled::Refused
                }
            }
            Input::Dns { client, data } => {
                self.on_dns(&mut cx, client, data);
                Handled::Done
            }
            Input::DnsUpstreamReply { data } => {
                if let Some(r) = self.sh.responder.handle_upstream(data) {
                    cx.out.emit(Out::DnsAnswer { client: r.client, data: &data[..r.len] });
                }
                Handled::Done
            }
            Input::DnsUpstream(a) => {
                self.sh.dns_upstream = a;
                Handled::Done
            }
            Input::MemberAdded(cfg) => {
                self.on_member_added(&mut cx, cfg);
                Handled::Done
            }
            Input::MemberEnabled { member } => {
                self.on_member_enabled(&mut cx, member);
                Handled::Done
            }
            Input::MemberDisabled { member } => {
                self.on_member_disabled(&mut cx, member);
                Handled::Done
            }
            Input::MemberRemoved { member } => {
                self.on_member_removed(&mut cx, member);
                Handled::Done
            }
            Input::EndpointsChanged { member, endpoints } => {
                self.on_endpoints(&mut cx, member, endpoints);
                Handled::Done
            }
            Input::ClockValid(v) => {
                self.sh.clock_valid = v;
                Handled::Done
            }
            Input::UsbDetach => {
                self.sh.router.usb_detach();
                self.sh.router.hold_flush();
                Handled::Done
            }
            Input::Tick => {
                self.on_tick(&mut cx);
                Handled::Done
            }
        };
        let w = self.next_deadline(now);
        self.sh.last_wake = w;
        cx.out.emit(Out::Wake(w));
        h
    }

    // ---- host packets --------------------------------------------------------------------------------------------------------------------------

    fn on_host_packet(&mut self, cx: &mut Cx<'_>, buf: &mut [u8], len: usize) -> HostFate {
        self.sh.stats.host_in.bump();
        let len = len.min(buf.len());
        let generation = self.sh.router.usb_generation();
        let outcome = self.sh.router.host_packet(&mut buf[..len], cx.now, generation);
        let fate = match outcome {
            HostOutcome::PassThrough => HostFate::PassThrough,
            HostOutcome::Reply { len, .. } => {
                let ok = cx.out.emit(Out::HostPacket { data: &buf[..len] });
                self.sh.router.tx_result(Dir::ToHost, ok);
                HostFate::Reply
            }
            HostOutcome::Held => {
                self.service_router(cx);
                HostFate::Held
            }
            HostOutcome::Dropped(_) => HostFate::RouterDrop,
            HostOutcome::Forwarded { member, peer, len } => {
                self.sh.tx[16..16 + len].copy_from_slice(&buf[..len]);
                let f = self.tunnel_entry(cx, member, peer, len);
                self.sh.stats.tx(f);
                HostFate::Forwarded
            }
        };
        self.sh.stats.host(fate);
        fate
    }

    /// A packet the router forwarded (plaintext at `tx[16..16+len]`) enters the tunnel path.
    fn tunnel_entry(&mut self, cx: &mut Cx<'_>, member: MemberId, peer_ip: u32, len: usize) -> TxFate {
        let Some(slot) = self.slot_by_id(member) else {
            self.sh.router.tx_result(Dir::ToTunnel, false);
            return TxFate::NoMember;
        };
        let idx = match self.members[slot].as_ref().and_then(|m| m.mship.table.by_ip(peer_ip)) {
            Some(i) => i,
            None => {
                let Some(rec) = self.sh.dir.find_by_ip(slot, peer_ip) else {
                    self.sh.router.tx_result(Dir::ToTunnel, false);
                    return TxFate::NoPeer;
                };
                match self.activate_record(cx, slot, &rec, ACTIVATE_IDLE_MS) {
                    Ok(i) => i,
                    Err(e) => {
                        self.sh.router.tx_result(Dir::ToTunnel, false);
                        return if e == ActFail::Rejected { TxFate::Rejected } else { TxFate::NoSlot };
                    }
                }
            }
        };
        let Some(m) = self.members[slot].as_mut() else { return TxFate::NoMember };
        let fate = self.sh.send_to_peer(m, idx, len, cx);
        self.sh.router.tx_result(Dir::ToTunnel, matches!(fate, TxFate::SentDirect | TxFate::SentDerp | TxFate::Parked));
        fate
    }

    /// Make a directory record resident (`directory_activate`): the activation rules, the arbiter, the WireGuard slot, the DISCO path.
    pub(crate) fn activate_record(&mut self, cx: &mut Cx<'_>, slot: usize, rec: &DirRecord, idle_ms: Millis) -> Result<usize, ActFail> {
        let now = cx.now;
        let mut others = [Resident { member: 0, peer: 0, cand: Default::default() }; 32];
        let n = residents_of_others(&self.members, slot, &mut others);
        let m = self.members[slot].as_mut().ok_or(ActFail::Rejected)?;
        let crate::member::Member { mship, rt } = m;
        let mut host = ActHost {
            dir: &mut self.sh.dir,
            dslot: slot,
            pool: &mut self.sh.pool,
            arbiter: &mut self.sh.arbiter,
            others: &others[..n],
            requester: slot as u8,
            now,
            rt,
            store: &mut self.sh.store,
            stats: &mut self.sh.stats,
            pending: &mut self.sh.pending_evict,
            plausible: false,
        };
        let idx = mship.activate_idle(&mut host, now, rec, idle_ms);
        match idx {
            None => {
                self.sh.pending_evict = None;
                Err(ActFail::Rejected)
            }
            Some(i) => self.finish_activation(cx, slot, i, rec).map_err(|()| ActFail::NoSlot),
        }
    }

    /// Alias fills and held packets (`ml_gateway_service_route`): answer the router's fill requests from the alias book, then send what the router
    /// releases from its hold.
    pub(crate) fn service_router(&mut self, cx: &mut Cx<'_>) {
        while let Some(alias) = self.sh.router.begin_fill(cx.now) {
            let rec = self.sh.book.owner(alias).map(|(id, peer)| AliasRecord { id, peer, alias });
            if rec.is_some() {
                self.sh.stats.alias_fills.bump();
            }
            self.sh.router.fill_done(alias, rec, cx.now);
        }
        loop {
            // the released packet is built straight into the transmit scratch, where the seal wants the plaintext
            let outcome = {
                let tx = &mut self.sh.tx;
                self.sh.router.hold_service(cx.now, &mut tx[16..16 + ROUTE_MTU])
            };
            match outcome {
                None => break,
                Some(HostOutcome::Forwarded { member, peer, len }) => {
                    self.sh.stats.held_released.bump();
                    let f = self.tunnel_entry(cx, member, peer, len);
                    self.sh.stats.tx(f);
                }
                Some(HostOutcome::Reply { len, .. }) => {
                    self.sh.stats.held_release_dropped.bump();
                    let _ = len;
                }
                Some(_) => self.sh.stats.held_release_dropped.bump(),
            }
        }
    }

    // ---- datagrams -----------------------------------------------------------------------------------------------------------------------------

    fn on_rx(&mut self, cx: &mut Cx<'_>, member: MemberId, from: From<'_>, data: &mut [u8], derp: bool) -> RxFate {
        self.sh.stats.rx_in.bump();
        if derp {
            self.sh.stats.rx_in_derp.bump();
        }
        let fate = match self.slot_by_id(member) {
            None => {
                self.sh.stats.no_member_inputs.bump();
                RxFate::NoMember
            }
            Some(slot) => {
                if self.members[slot].as_ref().is_some_and(|m| m.rt.phase != Phase::Running) {
                    RxFate::MemberDown
                } else {
                    self.rx_datagram(cx, slot, from, data)
                }
            }
        };
        self.sh.stats.rx(fate);
        fate
    }

    // ---- DERP ----------------------------------------------------------------------------------------------------------------------------------

    fn on_derp_event(&mut self, cx: &mut Cx<'_>, member: MemberId, ev: DerpNote) {
        let Some(slot) = self.slot_by_id(member) else {
            self.sh.stats.no_member_inputs.bump();
            return;
        };
        let Some(m) = self.members[slot].as_mut() else { return };
        match ev {
            DerpNote::Connected => {
                m.rt.derp_ready = true;
                if m.rt.phase == Phase::Running {
                    self.sh.probe_all(m, cx);
                    for idx in 0..P {
                        if m.mship.table.get(idx).is_some() {
                            self.sh.flush_peer(m, idx, cx);
                            self.sh.service_peer(m, idx, cx);
                        }
                    }
                }
            }
            DerpNote::Disconnected | DerpNote::ConnectFailed => m.rt.derp_ready = false,
        }
    }

    // ---- DNS -----------------------------------------------------------------------------------------------------------------------------------

    fn on_dns(&mut self, cx: &mut Cx<'_>, client: Client, q: &[u8]) {
        self.sh.stats.dns_in.bump();
        let before = self.sh.book.len();
        let action = {
            let view = DnsView { members: &self.members, dir: &self.sh.dir, book: &self.sh.book };
            self.sh.responder.handle_query(q, client, cx.now, &view, self.sh.dns_upstream, &mut self.sh.dns)
        };
        // aliases the lookup allocated reach the router's cache at once, so the first packet to them is not held
        for i in before..self.sh.book.len() {
            if let Some((id, peer, alias)) = self.sh.book.entry(i) {
                self.sh.router.alias_insert(AliasRecord { id, peer, alias });
            }
        }
        match action {
            DnsAction::Answer { len } => {
                cx.out.emit(Out::DnsAnswer { client, data: &self.sh.dns[..len] });
            }
            DnsAction::Forward { upstream, len, reset_socket, .. } => {
                self.sh.stats.dns_forwarded.bump();
                self.sh.dns_deadline = Some(cx.now + tdongle_tailnet_dns::UPSTREAM_TIMEOUT_MS);
                cx.out.emit(Out::DnsForward { upstream, data: &self.sh.dns[..len], reset_socket });
            }
            DnsAction::Drop(_) => {}
        }
    }

    // ---- membership life cycle -----------------------------------------------------------------------------------------------------------------

    fn publish_router(&mut self) {
        let mut set = MemberSet::<M>::new();
        for m in self.members.iter().flatten() {
            if m.rt.phase == Phase::Running {
                set.insert(RMember { id: m.rt.id, vpn_ip: m.rt.self_ip, ready: m.rt.ready });
            }
        }
        self.sh.router.publish(set);
    }

    fn recompute_ready(&mut self, cx: &mut Cx<'_>, slot: usize) {
        let Some(m) = self.members[slot].as_mut() else { return };
        let ready = m.rt.phase == Phase::Running && m.rt.self_ip != 0 && !m.rt.key_expired && m.mship.session_valid;
        if ready != m.rt.ready {
            m.rt.ready = ready;
            let id = m.rt.id;
            self.publish_router();
            cx.out.emit(Out::MemberReady { member: id, ready });
        }
    }

    fn on_member_added(&mut self, cx: &mut Cx<'_>, cfg: &MemberConfig) {
        if cfg.id == 0 || self.slot_by_id(cfg.id).is_some() {
            return;
        }
        let Some(slot) = self.members.iter().position(Option::is_none) else { return };
        let Some(m) = Member::new(cfg, slot as u8) else {
            self.sh.stats.netmap_refused.bump();
            return;
        };
        self.sh.dir.clear(slot);
        self.members[slot] = Some(m);
        self.sh.stats.members_added.bump();
        if cfg.enabled {
            self.on_member_enabled(cx, cfg.id);
        }
    }

    fn on_member_enabled(&mut self, cx: &mut Cx<'_>, id: MemberId) {
        let Some(slot) = self.slot_by_id(id) else {
            self.sh.stats.no_member_inputs.bump();
            return;
        };
        let Some(m) = self.members[slot].as_mut() else { return };
        if m.rt.phase == Phase::Running {
            return;
        }
        m.rt.phase = Phase::Running;
        // the relay link reports when it is ready (it may not have been asked to connect yet)
        m.rt.derp_ready = false;
        m.rt.next_disco_tick = cx.now + 1000;
        self.publish_router();
        self.recompute_ready(cx, slot);
        self.start_network(cx, slot);
    }

    /// Ask for the relay, start STUN and netcheck, once the map has something to say about them.
    fn start_network(&mut self, cx: &mut Cx<'_>, slot: usize) {
        let Some(m) = self.members[slot].as_mut() else { return };
        if m.rt.phase != Phase::Running || m.rt.derp_map.count == 0 {
            return;
        }
        let id = m.rt.id;
        let regions = m.rt.derp_map.region_list();
        let home = regions.iter().find(|r| r.region_id == m.rt.home_derp).or(regions.first());
        if let Some(r) = home
            && let Some(n) = r.node_list().first()
        {
            m.rt.home_derp = r.region_id;
            cx.out.emit(Out::DerpConnect {
                member: id,
                region: r.region_id,
                host: n.hostname.as_str(),
                port: if n.derp_port != 0 { n.derp_port } else { 443 },
            });
        }
        // STUN servers: the home region's node first, another region's as the NAT-check peer
        let stun_of = |r: &tdongle_tailnet_map::types::DerpRegion| {
            r.node_list().iter().find_map(|n| n.ipv4.map(|ip| Ep::v4(ip, if n.stun_port != 0 { n.stun_port } else { 3478 })))
        };
        let primary4 = regions.iter().find(|r| r.region_id == m.rt.home_derp).and_then(stun_of);
        let fallback4 = regions.iter().filter(|r| r.region_id != m.rt.home_derp).find_map(stun_of);
        m.rt.stun.set_servers(Servers { primary4, fallback4, primary6: None });
        if !m.rt.stun_started && (primary4.is_some() || fallback4.is_some()) {
            m.rt.stun_started = true;
            let stats = &mut self.sh.stats;
            let mut sends = [None; 3];
            let mut n = 0;
            m.rt.stun.begin(cx.now, cx.rng, &mut |s| {
                if n < 3 {
                    sends[n] = Some(s);
                    n += 1;
                }
            });
            for s in sends.iter().flatten() {
                Shared::<D, M, K, A, F, JB>::emit_stun(stats, cx, id, s);
            }
            m.rt.stun_next = cx.now + 1;
        }
        // netcheck: one probe per region with a STUN-capable node
        m.rt.netcheck.clear();
        for r in regions.iter().take(NETCHECK_REGIONS) {
            if let Some(ep) = stun_of(r) {
                m.rt.netcheck.add_region(r.region_id, ep);
            }
        }
        m.rt.netcheck.start(cx.now);
        m.rt.netcheck_wanted = true;
        m.rt.netcheck_next = cx.now;
    }

    fn on_member_disabled(&mut self, cx: &mut Cx<'_>, id: MemberId) {
        let Some(slot) = self.slot_by_id(id) else {
            self.sh.stats.no_member_inputs.bump();
            return;
        };
        self.stop_member(cx, slot);
        if let Some(m) = self.members[slot].as_mut() {
            m.rt.phase = Phase::Stopped;
        }
        self.publish_router();
        self.recompute_ready(cx, slot);
    }

    /// Stop traffic and give back everything that is not the netmap: flows, WireGuard slots, parked packets, the relay, STUN.
    fn stop_member(&mut self, cx: &mut Cx<'_>, slot: usize) {
        let Some(m) = self.members[slot].as_mut() else { return };
        let id = m.rt.id;
        // 1. no new traffic in: unpublish (forgets the flows)
        m.rt.ready = false;
        self.sh.router.suspend(id);
        // 2. stop what feeds it: the relay link and the schedules
        cx.out.emit(Out::DerpClose { member: id });
        cx.out.emit(Out::ReleaseToken { member: id });
        m.rt.derp_ready = false;
        m.rt.stun_started = false;
        m.rt.stun.reset();
        m.rt.netcheck_wanted = false;
        m.rt.public_ep = None;
        // 3. destroy what is private to it: parked packets, peers (their slots are wiped), paths
        for _ in 0..m.rt.park.drop_all(&mut self.sh.store) {
            self.sh.stats.park(ParkEnd::MemberGone);
        }
        for idx in 0..P {
            if let Some(w) = m.mship.table.remove(idx) {
                m.rt.slot_of[idx] = w.or(m.rt.slot_of[idx]);
                crate::shared::release_peer_state(&mut m.rt, &mut self.sh.pool, &mut self.sh.store, &mut self.sh.stats, idx, w);
            }
        }
        self.sh.pool.release_owner(OwnerId(m.rt.slot));
        m.rt.slot_of = [None; P];
        m.rt.ip_of = [0; P];
        m.mship.trial = tdongle_tailnet_peers::trial::Trial::new();
    }

    /// Remove a membership in the order ADR 0013 ("Merge with the router hot path") fixes: suspend the router so no packet enters, stop what feeds it
    /// (the relay, the control plane: the runtime's side, announced by `DerpClose`/`ReleaseToken`), then destroy. Afterwards every later packet for the id
    /// is a counted `NoMember`.
    fn on_member_removed(&mut self, cx: &mut Cx<'_>, id: MemberId) {
        let Some(slot) = self.slot_by_id(id) else {
            self.sh.stats.no_member_inputs.bump();
            return;
        };
        self.stop_member(cx, slot);
        self.sh.router.forget(id);
        self.sh.dir.clear(slot);
        self.members[slot] = None;
        self.sh.stats.members_removed.bump();
        self.publish_router();
        cx.out.emit(Out::MemberGone { member: id });
    }

    fn on_endpoints(&mut self, cx: &mut Cx<'_>, id: MemberId, eps: &[Ep]) {
        let Some(slot) = self.slot_by_id(id) else {
            self.sh.stats.no_member_inputs.bump();
            return;
        };
        let Some(m) = self.members[slot].as_mut() else { return };
        let mut changed = eps.len().min(crate::member::LOCAL_EPS) != m.rt.local_n;
        for (i, e) in eps.iter().take(crate::member::LOCAL_EPS).enumerate() {
            changed |= m.rt.local_eps[i] != *e;
            m.rt.local_eps[i] = *e;
        }
        m.rt.local_n = eps.len().min(crate::member::LOCAL_EPS);
        if changed && m.rt.phase == Phase::Running {
            for idx in 0..P {
                if m.mship.table.get(idx).is_some() {
                    self.sh.send_cmm(m, idx, cx);
                }
            }
        }
    }

    // ---- netmap --------------------------------------------------------------------------------------------------------------------------------

    /// `false`: refused (the map fails and the previous directory stays).
    fn on_netmap(&mut self, cx: &mut Cx<'_>, id: MemberId, ev: &NetmapEvent) -> bool {
        let Some(slot) = self.slot_by_id(id) else { return false };
        match ev {
            NetmapEvent::Peer(rec) => self.sh.dir.stage(slot, rec).is_ok(),
            NetmapEvent::Abort => {
                self.sh.dir.abort(slot);
                true
            }
            NetmapEvent::SelfNode(n) => {
                let Some(m) = self.members[slot].as_mut() else { return false };
                if let Some(ip) = n.vpn_ip {
                    m.rt.self_ip = ip;
                }
                if let Some(name) = &n.name {
                    m.rt.self_name.set(name.as_str());
                }
                if n.home_derp != 0 {
                    m.rt.home_derp = n.home_derp;
                }
                m.rt.key_expired = n.expired;
                true
            }
            NetmapEvent::Derp(d) => {
                let Some(m) = self.members[slot].as_mut() else { return false };
                m.rt.derp_map = d.clone();
                true
            }
            NetmapEvent::Dns(c) => {
                let Some(m) = self.members[slot].as_mut() else { return false };
                if m.rt.domain.is_empty()
                    && let Some(d) = c.domain_list().first()
                {
                    m.rt.domain.set(d.as_str());
                }
                true
            }
            NetmapEvent::Domain(d) => {
                let Some(m) = self.members[slot].as_mut() else { return false };
                m.rt.domain.set(d.as_str());
                true
            }
            NetmapEvent::ControlTime { secs, nanos } => {
                let Some(m) = self.members[slot].as_mut() else { return false };
                m.rt.wall = Some((u64::try_from(*secs).unwrap_or(0), *nanos, cx.now));
                true
            }
            NetmapEvent::Commit { authoritative, self_expired } => self.commit_map(cx, slot, *authoritative, *self_expired),
        }
    }

    fn commit_map(&mut self, cx: &mut Cx<'_>, slot: usize, authoritative: bool, self_expired: bool) -> bool {
        if self.sh.dir.commit(slot, authoritative).is_err() {
            return false;
        }
        let Some(m) = self.members[slot].as_mut() else { return false };
        if self_expired {
            m.rt.key_expired = true;
        }
        m.mship.session_valid = true;
        // resident peers follow the new directory: revoked ones leave, the others take the new endpoints, DISCO key and region
        for idx in 0..P {
            let Some(key) = m.mship.table.get(idx).map(|p| p.public_key) else { continue };
            match self.sh.dir.find_by_key(slot, &key) {
                None => {
                    if let Some(w) = m.mship.table.remove(idx) {
                        crate::shared::release_peer_state(&mut m.rt, &mut self.sh.pool, &mut self.sh.store, &mut self.sh.stats, idx, w);
                    }
                }
                Some(rec) => {
                    let Some(p) = m.mship.table.get_mut(idx) else { continue };
                    let disco_changed = p.disco_key != rec.disco_key;
                    p.vpn_ip = rec.vpn_ip;
                    p.disco_key = rec.disco_key;
                    p.meta = tdongle_tailnet_peers::table::Peer::from_record(&rec, cx.now).meta;
                    let mut eps = [Ep::NONE; 8];
                    let mut n = 0;
                    for e in rec.endpoints.iter().take(rec.endpoint_count.clamp(0, 8) as usize) {
                        if !e.is_ipv6 {
                            eps[n] = Ep::from_u32(e.ip, e.port);
                            n += 1;
                        }
                    }
                    if disco_changed {
                        m.rt.paths[idx].reset_path();
                    }
                    m.rt.paths[idx].set_endpoints(&eps[..n], &self.sh.path_cfg, &mut m.rt.pcounters);
                }
            }
        }
        m.rt.generation = m.rt.generation.wrapping_add(1);
        let first_map = !m.rt.stun_started && !m.rt.netcheck_wanted;
        // the home region vanished from the map: reconnect elsewhere
        let home_gone = m.rt.derp_map.count != 0 && !m.rt.derp_map.region_list().iter().any(|r| r.region_id == m.rt.home_derp);
        self.recompute_ready(cx, slot);
        if first_map || home_gone {
            self.start_network(cx, slot);
        }
        true
    }

    // ---- time ----------------------------------------------------------------------------------------------------------------------------------

    fn on_tick(&mut self, cx: &mut Cx<'_>) {
        for slot in 0..M {
            if self.members[slot].as_ref().is_none_or(|m| m.rt.phase != Phase::Running) {
                continue;
            }
            self.tick_member(cx, slot);
        }
        self.service_router(cx);
        if let Some(d) = self.sh.dns_deadline
            && cx.now >= d
        {
            let idle = self.sh.responder.expire(cx.now);
            self.sh.dns_deadline = if idle { None } else { Some(cx.now + 250) };
        }
    }

    fn tick_member(&mut self, cx: &mut Cx<'_>, slot: usize) {
        let now = cx.now;
        self.trial_poll(cx, slot);
        let Some(m) = self.members[slot].as_mut() else { return };
        let id = m.rt.id;
        for _ in 0..m.rt.park.expire(&mut self.sh.store, now) {
            self.sh.stats.park(ParkEnd::Expired);
        }
        // WireGuard timers of every resident peer (initiation retries, keepalives, key expiry)
        for idx in 0..P {
            if m.mship.table.get(idx).is_some() {
                self.sh.service_peer(m, idx, cx);
            }
        }
        // DISCO
        self.sh.disco_tick(m, cx);
        // STUN
        if m.rt.stun_started && now >= m.rt.stun_next {
            let stats = &mut self.sh.stats;
            let mut sends = [None; 3];
            let mut n = 0;
            m.rt.stun.poll(now, cx.rng, &mut |s| {
                if n < 3 {
                    sends[n] = Some(s);
                    n += 1;
                }
            });
            for s in sends.iter().flatten() {
                Shared::<D, M, K, A, F, JB>::emit_stun(stats, cx, id, s);
            }
            m.rt.stun_next = now + if m.rt.stun.retrying() { 2001 } else { 1000 };
        }
        self.netcheck_step(cx, slot);
    }

    /// Run the netcheck: send what is due, and when it has finished choose the DERP home region (the fastest to answer).
    pub(crate) fn netcheck_step(&mut self, cx: &mut Cx<'_>, slot: usize) {
        let now = cx.now;
        let Some(m) = self.members[slot].as_mut() else { return };
        let id = m.rt.id;
        if m.rt.netcheck_wanted && now >= m.rt.netcheck_next {
            let stats = &mut self.sh.stats;
            let mut sends = [None; 1];
            let mut n = 0;
            let poll = m.rt.netcheck.poll(now, cx.rng, &mut |s| {
                if n < 1 {
                    sends[n] = Some(s);
                    n += 1;
                }
            });
            for s in sends.iter().flatten() {
                Shared::<D, M, K, A, F, JB>::emit_stun(stats, cx, id, s);
            }
            match poll {
                NetcheckPoll::Pending { wake_at } => m.rt.netcheck_next = wake_at.max(now + 1),
                NetcheckPoll::Idle => m.rt.netcheck_wanted = false,
                NetcheckPoll::Done => {
                    m.rt.netcheck_wanted = false;
                    let best = m.rt.netcheck.best_region();
                    if best != 0 && best != m.rt.home_derp {
                        m.rt.home_derp = best;
                        m.rt.derp_ready = false;
                        cx.out.emit(Out::HomeDerp { member: id, region: best });
                        if let Some(r) = m.rt.derp_map.region_list().iter().find(|r| r.region_id == best)
                            && let Some(n) = r.node_list().first()
                        {
                            cx.out.emit(Out::DerpConnect {
                                member: id,
                                region: best,
                                host: n.hostname.as_str(),
                                port: if n.derp_port != 0 { n.derp_port } else { 443 },
                            });
                        }
                    }
                }
            }
        }
    }

    /// The one time the runtime must call `handle(.., Input::Tick, ..)` next (`None`: nothing is scheduled). `now` is the current time; a result at
    /// or before it means "tick now".
    pub fn next_deadline(&self, now: Millis) -> Option<Millis> {
        let mut t: Option<Millis> = None;
        self.deadlines(now, &mut |_, v| t = Some(t.map_or(v, |x| x.min(v))));
        t
    }

    /// Every reason the engine wants to be woken, with its time (the wake is their minimum). For diagnostics: "why am I awake?".
    pub fn deadlines(&self, now: Millis, f: &mut dyn FnMut(&'static str, Millis)) {
        for m in self.members.iter().flatten() {
            if m.rt.phase != Phase::Running {
                continue;
            }
            let owner = OwnerId(m.rt.slot);
            let mut any = false;
            for idx in 0..P {
                if m.mship.table.get(idx).is_none() {
                    continue;
                }
                any = true;
                if let Some(sl) = m.rt.slot_of[idx].and_then(|s| self.sh.pool.get(owner, s))
                    && let Some(w) = sl.hot.next_wake(now)
                {
                    f("wireguard", w.max(m.rt.hs_backoff[idx]));
                }
            }
            if any {
                f("disco", m.rt.next_disco_tick);
            }
            if let Some(e) = m.rt.park.next_expiry() {
                f("parked", e);
            }
            if m.rt.stun_started {
                f("stun", m.rt.stun_next);
            }
            if m.rt.netcheck_wanted {
                f("netcheck", m.rt.netcheck_next);
            }
            if m.mship.trial.pending != 0 {
                f("trial", m.mship.trial.deadline_ms);
            }
        }
        if let Some(r) = self.sh.router.next_deadline(now) {
            f("router", r);
        }
        if let Some(d) = self.sh.dns_deadline {
            f("dns", d);
        }
    }

    // ---- invariants ----------------------------------------------------------------------------------------------------------------------------

    /// Check every identity the engine promises (like `tdongle-bridge`'s `Stats::check_identities`): packet counts add up, the router's hold adds up,
    /// the parked queue and its arena agree, every table entry has exactly one pool slot of the right key, every receiver index is unique pool-wide, and
    /// no pool slot belongs to a membership that does not exist.
    pub fn check_identities(&self) -> Result<(), IdentityError> {
        let queued: usize = self.members.iter().flatten().map(|m| m.rt.park.len()).sum();
        self.sh.stats.check_counts(queued)?;
        // the router's hold: held = released + dropped + still held
        let rs = self.sh.router.stats();
        let held = u64::from(rs.get(tdongle_tailnet_router::Stat::Held));
        let out = u64::from(rs.get(tdongle_tailnet_router::Stat::HeldReleased))
            + u64::from(rs.get(tdongle_tailnet_router::Stat::HeldDropped))
            + self.sh.router.held_count() as u64;
        if held != out {
            return Err(IdentityError::Hold);
        }
        // the arena holds exactly the parked packets' blocks
        let blocks: usize = self.members.iter().flatten().map(|m| m.rt.park.blocks()).sum();
        if blocks != self.sh.store.used_blocks() {
            return Err(IdentityError::Park);
        }
        // table <-> pool
        let mut slots = 0usize;
        for (slot, m) in self.members.iter().enumerate() {
            let Some(m) = m else {
                if self.sh.pool.owner_count(OwnerId(slot as u8)) != 0 {
                    return Err(IdentityError::Pool);
                }
                continue;
            };
            let owner = OwnerId(m.rt.slot);
            let mut mine = 0usize;
            for (idx, p) in m.mship.table.iter() {
                if p.wg_slot != m.rt.slot_of[idx] {
                    return Err(IdentityError::Pool);
                }
                if let Some(s) = p.wg_slot {
                    mine += 1;
                    match self.sh.pool.get(owner, s) {
                        Some(sl) if sl.public == p.public_key => {}
                        _ => return Err(IdentityError::Pool),
                    }
                }
                if m.rt.ip_of[idx] != p.vpn_ip {
                    return Err(IdentityError::Pool);
                }
            }
            if mine != self.sh.pool.owner_count(owner) {
                return Err(IdentityError::Pool);
            }
            slots += mine;
            // every parked packet's peer is resident
            let mut orphan = false;
            m.rt.park.for_each_peer(|ip| orphan |= m.mship.table.by_ip(ip).is_none());
            if orphan {
                return Err(IdentityError::Orphan);
            }
        }
        if slots != self.sh.pool.used() {
            return Err(IdentityError::Pool);
        }
        // receiver indices are unique pool-wide
        let mut seen = [0u32; 64];
        let mut n = 0;
        let mut dup = false;
        self.sh.pool.each(|_, _, sl| {
            sl.hot.for_each_index(|i| {
                if seen[..n].contains(&i) {
                    dup = true;
                } else if n < seen.len() {
                    seen[n] = i;
                    n += 1;
                }
            });
        });
        if dup {
            return Err(IdentityError::Pool);
        }
        Ok(())
    }
}

/// The DNS responder's read-only view of the memberships (`tdongle_tailnet_dns::Directory`).
struct DnsView<'a, D, const P: usize, const M: usize> {
    members: &'a [Option<Member<P>>; M],
    dir: &'a D,
    book: &'a AliasBook,
}

impl<D: PeerDirectory, const P: usize, const M: usize> Directory for DnsView<'_, D, P, M> {
    fn member_count(&self) -> usize {
        M
    }
    fn member(&self, i: usize) -> Option<MemberView<'_>> {
        let m = self.members.get(i)?.as_ref()?;
        Some(MemberView {
            id: m.rt.id,
            label: m.rt.label.as_str(),
            self_dns_name: m.rt.self_name.as_str(),
            connected: m.rt.phase == Phase::Running,
            session_valid: m.mship.session_valid,
            generation: self.dir.generation(i),
            peer_count: self.dir.count(i),
        })
    }
    fn peer(&self, member: usize, j: usize) -> Option<PeerView<'_>> {
        self.dir.peer_view(member, j).map(|(hostname, vpn_ip)| PeerView { hostname, vpn_ip })
    }
    fn generation(&self, member: usize) -> u32 {
        self.dir.generation(member)
    }
    fn alias(&self, member_id: u32, peer_ip: u32) -> Option<u32> {
        self.book.alloc(member_id, peer_ip)
    }
}
