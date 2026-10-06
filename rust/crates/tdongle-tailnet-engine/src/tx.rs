//! The send side: the packet path (host -> router -> WireGuard seal -> direct UDP or DERP), the handshake driver, the parked queue's flush and the DISCO
//! actions. Methods of [`Shared`] that take the membership they work on, so the engine can hold the member table and the shared parts apart.

use crate::dir::PeerDirectory;
use crate::io::Out;
use crate::jit::{JIT_PACKET_MAX, ParkRefusal};
use crate::member::Member;
use crate::shared::{Cx, Sent, Shared, emit_route, wall_clock};
use crate::slot::{PreDrawn, WgSlot};
use crate::stats::{ParkEnd, TxFate};
use tdongle_tailnet_admission::heap::{HbSite, hb_ok};
use tdongle_tailnet_crypto::nacl;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::envelope::{fresh_nonce, seal_call_me_maybe, seal_ping, seal_pong};
use tdongle_tailnet_disco::msg::{Ping, Pong};
use tdongle_tailnet_disco::path::{Action, ActionBuf, Env, PathState, PingKind, Route, TickBudget, TickInput, Via, expire_probes};
use tdongle_tailnet_peers::pool::{OwnerId, Ungated};
use tdongle_tailnet_peers::record::DirRecord;
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_wg::{Actions, PeerCold, TxError, TxKind};

impl<D: PeerDirectory, const M: usize, const K: usize, const A: usize, const F: usize, const JB: usize> Shared<D, M, K, A, F, JB> {
    /// Give the peer at table index `idx` a pool slot (`peer_alloc`): its cold record (one X25519: the precomputed static DH) and a zeroed hot state.
    /// `Err` is counted by the caller as `NoSlot`.
    pub(crate) fn ensure_slot<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, now: u64) -> Result<u8, ()> {
        if let Some(s) = m.rt.slot_of[idx] {
            return Ok(s);
        }
        let public = m.mship.table.get(idx).ok_or(())?.public_key;
        let cold = PeerCold::new(&m.rt.identity, Key32(public), None).ok_or(())?;
        let owner = OwnerId(m.rt.slot);
        let r = match self.pool.acquire(owner, &mut Ungated) {
            Ok(r) => r,
            Err(_) => {
                self.stats.slot_refused.bump();
                return Err(());
            }
        };
        match self.pool.get_mut(owner, r.index) {
            Some(sl) => {
                *sl = WgSlot::new(public, cold);
                if m.rt.persistent_keepalive_s != 0 {
                    sl.hot.set_persistent_keepalive(m.rt.persistent_keepalive_s, now);
                }
            }
            None => return Err(()),
        }
        if let Some(p) = m.mship.table.get_mut(idx) {
            p.wg_slot = Some(r.index);
        }
        m.rt.slot_of[idx] = Some(r.index);
        Ok(r.index)
    }

    pub(crate) fn peer_key<const P: usize>(m: &Member<P>, idx: usize) -> [u8; 32] {
        m.mship.table.get(idx).map_or([0; 32], |p| p.public_key)
    }

    /// Send `self.ctl[..n]` to peer `idx` along its DISCO route.
    pub(crate) fn send_ctl<const P: usize>(&mut self, m: &Member<P>, idx: usize, n: usize, cx: &mut Cx<'_>) -> Sent {
        let key = Self::peer_key(m, idx);
        let route = m.rt.paths[idx].route(cx.now);
        emit_route(&mut self.stats, &self.hb, &self.heap, cx, m.rt.id, m.rt.derp_ready, route, &key, &self.ctl[..n])
    }

    /// The shared DISCO key with the peer, derived once per peer disco key (`NaCl box beforenm`).
    pub(crate) fn disco_shared<const P: usize>(m: &mut Member<P>, idx: usize) -> Option<Key32> {
        let p = m.mship.table.get_mut(idx)?;
        if p.disco_key == [0; 32] {
            return None;
        }
        if !p.disco.shared_valid || p.disco.shared_for != p.disco_key {
            let k = nacl::precompute(&m.rt.disco_priv, &Key32(p.disco_key))?;
            p.disco.shared = k.0;
            p.disco.shared_for = p.disco_key;
            p.disco.shared_valid = true;
        }
        Some(Key32(p.disco.shared))
    }

    // ---- the packet path -----------------------------------------------------------------------------------------------------------------------

    /// Send the plaintext IPv4 packet at `self.tx[16..16 + len]` to the peer at `idx` (`gateway_egress_packet`): seal and route it if a session exists
    /// (and nothing waits ahead of it), else park it and start the handshake.
    pub(crate) fn send_to_peer<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, len: usize, cx: &mut Cx<'_>) -> TxFate {
        let ip = m.rt.ip_of[idx];
        if let Some(p) = m.mship.table.get_mut(idx) {
            p.jit_used_ms = cx.now;
        }
        let owner = OwnerId(m.rt.slot);
        let Some(slot) = m.rt.slot_of[idx] else { return TxFate::NoSlot };
        if m.rt.park.has_peer(ip) {
            // ordering: a new packet queues behind the parked ones, whether or not the session is up now
            let fate = self.park_packet(m, ip, len, cx);
            if fate == TxFate::Parked {
                self.flush_peer(m, idx, cx);
                self.service_peer(m, idx, cx);
            }
            return fate;
        }
        let Some(sl) = self.pool.get_mut(owner, slot) else { return TxFate::NoSlot };
        match sl.hot.tx_prepare(cx.now, TxKind::Data) {
            Ok(ticket) => match ticket.seal(&mut self.tx, len) {
                Ok(n) => {
                    let key = Self::peer_key(m, idx);
                    let route = m.rt.paths[idx].route(cx.now);
                    match emit_route(&mut self.stats, &self.hb, &self.heap, cx, m.rt.id, m.rt.derp_ready, route, &key, &self.tx[..n]) {
                        Sent::Direct => TxFate::SentDirect,
                        Sent::Derp => TxFate::SentDerp,
                        Sent::NoRoute => TxFate::NoRoute,
                        Sent::HeapRefused => TxFate::HeapRefused,
                        Sent::Refused => TxFate::TxRefused,
                    }
                }
                Err(_) => TxFate::SealFail,
            },
            Err(TxError::BufferTooSmall) => TxFate::SealFail,
            Err(_) => {
                // no usable session: the handshake is armed by tx_prepare; park the packet and run the timers now
                let fate = self.park_packet(m, ip, len, cx);
                self.service_peer(m, idx, cx);
                fate
            }
        }
    }

    fn park_packet<const P: usize>(&mut self, m: &mut Member<P>, ip: u32, len: usize, cx: &mut Cx<'_>) -> TxFate {
        // what the arena really takes (whole blocks) is what the heap floor is asked about
        if !hb_ok(self.heap.free, len.div_ceil(crate::jit::JIT_BLOCK).max(1) * crate::jit::JIT_BLOCK) {
            self.hb.refuse(HbSite::Jit);
            return TxFate::JitNoMem;
        }
        match m.rt.park.park(&mut self.store, ip, &self.tx[16..16 + len], cx.now) {
            Ok(()) => TxFate::Parked,
            Err(ParkRefusal::Budget) => TxFate::JitBudget,
            Err(ParkRefusal::NoBlocks) => {
                self.hb.refuse(HbSite::Jit);
                TxFate::JitNoMem
            }
        }
    }

    /// Send what is parked for the peer, in arrival order, while a session exists (`directory_flush_packets`).
    pub(crate) fn flush_peer<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, cx: &mut Cx<'_>) {
        let ip = m.rt.ip_of[idx];
        let owner = OwnerId(m.rt.slot);
        let Some(slot) = m.rt.slot_of[idx] else { return };
        while let Some(i) = m.rt.park.oldest_for(ip) {
            let Some(sl) = self.pool.get_mut(owner, slot) else { return };
            let Ok(ticket) = sl.hot.tx_prepare(cx.now, TxKind::Data) else { return };
            let Some(len) = m.rt.park.take(&mut self.store, i, &mut self.tx[16..16 + JIT_PACKET_MAX]) else { return };
            let sent = match ticket.seal(&mut self.tx, len) {
                Ok(n) => {
                    let key = Self::peer_key(m, idx);
                    let route = m.rt.paths[idx].route(cx.now);
                    emit_route(&mut self.stats, &self.hb, &self.heap, cx, m.rt.id, m.rt.derp_ready, route, &key, &self.tx[..n])
                }
                Err(_) => Sent::Refused,
            };
            self.stats.park(if matches!(sent, Sent::Direct | Sent::Derp) { ParkEnd::Sent } else { ParkEnd::FlushFailed });
            if let Some(p) = m.mship.table.get_mut(idx) {
                p.jit_used_ms = cx.now;
            }
        }
    }

    // ---- the handshake driver and the WireGuard timers -------------------------------------------------------------------------------------------

    /// Run the peer's WireGuard timers and do what is due: the initiation, the keepalive, the abandonment of a handshake series. What doing it arms (a
    /// keepalive that finds its session due for rekeying asks for a handshake) is run in the same call, so the next wake lies in the future.
    pub(crate) fn service_peer<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, cx: &mut Cx<'_>) {
        let owner = OwnerId(m.rt.slot);
        for _ in 0..3 {
            let Some(slot) = m.rt.slot_of[idx] else { return };
            let Some(sl) = self.pool.get_mut(owner, slot) else { return };
            let mut actions = sl.hot.poll(cx.now);
            if actions.contains(Actions::HANDSHAKE_GAVE_UP) {
                let ip = m.rt.ip_of[idx];
                for _ in 0..m.rt.park.drop_peer(&mut self.store, ip) {
                    self.stats.park(ParkEnd::GaveUp);
                }
            }
            if cx.now < m.rt.hs_backoff[idx] {
                // an initiation just failed for want of an index: wait before trying again, do not spin
                actions = if actions.contains(Actions::SEND_KEEPALIVE) { Actions::SEND_KEEPALIVE } else { Actions::NONE };
            }
            if actions.is_empty() || actions == Actions::HANDSHAKE_GAVE_UP || actions == Actions::KEYS_EXPIRED {
                return;
            }
            if actions.contains(Actions::SEND_INITIATION) {
                self.send_initiation(m, idx, cx);
            }
            if actions.contains(Actions::SEND_KEEPALIVE) {
                self.send_keepalive(m, idx, cx);
            }
        }
    }

    fn send_initiation<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, cx: &mut Cx<'_>) {
        let owner = OwnerId(m.rt.slot);
        let Some(slot) = m.rt.slot_of[idx] else { return };
        let drawn = self.pool.generate_unique_index(&mut cx.rng);
        let wall = wall_clock(&m.rt, cx.now);
        let Some(sl) = self.pool.get_mut(owner, slot) else { return };
        let Some(cold) = sl.cold.as_ref() else { return };
        let msg = sl.hot.create_initiation(&m.rt.identity, cold, cx.now, wall, cx.rng, &mut PreDrawn::new(drawn));
        let msg = match msg {
            Ok(m) => m,
            Err(_) => {
                m.rt.hs_backoff[idx] = cx.now + 1000;
                return;
            }
        };
        self.ctl[..msg.len()].copy_from_slice(&msg);
        self.stats.hs_init_tx.bump();
        if !matches!(self.send_ctl(m, idx, msg.len(), cx), Sent::Direct | Sent::Derp) {
            self.stats.hs_init_noroute.bump();
        }
    }

    fn send_keepalive<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, cx: &mut Cx<'_>) {
        let owner = OwnerId(m.rt.slot);
        let Some(slot) = m.rt.slot_of[idx] else { return };
        let Some(sl) = self.pool.get_mut(owner, slot) else { return };
        let Ok(ticket) = sl.hot.tx_prepare(cx.now, TxKind::Keepalive) else { return };
        let Ok(n) = ticket.seal(&mut self.tx, 0) else { return };
        let key = Self::peer_key(m, idx);
        let route = m.rt.paths[idx].route(cx.now);
        if matches!(emit_route(&mut self.stats, &self.hb, &self.heap, cx, m.rt.id, m.rt.derp_ready, route, &key, &self.tx[..n]), Sent::Direct | Sent::Derp) {
            self.stats.keepalive_tx.bump();
        }
    }

    // ---- DISCO ---------------------------------------------------------------------------------------------------------------------------------

    /// Start a peer's path state from its directory record and send the first probes (`on_added`).
    pub(crate) fn path_added<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, rec: &DirRecord, cx: &mut Cx<'_>) {
        let mut eps = [Ep::NONE; 8];
        let mut n = 0;
        for e in rec.endpoints.iter().take(rec.endpoint_count.clamp(0, 8) as usize) {
            if !e.is_ipv6 {
                eps[n] = Ep::from_u32(e.ip, e.port);
                n += 1;
            }
        }
        m.rt.paths[idx] = PathState::new();
        m.rt.paths[idx].set_endpoints(&eps[..n], &self.path_cfg, &mut m.rt.pcounters);
        let mut buf = ActionBuf::<8>::new();
        {
            let mut env = Env { cfg: &self.path_cfg, probes: &mut m.rt.probes, rng: &mut *cx.rng, counters: &mut m.rt.pcounters };
            m.rt.paths[idx].on_added(idx as u8, cx.now, true, &mut m.rt.burst, &mut env, &mut buf);
        }
        self.exec_actions(m, idx, &buf, cx);
    }

    /// Carry out the actions the path machine returned.
    pub(crate) fn exec_actions<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, buf: &ActionBuf<8>, cx: &mut Cx<'_>) {
        for a in buf.iter() {
            match a {
                Action::SendPing { via, txid, kind: _ } => {
                    let Some(shared) = Self::disco_shared(m, idx) else { continue };
                    let nonce = fresh_nonce(cx.rng);
                    let ping = Ping { txid, node_key: Some(m.rt.node_pub.as_bytes()), padding: 0 };
                    let Ok(n) = seal_ping(&mut self.ctl, &m.rt.disco_pub, &shared, &nonce, &ping) else { continue };
                    self.send_disco(m, idx, via, n, cx);
                }
                Action::SendPong { via, txid, src, derp_if_direct_fails: _ } => {
                    let Some(shared) = Self::disco_shared(m, idx) else { continue };
                    let nonce = fresh_nonce(cx.rng);
                    let Ok(n) = seal_pong(&mut self.ctl, &m.rt.disco_pub, &shared, &nonce, &Pong { txid, src }) else { continue };
                    self.send_disco(m, idx, via, n, cx);
                }
                Action::SendCallMeMaybe => self.send_cmm(m, idx, cx),
                Action::WgDirectHandshake { .. } | Action::WgDerpHandshake { .. } => {
                    // a path was found (or a session-less peer is due a retry): handshake now, along whichever route DISCO says is current
                    let owner = OwnerId(m.rt.slot);
                    if let Some(sl) = m.rt.slot_of[idx].and_then(|s| self.pool.get_mut(owner, s)) {
                        sl.hot.request_handshake_now(cx.now);
                    }
                    self.service_peer(m, idx, cx);
                }
                // The best address is the path machine's own state (`route`), and WireGuard here has no endpoint of its own to move.
                Action::WgSetEndpoint(_) | Action::RevertToDerp => {}
            }
        }
    }

    fn send_disco<const P: usize>(&mut self, m: &Member<P>, idx: usize, via: Via, n: usize, cx: &mut Cx<'_>) {
        let route = match via {
            Via::Direct(ep) => Route::Direct(ep),
            Via::Derp => Route::Derp,
        };
        let key = Self::peer_key(m, idx);
        if matches!(emit_route(&mut self.stats, &self.hb, &self.heap, cx, m.rt.id, m.rt.derp_ready, route, &key, &self.ctl[..n]), Sent::Direct | Sent::Derp) {
            self.stats.disco_tx.bump();
        }
    }

    /// Tell the peer, over DERP, where we can be reached (`disco_send_call_me_maybe`): the local addresses and the STUN-mapped one.
    pub(crate) fn send_cmm<const P: usize>(&mut self, m: &mut Member<P>, idx: usize, cx: &mut Cx<'_>) {
        let mut eps = [Ep::NONE; crate::member::LOCAL_EPS + 1];
        let mut n = 0;
        for &e in &m.rt.local_eps[..m.rt.local_n] {
            eps[n] = e;
            n += 1;
        }
        if let Some(p) = m.rt.public_ep
            && !eps[..n].contains(&p)
        {
            eps[n] = p;
            n += 1;
        }
        if n == 0 {
            return;
        }
        let Some(shared) = Self::disco_shared(m, idx) else { return };
        let nonce = fresh_nonce(cx.rng);
        let Ok(len) = seal_call_me_maybe(&mut self.ctl, &m.rt.disco_pub, &shared, &nonce, &eps[..n]) else { return };
        self.send_disco(m, idx, Via::Derp, len, cx);
    }

    /// The once-a-second DISCO pass (`disco_periodic_probes`): trust expiry, DERP handshake retry, upgrade probes, heartbeats.
    pub(crate) fn disco_tick<const P: usize>(&mut self, m: &mut Member<P>, cx: &mut Cx<'_>) {
        if cx.now < m.rt.next_disco_tick {
            return;
        }
        m.rt.next_disco_tick = cx.now + 1000;
        let mut budget = TickBudget::new(&self.path_cfg);
        for idx in 0..P {
            let Some(peer) = m.mship.table.get(idx) else { continue };
            let online = peer.meta.online;
            let owner = OwnerId(m.rt.slot);
            let hot = m.rt.slot_of[idx].and_then(|s| self.pool.get(owner, s)).map(|sl| &sl.hot);
            let input = TickInput {
                online,
                allowed: true,
                udp_ok: true,
                session_up: hot.is_some_and(|h| h.has_session()),
                wg_present: hot.is_some(),
                data_age_ms: hot.and_then(|h| h.last_rx()).map(|t| cx.now.saturating_sub(t)),
            };
            let mut buf = ActionBuf::<8>::new();
            {
                let mut env = Env { cfg: &self.path_cfg, probes: &mut m.rt.probes, rng: &mut *cx.rng, counters: &mut m.rt.pcounters };
                m.rt.paths[idx].tick(idx as u8, cx.now, &input, &mut budget, &mut env, &mut buf);
            }
            self.exec_actions(m, idx, &buf, cx);
        }
        expire_probes(&mut m.rt.probes, cx.now, &self.path_cfg, &mut m.rt.pcounters);
    }

    /// Re-probe every resident peer now (the DERP link just came up: pings and call-me-maybes could not leave before).
    pub(crate) fn probe_all<const P: usize>(&mut self, m: &mut Member<P>, cx: &mut Cx<'_>) {
        for idx in 0..P {
            if m.mship.table.get(idx).is_none() {
                continue;
            }
            let mut buf = ActionBuf::<8>::new();
            {
                let mut env = Env { cfg: &self.path_cfg, probes: &mut m.rt.probes, rng: &mut *cx.rng, counters: &mut m.rt.pcounters };
                m.rt.paths[idx].send_pings(idx as u8, cx.now, true, true, PingKind::Discovery, &mut env, &mut buf);
            }
            self.exec_actions(m, idx, &buf, cx);
            self.send_cmm(m, idx, cx);
        }
    }

    /// Emit the 40-byte STUN requests a scheduler produced.
    pub(crate) fn emit_stun(stats: &mut crate::stats::Stats, cx: &mut Cx<'_>, member: u32, s: &tdongle_tailnet_disco::stun_sched::StunSend) {
        if cx.out.emit(Out::SendStun { member, sock: s.sock, dst: s.to, data: &s.packet }) {
            stats.stun_tx.bump();
        } else {
            stats.out_refused.bump();
        }
    }
}
