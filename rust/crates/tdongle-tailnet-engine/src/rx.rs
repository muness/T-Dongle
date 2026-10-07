//! The receive side: demultiplexing a datagram by its first bytes as the C's `net_io` does (STUN, DISCO, WireGuard), the WireGuard handshake responder,
//! the transport path into the router, and DISCO message handling.

use crate::dir::PeerDirectory;
use crate::engine::Engine;
use crate::io::Out;
use crate::member::Member;
use crate::shared::{ActHost, Cx, UNDER_LOAD_INITIATIONS, residents_of_others, src_allowed};
use crate::stats::RxFate;
use tdongle_tailnet_admission::heap::{HbSite, hb_rx_ok};
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::envelope::{self, HEADER_LEN, OVERHEAD, RxOutcome, open_in_place, parse_header};
use tdongle_tailnet_disco::msg::{Message, parse as parse_disco};
use tdongle_tailnet_disco::netcheck::NetcheckEvent;
use tdongle_tailnet_disco::path::{ActionBuf, Env, PingOutcome, PongOutcome, RxFrom};
use tdongle_tailnet_disco::stun::is_stun;
use tdongle_tailnet_disco::stun_sched::StunEvent;
use tdongle_tailnet_peers::arbiter::Resident;
use tdongle_tailnet_peers::pool::OwnerId;
use tdongle_tailnet_peers::record::DirRecord;
use tdongle_tailnet_router::TunnelOutcome;
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_wg::Dropped;
use tdongle_tailnet_wg::cookie::{Screen, screen};
use tdongle_tailnet_wg::msg::{CookieReply, Initiation, MsgType, Response, TransportHeader, classify};

/// Where a datagram came from.
#[derive(Clone, Copy, Debug)]
pub enum From<'a> {
    /// The member's UDP socket.
    Udp(Ep),
    /// The member's DERP link, relayed from this node key.
    Derp(&'a [u8; 32]),
}

impl From<'_> {
    /// The source in the form the cookie MAC covers (18 wire bytes for UDP, the node key for DERP: the C used the any-address for DERP).
    fn mac_source(&self, buf: &mut [u8; 32]) -> usize {
        match self {
            From::Udp(ep) => {
                ep.write_wire(&mut buf[..18]);
                18
            }
            From::Derp(k) => {
                buf.copy_from_slice(*k);
                32
            }
        }
    }
}

impl<D: PeerDirectory, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> Engine<D, M, P, K, A, F, JB> {
    /// One datagram for member `slot` (already known to exist and to run).
    pub(crate) fn rx_datagram(&mut self, cx: &mut Cx<'_>, slot: usize, from: From<'_>, data: &mut [u8]) -> RxFate {
        let is_udp = matches!(from, From::Udp(_));
        if !hb_rx_ok(self.sh.heap.free, data.len(), true) {
            self.sh.hb.refuse(if is_udp { HbSite::WgCopy } else { HbSite::DerpRx });
            return RxFate::HeapRefused;
        }
        if is_udp && is_stun(data) {
            return self.rx_stun(cx, slot, data);
        }
        if envelope::looks_like_disco(data) {
            return self.rx_disco(cx, slot, from, data);
        }
        match classify(data) {
            Ok(MsgType::Initiation) => self.rx_initiation(cx, slot, from, data),
            Ok(MsgType::Response) => self.rx_response(cx, slot, from, data),
            Ok(MsgType::CookieReply) => self.rx_cookie_reply(cx, slot, data),
            Ok(MsgType::Transport) => self.rx_transport(cx, slot, data),
            Err(_) => RxFate::Garbage,
        }
    }

    // ---- STUN ----------------------------------------------------------------------------------------------------------------------------------

    fn rx_stun(&mut self, cx: &mut Cx<'_>, slot: usize, data: &[u8]) -> RxFate {
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let id = m.rt.id;
        if matches!(m.rt.netcheck.on_datagram(cx.now, data), NetcheckEvent::Response { .. }) {
            // an answer may complete the run: decide the home region now, not at the next timer
            m.rt.netcheck_next = cx.now;
            self.netcheck_step(cx, slot);
            return RxFate::StunMatched;
        }
        let stats = &mut self.sh.stats;
        let mut sends = [None, None];
        let mut ns = 0;
        let ev = m.rt.stun.on_datagram(cx.now, data, cx.rng, &mut |s| {
            if ns < 2 {
                sends[ns] = Some(s);
                ns += 1;
            }
        });
        for s in sends.iter().flatten() {
            crate::shared::Shared::<D, M, K, A, F, JB>::emit_stun(stats, cx, id, s);
        }
        match ev {
            StunEvent::Public4 { ep, changed } => {
                if changed {
                    m.rt.public_ep = Some(ep);
                    cx.out.emit(Out::EndpointLearned { member: id, ep });
                    // the peers must hear about the new mapping
                    for idx in 0..P {
                        if m.mship.table.get(idx).is_some() {
                            self.sh.send_cmm(m, idx, cx);
                        }
                    }
                }
                RxFate::StunMatched
            }
            StunEvent::Public6 { .. } | StunEvent::NatChecked { .. } | StunEvent::Ignored => RxFate::StunMatched,
            StunEvent::NotStun | StunEvent::Bad(_) | StunEvent::Unmatched => RxFate::StunUnmatched,
        }
    }

    // ---- DISCO ---------------------------------------------------------------------------------------------------------------------------------

    fn rx_disco(&mut self, cx: &mut Cx<'_>, slot: usize, from: From<'_>, data: &mut [u8]) -> RxFate {
        let now = cx.now;
        // header
        let h = match parse_header(data) {
            Ok(h) => h,
            Err(o) => return self.disco_refused(slot, o),
        };
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        // the sender: resident peer, or a directory peer authenticated BEFORE it is activated (one X25519 and one box open, bounded by the token bucket)
        let (idx, shared) = match m.mship.table.by_disco_key(&h.sender) {
            Some(i) => {
                let Some(sh) = Self::resident_shared(m, i) else { return self.disco_refused(slot, RxOutcome::NoSharedKey) };
                (Some(i), sh)
            }
            None => {
                if !m.mship.trial.take_token(now) {
                    return self.disco_refused(slot, RxOutcome::UnknownSender);
                }
                let Some(rec) = self.sh.dir.find_by_disco(slot, &h.sender) else { return self.disco_refused(slot, RxOutcome::UnknownSender) };
                let Some(sh) = tdongle_tailnet_crypto::nacl::precompute(&m.rt.disco_priv, &Key32(h.sender)) else {
                    return self.disco_refused(slot, RxOutcome::NoSharedKey);
                };
                if open_in_place(data, &h.nonce, &sh).is_err() {
                    m.mship.trial.refused += 1;
                    return self.disco_refused(slot, RxOutcome::CandidateFailed);
                }
                // it authenticates: now it may cost a slot
                match self.activate_record(cx, slot, &rec, tdongle_tailnet_peers::trial::ACTIVATE_IDLE_MS) {
                    Ok(i) => return self.disco_dispatch(cx, slot, i, from, data, true),
                    Err(_) => return self.disco_refused(slot, RxOutcome::NoSlot),
                }
            }
        };
        let idx = idx.unwrap_or(0);
        if open_in_place(data, &h.nonce, &shared).is_err() {
            return self.disco_refused(slot, RxOutcome::OpenFailed);
        }
        self.disco_dispatch(cx, slot, idx, from, data, false)
    }

    fn resident_shared(m: &mut Member<P>, idx: usize) -> Option<Key32> {
        crate::shared::Shared::<D, M, K, A, F, JB>::disco_shared(m, idx)
    }

    fn disco_refused(&mut self, slot: usize, o: RxOutcome) -> RxFate {
        if let Some(m) = self.members[slot].as_mut() {
            m.rt.disco_rx.record(o);
        }
        RxFate::DiscoDropped
    }

    /// The box is open at `data[OVERHEAD..]`: parse it and hand it to the peer's path state.
    fn disco_dispatch(&mut self, cx: &mut Cx<'_>, slot: usize, idx: usize, from: From<'_>, data: &mut [u8], _activated: bool) -> RxFate {
        let _ = HEADER_LEN;
        let now = cx.now;
        let parsed = parse_disco(&data[OVERHEAD..]);
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let msg = match parsed {
            Ok(msg) => msg,
            Err(e) => return self.disco_refused(slot, RxOutcome::from(e)),
        };
        let region = m.rt.home_derp;
        let rxfrom = match from {
            From::Udp(ep) => RxFrom::Direct(ep),
            From::Derp(_) => RxFrom::Derp(region),
        };
        let session_up = m.rt.slot_of[idx].and_then(|s| self.sh.pool.get(OwnerId(m.rt.slot), s)).is_some_and(|sl| sl.hot.has_session());
        if let Some(p) = m.mship.table.get_mut(idx) {
            p.jit_used_ms = now;
        }
        let mut buf = ActionBuf::<8>::new();
        {
            let mut env = Env { cfg: &self.sh.path_cfg, probes: &mut m.rt.probes, rng: &mut *cx.rng, counters: &mut m.rt.pcounters };
            match msg {
                Message::Ping(p) => {
                    m.rt.disco_rx.record(RxOutcome::Ping);
                    let o = m.rt.paths[idx].on_ping(now, rxfrom, p.txid, &mut env, &mut buf);
                    let _ = matches!(o, PingOutcome::Answered);
                }
                Message::Pong(p) => {
                    m.rt.disco_rx.record(RxOutcome::Pong);
                    let o = m.rt.paths[idx].on_pong(idx as u8, now, rxfrom, &p.txid, session_up, &mut env, &mut buf);
                    let _ = matches!(o, PongOutcome::Unmatched);
                }
                Message::CallMeMaybe { endpoints, lax } => {
                    m.rt.disco_rx.record(if lax { RxOutcome::CallMeMaybeLax } else { RxOutcome::CallMeMaybe });
                    let _ = m.rt.paths[idx].on_call_me_maybe(idx as u8, now, endpoints, true, &mut env, &mut buf);
                }
                Message::Unsupported(_) => m.rt.disco_rx.record(RxOutcome::Unsupported),
            }
        }
        self.sh.exec_actions(m, idx, &buf, cx);
        RxFate::DiscoOk
    }

    // ---- WireGuard handshake -------------------------------------------------------------------------------------------------------------------

    /// Is the responder "under load" (wireguard-go's `UnderLoadAfterTime`): more than [`UNDER_LOAD_INITIATIONS`] initiations in the last second, or the heap below
    /// the elastic floor. Under load a valid initiation is answered with a cookie reply and processed only when it comes back with a valid mac2.
    fn under_load(&mut self, slot: usize, now: u64) -> bool {
        let heap_low = self.sh.heap.free < tdongle_tailnet_admission::heap::ML_HB_FLOOR;
        let Some(m) = self.members[slot].as_mut() else { return false };
        let (start, n) = m.rt.init_window;
        let n = if now.saturating_sub(start) >= 1000 {
            m.rt.init_window = (now, 1);
            1
        } else {
            m.rt.init_window.1 = n.saturating_add(1);
            m.rt.init_window.1
        };
        n > UNDER_LOAD_INITIATIONS || heap_low
    }

    fn reply_on(&mut self, cx: &mut Cx<'_>, slot: usize, from: &From<'_>, n: usize) {
        let Some(m) = self.members[slot].as_ref() else { return };
        let ok = match from {
            From::Udp(ep) => cx.out.emit(Out::SendUdp { member: m.rt.id, dst: *ep, data: &self.sh.ctl[..n] }),
            From::Derp(k) => {
                // the answer goes to the region the peer is homed on, which is not necessarily the one its packet came in by
                let region = m.mship.table.iter().find(|(_, p)| p.public_key == **k).map_or(0, |(i, _)| crate::tx::peer_region(m, i));
                cx.out.emit(Out::DerpSend { member: m.rt.id, dst: k, region, data: &self.sh.ctl[..n] })
            }
        };
        match (ok, from) {
            (true, From::Udp(_)) => self.sh.stats.udp_tx.bump(),
            (true, From::Derp(_)) => self.sh.stats.derp_tx.bump(),
            (false, _) => self.sh.stats.out_refused.bump(),
        }
    }

    fn rx_initiation(&mut self, cx: &mut Cx<'_>, slot: usize, from: From<'_>, data: &mut [u8]) -> RxFate {
        let now = cx.now;
        let under_load = self.under_load(slot, now);
        if under_load {
            self.sh.stats.under_load_screens.bump();
        }
        let mut src = [0u8; 32];
        let sn = from.mac_source(&mut src);
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        match screen(&m.rt.identity, &mut m.rt.cookie, data, &src[..sn], under_load, now, cx.rng) {
            Screen::Pass => {}
            Screen::CookieReply(r) => {
                self.sh.ctl[..r.len()].copy_from_slice(&r);
                self.sh.stats.cookie_tx.bump();
                self.reply_on(cx, slot, &from, r.len());
                return RxFate::WgCookie;
            }
            Screen::Drop(d) => return self.wg_hs_drop(slot, d),
        }
        let Ok(msg) = Initiation::parse(data) else { return self.wg_hs_drop(slot, Dropped::ParseLength) };
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let st = match m.rt.identity.consume_initiation_stage1(&msg) {
            Ok(st) => st,
            Err(d) => return self.wg_hs_drop(slot, d),
        };
        let pk = st.peer_public().0;
        // the peer: resident, or a trial activation for a directory peer (ADR 0012's amendment: one trial, token bucket, cool-down)
        let idx = match m.mship.table.by_key(&pk) {
            Some(i) => i,
            None => match self.activate_claim(cx, slot, &pk) {
                Some(i) => i,
                None => return self.wg_hs_drop(slot, Dropped::HsUnknownPeer),
            },
        };
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let owner = OwnerId(m.rt.slot);
        let Some(sl) = m.rt.slot_of[idx].and_then(|s| self.sh.pool.get_mut(owner, s)) else { return self.wg_hs_drop(slot, Dropped::HsUnknownPeer) };
        let Some(cold) = sl.cold.as_ref() else { return self.wg_hs_drop(slot, Dropped::HsUnknownPeer) };
        if let Err(d) = sl.hot.consume_initiation(&st, cold, now) {
            return self.wg_hs_drop(slot, d);
        }
        if let Some(p) = m.mship.table.get_mut(idx) {
            p.jit_used_ms = now;
        }
        let drawn = self.sh.pool.generate_unique_index(&mut cx.rng);
        let Some(sl) = m.rt.slot_of[idx].and_then(|s| self.sh.pool.get_mut(owner, s)) else { return RxFate::WgHandshakeDropped };
        let Some(cold) = sl.cold.as_ref() else { return RxFate::WgHandshakeDropped };
        match sl.hot.create_response(&m.rt.identity, cold, now, cx.rng, &mut crate::slot::PreDrawn::new(drawn)) {
            Ok(resp) => {
                self.sh.ctl[..resp.len()].copy_from_slice(&resp);
                self.sh.stats.hs_resp_tx.bump();
                self.reply_on(cx, slot, &from, resp.len());
                RxFate::WgInitiation
            }
            Err(_) => self.wg_hs_drop(slot, Dropped::HsNoHandshake),
        }
    }

    fn wg_hs_drop(&mut self, slot: usize, d: Dropped) -> RxFate {
        if let Some(m) = self.members[slot].as_mut() {
            m.rt.wg_drops.bump(d);
        }
        RxFate::WgHandshakeDropped
    }

    fn rx_response(&mut self, cx: &mut Cx<'_>, slot: usize, from: From<'_>, data: &mut [u8]) -> RxFate {
        let now = cx.now;
        let mut src = [0u8; 32];
        let sn = from.mac_source(&mut src);
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        match screen(&m.rt.identity, &mut m.rt.cookie, data, &src[..sn], false, now, cx.rng) {
            Screen::Pass => {}
            Screen::CookieReply(_) => return RxFate::WgHandshakeDropped,
            Screen::Drop(d) => return self.wg_hs_drop(slot, d),
        }
        let Ok(msg) = Response::parse(data) else { return self.wg_hs_drop(slot, Dropped::ParseLength) };
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let owner = OwnerId(m.rt.slot);
        let Some(dev) = self.sh.pool.lookup_by_handshake(owner, msg.receiver) else { return self.wg_hs_drop(slot, Dropped::HsNoHandshake) };
        let Some(idx) = m.mship.table.by_wg_slot(dev) else { return self.wg_hs_drop(slot, Dropped::HsNoHandshake) };
        let Some(sl) = self.sh.pool.get_mut(owner, dev) else { return self.wg_hs_drop(slot, Dropped::HsNoHandshake) };
        let Some(cold) = sl.cold.as_ref() else { return self.wg_hs_drop(slot, Dropped::HsNoHandshake) };
        match sl.hot.consume_response(&m.rt.identity, cold, &msg, now) {
            Ok(_) => {
                if let Some(p) = m.mship.table.get_mut(idx) {
                    p.jit_used_ms = now;
                }
                // the session is up: what was parked goes out first, then the confirming keepalive
                self.sh.flush_peer(m, idx, cx);
                self.sh.service_peer(m, idx, cx);
                self.trial_poll(cx, slot);
                RxFate::WgResponse
            }
            Err(d) => self.wg_hs_drop(slot, d),
        }
    }

    fn rx_cookie_reply(&mut self, cx: &mut Cx<'_>, slot: usize, data: &[u8]) -> RxFate {
        let Ok(reply) = CookieReply::parse(data) else { return self.wg_hs_drop(slot, Dropped::ParseLength) };
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let owner = OwnerId(m.rt.slot);
        let Some(dev) = self.sh.pool.lookup_by_handshake(owner, reply.receiver) else { return self.wg_hs_drop(slot, Dropped::CookieUnexpected) };
        let Some(sl) = self.sh.pool.get_mut(owner, dev) else { return self.wg_hs_drop(slot, Dropped::CookieUnexpected) };
        let Some(cold) = sl.cold.as_ref() else { return self.wg_hs_drop(slot, Dropped::CookieUnexpected) };
        match sl.hot.consume_cookie_reply(cold, &reply, cx.now) {
            Ok(()) => RxFate::WgCookie,
            Err(d) => self.wg_hs_drop(slot, d),
        }
    }

    // ---- WireGuard transport -------------------------------------------------------------------------------------------------------------------

    fn rx_transport(&mut self, cx: &mut Cx<'_>, slot: usize, data: &mut [u8]) -> RxFate {
        let now = cx.now;
        let Ok(h) = TransportHeader::parse(data) else { return RxFate::WgDataDropped };
        let Some(m) = self.members[slot].as_mut() else { return RxFate::NoMember };
        let owner = OwnerId(m.rt.slot);
        let wg = &mut m.rt.wg_drops;
        let Some(dev) = self.sh.pool.lookup_by_receiver(owner, h.receiver) else {
            wg.bump(Dropped::NoSession);
            return RxFate::WgDataDropped;
        };
        let Some(idx) = m.mship.table.by_wg_slot(dev) else {
            wg.bump(Dropped::NoSession);
            return RxFate::WgDataDropped;
        };
        let Some(sl) = self.sh.pool.get_mut(owner, dev) else {
            wg.bump(Dropped::NoSession);
            return RxFate::WgDataDropped;
        };
        let out = match sl.hot.decrypt(data, now) {
            Ok(o) => o,
            Err(d) => {
                wg.bump(d);
                return RxFate::WgDataDropped;
            }
        };
        if let Some(p) = m.mship.table.get_mut(idx) {
            p.jit_used_ms = now;
        }
        if !out.keepalive {
            m.rt.wg_bytes[idx][1] = m.rt.wg_bytes[idx][1].saturating_add(out.plain_len as u32);
        }
        if out.confirmed {
            // a responder session just came up: send what waited for it
            self.sh.flush_peer(m, idx, cx);
        }
        let fate = if out.keepalive {
            RxFate::WgKeepalive
        } else {
            let end = 16 + out.plain_len;
            let allowed = data.len() >= end
                && end >= 36
                && m.mship.table.get(idx).is_some_and(|p| src_allowed(p, u32::from_be_bytes([data[28], data[29], data[30], data[31]])));
            if !allowed && end >= 36 && data.len() >= end {
                RxFate::WgNotAllowed
            } else if data.len() < end {
                RxFate::WgDataDropped
            } else {
                match self.sh.router.tunnel_packet(m.rt.id, &mut data[16..end], now) {
                    TunnelOutcome::ToHost { len, .. } => {
                        let ok = cx.out.emit(Out::HostPacket { data: &data[16..16 + len] });
                        self.sh.router.tx_result(tdongle_tailnet_router::Dir::ToHost, ok);
                        if ok { RxFate::WgDelivered } else { RxFate::HostTxRefused }
                    }
                    TunnelOutcome::Dropped(_) => RxFate::WgRouterDrop,
                }
            }
        };
        self.sh.service_peer(m, idx, cx);
        self.trial_poll(cx, slot);
        fate
    }

    // ---- activation helpers --------------------------------------------------------------------------------------------------------------------

    /// An inbound handshake claims to be from the directory peer with WireGuard key `key`: trial activation (`derp_sender_admit` with a plausible initiation).
    pub(crate) fn activate_claim(&mut self, cx: &mut Cx<'_>, slot: usize, key: &[u8; 32]) -> Option<usize> {
        let now = cx.now;
        let mut others = [Resident { member: 0, peer: 0, cand: Default::default() }; 32];
        let n = residents_of_others(&self.members, slot, &mut others);
        let m = self.members[slot].as_mut()?;
        let Member { mship, rt } = m;
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
            plausible: true,
        };
        let idx = mship.derp_sender_admit(&mut host, now, key)?;
        let rec = self.sh.dir.find_by_key(slot, key)?;
        self.finish_activation(cx, slot, idx, &rec).ok()
    }

    /// The trial peer may have authenticated (or expired): `directory_trial_poll`.
    pub(crate) fn trial_poll(&mut self, cx: &mut Cx<'_>, slot: usize) {
        let now = cx.now;
        let mut others = [Resident { member: 0, peer: 0, cand: Default::default() }; 32];
        let n = residents_of_others(&self.members, slot, &mut others);
        let Some(m) = self.members[slot].as_mut() else { return };
        let Member { mship, rt } = m;
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
        mship.trial_poll(&mut host, now);
    }

    /// A directory record became resident at table index `idx`: carry out the evictions the arbiter decided on in other memberships, take the
    /// WireGuard slot, start the DISCO path. On failure the peer is removed again. Idempotent for a peer that was already resident.
    pub(crate) fn finish_activation(&mut self, cx: &mut Cx<'_>, slot: usize, idx: usize, rec: &DirRecord) -> Result<usize, ()> {
        if let Some((om, op)) = self.sh.pending_evict.take() {
            self.evict_remote(usize::from(om), usize::from(op));
        }
        let Some(m) = self.members[slot].as_mut() else { return Err(()) };
        let fresh = m.rt.ip_of[idx] == 0;
        if self.sh.ensure_slot(m, idx, cx.now).is_err() {
            if let Some(w) = m.mship.table.remove(idx) {
                crate::shared::release_peer_state(&mut m.rt, &mut self.sh.pool, &mut self.sh.store, &mut self.sh.stats, idx, w);
            }
            return Err(());
        }
        if fresh {
            m.rt.ip_of[idx] = rec.vpn_ip;
            self.sh.path_added(m, idx, rec, cx);
        }
        Ok(idx)
    }

    /// Remove a peer of another membership (the arbiter's victim).
    pub(crate) fn evict_remote(&mut self, slot: usize, idx: usize) {
        let Some(m) = self.members.get_mut(slot).and_then(Option::as_mut) else { return };
        if let Some(w) = m.mship.table.remove(idx) {
            crate::shared::release_peer_state(&mut m.rt, &mut self.sh.pool, &mut self.sh.store, &mut self.sh.stats, idx, w);
        }
    }
}
