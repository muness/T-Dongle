//! `TailnetApi` for [`Shared`]: what the image's setup HTTP server and console call.
//!
//! * `member_action`: [`crate::members::apply_action`].
//! * `render_status`: the `/status` JSON of the C, byte-compatible in structure (the `tdongle-tailnet-status` writer) from the engine's [`StatusSnapshot`]
//!   (through the engine's `status_map` helpers) and the slots' published state. **Fields the image owns** (chip temperature, power, the Wi-Fi link
//!   JSON, saved Wi-Fi networks, reset reason, the radio's pin accounting) are left at their defaults here: a `StatusExtras` hook for them is an open
//!   point (see the crate docs). The peer list is the first page only (the `peer_offset` / `peer_member` query is not passed through the seam).
//! * `serial_command`: `route`, `members`, `inbound`, `memory` (heap only) as the one-line JSON reports of `tdongle_tailnet_status::diag`.
//! * `serial_status_extra`: the tailnet lines the Android app does not parse (new lines only).
//! * `counts`: for the LCD.

use crate::shared::{Shared, SlotState};
use crate::sizes;
use core::sync::atomic::Ordering;
use embassy_sync::blocking_mutex::raw::RawMutex;
use tdongle_tailnet_admission::adm::Budget;
use tdongle_tailnet_admission::heap::{ML_HB_FLOOR, ML_HB_RESERVE};
use tdongle_tailnet_admission::negotiation::Phase;
use tdongle_tailnet_engine::status_map;
use tdongle_tailnet_engine::{PeerDirectory, StatusSnapshot};
use tdongle_tailnet_fw::{ChunkSink, MemberAction, MemberCounts, Platform, Reply, Storage, TailnetApi};
use tdongle_tailnet_status::diag::{self, Command};
use tdongle_tailnet_status::glue::{ML_MAX_PEERS, protocol_error, routing_ready};
use tdongle_tailnet_status::input as si;
use tdongle_tailnet_status::{JsonWriter, write_status};

const MEMBERS: usize = tdongle_tailnet_members::MAX_MEMBERS;

/// One registry entry as `/status` shows it (the secrets are not copied).
#[derive(Clone, Copy)]
struct Entry {
    id: u32,
    label: [u8; 21],
    enabled: bool,
    error: [u8; 64],
}

fn cbytes(b: &[u8; 21]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(21)]
}

fn ebytes(b: &[u8; 64]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(64)]
}

fn neg_phase(p: Phase) -> si::NegPhase {
    match p {
        Phase::None => si::NegPhase::None,
        Phase::Start => si::NegPhase::Start,
        Phase::Control => si::NegPhase::Control,
        Phase::Derp => si::NegPhase::Derp,
    }
}

/// The C's `ml_state_t` of a membership from what the slot publishes.
fn control_state(st: &crate::shared::SlotStatus) -> u32 {
    match st.state {
        SlotState::Free | SlotState::Stopping => 0,
        _ if st.connected => 4,
        _ if st.control_stage >= 5 => 3,
        _ if st.control_stage >= 1 => 2,
        _ => 5,
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Shared<R, P, S, D> {
    fn registry_entries(&self) -> ([Entry; MEMBERS], usize, bool) {
        self.registry.lock(|c| {
            let c = c.borrow();
            let mut out = [Entry { id: 0, label: [0; 21], enabled: false, error: [0; 64] }; MEMBERS];
            let mut n = 0;
            for m in c.reg.iter().take(MEMBERS) {
                out[n].id = m.id;
                let l = m.label();
                out[n].label[..l.len().min(20)].copy_from_slice(&l[..l.len().min(20)]);
                out[n].enabled = m.enabled;
                let e = m.error.as_bytes();
                out[n].error[..e.len().min(63)].copy_from_slice(&e[..e.len().min(63)]);
                n += 1;
            }
            (out, n, c.damaged)
        })
    }

    fn budget(&self) -> Budget {
        let running = self.slots.iter().any(|s| s.st.lock(|st| st.borrow().state != SlotState::Free));
        crate::members::admission_params(self).budget(running)
    }

    /// The engine's snapshot (the one the `/status` and the serial reports read).
    pub fn snapshot(&self) -> StatusSnapshot<{ crate::shared::MAX_RUN }> {
        self.with_engine(|e, now| e.status(now))
    }

    fn fill_status(&self, f: &mut dyn FnMut(&si::Status<'_>) -> bool) -> bool {
        let snap = self.snapshot();
        let (entries, n_entries, damaged) = self.registry_entries();
        let slots: [crate::shared::SlotStatus; crate::shared::MAX_RUN] = core::array::from_fn(|i| self.slots[i].status());
        let heap = self.platform.heap().snapshot();
        let now = self.now();
        let link = self.link.try_get();
        let neg = self.token.status(now);
        let budget = self.budget();
        let params = crate::members::admission_params(self);

        // peers of each running membership: the first page
        let mut names = [[[0u8; 64]; ML_MAX_PEERS]; crate::shared::MAX_RUN];
        let mut addrs = [[0u32; ML_MAX_PEERS]; crate::shared::MAX_RUN];
        let mut counts = [0usize; crate::shared::MAX_RUN];
        self.with_engine(|e, _| {
            for (slot, m) in snap.members.iter().enumerate() {
                if m.is_none() {
                    continue;
                }
                let total = e.dir().count(slot);
                let mut k = 0;
                for i in 0..total {
                    if k == ML_MAX_PEERS {
                        break;
                    }
                    if let Some((name, addr)) = e.dir().peer_view(slot, i) {
                        let b = name.as_bytes();
                        let n = b.len().min(63);
                        names[slot][k][..n].copy_from_slice(&b[..n]);
                        addrs[slot][k] = addr;
                        k += 1;
                    }
                }
                counts[slot] = k;
            }
        });
        let peers: [[si::Peer<'_>; ML_MAX_PEERS]; crate::shared::MAX_RUN] =
            core::array::from_fn(|s| core::array::from_fn(|k| si::Peer { name: cstr(&names[s][k]), address: addrs[s][k] }));

        let mut members = [si::Member::default(); MEMBERS];
        for (i, e) in entries.iter().take(n_entries).enumerate() {
            let slot = self.slots.iter().position(|s| s.id.load(Ordering::Acquire) == e.id);
            let st = slot.map(|s| &slots[s]);
            let est = slot.and_then(|s| snap.members[s]);
            let err = if !ebytes(&e.error).is_empty() { ebytes(&e.error) } else { st.map_or(&b""[..], |s| s.last_error.as_str().as_bytes()) };
            let client = st.map(|s| {
                let mut c = si::Client {
                    login_url: s.auth_url.as_str().as_bytes(),
                    protocol_error: protocol_error(s.last_error.as_str().as_bytes(), b""),
                    control_stage: s.control_stage,
                    derp_state: s.derp_state.name().as_bytes(),
                    frames_rx: s.derp.frames_rx.get(),
                    frames_tx: s.derp.frames_tx.get(),
                    record_timeouts: s.derp.rx_timeouts.get(),
                    write_stalls: s.derp.tx_stalls.get(),
                    connects: s.derp.connects.get(),
                    derp_tls_verify_failures: s.tls_untrusted,
                    derp_tls_deferred: s.tls_deferred,
                    control_key_auth: u32::from(s.ctl.challenge_seen),
                    stack_free: [u32::MAX; 5],
                    ..si::Client::default()
                };
                c.diagnostics[0] = s.sessions;
                c.diagnostics[1] = s.sessions.saturating_sub(u32::from(s.joined));
                c.diagnostics[2] = s.map_error;
                c.diagnostics[3] = s.ctl.map_bytes as u32;
                c.diagnostics[11] = s.noise_error;
                c.diagnostics[13] = s.ctl.maps;
                if let Some(m) = &est {
                    status_map::fill_client(&mut c, m);
                    let sl = slot.unwrap_or(0);
                    c.peers = &peers[sl][..counts[sl]];
                    c.next_peer_offset = counts[sl] as u32;
                }
                c
            });
            members[i] = si::Member {
                id: e.id,
                start_heap_before: 0,
                start_heap_after: 0,
                label: cbytes(&e.label),
                enabled: e.enabled,
                error: err,
                state: st.map_or(0, control_state),
                routing_ready: st.is_some_and(|s| {
                    routing_ready(e.enabled, s.state == SlotState::Running, s.connected, s.key_expired, s.last_error.is_empty(), est.is_some_and(|m| m.ready))
                }),
                client,
            };
        }

        let running = slots.iter().any(|s| s.state != SlotState::Free);
        let status = si::Status {
            firmware: self.cfg.firmware.as_bytes(),
            mode: b"tailnet",
            recovery: damaged,
            membership_start_budget: budget.required as u64,
            membership_context_bytes: params.context as u64,
            admission: si::Admission {
                required: budget.required as u32,
                shared_runtime: budget.shared_runtime as u32,
                member_start: budget.member_start as u32,
                member_growth: budget.member_growth as u32,
                member_steady: budget.member_steady as u32,
                negotiation: budget.negotiation as u32,
                recovery: budget.recovery as u32,
                largest_block: budget.largest_block as u32,
                peer_slots_charged: tdongle_tailnet_admission::adm::ML_ADM_PEER_SLOTS,
                peer_slot_bytes: tdongle_tailnet_engine::slot::WgSlot::BYTES as u32,
            },
            shared_runtime: si::SharedRuntime {
                running,
                members: slots.iter().filter(|s| s.state != SlotState::Free).count() as u32,
                starts: crate::shared::RtStats::get(&self.stats.admitted),
                negotiation: si::Negotiation {
                    holder: (neg.holder != 0).then(|| neg_phase(neg.phase)),
                    held_ms: neg.held_ms,
                    waiting: neg.waiting,
                    grants: neg.grants,
                    timeouts: neg.timeouts,
                    lease_expired: neg.lease_expired,
                    stale_dropped: neg.stale_dropped,
                    refused_full: neg.refused_full,
                    max_wait_ms: neg.max_wait_ms,
                    max_hold_ms: neg.max_hold_ms,
                },
                ..si::SharedRuntime::default()
            },
            wg_pool: status_map::wg_pool(&snap, 0),
            wifi: link.is_some_and(|l| l.up),
            clock: si::Clock {
                state: if self.clock_valid.load(Ordering::Relaxed) { b"valid" } else { b"unset" },
                valid: self.clock_valid.load(Ordering::Relaxed),
                ..si::Clock::default()
            },
            route_storage_ok: !damaged,
            free_memory: heap.free as u32,
            largest_free_block: heap.largest as u32,
            minimum_free_memory: heap.minimum as u32,
            heap_budget: status_map::heap_budget(&snap, crate::shared::RtStats::get(&self.stats.usb_tx_refused)),
            members: &members[..n_entries],
            ..si::Status::default()
        };
        f(&status)
    }
}

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// A `ChunkSink` over `core::fmt::Write` (the serial reports are text).
struct FmtSink<'a>(&'a mut dyn core::fmt::Write);

impl ChunkSink for FmtSink<'_> {
    fn chunk(&mut self, bytes: &[u8]) -> bool {
        self.0.write_str(core::str::from_utf8(bytes).unwrap_or("")).is_ok()
    }
}

impl<R, P, S, D> TailnetApi for Shared<R, P, S, D>
where
    R: RawMutex + Sync,
    P: Platform + Sync,
    S: Storage + Send,
    D: PeerDirectory + Send,
{
    fn member_action(&self, action: &MemberAction) -> Reply {
        crate::members::apply_action(self, action)
    }

    fn render_status(&self, sink: &mut dyn ChunkSink) -> bool {
        self.fill_status(&mut |s| write_status(sink, s))
    }

    fn serial_command(&self, line: &str, out: &mut dyn core::fmt::Write) -> bool {
        let Some(cmd) = Command::parse(line.as_bytes()) else { return false };
        let mut sink = FmtSink(out);
        let mut w = JsonWriter::new(&mut sink);
        match cmd {
            Command::Route => {
                let snap = self.snapshot();
                diag::write_route(&mut w, &snap.router);
            }
            Command::Members => {
                let mut recs = [tdongle_tailnet_status::diag::AdmissionRecord::default(); 8];
                let n = self.adm_log.lock(|l| l.borrow().ordered(&mut recs));
                diag::write_phases(&mut w, &[]);
                diag::write_admission(&mut w, ML_HB_FLOOR as u32, false, self.snapshot().arbiter.0, &recs[..n]);
            }
            Command::Inbound => {
                let (queued, peak) = self.with_engine(|e, _| (e.rx_budget().queued(), e.rx_budget().peak()));
                let i = diag::Inbound {
                    wg_rx_queue_bytes: tdongle_tailnet_admission::wg_rx::ML_WG_RX_QUEUE_BYTES,
                    wg_rx_bytes_queued: queued,
                    wg_rx_bytes_peak: peak,
                    ..diag::Inbound::default()
                };
                diag::write_inbound(&mut w, &i);
            }
            Command::Memory => {
                let h = self.platform.heap().snapshot();
                diag::write_heap(
                    &mut w,
                    &diag::Heap {
                        uptime_ms: self.now(),
                        firmware: self.cfg.firmware.as_bytes(),
                        free: h.free as u64,
                        min: h.minimum as u64,
                        largest: h.largest as u64,
                        guard_floor: ML_HB_RESERVE as u64,
                        owners: {
                            let mut o = [diag::OwnerStats::default(); 8];
                            for (i, ow) in tdongle_tailnet_admission::ledger::Owner::ALL.iter().enumerate() {
                                let st = self.ledger.owner(*ow);
                                o[i] =
                                    diag::OwnerStats { live: st.live, peak: st.peak, allocs: st.allocs, frees: st.frees, failed: st.failed, denied: st.denied };
                            }
                            o
                        },
                        ..diag::Heap::default()
                    },
                );
            }
            // diagnostics-image commands the runtime has nothing to say about; the image's dispatcher answers them (or not)
            _ => return false,
        }
        let _ = w.flush();
        true
    }

    fn serial_status_extra(&self, out: &mut dyn core::fmt::Write) {
        let snap = self.snapshot();
        let neg = self.token.status(self.now());
        let _ = write!(
            out,
            "tailnet members={} ready={} pool={}/{} derp_refused={} token_grants={} token_waiting={}\r\n",
            snap.members.iter().flatten().count(),
            self.ready_count.load(Ordering::Relaxed),
            snap.pool.used,
            snap.pool.capacity,
            snap.heap_refused[1],
            neg.grants,
            neg.waiting
        );
        for st in self.slots.iter().map(|s| s.status()).filter(|s| s.state != SlotState::Free) {
            let _ = write!(
                out,
                "tailnet member={} state={} derp={} udp_port={} err={:?}\r\n",
                st.id,
                control_state(&st),
                st.derp_state.name(),
                st.udp_port,
                st.last_error.as_str()
            );
        }
    }

    fn counts(&self) -> MemberCounts {
        let (_, n, _) = self.registry_entries();
        let enabled = self.registry.lock(|c| c.borrow().reg.iter().filter(|m| m.enabled).count());
        let snap = self.snapshot();
        let connected = self.slots.iter().filter(|s| s.st.lock(|st| st.borrow().connected)).count();
        let tunnels: u32 = snap.members.iter().flatten().map(|m| u32::from(m.sessions)).sum();
        MemberCounts { configured: n as u8, enabled: enabled as u8, connected: connected as u8, tunnels: tunnels.min(255) as u8 }
    }
}

/// The names the memory table uses for the figures [`sizes`] reports (kept next to the API so the console and the tests print the same labels).
pub const SIZE_LABELS: [&str; sizes::FUTURES] = sizes::FUTURE_NAMES;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetV4;
    use crate::shared::LinkView;
    use crate::testutil::{Sh, shared};
    use std::string::String;

    fn status_json(sh: &Sh) -> serde_json::Value {
        let mut body = String::new();
        let mut sink = |b: &[u8]| {
            body.push_str(core::str::from_utf8(b).unwrap());
            true
        };
        assert!(TailnetApi::render_status(sh, &mut sink));
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("/status is not JSON ({e}): {body}"))
    }

    #[test]
    fn status_is_json_with_the_c_keys_and_reports_members_and_admission() {
        let sh = shared();
        sh.link.sender().send(LinkView { generation: 1, up: true, v4: Some(NetV4 { addr: [10, 0, 0, 2], prefix: 24, gateway: None, dns: None }) });
        let v = status_json(&sh);
        assert_eq!(v["mode"], "tailnet");
        assert_eq!(v["firmware"], "tdongle-rs");
        assert_eq!(v["recovery"], false);
        assert_eq!(v["wifi"], true);
        assert_eq!(v["members"].as_array().unwrap().len(), 0);
        assert_eq!(v["free_memory"], 106_000);
        assert_eq!(v["admission"]["recovery_reserve_bytes"], 16_384);
        assert_eq!(v["admission"]["negotiation_reserve_bytes"], 13_500);
        assert!(v["admission"]["required_bytes"].as_u64().unwrap() > 32_000);
        assert_eq!(v["membership_start_budget"], v["admission"]["required_bytes"]);
        assert_eq!(v["heap_budget"]["floor"], 29_884);
        // a member that was added but not started appears with its error text and no client
        assert_eq!(TailnetApi::member_action(&sh, &MemberAction::add(b"lab", b"tskey-x")).error, None);
        sh.registry.lock(|c| c.borrow_mut().reg.get_mut(1).unwrap().set_error("Waiting for another membership to finish joining"));
        let v = status_json(&sh);
        let m = &v["members"][0];
        assert_eq!((m["id"].as_u64(), m["label"].as_str(), m["enabled"].as_bool()), (Some(1), Some("lab"), Some(true)));
        assert_eq!(m["error"], "Waiting for another membership to finish joining");
        assert_eq!(m["routing_ready"], false);
        assert_eq!(TailnetApi::counts(&sh), MemberCounts { configured: 1, enabled: 1, connected: 0, tunnels: 0 });
    }

    #[test]
    fn serial_commands_are_the_one_line_reports_and_unknown_lines_are_left_alone() {
        let sh = shared();
        let mut out = String::new();
        assert!(TailnetApi::serial_command(&sh, "route", &mut out));
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!((v["schema"].as_u64(), v["kind"].as_str()), (Some(1), Some("route")));
        assert_eq!(v["queue_depth"], 16);
        for line in ["members", "inbound", "memory"] {
            let mut out = String::new();
            assert!(TailnetApi::serial_command(&sh, line, &mut out), "{line}");
            assert!(out.contains("\"kind\""), "{line}: {out}");
        }
        let mut out = String::new();
        assert!(!TailnetApi::serial_command(&sh, "wifi list", &mut out) && out.is_empty());
        assert!(!TailnetApi::serial_command(&sh, "cpu", &mut out), "diagnostics-image commands belong to the image's dispatcher");
        let mut extra = String::new();
        TailnetApi::serial_status_extra(&sh, &mut extra);
        assert!(extra.starts_with("tailnet members=0 ready=0 pool=0/12"), "{extra}");
    }
}
