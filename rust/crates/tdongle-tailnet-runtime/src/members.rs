//! The member supervisor: the registry (persisted through `Storage` exactly as the C: JSON string `members` in namespace `tn_settings`), the identities
//! (`tn_%08x` / `identity_v1`), admission before a start, and the start / stop / enable / disable / remove reconciliation in the order ADR 0013 fixes.
//!
//! # Who does what
//!
//! * [`apply_action`] (the `TailnetApi::member_action` body, **synchronous**, from the HTTP task) validates and persists through
//!   `tdongle_tailnet_members::apply` and does the part of a stop that must not wait: `MemberDisabled` to the engine (the router is suspended and the
//!   WireGuard slots released before the call returns) and the slot's run state set to stopped (control, DERP and UDP tasks cancel themselves).
//! * [`supervisor`] (the task) starts what the registry says should run (one membership at a time under the negotiation token, admission measured with the
//!   token held), finalises stops (waits for the slot's tasks to be gone, `MemberRemoved`, wipes the secrets, frees the slot), drops the provisioning key
//!   once a membership joined, and retries refused starts every 10 s (the C's manager period).
//!
//! The ADR 0013 stop order, as implemented: (1) engine `MemberDisabled`: router unpublished and the slots released; (2) the slot's tasks stop (their
//! futures are dropped: sockets closed, token keys released); (3) engine `MemberRemoved` (nothing of the membership is left, `MemberGone`); (4) secrets
//! zeroed and the slot freed; (5) for a removal, the identity namespace erased (done synchronously by the action, the keys already being in RAM).

use crate::identity::{IdentityError, load_or_generate};
use crate::shared::{RtStats, Shared, SlotRun, SlotState};
use crate::token::{key_control, key_derp};
use core::sync::atomic::Ordering;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Timer;
use tdongle_tailnet_admission::adm::{Params, Provisional, SharedSizes, Verdict};
use tdongle_tailnet_admission::negotiation::{Phase, Prio};
use tdongle_tailnet_engine::{Input, MemberConfig, PeerDirectory};
use tdongle_tailnet_fw::{MemberAction, Platform, Reply, Storage, StorageError};
use tdongle_tailnet_members::command::text;
use tdongle_tailnet_members::{CText, MemberIo, apply};
use tdongle_tailnet_types::FixedStr;

/// The settings namespace and the registry's key.
pub const SETTINGS_NAMESPACE: &str = "tn_settings";
/// The key of the member list (a JSON string).
pub const MEMBERS_KEY: &str = "members";
/// How long a refused start waits before the supervisor tries again (the C's manager period).
pub const RETRY_MS: u64 = 10_000;
/// How long the start path waits for the negotiation token (the C: 1,500 ms; a busy token is a retryable refusal, not a failure).
pub const TOKEN_WAIT_MS: u32 = 1500;

/// Read the stored member list into the registry. A fresh install (no key) is an empty registry; anything else that fails marks the settings damaged
/// (tailnet access is then refused with the recovery text, as the C does when `load_members` fails).
pub fn load_registry<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) {
    sh.registry.lock(|c| {
        let mut c = c.borrow_mut();
        let c = &mut *c;
        if c.loaded {
            return;
        }
        let r = sh.with_scratch(|scratch| {
            let got = sh.storage.lock(|s| s.borrow_mut().get(SETTINGS_NAMESPACE, MEMBERS_KEY, &mut scratch[..]));
            let r = match got {
                Ok(n) => c.reg.load_stored(Some(&scratch[..n])).is_ok(),
                Err(StorageError::NotFound) => c.reg.load_stored(None).is_ok(),
                Err(_) => false,
            };
            zero(&mut scratch[..]);
            r
        });
        c.loaded = true;
        c.damaged = !r;
    });
}

fn zero(b: &mut [u8]) {
    use zeroize::Zeroize;
    b.zeroize();
}

/// `MemberIo` over the shared state: what the setup page's actions do beyond the registry itself.
struct ActionIo<'a, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    damaged: bool,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> MemberIo for ActionIo<'_, R, P, S, D> {
    fn recovery(&self) -> bool {
        self.damaged
    }
    fn persist(&mut self, json: &[u8]) -> bool {
        let ok = self.sh.storage.lock(|s| s.borrow_mut().set(SETTINGS_NAMESPACE, MEMBERS_KEY, json)).is_ok();
        if !ok {
            RtStats::bump(&self.sh.stats.storage_failures);
        }
        ok
    }
    fn has_client(&self, id: u32) -> bool {
        self.sh.slot_of(id).is_some()
    }
    fn stop(&mut self, id: u32) -> bool {
        request_stop(self.sh, id)
    }
    fn forget(&mut self, _id: u32) {
        // the engine forgets the membership when the supervisor finalises the stop (`MemberRemoved` after the tasks are gone)
    }
    fn erase_identity(&mut self, namespace: &[u8]) -> bool {
        match core::str::from_utf8(namespace) {
            Ok(ns) => self.sh.storage.lock(|s| s.borrow_mut().erase_namespace(ns)).is_ok(),
            Err(_) => false,
        }
    }
    fn refresh_dns(&mut self) {
        // the engine's DNS view reads the memberships directly
    }
}

/// The synchronous half of a stop. `false` only when an earlier stop of the same membership is still finishing (the C's "retry shortly").
pub fn request_stop<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, id: u32) -> bool {
    let Some((_, slot)) = sh.slot_of(id) else { return true };
    match slot.status().state {
        SlotState::Free => true,
        SlotState::Stopping => false,
        SlotState::Starting | SlotState::Running => {
            // 1. suspend the router, release the WireGuard slots, drop parked packets
            let _ = sh.feed(Input::MemberDisabled { member: id });
            slot.update(|st| st.state = SlotState::Stopping);
            // 2. stop what feeds it
            let epoch = sh.epoch.fetch_add(1, Ordering::Relaxed);
            slot.run.sender().send(SlotRun { epoch, id: 0 });
            sh.supervisor_kick.signal(());
            true
        }
    }
}

/// `TailnetApi::member_action`: the C's `command()` under its lock, with the stop split as described in the module docs.
pub fn apply_action<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, action: &MemberAction) -> Reply {
    // an action that beats the supervisor's first pass loads the list itself
    if !sh.registry.lock(|c| c.borrow().loaded) {
        load_registry(sh);
    }
    let reply = sh.registry.lock(|c| {
        let mut c = c.borrow_mut();
        let c = &mut *c;
        if !c.loaded {
            return Reply::busy();
        }
        let mut io = ActionIo { sh, damaged: c.damaged };
        sh.with_scratch(|scratch| apply(&mut c.reg, action, &mut io, &mut scratch[..]))
    });
    sh.supervisor_kick.signal(());
    reply
}

/// What the supervisor needs of a registry entry (copied out so the lock is not held while it waits).
#[derive(Clone)]
struct Wanted {
    id: u32,
    label: CText<20>,
    key: CText<159>,
    hostname: CText<47>,
    namespace: CText<11>,
}

/// Why a start did not happen.
enum Refusal {
    /// Not an error: the network is not up (the C returns silently).
    Offline,
    /// Retry later, with this text on the setup page.
    Text(&'static str),
}

fn set_error<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, id: u32, text: &str) {
    sh.registry.lock(|c| {
        if let Some(m) = c.borrow_mut().reg.get_mut(id) {
            m.set_error(text);
        }
    });
}

fn clear_error<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, id: u32) {
    sh.registry.lock(|c| {
        if let Some(m) = c.borrow_mut().reg.get_mut(id) {
            m.error.clear();
        }
    });
}

/// The admission parameters of the Rust runtime (`Params::rust`): see `sizes::member_sizes` for what a membership is charged and
/// `Config::charge_static_bytes` for why that is off by default.
pub fn admission_params<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) -> Params {
    let ms = if sh.cfg.charge_static_bytes { crate::sizes::member_sizes(sh) } else { Default::default() };
    let shared = SharedSizes { executor_bytes: if sh.cfg.charge_static_bytes { crate::sizes::shared_bytes(sh) } else { 0 } };
    Params::rust(&ms, tdongle_tailnet_engine::slot::WgSlot::BYTES, &shared, &Provisional { tls_live: 0, lwip: 0, other: 0 })
}

async fn try_start<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, w: &Wanted) -> Result<(), Refusal> {
    let online = sh.link.try_get().is_some_and(|l| l.up && l.v4.is_some());
    if !online {
        return Err(Refusal::Offline);
    }
    if sh.slot_of(w.id).is_some() {
        return Ok(());
    }
    let Some(idx) = sh.free_slot() else {
        RtStats::bump(&sh.stats.admission_refused);
        return Err(Refusal::Text(text::NO_ROOM));
    };
    // The token first: another membership's negotiation moves free memory by its peak, so a reading taken beside it would lie (ml_negotiation.h).
    let key = key_control(w.id);
    if sh.token.acquire(&sh.platform, key, Prio::Start, Phase::Start, Some(TOKEN_WAIT_MS)).await.is_err() {
        return Err(Refusal::Text(text::WAITING_FOR_JOIN));
    }
    let release = |sh: &Shared<R, P, S, D>| {
        sh.token.release(sh.now(), key);
    };
    // admission: free heap (plus what waits in the receive budget, which the next pass returns), the largest block
    let running = sh.slots.iter().any(|s| s.st.lock(|st| st.borrow().state != SlotState::Free));
    let budget = admission_params(sh).budget(running);
    let heap = sh.platform.heap().snapshot();
    let queued = sh.with_engine(|e, _| e.rx_budget().queued() as usize);
    let verdict = budget.decide(heap.free + queued, heap.largest);
    let active = sh.slots.iter().filter(|s| s.st.lock(|st| st.borrow().state != SlotState::Free)).count() as u32;
    sh.adm_log.lock(|l| {
        l.borrow_mut().push(tdongle_tailnet_status::diag::AdmissionRecord {
            uptime_ms: sh.now() as u32,
            member_id: w.id,
            free_bytes: heap.free as u32,
            largest_bytes: heap.largest as u32,
            budget_bytes: budget.required as u32,
            sockets_open: 0,
            sockets_limit: crate::shared::MAX_RUN as u32,
            active,
            verdict: match verdict {
                Verdict::Ok => 0,
                Verdict::RefusedBudget => 1,
                Verdict::RefusedLargest => 2,
            },
        })
    });
    if verdict != Verdict::Ok {
        RtStats::bump(&sh.stats.admission_refused);
        release(sh);
        return Err(Refusal::Text(text::NOT_ENOUGH_MEMORY));
    }
    // the identity (generated and saved when absent)
    let id = match sh.storage.lock(|s| {
        let mut rng = crate::shared::PlatformRng(&sh.platform);
        load_or_generate(&mut *s.borrow_mut(), w.namespace.as_str().unwrap_or(""), &mut rng)
    }) {
        Ok(i) => i,
        Err(e) => {
            if matches!(e, IdentityError::Storage(_)) {
                RtStats::bump(&sh.stats.storage_failures);
            }
            release(sh);
            return Err(Refusal::Text(text::IDENTITY_FAILED));
        }
    };
    RtStats::bump(if id.generated { &sh.stats.identities_generated } else { &sh.stats.identities_loaded });
    RtStats::bump(&sh.stats.admitted);
    let slot = &sh.slots[idx];
    slot.ident.lock(|i| {
        let mut i = i.borrow_mut();
        i.id = w.id;
        i.label = w.label;
        i.hostname = w.hostname;
        i.auth_key = w.key;
        i.machine = id.machine.clone();
        i.wg = id.wg.clone();
        i.disco = id.disco.clone();
    });
    slot.udp_q.clear();
    slot.derp_q.clear();
    slot.derp_cmd.reset();
    slot.update(|st| st.reset(SlotState::Starting, w.id));
    slot.id.store(w.id, Ordering::Release);
    // charged from here on, so that a stop that arrives while the start is still going (the API runs on another task, possibly another core) finds
    // everything it has to give back
    for (owner, bytes) in crate::shared::member_charges::<D>() {
        sh.ledger.alloc(owner, bytes);
    }
    let mut label = FixedStr::new();
    label.set(w.label.as_str().unwrap_or(""));
    let cfg = MemberConfig {
        id: w.id,
        node_private: id.wg.clone(),
        disco_private: id.disco.clone(),
        label,
        priority_peer_ip: 0,
        persistent_keepalive_s: 0,
        enabled: true,
    };
    let _ = sh.feed(Input::MemberAdded(&cfg));
    // Running only if no stop got in between; if one did, it has already set Stopping and sent the stop (`request_stop`), and the supervisor's next pass
    // finalises the slot (`MemberRemoved`, ledger, secrets): the tasks are never started.
    let started = slot.update(|st| {
        let ok = st.state == SlotState::Starting;
        if ok {
            st.state = SlotState::Running;
        }
        ok
    });
    if started {
        let epoch = sh.epoch.fetch_add(1, Ordering::Relaxed);
        // from here the control task holds the token (same key) and releases it after the first map
        slot.run.sender().send(SlotRun { epoch, id: w.id });
    }
    Ok(())
}

/// Finish the stops: the slot's tasks are gone, so nothing feeds the membership any more.
fn finalize_stops<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) {
    for slot in &sh.slots {
        let st = slot.status();
        if st.state != SlotState::Stopping || slot.alive.load(Ordering::Acquire) != 0 {
            continue;
        }
        let id = st.id;
        // 3. nothing of the membership is left in the engine
        let _ = sh.feed(Input::MemberRemoved { member: id });
        let now = sh.now();
        sh.token.release(now, key_control(id));
        sh.token.release(now, key_derp(id));
        slot.udp_q.clear();
        slot.derp_q.clear();
        slot.derp_cmd.reset();
        // 4. secrets zeroed, slot free
        slot.ident.lock(|i| i.borrow_mut().wipe());
        for (owner, bytes) in crate::shared::member_charges::<D>() {
            sh.ledger.free(owner, bytes);
        }
        // a membership that was published ready and is stopped before the engine said otherwise must not stay counted (the carrier follows the count)
        if slot.update(|s| core::mem::replace(&mut s.ready, false)) {
            sh.ready_count.fetch_sub(1, Ordering::AcqRel);
            sh.carrier_kick.signal(());
        }
        slot.update(|s| s.reset(SlotState::Free, 0));
        slot.id.store(0, Ordering::Release);
    }
}

/// After a membership joined the provisioning key is spent: drop it from the registry and the slot (`manager()` in the C).
fn drop_spent_keys<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) {
    for slot in &sh.slots {
        let st = slot.status();
        if st.state != SlotState::Running || !st.joined {
            continue;
        }
        let id = st.id;
        // Also while the last save failed (`KEY_CLEANUP`): the C clears the key in RAM first and never saves again, leaving the key in flash for good;
        // here the save is retried on every pass until it sticks.
        let had = sh.registry.lock(|c| c.borrow().reg.get(id).is_some_and(|m| !m.key().is_empty() || m.error.as_bytes() == text::KEY_CLEANUP.as_bytes()));
        if !had {
            continue;
        }
        let saved = sh.registry.lock(|c| {
            let mut c = c.borrow_mut();
            let c = &mut *c;
            c.reg.clear_key(id);
            let ok = sh.with_scratch(|scratch| {
                let ok = match c.reg.encode(&mut scratch[..]) {
                    Ok(n) => sh.storage.lock(|s| s.borrow_mut().set(SETTINGS_NAMESPACE, MEMBERS_KEY, &scratch[..n])).is_ok(),
                    Err(_) => false,
                };
                zero(&mut scratch[..]);
                ok
            });
            if let Some(m) = c.reg.get_mut(id) {
                if ok {
                    if m.error.as_bytes() == text::KEY_CLEANUP.as_bytes() {
                        m.error.clear();
                    }
                } else {
                    m.set_error(text::KEY_CLEANUP);
                }
            }
            ok
        });
        if !saved {
            RtStats::bump(&sh.stats.storage_failures);
        }
        slot.ident.lock(|i| i.borrow_mut().auth_key.clear());
    }
}

/// The supervisor task. Never returns.
pub async fn supervisor<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) {
    load_registry(sh);
    // seed the run watches so a receiver's first `get` returns at once
    for slot in &sh.slots {
        slot.run.sender().send(SlotRun { epoch: 0, id: 0 });
    }
    let mut retry_at = [(0u32, 0u64); tdongle_tailnet_members::MAX_MEMBERS];
    loop {
        let now = sh.now();
        sh.token.reap(now);
        finalize_stops(sh);
        drop_spent_keys(sh);
        // collect what should run
        let mut want: [Option<Wanted>; MAX_START_PER_PASS] = [const { None }; MAX_START_PER_PASS];
        let damaged = sh.registry.lock(|c| {
            let c = c.borrow();
            let mut n = 0;
            if !c.damaged {
                for m in c.reg.iter() {
                    if m.enabled && sh.slot_of(m.id).is_none() && n < want.len() {
                        want[n] = Some(Wanted {
                            id: m.id,
                            label: CText::from_bytes(m.label()),
                            key: CText::from_bytes(m.key()),
                            hostname: m.hostname(),
                            namespace: m.namespace(),
                        });
                        n += 1;
                    }
                }
            }
            c.damaged
        });
        let _ = damaged;
        for w in want.iter().flatten() {
            let due = retry_at.iter().find(|(i, _)| *i == w.id).is_none_or(|(_, t)| *t <= now);
            if !due {
                continue;
            }
            match try_start(sh, w).await {
                Ok(()) => {
                    clear_error(sh, w.id);
                    forget_retry(&mut retry_at, w.id);
                }
                Err(Refusal::Offline) => {}
                Err(Refusal::Text(t)) => {
                    set_error(sh, w.id, t);
                    note_retry(&mut retry_at, w.id, sh.now() + RETRY_MS);
                }
            }
        }
        let _ = select(sh.supervisor_kick.wait(), Timer::after_millis(1000)).await;
    }
}

/// Starts attempted per pass (one per free slot is the most that can succeed).
const MAX_START_PER_PASS: usize = crate::shared::MAX_RUN;

fn note_retry(t: &mut [(u32, u64)], id: u32, at: u64) {
    let at_idx = t.iter().position(|(i, _)| *i == id).or_else(|| t.iter().position(|(i, _)| *i == 0));
    if let Some(i) = at_idx {
        t[i] = (id, at);
    }
}

fn forget_retry(t: &mut [(u32, u64)], id: u32) {
    if let Some(e) = t.iter_mut().find(|(i, _)| *i == id) {
        *e = (0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetV4;
    use crate::shared::LinkView;
    use crate::testutil::{Sh, TestStorage, shared, shared_with};
    use futures::executor::block_on;
    use std::string::ToString;
    use std::sync::atomic::Ordering as O;
    use tdongle_tailnet_admission::ledger::Owner;

    fn online(sh: &Sh) {
        let v4 = NetV4 { addr: [192, 168, 1, 50], prefix: 24, gateway: Some([192, 168, 1, 1]), dns: Some([192, 168, 1, 1]) };
        sh.link.sender().send(LinkView { generation: 1, up: true, v4: Some(v4) });
    }

    fn add(sh: &Sh, label: &str) -> u32 {
        assert_eq!(apply_action(sh, &MemberAction::add(label.as_bytes(), b"tskey-abc")).error, None);
        sh.registry.lock(|c| c.borrow().reg.iter().find(|m| m.label() == label.as_bytes()).unwrap().id)
    }

    fn wanted(sh: &Sh, id: u32) -> Wanted {
        sh.registry.lock(|c| {
            let c = c.borrow();
            let m = c.reg.get(id).unwrap();
            Wanted { id, label: CText::from_bytes(m.label()), key: CText::from_bytes(m.key()), hostname: m.hostname(), namespace: m.namespace() }
        })
    }

    fn ledger_live(sh: &Sh) -> u32 {
        Owner::ALL.iter().map(|o| sh.ledger.owner(*o).live).sum()
    }

    #[test]
    fn a_fresh_install_has_no_members_and_actions_load_the_list_themselves() {
        let sh = shared();
        // no supervisor has run: the first action loads
        let id = add(&sh, "work");
        assert_eq!(id, 1);
        let stored = sh.storage.lock(|s| {
            let mut buf = [0u8; 512];
            let n = s.borrow_mut().get(SETTINGS_NAMESPACE, MEMBERS_KEY, &mut buf).unwrap();
            std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
        });
        assert_eq!(stored, r#"{"members":[{"id":1,"label":"work","key":"tskey-abc","enabled":true}],"next_id":2}"#);
        assert_eq!(apply_action(&sh, &MemberAction::add(b"work", b"k")).error, Some(text::LABEL_TAKEN));
        assert_eq!(apply_action(&sh, &MemberAction::add(b"bad label", b"k")).error, Some(text::LABEL_CHARS));
        assert_eq!(apply_action(&sh, &MemberAction::Remove(9)).error, Some(text::NOT_FOUND));
    }

    #[test]
    fn a_stored_list_is_restored_and_a_damaged_one_puts_the_gateway_in_recovery() {
        let st = TestStorage::default();
        st.map.lock().unwrap().insert(
            (SETTINGS_NAMESPACE.to_string(), MEMBERS_KEY.to_string()),
            br#"{"members":[{"id":4,"label":"a","key":"k","enabled":false}],"next_id":5}"#.to_vec(),
        );
        let sh = shared_with(st);
        load_registry(&sh);
        assert_eq!(sh.registry.lock(|c| (c.borrow().reg.len(), c.borrow().damaged)), (1, false));
        assert_eq!(apply_action(&sh, &MemberAction::Enable(4)).error, None);
        let bad = TestStorage::default();
        bad.map.lock().unwrap().insert((SETTINGS_NAMESPACE.to_string(), MEMBERS_KEY.to_string()), b"{not json".to_vec());
        let sh = shared_with(bad);
        load_registry(&sh);
        assert!(sh.registry.lock(|c| c.borrow().damaged));
        assert_eq!(apply_action(&sh, &MemberAction::add(b"x", b"k")).error, Some(text::RECOVERY));
    }

    #[test]
    fn a_failed_save_is_reported_and_rolled_back() {
        let st = TestStorage::default();
        let sh = shared_with(st.clone());
        st.fail.store(true, O::SeqCst);
        assert_eq!(apply_action(&sh, &MemberAction::add(b"x", b"k")).error, Some(text::ADD_NOT_SAVED));
        assert_eq!(sh.registry.lock(|c| c.borrow().reg.len()), 0);
        st.fail.store(false, O::SeqCst);
        let id = add(&sh, "x");
        st.fail.store(true, O::SeqCst);
        assert_eq!(apply_action(&sh, &MemberAction::Disable(id)).error, Some(text::CHANGE_NOT_SAVED));
        assert!(sh.registry.lock(|c| c.borrow().reg.get(id).unwrap().enabled), "unchanged");
        assert!(RtStats::get(&sh.stats.storage_failures) >= 2);
    }

    #[test]
    fn start_stop_remove_follow_the_adr_order_and_release_everything() {
        let sh = shared();
        online(&sh);
        let id = add(&sh, "lab");
        let w = wanted(&sh, id);
        assert_eq!(ledger_live(&sh), 0);
        // start: token (phase A) held for the control task, slot running, engine has the membership, ledger charged
        assert!(block_on(try_start(&sh, &w)).is_ok());
        let (idx, slot) = sh.slot_of(id).expect("a slot runs it");
        assert_eq!(slot.status().state, SlotState::Running);
        assert!(sh.token.holds(key_control(id)), "the hand-over: the start path's token is the control task's");
        assert!(sh.with_engine(|e, _| e.member(id).is_some()));
        assert_eq!(slot.run.try_get(), Some(SlotRun { epoch: slot.run.try_get().unwrap().epoch, id }));
        let charged: usize = crate::shared::member_charges::<crate::testutil::Dir>().iter().map(|c| c.1).sum();
        assert_eq!(ledger_live(&sh) as usize, charged);
        let secrets = slot.ident.lock(|i| (i.borrow().wg.is_zero(), i.borrow().auth_key.as_bytes().to_vec()));
        assert_eq!(secrets, (false, b"tskey-abc".to_vec()));
        assert_eq!(sh.storage.lock(|s| s.borrow_mut().get("tn_00000001", "identity_v1", &mut [0u8; 97])), Ok(96), "identity_v1 saved in tn_%08x");
        // a second start of the same id is a no-op
        assert!(block_on(try_start(&sh, &w)).is_ok());
        assert_eq!(sh.slots.iter().filter(|s| s.id.load(O::SeqCst) == id).count(), 1);

        // disable: the sync half. The router is suspended and the run state says stop, but the slot is not free until its tasks are gone
        assert_eq!(apply_action(&sh, &MemberAction::Disable(id)).error, None);
        assert_eq!(slot.status().state, SlotState::Stopping);
        assert_eq!(slot.run.try_get().unwrap().id, 0);
        assert!(!request_stop(&sh, id), "a second stop while one is finishing is the C's retry-shortly");
        // tasks still alive: nothing is finalised
        slot.alive.store(crate::shared::ALIVE_DERP, O::SeqCst);
        finalize_stops(&sh);
        assert_eq!(slot.status().state, SlotState::Stopping);
        assert!(sh.with_engine(|e, _| e.member(id).is_some()));
        // the tasks drop their sockets and bits: finalised in order, secrets wiped, ledger back, token free, engine empty
        slot.alive.store(0, O::SeqCst);
        finalize_stops(&sh);
        assert_eq!(slot.status().state, SlotState::Free);
        assert_eq!(idx, sh.free_slot().unwrap(), "the slot is reusable");
        assert!(sh.with_engine(|e, _| e.member_count() == 0));
        assert_eq!(ledger_live(&sh), 0);
        assert_eq!(sh.ledger.underflows(), 0);
        assert!(!sh.token.holds(key_control(id)) && sh.token.status(sh.now()).holder == 0);
        assert_eq!(slot.ident.lock(|i| (i.borrow().id, i.borrow().wg.is_zero(), i.borrow().auth_key.len())), (0, true, 0));
        // remove: identity namespace erased synchronously by the action
        assert_eq!(apply_action(&sh, &MemberAction::Remove(id)).error, None);
        assert_eq!(sh.storage.lock(|s| s.borrow_mut().get("tn_00000001", "identity_v1", &mut [0u8; 97])), Err(StorageError::NotFound));
        assert_eq!(sh.registry.lock(|c| c.borrow().reg.len()), 0);
    }

    #[test]
    fn admission_refuses_for_memory_and_for_the_largest_block_without_leaving_anything() {
        let sh = shared();
        online(&sh);
        let id = add(&sh, "lab");
        let w = wanted(&sh, id);
        // not enough free heap: the budget (recovery 16,384 + one negotiation 13,500 + router floor 2,800 = 32,684 for the Rust task model)
        sh.platform.heap.free.store(30_000, O::SeqCst);
        let r = block_on(try_start(&sh, &w));
        assert!(matches!(r, Err(Refusal::Text(t)) if t == text::NOT_ENOUGH_MEMORY));
        // enough heap, fragmented: the largest-block rule
        sh.platform.heap.free.store(100_000, O::SeqCst);
        sh.platform.heap.largest.store(20_000, O::SeqCst);
        assert!(matches!(block_on(try_start(&sh, &w)), Err(Refusal::Text(t)) if t == text::NOT_ENOUGH_MEMORY));
        assert_eq!(RtStats::get(&sh.stats.admission_refused), 2);
        assert!(sh.slot_of(id).is_none());
        assert_eq!(ledger_live(&sh), 0);
        assert_eq!(sh.token.status(sh.now()).holder, 0, "the start path let go of the token");
        assert_eq!(sh.with_engine(|e, _| e.member_count()), 0);
        let mut recs = [tdongle_tailnet_status::diag::AdmissionRecord::default(); 8];
        let n = sh.adm_log.lock(|l| l.borrow().ordered(&mut recs));
        assert_eq!((n, recs[0].verdict, recs[1].verdict), (2, 1, 2), "refused_budget then refused_largest");
        // with memory back it starts
        sh.platform.heap.largest.store(24_576, O::SeqCst);
        assert!(block_on(try_start(&sh, &w)).is_ok());
        assert_eq!(recs[0].member_id, id);
    }

    #[test]
    fn offline_and_no_room_and_a_busy_token_are_retryable_refusals() {
        let sh = shared();
        let id = add(&sh, "lab");
        let w = wanted(&sh, id);
        assert!(matches!(block_on(try_start(&sh, &w)), Err(Refusal::Offline)), "no link: silent");
        online(&sh);
        // another membership holds the token
        let other = key_control(99);
        assert!(sh.token.request(sh.now(), other, Prio::Start, Phase::Control) == tdongle_tailnet_admission::negotiation::Grant::Granted);
        assert!(matches!(block_on(try_start(&sh, &w)), Err(Refusal::Text(t)) if t == text::WAITING_FOR_JOIN));
        assert_eq!(sh.token.status(sh.now()).waiting, 0, "the failed wait left the queue");
        sh.token.release(sh.now(), other);
        // every slot taken
        for s in &sh.slots {
            s.update(|st| st.state = SlotState::Running);
        }
        assert!(matches!(block_on(try_start(&sh, &w)), Err(Refusal::Text(t)) if t == text::NO_ROOM));
    }

    #[test]
    fn the_provisioning_key_is_dropped_once_joined_and_a_failed_save_says_so() {
        let st = TestStorage::default();
        let sh = shared_with(st.clone());
        online(&sh);
        let id = add(&sh, "lab");
        assert!(block_on(try_start(&sh, &wanted(&sh, id))).is_ok());
        let (_, slot) = sh.slot_of(id).unwrap();
        drop_spent_keys(&sh); // not joined yet: untouched
        assert!(!sh.registry.lock(|c| c.borrow().reg.get(id).unwrap().key().is_empty()));
        slot.update(|s| s.joined = true);
        st.fail.store(true, O::SeqCst);
        drop_spent_keys(&sh);
        assert_eq!(sh.registry.lock(|c| c.borrow().reg.get(id).unwrap().error.as_bytes().to_vec()), text::KEY_CLEANUP.as_bytes());
        st.fail.store(false, O::SeqCst);
        drop_spent_keys(&sh); // the key is already gone from RAM, but the save is retried (the C never retries)
        assert!(sh.registry.lock(|c| c.borrow().reg.get(id).unwrap().key().is_empty() && c.borrow().reg.get(id).unwrap().error.is_empty()));
        assert!(
            st.map
                .lock()
                .unwrap()
                .get(&(SETTINGS_NAMESPACE.to_string(), MEMBERS_KEY.to_string()))
                .is_some_and(|v| std::str::from_utf8(v).unwrap().contains(r#""key":"""#))
        );
        assert_eq!(slot.ident.lock(|i| i.borrow().auth_key.len()), 0);
    }

    #[test]
    fn identity_failures_are_reported_and_release_the_token() {
        let st = TestStorage::default();
        let sh = shared_with(st.clone());
        online(&sh);
        let id = add(&sh, "lab");
        st.fail.store(true, O::SeqCst);
        assert!(matches!(block_on(try_start(&sh, &wanted(&sh, id))), Err(Refusal::Text(t)) if t == text::IDENTITY_FAILED));
        assert_eq!(sh.token.status(sh.now()).holder, 0);
        assert_eq!(ledger_live(&sh), 0);
        // a damaged blob (wrong size) is the same refusal
        st.fail.store(false, O::SeqCst);
        st.map.lock().unwrap().insert(("tn_00000001".to_string(), "identity_v1".to_string()), std::vec![0u8; 95]);
        assert!(matches!(block_on(try_start(&sh, &wanted(&sh, id))), Err(Refusal::Text(t)) if t == text::IDENTITY_FAILED));
    }

    #[test]
    fn retry_bookkeeping() {
        let mut t = [(0u32, 0u64); 3];
        note_retry(&mut t, 5, 100);
        note_retry(&mut t, 6, 200);
        note_retry(&mut t, 5, 300);
        assert_eq!(t, [(5, 300), (6, 200), (0, 0)]);
        forget_retry(&mut t, 5);
        assert_eq!(t[0], (0, 0));
    }
}
