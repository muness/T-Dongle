//! Port of tests/test_inbound_trial.c: activation on an unauthenticated claim buys no slot, no eviction and only bounded work, while a genuine
//! peer is still activated; the authenticated path (10 s idle window) is unchanged. WireGuard and the pool are test doubles.

use tdongle_tailnet_peers::PubKey;
use tdongle_tailnet_peers::membership::{Host, Membership, Room};
use tdongle_tailnet_peers::policy::VictimCandidate;
use tdongle_tailnet_peers::record::DirRecord;
use tdongle_tailnet_peers::table::ML_MAX_PEERS;

struct Dir {
    records: Vec<DirRecord>,
    authenticated: [bool; 8],
    initiation_valid: bool,
    pool_ok: bool,
    removals: u32,
    signers: Vec<PubKey>,
    boxes_opened: u32,
}

impl Host for Dir {
    fn directory_by_key(&mut self, key: &PubKey) -> Option<DirRecord> {
        self.records.iter().find(|r| r.public_key == *key).cloned()
    }
    fn directory_by_disco(&mut self, key: &PubKey) -> Option<DirRecord> {
        self.records.iter().find(|r| r.disco_key == *key).cloned()
    }
    fn pool_reserve(&mut self, _idle_ms: u64, _own: &[(u8, VictimCandidate)]) -> Room {
        if self.pool_ok { Room::Free } else { Room::Refused }
    }
    fn peer_removed(&mut self, _i: usize, _slot: Option<u8>) {
        self.removals += 1;
    }
    fn wg_authenticated(&mut self, i: usize) -> bool {
        self.authenticated[i]
    }
    fn initiation_plausible(&mut self) -> bool {
        self.initiation_valid
    }
    fn disco_authenticates(&mut self, key: &PubKey, _nonce: &[u8; 24], _len: usize) -> bool {
        self.boxes_opened += 1;
        self.signers.contains(key)
    }
}

fn key(id: u32) -> PubKey {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&id.to_le_bytes());
    k
}
fn record(id: u32) -> DirRecord {
    let mut r = DirRecord { vpn_ip: 0x6440_0000 + id, node_id: u64::from(id), has_node_id: true, public_key: key(id), ..DirRecord::default() };
    r.disco_key = key(id);
    r.disco_key[31] = 1;
    r
}

fn world() -> (Membership, Dir) {
    let mut m = Membership::new();
    m.session_valid = true;
    (
        m,
        Dir {
            records: (1..=40).map(record).collect(),
            authenticated: [false; 8],
            initiation_valid: true,
            pool_ok: true,
            removals: 0,
            signers: Vec::new(),
            boxes_opened: 0,
        },
    )
}

fn resident(m: &Membership) -> usize {
    m.table.len()
}

fn fill(m: &mut Membership, first: u32, count: u32, used: u64) {
    for i in 0..count {
        let idx = m.table.insert(&record(first + i), 0).expect("room");
        m.table.get_mut(idx).unwrap().jit_used_ms = used;
    }
}

#[test]
fn forged_derp_key_that_is_not_an_initiation_never_reaches_the_directory() {
    let (mut m, mut h) = world();
    h.initiation_valid = false;
    for i in 1..=40 {
        assert!(m.derp_sender_admit(&mut h, 100_000, &key(i)).is_none());
    }
    assert!(resident(&m) == 0 && m.trial.started == 0 && m.trial.pending == 0);
}

#[test]
fn plausible_initiation_naming_an_unknown_key_is_refused() {
    let (mut m, mut h) = world();
    assert!(m.derp_sender_admit(&mut h, 100_000, &key(9999)).is_none());
    assert!(resident(&m) == 0 && m.trial.pending == 0);
}

#[test]
fn forged_initiation_for_a_real_peer_gets_a_trial_not_standing() {
    let (mut m, mut h) = world();
    let mut now = 100_000;
    let idx = m.derp_sender_admit(&mut h, now, &key(5)).unwrap();
    assert!(m.table.get(idx).unwrap().unconfirmed && usize::from(m.trial.pending) == idx + 1 && m.trial.started == 1);
    // While it is pending no other unknown key gets in, however plausible.
    assert!(m.derp_sender_admit(&mut h, now, &key(6)).is_none());
    assert!(resident(&m) == 1 && m.trial.refused >= 1);
    // WireGuard never authenticates it: it is removed at the deadline, the slot is free, and a cool-down follows.
    now += 4999;
    m.trial_poll(&mut h, now);
    assert_eq!(resident(&m), 1);
    now += 1;
    m.trial_poll(&mut h, now);
    assert!(resident(&m) == 0 && h.removals == 1 && m.trial.expired == 1 && m.trial.pending == 0);
    now += 1000;
    assert!(m.derp_sender_admit(&mut h, now, &key(6)).is_none() && resident(&m) == 0, "cool-down");
    now += 29_000;
    let idx = m.derp_sender_admit(&mut h, now, &key(6)).unwrap();
    assert!(m.table.get(idx).unwrap().unconfirmed, "the cool-down is over");
}

#[test]
fn the_genuine_peer_is_confirmed_and_kept() {
    let (mut m, mut h) = world();
    let mut now = 100_000;
    let idx = m.derp_sender_admit(&mut h, now, &key(7)).unwrap();
    assert!(m.table.get(idx).unwrap().unconfirmed);
    h.authenticated[idx] = true;
    m.trial_poll(&mut h, now);
    assert!(!m.table.get(idx).unwrap().unconfirmed && m.trial.pending == 0 && m.trial.confirmed == 1);
    now += 60_000;
    m.trial_poll(&mut h, now);
    assert!(m.table.get(idx).is_some(), "never expires");
    assert!(m.derp_sender_admit(&mut h, now, &key(8)).is_some(), "slot free for the next");
    assert_eq!(m.derp_sender_admit(&mut h, now, &key(7)), Some(idx), "resident: no trial");
}

#[test]
fn a_forged_key_never_evicts_a_warm_peer() {
    // all hot
    let (mut m, mut h) = world();
    let now = 100_000;
    fill(&mut m, 1, 8, now - 1000);
    assert!(m.derp_sender_admit(&mut h, now, &key(20)).is_none() && resident(&m) == 8 && h.removals == 0);
    // idle 20 s: evictable for the host, not for a claim
    let (mut m, mut h) = world();
    fill(&mut m, 1, 8, now - 20_000);
    assert!(m.derp_sender_admit(&mut h, now, &key(20)).is_none() && resident(&m) == 8 && h.removals == 0);
    // idle a minute: one cold peer may go
    let (mut m, mut h) = world();
    fill(&mut m, 1, 8, now - 61_000);
    m.table.get_mut(3).unwrap().jit_used_ms = now - 90_000;
    let idx = m.derp_sender_admit(&mut h, now, &key(20)).unwrap();
    assert!(idx == 3 && h.removals == 1 && resident(&m) == 8);
    assert!(m.table.get(idx).unwrap().unconfirmed);
    // the authenticated path is unchanged
    let (mut m, mut h) = world();
    fill(&mut m, 1, 8, now - 1000);
    let u = record(20);
    assert!(m.activate(&mut h, now, &u).is_none());
    for i in 0..8 {
        m.table.get_mut(i).unwrap().jit_used_ms = now - 20_000;
    }
    assert!(m.activate(&mut h, now, &u).is_some() && h.removals == 1);
    assert_eq!((m.stats.misses, m.stats.rejected, m.stats.evictions), (2, 1, 1));
}

#[test]
fn the_priority_peer_is_never_the_victim_of_a_trial() {
    let (mut m, mut h) = world();
    let now = 100_000;
    fill(&mut m, 1, 8, now - 90_000);
    m.priority_peer_ip = record(1).vpn_ip;
    let idx = m.derp_sender_admit(&mut h, now, &key(30)).unwrap();
    assert!(idx != 0 && m.table.get(0).is_some());
}

#[test]
fn lookups_an_unauthenticated_packet_can_cause_are_budgeted() {
    let (mut m, mut h) = world();
    let mut now = 100_000;
    for i in 0..3 {
        assert!(m.derp_sender_admit(&mut h, now, &key(9000 + i)).is_none());
    }
    assert!(m.trial.refused == 0 && m.trial.tokens == 0, "three lookups reached the directory");
    assert!(m.derp_sender_admit(&mut h, now, &key(5)).is_none() && m.trial.refused == 1, "even a real key waits");
    now += 1000;
    assert!(m.derp_sender_admit(&mut h, now, &key(5)).is_some(), "one token back");
}

#[test]
fn disco_a_forged_sender_is_dropped_before_it_can_activate_anything() {
    let (mut m, mut h) = world();
    let now = 100_000;
    let u = record(12);
    let nonce = [0u8; 24];
    assert!(m.disco_admit(&mut h, now, &u.disco_key, &nonce, 32).is_none(), "nobody signed it");
    assert!(resident(&m) == 0 && h.boxes_opened == 1);
    h.signers.push(u.disco_key);
    let idx = m.disco_admit(&mut h, now, &u.disco_key, &nonce, 32).unwrap();
    assert!(m.table.get(idx).is_some() && !m.table.get(idx).unwrap().unconfirmed);
    h.boxes_opened = 0;
    assert_eq!(m.disco_admit(&mut h, now, &u.disco_key, &nonce, 32), Some(idx));
    assert_eq!(h.boxes_opened, 0, "resident: no new crypto");
    let mut stranger = [0u8; 32];
    stranger[0] = 255;
    assert!(m.disco_admit(&mut h, now, &stranger, &nonce, 32).is_none() && h.boxes_opened == 0);
    assert_eq!(m.disco_admit(&mut h, now, &u.disco_key, &nonce, 8), Some(idx), "short input is only refused for strangers");

    // authentic, but no slot for it
    let (mut m, mut h) = world();
    fill(&mut m, 1, 8, now - 1000);
    h.signers.push(record(12).disco_key);
    assert!(m.disco_admit(&mut h, now, &record(12).disco_key, &nonce, 32).is_none() && resident(&m) == 8 && h.removals == 0);

    // forged DISCO flood: only the burst reaches crypto
    let (mut m, mut h) = world();
    for i in 0..10 {
        assert!(m.disco_admit(&mut h, now, &record(11 + i).disco_key, &nonce, 32).is_none());
    }
    assert!(h.boxes_opened == 3 && resident(&m) == 0);
}

#[test]
fn no_session_no_activation_and_a_pool_refusal_is_a_rejection() {
    let (mut m, mut h) = world();
    m.session_valid = false;
    assert!(m.activate(&mut h, 1000, &record(1)).is_none());
    assert_eq!(m.stats.misses, 0, "not even counted");
    m.session_valid = true;
    h.pool_ok = false;
    assert!(m.activate(&mut h, 1000, &record(1)).is_none() && m.stats.rejected == 1);
    h.pool_ok = true;
    let i = m.activate(&mut h, 1000, &record(1)).unwrap();
    assert_eq!(m.activate(&mut h, 2000, &record(1)), Some(i));
    assert_eq!((m.stats.hits, m.table.get(i).unwrap().jit_used_ms), (1, 2000));
    assert_eq!(ML_MAX_PEERS, 8);
}

#[test]
fn table_lookups_are_by_key_ip_disco_node_and_slot() {
    let (mut m, mut h) = world();
    fill(&mut m, 1, 8, 0);
    let _ = &mut h;
    for id in 1..=8u32 {
        let r = record(id);
        let i = m.table.by_key(&r.public_key).unwrap();
        assert_eq!(m.table.by_ip(r.vpn_ip), Some(i));
        assert_eq!(m.table.by_disco_key(&r.disco_key), Some(i));
        assert_eq!(m.table.by_node_id(u64::from(id)), Some(i));
    }
    assert_eq!((m.table.by_key(&key(99)), m.table.by_ip(5), m.table.by_node_id(0), m.table.by_node_id(77)), (None, None, None, None));
    m.table.get_mut(4).unwrap().wg_slot = Some(6);
    assert_eq!(m.table.by_wg_slot(6), Some(4));
    assert_eq!(m.table.by_wg_slot(5), None);
    assert!(m.table.is_full() && m.table.insert(&record(50), 0).is_none());
    assert_eq!(m.table.remove(4), Some(Some(6)));
    assert_eq!(m.table.remove(4), None);
    assert_eq!(m.table.by_key(&record(5).public_key), None);
    assert_eq!(m.table.insert(&record(50), 0), Some(4), "the first free entry");
}
