//! The pure rules a peer directory applies to staged [`PeerRecord`]s (the C's `ml_directory.c`: `same`, `apply`, the three commit passes), without any
//! storage. A flash directory, a RAM table and the tests' model all use these, so they cannot drift apart.

use tdongle_tailnet_types::Key32;

use crate::types::{Group, PeerAction, PeerRecord};

/// Does `existing` (a stored record) denote the same peer as `update`? By node id when the update has one, else by node key (`same()`).
pub fn same_peer(existing: &PeerRecord, update: &PeerRecord) -> bool {
    match (existing.node_id, update.node_id) {
        (Some(a), Some(b)) if a == b => true,
        _ => update.node_id.is_none() && existing.node_key == update.node_key,
    }
}

/// The commit pass of a record: all `Add`s first, then `Remove`s, then patches, whatever order the root fields arrived in ("preserve operation order
/// regardless of root field order").
pub fn commit_pass(action: PeerAction) -> u8 {
    match action {
        PeerAction::Add => 0,
        PeerAction::Remove => 1,
        PeerAction::Patch => 2,
    }
}

/// Is a staged record of `group` applied at commit? `Changed` records are superseded when the same map carried a full `Peers` list (`authoritative`).
pub fn is_effective(group: Group, authoritative: bool) -> bool {
    !(authoritative && group == Group::Changed)
}

/// A record slot with `vpn_ip == 0` is empty to the directory (the C's `!old.vpn_ip`), so a peer without an IPv4 address is never stored.
pub fn is_storable(record: &PeerRecord) -> bool {
    record.vpn_ip != 0
}

/// Apply a [`PeerAction::Patch`] to the stored record (`apply()`'s `ML_PEER_UPDATE_ENDPOINT` branch): a non-zero key, a non-zero disco key, present
/// endpoints, a non-zero DERP region and a known online state replace the stored ones; everything else is kept. The result is an `Add`.
pub fn merge_update(old: &PeerRecord, update: &PeerRecord) -> PeerRecord {
    let mut v = old.clone();
    if !update.node_key.is_zero() {
        v.node_key = update.node_key.clone();
    }
    if !update.disco_key.is_zero() {
        v.disco_key = update.disco_key.clone();
    }
    if update.endpoints_present {
        v.endpoint_count = update.endpoint_count;
        v.endpoints = update.endpoints;
    }
    if update.home_derp != 0 {
        v.home_derp = update.home_derp;
    }
    if update.online.is_some() {
        v.online = update.online;
    }
    if update.key_expiry != 0 {
        v.key_expiry = update.key_expiry;
    }
    if update.cap != 0 {
        v.cap = update.cap;
    }
    v.action = PeerAction::Add;
    v
}

/// The key a `Remove` by key carries is all zero when it was by node id.
pub fn removes_by_key(update: &PeerRecord) -> Option<&Key32> {
    (update.action == PeerAction::Remove && update.node_id.is_none()).then_some(&update.node_key)
}
