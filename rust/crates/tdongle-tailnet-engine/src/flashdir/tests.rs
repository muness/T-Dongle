//! Host tests of the flash directory: a differential test against a `HashMap` model, LRU churn and pinning, a thousand peers, and power loss at every write.

extern crate std;

use super::*;
use std::collections::{HashMap, HashSet};
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;
use tdongle_tailnet_map::types::{Endpoint, Group};
use tdongle_tailnet_types::Key32;

// ---- the reference model ------------------------------------------------------------------------------------------------------------------------------

/// `directory::commit` on a map keyed by identity.
#[derive(Clone, Default, Debug)]
struct Model {
    recs: HashMap<Canon, DirRecord>,
    generation: u32,
}

impl Model {
    fn find_same(&self, u: &DirRecord) -> Option<DirRecord> {
        if u.has_node_id { self.recs.get(&Canon::Id(u.node_id)).cloned() } else { self.recs.values().find(|r| r.public_key == u.public_key).cloned() }
    }
    fn commit(&mut self, staged: &[(Action, u32, DirRecord)], auth: bool) {
        let mut cur = if auth { HashMap::new() } else { self.recs.clone() };
        for pass in 0..3 {
            for (action, group, u) in staged {
                if auth && *group == 6 {
                    continue;
                }
                let order = match action {
                    Action::Add => 0,
                    Action::Remove => 1,
                    Action::UpdateEndpoint => 2,
                };
                if order != pass {
                    continue;
                }
                let m = Model { recs: cur.clone(), generation: 0 };
                let found = if auth && *group == 2 && *action == Action::Add { cur.get(&Canon::of(u)).cloned() } else { m.find_same(u) };
                match (action, found) {
                    (Action::Add, f) => {
                        if let Some(e) = f {
                            cur.remove(&Canon::of(&e));
                        }
                        cur.insert(Canon::of(u), u.clone());
                    }
                    (Action::Remove, Some(e)) => {
                        cur.remove(&Canon::of(&e));
                    }
                    (Action::UpdateEndpoint, Some(e)) => {
                        let v = patch(e.clone(), u);
                        cur.remove(&Canon::of(&e));
                        cur.insert(Canon::of(&v), v);
                    }
                    _ => {}
                }
            }
        }
        self.recs = cur;
        self.generation += 1;
    }
}

fn enc(r: &DirRecord) -> [u8; RECORD_BYTES] {
    dirfmt::encode_record(r)
}

// ---- generators -----------------------------------------------------------------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// Peer `id`: ids up to `KEYED` have a node id, the others only a key (`directory::same` by key). Keys, addresses and DISCO keys follow from the id.
const KEYED: u64 = 30;
fn key_of(id: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&id.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    k[8] = 0xAA;
    k
}
fn ip_of(id: u64) -> u32 {
    0x6440_0000 + id as u32
}
fn add(id: u64, name: &str) -> PeerRecord {
    let mut r = PeerRecord::new(PeerAction::Add, Group::Peers);
    r.vpn_ip = ip_of(id);
    r.node_key = Key32(key_of(id));
    let mut d = key_of(id);
    d[9] = 0xD1;
    r.disco_key = Key32(d);
    r.node_id = (id <= KEYED).then_some(id);
    r.name.set(name);
    r.home_derp = 1;
    r.endpoints[0] = Endpoint { ip: 0xc633_6407, port: 41641 };
    r.endpoint_count = 1;
    r.endpoints_present = true;
    r
}
fn remove(id: u64) -> PeerRecord {
    let mut r = PeerRecord::new(PeerAction::Remove, Group::Removed);
    if id <= KEYED {
        r.node_id = Some(id);
    } else {
        r.node_key = Key32(key_of(id));
    }
    r
}
fn patch_of(id: u64, derp: u16, online: bool) -> PeerRecord {
    let mut r = PeerRecord::new(PeerAction::Patch, Group::Patch);
    if id <= KEYED {
        r.node_id = Some(id);
    } else {
        r.node_key = Key32(key_of(id));
    }
    r.home_derp = derp;
    r.online = Some(online);
    r
}
fn random_update(rng: &mut Rng, ids: u64) -> PeerRecord {
    let id = rng.next(ids) + 1;
    match rng.next(6) {
        0 => remove(id),
        1 | 2 => patch_of(id, rng.next(5) as u16 + 1, rng.next(2) == 0),
        n => {
            let mut r = add(id, &std::format!("h{id}-{}.tail.ts.net", rng.next(3)));
            if n == 5 {
                r.group = Group::Changed;
            }
            r
        }
    }
}

type D<const M: usize> = FlashDirectory<MemFlash, M, 8>;

/// A small partition (two memberships of 40 sectors: about 200 slots an area), so compaction runs often.
const SMALL: usize = 2 * 40 * SECTOR;

fn reboot<const M: usize, const C: usize>(d: FlashDirectory<MemFlash, M, C>) -> FlashDirectory<MemFlash, M, C> {
    let mut f = d.into_flash();
    f.power_on();
    let mut d = FlashDirectory::new(f);
    d.mount();
    d
}

/// Every lookup of `d` agrees with the model.
fn check<const M: usize, const C: usize>(d: &mut FlashDirectory<MemFlash, M, C>, m: usize, model: &Model, ids: u64, ctx: &str) {
    assert_eq!(d.count(m), model.recs.len(), "count, {ctx}");
    for id in 1..=ids {
        let want = model.recs.values().find(|r| r.vpn_ip == ip_of(id)).map(enc);
        assert_eq!(d.find_by_ip(m, ip_of(id)).map(|r| enc(&r)), want, "ip of {id}, {ctx}");
        let wk = model.recs.values().find(|r| r.public_key == key_of(id)).map(enc);
        assert_eq!(d.find_by_key(m, &key_of(id)).map(|r| enc(&r)), wk, "key of {id}, {ctx}");
        if let Some(r) = model.recs.values().find(|r| r.vpn_ip == ip_of(id)) {
            assert_eq!(d.find_by_disco(m, &r.disco_key).map(|r| enc(&r)), Some(enc(r)), "disco of {id}, {ctx}");
        }
    }
    let mut seen = HashSet::new();
    d.for_each_peer(m, &mut |name, info| {
        assert!(seen.insert(info.ip), "one line a peer, {ctx}");
        let r = model.recs.values().find(|r| r.vpn_ip == info.ip).unwrap_or_else(|| panic!("listed peer {:x} not in the model, {ctx}", info.ip));
        assert_eq!((name, info), (r.hostname.as_str(), info_of(r)));
        true
    });
    assert_eq!(seen.len(), model.recs.len(), "listing, {ctx}");
    for r in model.recs.values() {
        let label = first_label(r.hostname.as_str()).to_ascii_uppercase();
        let mut hit = false;
        assert!(d.for_each_named(m, &label, &mut |name, ip| hit |= ip == r.vpn_ip && name == r.hostname.as_str()));
        assert!(hit, "{} by name, {ctx}", r.hostname.as_str());
    }
}

fn stage_both<const M: usize, const C: usize>(d: &mut FlashDirectory<MemFlash, M, C>, staged: &mut Vec<(Action, u32, DirRecord)>, m: usize, u: &PeerRecord) {
    d.stage(m, u).unwrap();
    if !(u.action == PeerAction::Add && !is_storable(u)) {
        staged.push((action_of(u.action), u.group as u32, to_dir_record(u)));
    }
}

// ---- tests -----------------------------------------------------------------------------------------------------------------------------------------

#[test]
fn the_geometry_of_the_peerstore() {
    let g = Geometry::of(PEERSTORE_BYTES, 3).unwrap();
    assert_eq!((g.region, g.tx, g.area), (341, 85, 128));
    assert!(g.capacity() >= 1_300, "{g:?}");
    assert!(g.tx_slots() >= 1_300, "a full map of {} peers stages", g.tx_slots());
    assert!(g.slots * SLOT_BYTES + TABLES * g.buckets * BUCKET <= g.area * SECTOR);
    assert!(3 * g.region * SECTOR <= PEERSTORE_BYTES);
    let one = Geometry::of(PEERSTORE_BYTES, 1).unwrap();
    assert!(one.capacity() >= 3_900, "{one:?}");
}

#[test]
fn the_ram_footprint_is_fixed_and_small() {
    /// The firmware's flash is a unit value.
    struct Unit;
    impl DirFlash for Unit {
        fn read(&mut self, _: usize, _: &mut [u8]) -> bool {
            false
        }
        fn erase_sector(&mut self, _: usize) -> bool {
            false
        }
        fn write(&mut self, _: usize, _: &[u8]) -> bool {
            false
        }
        fn size(&self) -> usize {
            0
        }
    }
    let total = FlashDirectory::<Unit, 3, 8>::RAM_BYTES;
    let empty = FlashDirectory::<Unit, 3, 0>::RAM_BYTES;
    let per_entry = (total - empty) / 8;
    std::println!("flash directory RAM: {total} B for 3 memberships and a cache of 8 ({empty} B without the cache, {per_entry} B a cached record; DirRecord is {} B)", core::mem::size_of::<DirRecord>());
    assert!(total <= 3 * 1024, "{total} B");
    assert!(empty <= 512, "{empty} B");
}

#[test]
fn stage_commit_find_remove_patch() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    d.stage(0, &add(2, "alpha.tail.ts.net")).unwrap();
    d.stage(0, &add(3, "beta.tail.ts.net")).unwrap();
    assert!(d.find_by_ip(0, ip_of(2)).is_none(), "not visible before commit");
    d.commit(0, true).unwrap();
    assert_eq!(d.count(0), 2);
    assert!(d.find_by_key(0, &key_of(3)).is_some());
    assert!(d.find_by_ip(1, ip_of(2)).is_none(), "per membership");
    let mut named = Vec::new();
    assert!(d.for_each_named(0, b"BETA", &mut |n, ip| named.push((n.to_string(), ip))));
    assert_eq!(named, vec![("beta.tail.ts.net".to_string(), ip_of(3))]);
    d.stage(0, &add(2, "alpha.tail.ts.net")).unwrap();
    d.commit(0, true).unwrap();
    assert_eq!(d.count(0), 1, "an authoritative map that omits a peer removes it");
    assert!(d.find_by_ip(0, ip_of(3)).is_none());
    d.stage(0, &add(4, "gamma.tail.ts.net")).unwrap();
    d.commit(0, false).unwrap();
    assert_eq!(d.count(0), 2);
    d.stage(0, &remove(2)).unwrap();
    d.commit(0, false).unwrap();
    assert_eq!(d.count(0), 1);
    d.stage(0, &patch_of(4, 9, true)).unwrap();
    d.commit(0, false).unwrap();
    assert_eq!(d.find_by_ip(0, ip_of(4)).unwrap().derp_region, 9);
    assert_eq!(d.generation(0), 5);
    // an unchanged full map writes one slot: its commit
    let used = d.slots_used(0);
    let mut same = add(4, "gamma.tail.ts.net");
    same.home_derp = 9;
    same.online = Some(true);
    d.stage(0, &same).unwrap();
    d.commit(0, true).unwrap();
    assert_eq!(d.slots_used(0), used + 1);
    assert_eq!(d.count(0), 1);
}

#[test]
fn a_directory_survives_a_restart_and_a_cleared_one_does_not() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    for i in 1..=12 {
        d.stage(1, &add(i, "peer")).unwrap();
    }
    d.commit(1, true).unwrap();
    d.stage(1, &patch_of(5, 3, true)).unwrap();
    d.commit(1, false).unwrap();
    let generation = d.generation(1);
    let mut d = reboot(d);
    assert_eq!((d.count(1), d.generation(1)), (12, generation));
    assert_eq!(d.find_by_ip(1, ip_of(5)).unwrap().derp_region, 3);
    d.clear(1);
    assert_eq!(d.count(1), 0);
    let mut d = reboot(d);
    assert_eq!(d.mount(), 0, "cleared means gone at the next boot");
    assert!(d.find_by_ip(1, ip_of(5)).is_none());
    // and it works again
    d.stage(1, &add(7, "again")).unwrap();
    d.commit(1, true).unwrap();
    assert_eq!(reboot(d).count(1), 1);
}

/// Random streams of maps into the directory and into the model, with aborts, background maintenance (so compactions run and switch areas) and reboots.
#[test]
fn it_agrees_with_a_hashmap_model_on_random_maps() {
    let ids = 40;
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    let mut model = [Model::default(), Model::default()];
    let mut compactions = 0;
    for round in 0..600 {
        let m = rng.next(2) as usize;
        let auth = rng.next(4) == 0;
        let mut staged = Vec::new();
        for _ in 0..rng.next(14) {
            let u = random_update(&mut rng, ids);
            stage_both(&mut d, &mut staged, m, &u);
        }
        if auth {
            // a full map carries most of the peers
            for id in 1..=ids {
                if rng.next(5) != 0 {
                    let mut u = add(id, &std::format!("h{id}-{}.tail.ts.net", rng.next(2)));
                    if let Some(r) = model[m].recs.get(&if id <= KEYED { Canon::Id(id) } else { Canon::Key(key_of(id)) })
                        && rng.next(2) == 0
                    {
                        // unchanged
                        u.name.set(r.hostname.as_str());
                        u.home_derp = r.derp_region;
                        u.online = r.has_online.then_some(r.online);
                    }
                    stage_both(&mut d, &mut staged, m, &u);
                }
            }
        }
        if rng.next(12) == 0 {
            d.abort(m);
        } else {
            d.commit(m, auth).unwrap();
            model[m].commit(&staged, auth);
        }
        for _ in 0..rng.next(30) {
            d.maintain();
        }
        if rng.next(25) == 0 {
            compactions += d.stats().compactions;
            d = reboot(d);
        }
        if rng.next(150) == 0 {
            d.clear(m);
            model[m].recs.clear();
        }
        if round % 10 == 0 || round > 590 {
            for (k, model) in model.iter().enumerate() {
                check(&mut d, k, model, ids, &std::format!("round {round} member {k}"));
            }
        }
    }
    let s = d.stats();
    assert!(compactions + s.compactions >= 10, "compactions ran: {compactions} + {s:?}");
    assert_eq!((s.compactions_failed, s.commits_failed, s.flash_errors), (0, 0, 0), "{s:?}");
}

#[test]
fn the_cache_keeps_the_hot_peers_and_never_evicts_the_pinned_ones() {
    let mut d: FlashDirectory<MemFlash, 1, 4> = FlashDirectory::new(MemFlash::new(40 * SECTOR));
    for id in 1..=50 {
        d.stage(0, &add(id, "p")).unwrap();
    }
    d.commit(0, true).unwrap();
    d.pin(0, &[key_of(7), key_of(9)]);
    assert_eq!(d.pinned(0), 2);
    let mut rng = Rng(77);
    for _ in 0..2_000 {
        let id = rng.next(50) + 1;
        assert_eq!(d.find_by_ip(0, ip_of(id)).unwrap().vpn_ip, ip_of(id));
        assert!(d.cached() <= 4);
        assert_eq!(d.pinned(0), 2, "churn never evicts a pinned peer");
    }
    // the pinned ones are answered from RAM
    let before = d.stats().cache_hits;
    let reads = d.flash().reads.get();
    for _ in 0..100 {
        let dk = d.find_by_ip(0, ip_of(9)).unwrap().disco_key;
        assert!(d.find_by_key(0, &key_of(7)).is_some() && d.find_by_disco(0, &dk).is_some());
    }
    assert_eq!(d.stats().cache_hits - before, 300);
    assert_eq!(d.flash().reads.get(), reads, "no flash reads for the pinned peers");
    // a hot unpinned peer stays while it is hot (LRU)
    for _ in 0..10 {
        d.find_by_ip(0, ip_of(20));
        d.find_by_ip(0, ip_of(21));
    }
    let reads = d.flash().reads.get();
    d.find_by_ip(0, ip_of(20));
    assert_eq!(d.flash().reads.get(), reads);
    // a commit refreshes a cached record and drops a removed one; the pins follow the key set
    d.stage(0, &patch_of(7, 11, true)).unwrap();
    d.stage(0, &remove(9)).unwrap();
    d.commit(0, false).unwrap();
    assert_eq!(d.find_by_key(0, &key_of(7)).unwrap().derp_region, 11);
    assert!(d.find_by_key(0, &key_of(9)).is_none());
    assert_eq!(d.pinned(0), 1);
    // more resident peers than the cache: the cache holds what it can, lookups still work
    let keys: Vec<_> = (1..=6).map(key_of).collect();
    d.pin(0, &keys);
    assert_eq!(d.pinned(0), 4);
    assert!(d.stats().pins_refused > 0);
    assert_eq!(d.find_by_ip(0, ip_of(30)).unwrap().vpn_ip, ip_of(30));
    d.pin(0, &[]);
    assert_eq!(d.pinned(0), 0);
}

#[test]
fn a_thousand_peers_without_a_scan() {
    type Big = FlashDirectory<MemFlash, 3, 8>;
    let mut d: Big = FlashDirectory::new(MemFlash::new(PEERSTORE_BYTES));
    let n = 1_000u64;
    let name = |id: u64| std::format!("node-{id}.tail.ts.net");
    let peer = |id: u64| {
        let mut r = add(id, &name(id));
        r.node_id = Some(id);
        r
    };
    for id in 1..=n {
        d.stage(0, &peer(id)).unwrap();
    }
    assert_eq!(d.overflow(0), (0, 0));
    d.commit(0, true).unwrap();
    assert_eq!(d.count(0), n as usize);
    // every peer is found, by each key, in a handful of reads (the tables), with a cold cache
    let mut worst = 0;
    for id in 1..=n {
        for k in 0..3 {
            let reads = d.flash().reads.get();
            let r = match k {
                0 => d.find_by_ip(0, ip_of(id)),
                1 => d.find_by_key(0, &key_of(id)),
                _ => {
                    let mut dk = key_of(id);
                    dk[9] = 0xD1;
                    d.find_by_disco(0, &dk)
                }
            };
            assert_eq!(r.map(|r| r.node_id), Some(id));
            if k == 0 {
                worst = worst.max(d.flash().reads.get() - reads);
            }
        }
        let mut hits = 0;
        assert!(d.for_each_named(0, format_label(id).as_bytes(), &mut |h, ip| hits += usize::from(h == name(id) && ip == ip_of(id))));
        assert_eq!(hits, 1);
    }
    assert!(worst <= 12, "{worst} flash reads for a cold lookup");
    assert!(d.find_by_ip(0, ip_of(n + 1)).is_none());
    // the same full map again writes only its commit; a patch writes one record
    let used = d.slots_used(0);
    for id in 1..=n {
        d.stage(0, &peer(id)).unwrap();
    }
    d.commit(0, true).unwrap();
    assert_eq!(d.slots_used(0), used + 1);
    d.stage(0, &patch_of(500, 7, true)).unwrap();
    d.commit(0, false).unwrap();
    assert_eq!(d.slots_used(0), used + 3);
    assert_eq!(d.find_by_ip(0, ip_of(500)).unwrap().derp_region, 7);
    // half of them leave; the background compacts, one bounded step at a time
    for id in (2..=n).step_by(2) {
        d.stage(0, &remove(id)).unwrap();
    }
    d.commit(0, false).unwrap();
    assert_eq!(d.count(0), 500);
    let mut steps = 0;
    while d.maintain() {
        steps += 1;
        assert!(steps < 10_000);
    }
    let s = d.stats();
    assert!(s.compactions >= 1 && s.sync_compactions == 0, "{s:?} after {steps} steps");
    assert_eq!(d.slots_used(0), 501, "the compacted area holds the live records and its header");
    let mut d = reboot(d);
    assert_eq!(d.count(0), 500);
    assert!(d.find_by_ip(0, ip_of(999)).is_some() && d.find_by_ip(0, ip_of(998)).is_none());
}

fn format_label(id: u64) -> String {
    std::format!("NODE-{id}")
}

/// Every maintenance step does at most one sector erase.
#[test]
fn maintenance_erases_one_sector_a_step() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    d.mount();
    // the flash is not blank: an earlier life left bytes everywhere
    d.flash().d.iter_mut().for_each(|b| *b = 0x00);
    let mut d = reboot(d);
    let mut steps = 0;
    loop {
        let before = d.flash().erases;
        let more = d.maintain();
        assert!(d.flash().erases - before <= 1);
        steps += 1;
        if !more {
            break;
        }
    }
    assert!(steps >= 2 * (10 + 15), "the staging logs and the first areas: {steps} steps");
    // the first commit needs no erase now, and staging neither
    let erases = d.flash().erases;
    for id in 1..=20 {
        d.stage(0, &add(id, "x")).unwrap();
    }
    d.commit(0, true).unwrap();
    assert_eq!(d.flash().erases, erases, "no erase inside stage or commit");
    assert_eq!(d.count(0), 20);
}

/// Power fails at every write of a commit, torn at several places: after the reboot the directory is the previous generation or, when the commit returned,
/// the new one; and the next map applies cleanly over a torn one.
#[test]
fn power_loss_at_any_write_of_a_commit_keeps_the_previous_generation() {
    let ids = 24;
    let mut base: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    let mut model = Model::default();
    let mut staged = Vec::new();
    for id in 1..=16 {
        stage_both(&mut base, &mut staged, 0, &add(id, "old.tail.ts.net"));
    }
    base.commit(0, true).unwrap();
    model.commit(&staged, true);
    let image = base.into_flash().d;
    // the map that is cut: an authoritative one with changes, removals by omission and patches
    let map = |d: &mut D<2>, st: &mut Vec<(Action, u32, DirRecord)>| {
        for id in 5..=ids {
            stage_both(d, st, 0, &add(id, if id % 3 == 0 { "new.tail.ts.net" } else { "old.tail.ts.net" }));
        }
        stage_both(d, st, 0, &patch_of(6, 4, true));
        stage_both(d, st, 0, &remove(7));
    };
    let mut cut = 0;
    let mut torn_commits = 0;
    let mut completed = false;
    while !completed {
        for torn in [0usize, 3, 100, 255] {
            let mut f = MemFlash::new(0);
            f.d = image.clone();
            let mut d: D<2> = FlashDirectory::new(f);
            d.mount();
            let mut st = Vec::new();
            map(&mut d, &mut st);
            d.flash().cut_after(cut, torn);
            let ok = d.commit(0, true).is_ok();
            torn_commits += usize::from(!ok);
            let mut next = model.clone();
            next.commit(&st, true);
            let dead = d.flash().dead;
            let mut d = reboot(d);
            let want = if ok { &next } else { &model };
            check(&mut d, 0, want, ids, &std::format!("cut at write {cut}, torn {torn}, committed {ok}"));
            if !dead {
                completed = true;
            }
            // the map is fetched again after the reboot
            let mut st = Vec::new();
            map(&mut d, &mut st);
            d.commit(0, true).unwrap();
            check(&mut d, 0, &next, ids, &std::format!("retry after cut {cut}, torn {torn}"));
            let mut d = reboot(d);
            check(&mut d, 0, &next, ids, &std::format!("reboot after retry, cut {cut}"));
        }
        cut += 1;
    }
    assert!(cut > 20, "a commit of this map is {cut} writes");
    assert!(torn_commits >= 4 * 20, "{torn_commits} commits were cut");
}

/// Power fails at every write of a compaction (and of its erases): the directory is whole after the reboot.
#[test]
fn power_loss_during_compaction_loses_nothing() {
    let ids = 30;
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    let mut model = Model::default();
    let mut rng = Rng(99);
    // churn until a compaction is due
    while !d.should_compact(&d.geometry().unwrap_or(Geometry::of(SMALL, 2).unwrap()), 0) {
        let mut staged = Vec::new();
        for _ in 0..8 {
            stage_both(&mut d, &mut staged, 0, &random_update(&mut rng, ids));
        }
        d.commit(0, false).unwrap();
        model.commit(&staged, false);
    }
    // the spare area is erased first (no cut there matters: it holds nothing)
    while d.m[0].spare_clean as usize != d.geometry().unwrap().area {
        d.maintain();
    }
    let image = d.into_flash().d;
    let mut cut = 0;
    loop {
        let mut f = MemFlash::new(0);
        f.d = image.clone();
        let mut d: D<2> = FlashDirectory::new(f);
        d.mount();
        d.m[0].spare_clean = d.geometry().unwrap().area as u32; // as before the image was taken
        d.flash().cut_after(cut, 7);
        let mut steps = 0;
        while d.maintain() && !d.flash().dead {
            steps += 1;
            assert!(steps < 100_000);
        }
        let dead = d.flash().dead;
        let mut d = reboot(d);
        check(&mut d, 0, &model, ids, &std::format!("compaction cut at write {cut}"));
        // and the directory goes on
        let mut staged = Vec::new();
        stage_both(&mut d, &mut staged, 0, &add(3, "after.tail.ts.net"));
        d.commit(0, false).unwrap();
        let mut after = model.clone();
        after.commit(&staged, false);
        while d.maintain() {}
        check(&mut d, 0, &after, ids, &std::format!("after compaction cut {cut}"));
        if !dead {
            break;
        }
        cut += 1;
    }
    assert!(cut > 10, "a compaction is {cut} writes");
}

/// A commit that cannot get its writes through (a flash error) fails, the previous generation stays, and later commits are fine.
#[test]
fn a_flash_error_fails_the_map_and_nothing_else() {
    let ids = 20;
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    let mut model = Model::default();
    let mut rng = Rng(5);
    for round in 0..200 {
        let mut staged = Vec::new();
        for _ in 0..6 {
            stage_both(&mut d, &mut staged, 0, &random_update(&mut rng, ids));
        }
        if round % 7 == 3 {
            d.flash().cut_after(rng.next(10) as usize, rng.next(256) as usize);
        }
        let ok = d.commit(0, false).is_ok();
        d.flash().power_on();
        if ok {
            model.commit(&staged, false);
        }
        while d.maintain() {}
        check(&mut d, 0, &model, ids, &std::format!("round {round}"));
    }
    let mut d = reboot(d);
    check(&mut d, 0, &model, ids, "after reboot");
    assert!(d.stats().commits_failed == 0);
}
