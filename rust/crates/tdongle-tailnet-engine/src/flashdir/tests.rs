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

/// Background maintenance until there is none left (or the flash lost power).
fn settle<const M: usize, const C: usize>(d: &mut FlashDirectory<MemFlash, M, C>) {
    let mut n = 0;
    while !d.flash().dead && d.maintain() {
        n += 1;
        assert!(n < 1_000_000, "maintenance never settles");
    }
}

/// Commit and run maintenance until the map is applied: `Err` when it was refused, failed later, or power went first.
fn commit_now<const M: usize, const C: usize>(d: &mut FlashDirectory<MemFlash, M, C>, m: usize, auth: bool) -> Result<(), DirError> {
    let failed = d.stats().commits_failed;
    d.commit(m, auth)?;
    let mut n = 0;
    while d.queued(m) > 0 {
        if d.flash().dead {
            return Err(DirError);
        }
        d.maintain();
        n += 1;
        assert!(n < 1_000_000, "a queued commit never applies");
    }
    if d.stats().commits_failed > failed { Err(DirError) } else { Ok(()) }
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
    std::println!(
        "flash directory RAM: {total} B for 3 memberships and a cache of 8 ({empty} B without the cache, {per_entry} B a cached record; DirRecord is {} B)",
        core::mem::size_of::<DirRecord>()
    );
    assert!(total <= 3 * 1024, "{total} B");
    // Three persisted owner keys add 96 fixed bytes, independent of peer count.
    assert!(empty <= 512 + 3 * 32, "{empty} B");
}

#[test]
fn stage_commit_find_remove_patch() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    d.stage(0, &add(2, "alpha.tail.ts.net")).unwrap();
    d.stage(0, &add(3, "beta.tail.ts.net")).unwrap();
    assert!(d.find_by_ip(0, ip_of(2)).is_none(), "not visible before commit");
    commit_now(&mut d, 0, true).unwrap();
    assert_eq!(d.count(0), 2);
    assert!(d.find_by_key(0, &key_of(3)).is_some());
    assert!(d.find_by_ip(1, ip_of(2)).is_none(), "per membership");
    let mut named = Vec::new();
    assert!(d.for_each_named(0, b"BETA", &mut |n, ip| named.push((n.to_string(), ip))));
    assert_eq!(named, vec![("beta.tail.ts.net".to_string(), ip_of(3))]);
    d.stage(0, &add(2, "alpha.tail.ts.net")).unwrap();
    commit_now(&mut d, 0, true).unwrap();
    assert_eq!(d.count(0), 1, "an authoritative map that omits a peer removes it");
    assert!(d.find_by_ip(0, ip_of(3)).is_none());
    d.stage(0, &add(4, "gamma.tail.ts.net")).unwrap();
    commit_now(&mut d, 0, false).unwrap();
    assert_eq!(d.count(0), 2);
    d.stage(0, &remove(2)).unwrap();
    commit_now(&mut d, 0, false).unwrap();
    assert_eq!(d.count(0), 1);
    d.stage(0, &patch_of(4, 9, true)).unwrap();
    commit_now(&mut d, 0, false).unwrap();
    assert_eq!(d.find_by_ip(0, ip_of(4)).unwrap().derp_region, 9);
    assert_eq!(d.generation(0), 5);
    // an unchanged full map writes one slot: its commit
    let used = d.slots_used(0);
    let mut same = add(4, "gamma.tail.ts.net");
    same.home_derp = 9;
    same.online = Some(true);
    d.stage(0, &same).unwrap();
    commit_now(&mut d, 0, true).unwrap();
    assert_eq!(d.slots_used(0), used + 1);
    assert_eq!(d.count(0), 1);
}

#[test]
fn a_directory_survives_a_restart_and_a_cleared_one_does_not() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    for i in 1..=12 {
        d.stage(1, &add(i, "peer")).unwrap();
    }
    commit_now(&mut d, 1, true).unwrap();
    d.stage(1, &patch_of(5, 3, true)).unwrap();
    commit_now(&mut d, 1, false).unwrap();
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
    commit_now(&mut d, 1, true).unwrap();
    assert_eq!(reboot(d).count(1), 1);
}

/// Erases `f` made: at most `max`.
fn erases_at_most<const M: usize, const C: usize, T>(
    d: &mut FlashDirectory<MemFlash, M, C>,
    max: usize,
    what: &str,
    f: impl FnOnce(&mut FlashDirectory<MemFlash, M, C>) -> T,
) -> T {
    let before = d.flash().erases;
    let r = f(d);
    let n = d.flash().erases - before;
    assert!(n <= max, "{n} erases in one {what}");
    r
}

/// Random streams of maps into the directory and into the model, on flash an earlier life left dirty, with aborts, bounded background maintenance (so
/// commits queue, compactions run and switch areas) and reboots. While maps are queued, lookups answer from the last applied one; no single `stage`,
/// `commit` or `maintain` erases more than one sector.
#[test]
fn it_agrees_with_a_hashmap_model_on_random_maps() {
    use std::collections::VecDeque;
    let ids = 40;
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut f = MemFlash::new(SMALL);
    f.d.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(37));
    let mut d: D<2> = FlashDirectory::new(f);
    // applied: what lookups answer; queued: the model after each queued map, oldest first
    let mut model = [Model::default(), Model::default()];
    let mut queued: [VecDeque<Model>; 2] = [VecDeque::new(), VecDeque::new()];
    let (mut compactions, mut deferred, mut max_queued, mut refused) = (0, 0, 0, 0);
    let follow = |d: &D<2>, model: &mut [Model; 2], queued: &mut [VecDeque<Model>; 2]| {
        for m in 0..2 {
            while queued[m].len() > d.queued(m) {
                model[m] = queued[m].pop_front().unwrap();
            }
            assert_eq!(queued[m].len(), d.queued(m));
        }
    };
    for round in 0..800 {
        let m = rng.next(2) as usize;
        let auth = rng.next(4) == 0;
        let mut staged = Vec::new();
        let stage = |d: &mut D<2>, staged: &mut Vec<_>, u: &PeerRecord| erases_at_most(d, 1, "stage", |d| stage_both(d, staged, m, u));
        for _ in 0..rng.next(14) {
            let u = random_update(&mut rng, ids);
            stage(&mut d, &mut staged, &u);
        }
        let base = queued[m].back().unwrap_or(&model[m]).clone();
        if auth {
            // a full map carries most of the peers
            for id in 1..=ids {
                if rng.next(5) != 0 {
                    let mut u = add(id, &std::format!("h{id}-{}.tail.ts.net", rng.next(2)));
                    if let Some(r) = base.recs.get(&if id <= KEYED { Canon::Id(id) } else { Canon::Key(key_of(id)) })
                        && rng.next(2) == 0
                    {
                        // unchanged
                        u.name.set(r.hostname.as_str());
                        u.home_derp = r.derp_region;
                        u.online = r.has_online.then_some(r.online);
                    }
                    stage(&mut d, &mut staged, &u);
                }
            }
        }
        if rng.next(12) == 0 {
            d.abort(m);
        } else {
            let full = d.queued(m) == QUEUED;
            let before = d.stats().deferred_commits;
            match erases_at_most(&mut d, 1, "commit", |d| d.commit(m, auth)) {
                Ok(()) => {
                    let mut next = base;
                    next.commit(&staged, auth);
                    queued[m].push_back(next);
                    deferred += (d.stats().deferred_commits - before) as usize;
                }
                Err(_) => {
                    assert!(full, "only a full queue refuses a commit, round {round}");
                    refused += 1;
                }
            }
        }
        follow(&d, &mut model, &mut queued);
        max_queued = max_queued.max(d.queued(m));
        // sometimes the background falls behind, so maps queue (and the queue fills)
        let steps = if rng.next(3) == 0 { 0 } else { rng.next(30) };
        for _ in 0..steps {
            erases_at_most(&mut d, 1, "maintain", |d| d.maintain());
        }
        follow(&d, &mut model, &mut queued);
        if rng.next(25) == 0 {
            compactions += d.stats().compactions;
            d = reboot(d);
            // queued maps are lost: the previous generation stays, the maps are fetched again
            queued.iter_mut().for_each(VecDeque::clear);
        }
        if rng.next(150) == 0 {
            erases_at_most(&mut d, 0, "clear", |d| d.clear(m));
            model[m].recs.clear();
            queued[m].clear();
        }
        if round % 10 == 0 || round > 790 {
            for (k, model) in model.iter().enumerate() {
                check(&mut d, k, model, ids, &std::format!("round {round} member {k}, {} queued", queued[k].len()));
            }
        }
    }
    let s = d.stats();
    assert!(compactions + s.compactions >= 10, "compactions ran: {compactions} + {s:?}");
    std::println!("{deferred} commits deferred, at most {max_queued} queued, {refused} refused by a full queue; {s:?}");
    assert!(deferred >= 5 && max_queued == QUEUED && refused >= 1, "maps queued: {deferred} deferred, at most {max_queued} at once");
    assert_eq!((s.compactions_failed, s.commits_failed, s.flash_errors), (0, 0, 0), "{s:?}");
}

#[test]
fn the_cache_keeps_the_hot_peers_and_never_evicts_the_pinned_ones() {
    let mut d: FlashDirectory<MemFlash, 1, 4> = FlashDirectory::new(MemFlash::new(40 * SECTOR));
    for id in 1..=50 {
        d.stage(0, &add(id, "p")).unwrap();
    }
    commit_now(&mut d, 0, true).unwrap();
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
    commit_now(&mut d, 0, false).unwrap();
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
    commit_now(&mut d, 0, true).unwrap();
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
    commit_now(&mut d, 0, true).unwrap();
    assert_eq!(d.slots_used(0), used + 1);
    d.stage(0, &patch_of(500, 7, true)).unwrap();
    commit_now(&mut d, 0, false).unwrap();
    assert_eq!(d.slots_used(0), used + 3);
    assert_eq!(d.find_by_ip(0, ip_of(500)).unwrap().derp_region, 7);
    // half of them leave; the background compacts, one bounded step at a time
    for id in (2..=n).step_by(2) {
        d.stage(0, &remove(id)).unwrap();
    }
    commit_now(&mut d, 0, false).unwrap();
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
    commit_now(&mut d, 0, true).unwrap();
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
    commit_now(&mut base, 0, true).unwrap();
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
            let ok = commit_now(&mut d, 0, true).is_ok();
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
            commit_now(&mut d, 0, true).unwrap();
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
        commit_now(&mut d, 0, false).unwrap();
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
        commit_now(&mut d, 0, false).unwrap();
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

/// Power fails at every write while `maintain` finishes a commit that `commit` queued (over `image`, whose directory is `model`): after the reboot the
/// directory is the previous generation or, when the map was applied before the power went, the new one; and the map applies when it is fetched again.
fn power_loss_while_a_queued_commit_finishes(image: &[u8], model: &Model, map: &[PeerRecord], auth: bool, ids: u64, ctx: &str) -> usize {
    let mut next = model.clone();
    let mut cut = 0;
    let mut erases = 0;
    loop {
        let mut f = MemFlash::new(0);
        f.d = image.to_vec();
        let mut d: D<2> = FlashDirectory::new(f);
        d.mount();
        let mut st = Vec::new();
        for u in map {
            stage_both(&mut d, &mut st, 0, u);
        }
        let before = d.flash().erases;
        d.commit(0, auth).unwrap();
        assert_eq!(d.flash().erases, before, "{ctx}: commit erases nothing");
        assert_eq!(d.queued(0), 1, "{ctx}: the commit is deferred");
        if cut == 0 {
            next = model.clone();
            next.commit(&st, auth);
        }
        // the previous generation serves while it is queued
        check(&mut d, 0, model, ids, &std::format!("{ctx}: queued"));
        d.flash().cut_after(cut, 7);
        let mut applied = false;
        let mut steps = 0;
        while !d.flash().dead {
            let e = d.flash().erases;
            let more = d.maintain();
            erases = erases.max(d.flash().erases - e);
            if d.queued(0) == 0 && !d.flash().dead {
                applied = true;
                assert_eq!(d.stats().commits_failed, 0, "{ctx}: cut {cut}");
            }
            if !more {
                break;
            }
            steps += 1;
            assert!(steps < 100_000);
        }
        let dead = d.flash().dead;
        let mut d = reboot(d);
        check(&mut d, 0, if applied { &next } else { model }, ids, &std::format!("{ctx}: cut at write {cut}, applied {applied}"));
        // fetched again
        for u in map {
            d.stage(0, u).unwrap();
        }
        commit_now(&mut d, 0, auth).unwrap();
        check(&mut d, 0, &next, ids, &std::format!("{ctx}: again after cut {cut}"));
        let mut d = reboot(d);
        check(&mut d, 0, &next, ids, &std::format!("{ctx}: reboot after cut {cut}"));
        if !dead {
            break;
        }
        cut += 1;
    }
    assert!(erases <= 1, "{ctx}: {erases} erases in one maintenance step");
    cut
}

/// A commit after a clear waits for the area to be erased: power loss at any write of that.
#[test]
fn power_loss_while_a_commit_queued_after_a_clear_finishes() {
    let ids = 20;
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    for id in 1..=12 {
        d.stage(0, &add(id, "old.tail.ts.net")).unwrap();
    }
    commit_now(&mut d, 0, true).unwrap();
    d.clear(0);
    // both areas are dirty now: the first commit waits for one to be erased
    let image = d.into_flash().d;
    let map: Vec<_> = (3..=ids).map(|id| add(id, "new.tail.ts.net")).collect();
    let cuts = power_loss_while_a_queued_commit_finishes(&image, &Model::default(), &map, true, ids, "after a clear");
    assert!(cuts > 10, "{cuts} writes");
}

/// A commit with no room left waits for a compaction: power loss at any write of the compaction and of the commit after it.
#[test]
fn power_loss_while_a_commit_queued_for_a_compaction_finishes() {
    let ids = 30;
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    let mut model = Model::default();
    let mut rng = Rng(4242);
    let mut first = Vec::new();
    for id in 1..=ids {
        stage_both(&mut d, &mut first, 0, &add(id, "base.tail.ts.net"));
    }
    commit_now(&mut d, 0, true).unwrap();
    model.commit(&first, true);
    // churn without background maintenance until a commit has to wait for room
    let (image, map) = loop {
        let image = d.flash().d.clone();
        let map: Vec<_> = (0..10).map(|_| random_update(&mut rng, ids)).collect();
        let mut staged = Vec::new();
        for u in &map {
            stage_both(&mut d, &mut staged, 0, u);
        }
        d.commit(0, false).unwrap();
        if d.queued(0) > 0 {
            settle(&mut d);
            assert!(d.stats().sync_compactions >= 1 && d.stats().compactions >= 1, "it waited for a compaction: {:?}", d.stats());
            break (image, map);
        }
        model.commit(&staged, false);
    };
    let cuts = power_loss_while_a_queued_commit_finishes(&image, &model, &map, false, ids, "waiting for a compaction");
    assert!(cuts > 20, "{cuts} writes");
}

/// The in-memory list of torn transactions overflows: nothing is forgotten, commits wait for a compaction, which leaves the torn ones behind.
#[test]
fn an_overflowing_aborted_list_blocks_commits_until_a_compaction() {
    let mut s = Member::new();
    s.txn = 10;
    for t in 11..=11 + ABORTED as u32 {
        s.abort(t);
    }
    assert!(s.abort_over && s.n_aborted as usize == ABORTED);
    assert!((11..=11 + ABORTED as u32).all(|t| !s.committed(t)), "a torn transaction above the last commit stays invisible");
    assert!(s.committed(10));
    let g = Geometry::of(SMALL, 2).unwrap();
    assert!(s.short(&g), "no commit raises `txn` over the forgotten one");
}

/// A mount over flash with more torn transactions than the aborted list holds: the committed state is the last commit before the overflow, and the
/// directory goes on (the first commit compacts).
#[test]
fn a_mount_over_more_torn_transactions_than_it_can_list() {
    let ids = 30;
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    let mut model = Model::default();
    let mut staged = Vec::new();
    for id in 1..=10 {
        stage_both(&mut d, &mut staged, 0, &add(id, "base.tail.ts.net"));
    }
    commit_now(&mut d, 0, true).unwrap();
    model.commit(&staged, true);
    // craft what no live directory writes: ABORTED + 2 torn transactions, then a complete one after them
    let g = d.geometry().unwrap();
    let a = d.m[0].active.unwrap();
    let mut end = d.m[0].end;
    let mut txn = d.m[0].next_txn;
    for i in 0..ABORTED as u64 + 2 {
        let r = to_dir_record(&add(11 + i, "torn.tail.ts.net"));
        d.append(&g, 0, a, &mut end, &seal(K_PUT, txn, &dirfmt::encode_record(&r))).unwrap();
        txn += 1;
    }
    let r = to_dir_record(&add(25, "late.tail.ts.net"));
    d.append(&g, 0, a, &mut end, &seal(K_PUT, txn, &dirfmt::encode_record(&r))).unwrap();
    d.append(&g, 0, a, &mut end, &seal(K_COMMIT, txn, &words(&[d.m[0].generation + 1, 11]))).unwrap();
    let mut d = reboot(d);
    assert!(d.m[0].abort_over, "the list overflowed");
    check(&mut d, 0, &model, ids, "frozen at the last commit before the overflow");
    let mut d = reboot(d);
    check(&mut d, 0, &model, ids, "frozen, again");
    // a commit waits for the compaction that leaves the torn transactions behind
    let mut staged = Vec::new();
    stage_both(&mut d, &mut staged, 0, &add(3, "after.tail.ts.net"));
    d.commit(0, false).unwrap();
    assert_eq!(d.queued(0), 1, "the commit waits");
    check(&mut d, 0, &model, ids, "while it waits");
    settle(&mut d);
    model.commit(&staged, false);
    assert!(d.stats().compactions >= 1 && !d.m[0].abort_over, "{:?}", d.stats());
    check(&mut d, 0, &model, ids, "after the compaction");
    let mut d = reboot(d);
    check(&mut d, 0, &model, ids, "after the compaction and a reboot");
}

/// Both generations can have valid headers after compaction; clearing must
/// invalidate both without blocking the executor on two sector erases.
#[test]
fn clear_invalidates_both_headers_without_erasing() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    d.stage(0, &add(1, "old")).unwrap();
    commit_now(&mut d, 0, true).unwrap();
    settle(&mut d);
    let g = d.geometry().unwrap();
    d.m[0].copy = Some((1, 1));
    while d.m[0].copy.is_some() {
        assert!(d.copy_step(&g, 0).is_ok());
    }
    assert_eq!(d.m[0].spare_clean, 0);
    for a in 0..=1 {
        assert_eq!(d.slot(&g, 0, a, 0).unwrap()[0], K_HEADER);
    }
    erases_at_most(&mut d, 0, "clear with two headers", |d| d.clear(0));
    let mut d = reboot(d);
    assert_eq!(d.count(0), 0);
    assert!(d.find_by_ip(0, ip_of(1)).is_none());
    d.stage(0, &add(2, "new")).unwrap();
    commit_now(&mut d, 0, true).unwrap();
    assert_eq!(reboot(d).count(0), 1);
}

#[test]
fn failed_clear_keeps_the_active_generation_until_retry() {
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    d.stage(0, &add(1, "old")).unwrap();
    commit_now(&mut d, 0, true).unwrap();
    d.flash().cut_after(0, 0);
    erases_at_most(&mut d, 0, "failed clear", |d| d.clear(0));
    assert_eq!(d.count(0), 1);
    let mut d = reboot(d);
    assert_eq!(d.count(0), 1);
    erases_at_most(&mut d, 0, "retried clear", |d| d.clear(0));
    assert_eq!(reboot(d).count(0), 0);
}

#[test]
fn ownership_survives_compaction_and_rejects_legacy_or_failed_rebind() {
    let owner = [1; 32];
    let mut d: D<2> = FlashDirectory::new(MemFlash::new(SMALL));
    assert!(d.attach(0, &owner));
    d.stage(0, &add(1, "cached")).unwrap();
    commit_now(&mut d, 0, true).unwrap();
    settle(&mut d);
    let g = d.geometry().unwrap();
    d.m[0].copy = Some((1, 1));
    while d.m[0].copy.is_some() {
        assert!(d.copy_step(&g, 0).is_ok());
    }
    let mut d = reboot(d);
    assert!(d.attach(0, &owner));
    assert_eq!(d.count(0), 1);
    d.flash().cut_after(0, 0);
    assert!(!d.attach(0, &[2; 32]), "failed invalidation cannot admit another owner");
    let mut d = reboot(d);
    assert!(d.attach(0, &owner));
    assert_eq!(d.count(0), 1);
    // The old header format's unused payload was zero-filled, hence unbound.
    d.m[0].owner = [0; 32];
    assert!(d.attach(0, &owner));
    assert_eq!(d.count(0), 0, "unbound legacy records must be discarded");
}
