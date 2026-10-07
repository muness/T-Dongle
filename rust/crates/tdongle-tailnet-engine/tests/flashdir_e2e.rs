//! End to end on the flash directory: a control map of 300 peers (beyond the old caps of 24 and 128) through the JSON projector into an engine whose
//! directory is the flash one over an in-memory `peerstore`; DNS, a packet to a far peer, a delta map, the background upkeep driven by the engine's ticks.

mod common;
use common::*;
use std::string::String;
use tdongle_tailnet_engine::flashdir::{FlashDirectory, MemFlash, PEERSTORE_BYTES};
use tdongle_tailnet_engine::{EngineNetmap, Handled, HostFate, Input, MemberConfig, NetmapSink, Out, PeerDirectory};
use tdongle_tailnet_map::{MapConfig, MapProjector};
use tdongle_tailnet_types::FixedStr;

type FDir = FlashDirectory<MemFlash, 3, 8>;
type FSolo = SoloA<64, FDir>;

const PEERS: u32 = 300;

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}
fn peer_key(i: u32) -> [u8; 32] {
    if i == 2 {
        return keys(2).node_pub.0;
    }
    let mut k = [0x5au8; 32];
    k[..4].copy_from_slice(&i.to_le_bytes());
    k
}
fn disco_key(i: u32) -> [u8; 32] {
    if i == 2 {
        return keys(2).disco_pub.0;
    }
    let mut k = [0xd1u8; 32];
    k[..4].copy_from_slice(&i.to_le_bytes());
    k
}
fn addr(i: u32) -> String {
    std::format!("100.64.{}.{}", i / 250, i % 250 + 2)
}
fn ip(i: u32) -> u32 {
    0x6440_0000 | (i / 250) << 8 | (i % 250 + 2)
}

fn full_map() -> String {
    let mut peers = String::new();
    for i in 2..PEERS + 2 {
        if !peers.is_empty() {
            peers.push(',');
        }
        peers += &std::format!(
            "{{\"ID\":{i},\"Name\":\"p{i}.tail.ts.net.\",\"Key\":\"nodekey:{}\",\"DiscoKey\":\"discokey:{}\",\"Addresses\":[\"{}/32\"],\"HomeDERP\":1,\"Endpoints\":[\"198.51.100.7:41641\"]}}",
            hex(&peer_key(i)),
            hex(&disco_key(i)),
            addr(i)
        );
    }
    std::format!(
        "{{\"Node\":{{\"ID\":1,\"Name\":\"me.tail.ts.net.\",\"Addresses\":[\"100.64.0.1/32\"],\"HomeDERP\":1}},\
\"DERPMap\":{{\"Regions\":{{\"1\":{{\"RegionID\":1,\"RegionCode\":\"t\",\"Nodes\":[{{\"Name\":\"1a\",\"RegionID\":1,\"HostName\":\"derp1.example\",\"IPv4\":\"192.0.2.1\",\"STUNPort\":3478}}]}}}}}},\
\"Domain\":\"tail.ts.net\",\"Peers\":[{peers}]}}"
    )
}

fn apply(s: &mut FSolo, json: &str) {
    let mut out = |_: Out<'_>| true;
    let mut rng = tdongle_tailnet_types::test_util::TestRng(5);
    let target = EngineNetmap { engine: &mut s.eng, member: 1, now: s.now, rng: &mut rng, out: &mut out };
    let mut sink = NetmapSink::new(target);
    let mut p = MapProjector::new(MapConfig::new(1).with_flash_directory());
    for chunk in json.as_bytes().chunks(61) {
        p.feed(chunk, &mut sink).unwrap();
    }
    p.finish(&mut sink).unwrap();
}

fn resolve(s: &mut FSolo, name: &str) -> Option<u32> {
    let q = dns_query(1, name);
    let before = s.outs.len();
    s.input(Input::Dns { client: tdongle_tailnet_dns::Client { addr: HOST_IP, port: 1 }, data: &q });
    s.outs[before..].iter().find_map(|o| if let Owned::Dns(a) = o { dns_answer_ip(a) } else { None })
}

#[test]
fn a_map_of_300_peers_applies_end_to_end_on_the_flash_directory() {
    let mut s = FSolo::with_dir(41, FlashDirectory::new(MemFlash::new(PEERSTORE_BYTES)));
    let me = keys(1);
    let mut label = FixedStr::new();
    label.set("tail");
    let cfg =
        MemberConfig { id: 1, node_private: me.node_priv, disco_private: me.disco_priv, label, priority_peer_ip: 0, persistent_keepalive_s: 0, enabled: true };
    s.input(Input::MemberAdded(&cfg));
    apply(&mut s, &full_map());
    // a new directory has no erased area yet: the map is queued, and the ticks apply it (one erase at most each) while the engine waits for it
    assert_eq!(s.eng.dir().queued(0), 1, "the first commit is deferred");
    assert_eq!(s.eng.dir().count(0), 0);
    let mut ticks = 0;
    while s.eng.dir().queued(0) > 0 {
        let before = s.eng.dir().stats().erases;
        assert!(s.wake.is_some_and(|w| w <= s.now + 10), "the engine wakes for the queued commit");
        s.now += 10;
        s.input(Input::Tick);
        assert!(s.eng.dir().stats().erases - before <= 1, "one erase a tick");
        ticks += 1;
        assert!(ticks < 10_000);
    }
    assert!(ticks > 10, "{ticks} ticks to the first commit");
    assert_eq!(s.eng.dir().count(0), PEERS as usize, "no peer cap");
    assert_eq!(s.eng.dir().overflow(0), (0, 0));
    for i in [2, 150, PEERS + 1] {
        assert_eq!(s.eng.dir_mut().find_by_ip(0, ip(i)).map(|r| r.public_key), Some(peer_key(i)), "peer {i}");
    }
    assert!(s.eng.member(1).unwrap().mship.session_valid);

    // DNS by name, through the directory's name index
    let far = resolve(&mut s, &std::format!("p{}.tail.ts.net", PEERS)).expect("the 300th peer resolves");
    assert!(resolve(&mut s, "P150.TAIL.TS.NET").is_some(), "case-insensitive");
    assert!(resolve(&mut s, "p150.tail.tailnet").is_some(), "the qualified form");
    assert!(resolve(&mut s, "nobody.tail.ts.net").is_none());
    // a packet to a far peer's alias is accepted and parked for its handshake
    s.derp_up();
    assert_eq!(s.send(far, 50), Handled::Host(HostFate::Forwarded));
    assert_eq!(s.eng.member(1).unwrap().rt.park.len(), 1);

    // the status page lists every peer
    let mut listed = 0;
    s.eng.directory_lines(0, |_| listed += 1);
    assert_eq!(listed, PEERS as usize);

    // a delta map: one removal, one patch
    apply(&mut s, "{\"PeersRemoved\":[150],\"PeersChangedPatch\":[{\"NodeID\":151,\"DERPRegion\":5}]}");
    assert_eq!(s.eng.dir().count(0), PEERS as usize - 1);
    assert!(s.eng.dir_mut().find_by_ip(0, ip(150)).is_none());
    assert_eq!(s.eng.dir_mut().find_by_ip(0, ip(151)).unwrap().derp_region, 5);
    assert!(resolve(&mut s, "p150.tail.ts.net").is_none(), "a removed peer no longer resolves");

    // the engine asks to be woken while the directory has upkeep, and the ticks do it one step at a time
    let mut steps = 0;
    while s.eng.dir().wants_maintenance() {
        let before = s.eng.dir().stats().erases;
        s.now += 10;
        s.input(Input::Tick);
        assert!(s.eng.dir().stats().erases - before <= 1, "one erase a tick");
        assert!(!s.eng.dir().wants_maintenance() || s.wake.is_some_and(|w| w <= s.now + 10), "the engine wakes for the upkeep");
        steps += 1;
        assert!(steps < 10_000);
    }
    assert!(steps > 10, "{steps} ticks of upkeep");
    // the WireGuard-resident peers are pinned in the directory's cache
    let resident = s.eng.member(1).unwrap().mship.table.len();
    assert_eq!(s.eng.dir().pinned(0), resident.min(8));
    s.eng.check_identities().unwrap();
}

#[test]
fn boot_restores_only_the_same_membership_directory_before_any_map() {
    let cfg = |id: u32, who: u8| {
        let me = keys(who);
        MemberConfig { id, node_private: me.node_priv, disco_private: me.disco_priv,
            label: FixedStr::new(), priority_peer_ip: 0, persistent_keepalive_s: 0, enabled: true }
    };
    let mut first = FSolo::with_dir(41, FlashDirectory::new(MemFlash::new(PEERSTORE_BYTES)));
    first.input(Input::MemberAdded(&cfg(1, 1)));
    apply(&mut first, &full_map());
    while first.eng.dir().queued(0) > 0 {
        first.now += 10;
        first.input(Input::Tick);
    }
    let image = first.eng.dir_mut().flash().d.clone();
    let boot = |who| {
        let mut flash = MemFlash::new(PEERSTORE_BYTES);
        flash.d = image.clone();
        let mut s = FSolo::with_dir(41, FlashDirectory::new(flash));
        s.input(Input::MemberAdded(&cfg(1, who)));
        s
    };
    let mut restored = boot(1);
    assert_eq!(restored.eng.dir().count(0), PEERS as usize, "before any control map");
    assert_eq!(restored.eng.dir_mut().find_by_ip(0, ip(150)).unwrap().public_key, peer_key(150));
    assert!(!restored.eng.member(1).unwrap().mship.session_valid, "cache alone cannot authorize traffic");
    let mut changed = boot(3);
    assert_eq!(changed.eng.dir().count(0), 0, "another node key cannot inherit peers");
    assert!(changed.eng.dir_mut().find_by_ip(0, ip(150)).is_none());
    restored.input(Input::MemberRemoved { member: 1 });
    restored.input(Input::MemberAdded(&cfg(1, 1)));
    assert_eq!(restored.eng.dir().count(0), 0, "explicit removal still clears the directory");
}
