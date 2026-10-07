//! The map projector feeding an engine through `NetmapSink`: JSON in, directory and DERP requests out.

mod common;
use common::*;
use tdongle_tailnet_engine::{EngineNetmap, Handled, HostFate, Input, MemberConfig, NetmapEvent, NetmapSink, Out, PeerDirectory};
use tdongle_tailnet_map::{MapConfig, MapProjector};
use tdongle_tailnet_types::FixedStr;

fn hex(k: &tdongle_tailnet_types::Key32) -> std::string::String {
    let mut h = [0u8; 64];
    k.to_hex(&mut h);
    std::string::String::from_utf8(h.to_vec()).unwrap()
}

fn map_json(peer: &Keys) -> std::string::String {
    std::format!(
        "{{\"Node\":{{\"ID\":1,\"Name\":\"me.tail.ts.net.\",\"Addresses\":[\"100.64.0.1/32\"],\"HomeDERP\":1}},\
\"DERPMap\":{{\"Regions\":{{\"1\":{{\"RegionID\":1,\"RegionCode\":\"t\",\"Nodes\":[{{\"Name\":\"1a\",\"RegionID\":1,\"HostName\":\"derp1.example\",\"IPv4\":\"192.0.2.1\",\"STUNPort\":3478}}]}}}}}},\
\"Domain\":\"tail.ts.net\",\
\"Peers\":[{{\"ID\":2,\"Name\":\"b.tail.ts.net.\",\"Key\":\"nodekey:{}\",\"DiscoKey\":\"discokey:{}\",\"Addresses\":[\"100.64.0.2/32\"],\"HomeDERP\":1,\"Endpoints\":[\"198.51.100.7:41641\"]}}]}}",
        hex(&peer.node_pub),
        hex(&peer.disco_pub)
    )
}

#[test]
fn a_projected_map_reaches_the_directory_and_starts_the_relay() {
    let mut s = Solo::new(31);
    let me = keys(1);
    let mut label = FixedStr::new();
    label.set("tail");
    let cfg =
        MemberConfig { id: 1, node_private: me.node_priv, disco_private: me.disco_priv, label, priority_peer_ip: 0, persistent_keepalive_s: 0, enabled: true };
    s.input(Input::MemberAdded(&cfg));
    let peer = keys(2);
    let json = map_json(&peer);
    let mut outs = std::vec::Vec::new();
    {
        let mut out = |o: Out<'_>| {
            outs.push(own(o));
            true
        };
        let mut rng = tdongle_tailnet_types::test_util::TestRng(5);
        let target = EngineNetmap { engine: &mut s.eng, member: 1, now: 2_000, rng: &mut rng, out: &mut out };
        let mut sink = NetmapSink::new(target);
        let mut p = MapProjector::new(MapConfig::new(1));
        for chunk in json.as_bytes().chunks(37) {
            p.feed(chunk, &mut sink).unwrap();
        }
        p.finish(&mut sink).unwrap();
    }
    assert_eq!(s.eng.dir().count(0), 1);
    assert!(s.eng.dir_mut().find_by_ip(0, 0x6440_0002).is_some());
    assert!(outs.iter().any(|o| matches!(o, Owned::DerpConnect { region: 1, host, port: 443 } if host == "derp1.example")), "{outs:?}");
    assert!(outs.iter().any(|o| matches!(o, Owned::Ready(true))));
    let m = s.eng.member(1).unwrap();
    assert_eq!(m.rt.self_ip, 0x6440_0001);
    assert_eq!(m.rt.domain.as_str(), "tail.ts.net");
    assert!(m.mship.session_valid);
    // a name in the MagicDNS domain resolves, and a packet to its alias is accepted and parked for the handshake
    let q = dns_query(1, "b.tail.ts.net");
    s.input(Input::Dns { client: tdongle_tailnet_dns::Client { addr: HOST_IP, port: 1 }, data: &q });
    let a = s.outs.iter().rev().find_map(|o| if let Owned::Dns(a) = o { dns_answer_ip(a) } else { None }).expect("alias");
    s.derp_up();
    assert_eq!(s.send(a, 50), Handled::Host(HostFate::Forwarded));
    assert_eq!(s.eng.member(1).unwrap().rt.park.len(), 1);
    s.eng.check_identities().unwrap();
}

#[test]
fn more_peers_than_the_staging_holds_are_counted_not_refused() {
    let mut s = Solo::new(32);
    s.member(1, 3, 0);
    assert_eq!(s.eng.dir().count(0), 3);
    // more staged updates than the directory has room for: dropped and counted, the map goes on (a real tailnet has hundreds of peers)
    for k in 0..40u32 {
        let r = peer_record(5000 + u64::from(k), Solo::ip(1, 100 + k), &keys(k as u8), "x.m1.ts.net", None);
        let ev = NetmapEvent::Peer(r);
        assert_ne!(s.input(Input::Netmap { member: 1, event: &ev }), Handled::Refused);
    }
    assert!(s.eng.dir().overflow(0).1 > 0, "counted");
    s.input(Input::Netmap { member: 1, event: &NetmapEvent::Abort });
    assert_eq!(s.eng.dir().count(0), 3, "abort keeps the previous directory");
    s.eng.check_identities().unwrap();
}

#[test]
fn a_peer_update_below_the_elastic_floor_is_refused_not_stored() {
    use tdongle_tailnet_admission::heap::ML_HB_FLOOR;
    use tdongle_tailnet_admission::probe::HeapSnapshot;
    let mut s = Solo::new(33);
    s.member(1, 2, 0);
    assert_eq!(s.eng.dir().count(0), 2);
    // the directory is an elastic consumer (ADR 0022): with the heap at the floor a staged update would cross it
    s.eng.set_heap(HeapSnapshot { free: ML_HB_FLOOR + 10, largest: 20_000, minimum: 0 });
    let r = peer_record(6000, Solo::ip(1, 200), &keys(9), "late.m1.ts.net", None);
    let before = s.eng.stats().netmap_refused.get();
    assert_eq!(s.input(Input::Netmap { member: 1, event: &NetmapEvent::Peer(r.clone()) }), Handled::Refused);
    assert_eq!(s.eng.stats().netmap_refused.get(), before + 1, "counted");
    assert_eq!(s.eng.dir().count(0), 2, "the previous directory stays");
    // with room again the same update is staged and the map commits
    s.eng.set_heap(HeapSnapshot { free: ML_HB_FLOOR + 100_000, largest: 50_000, minimum: 0 });
    assert_ne!(s.input(Input::Netmap { member: 1, event: &NetmapEvent::Peer(r) }), Handled::Refused);
    s.eng.set_heap(HeapSnapshot { free: ML_HB_FLOOR + 10, largest: 20_000, minimum: 0 });
    assert_eq!(
        s.input(Input::Netmap { member: 1, event: &NetmapEvent::Commit { authoritative: false, self_expired: false } }),
        Handled::Refused,
        "the commit builds the next bank beside the live one: it is refused at the floor too"
    );
    assert_eq!(s.eng.dir().count(0), 2);
}

/// A map like a real tailnet's: hundreds of peers, a full DERP map, a DNS config with a long route table, a big packet filter and user list. The control plane
/// sends all of it; the gateway keeps what it needs and counts the rest. Before, the first section over the RAM limit failed the whole map
/// (`Map(Projector(SectionFull))` on the board) and the membership never routed.
fn big_map(peer: &Keys, peers: usize) -> std::string::String {
    use std::fmt::Write as _;
    let mut j = std::string::String::from("{\"Node\":{\"ID\":1,\"Name\":\"me.tail.ts.net.\",\"Addresses\":[\"100.64.0.1/32\"],\"HomeDERP\":3}");
    j.push_str(",\"DERPMap\":{\"Regions\":{");
    for r in 1..=24 {
        let _ = write!(j, "{}\"{r}\":{{\"RegionID\":{r},\"RegionCode\":\"r{r}\",\"RegionName\":\"Region {r}\",\"Nodes\":[{{\"Name\":\"{r}a\",\"RegionID\":{r},\"HostName\":\"derp{r}.example\",\"IPv4\":\"192.0.2.{r}\",\"STUNPort\":3478}},{{\"Name\":\"{r}b\",\"RegionID\":{r},\"HostName\":\"derp{r}b.example\",\"IPv4\":\"192.0.3.{r}\"}}]}}", if r > 1 { "," } else { "" });
    }
    j.push_str("}}");
    j.push_str(",\"Domain\":\"tail.ts.net\",\"DNSConfig\":{\"Resolvers\":[{\"Addr\":\"100.100.100.100\"},{\"Addr\":\"1.1.1.1\"}],\"Routes\":{");
    for r in 0..300 {
        let _ = write!(j, "{}\"corp{r}.example.com.\":[{{\"Addr\":\"10.{}.0.53\"}}]", if r > 0 { "," } else { "" }, r % 250);
    }
    j.push_str("},\"Domains\":[\"tail.ts.net\",\"corp.example.com\"],\"Proxied\":true,\"CertDomains\":[\"me.tail.ts.net\"]}");
    j.push_str(",\"PacketFilter\":[");
    for r in 0..400 {
        let _ = write!(j, "{}{{\"SrcIPs\":[\"100.64.{}.0/24\",\"fd7a:115c:a1e0::/48\"],\"DstPorts\":[{{\"IP\":\"*\",\"Ports\":{{\"First\":{},\"Last\":{}}}}}]}}", if r > 0 { "," } else { "" }, r % 250, 1000 + r, 2000 + r);
    }
    j.push_str("],\"UserProfiles\":[");
    for u in 0..400 {
        let _ = write!(j, "{}{{\"ID\":{u},\"LoginName\":\"user{u}@example.com\",\"DisplayName\":\"User Number {u}\",\"ProfilePicURL\":\"https://example.com/p/{u}.png\"}}", if u > 0 { "," } else { "" });
    }
    j.push_str("],\"Peers\":[");
    for i in 0..peers {
        let _ = write!(
            j,
            "{}{{\"ID\":{},\"Name\":\"p{i}.tail.ts.net.\",\"Key\":\"nodekey:{}\",\"DiscoKey\":\"discokey:{}\",\"Addresses\":[\"100.64.{}.{}/32\"],\"HomeDERP\":{},\"Endpoints\":[\"198.51.100.{}:41641\",\"203.0.113.{}:41641\"],\"Online\":{},\"Capabilities\":[\"https\",\"ssh\",\"funnel\"],\"Hostinfo\":{{\"OS\":\"linux\",\"Hostname\":\"p{i}\"}}}}",
            if i > 0 { "," } else { "" },
            1000 + i,
            hex(&peer.node_pub),
            hex(&peer.disco_pub),
            (i / 250) + 1,
            (i % 250) + 2,
            1 + (i % 24),
            i % 250,
            i % 250,
            i % 3 != 0
        );
    }
    j.push_str("]}");
    j
}

#[test]
fn a_real_sized_map_applies_keeps_what_fits_and_counts_the_rest() {
    let mut s = Solo::new(41);
    let me = keys(1);
    let mut label = FixedStr::new();
    label.set("tail");
    let cfg = MemberConfig { id: 1, node_private: me.node_priv, disco_private: me.disco_priv, label, priority_peer_ip: 0, persistent_keepalive_s: 0, enabled: true };
    s.input(Input::MemberAdded(&cfg));
    let json = big_map(&keys(2), 450);
    assert!(json.len() > 150_000, "{} bytes", json.len());
    let mut outs = std::vec::Vec::new();
    let r = {
        let mut out = |o: Out<'_>| {
            outs.push(own(o));
            true
        };
        let mut rng = tdongle_tailnet_types::test_util::TestRng(5);
        let target = EngineNetmap { engine: &mut s.eng, member: 1, now: 2_000, rng: &mut rng, out: &mut out };
        let mut sink = NetmapSink::new(target);
        // as the control driver runs it: the unbounded sections of the flash-directory configuration, then the directory caps
        let mut p = MapProjector::new(MapConfig::new(3).with_flash_directory());
        let mut r = Ok(());
        for chunk in json.as_bytes().chunks(1400) {
            if let Err(e) = p.feed(chunk, &mut sink) {
                r = Err(e);
                break;
            }
        }
        r.and_then(|()| p.finish(&mut sink).map(|_| ()))
    };
    assert_eq!(r, Ok(()), "the map is not refused for its size");
    // and the RAM limits this replaced did refuse it, naming the section
    let mut o = |_: Out<'_>| true;
    let mut rng2 = tdongle_tailnet_types::test_util::TestRng(6);
    let mut s2 = Solo::new(42);
    s2.input(Input::MemberAdded(&cfg));
    let mut sink2 = NetmapSink::new(EngineNetmap { engine: &mut s2.eng, member: 1, now: 2_000, rng: &mut rng2, out: &mut o });
    let mut p2 = MapProjector::new(MapConfig::new(3));
    let old = json.as_bytes().chunks(1400).try_for_each(|c| p2.feed(c, &mut sink2).map(|_| ()));
    assert!(matches!(old, Err(tdongle_tailnet_map::MapError::SectionFull(tdongle_tailnet_map::types::Group::Peers))), "{old:?}");
    // the Dir of these tests holds 16 peers a membership: it keeps 16 and counts the rest, the engine goes on
    assert_eq!(s.eng.dir().count(0), 16);
    let (over, dropped) = s.eng.dir().overflow(0);
    assert!(over + dropped >= 450 - 32, "overflow {over}, staging drops {dropped}");
    let m = s.eng.member(1).unwrap();
    assert!(m.mship.session_valid, "the map applied");
    assert_eq!(m.rt.self_ip, 0x6440_0001);
    // the DERP map: the C keeps four regions, the home region (3) among them; the relay is asked for
    assert!(outs.iter().any(|o| matches!(o, Owned::DerpConnect { region: 3, .. })), "{outs:?}");
    s.eng.check_identities().unwrap();
}
