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
fn a_refused_staging_fails_the_map_and_the_old_directory_stays() {
    let mut s = Solo::new(32);
    s.member(1, 3, 0);
    assert_eq!(s.eng.dir().count(0), 3);
    // more staged updates than the directory has room for: the sink refuses, the projector reports it, nothing was applied
    let mut refused = false;
    for k in 0..40u32 {
        let r = peer_record(5000 + u64::from(k), Solo::ip(1, 100 + k), &keys(k as u8), "x.m1.ts.net", None);
        let ev = NetmapEvent::Peer(r);
        if s.input(Input::Netmap { member: 1, event: &ev }) == Handled::Refused {
            refused = true;
            break;
        }
    }
    assert!(refused, "staging is bounded");
    s.input(Input::Netmap { member: 1, event: &NetmapEvent::Abort });
    assert_eq!(s.eng.dir().count(0), 3, "abort keeps the previous directory");
    s.eng.check_identities().unwrap();
}
