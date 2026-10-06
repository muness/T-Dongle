//! MapResponses produced by the real Go `tailcfg` types (`tests/fixtures/gen_maps.go.txt`, Tailscale v1.104.0): field names and shapes as a real control
//! server sends them, including everything the gateway ignores.

mod common;

use common::*;
use tdongle_tailnet_map::derp_cert::DerpCert;
use tdongle_tailnet_map::*;

fn load(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/{name}")).unwrap()
}

#[test]
fn full_map_from_go() {
    let j = load("map-full.json");
    let (r, rec, stats) = run(1, &j);
    assert_eq!(r, Ok(()));
    let s = rec.summary.as_ref().unwrap();
    assert!(s.authoritative && s.has_self && s.derp_present && s.packet_filter_seen && !s.self_expired);

    // self
    let me = rec.self_node.as_ref().unwrap();
    assert_eq!(me.name.as_ref().unwrap().as_str(), "dongle.tail1234.ts.net."); // the trailing dot is kept for the self name
    assert_eq!(me.vpn_ip, Some(u32::from_be_bytes([100, 101, 102, 103])));
    assert_eq!((me.node_id, me.home_derp, me.cap, me.tag_count), (Some(1), 1, 130, 2));
    assert_eq!(me.key_expiry, 1805036966); // 2027-03-14T15:09:26Z
    assert!(!me.node_key.is_zero() && !me.disco_key.is_zero() && !me.machine_key.is_zero());

    // peers: laptop, router (exit node + subnet router), shared (expired)
    assert_eq!(rec.staged.len(), 3);
    let laptop = &rec.staged[0];
    assert_eq!((laptop.action, laptop.group, laptop.node_id), (PeerAction::Add, Group::Peers, Some(2)));
    assert_eq!(laptop.name.as_str(), "laptop.tail1234.ts.net");
    assert_eq!(laptop.vpn_ip, u32::from_be_bytes([100, 101, 102, 104]));
    assert_eq!(laptop.home_derp, 2);
    assert_eq!(laptop.online, Some(true));
    assert_eq!(
        laptop.endpoint_list(),
        &[Endpoint { ip: u32::from_be_bytes([203, 0, 113, 7]), port: 41641 }, Endpoint { ip: u32::from_be_bytes([192, 168, 1, 20]), port: 41641 }]
    );
    assert_eq!((laptop.tag_count, laptop.cap, laptop.key_expiry), (2, 130, 1805036966));
    assert!(!laptop.machine_key.is_zero());
    assert!(!laptop.is_exit_node && laptop.route_count == 0);
    let router = &rec.staged[1];
    assert!(router.is_exit_node);
    assert_eq!(router.route_list(), &[Route { network: u32::from_be_bytes([192, 168, 50, 0]), prefix_len: 24 }]);
    assert_eq!(router.online, Some(false));
    let shared = &rec.staged[2];
    assert_eq!(shared.action, PeerAction::Remove, "Expired is a removal");
    assert_eq!((shared.key_expiry, shared.online, shared.tag_count), (0, None, 0), "Go's zero time and a missing Online");
    assert_eq!(shared.home_derp, 0);

    // DERP: nyc has three nodes, two are kept; sfo is stun-only; the avoided region has a pinned certificate and a "disabled" STUN port
    let d = rec.derp.as_ref().unwrap();
    assert_eq!(d.region_list().iter().map(|r| (r.region_id, r.code.as_str())).collect::<Vec<_>>(), vec![(1, "nyc"), (2, "sfo"), (9, "dev")]);
    assert_eq!(d.regions[0].name.as_str(), "New York City");
    assert_eq!(d.regions[0].node_count, 2);
    assert_eq!(d.regions[0].nodes[0].hostname.as_str(), "derp1f.tailscale.com");
    assert_eq!(d.regions[0].nodes[0].ipv4, Some([199, 38, 181, 104]));
    assert!(d.regions[0].nodes[0].ipv6.is_some() && d.regions[0].nodes[0].can_port80);
    assert!(d.regions[1].nodes[0].stun_only && !d.regions[1].avoid);
    assert!(d.regions[2].avoid);
    assert!(matches!(d.regions[2].nodes[0].cert, DerpCert::Pin(p) if p[0] == 0 && p[31] == 0xff));
    assert_eq!(d.regions[2].nodes[0].stun_port, 0);
    assert_eq!(stats.derp_nodes_over_cap.get(), 1);
    assert_eq!(stats.numbers_bad.get(), 1); // STUNPort -1

    // DNS
    let dns = rec.dns.as_ref().unwrap();
    assert_eq!(
        dns.resolver_list().iter().map(|r| (r.addr.as_str(), r.use_with_exit_node)).collect::<Vec<_>>(),
        vec![("1.1.1.1", false), ("https://dns.google/dns-query", true)]
    );
    assert!(dns.proxied);
    assert_eq!(dns.domain_list().iter().map(|d| d.as_str()).collect::<Vec<_>>(), vec!["tail1234.ts.net", "corp.example.com"]);
    assert_eq!(dns.cert_domain_list()[0].as_str(), "dongle.tail1234.ts.net");
    let mut routes: Vec<_> = dns.route_list().iter().map(|r| (r.suffix.as_str(), r.resolver_count)).collect();
    routes.sort();
    assert_eq!(routes, vec![("corp.example.com.", 1), ("ts.net.", 0)]);
    assert_eq!(dns.route_list().iter().find(|r| r.suffix.as_str() == "corp.example.com.").unwrap().resolvers[0].addr.as_str(), "10.0.0.53");

    // the rest
    assert_eq!(rec.domain.as_deref(), Some("tail1234.ts.net"));
    assert_eq!(rec.control_time, Some((1791290096, 789_000_000)));
    assert_eq!(rec.collect, Some(true));
    assert!(!rec.keep_alive);
    assert_eq!(rec.order.last(), Some(&"commit"));
    assert!(stats.fields_skipped.get() > 10, "Hostinfo, User, StableID ... are validated and dropped");
    assert!((stats.projected_bytes as usize) < j.len() / 2);
    assert_eq!(stats.endpoints_bad.get(), 3, "one IPv6 endpoint per peer");
    // unknown fields are not stored: the whole map ran through a state that is a few KB, not a function of its size
    const { assert!(MapProjector::STATE_BYTES < 16 * 1024) };
}

#[test]
fn full_map_any_chunking() {
    let j = load("map-full.json");
    let (_, whole, s1) = run(1, &j);
    for chunk in [1, 2, 3, 5, 7, 13, 64, 100, 1000] {
        let (r, rec, s2) = run_cfg(MapConfig::new(1), j.as_bytes(), chunk);
        assert_eq!(r, Ok(()), "chunk {chunk}");
        assert_eq!(format!("{whole:?}"), format!("{rec:?}"), "chunk {chunk}");
        assert_eq!(s1, s2);
    }
}

#[test]
fn delta_map_from_go() {
    let (r, rec, stats) = run(1, &load("map-delta.json"));
    assert_eq!(r, Ok(()));
    let s = rec.summary.as_ref().unwrap();
    assert!(!s.authoritative);
    // PeersChanged (1), PeersRemoved (2), PeersChangedPatch (2), OnlineChange (2) -> staged in document order of the Go struct
    let groups: Vec<_> = rec.staged.iter().map(|r| (r.group, r.action, r.node_id)).collect();
    assert!(groups.contains(&(Group::Changed, PeerAction::Add, Some(5))));
    assert!(groups.contains(&(Group::Removed, PeerAction::Remove, Some(3))));
    assert!(groups.contains(&(Group::Removed, PeerAction::Remove, Some(4))));
    let patch2 = rec.staged.iter().find(|r| r.group == Group::Patch && r.node_id == Some(2)).unwrap();
    assert_eq!(patch2.home_derp, 1);
    assert_eq!(patch2.online, Some(false));
    assert_eq!(patch2.cap, 131);
    assert_eq!(patch2.key_expiry, 1806537600);
    assert!(patch2.endpoints_present);
    assert_eq!(patch2.endpoint_list(), &[Endpoint { ip: u32::from_be_bytes([198, 51, 100, 9]), port: 1234 }]);
    let patch5 = rec.staged.iter().find(|r| r.group == Group::Patch && r.node_id == Some(5)).unwrap();
    assert!(!patch5.node_key.is_zero() && !patch5.disco_key.is_zero());
    assert!(!patch5.endpoints_present, "a patch without Endpoints leaves them alone");
    assert_eq!(patch5.online, None);
    let online: Vec<_> = rec.staged.iter().filter(|r| r.group == Group::OnlineChange).map(|r| (r.node_id.unwrap(), r.online.unwrap())).collect();
    assert_eq!(online.len(), 2);
    assert!(online.contains(&(2, false)) && online.contains(&(5, true)));
    let mut seen = rec.seen.clone();
    seen.sort();
    assert_eq!(seen, vec![(2, true), (5, false)]);
    assert_eq!(rec.control_time, Some((1791290156, 0)));
    assert_eq!(stats.removals_staged.get(), 2);
    assert_eq!(stats.seen_staged.get(), 2);

    // applied on the model directory after the full map
    let mut dir = Dir::default();
    dir.apply_map(&ok(1, &load("map-full.json")));
    dir.apply_map(&rec);
    assert_eq!(dir.count(), 3, "laptop, phone and the (blanked) slots of the removed peers collapse on the next full commit");
}

#[test]
fn keepalive_and_derp_only_maps_from_go() {
    let rec = ok(1, &load("map-keepalive.json"));
    assert!(rec.keep_alive && rec.staged.is_empty() && rec.self_node.is_none());
    assert_eq!(rec.order, vec!["keepalive", "commit"]);
    let rec = ok(1, &load("map-derp-only.json"));
    assert_eq!(rec.derp.unwrap().count, 3);
}

#[test]
fn flash_mode_has_no_section_limit_on_real_maps() {
    let j = load("map-full.json");
    let (r, _, _) = run_flash(1, &j);
    assert_eq!(r, Ok(()));
}
