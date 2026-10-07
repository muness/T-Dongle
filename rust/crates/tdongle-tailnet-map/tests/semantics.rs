//! Field-level behaviour of the projector: every drop has a counter, every bound is exact.

mod common;

use common::*;
use tdongle_tailnet_map::*;

fn one(peer: &str) -> (PeerRecord, MapStats) {
    let (r, rec, stats) = run_flash(4, &format!("{{\"Peers\":[{peer}]}}"));
    assert_eq!(r, Ok(()), "{peer}");
    assert_eq!(rec.staged.len(), 1);
    (rec.staged[0].clone(), stats)
}

fn patch(p: &str) -> PeerRecord {
    let (r, rec, _) = run_flash(4, &format!("{{\"PeersChangedPatch\":[{p}]}}"));
    assert_eq!(r, Ok(()), "{p}");
    rec.staged[0].clone()
}

#[test]
fn names() {
    assert_eq!(one(r#"{"Name":"a.b.ts.net."}"#).0.name.as_str(), "a.b.ts.net");
    assert_eq!(one(r#"{"Name":"a.b.ts.net.."}"#).0.name.as_str(), "a.b.ts.net.", "one dot only, as the C");
    assert_eq!(one(r#"{"Name":""}"#).0.name.as_str(), "");
    assert_eq!(one(r#"{"Name":5}"#).0.name.as_str(), "");
    let long = "n".repeat(70);
    let (p, s) = one(&format!("{{\"Name\":\"{long}\"}}"));
    assert_eq!(p.name.as_str(), &long[..63]);
    assert_eq!(s.names_cut.get(), 1);
    // cut at 63 then the dot is stripped: a dot at byte 64 is not seen, a dot at byte 63 is
    let dot63 = format!("{}.{}", "n".repeat(62), "xyz");
    assert_eq!(one(&format!("{{\"Name\":\"{dot63}\"}}")).0.name.as_str(), "n".repeat(62));
    // a multi-byte character straddling the cut is dropped whole
    let wide = format!("{}é", "n".repeat(62));
    assert_eq!(one(&format!("{{\"Name\":\"{wide}\"}}")).0.name.as_str(), "n".repeat(62));
}

#[test]
fn addresses_only_the_first_and_only_ipv4() {
    let (p, s) = one(r#"{"Addresses":["100.1.2.3/32","100.9.9.9/32","fd7a::1/128"]}"#);
    assert_eq!(p.vpn_ip, 0x6401_0203);
    assert_eq!(s.addresses_ignored.get(), 2);
    let (p, s) = one(r#"{"Addresses":["fd7a:115c:a1e0::1/128","100.1.2.3/32"]}"#);
    assert_eq!(p.vpn_ip, 0, "the C reads Addresses[0] only; Go sends the IPv4 first");
    assert_eq!((s.addresses_bad.get(), s.addresses_ignored.get()), (1, 1));
    assert_eq!(one(r#"{"Addresses":"100.1.2.3"}"#).0.vpn_ip, 0);
    assert_eq!(one(r#"{"Addresses":[]}"#).0.vpn_ip, 0);
    assert_eq!(one(r#"{"Addresses":[1]}"#).0.vpn_ip, 0);
}

#[test]
fn keys() {
    let h = key_hex(0xab);
    let (p, s) = one(&format!("{{\"Key\":\"nodekey:{h}\",\"DiscoKey\":\"discokey:{h}\",\"Machine\":\"mkey:{h}\"}}"));
    assert_eq!((p.node_key, p.disco_key, p.machine_key), (key(0xab), key(0xab), key(0xab)));
    assert_eq!(s.keys_bad.get(), 0);
    assert_eq!(one(&format!("{{\"Key\":\"{h}\"}}")).0.node_key, key(0xab), "the prefix is optional");
    assert_eq!(one(&format!("{{\"Key\":\"nodekey:{}\"}}", h.to_uppercase())).0.node_key, key(0xab));
    for bad in [format!("nodekey:{}", &h[2..]), format!("nodekey:{h}00"), format!("discokey:{h}"), "nodekey:".to_string(), String::new()] {
        let (p, s) = one(&format!("{{\"Key\":\"{bad}\"}}"));
        assert!(p.node_key.is_zero(), "{bad}");
        assert_eq!(s.keys_bad.get(), 1);
    }
    assert!(one(r#"{"Key":null}"#).0.node_key.is_zero());
    // a patch rotates keys
    let pt = patch(&format!("{{\"NodeID\":9,\"Key\":\"nodekey:{h}\",\"DiscoKey\":\"discokey:{h}\"}}"));
    assert_eq!((pt.node_key, pt.disco_key, pt.node_id), (key(0xab), key(0xab), Some(9)));
}

#[test]
fn derp_region_modern_beats_legacy() {
    assert_eq!(one(r#"{"HomeDERP":7,"DERP":"127.3.3.40:9"}"#).0.home_derp, 7);
    assert_eq!(one(r#"{"DERP":"127.3.3.40:9","HomeDERP":7}"#).0.home_derp, 7, "key order does not matter");
    assert_eq!(one(r#"{"DERP":"127.3.3.40:9"}"#).0.home_derp, 9);
    assert_eq!(one(r#"{"HomeDERP":0,"DERP":"127.3.3.40:9"}"#).0.home_derp, 9);
    assert_eq!(one(r#"{"HomeDERP":-3,"DERP":"127.3.3.40:9"}"#).0.home_derp, 9);
    assert_eq!(one(r#"{"HomeDERP":7.9}"#).0.home_derp, 7, "truncated like the C's valueint");
    assert_eq!(one(r#"{"DERP":"junk"}"#).0.home_derp, 0);
    let (p, s) = one(r#"{"HomeDERP":70000}"#);
    assert_eq!((p.home_derp, s.numbers_bad.get()), (0, 1));
    assert_eq!(patch(r#"{"NodeID":1,"DERPRegion":5}"#).home_derp, 5);
    assert_eq!(patch(r#"{"NodeID":1,"DERPRegion":0}"#).home_derp, 0);
    // a patch does not read HomeDERP, a full record does not read DERPRegion
    assert_eq!(patch(r#"{"NodeID":1,"HomeDERP":5}"#).home_derp, 0);
    assert_eq!(one(r#"{"DERPRegion":5}"#).0.home_derp, 0);
}

#[test]
fn endpoints_are_bounded_and_ipv4_only() {
    let eps: Vec<String> = (1..=12).map(|i| format!("\"10.0.0.{i}:{}\"", 1000 + i)).collect();
    let (p, s) = one(&format!("{{\"Endpoints\":[{}]}}", eps.join(",")));
    assert_eq!(p.endpoint_count, 8);
    assert_eq!(p.endpoints[7], Endpoint { ip: 0x0a00_0008, port: 1008 });
    assert_eq!(s.endpoints_over_cap.get(), 4);
    assert!(p.endpoints_present);
    // unparsable ones do not take a slot
    let (p, s) = one(r#"{"Endpoints":["[2001:db8::1]:1","bogus","1.2.3.4:70000",5,"1.2.3.4:9"]}"#);
    assert_eq!(p.endpoint_list(), &[Endpoint { ip: 0x0102_0304, port: 9 }]);
    assert_eq!(s.endpoints_bad.get(), 4);
    // absent / null / empty in a full record: no endpoints; in a patch: absent keeps, empty clears
    assert_eq!(one("{}").0.endpoint_count, 0);
    assert!(one("{}").0.endpoints_present);
    assert!(!patch(r#"{"NodeID":1}"#).endpoints_present);
    assert!(!patch(r#"{"NodeID":1,"Endpoints":null}"#).endpoints_present);
    let cleared = patch(r#"{"NodeID":1,"Endpoints":[]}"#);
    assert!(cleared.endpoints_present && cleared.endpoint_count == 0);
}

#[test]
fn allowed_ips_exit_subnets_and_cgnat() {
    let ips: Vec<String> = (0..10).map(|i| format!("\"172.16.{i}.0/24\"")).collect();
    let (p, s) = one(&format!(
        "{{\"AllowedIPs\":[\"0.0.0.0/0\",\"100.64.0.5/32\",\"100.127.255.255/32\",\"100.128.0.1/32\",\"::/0\",\"x\",\"1.2.3.4/33\",{}]}}",
        ips.join(",")
    ));
    assert!(p.is_exit_node);
    assert_eq!(p.route_count, 8);
    assert_eq!(p.routes[0], Route { network: 0x6480_0001, prefix_len: 32 }, "100.128/9 is outside the CGNAT range");
    assert_eq!(p.routes[1], Route { network: 0xac10_0000, prefix_len: 24 });
    assert_eq!(s.routes_cgnat_skipped.get(), 2);
    assert_eq!(s.routes_bad.get(), 3);
    assert_eq!(s.routes_over_cap.get(), 3);
    // not read in a patch
    assert!(!patch(r#"{"NodeID":1,"AllowedIPs":["0.0.0.0/0"]}"#).is_exit_node);
}

#[test]
fn online_expired_and_extras() {
    assert_eq!(one(r#"{"Online":true}"#).0.online, Some(true));
    assert_eq!(one(r#"{"Online":false}"#).0.online, Some(false));
    assert_eq!(one(r#"{"Online":null}"#).0.online, None);
    assert_eq!(one(r#"{"Online":"yes"}"#).0.online, None);
    assert_eq!(one("{}").0.online, None);
    assert_eq!(one(r#"{"Expired":true}"#).0.action, PeerAction::Remove);
    assert_eq!(one(r#"{"Expired":false}"#).0.action, PeerAction::Add);
    assert_eq!(one(r#"{"Expired":1}"#).0.action, PeerAction::Add);
    let (p, s) = one(r#"{"KeyExpiry":"2027-03-14T15:09:26Z","Tags":["tag:a","tag:b",3],"Cap":130,"Machine":"x"}"#);
    assert_eq!((p.key_expiry, p.tag_count, p.cap), (1_805_036_966, 2, 130));
    assert_eq!(s.keys_bad.get(), 1);
    assert_eq!(one(r#"{"KeyExpiry":"0001-01-01T00:00:00Z"}"#).0.key_expiry, 0);
    assert_eq!(one(r#"{"KeyExpiry":"0001-01-01T00:00:00Z"}"#).1.times_bad.get(), 0);
    assert_eq!(one(r#"{"KeyExpiry":"soon"}"#).1.times_bad.get(), 1);
    assert_eq!(one(r#"{"Cap":-1}"#).1.numbers_bad.get(), 1);
}

#[test]
fn node_ids() {
    assert_eq!(one(r#"{"ID":42}"#).0.node_id, Some(42));
    assert_eq!(one(r#"{"ID":9007199254740993}"#).0.node_id, Some(9_007_199_254_740_993), "exact above 2^53, where the C's double is not");
    assert_eq!(one(r#"{"ID":42.0}"#).0.node_id, Some(42));
    assert_eq!(one(r#"{"ID":"42"}"#).0.node_id, None);
    assert_eq!(one("{}").0.node_id, None);
    assert_eq!(patch(r#"{"NodeID":-1}"#).node_id, Some(u64::MAX));
    // a patch reads NodeID, a full record reads ID
    assert_eq!(patch(r#"{"ID":4}"#).node_id, None);
    assert_eq!(one(r#"{"NodeID":4}"#).0.node_id, None);
}

#[test]
fn duplicate_members_first_wins() {
    let (p, s) = one(r#"{"ID":1,"ID":2,"Name":"a","name":"b","Addresses":["100.1.1.1/32"],"Addresses":["100.2.2.2/32"],"Online":true,"ONLINE":false}"#);
    assert_eq!((p.node_id, p.name.as_str(), p.vpn_ip, p.online), (Some(1), "a", 0x6401_0101, Some(true)));
    assert_eq!(s.fields_duplicate.get(), 4);
    // inside a duplicate container nothing leaks out
    let (p, _) = one(r#"{"Endpoints":["1.1.1.1:1"],"Endpoints":["2.2.2.2:2","3.3.3.3:3"]}"#);
    assert_eq!(p.endpoint_count, 1);
}

#[test]
fn removals() {
    let h = key_hex(7);
    let (r, rec, s) = run_flash(4, &format!("{{\"PeersRemoved\":[5,\"nodekey:{h}\",\"{h}\",true,null,\"junk\",[1],{{\"a\":1}},-2,7.0]}}"));
    assert_eq!(r, Ok(()));
    let ids: Vec<_> = rec.staged.iter().map(|r| (r.node_id, r.node_key.is_zero())).collect();
    assert_eq!(ids, vec![(Some(5), true), (None, false), (None, false), (Some(u64::MAX - 1), true), (Some(7), true)]);
    assert_eq!(s.removed_bad_element.get(), 5);
    assert!(rec.staged.iter().all(|r| r.action == PeerAction::Remove && r.group == Group::Removed));
    // a removal list that is not a list is ignored
    assert!(ok(4, r#"{"PeersRemoved":{"1":2}}"#).staged.is_empty());
}

#[test]
fn sections_that_are_not_arrays_are_ignored_and_elements_that_are_not_objects_are_counted() {
    let (r, rec, s) = run_flash(4, r#"{"Peers":[1,"x",null,[2],{"ID":5}],"PeersChangedPatch":[3,{"NodeID":6}],"PeersChanged":{"a":1}}"#);
    assert_eq!(r, Ok(()));
    assert_eq!(rec.staged.iter().map(|r| r.node_id).collect::<Vec<_>>(), vec![Some(5), Some(6)]);
    assert_eq!((s.peer_not_object.get(), s.patch_not_object.get()), (4, 1));
    assert!(rec.summary.unwrap().authoritative);
}

#[test]
fn online_and_seen_change_maps() {
    let (r, rec, s) = run_flash(4, r#"{"OnlineChange":{"12":true,"13":false,"x":true,"99999999999999999999":true},"PeerSeenChange":{"12":true,"14":false}}"#);
    assert_eq!(r, Ok(()));
    let on: Vec<_> = rec.staged.iter().map(|r| (r.node_id.unwrap(), r.online.unwrap(), r.action, r.group)).collect();
    assert_eq!(on, vec![(12, true, PeerAction::Patch, Group::OnlineChange), (13, false, PeerAction::Patch, Group::OnlineChange)]);
    assert!(rec.staged.iter().all(|r| !r.endpoints_present));
    assert_eq!(rec.seen, vec![(12, true), (14, false)]);
    assert_eq!(s.seen_keys_bad.get(), 2);
    // in RAM mode they count towards the section bound
    let many: Vec<String> = (1..=9).map(|i| format!("\"{i}\":true")).collect();
    assert_eq!(run(4, &format!("{{\"OnlineChange\":{{{}}}}}", many.join(","))).0, Err(MapError::SectionFull(Group::OnlineChange)));
}

#[test]
fn self_node_fields() {
    let name127 = "s".repeat(127);
    let rec = ok(4, &format!("{{\"Node\":{{\"Name\":\"{name127}\",\"ID\":9,\"HomeDERP\":3,\"DERP\":\"127.3.3.40:8\"}}}}"));
    let n = rec.self_node.unwrap();
    assert_eq!(n.name.unwrap().as_str(), name127);
    assert_eq!((n.node_id, n.home_derp, n.vpn_ip), (Some(9), 3, None));
    let rec = ok(4, &format!("{{\"Node\":{{\"Name\":\"{}\"}}}}", "s".repeat(128)));
    assert!(rec.self_node.unwrap().name.is_none());
    // the trailing dot of the self name is kept (the C's strlcpy)
    assert_eq!(ok(4, r#"{"Node":{"Name":"a.ts.net."}}"#).self_node.unwrap().name.unwrap().as_str(), "a.ts.net.");
    // an empty name is a name (the published value is replaced by "")
    assert_eq!(ok(4, r#"{"Node":{"Name":""}}"#).self_node.unwrap().name.unwrap().as_str(), "");
    // Addresses[0] = 0.0.0.0 still counts as an address (sscanf matched)
    assert_eq!(ok(4, r#"{"Node":{"Addresses":["0.0.0.0/32"]}}"#).self_node.unwrap().vpn_ip, Some(0));
    // the self node stages nothing
    assert!(ok(4, r#"{"Node":{"Addresses":["100.1.1.1/32"]}}"#).staged.is_empty());
}

#[test]
fn root_extras() {
    let rec = ok(
        4,
        r#"{"KeepAlive":true,"ControlTime":"2026-10-06T12:34:56Z","Domain":"example.ts.net","CollectServices":false,"PacketFilters":{"base":[{"SrcIPs":["*"]}]},"Seq":5,"Unknown":[1,{"a":2}]}"#,
    );
    assert!(rec.keep_alive);
    assert_eq!(rec.control_time, Some((1_791_290_096, 0)));
    assert_eq!(rec.domain.as_deref(), Some("example.ts.net"));
    assert_eq!(rec.collect, Some(false));
    assert!(rec.summary.unwrap().packet_filter_seen);
    assert_eq!(rec.order, vec!["domain", "time", "collect", "keepalive", "commit"]);
    let (_, rec, s) = run(4, r#"{"ControlTime":"yesterday","KeepAlive":false}"#);
    assert!(!rec.keep_alive && rec.control_time.is_none());
    assert_eq!(s.times_bad.get(), 1);
    // duplicates of the root extras fail the map too
    assert_eq!(run(4, r#"{"KeepAlive":true,"KeepAlive":true}"#).0, Err(MapError::DuplicateControlField));
}

#[test]
fn dns_bounds_and_shapes() {
    let rec = ok(
        4,
        r#"{"DNSConfig":{"Resolvers":[{"Addr":"1.1.1.1"},{"Addr":"8.8.8.8","UseWithExitNode":true},{"Addr":"9.9.9.9"},{"Addr":"[2606:4700::1111]:53"},{"Addr":"5.5.5.5"}],
            "Routes":{"a.example.":[{"Addr":"10.0.0.1"},{"Addr":"10.0.0.2"},{"Addr":"10.0.0.3"}],"b.example.":[],"c.example.":null,"d.example.":[{"Addr":"10.1.1.1"}],"e.example.":[]},
            "Domains":["a","b","c","d","e"],"CertDomains":["x.ts.net"],"Proxied":true,"Nameservers":["4.4.4.4"],"FallbackResolvers":[{"Addr":"1.0.0.1"}],"ExtraRecords":[{"Name":"n","Value":"v"}]}}"#,
    );
    let d = rec.dns.unwrap();
    assert_eq!(d.resolver_count, 4);
    assert!(d.resolvers[1].use_with_exit_node);
    assert_eq!(d.resolvers[3].addr.as_str(), "[2606:4700::1111]:53");
    assert_eq!(d.route_count, 4);
    assert_eq!(d.routes[0].suffix.as_str(), "a.example.");
    assert_eq!(d.routes[0].resolver_count, 2);
    assert_eq!((d.routes[1].resolver_count, d.routes[2].resolver_count, d.routes[3].resolver_count), (0, 0, 1));
    assert_eq!((d.domain_count, d.cert_domain_count, d.proxied), (4, 1, true));
    // Nameservers (the legacy field) found the resolver list full
    assert_eq!(d.resolver_list().iter().filter(|r| r.addr.as_str() == "4.4.4.4").count(), 0);
    let (_, _, s) = run(
        4,
        r#"{"DNSConfig":{"Resolvers":[{"Addr":"1.1.1.1"},{"Addr":"2.2.2.2"},{"Addr":"3.3.3.3"},{"Addr":"4.4.4.4"},{"Addr":"5.5.5.5"}],"Domains":["a","b","c","d","e"]}}"#,
    );
    assert_eq!(s.dns_over_cap.get(), 2);
    // legacy Nameservers when there is room
    let rec = ok(4, r#"{"DNSConfig":{"Nameservers":["4.4.4.4","8.8.4.4"]}}"#);
    assert_eq!(rec.dns.unwrap().resolver_list().iter().map(|r| r.addr.as_str()).collect::<Vec<_>>(), vec!["4.4.4.4", "8.8.4.4"]);
    // a DNSConfig that is not an object is ignored; null is fine
    assert!(ok(4, r#"{"DNSConfig":null}"#).dns.is_none());
    assert!(ok(4, r#"{"DNSConfig":5}"#).dns.is_none());
    // an empty DNSConfig is present
    assert_eq!(ok(4, r#"{"DNSConfig":{}}"#).dns.unwrap().resolver_count, 0);
    // names are cut and counted
    let long = "d".repeat(100);
    let (_, rec, s) = run(4, &format!("{{\"DNSConfig\":{{\"Domains\":[\"{long}\"]}},\"Domain\":\"{long}\"}}"));
    assert_eq!(rec.dns.as_ref().unwrap().domains[0].as_str(), &long[..63]);
    assert_eq!(s.dns_text_cut.get(), 1, "the 100-byte Domain fits its 127-byte field; the search domain is cut at 63");
    assert_eq!(rec.domain.unwrap().len(), 100);
}

#[test]
fn derp_node_fields_and_bounds() {
    let rec = ok(
        1,
        r#"{"DERPMap":{"HomeParams":{"RegionScore":{"1":1}},"OmitDefaultRegions":true,"Regions":{"1":{"RegionID":1,"RegionCode":"nyc-long-code","RegionName":"A region name that is rather too long to keep","Avoid":true,"Latitude":1,
            "Nodes":[{"Name":"1a","HostName":"d1.example.com","IPv4":"1.2.3.4","IPv6":"::1","STUNPort":3479,"DERPPort":8443,"STUNOnly":true,"CanPort80":true,"CertName":"front.example"},
                     {"HostName":"d2.example.com","IPv4":"bogus","IPv6":"bogus","STUNPort":-1,"DERPPort":70000},
                     {"HostName":"d3.example.com"}, 5]}}}}"#,
    );
    let d = rec.derp.unwrap();
    let r = &d.regions[0];
    assert_eq!((r.region_id, r.code.as_str(), r.name.as_str(), r.avoid, r.node_count), (1, "nyc-lon", "A region name that is r", true, 2));
    let n = &r.nodes[0];
    assert_eq!(
        (n.hostname.as_str(), n.ipv4, n.stun_port, n.derp_port, n.stun_only, n.can_port80),
        ("d1.example.com", Some([1, 2, 3, 4]), 3479, 8443, true, true)
    );
    assert!(n.ipv6.is_some());
    assert!(matches!(&n.cert, DerpCert::Name(c) if c.as_str() == "front.example"));
    let n = &r.nodes[1];
    assert_eq!((n.ipv4, n.ipv6, n.stun_port, n.derp_port, &n.cert), (None, None, 0, 0, &DerpCert::Hostname));
    let (_, _, s) = run(
        1,
        r#"{"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"a","IPv4":"x","IPv6":"y","STUNPort":-1},{"HostName":"b"},{"HostName":"c"},5]}}}}"#,
    );
    assert_eq!((s.derp_ips_bad.get(), s.numbers_bad.get(), s.derp_nodes_over_cap.get()), (2, 1, 1));
    // the Nodes element 5 is after the cap: counted as over cap only when it is an object; here it is ignored once the first two are kept
    // a region whose RegionID is missing has id 0 and is never "home"
    let rec = ok(0, r#"{"DERPMap":{"Regions":{"1":{},"2":{},"3":{},"4":{},"5":{}}}}"#);
    assert_eq!(rec.derp.unwrap().count, 4);
    let rec = ok(5, r#"{"DERPMap":{"Regions":{"1":{},"2":{},"3":{},"4":{},"5":{"RegionID":5}}}}"#);
    assert_eq!(rec.derp.unwrap().region_list().iter().map(|r| r.region_id).collect::<Vec<_>>(), vec![0, 0, 0, 5]);
}

#[test]
fn unknown_members_are_validated_and_dropped() {
    let (r, rec, s) = run_flash(4, r#"{"Peers":[{"ID":1,"Hostinfo":{"a":[1,2,{"b":null}]},"CapMap":{"x":[1]},"Weird":"\u0000\ud800"}],"Debug":{"x":1}}"#);
    assert_eq!(r, Ok(()));
    assert_eq!(rec.staged.len(), 1);
    assert_eq!(s.fields_skipped.get(), 4, "Hostinfo, CapMap, Weird, and the root's Debug");
    // ... but their syntax is checked
    assert!(run_flash(4, r#"{"Peers":[{"ID":1,"Hostinfo":{"a":[1,]}}]}"#).0.is_err());
    // and never stored: the unknown member does not count against the record bounds
    let big = "z".repeat(10_000);
    assert_eq!(run_flash(4, &format!("{{\"Peers\":[{{\"ID\":1,\"Hostinfo\":{{\"notes\":\"{big}\"}}}}]}}")).0, Ok(()));
}

#[test]
fn byte_accounting_is_chunk_independent_even_on_failure() {
    let bad = br#"{"Peers":[{"ID":1}],"X":tru}"#;
    let a = run_cfg(MapConfig::new(1), bad, 0).2;
    let b = run_cfg(MapConfig::new(1), bad, 1).2;
    assert_eq!(a, b);
    assert!(a.bytes_in > 0);
}

#[test]
fn reuse_after_reset_and_after_failure() {
    let mut p = MapProjector::new(MapConfig::new(1));
    let mut rec = Rec::default();
    assert!(p.feed(b"{\"Peers\":[", &mut rec).is_ok());
    assert!(p.feed(b"x]}", &mut rec).is_err());
    assert_eq!(p.failure(), Some(MapError::Json(json::JsonError::Unexpected(b'x'))));
    // every later call repeats the error and sends nothing more
    let events = rec.order.len();
    assert!(p.feed(b"{}", &mut rec).is_err() && p.finish(&mut rec).is_err());
    assert_eq!(rec.order.len(), events);
    p.reset(MapConfig::new(1));
    let mut rec = Rec::default();
    p.feed(b"{\"Peers\":[]}", &mut rec).unwrap();
    p.finish(&mut rec).unwrap();
    assert!(p.is_done());
    // after a good map: whitespace is fine, anything else is refused without events
    assert!(p.feed(b"\n", &mut rec).is_ok());
    let n = rec.order.len();
    assert!(p.feed(b"{}", &mut rec).is_err());
    assert_eq!(rec.order.len(), n);
    // an unfinished map cannot be finished
    let mut p = MapProjector::new(MapConfig::new(1));
    let mut rec = Rec::default();
    p.feed(b"{\"Peers\":[", &mut rec).unwrap();
    assert_eq!(p.finish(&mut rec), Err(MapError::Incomplete));
    assert_eq!(rec.aborted, Some(MapError::Incomplete));
    assert_eq!(MapError::Incomplete.code(), 8);
}
