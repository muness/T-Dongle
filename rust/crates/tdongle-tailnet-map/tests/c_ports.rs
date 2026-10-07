//! The C's tests, ported: `test_semantic_map.c`, `test_semantic_directory.c`, `test_peer_directory.c` (the pure rules), `test_projection.c`,
//! `test_project_stream.c`, `test_json_depth.c`, `test_published_name.c` (the value semantics).

mod common;

use common::*;
use tdongle_tailnet_map::derp_cert::DerpCert;
use tdongle_tailnet_map::json::{Event, JsonError, MAX_DEPTH, Policy, TokenSink, Tokenizer, nesting_within};
use tdongle_tailnet_map::project::*;
use tdongle_tailnet_map::*;

const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

// ---- test_semantic_map.c --------------------------------------------------------------------------------------------------------------------------

#[test]
fn semantic_map_peers_removed_patch_exact_records() {
    let rec = ok(
        4,
        &format!(
            "{{\"Peers\":[{{\"ID\":42,\"Name\":\"server.ts.net.\",\"Key\":\"nodekey:{KEY}\",\"DiscoKey\":\"discokey:{KEY}\",\"Addresses\":[\"100.1.2.3/32\"],\
             \"Endpoints\":[\"1.2.3.4:123\"],\"HomeDERP\":4,\"Online\":true,\"AllowedIPs\":[\"0.0.0.0/0\",\"192.168.5.0/24\"]}}],\
             \"PeersRemoved\":[12],\"PeersChangedPatch\":[{{\"NodeID\":42,\"DERPRegion\":3,\"Online\":false,\"Endpoints\":[\"5.6.7.8:456\"]}}]}}"
        ),
    );
    assert_eq!(rec.staged.len(), 3);
    let p = &rec.staged[0];
    assert_eq!((p.action, p.group, p.node_id), (PeerAction::Add, Group::Peers, Some(42)));
    assert_eq!(p.name.as_str(), "server.ts.net");
    assert_eq!(p.node_key, key(1));
    assert_eq!(p.disco_key, key(1));
    assert_eq!(p.vpn_ip, 0x6401_0203);
    assert_eq!(p.endpoint_list(), &[Endpoint { ip: 0x0102_0304, port: 123 }]);
    assert_eq!(p.home_derp, 4);
    assert_eq!(p.online, Some(true));
    assert!(p.is_exit_node);
    assert_eq!(p.route_list(), &[Route { network: 0xc0a8_0500, prefix_len: 24 }]);
    let r = &rec.staged[1];
    assert_eq!((r.action, r.group, r.node_id), (PeerAction::Remove, Group::Removed, Some(12)));
    assert!(r.node_key.is_zero());
    let u = &rec.staged[2];
    assert_eq!((u.action, u.group, u.node_id), (PeerAction::Patch, Group::Patch, Some(42)));
    assert_eq!(u.home_derp, 3);
    assert_eq!(u.online, Some(false));
    assert!(u.endpoints_present);
    assert_eq!(u.endpoint_list(), &[Endpoint { ip: 0x0506_0708, port: 456 }]);
    let s = rec.summary.unwrap();
    assert!(s.authoritative && !s.self_expired && !s.has_self);
    assert_eq!(s.section_entries[2..5], [1, 1, 1]);
}

#[test]
fn semantic_map_changed_and_removal_by_key() {
    let rec =
        ok(4, &format!("{{\"PeersChanged\":[{{\"ID\":43,\"Key\":\"nodekey:{KEY}\",\"Addresses\":[\"100.2.3.4/32\"]}}],\"PeersRemoved\":[\"nodekey:{KEY}\"]}}"));
    assert_eq!(rec.staged.len(), 2);
    assert_eq!(rec.staged[0].group, Group::Changed);
    assert_eq!(rec.staged[0].vpn_ip, 0x6402_0304);
    assert_eq!((rec.staged[1].action, rec.staged[1].node_id), (PeerAction::Remove, None));
    assert_eq!(rec.staged[1].node_key, key(1));
    assert!(!rec.summary.unwrap().authoritative);
}

#[test]
fn semantic_map_full_list_supersedes_changed_regardless_of_root_order() {
    let rec = ok(4, "{\"PeersChanged\":[{\"ID\":2}],\"Peers\":[{\"ID\":1}]}");
    let s = rec.summary.as_ref().unwrap();
    assert!(s.authoritative);
    let effective: Vec<_> = rec.staged.iter().filter(|r| directory::is_effective(r.group, s.authoritative)).map(|r| r.node_id).collect();
    assert_eq!(effective, vec![Some(1)]);
    // and the other order
    let rec = ok(4, "{\"Peers\":[{\"ID\":1}],\"PeersChanged\":[{\"ID\":2}]}");
    let s = rec.summary.as_ref().unwrap();
    let effective: Vec<_> = rec.staged.iter().filter(|r| directory::is_effective(r.group, s.authoritative)).map(|r| r.node_id).collect();
    assert_eq!(effective, vec![Some(1)]);
}

#[test]
fn semantic_map_self_unicode_ip_and_preferred_derp() {
    let rec = ok(
        4,
        "{\"Node\":{\"Name\":\"d\\u00f6ngle\\ud83d\\ude00.ts.net\",\"Addresses\":[\"100.3.4.5/32\"]},\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1},\"2\":{\"RegionID\":2},\
         \"3\":{\"RegionID\":3},\"5\":{\"RegionID\":5},\"4\":{\"RegionID\":4,\"Nodes\":[{\"HostName\":\"derp\",\"IPv4\":\"1.2.3.4\"}]}}}}",
    );
    let n = rec.self_node.unwrap();
    assert_eq!(n.vpn_ip, Some(0x6403_0405));
    assert_eq!(n.name.unwrap().as_str(), "d\u{f6}ngle\u{1f600}.ts.net");
    let d = rec.derp.unwrap();
    assert_eq!(d.count, 4);
    assert_eq!(d.regions[3].region_id, 4);
    assert_eq!(d.regions.iter().take(4).map(|r| r.region_id).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    assert_eq!(d.regions[3].nodes[0].ipv4, Some([1, 2, 3, 4]));
    assert_eq!(rec.order, vec!["self", "derp", "commit"]);
}

fn derp_nodes(json: &str) -> DerpRegion {
    let rec = ok(4, json);
    let d = rec.derp.unwrap();
    assert_eq!(d.count, 1);
    d.regions[0].clone()
}

#[test]
fn semantic_map_cert_name_default_name_pin() {
    let r = derp_nodes(
        "{\"DERPMap\":{\"Regions\":{\"4\":{\"RegionID\":4,\"Nodes\":[{\"HostName\":\"derp4a\",\"CertName\":\"front.example\"},{\"HostName\":\"10.0.0.1\",\"CertName\":\
         \"sha256-raw:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}]}}}}",
    );
    assert_eq!(r.node_count, 2);
    match &r.nodes[0].cert {
        DerpCert::Name(n) => assert_eq!(n.as_str(), "front.example"),
        other => panic!("{other:?}"),
    }
    match &r.nodes[1].cert {
        DerpCert::Pin(p) => assert_eq!((p[0], p[31]), (0x00, 0xff)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn semantic_map_cert_name_unusable_forms_never_fall_back() {
    let r = derp_nodes(
        "{\"DERPMap\":{\"Regions\":{\"4\":{\"RegionID\":4,\"Nodes\":[{\"HostName\":\"derp4a\",\"CertName\":\"sha256-raw:abcd\"},\
         {\"HostName\":\"derp4b\",\"CertName\":7,\"InsecureForTests\":true}]}}}}",
    );
    assert_eq!(r.nodes[0].cert, DerpCert::Invalid); // bad pin
    assert_eq!(r.nodes[1].cert, DerpCert::Invalid); // not a string
    let r = derp_nodes(
        "{\"DERPMap\":{\"Regions\":{\"4\":{\"RegionID\":4,\"Nodes\":[{\"HostName\":\"derp4a\",\"InsecureForTests\":true},{\"HostName\":\"derp4b\",\"CertName\":\"derp4b\"}]}}}}",
    );
    assert_eq!(r.nodes[0].cert, DerpCert::Hostname); // InsecureForTests is not honoured
    assert_eq!(r.nodes[1].cert, DerpCert::Hostname);
    // no HostName: unconnectable
    let r = derp_nodes("{\"DERPMap\":{\"Regions\":{\"4\":{\"RegionID\":4,\"Nodes\":[{\"IPv4\":\"1.2.3.4\"}]}}}}");
    assert_eq!(r.nodes[0].cert, DerpCert::Invalid);
    // a host name too long to keep whole
    let long = "h".repeat(64);
    let r = derp_nodes(&format!("{{\"DERPMap\":{{\"Regions\":{{\"4\":{{\"RegionID\":4,\"Nodes\":[{{\"HostName\":\"{long}\"}}]}}}}}}}}"));
    assert_eq!(r.nodes[0].cert, DerpCert::Invalid);
}

#[test]
fn semantic_map_late_error_applies_nothing() {
    let (r, rec, stats) = run(0, "{\"PeersChanged\":[{\"ID\":1}],\"Node\":{\"Addresses\":[\"100.1.2.3/32\"]},\"Ignored\":\"bad\\q\"}");
    assert_eq!(r, Err(MapError::Json(JsonError::BadEscape)));
    assert_eq!(rec.aborted, Some(MapError::Json(JsonError::BadEscape)));
    assert!(rec.summary.is_none() && rec.self_node.is_none());
    assert_eq!(rec.order.last(), Some(&"abort"));
    assert_eq!(rec.order.iter().filter(|e| **e == "abort").count(), 1);
    assert_eq!(stats.peers_staged.get(), 1); // staged, never committed
}

#[test]
fn semantic_map_sink_refusals_fail_the_map() {
    // staging refused (the C's failed allocation / flash staging)
    let mut rec = Rec { refuse_stage_at: Some(0), ..Default::default() };
    let (r, rec, _) = run_into(MapConfig::new(0), b"{\"Node\":{\"Addresses\":[\"100.1.2.3/32\"]},\"Peers\":[{}]}", 0, &mut rec);
    assert_eq!(r, Err(MapError::SinkRefused));
    assert_eq!(rec.aborted, Some(MapError::SinkRefused));
    assert!(rec.self_node.is_none());
    // commit refused (the C's rejected queue)
    let mut rec = Rec { refuse_commit: true, ..Default::default() };
    let (r, rec, _) = run_into(MapConfig::new(0), b"{\"Node\":{\"Name\":\"unchanged\"},\"Peers\":[]}", 0, &mut rec);
    assert_eq!(r, Err(MapError::CommitRefused));
    assert!(rec.aborted.is_none()); // the sink knows it refused
}

#[test]
fn semantic_map_300kb_discarded_string_keeps_node() {
    let mut j = String::from("{\"Unused\":\"");
    j.push_str(&"x".repeat(300_000));
    j.push_str("\",\"Node\":{\"Name\":\"kept\"}}");
    for chunk in [0, 1, 257, 16000] {
        let (r, rec, stats) = run_cfg(MapConfig::new(0), j.as_bytes(), chunk);
        assert_eq!(r, Ok(()), "chunk {chunk}");
        assert_eq!(rec.self_node.unwrap().name.unwrap().as_str(), "kept");
        assert!(stats.projected_bytes < 64);
        assert_eq!(stats.bytes_in as usize, j.len());
    }
}

#[test]
fn semantic_map_duplicate_control_fields_fail() {
    let (r, rec, _) = run(0, "{\"Node\":{},\"Node\":{\"Name\":\"duplicate\"}}");
    assert_eq!(r, Err(MapError::DuplicateControlField));
    assert!(rec.self_node.is_none() && rec.summary.is_none());
    for dup in ["\"Peers\":[]", "\"PeersChanged\":[]", "\"PeersRemoved\":[]", "\"PeersChangedPatch\":[]", "\"DERPMap\":null"] {
        let (r, _, _) = run(0, &format!("{{{dup},{dup}}}"));
        assert_eq!(r, Err(MapError::DuplicateControlField), "{dup}");
    }
    // case-insensitive, like cJSON: "peers" is Peers
    let (r, _, _) = run(0, "{\"Peers\":[],\"peers\":[]}");
    assert_eq!(r, Err(MapError::DuplicateControlField));
}

#[test]
fn semantic_map_section_over_capacity_in_ram_mode_only() {
    let mut many = String::from("{\"PeersChanged\":[");
    for i in 0..9 {
        many.push_str(if i > 0 { ",{}" } else { "{}" });
    }
    many.push_str("]}");
    let (r, rec, _) = run(0, &many);
    assert_eq!(r, Err(MapError::SectionFull(Group::Changed)));
    assert_eq!(MapError::SectionFull(Group::Changed).message(), "Map peer update section exceeds configured capacity");
    assert!(rec.summary.is_none());
    // exactly eight is fine
    let eight = many.replacen(",{}", "", 1);
    assert_eq!(run(0, &eight).0, Ok(()));
    // the flash directory has no section limit
    let (r, rec, _) = run_flash(0, &many);
    assert_eq!(r, Ok(()));
    assert_eq!(rec.staged.len(), 9);
    // the removal section counts too
    let (r, _, _) = run(0, "{\"PeersRemoved\":[1,2,3,4,5,6,7,8,9]}");
    assert_eq!(r, Err(MapError::SectionFull(Group::Removed)), "the error names the section");
}

#[test]
fn semantic_map_record_too_big() {
    let name = "x".repeat(6000);
    let (r, rec, _) = run(0, &format!("{{\"Node\":{{\"Name\":\"{name}\"}}}}"));
    assert_eq!(r, Err(MapError::RecordTooLarge));
    assert_eq!(MapError::RecordTooLarge.message(), "Map record exceeds 4 KiB capacity");
    assert_eq!(MapError::RecordTooLarge.code(), 6);
    assert!(rec.self_node.is_none() && rec.summary.is_none());
    // a 4,000 byte name fits the record but is a name the C ignores (>= 128)
    let ok_name = "y".repeat(4000);
    let (r, rec, stats) = run(0, &format!("{{\"Node\":{{\"Name\":\"{ok_name}\",\"Addresses\":[\"100.1.1.1/32\"]}}}}"));
    assert_eq!(r, Ok(()));
    assert_eq!(rec.self_node.unwrap().name, None);
    assert_eq!(stats.self_name_ignored.get(), 1);
}

#[test]
fn semantic_map_record_bounds_nodes_and_text() {
    // 129 JSON values in one peer record (the C's cJSON node pool is 128): the peer + 1 + array + 126 strings = 129
    let mut j = String::from("{\"Peers\":[{\"Endpoints\":[");
    for i in 0..127 {
        j.push_str(if i > 0 { ",\"x\"" } else { "\"x\"" });
    }
    j.push_str("]}]}");
    assert_eq!(run(0, &j).0, Err(MapError::RecordDecode)); // 1 object + 1 array + 127 = 129
    let j2 = j.replacen(",\"x\"", "", 1);
    assert_eq!(run(0, &j2).0, Ok(())); // 128
    // NUL escape and a lone surrogate in retained text are refused ...
    assert_eq!(run(0, "{\"Peers\":[{\"Name\":\"a\\u0000b\"}]}").0, Err(MapError::RecordDecode));
    assert_eq!(run(0, "{\"Peers\":[{\"Name\":\"a\\ud800\"}]}").0, Err(MapError::RecordDecode));
    assert_eq!(run(0, "{\"Peers\":[{\"Name\":\"a\\udc00b\"}]}").0, Err(MapError::RecordDecode));
    assert_eq!(run(0, "{\"Peers\":[{\"Name\":\"\\ud83dx\"}]}").0, Err(MapError::RecordDecode));
    // ... but fine in a discarded field
    assert_eq!(run(0, "{\"Ignored\":\"a\\u0000b\\ud800\",\"Peers\":[{\"Hostinfo\":{\"x\":\"\\udc00\"}}]}").0, Ok(()));
    // invalid UTF-8 in retained text is refused (the C passes the bytes through; the port needs text)
    let mut bytes = b"{\"Peers\":[{\"Name\":\"a".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    bytes.extend_from_slice(b"\"}]}");
    assert_eq!(run_cfg(MapConfig::new(0), &bytes, 0).0, Err(MapError::RecordDecode));
    // retained text budget: 4096 string bytes, one NUL per string and key
    let long = "a".repeat(200);
    let mut j = String::from("{\"PeersRemoved\":[{\"k\":[");
    for i in 0..20 {
        j.push_str(if i > 0 { ",\"" } else { "\"" });
        j.push_str(&long[..200]);
        j.push('"');
    }
    j.push_str("]}]}"); // 20 * 201 = 4020 + "k\0" 2 = 4022 <= 4096, raw 20*203 + ... < 4095? 4060+..
    let r = run(0, &j).0;
    assert!(r == Ok(()) || r == Err(MapError::RecordTooLarge), "{r:?}");
    let mut j = String::from("{\"PeersRemoved\":[{\"k\":[");
    for i in 0..21 {
        j.push_str(if i > 0 { ",\"" } else { "\"" });
        j.push_str(&"a".repeat(195));
        j.push('"');
    }
    j.push_str("]}]}"); // raw 21*198-ish = 4158 > 4095
    assert_eq!(run(0, &j).0, Err(MapError::RecordTooLarge));
}

#[test]
fn semantic_map_one_thousand_peers_in_256_byte_chunks() {
    // test_semantic_directory.c + the framed 257-byte reader of test_semantic_map.c, at the projector level
    let json = many_peers(1000);
    let (r, rec, stats) = run_cfg(MapConfig::new(0).with_flash_directory(), json.as_bytes(), 257);
    assert_eq!(r, Ok(()));
    assert_eq!(rec.staged.len(), 1000);
    assert_eq!(stats.peers_staged.get(), 1000);
    assert!(rec.summary.as_ref().unwrap().authoritative);
    let mut dir = Dir::default();
    dir.apply_map(&rec);
    assert_eq!(dir.count(), 1000);
    assert_eq!(dir.find_id(1000).unwrap().vpn_ip, 0x6440_03e8);
    // malformed tail cannot expose an already parsed replacement peer
    let bad = format!("{{\"Peers\":[{{\"ID\":2000,\"Key\":\"nodekey:{KEY}\",\"Addresses\":[\"100.64.9.1/32\"]}}],\"Bad\":}}");
    let (r, rec2, _) = run_flash(0, &bad);
    assert!(r.is_err());
    assert_eq!(rec2.aborted, Some(MapError::Json(JsonError::Unexpected(b'}'))));
    dir.apply_map(&rec2);
    assert!(dir.find_id(2000).is_none() && dir.find_id(1000).is_some());
    // more than eight removals is legitimate
    let (r, rec3, _) = run_flash(0, "{\"PeersRemoved\":[1,2,3,4,5,6,7,8,9,10,11,12] }");
    assert_eq!(r, Ok(()));
    dir.apply_map(&rec3);
    assert!(dir.find_id(12).is_none() && dir.find_id(1000).is_some() && dir.find_id(13).is_some());
    // an Expired peer is a removal
    let (r, rec4, _) = run_flash(0, "{\"PeersChanged\":[{\"ID\":1000,\"Expired\":true}]}");
    assert_eq!(r, Ok(()));
    assert_eq!(rec4.staged[0].action, PeerAction::Remove);
    dir.apply_map(&rec4);
    assert!(dir.find_id(1000).is_none());
}

#[test]
fn semantic_map_authoritative_replaces_all_slots() {
    // "production batch consumer replaces eight occupied slots": an authoritative one-peer list drops the seven others and the eight-slot working set
    let mut dir = Dir::default();
    let mut eight = String::from("{\"Peers\":[");
    for i in 2..=9u8 {
        if i > 2 {
            eight.push(',');
        }
        eight.push_str(&format!("{{\"ID\":{i},\"Key\":\"nodekey:{}\",\"Addresses\":[\"100.64.0.{i}/32\"]}}", key_hex(i)));
    }
    eight.push_str("]}");
    dir.apply_map(&ok(0, &eight));
    assert_eq!(dir.count(), 8);
    dir.apply_map(&ok(0, &format!("{{\"Peers\":[{{\"Key\":\"nodekey:{KEY}\",\"ID\":1,\"Addresses\":[\"100.64.0.1/32\"]}}]}}")));
    assert_eq!(dir.count(), 1);
    assert_eq!(dir.slots[0].node_key, key(1));
}

#[test]
fn semantic_map_expired_self_is_flagged_for_the_commit() {
    let rec = ok(4, "{\"Node\":{\"Expired\":true,\"Name\":\"n\",\"Addresses\":[\"100.1.2.3/32\"]},\"DERPMap\":{\"Regions\":{}},\"Peers\":[{\"ID\":1}]}");
    let s = rec.summary.unwrap();
    assert!(s.self_expired && s.has_self);
    assert!(rec.self_node.unwrap().expired);
    assert!(rec.derp.is_none(), "the C applies no DERP map for an expired node");
    assert_eq!(rec.staged.len(), 1);
}

#[test]
fn semantic_map_node_type_and_derp_type_checks() {
    assert_eq!(run(0, "{\"Node\":\"x\"}").0, Err(MapError::BadSelfNode));
    assert_eq!(run(0, "{\"Node\":[1]}").0, Err(MapError::BadSelfNode));
    assert_eq!(run(0, "{\"Node\":null}").0, Ok(()));
    assert_eq!(run(0, "{\"DERPMap\":5}").0, Err(MapError::BadDerpMap));
    assert_eq!(run(0, "{\"DERPMap\":{\"Regions\":null}}").0, Err(MapError::BadDerpMap));
    assert_eq!(run(0, "{\"DERPMap\":{\"Regions\":{\"1\":5}}}").0, Err(MapError::BadDerpMap));
    assert_eq!(run(0, "{\"DERPMap\":{\"Regions\":{}}}").0, Ok(()));
    let rec = ok(0, "{\"DERPMap\":{\"Regions\":{}}}");
    assert_eq!(rec.derp.unwrap().count, 0);
    // a non-array Peers is ignored, not authoritative
    let rec = ok(0, "{\"Peers\":null}");
    assert!(!rec.summary.unwrap().authoritative);
}

// ---- test_projection.c ----------------------------------------------------------------------------------------------------------------------------

#[test]
fn projection_keeps_what_the_c_keeps_and_counts_the_rest() {
    let fixture = " {\"Node\":{\"Addresses\":[\"100.64.0.1/32\"],\"Expired\":false,\"Hostinfo\":{\"large\":[1,2,3]}},\"Peers\":[{\"ID\":3,\"Key\":\"nodekey:a\",\"Name\":\
        \"quote\\\"slash\\\\unicode\\u1234\",\"AllowedIPs\":[\"10.0.0.0/8\"],\"Hostinfo\":{\"unused\":true}}],\"PeersChangedPatch\":[{\"NodeID\":3,\"Online\":false}],\
        \"PeersRemoved\":[4],\"PacketFilter\":[{\"unused\":null}]} ";
    let (r, rec, stats) = run(99, fixture);
    assert_eq!(r, Ok(()));
    assert!(stats.projected_bytes > 0 && (stats.projected_bytes as usize) < fixture.len());
    assert_eq!(rec.self_node.as_ref().unwrap().vpn_ip, Some(0x6440_0001));
    assert_eq!(rec.staged.len(), 3);
    assert_eq!(rec.staged[0].name.as_str(), "quote\"slash\\unicode\u{1234}");
    assert!(rec.staged[0].node_key.is_zero()); // "nodekey:a" is not a key
    assert_eq!(stats.keys_bad.get(), 1);
    assert_eq!(rec.staged[0].route_list(), &[Route { network: 0x0a00_0000, prefix_len: 8 }]);
    assert!(rec.summary.unwrap().packet_filter_seen);
    assert_eq!(stats.fields_skipped.get(), 2); // Node.Hostinfo and the peer's Hostinfo (PacketFilter is known and noted)
}

#[test]
fn projection_rejects_malformed_discarded_values() {
    for bad in [
        "{\"ignored\":01}",
        "{\"ignored\":1.}",
        "{\"ignored\":1e+}",
        "{\"ignored\":tru}",
        "{\"ignored\":\"\\x\"}",
        "{\"ignored\":[1,]}",
        "{\"ignored\":{\"a\":1,}}",
        "{} garbage",
        "[]",
        "{\"Node\":{\"Addresses\":[1]",
        "{\"Unused\":\"bad\\q\"}",
        "{\"Unused\":[1,]}",
        "{\"Unused\":01}",
        "{\"Unused\":truee}",
        "{\"Unused\":{\"x\":}}",
        "{}{}",
        "",
        "   ",
    ] {
        let (r, rec, _) = run(99, bad);
        assert!(r.is_err(), "{bad:?}");
        if !bad.trim().is_empty() {
            assert!(rec.summary.is_none(), "{bad:?}");
        }
    }
}

#[test]
fn projection_eighty_regions_keep_four_and_the_preferred_one() {
    let mut j = String::from("{\"DERPMap\":{\"Regions\":{");
    for i in 1..=80 {
        j.push_str(&format!(
            "{}\"{i}\":{{\"RegionID\":{i},\"RegionCode\":\"r{i}\",\"Nodes\":[{{\"HostName\":\"derp.example.com\",\"IPv4\":\"1.2.3.4\",\"IPv6\":\"::1\",\"DERPPort\":443,\"STUNPort\":3478,\
             \"STUNOnly\":false,\"unused\":{{\"many\":[1,2,3,4,5,6,7,8,9]}}}}]}}",
            if i == 1 { "" } else { "," }
        ));
    }
    j.push_str("}}}");
    let (r, rec, stats) = run(79, &j);
    assert_eq!(r, Ok(()));
    let d = rec.derp.unwrap();
    assert_eq!(d.region_list().iter().map(|r| r.region_id).collect::<Vec<_>>(), vec![1, 2, 3, 79]);
    assert_eq!(stats.derp_regions_replaced.get(), 1);
    assert_eq!(stats.derp_regions_dropped.get(), 75);
    assert!((stats.projected_bytes as usize) < j.len() / 5);
    assert_eq!(d.regions[3].nodes[0].ipv6, Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(d.regions[0].nodes[0].derp_port, 443);
    // a home region that is not in the map: the first four stay
    let (_, rec, stats) = run(500, &j);
    assert_eq!(rec.derp.unwrap().region_list().iter().map(|r| r.region_id).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    assert_eq!(stats.derp_regions_dropped.get(), 76);
}

#[test]
fn projection_nesting_fails_even_in_discarded_metadata() {
    let mut j = String::from("{\"unused\":");
    j.push_str(&"[".repeat(40));
    j.push('0');
    j.push_str(&"]".repeat(40));
    j.push('}');
    assert_eq!(run(99, &j).0, Err(MapError::Json(JsonError::Depth)));
    // C's streaming test: root + 32 nested arrays is 33 containers: refused
    let mut j = String::from("{\"Unused\":");
    j.push_str(&"[".repeat(32));
    j.push_str(&"]".repeat(32));
    j.push('}');
    assert_eq!(run(0, &j).0, Err(MapError::Json(JsonError::Depth)));
    // 31 nested arrays plus the root object is exactly 32
    let mut j = String::from("{\"Unused\":");
    j.push_str(&"[".repeat(31));
    j.push_str(&"]".repeat(31));
    j.push('}');
    assert_eq!(run(0, &j).0, Ok(()));
}

#[test]
fn projection_public_derp_map_fixture() {
    let fixture = std::fs::read_to_string("tests/fixtures/derp-map-2026-10-01.json").unwrap();
    let j = format!("{{\"DERPMap\":{fixture}}}");
    let (r, rec, stats) = run(4, &j);
    assert_eq!(r, Ok(()));
    let d = rec.derp.unwrap();
    assert_eq!(d.count, 4);
    assert!(d.region_list().iter().any(|r| r.region_id == 4), "the preferred region survives");
    assert!((stats.projected_bytes as usize) < j.len() / 3);
    for r in d.region_list() {
        assert!(r.node_count as usize <= MAX_DERP_NODES_FOR_TEST);
        assert!(!r.code.is_empty() && !r.name.is_empty() || r.region_id == 0);
        for n in r.node_list() {
            assert_eq!(n.cert, DerpCert::Hostname);
            assert!(n.ipv4.is_some() && n.can_port80);
        }
    }
    // exactly the first four regions in key order when home is not among the first four
    let (_, rec, _) = run(999, &j);
    assert_eq!(rec.derp.unwrap().count, 4);
}
const MAX_DERP_NODES_FOR_TEST: usize = 2;

#[test]
fn projection_escaped_member_names_and_case() {
    let rec = ok(4, "{\"\\u004eode\":{\"Addresses\":[\"100.64.0.1/32\"]}}");
    assert_eq!(rec.self_node.unwrap().vpn_ip, Some(0x6440_0001));
    let rec = ok(4, "{\"NODE\":{\"nAmE\":\"x\"},\"PEERS\":[{\"id\":9}]}");
    assert_eq!(rec.self_node.unwrap().name.unwrap().as_str(), "x");
    assert_eq!(rec.staged[0].node_id, Some(9));
    // a member name that decodes above ASCII never matches
    let rec = ok(4, "{\"\\u00d6de\":1,\"Node\":{}}");
    assert!(rec.self_node.is_some());
}

// ---- test_project_stream.c ------------------------------------------------------------------------------------------------------------------------

#[test]
fn stream_byte_by_byte_equals_whole() {
    let inputs = [
        "{\"Node\":{\"Name\":\"dongle.example.ts.net\",\"Addresses\":[\"100.90.1.1/32\"],\"Expired\":false},\"PeersChanged\":[{\"ID\":123,\"Name\":\"peer\",\"Online\":true}],\
         \"PeersRemoved\":[42],\"PeersChangedPatch\":[{\"NodeID\":123,\"Endpoints\":[\"1.2.3.4:5\"]}],\"Ignored\":{\"escaped\":\"a\\u0030\\\\b\"}}",
        "{\"Peers\":[{\"ID\":1,\"Name\":\"a.ts.net\",\"Addresses\":[\"100.1.2.3/32\"],\"Key\":\"nodekey:test\"}],\"PeersRemoved\":[1]}",
        "{\"DERPMap\":{\"Regions\":{\"1\":{},\"2\":{},\"3\":{},\"5\":{},\"6\":{},\"4\":{\"Nodes\":[{\"HostName\":\"derp\",\"IPv4\":\"1.2.3.4\"}]}}}}",
        "{\"\\u004eode\":{\"ID\":-12.34e+2},\"Dropped\":[null,false,true,{},[]]}",
    ];
    for input in inputs {
        let (r1, whole, s1) = run(4, input);
        assert_eq!(r1, Ok(()));
        let (r2, bytes, s2) = run_cfg(MapConfig::new(4), input.as_bytes(), 1);
        assert_eq!(r2, Ok(()));
        assert_eq!(format!("{whole:?}"), format!("{bytes:?}"));
        assert_eq!(s1, s2);
    }
    // the third: regions 1,2,3,5 then 4 (preferred) replaces 5
    let rec = ok(4, inputs[2]);
    assert_eq!(rec.derp.unwrap().count, 4);
    // the fourth: a non-integer ID is truncated like (uint64_t)(int64_t)double
    let rec = ok(4, inputs[3]);
    assert_eq!(rec.self_node.unwrap().node_id, Some((-1234i64) as u64));
}

#[test]
fn stream_300kb_byte_by_byte_with_retained_identity() {
    let mut large = String::from("{\"Unused\":\"");
    large.push_str(&"x".repeat(300_000));
    large.push_str("\",\"Node\":{\"Name\":\"kept\",\"Addresses\":[\"100.1.2.3/32\"]}}");
    let (r, rec, _) = run_cfg(MapConfig::new(4), large.as_bytes(), 1);
    assert_eq!(r, Ok(()));
    let n = rec.self_node.unwrap();
    assert_eq!((n.name.unwrap().as_str(), n.vpn_ip), ("kept", Some(0x6401_0203)));
}

#[test]
fn stream_malformed_after_the_fact_and_retained_overflow() {
    for bad in ["{\"Unused\":\"bad\\q\"}", "{\"Unused\":[1,]}", "{\"Unused\":01}", "{\"Unused\":truee}", "{\"Unused\":{\"x\":}}", "{}{}"] {
        let (r, _, _) = run(4, bad);
        assert!(r.is_err(), "{bad}");
    }
    // the C's "retained map exceeds capacity" is, per record, a bound on the record
    let big = format!("{{\"Node\":{{\"Name\":\"{}\"}}}}", "a".repeat(5000));
    assert_eq!(run(4, &big).0, Err(MapError::RecordTooLarge));
}

// ---- test_json_depth.c ----------------------------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Depth {
    max: usize,
    cur: usize,
}
impl TokenSink for Depth {
    type Error = ();
    fn event(&mut self, e: Event<'_>) -> Result<(), ()> {
        match e {
            Event::StartObject | Event::StartArray => {
                self.cur += 1;
                self.max = self.max.max(self.cur);
            }
            Event::EndObject | Event::EndArray => self.cur -= 1,
            _ => {}
        }
        Ok(())
    }
}

fn nested(depth: usize, objects: bool, leaf: &str) -> String {
    let mut s = String::new();
    for _ in 0..depth {
        s.push_str(if objects { "{\"a\":" } else { "[" });
    }
    s.push_str(leaf);
    for _ in 0..depth {
        s.push(if objects { '}' } else { ']' });
    }
    s
}

fn depth_of(doc: &str) -> Result<usize, JsonError> {
    let mut t = Tokenizer::new(Policy::CCompat);
    let mut d = Depth::default();
    t.feed(doc.as_bytes(), &mut d).map_err(|e| match e {
        tdongle_tailnet_map::json::ParseError::Json(j) => j,
        _ => unreachable!(),
    })?;
    t.finish(&mut d).map_err(|e| match e {
        tdongle_tailnet_map::json::ParseError::Json(j) => j,
        _ => unreachable!(),
    })?;
    Ok(d.max)
}

#[test]
fn json_depth_bombs_are_refused_with_a_fixed_state() {
    for objects in [false, true] {
        let bomb = nested(5000, objects, "1");
        let mut t = Tokenizer::new(Policy::CCompat);
        let mut d = Depth::default();
        let e = t.feed(bomb.as_bytes(), &mut d);
        assert_eq!(e, Err(tdongle_tailnet_map::json::ParseError::Json(JsonError::Depth)));
        assert_eq!(d.max, MAX_DEPTH, "never opened more than the limit");
        assert!(t.consumed() < 5 * (MAX_DEPTH as u64 + 2));
        // poisoned until reset
        assert_eq!(t.feed(b"1", &mut d), Err(tdongle_tailnet_map::json::ParseError::Json(JsonError::Poisoned)));
        // the same through the projector: no recursion anywhere, an Abort
        let (r, rec, _) = run(0, &format!("{{\"x\":{bomb}}}"));
        assert_eq!(r, Err(MapError::Json(JsonError::Depth)));
        assert_eq!(rec.aborted, Some(MapError::Json(JsonError::Depth)));
        // exactly the limit parses, one more does not
        assert_eq!(depth_of(&nested(MAX_DEPTH, objects, "1")), Ok(MAX_DEPTH));
        assert_eq!(depth_of(&nested(MAX_DEPTH + 1, objects, "1")), Err(JsonError::Depth));
    }
    assert_eq!(std::mem::size_of::<Tokenizer>(), Tokenizer::STATE_BYTES);
}

#[test]
fn json_depth_real_tailscale_documents_are_shallow() {
    let cap_map = "{\"Node\":{\"CapMap\":{\"https://tailscale.com/cap/app-connectors\":[{\"name\":\"a\",\"domains\":[\"x\"],\"routes\":[\"10.0.0.0/8\"],\"extra\":{\"k\":[{\"v\":[1]}]}}]}},\
        \"PacketFilters\":{\"base\":[{\"SrcIPs\":[\"*\"],\"CapGrant\":[{\"Dsts\":[\"*\"],\"CapMap\":{\"cap\":[{\"o\":{\"p\":[1]}}]}}]}]},\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"HostName\":\"d\"}]}}}}";
    let d = depth_of(cap_map).unwrap();
    assert!(d <= 12 && d * 2 < MAX_DEPTH, "{d}");
    assert_eq!(run(1, cap_map).0, Ok(()));
    let fixture = std::fs::read_to_string("tests/fixtures/derp-map-2026-10-01.json").unwrap();
    assert!(depth_of(&fixture).unwrap() < MAX_DEPTH / 2);
    // the control documents' pre-check (json_nesting_within)
    assert!(nesting_within(br#"{"publicKey":"mkey:00"}"#, 4));
    assert!(!nesting_within(b"[[[[[1]]]]]", 4));
    assert!(nesting_within(br#"["[[[[[[[[["]"#, 4), "brackets inside strings do not count");
    assert!(nesting_within(br#"{"a":"\"[[[[[[["}"#, 4), "an escaped quote does not end the string");
    assert!(!nesting_within(&nested(17, false, "1").into_bytes(), tdongle_tailnet_map::json::DEPTH_REGISTER));
    assert!(nesting_within(&nested(16, false, "1").into_bytes(), tdongle_tailnet_map::json::DEPTH_REGISTER));
}

// ---- test_published_name.c (value semantics; the seqlock is the runtime's mutex now) ---------------------------------------------------------------

#[test]
fn published_name_set_get_and_bounds() {
    let mut n = PublishedName::new();
    assert_eq!((n.get(), n.seq()), ("", 0));
    assert!(n.set("dongle.old-tailnet"));
    assert_eq!((n.get(), n.seq()), ("dongle.old-tailnet", 2));
    assert!(n.set("gw.corp.ts.net"));
    assert_eq!(n.get(), "gw.corp.ts.net", "a shorter name fully replaces a longer one (no 'gw.corpold-tailnet')");
    // 127 bytes fit, 128 do not and leave the old value
    let max = "m".repeat(127);
    assert!(n.set(&max));
    assert_eq!(n.get(), max);
    assert!(!n.set(&"m".repeat(128)));
    assert_eq!((n.get(), n.seq()), (max.as_str(), 6));
    assert!(n.set(""));
    assert_eq!(n.get(), "");
    // names of every length 1..=127 round-trip
    for len in 1..=127 {
        let s = "a".repeat(len);
        assert!(n.set(&s));
        assert_eq!(n.get(), s);
        assert_eq!(n.seq() % 2, 0);
    }
}

#[test]
fn published_name_follows_the_self_node_of_a_map() {
    let rec = ok(0, "{\"Node\":{\"Name\":\"d\\u00f6ngle.ts.net\"}}");
    let mut n = PublishedName::new();
    assert!(n.set(rec.self_node.unwrap().name.unwrap().as_str()));
    assert_eq!(n.get(), "d\u{f6}ngle.ts.net");
    // a 128-byte name is ignored by the map, so the published one stays
    let long = "z".repeat(128);
    let rec = ok(0, &format!("{{\"Node\":{{\"Name\":\"{long}\"}}}}"));
    assert_eq!(rec.self_node.unwrap().name, None);
    assert_eq!(n.get(), "d\u{f6}ngle.ts.net");
}

// ---- test_peer_directory.c: the pure rules --------------------------------------------------------------------------------------------------------

fn peer(id: u64) -> PeerRecord {
    let mut p = PeerRecord::new(PeerAction::Add, Group::Peers);
    p.vpn_ip = 0x6440_0000 + id as u32;
    p.node_id = Some(id);
    p.node_key = tdongle_tailnet_types::Key32({
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&id.to_le_bytes());
        k
    });
    p.disco_key.0[0] = id as u8;
    p.endpoints[0] = Endpoint { ip: id as u32, port: 0 };
    p.endpoint_count = 1;
    p.name.set(&format!("peer-{id}"));
    p
}

#[test]
fn peer_directory_rules() {
    let mut a = Dir::default();
    let staged: Vec<_> = (1..=1000).map(peer).collect();
    a.commit(&staged, true);
    assert_eq!(a.count(), 1000);
    assert_eq!(a.find_ip(0x6440_03e8).unwrap().node_id, Some(1000));
    // an independent membership never sees it
    let mut b = Dir::default();
    assert!(b.find_ip(0x6440_03e8).is_none());
    let mut p = peer(1000);
    p.node_key.0[0] = 77;
    b.commit(&[p.clone()], true);
    assert_eq!(b.find_ip(p.vpn_ip).unwrap().node_key.0[0], 77);
    // removal and key rotation; absent endpoints keep, explicit empty clears
    let mut rm = peer(10);
    rm.action = PeerAction::Remove;
    rm.group = Group::Removed;
    let mut rot = PeerRecord::new(PeerAction::Patch, Group::Patch);
    rot.node_id = Some(1000);
    rot.node_key.0[0] = 99;
    rot.endpoints_present = false;
    a.commit(&[rm, rot.clone()], false);
    assert!(a.find_ip(0x6440_000a).is_none());
    let r = a.find_id(1000).unwrap();
    assert_eq!((r.node_key.0[0], r.endpoint_count), (99, 1));
    rot.endpoints_present = true;
    rot.endpoint_count = 0;
    a.commit(&[rot], false);
    assert_eq!(a.find_id(1000).unwrap().endpoint_count, 0);
    // a patch for an unknown peer changes nothing
    let mut ghost = PeerRecord::new(PeerAction::Patch, Group::Patch);
    ghost.node_id = Some(424242);
    ghost.online = Some(true);
    let before = a.count();
    a.commit(&[ghost], false);
    assert_eq!(a.count(), before);
    // authoritative omission removes every prior record, not merely warm peers
    a.commit(&[peer(2000)], true);
    assert!(a.find_id(1000).is_none());
    assert!(a.find_ip(peer(2000).vpn_ip).is_some());
    // staged operations are applied add, remove, patch regardless of the order they arrived in
    let mut add = peer(3000);
    add.online = Some(false);
    let mut patch = PeerRecord::new(PeerAction::Patch, Group::Patch);
    patch.node_id = Some(3000);
    patch.online = Some(true);
    let mut rm3 = peer(3000);
    rm3.action = PeerAction::Remove;
    a.commit(&[patch.clone(), rm3.clone(), add.clone()], false);
    assert!(a.find_id(3000).is_none(), "add, then remove, then patch of nothing");
    a.commit(&[patch, add], false);
    assert_eq!(a.find_id(3000).unwrap().online, Some(true));
}

#[test]
fn peer_directory_match_rules_and_empty_slots() {
    let by_id = peer(1);
    let mut upd = peer(1);
    upd.node_key.0[0] ^= 0xff; // rotated key, same node id
    assert!(directory::same_peer(&by_id, &upd));
    let mut no_id = upd.clone();
    no_id.node_id = None;
    assert!(!directory::same_peer(&by_id, &no_id), "an update without id matches by key only");
    no_id.node_key = by_id.node_key.clone();
    assert!(directory::same_peer(&by_id, &no_id));
    let mut other = peer(2);
    other.node_key = by_id.node_key.clone();
    assert!(!directory::same_peer(&by_id, &other), "different ids never match, even with the same key");
    assert!(!directory::is_storable(&PeerRecord::new(PeerAction::Add, Group::Peers)));
    assert_eq!(directory::commit_pass(PeerAction::Add), 0);
    assert_eq!(directory::commit_pass(PeerAction::Remove), 1);
    assert_eq!(directory::commit_pass(PeerAction::Patch), 2);
}

#[test]
fn authoritative_map_end_to_end_with_the_model_directory() {
    let mut dir = Dir::default();
    let rec = ok(4, &std::fs::read_to_string("tests/fixtures/map-full.json").unwrap());
    dir.apply_map(&rec);
    assert_eq!(dir.count(), 2, "p4 is expired (a removal), the others have addresses");
    let delta = ok(4, &std::fs::read_to_string("tests/fixtures/map-delta.json").unwrap());
    dir.apply_map(&delta);
    assert_eq!(dir.find_id(2).unwrap().online, Some(false)); // the patch, then the OnlineChange
    assert!(dir.find_id(3).is_none());
    assert!(dir.find_id(5).is_some());
}
