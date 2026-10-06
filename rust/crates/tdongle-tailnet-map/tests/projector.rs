//! The projector against an independent DOM-based reference, chunking invariance, and a deterministic mini-fuzz.

mod common;

use common::*;
use proptest::prelude::*;
use serde_json::{Value, json};
use tdongle_tailnet_map::derp_cert::{DerpCert, cert_parse};
use tdongle_tailnet_map::project::*;
use tdongle_tailnet_map::*;
use tdongle_tailnet_types::{FixedStr, Key32};

// ---- the reference: what the C does to a parsed tree, written against serde_json::Value -------------------------------------------------------------

fn s_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn key_of(v: Option<&Value>, prefix: &str) -> Key32 {
    match s_of(v) {
        Some(s) => {
            let h = s.strip_prefix(prefix).unwrap_or(s);
            if h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()) {
                let mut k = [0u8; 32];
                for i in 0..32 {
                    k[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
                }
                Key32(k)
            } else {
                Key32::ZERO
            }
        }
        None => Key32::ZERO,
    }
}

fn v4(s: &str) -> Option<u32> {
    s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

fn prefix_len(s: &str) -> Option<u8> {
    (!s.is_empty() && s.len() <= 3 && s.bytes().all(|c| c.is_ascii_digit())).then(|| s.parse::<u16>().ok().filter(|v| *v <= 32).map(|v| v as u8)).flatten()
}

fn num_u64(v: &Value) -> Option<u64> {
    v.as_f64().map(|f| (f as i64) as u64)
}

fn num_i32(v: &Value) -> Option<i32> {
    v.as_f64().map(|f| f as i32)
}

fn cut(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

fn ref_peer(p: &Value, group: Group) -> PeerRecord {
    let patch = group == Group::Patch;
    let mut r = PeerRecord::new(if patch { PeerAction::Patch } else { PeerAction::Add }, group);
    let g = |k: &str| p.get(k);
    if patch {
        r.node_id = g("NodeID").and_then(num_u64);
    } else {
        r.node_id = g("ID").and_then(num_u64);
        if g("Expired") == Some(&Value::Bool(true)) {
            r.action = PeerAction::Remove;
        }
        if let Some(n) = s_of(g("Name")) {
            let c = cut(n, 63);
            r.name.set(c.strip_suffix('.').unwrap_or(c));
        }
        r.machine_key = key_of(g("Machine"), "mkey:");
        if let Some(a) = g("Addresses").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str) {
            let (ip, len) = a.split_once('/').map_or((a, None), |(i, l)| (i, Some(l)));
            if len.is_none_or(|l| prefix_len(l).is_some())
                && let Some(ip) = v4(ip)
            {
                r.vpn_ip = ip;
            }
        }
        let modern = g("HomeDERP").and_then(num_i32).filter(|v| *v > 0).and_then(|v| u16::try_from(v).ok()).unwrap_or(0);
        let legacy = s_of(g("DERP"))
            .and_then(|s| s.strip_prefix("127.3.3.40:"))
            .filter(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|d| d.parse::<u16>().ok())
            .unwrap_or(0);
        r.home_derp = if modern > 0 { modern } else { legacy };
        if let Some(arr) = g("AllowedIPs").and_then(Value::as_array) {
            for s in arr.iter().filter_map(Value::as_str) {
                if s == "0.0.0.0/0" {
                    r.is_exit_node = true;
                    continue;
                }
                let Some((ip, l)) = s.split_once('/') else { continue };
                let (Some(ip), Some(l)) = (v4(ip), prefix_len(l)) else { continue };
                if ip & 0xffc0_0000 == 0x6440_0000 {
                    continue;
                }
                if (r.route_count as usize) < MAX_PEER_ROUTES_T {
                    r.routes[r.route_count as usize] = Route { network: ip, prefix_len: l };
                    r.route_count += 1;
                }
            }
        }
        r.tag_count = g("Tags").and_then(Value::as_array).map_or(0, |a| a.iter().filter(|t| t.is_string()).count().min(255) as u8);
    }
    r.node_key = key_of(g("Key"), "nodekey:");
    r.disco_key = key_of(g("DiscoKey"), "discokey:");
    if patch && let Some(v) = g("DERPRegion").and_then(num_i32).filter(|v| *v > 0).and_then(|v| u16::try_from(v).ok()) {
        r.home_derp = v;
    }
    if let Some(arr) = g("Endpoints").and_then(Value::as_array) {
        r.endpoints_present = true;
        for s in arr.iter().filter_map(Value::as_str) {
            if r.endpoint_count as usize >= MAX_ENDPOINTS_T {
                break;
            }
            if let Ok(sa) = s.parse::<std::net::SocketAddrV4>() {
                r.endpoints[r.endpoint_count as usize] = Endpoint { ip: u32::from(*sa.ip()), port: sa.port() };
                r.endpoint_count += 1;
            }
        }
    }
    if let Some(Value::Bool(b)) = g("Online") {
        r.online = Some(*b);
    }
    if let Some(c) = g("Cap").and_then(Value::as_i64).and_then(|c| u32::try_from(c).ok()) {
        r.cap = c;
    }
    r
}
const MAX_PEER_ROUTES_T: usize = 8;
const MAX_ENDPOINTS_T: usize = 8;

fn ref_expiry(p: &Value) -> i64 {
    s_of(p.get("KeyExpiry"))
        .and_then(|s| s.strip_suffix('Z'))
        .and_then(|s| {
            // 2027-03-14T15:09:26 only (the generator's shape)
            let (d, t) = s.split_once('T')?;
            let mut di = d.split('-').map(|x| x.parse::<i64>().ok());
            let (y, m, dd) = (di.next()??, di.next()??, di.next()??);
            let mut ti = t.split(':').map(|x| x.parse::<i64>().ok());
            let (h, mi, se) = (ti.next()??, ti.next()??, ti.next()??);
            if y < 1970 {
                return None;
            }
            // days from civil
            let y2 = if m <= 2 { y - 1 } else { y };
            let era = y2.div_euclid(400);
            let yoe = y2 - era * 400;
            let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + dd - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            Some((era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + se)
        })
        .unwrap_or(0)
}

type RefNode = (String, Option<[u8; 4]>, u16, u16, bool, bool, bool, DerpCert);
type RefRegion = (u16, String, String, bool, Vec<RefNode>);

#[derive(Debug, PartialEq)]
struct Expected {
    staged: Vec<PeerRecord>,
    self_node: Option<SelfNode>,
    derp: Option<Vec<RefRegion>>,
    authoritative: bool,
}

fn reference(map: &Value, home: u16) -> Result<Expected, MapError> {
    let mut e = Expected { staged: vec![], self_node: None, derp: None, authoritative: false };
    let root = map.as_object().unwrap();
    // document order of the rendering is the BTreeMap's: Node, DERPMap, PeersChanged..., but staging order is what the stream sees
    for (k, v) in root {
        match k.as_str() {
            "Node" => match v {
                Value::Null => {}
                Value::Object(_) => {
                    let r = ref_peer(v, Group::Peers);
                    let mut n = SelfNode::new();
                    n.node_id = r.node_id;
                    n.node_key = r.node_key.clone();
                    n.disco_key = r.disco_key.clone();
                    n.machine_key = r.machine_key.clone();
                    n.home_derp = v.get("HomeDERP").and_then(num_i32).filter(|v| *v > 0).and_then(|v| u16::try_from(v).ok()).unwrap_or(0);
                    n.cap = r.cap;
                    n.tag_count = r.tag_count;
                    n.key_expiry = ref_expiry(v);
                    n.expired = v.get("Expired") == Some(&Value::Bool(true));
                    n.vpn_ip = v.get("Addresses").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str).and_then(|a| {
                        let (ip, len) = a.split_once('/').map_or((a, None), |(i, l)| (i, Some(l)));
                        if len.is_none_or(|l| prefix_len(l).is_some()) { v4(ip) } else { None }
                    });
                    if let Some(name) = s_of(v.get("Name")).filter(|s| s.len() < 128) {
                        let mut f = FixedStr::new();
                        f.set(name);
                        n.name = Some(f);
                    }
                    e.self_node = Some(n);
                }
                _ => return Err(MapError::BadSelfNode),
            },
            "Peers" => {
                if let Value::Array(a) = v {
                    e.authoritative = true;
                    for p in a.iter().filter(|p| p.is_object()) {
                        let mut r = ref_peer(p, Group::Peers);
                        r.key_expiry = ref_expiry(p);
                        e.staged.push(r);
                    }
                }
            }
            "PeersChanged" => {
                if let Value::Array(a) = v {
                    for p in a.iter().filter(|p| p.is_object()) {
                        let mut r = ref_peer(p, Group::Changed);
                        r.key_expiry = ref_expiry(p);
                        e.staged.push(r);
                    }
                }
            }
            "PeersRemoved" => {
                if let Value::Array(a) = v {
                    for x in a {
                        let mut r = PeerRecord::new(PeerAction::Remove, Group::Removed);
                        if x.is_number() {
                            r.node_id = num_u64(x);
                        } else if let Some(s) = x.as_str() {
                            let k = key_of(Some(x), "nodekey:");
                            let _ = s;
                            if k.is_zero() {
                                continue;
                            }
                            r.node_key = k;
                        } else {
                            continue;
                        }
                        e.staged.push(r);
                    }
                }
            }
            "PeersChangedPatch" => {
                if let Value::Array(a) = v {
                    for p in a.iter().filter(|p| p.is_object()) {
                        let mut r = ref_peer(p, Group::Patch);
                        r.key_expiry = ref_expiry(p);
                        e.staged.push(r);
                    }
                }
            }
            "DERPMap" => match v {
                Value::Null => {}
                Value::Object(m) => {
                    let Some(regions) = m.get("Regions") else { continue };
                    let Value::Object(regions) = regions else { return Err(MapError::BadDerpMap) };
                    let mut kept = vec![];
                    let mut keys = 0;
                    for (k, rv) in regions {
                        if keys >= 4 && *k != home.to_string() {
                            continue;
                        }
                        keys += 1;
                        let Value::Object(ro) = rv else { return Err(MapError::BadDerpMap) };
                        let is_home = ro.get("RegionID").and_then(num_i32) == Some(home as i32);
                        if kept.len() >= 4 {
                            if !is_home {
                                continue;
                            }
                            kept.pop();
                        }
                        let mut nodes = vec![];
                        if let Some(Value::Array(ns)) = ro.get("Nodes") {
                            for n in ns.iter().filter(|n| n.is_object()) {
                                if nodes.len() >= 2 {
                                    break;
                                }
                                let host = s_of(n.get("HostName"));
                                let whole = host.is_some_and(|h| h.len() < 64);
                                let cert = match n.get("CertName") {
                                    _ if !whole => DerpCert::Invalid,
                                    Some(Value::String(s)) if s.len() > 96 => DerpCert::Invalid,
                                    Some(Value::String(s)) => cert_parse(cut(host.unwrap(), 63), Some(s)),
                                    Some(_) => DerpCert::Invalid,
                                    None => cert_parse(cut(host.unwrap(), 63), None),
                                };
                                let port = |k: &str| n.get(k).and_then(Value::as_f64).filter(|f| (0.0..=65535.0).contains(f)).map_or(0, |f| f as u16);
                                nodes.push((
                                    cut(host.unwrap_or(""), 63).to_string(),
                                    s_of(n.get("IPv4")).and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()).map(|a| a.octets()),
                                    port("STUNPort"),
                                    port("DERPPort"),
                                    n.get("STUNOnly") == Some(&Value::Bool(true)),
                                    n.get("CanPort80") == Some(&Value::Bool(true)),
                                    s_of(n.get("IPv6")).is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok()),
                                    cert,
                                ));
                            }
                        }
                        let id = ro.get("RegionID").and_then(Value::as_f64).filter(|f| (0.0..=65535.0).contains(f)).map_or(0, |f| f as u16);
                        kept.push((
                            id,
                            cut(s_of(ro.get("RegionCode")).unwrap_or(""), 7).to_string(),
                            cut(s_of(ro.get("RegionName")).unwrap_or(""), 23).to_string(),
                            ro.get("Avoid") == Some(&Value::Bool(true)),
                            nodes,
                        ));
                    }
                    e.derp = Some(kept);
                }
                _ => return Err(MapError::BadDerpMap),
            },
            _ => {}
        }
    }
    if e.self_node.as_ref().is_some_and(|n| n.expired) {
        e.derp = None; // an expired node applies no DERP map
    }
    Ok(e)
}

// ---- generators ---------------------------------------------------------------------------------------------------------------------------------

fn hex64() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 32).prop_map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
}

fn arb_key(prefix: &'static str) -> impl Strategy<Value = Value> {
    prop_oneof![
        8 => hex64().prop_map(move |h| json!(format!("{prefix}{h}"))),
        2 => hex64().prop_map(|h| json!(h)),
        1 => Just(json!("nodekey:short")),
        1 => Just(json!(12)),
        1 => Just(Value::Null),
    ]
}

fn arb_v4() -> impl Strategy<Value = String> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"))
}

fn arb_addr() -> impl Strategy<Value = Value> {
    prop_oneof![
        6 => (arb_v4(), 0u8..=32).prop_map(|(ip, l)| json!(format!("{ip}/{l}"))),
        2 => arb_v4().prop_map(|ip| json!(ip)),
        2 => Just(json!("fd7a:115c:a1e0::1/128")),
        1 => Just(json!("not an address")),
        1 => Just(json!("1.2.3.4/33")),
        1 => Just(json!("1.2.3.256")),
        1 => Just(json!(5)),
        1 => Just(json!("100.64.1.1/32")),
    ]
}

fn arb_aip() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => (arb_v4(), 0u8..=32).prop_map(|(ip, l)| json!(format!("{ip}/{l}"))),
        2 => Just(json!("0.0.0.0/0")),
        1 => Just(json!("::/0")),
        2 => Just(json!("100.101.102.103/32")),
        2 => Just(json!("192.168.50.0/24")),
        1 => Just(json!("garbage")),
        1 => Just(json!(7)),
    ]
}

fn arb_endpoint() -> impl Strategy<Value = Value> {
    prop_oneof![
        6 => (arb_v4(), any::<u16>()).prop_map(|(ip, p)| json!(format!("{ip}:{p}"))),
        2 => Just(json!("[2001:db8::7]:41641")),
        1 => Just(json!("1.2.3.4:99999")),
        1 => Just(json!("1.2.3.4")),
        1 => Just(json!(1)),
    ]
}

fn arb_num() -> impl Strategy<Value = Value> {
    prop_oneof![
        4 => (0u32..300).prop_map(|n| json!(n)),
        1 => Just(json!(0)),
        1 => Just(json!(-5)),
        1 => (1u64..(1 << 50)).prop_map(|n| json!(n)),
        1 => Just(json!(3.7)),
        1 => Just(json!(70000)),
        1 => Just(json!("12")),
        1 => Just(Value::Null),
    ]
}

fn arb_name() -> impl Strategy<Value = Value> {
    prop_oneof![
        4 => "[a-z0-9-]{1,20}(\\.[a-z0-9]{2,8}){0,2}\\.?".prop_map(|s| json!(s)),
        1 => "[a-z]{60,90}\\.?".prop_map(|s| json!(s)),
        1 => Just(json!("d\u{f6}ngle\u{1f600}.ts.net.")),
        1 => Just(json!("")),
        1 => Just(json!(5)),
        1 => "\u{e9}{30,40}".prop_map(|s| json!(s)),
    ]
}

fn arb_expiry() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => (2000u32..2100, 1u32..=12, 1u32..=28, 0u32..24, 0u32..60, 0u32..60).prop_map(|(y, mo, d, h, mi, s)| json!(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"))),
        1 => Just(json!("0001-01-01T00:00:00Z")),
        1 => Just(json!("garbage")),
        1 => Just(json!(1)),
    ]
}

fn opt<S: Strategy<Value = Value> + 'static>(k: &'static str, s: S) -> impl Strategy<Value = Option<(&'static str, Value)>> {
    prop_oneof![1 => Just(None), 3 => s.prop_map(move |v| Some((k, v)))]
}

fn arb_peer() -> impl Strategy<Value = Value> {
    let a = (
        opt("ID", arb_num()),
        opt("Name", arb_name()),
        opt("Key", arb_key("nodekey:")),
        opt("DiscoKey", arb_key("discokey:")),
        opt("Machine", arb_key("mkey:")),
        opt("Addresses", proptest::collection::vec(arb_addr(), 0..3).prop_map(Value::Array)),
        opt("AllowedIPs", proptest::collection::vec(arb_aip(), 0..14).prop_map(Value::Array)),
    );
    let b = (
        opt("HomeDERP", arb_num()),
        opt("DERP", prop_oneof![(0u32..20).prop_map(|n| json!(format!("127.3.3.40:{n}"))), Just(json!("junk"))]),
        opt("Endpoints", proptest::collection::vec(arb_endpoint(), 0..13).prop_map(Value::Array)),
        opt("Online", prop_oneof![any::<bool>().prop_map(|b| json!(b)), Just(Value::Null), Just(json!("yes"))]),
        opt("Expired", prop_oneof![any::<bool>().prop_map(|b| json!(b)), Just(json!(1))]),
        opt("KeyExpiry", arb_expiry()),
        opt("Tags", proptest::collection::vec(Just(json!("tag:a")), 0..4).prop_map(Value::Array)),
        opt("Cap", arb_num()),
        opt("Hostinfo", Just(json!({"OS":"linux","Services":[{"Port":22}],"NetInfo":{"DERPLatency":{"1-v4":0.01}}}))),
        opt("User", arb_num()),
    );
    (a, b).prop_map(|(a, b)| {
        let mut m = serde_json::Map::new();
        let items = [a.0, a.1, a.2, a.3, a.4, a.5, a.6, b.0, b.1, b.2, b.3, b.4, b.5, b.6, b.7, b.8, b.9];
        for (k, v) in items.into_iter().flatten() {
            m.insert(k.to_string(), v);
        }
        Value::Object(m)
    })
}

fn arb_patch() -> impl Strategy<Value = Value> {
    (
        opt("NodeID", arb_num()),
        opt("Key", arb_key("nodekey:")),
        opt("DiscoKey", arb_key("discokey:")),
        opt("DERPRegion", arb_num()),
        opt("Endpoints", proptest::collection::vec(arb_endpoint(), 0..11).prop_map(Value::Array)),
        opt("Online", any::<bool>().prop_map(|b| json!(b))),
        opt("Cap", arb_num()),
        opt("KeyExpiry", arb_expiry()),
    )
        .prop_map(|t| {
            let mut m = serde_json::Map::new();
            for (k, v) in [t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7].into_iter().flatten() {
                m.insert(k.to_string(), v);
            }
            Value::Object(m)
        })
}

fn arb_derp_node() -> impl Strategy<Value = Value> {
    (
        opt("HostName", prop_oneof![3 => "[a-z0-9]{3,12}\\.example\\.com".prop_map(|s| json!(s)), 1 => Just(json!("h".repeat(70))), 1 => Just(json!(3))]),
        opt("IPv4", prop_oneof![arb_v4().prop_map(|s| json!(s)), Just(json!("nope"))]),
        opt("IPv6", prop_oneof![Just(json!("2607:f740:f::bc")), Just(json!("zzz"))]),
        opt("STUNPort", prop_oneof![Just(json!(3478)), Just(json!(-1)), Just(json!(70000))]),
        opt("DERPPort", prop_oneof![Just(json!(443)), Just(json!(8443))]),
        opt("STUNOnly", any::<bool>().prop_map(|b| json!(b))),
        opt("CanPort80", any::<bool>().prop_map(|b| json!(b))),
        opt(
            "CertName",
            prop_oneof![
                Just(json!("front.example")),
                Just(json!("sha256-raw:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")),
                Just(json!("sha256-raw:zz")),
                Just(json!(7)),
                Just(json!("a".repeat(100)))
            ],
        ),
    )
        .prop_map(|t| {
            let mut m = serde_json::Map::new();
            for (k, v) in [t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7].into_iter().flatten() {
                m.insert(k.to_string(), v);
            }
            m.insert("Name".into(), json!("ignored"));
            Value::Object(m)
        })
}

fn arb_region(id: u32) -> impl Strategy<Value = Value> {
    (
        proptest::collection::vec(arb_derp_node(), 0..4),
        prop_oneof![Just(json!(id)), Just(json!(id + 1000)), Just(json!(f64::from(id) + 0.5)), Just(json!("x"))],
        "[a-z]{0,10}",
        "[A-Za-z ]{0,40}",
        any::<bool>(),
    )
        .prop_map(
            |(nodes, rid, code, name, avoid)| json!({"RegionID": rid, "RegionCode": code, "RegionName": name, "Avoid": avoid, "Latitude": 1.5, "Nodes": nodes}),
        )
}

fn arb_map() -> impl Strategy<Value = (Value, u16)> {
    let node = prop_oneof![
        3 => (arb_peer()).prop_map(Some),
        1 => Just(None),
    ];
    let peers = proptest::collection::vec(arb_peer(), 0..6);
    let changed = proptest::collection::vec(arb_peer(), 0..4);
    let removed = proptest::collection::vec(prop_oneof![arb_num(), arb_key("nodekey:"), Just(json!({"x":[1]}))], 0..6);
    let patches = proptest::collection::vec(arb_patch(), 0..5);
    let derp = proptest::collection::vec(1u32..30, 0..8).prop_flat_map(|ids| {
        let ids: Vec<u32> = ids.into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let regions: Vec<_> = ids.iter().map(|id| arb_region(*id)).collect();
        (Just(ids), regions)
    });
    (
        node,
        opt("Peers", peers.prop_map(Value::Array)),
        opt("PeersChanged", changed.prop_map(Value::Array)),
        opt("PeersRemoved", removed.prop_map(Value::Array)),
        opt("PeersChangedPatch", patches.prop_map(Value::Array)),
        prop_oneof![Just(None), derp.prop_map(Some)],
        1u16..30,
        any::<bool>(),
    )
        .prop_map(|(node, peers, changed, removed, patches, derp, home, noise)| {
            let mut m = serde_json::Map::new();
            if let Some(n) = node {
                m.insert("Node".into(), n);
            }
            for (k, v) in [peers, changed, removed, patches].into_iter().flatten() {
                m.insert(k.to_string(), v);
            }
            if let Some((ids, regions)) = derp {
                let mut r = serde_json::Map::new();
                for (id, v) in ids.iter().zip(regions) {
                    r.insert(id.to_string(), v);
                }
                m.insert("DERPMap".into(), json!({"Regions": r, "HomeParams": {"RegionScore": {"1": 1.0}}}));
            }
            if noise {
                m.insert("Health".into(), json!(["a", "b"]));
                m.insert("PacketFilter".into(), json!([{"SrcIPs": ["*"], "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}]}]));
            }
            (Value::Object(m), home)
        })
}

fn check(map: &Value, home: u16, chunk: usize) -> Result<(), TestCaseError> {
    let text = serde_json::to_string(map).unwrap();
    let cfg = MapConfig::new(home).with_flash_directory();
    let (r, rec, _) = run_cfg(cfg, text.as_bytes(), chunk);
    match reference(map, home) {
        Err(e) => {
            prop_assert_eq!(r, Err(e), "{}", text);
            prop_assert!(rec.summary.is_none() && rec.aborted == Some(e));
        }
        Ok(exp) => {
            prop_assert_eq!(r, Ok(()), "{}", text);
            prop_assert_eq!(rec.staged.len(), exp.staged.len(), "{}", text);
            for (got, want) in rec.staged.iter().zip(&exp.staged) {
                prop_assert_eq!(got, want, "{}", text);
            }
            prop_assert_eq!(rec.summary.as_ref().unwrap().authoritative, exp.authoritative);
            prop_assert_eq!(&rec.self_node, &exp.self_node, "{}", text);
            match (&rec.derp, &exp.derp) {
                (None, None) => {}
                (Some(d), Some(want)) => {
                    prop_assert_eq!(d.count as usize, want.len(), "{}", text);
                    for (got, w) in d.region_list().iter().zip(want) {
                        prop_assert_eq!((got.region_id, got.code.as_str(), got.name.as_str(), got.avoid), (w.0, w.1.as_str(), w.2.as_str(), w.3), "{}", text);
                        prop_assert_eq!(got.node_count as usize, w.4.len());
                        for (gn, wn) in got.node_list().iter().zip(&w.4) {
                            prop_assert_eq!(gn.hostname.as_str(), wn.0.as_str());
                            prop_assert_eq!(gn.ipv4, wn.1);
                            prop_assert_eq!((gn.stun_port, gn.derp_port, gn.stun_only, gn.can_port80, gn.ipv6.is_some()), (wn.2, wn.3, wn.4, wn.5, wn.6));
                            prop_assert_eq!(&gn.cert, &wn.7, "{}", text);
                        }
                    }
                }
                (g, w) => prop_assert!(false, "derp {:?} vs {:?}: {}", g.is_some(), w.is_some(), text),
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    /// The streaming projector produces exactly what the DOM reference produces, for every chunking.
    #[test]
    fn streaming_equals_dom_reference((map, home) in arb_map(), chunk in prop_oneof![Just(0usize), Just(1), 2usize..50]) {
        check(&map, home, chunk)?;
    }

    /// Chunking invariance of the whole projector (events, statistics, verdict), including on corrupted maps.
    #[test]
    fn chunking_invariance((map, home) in arb_map(), cuts in proptest::collection::vec(any::<usize>(), 0..12),
                           corrupt in proptest::option::of((any::<usize>(), any::<u8>()))) {
        let mut bytes = serde_json::to_vec(&map).unwrap();
        if let Some((at, b)) = corrupt && !bytes.is_empty() { let i = at % bytes.len(); bytes[i] = b; }
        let cfg = MapConfig::new(home);
        let (r0, rec0, s0) = run_cfg(cfg, &bytes, 0);
        let mut points: Vec<usize> = cuts.iter().map(|c| c % (bytes.len() + 1)).collect();
        points.sort_unstable();
        let mut rec = Rec::default();
        let mut p = MapProjector::new(cfg);
        let mut prev = 0;
        let mut result = Ok(());
        for pt in points.into_iter().chain([bytes.len()]) {
            if result.is_ok() { result = p.feed(&bytes[prev..pt], &mut rec); }
            prev = pt;
        }
        if result.is_ok() { result = p.finish(&mut rec); }
        prop_assert_eq!(r0, result);
        prop_assert_eq!(format!("{rec0:?}"), format!("{rec:?}"));
        prop_assert_eq!(&s0, p.stats());
    }
}

// ---- deterministic mini-fuzz ---------------------------------------------------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn invariants(rec: &Rec, r: Result<(), MapError>, stats: &MapStats, cfg: MapConfig) {
    match r {
        Ok(()) => {
            assert_eq!(rec.order.last(), Some(&"commit"));
            assert!(rec.aborted.is_none());
            assert_eq!(rec.order.iter().filter(|e| **e == "commit").count(), 1);
        }
        Err(MapError::CommitRefused) => unreachable!(),
        Err(e) => {
            assert_eq!(rec.order.last(), Some(&"abort"), "{e:?}");
            assert_eq!(rec.aborted, Some(e));
            assert!(rec.summary.is_none());
            // nothing but staged records was delivered before the abort
            assert!(rec.order.iter().all(|k| matches!(*k, "peer" | "seen" | "abort")), "{:?}", rec.order);
        }
    }
    if let Some(d) = &rec.derp {
        assert!(d.count as usize <= MAX_DERP_REGIONS_T);
        for r in d.region_list() {
            assert!(r.node_count as usize <= 2);
        }
    }
    if let Some(l) = cfg.limits.section_entries {
        let s = rec.staged.iter().filter(|r| r.group == Group::Peers).count();
        assert!(s <= l as usize);
    }
    for p in &rec.staged {
        assert!(p.endpoint_count as usize <= 8 && p.route_count as usize <= 8);
        assert!(p.name.len() <= 63);
    }
    let _ = stats;
}
const MAX_DERP_REGIONS_T: usize = 4;

#[test]
fn mini_fuzz_mutated_real_maps() {
    let seeds: Vec<Vec<u8>> = ["map-full.json", "map-delta.json", "map-keepalive.json", "map-derp-only.json", "derp-map-2026-10-01.json"]
        .iter()
        .map(|n| std::fs::read(format!("tests/fixtures/{n}")).unwrap())
        .collect();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut accepted = 0;
    let mut rejected = 0;
    for iter in 0..6000 {
        let mut b = seeds[rng.below(seeds.len())].clone();
        if iter % 5 == 0 && b.first() != Some(&b'{') {
            let mut w = b"{\"DERPMap\":".to_vec();
            w.extend_from_slice(&b);
            w.push(b'}');
            b = w;
        }
        for _ in 0..rng.below(6) {
            if b.is_empty() {
                break;
            }
            let i = rng.below(b.len());
            match rng.below(6) {
                0 => b[i] = rng.next() as u8,
                1 => b.insert(i, rng.next() as u8),
                2 => {
                    b.remove(i);
                }
                3 => b.truncate(i),
                4 => {
                    let n = rng.below(40).min(b.len() - i);
                    let dup = b[i..i + n].to_vec();
                    b.splice(i..i, dup);
                }
                _ => {
                    let pool = b"{}[]\",:\\ 0-ntf";
                    b[i] = pool[rng.below(pool.len())]
                }
            }
        }
        let cfg = if iter % 2 == 0 { MapConfig::new(1) } else { MapConfig::new(2).with_flash_directory() };
        let chunk = [0, 1, 7, 100][rng.below(4)];
        let (r, rec, stats) = run_cfg(cfg, &b, chunk);
        invariants(&rec, r, &stats, cfg);
        if r.is_ok() {
            accepted += 1
        } else {
            rejected += 1
        }
        // ... and the verdict never depends on the chunking
        let (r2, rec2, _) = run_cfg(cfg, &b, 0);
        assert_eq!(r, r2);
        assert_eq!(format!("{rec:?}"), format!("{rec2:?}"));
    }
    assert!(accepted > 100 && rejected > 100, "{accepted} accepted, {rejected} rejected");
}

#[test]
fn mini_fuzz_random_bytes_and_structured_garbage() {
    let mut rng = Rng(42);
    let alphabet: &[&str] = &[
        "{",
        "}",
        "[",
        "]",
        ",",
        ":",
        "\"Node\"",
        "\"Peers\"",
        "\"PeersChanged\"",
        "\"PeersRemoved\"",
        "\"DERPMap\"",
        "\"Regions\"",
        "\"Nodes\"",
        "\"RegionID\"",
        "\"Addresses\"",
        "\"Endpoints\"",
        "\"Name\"",
        "1",
        "-1",
        "1.5e3",
        "true",
        "null",
        "\"x\"",
        "\"1\"",
        "\"100.64.0.1/32\"",
        "\\u0000",
        "\\ud800",
        " ",
        "\n",
    ];
    for iter in 0..8000 {
        let mut s = String::new();
        for _ in 0..rng.below(40) {
            s.push_str(alphabet[rng.below(alphabet.len())]);
        }
        let cfg = if iter % 2 == 0 { MapConfig::new(1) } else { MapConfig::new(1).with_flash_directory() };
        let (r, rec, stats) = run_cfg(cfg, s.as_bytes(), 0);
        invariants(&rec, r, &stats, cfg);
        let raw: Vec<u8> = (0..rng.below(200)).map(|_| rng.next() as u8).collect();
        let (r, rec, stats) = run_cfg(cfg, &raw, 3);
        invariants(&rec, r, &stats, cfg);
    }
}

#[test]
fn sizes_are_what_the_adr_will_quote() {
    let sizes = [
        ("PeerRecord", PEER_RECORD_BYTES),
        ("SelfNode", SELF_NODE_BYTES),
        ("DerpRegion", DERP_REGION_BYTES),
        ("DerpMap", DERP_MAP_BYTES),
        ("DnsConfig", DNS_CONFIG_BYTES),
        ("MapEvent", MAP_EVENT_BYTES),
        ("Tokenizer", TOKENIZER_STATE_BYTES),
        ("MapProjector", PROJECTOR_STATE_BYTES),
        ("PublishedName", PublishedName::SIZE),
    ];
    for (n, s) in sizes {
        println!("size_of {n}: {s}");
    }
    assert_eq!(MapProjector::STATE_BYTES, PROJECTOR_STATE_BYTES);
    const { assert!(MAP_EVENT_BYTES <= 32) };
    const { assert!(PROJECTOR_STATE_BYTES < 8192) };
    // the C's parser (5000) plus its stage (23992) is the figure to beat
}
