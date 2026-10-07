//! Every expected value here was produced by the real C (tools/gen_golden.c, tools/regen.sh).
mod common;
use common::*;
use tdongle_setup::access::{self, Action, Endpoint, Facts, Origin};
use tdongle_setup::boot::{self, Request, SetupBoot};
use tdongle_setup::json::{self, Json, Val};
use tdongle_setup::scan::ScanList;
use tdongle_setup::{dns, router::Tick};

#[test]
fn dns_matches_c() {
    let g = golden("dns.golden");
    let mut n = 0;
    for line in g.lines() {
        let mut it = line.split(' ');
        let cap: usize = it.next().unwrap().parse().unwrap();
        let q = unhex(it.next().unwrap());
        let want = it.next().unwrap();
        let mut out = vec![0u8; cap];
        let got = dns::reply(&q, &mut out, dns::DONGLE).map(|m| hex(&out[..m]));
        assert_eq!(got.as_deref().unwrap_or("-"), want, "query {}", hex(&q));
        n += 1;
    }
    assert!(n > 2000);
}

fn opt(s: &str) -> Option<Vec<u8>> {
    if s == "~" { None } else if s == "-" { Some(Vec::new()) } else { Some(unhex(s)) }
}

fn origin_of(n: i32) -> Origin {
    [Origin::Denied, Origin::Usb, Origin::SetupAp][n as usize]
}

const ENDPOINTS: [Endpoint; 7] =
    [Endpoint::Home, Endpoint::Status, Endpoint::Diagnostics, Endpoint::WifiScan, Endpoint::WifiSaved, Endpoint::Command, Endpoint::BootStatus];
const ACTIONS: [Action; 8] =
    [Action::Mode, Action::Wifi, Action::WifiRemove, Action::Add, Action::Remove, Action::Enable, Action::SetupDone, Action::Unknown];

#[test]
fn access_matches_c() {
    let g = golden("access.golden");
    for line in g.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "C" => {
                let (peer, local): (u32, u32) = (f[1].parse().unwrap(), f[2].parse().unwrap());
                let host = opt(f[6]);
                let origin = opt(f[7]);
                let facts = Facts {
                    peer: (f[3] == "1").then_some(peer),
                    local: (f[4] == "1").then_some(local),
                    setup_active: f[5] == "1",
                    host: host.as_deref(),
                    origin: origin.as_deref(),
                };
                assert_eq!(access::classify(&facts), origin_of(f[8].parse().unwrap()), "{line}");
            }
            "S" => assert_eq!(access::in_setup_subnet(f[1].parse().unwrap()), f[2] == "1"),
            "E" => assert_eq!(
                access::endpoint_allowed(origin_of(f[1].parse().unwrap()), ENDPOINTS[f[2].parse::<usize>().unwrap()]),
                f[3] == "1",
                "{line}"
            ),
            "A" => assert_eq!(
                access::action_allowed(origin_of(f[1].parse().unwrap()), ACTIONS[f[2].parse::<usize>().unwrap()]),
                f[3] == "1",
                "{line}"
            ),
            "M" => {
                let o = origin_of(f[1].parse().unwrap());
                assert_eq!((access::may_set_metadata(o), access::may_replace(o)), (f[2] == "1", f[3] == "1"));
            }
            "P" => {
                let name = opt(f[1]);
                assert_eq!(access::parse_action(name.as_deref()), ACTIONS[f[2].parse::<usize>().unwrap()], "{line}");
            }
            "T" => {
                let r: [u8; 16] = unhex(f[1]).try_into().unwrap();
                assert_eq!(access::token_format(&r), f[2].as_bytes());
            }
            "Q" => assert_eq!(access::token_equal(Some(f[2].as_bytes()), f[1].as_bytes()), f[3] == "1", "{line}"),
            _ => panic!("{line}"),
        }
    }
}

#[test]
fn boot_matches_c() {
    let g = golden("boot.golden");
    for line in g.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let n = |i: usize| -> u32 { f[i].parse().unwrap() };
        match f[0] {
            "D" => {
                let d = SetupBoot::decide(n(1) == 1, n(2), n(3), n(4), n(5) == 1, n(6) == 1);
                assert_eq!(d.is_some(), n(7) == 1, "{line}");
                assert_eq!(d.map_or(0, |b| u32::from(b.preselect())), n(8), "{line}");
            }
            "R" => {
                let req = [Request::None, Request::Enter, Request::Leave][n(1) as usize];
                assert_eq!(boot::request_words(req, n(2)), (n(3), n(4), n(5)), "{line}");
            }
            "T" => {
                let boot = SetupBoot::decide(true, boot::MAGIC, 1, 0, false, true).unwrap();
                let s = boot.session(n(1));
                let (now, up) = (n(2), n(3) == 1);
                assert_eq!(u32::from(s.expired(now)), n(4), "{line}");
                assert_eq!(u32::from(s.should_end(now, up)), n(5), "{line}");
                assert_eq!(s.seconds_left(now), n(6), "{line}");
                assert_eq!(s.failsafe_delay_ms(now, up), n(7), "{line}");
            }
            "I" => {
                let s = boot::Session::INACTIVE;
                let (now, up) = (n(1), n(2) == 1);
                assert_eq!((u32::from(s.expired(now)), u32::from(s.should_end(now, up)), s.failsafe_delay_ms(now, up)), (n(3), n(4), n(5)));
            }
            "N" => {
                let mac: [u8; 6] = unhex(f[1]).try_into().unwrap();
                let size = n(2) as usize;
                let mut out = vec![b'x'; size.max(1)];
                let written = if size == 0 { 0 } else { boot::ap_ssid_into(&mut out, &mac) + 1 };
                assert_eq!(hex(&out[..if size == 0 { 0 } else { written }]), f[3], "{line}");
            }
            _ => panic!("{line}"),
        }
    }
}

#[test]
fn scan_list_and_json_match_c() {
    let g = golden("scan.golden");
    let mut lines = g.lines().peekable();
    let mut cases = 0;
    while let Some(l) = lines.next() {
        assert!(l.starts_with("L "));
        let mut list = ScanList::new();
        let mut fed = 0;
        while lines.peek().is_some_and(|l| l.starts_with("O ")) {
            let f: Vec<&str> = lines.next().unwrap().split(' ').collect();
            let ssid: [u8; 32] = unhex(f[1]).try_into().unwrap();
            list.offer(&ssid, f[2].parse().unwrap(), f[3] == "1");
            fed += 1;
        }
        assert!(fed > 0);
        let r: usize = lines.next().unwrap().strip_prefix("R ").unwrap().parse().unwrap();
        assert_eq!(list.entries().len(), r);
        for e in list.entries() {
            let f: Vec<String> = lines.next().unwrap().split(' ').map(String::from).collect();
            assert_eq!(f[1], hex(e.ssid()));
            assert_eq!((f[2].parse::<i8>().unwrap(), f[3] == "1"), (e.rssi, e.secure));
        }
        // the page the router builds from this list is the C's JSON
        let j: Vec<&str> = lines.next().unwrap().split(' ').collect();
        let p = portal();
        let mut host = FakeHost::new();
        host.scan = Some(list);
        host.busy = j[1] == "1";
        let req = get("/wifi-scan", "192.168.4.1", &format!("X-Setup-Token: {}\r\n", token(&p)));
        let (resp, _) = exchange(&p, &ap_conn(), &mut host, &req);
        assert_eq!(hex(&body_of(&resp)), j[2]);
        cases += 1;
    }
    assert!(cases >= 100);
}

fn num_text(v: Val) -> String {
    match v {
        Val::Num(d) => format!("{d}"),
        _ => unreachable!(),
    }
}

#[test]
fn json_bodies_match_cjson() {
    let g = golden("json.golden");
    let mut lines = g.lines().peekable();
    let keys = ["action", "ssid", "password", "name", "slot", "priority", "mode", "label", "key", "id", "enabled"];
    let mut cases = 0;
    while let Some(l) = lines.next() {
        let Some(b) = l.strip_prefix("B ") else { break };
        let body = unhex(b);
        let parsed = json::parse(&body);
        if lines.peek().unwrap().starts_with("X ") {
            lines.next();
            assert!(parsed.is_none(), "C refused, Rust accepted: {}", String::from_utf8_lossy(&body));
            cases += 1;
            continue;
        }
        let f = parsed.unwrap_or_else(|| panic!("C accepted, Rust refused: {}", String::from_utf8_lossy(&body)));
        for key in keys {
            let k: Vec<&str> = lines.next().unwrap().split(' ').collect();
            assert_eq!(k[1], key);
            let v = match key {
                "action" => f.action,
                "ssid" => f.ssid,
                "password" => f.password,
                "name" => f.name,
                "slot" => f.slot,
                "priority" => f.priority,
                "mode" => f.mode,
                "label" => f.label,
                "key" => f.key,
                "id" => f.id,
                _ => f.enabled,
            };
            let ctx = || format!("{key} of {}", String::from_utf8_lossy(&body));
            match k[2] {
                "ABSENT" => assert_eq!(v, Val::Absent, "{}", ctx()),
                "STR" => assert_eq!(hex(f.string(v).unwrap_or_else(|| panic!("{}", ctx()))), k[3], "{}", ctx()),
                "NUM" => {
                    let want: f64 = k[3].parse().unwrap();
                    assert!(matches!(v, Val::Num(d) if d == want), "{} {} vs {}", ctx(), num_text_safe(v), k[3]);
                }
                "TRUE" => assert_eq!(v, Val::True, "{}", ctx()),
                "FALSE" => assert_eq!(v, Val::False, "{}", ctx()),
                "OTHER" => assert_eq!(v, Val::Other, "{}", ctx()),
                x => panic!("{x}"),
            }
        }
        cases += 1;
    }
    assert!(cases > 4000);
}

fn num_text_safe(v: Val) -> String {
    if let Val::Num(_) = v { num_text(v) } else { format!("{v:?}") }
}

#[test]
fn json_string_escaping_matches_cjson() {
    let g = golden("json.golden");
    let mut n = 0;
    for line in g.lines().filter(|l| l.starts_with("W ")) {
        let f: Vec<&str> = line.split(' ').collect();
        let s = unhex(f[1]);
        let mut out = [0u8; 512];
        let mut j = Json::new(&mut out);
        j.raw(b"{\"error\":").string(&s).raw(b",\"ok\":false}");
        assert_eq!(hex(j.bytes()), f[2]);
        n += 1;
    }
    assert!(n >= 300);
}

#[test]
fn tick_agrees_with_session() {
    let p = portal();
    assert_eq!(p.tick(1000 + 29_999, false), Tick::Continue);
    assert_eq!(p.tick(1000 + 30_000, false), Tick::Leave);
    assert_eq!(p.tick(1000 + 599_999, true), Tick::Continue);
    assert_eq!(p.tick(1000 + 600_000, true), Tick::Leave);
}
