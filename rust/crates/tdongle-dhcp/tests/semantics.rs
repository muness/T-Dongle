//! lwIP dhcpserver.c semantics, one behaviour per test (the byte-exact comparison against the real file is tests/golden.rs).
use tdongle_dhcp::*;

const COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

fn req(mac: u8, opts: &[u8], flags: u16, ciaddr: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 300];
    p[0] = 1;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&[1, 2, 3, 4]);
    p[10..12].copy_from_slice(&flags.to_be_bytes());
    p[12..16].copy_from_slice(&ciaddr);
    p[28..34].copy_from_slice(&[2, 0, 0, 0, 0, mac]);
    p[236..240].copy_from_slice(&COOKIE);
    p[240..240 + opts.len()].copy_from_slice(opts);
    p
}

fn msg(t: u8) -> Vec<u8> {
    vec![53, 1, t, 255]
}

fn with_ip(t: u8, ip: [u8; 4]) -> Vec<u8> {
    let mut v = vec![53, 1, t, 50, 4];
    v.extend_from_slice(&ip);
    v.push(255);
    v
}

fn server() -> Server {
    Server::new(Config::setup_ap()).unwrap()
}

fn run(s: &mut Server, p: &[u8], now: u32) -> Option<(Reply, Vec<u8>)> {
    let mut out = vec![0u8; 1500];
    let r = s.handle(p, now, &mut out)?;
    out.truncate(r.len);
    Some((r, out))
}

fn find_opt(reply: &[u8], code: u8) -> Option<Vec<u8>> {
    let mut i = 240;
    while i < reply.len() {
        match reply[i] {
            0 => i += 1,
            255 => return None,
            c => {
                let l = reply[i + 1] as usize;
                if c == code {
                    return Some(reply[i + 2..i + 2 + l].to_vec());
                }
                i += 2 + l;
            }
        }
    }
    None
}

#[test]
fn offer_carries_the_setup_ap_options() {
    let mut s = server();
    let (r, o) = run(&mut s, &req(1, &msg(1), 0x8000, [0; 4]), 0).unwrap();
    assert_eq!(r.kind, ReplyKind::Offer);
    assert_eq!(find_opt(&o, 53), Some(vec![2]));
    assert_eq!(find_opt(&o, 1), Some(vec![255, 255, 255, 0]));
    assert_eq!(find_opt(&o, 51), Some(7200u32.to_be_bytes().to_vec()));
    assert_eq!(find_opt(&o, 54), Some(vec![192, 168, 4, 1]));
    assert_eq!(find_opt(&o, 3), Some(vec![192, 168, 4, 1]), "router");
    assert_eq!(find_opt(&o, 6), Some(vec![192, 168, 4, 1]), "DNS = the captive DNS");
    assert_eq!(find_opt(&o, 28), Some(vec![192, 168, 4, 255]));
    assert_eq!(find_opt(&o, 114), None, "no captive-portal option, like the C firmware");
    assert_eq!(&o[16..20], &[192, 168, 4, 2]);
    assert_eq!(o.len(), 548);
    assert_eq!(&o[4..8], &[1, 2, 3, 4], "xid echoed");
    assert_eq!(&o[28..34], &[2, 0, 0, 0, 0, 1], "chaddr echoed");
}

#[test]
fn same_client_gets_same_address_and_others_the_next() {
    let mut s = server();
    let a = run(&mut s, &req(1, &msg(1), 0x8000, [0; 4]), 0).unwrap().0.yiaddr;
    let b = run(&mut s, &req(2, &msg(1), 0x8000, [0; 4]), 1).unwrap().0.yiaddr;
    let a2 = run(&mut s, &req(1, &msg(1), 0x8000, [0; 4]), 2).unwrap().0.yiaddr;
    assert_eq!((a, b, a2), ([192, 168, 4, 2], [192, 168, 4, 3], [192, 168, 4, 2]));
    assert_eq!(s.lease_count(), 2);
}

#[test]
fn request_for_the_offered_address_acks_and_for_another_naks() {
    let mut s = server();
    run(&mut s, &req(1, &msg(1), 0x8000, [0; 4]), 0).unwrap();
    let (r, _) = run(&mut s, &req(1, &with_ip(3, [192, 168, 4, 2]), 0x8000, [0; 4]), 1).unwrap();
    assert_eq!((r.kind, r.yiaddr), (ReplyKind::Ack, [192, 168, 4, 2]));
    let (r, o) = run(&mut s, &req(1, &with_ip(3, [192, 168, 4, 77]), 0x8000, [0; 4]), 2).unwrap();
    assert_eq!((r.kind, r.yiaddr, r.dest), (ReplyKind::Nak, [0; 4], Dest::Broadcast));
    assert_eq!(find_opt(&o, 53), Some(vec![6]));
    assert_eq!(find_opt(&o, 1), None, "a NAK carries only the message type");
    assert_eq!(s.lease_count(), 0, "a NAK drops the lease");
}

#[test]
fn address_leased_to_someone_else_is_nak() {
    let mut s = server();
    run(&mut s, &req(1, &msg(1), 0x8000, [0; 4]), 0).unwrap();
    let (r, _) = run(&mut s, &req(2, &with_ip(3, [192, 168, 4, 2]), 0x8000, [0; 4]), 1).unwrap();
    assert_eq!(r.kind, ReplyKind::Nak);
    assert_eq!(s.lease_of([2, 0, 0, 0, 0, 1]), Some([192, 168, 4, 2]));
}

#[test]
fn request_outside_the_subnet_is_nak() {
    let mut s = server();
    let (r, _) = run(&mut s, &req(1, &with_ip(3, [10, 0, 0, 5]), 0x8000, [0; 4]), 0).unwrap();
    assert_eq!(r.kind, ReplyKind::Nak);
}

#[test]
fn renew_with_ciaddr_acks_unicast_to_ciaddr() {
    let mut s = server();
    run(&mut s, &req(1, &msg(1), 0, [0; 4]), 0).unwrap();
    let (r, _) = run(&mut s, &req(1, &msg(3), 0, [192, 168, 4, 2]), 10).unwrap();
    assert_eq!(r.kind, ReplyKind::Ack);
    assert_eq!(r.dest, Dest::Unicast { ip: [192, 168, 4, 2], mac: [2, 0, 0, 0, 0, 1] });
    assert!(r.static_arp);
}

#[test]
fn broadcast_flag_selects_broadcast_otherwise_unicast_to_yiaddr() {
    let mut s = server();
    let (r, _) = run(&mut s, &req(1, &msg(1), 0x8000, [0; 4]), 0).unwrap();
    assert_eq!((r.dest, r.static_arp), (Dest::Broadcast, false));
    let (r, _) = run(&mut s, &req(2, &msg(1), 0, [0; 4]), 0).unwrap();
    assert_eq!(r.dest, Dest::Unicast { ip: [192, 168, 4, 3], mac: [2, 0, 0, 0, 0, 2] });
}

#[test]
fn giaddr_wins_over_everything() {
    let mut s = server();
    let mut p = req(1, &msg(1), 0x8000, [192, 168, 4, 9]);
    p[24..28].copy_from_slice(&[192, 168, 4, 99]);
    let (r, _) = run(&mut s, &p, 0).unwrap();
    assert_eq!(r.dest, Dest::Unicast { ip: [192, 168, 4, 99], mac: [2, 0, 0, 0, 0, 1] });
}

#[test]
fn release_and_decline_free_the_lease_and_get_no_reply() {
    let mut s = server();
    run(&mut s, &req(1, &msg(1), 0, [0; 4]), 0).unwrap();
    assert!(run(&mut s, &req(1, &msg(7), 0, [192, 168, 4, 2]), 1).is_none());
    assert_eq!(s.lease_count(), 0);
    run(&mut s, &req(1, &msg(1), 0, [0; 4]), 2).unwrap();
    assert!(run(&mut s, &req(1, &with_ip(4, [192, 168, 4, 2]), 0, [0; 4]), 3).is_none());
    assert_eq!(s.lease_count(), 0);
}

#[test]
fn inform_acks_without_lease_and_without_touching_the_table() {
    let mut s = server();
    let (r, o) = run(&mut s, &req(1, &msg(8), 0, [192, 168, 4, 50]), 0).unwrap();
    assert_eq!((r.kind, r.yiaddr), (ReplyKind::InformAck, [0; 4]));
    assert_eq!(find_opt(&o, 53), Some(vec![5]));
    assert_eq!(find_opt(&o, 51), None);
    assert_eq!(find_opt(&o, 6), Some(vec![192, 168, 4, 1]));
    assert!(!r.static_arp);
    assert_eq!(s.lease_count(), 0);
    assert!(run(&mut s, &req(1, &msg(8), 0, [0; 4]), 0).is_none(), "ciaddr must be set");
    assert!(run(&mut s, &req(1, &msg(8), 0, [10, 0, 0, 1]), 0).is_none(), "foreign subnet");
}

#[test]
fn leases_expire_after_lease_secs_and_survive_clock_wrap() {
    for start in [0u32, u32::MAX - 5_000_000, 0x7FFF_0000] {
        let mut s = server();
        run(&mut s, &req(1, &msg(1), 0, [0; 4]), start).unwrap();
        s.expire(start.wrapping_add(7_199_999));
        assert_eq!(s.lease_count(), 1);
        s.expire(start.wrapping_add(7_200_000));
        assert_eq!(s.lease_count(), 0);
    }
}

#[test]
fn a_ninth_station_evicts_the_oldest_lease() {
    let mut s = server();
    for i in 1..=9u8 {
        run(&mut s, &req(i, &msg(1), 0, [0; 4]), u32::from(i) * 1000).unwrap();
    }
    assert_eq!(s.lease_count(), 8);
    assert_eq!(s.lease_of([2, 0, 0, 0, 0, 1]), None, "first (oldest) client evicted");
    assert!(s.lease_of([2, 0, 0, 0, 0, 9]).is_some());
}

#[test]
fn malformed_requests_are_ignored() {
    let mut s = server();
    let good = req(1, &msg(1), 0, [0; 4]);
    let mut out = [0u8; 1500];
    assert!(s.handle(&good[..239], 0, &mut out).is_none(), "short");
    assert!(s.handle(&[], 0, &mut out).is_none());
    let mut bad = good.clone();
    bad[236] ^= 1;
    assert!(s.handle(&bad, 0, &mut out).is_none(), "cookie");
    let mut reply = good.clone();
    reply[0] = 2;
    assert!(s.handle(&reply, 0, &mut out).is_none(), "BOOTREPLY");
    let mut big = good.clone();
    big.resize(1501, 0);
    assert!(s.handle(&big, 0, &mut out).is_none(), "oversized");
    assert!(s.handle(&good, 0, &mut out[..547]).is_none(), "output too small");
    assert_eq!(s.lease_count(), 0, "none of them touched the table");
    // truncated option area: no message type, so no reply, but (like lwIP) a lease was allocated for the sender
    let mut cut = req(1, &[53, 1], 0, [0; 4]);
    cut.truncate(242);
    assert!(s.handle(&cut, 0, &mut out).is_none());
}

#[test]
fn config_validation() {
    let c = Config::setup_ap();
    assert_eq!(Server::new(Config { netmask: [255, 0, 255, 0], ..c }).unwrap_err(), ConfigError::BadNetmask);
    assert_eq!(Server::new(Config { server_ip: [192, 168, 4, 0], ..c }).unwrap_err(), ConfigError::BadServerIp);
    assert_eq!(Server::new(Config { server_ip: [192, 168, 4, 255], ..c }).unwrap_err(), ConfigError::BadServerIp);
    assert_eq!(Server::new(Config { lease_secs: 0, ..c }).unwrap_err(), ConfigError::BadLease);
    assert_eq!(Server::new(Config { max_stations: 0, ..c }).unwrap_err(), ConfigError::BadStations);
    let s = Server::new(Config { pool: Some(([192, 168, 4, 100], [192, 168, 4, 110])), ..c }).unwrap();
    assert_eq!(s.pool(), ([192, 168, 4, 100], [192, 168, 4, 110]));
    let s = Server::new(Config { pool: Some(([192, 168, 4, 1], [192, 168, 4, 110])), ..c }).unwrap();
    assert_eq!(s.pool(), ([192, 168, 4, 2], [192, 168, 4, 101]), "pool holding the server is replaced by the default");
}
