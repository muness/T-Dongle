//! End to end: the real runtime against the real Tailscale control server, DERP server and tsnet peers. See `harness.rs`.
//!
//! `cargo test -p tdongle-tailnet-host --test e2e -- --test-threads=1 --nocapture`. Skips (printing why) when the Go server cannot be built.

use std::sync::atomic::Ordering;
use std::time::Duration;
use tdongle_tailnet_fw::{HeapProbe, MemberAction, TailnetApi};
use tdongle_tailnet_host::harness::*;

macro_rules! go_or_skip {
    () => {
        match spawn_go() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("SKIP: the Go interop server is not available: {e}");
                return;
            }
        }
    };
}

fn mbit(bytes: usize, d: Duration) -> f64 {
    bytes as f64 * 8.0 / d.as_secs_f64() / 1e6
}

/// Start a gateway on `go`, add one membership "lab" and wait until it routes and the host has its lease. Returns (gateway, member id, alias of `peer`).
fn up(go: &mut tdongle_tailnet_host::server::GoServer, peer: &str) -> (Gateway, u32, [u8; 4]) {
    let (_, _) = go.peer(peer).expect("peer");
    let gw = Gateway::start(GatewayOpts::new(&go.control_addr));
    let t = std::time::Instant::now();
    let id = gw.add("lab", "tskey-fake");
    wait_until("the membership to be routing", 60, || gw.is_ready(id));
    println!("JOIN: membership routing {:?} after add (the first map is due within 30 s); pool {:?}", t.elapsed(), gw.sh.pool.stats());
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let alias = gw.host.resolve(&format!("{peer}.lab.tailnet"), Duration::from_secs(10)).expect("dns");
    (gw, id, alias)
}

#[test]
fn derp_only_end_to_end() {
    let mut go = go_or_skip!();
    let reply = go.cmd("peer");
    assert!(reply.starts_with("PEER "), "{reply}");
    let gw = Gateway::start(GatewayOpts::new(&go.control_addr));
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    let id = gw.add("lab", "tskey-fake");
    wait_until("the membership to be routing", 60, || gw.is_ready(id));
    let hip = gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    assert_eq!(&hip[..3], &[192, 168, 77]);
    let alias = gw.host.resolve("gopeer.lab.tailnet", Duration::from_secs(10)).expect("dns");
    assert_eq!(&alias[..2], &[198, 18]);
    // the MagicDNS name of the tailnet resolves to the same alias (the domain is the membership's own published name minus its first label)
    assert_eq!(gw.host.resolve("gopeer.tailnet.test", Duration::from_secs(10)).expect("magicdns"), alias);
    let echoed = gw.host.echo(alias, 7, b"hello over derp", Duration::from_secs(30)).expect("echo");
    assert_eq!(echoed, b"hello over derp");
    let (derp, direct) = gw.sent();
    assert!(derp > 0 && direct == 0, "derp {derp} direct {direct}");
    gw.check_engine();
}

/// The coordinator's board symptom: counters all zero and no per-peer state. A USB-side echo to a real tsnet peer through the full router path
/// (alias -> router -> engine -> WireGuard -> DERP) must show up in `route`, `inbound`, and the per-peer line, and raw 100.x (not an alias) must not.
#[test]
fn usb_ping_through_the_router_is_visible_in_every_counter() {
    use tdongle_tailnet_fw::TailnetApi;
    let mut go = go_or_skip!();
    let (gw, _id, alias) = up(&mut go, "gopeer");
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    let cmd = |c: &str| {
        let mut o = String::new();
        let _ = gw.sh.serial_command(c, &mut o);
        o
    };
    let num = |j: &str, k: &str| -> u64 {
        let pat = format!("\"{k}\":");
        let i = j.find(&pat).unwrap_or_else(|| panic!("no {k} in {j}")) + pat.len();
        j[i..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap()
    };
    assert_eq!(num(&cmd("route"), "forwarded_out"), 0);
    assert_eq!(gw.host.echo(alias, 7, b"through the router", Duration::from_secs(30)).unwrap(), b"through the router");
    let route = cmd("route");
    assert!(num(&route, "forwarded_out") >= 1, "{route}");
    assert!(num(&route, "forwarded_in") >= 1, "{route}");
    let inbound = cmd("inbound");
    assert!(num(&inbound, "udp_wg") + num(&inbound, "derp_rx_wg") >= 1, "{inbound}");
    assert!(num(&inbound, "wg_delivered") >= 1, "{inbound}");
    let mut extra = String::new();
    gw.sh.serial_status_extra(&mut extra);
    let wg = extra.lines().find(|l| l.starts_with("tn_wg ")).unwrap_or_else(|| panic!("no tn_wg line in {extra}"));
    assert!(wg.contains("session=true") && wg.contains("path=derp"), "{wg}");
    assert!(!wg.contains("hs_ms=None"), "handshake time missing: {wg}");
    assert!(!wg.contains("tx_bytes=0 ") && !wg.contains("rx_bytes=0 "), "{wg}");
    let eng = extra.lines().find(|l| l.starts_with("tn_eng ")).unwrap();
    assert!(!eng.contains("hs_init=0 "), "the first packet must start a handshake: {eng}");
    // a raw tailnet address is not an alias: it is NAT traffic by design (C `gateway_alias`), so the tunnel counters do not move
    let before = num(&cmd("route"), "forwarded_out");
    let _ = gw.host.udp_echo([100, 90, 1, 2], 7, b"raw", Duration::from_secs(2));
    assert_eq!(num(&cmd("route"), "forwarded_out"), before);
    gw.check_engine();
}

fn ip_sum(b: &[u8]) -> u16 {
    let mut s: u32 = b.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// An Ethernet frame carrying an IPv4 packet the way a macOS host builds it (TTL 64, ID set, header checksum filled).
fn host_frame(src: [u8; 4], dst: [u8; 4], proto: u8, df: bool, l4: &[u8], pad_to: usize) -> Vec<u8> {
    let mut ip = vec![0x45, 0, 0, 0, 0x5c, 0x1d, if df { 0x40 } else { 0 }, 0, 64, proto, 0, 0];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let total = (20 + l4.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    let c = ip_sum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(l4);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, proto]);
    pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(l4);
    let off = match proto {
        6 => Some(36),
        17 => Some(26),
        _ => None,
    };
    if let Some(o) = off {
        // the checksum field of the L4 header sits at `o - 20` inside `l4`, and is zero in `pseudo` at 12 + that
        let pos = 12 + (o - 20);
        pseudo[pos] = 0;
        pseudo[pos + 1] = 0;
        let c = ip_sum(&pseudo);
        let l = 20 + (o - 20);
        ip[l..l + 2].copy_from_slice(&c.to_be_bytes());
    }
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0x77, 0x02]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&ip);
    while f.len() < pad_to {
        f.push(0);
    }
    f
}

/// Frames as a real macOS host sends them over NCM: a ping (84-byte IP packet, ICMP), a SYN with macOS's option block (MSS, NOP, wscale, NOP, NOP,
/// timestamps, SACK-permitted, EOL; 64-byte IP packet, DF), the same SYN-ACK-less ACK padded to the 60-byte Ethernet minimum, and a DNS query.
/// Every drop must name its reason, and the packets the C routes (TCP, UDP) must be routed; ICMP to an alias is `bad_packet` in the C as well.
#[test]
fn macos_frames_through_usbnet_and_the_router() {
    use tdongle_tailnet_fw::TailnetApi;
    let mut go = go_or_skip!();
    let (gw, _id, alias) = up(&mut go, "gopeer");
    let hip = gw.host.wait_dhcp(Duration::from_secs(10)).unwrap();
    let cmd = |c: &str| {
        let mut o = String::new();
        let _ = gw.sh.serial_command(c, &mut o);
        o
    };
    let num = |j: &str, k: &str| -> u64 {
        let pat = format!("\"{k}\":");
        let i = j.find(&pat).unwrap() + pat.len();
        j[i..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap()
    };
    let extra = || {
        let mut e = String::new();
        gw.sh.serial_status_extra(&mut e);
        e
    };
    let settle = || std::thread::sleep(Duration::from_millis(300));
    let base_bad = num(&cmd("route"), "bad_packet");

    // ping: ICMP echo request, id/seq, 56 bytes of payload starting with a timestamp
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    icmp.extend_from_slice(&[0x66, 0x1a, 0x2b, 0x3c, 0, 0, 0, 0]);
    icmp.extend((8u8..56).map(|i| i));
    let c = ip_sum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    gw.host.inject(host_frame(hip, alias, 1, false, &icmp, 0));
    settle();
    let e = extra();
    assert_eq!(num(&cmd("route"), "bad_packet"), base_bad + 1, "{e}");
    let bad = e.lines().find(|l| l.starts_with("tn_bad ")).unwrap();
    assert!(bad.contains("last=icmp total=84") && bad.contains("hex=45000054"), "{bad}");

    // a macOS SYN with its option block
    let mut syn = vec![0xc3, 0x50, 0x01, 0xbb, 0x1a, 0x2b, 0x3c, 0x4d, 0, 0, 0, 0, 0xb0, 0x02, 0xff, 0xff, 0, 0, 0, 0];
    syn.extend_from_slice(&[2, 4, 5, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 4, 2, 0, 0]);
    let fwd0 = num(&cmd("route"), "forwarded_out");
    gw.host.inject(host_frame(hip, alias, 6, true, &syn, 0));
    // and a bare 40-byte ACK padded to the Ethernet minimum, as a NIC or a Linux host would send it
    let ack = vec![0xc3, 0x51, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0];
    gw.host.inject(host_frame(hip, alias, 6, true, &ack, 60));
    settle();
    let e = extra();
    assert!(e.contains("tn_bad host={icmp:1 }"), "TCP frames must not be bad packets: {e}");
    assert!(num(&cmd("route"), "forwarded_out") >= fwd0 + 1, "the SYN must be routed: {e}");
    let eng = e.lines().find(|l| l.starts_with("tn_eng ")).unwrap();
    assert!(!eng.contains("hs_init=0 "), "routing the SYN starts the handshake: {eng}");

    // a DNS query for the peer from a fresh source port: answered by the gateway (a frame comes back)
    let before = gw.host.counters.to_host.load(Ordering::Relaxed);
    let mut q = vec![0xd1, 0x01, 0, 53, 0, 0, 0, 0, 0xab, 0xcd, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in ["gopeer", "lab", "tailnet"] {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let ulen = q.len() as u16;
    q[4..6].copy_from_slice(&ulen.to_be_bytes());
    q.drain(0..0);
    gw.host.inject(host_frame(hip, [192, 168, 77, 1], 17, false, &q[..], 0));
    settle();
    assert!(gw.host.counters.to_host.load(Ordering::Relaxed) > before, "no DNS answer: {}", extra());
}

/// The board symptom of 2831c4f: the host kept using an alias it had resolved before the dongle rebooted; the new boot did not know it (no alias log), so
/// every packet was held, then dropped. The C persists the alias log (ADR 0013): after a reboot the same alias reaches the same peer without a new lookup.
#[test]
fn an_alias_resolved_before_a_reboot_still_reaches_its_peer() {
    let mut go = go_or_skip!();
    let (gw, id, alias) = up(&mut go, "gopeer");
    assert_eq!(gw.host.echo(alias, 7, b"before", Duration::from_secs(30)).unwrap(), b"before");
    let mut opts = GatewayOpts::new(&go.control_addr);
    opts.storage = Some(gw.storage.clone());
    drop(gw);
    let gw2 = Gateway::start(opts);
    wait_until("the membership to come back", 60, || gw2.is_ready(id));
    gw2.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    // no DNS lookup: the host still holds the old alias
    assert_eq!(gw2.host.echo(alias, 7, b"after the reboot", Duration::from_secs(30)).unwrap(), b"after the reboot");
    gw2.check_engine();
}

#[test]
fn direct_path_is_discovered_and_traffic_moves_to_it() {
    let mut go = go_or_skip!();
    let reply = go.cmd("peer");
    assert!(reply.starts_with("PEER "), "{reply}");
    let gw = Gateway::start(GatewayOpts::new(&go.control_addr));
    let t = std::time::Instant::now();
    let id = gw.add("lab", "tskey-fake");
    wait_until("the membership to be routing", 60, || gw.is_ready(id));
    println!("JOIN: membership routing {:?} after add (the first map is due within 30 s); pool {:?}", t.elapsed(), gw.sh.pool.stats());
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let alias = gw.host.resolve("gopeer.lab.tailnet", Duration::from_secs(10)).expect("dns");
    let mut direct_at = None;
    for n in 0..120 {
        let msg = format!("ping {n}");
        let r = gw.host.echo(alias, 7, msg.as_bytes(), Duration::from_secs(20)).expect("echo");
        assert_eq!(r, msg.as_bytes());
        if gw.member_status(id).unwrap().direct_paths >= 1 {
            direct_at = Some(n);
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let n = direct_at.expect("DISCO found a direct path");
    eprintln!("direct path found after {n} echoes; udp tx/rx {}/{}", gw.net.udp_tx.load(Ordering::Relaxed), gw.net.udp_rx.load(Ordering::Relaxed));
    let (_, d0) = gw.sent();
    for n in 0..10 {
        let msg = format!("after {n}");
        assert_eq!(gw.host.echo(alias, 7, msg.as_bytes(), Duration::from_secs(20)).unwrap(), msg.as_bytes());
    }
    let (_, d1) = gw.sent();
    assert!(d1 >= d0 + 10, "traffic moved to the direct path: {d0} -> {d1}");
    gw.check_engine();
}

#[test]
fn throughput_sanity_over_derp_and_direct() {
    let mut go = go_or_skip!();
    let (gw, id, alias) = up(&mut go, "gopeer");
    // DERP only
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    assert_eq!(gw.host.echo(alias, 7, b"warm", Duration::from_secs(30)).unwrap(), b"warm");
    let (n, d) = gw.host.get_bytes(alias, 80, 512 * 1024, Duration::from_secs(60)).expect("download over derp");
    assert_eq!(n, 512 * 1024);
    let down_derp = mbit(n, d);
    let up = gw.host.upload(alias, 9, 256 * 1024, Duration::from_secs(60));
    if up.is_err() {
        eprintln!("{}", gw.dump());
    }
    let (n, d) = up.expect("upload over derp");
    assert_eq!(n, 256 * 1024);
    let up_derp = mbit(n, d);
    // direct
    gw.net.udp_blocked.store(false, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    let mut probes = 0;
    while gw.member_status(id).unwrap().direct_paths < 1 {
        assert!(t0.elapsed() < Duration::from_secs(150), "no direct path after DERP-only traffic\n{}", gw.dump());
        let _ = gw.host.echo(alias, 7, b"x", Duration::from_secs(10)); // a flow per probe: the router holds 64, so go slowly
        probes += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
    eprintln!("direct path {:.1}s after the UDP block was lifted ({probes} probes)", t0.elapsed().as_secs_f64());
    let r = gw.host.get_bytes(alias, 80, 2 * 1024 * 1024, Duration::from_secs(60));
    if r.is_err() {
        eprintln!("{}", gw.dump());
    }
    let (n, d) = r.expect("download direct");
    assert_eq!(n, 2 * 1024 * 1024);
    let down_direct = mbit(n, d);
    let (n, d) = gw.host.upload(alias, 9, 1024 * 1024, Duration::from_secs(60)).expect("upload direct");
    assert_eq!(n, 1024 * 1024);
    let up_direct = mbit(n, d);
    println!(
        "THROUGHPUT (host, debug-ish profile, loopback, one TCP flow, 60 KB window): derp down {down_derp:.1} up {up_derp:.1} Mbit/s; direct down {down_direct:.1} up {up_direct:.1} Mbit/s"
    );
    assert!(down_derp > 0.3 && up_derp > 0.3 && down_direct > 0.5 && up_direct > 0.5, "sanity floor");
    gw.check_engine();
}

#[test]
fn two_memberships_on_two_control_servers_at_once() {
    let mut a = go_or_skip!();
    let mut b = go_or_skip!();
    a.peer("gopeer").expect("peer a");
    b.peer("gopeer").expect("peer b");
    let mut opts = GatewayOpts::new(&a.control_addr);
    opts.control_routes = vec![a.control_addr.clone(), b.control_addr.clone()];
    let gw = Gateway::start(opts);
    let ia = gw.add("alpha", "tskey-fake");
    wait_until("alpha routing", 60, || gw.is_ready(ia));
    let ib = gw.add("beta", "tskey-fake");
    wait_until("beta routing", 60, || gw.is_ready(ib));
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let aa = gw.host.resolve("gopeer.alpha.tailnet", Duration::from_secs(10)).expect("dns alpha");
    let ab = gw.host.resolve("gopeer.beta.tailnet", Duration::from_secs(10)).expect("dns beta");
    assert_ne!(aa, ab, "one alias per (membership, peer)");
    // both at once
    std::thread::scope(|s| {
        let (h, g) = (&gw.host, &gw);
        let t1 = s.spawn(move || {
            for i in 0..10 {
                let m = format!("alpha {i}");
                assert_eq!(h.echo(aa, 7, m.as_bytes(), Duration::from_secs(30)).unwrap(), m.as_bytes());
            }
        });
        let t2 = s.spawn(move || {
            for i in 0..10 {
                let m = format!("beta {i}");
                assert_eq!(g.host.echo(ab, 7, m.as_bytes(), Duration::from_secs(30)).unwrap(), m.as_bytes());
            }
        });
        t1.join().unwrap();
        t2.join().unwrap();
    });
    let snap = gw.sh.snapshot();
    assert_eq!(snap.members.iter().flatten().count(), 2);
    assert!(snap.members.iter().flatten().all(|m| m.ready && m.sessions >= 1));
    let neg = gw.sh.token.status(0);
    println!("two tailnets: token grants {} max_hold_ms {} max_wait_ms {}", neg.grants, neg.max_hold_ms, neg.max_wait_ms);
    gw.check_engine();
}

#[test]
fn peers_changed_and_removed_deltas() {
    let mut go = go_or_skip!();
    let (gw, id, _alias) = up(&mut go, "gopeer");
    // a peer that joins later arrives as a PeersChanged delta
    let (_, late_key) = go.peer("late").expect("late peer");
    wait_until("the late peer in the directory", 30, || gw.sh.with_engine(|e, _| tdongle_tailnet_engine::PeerDirectory::count(e.dir(), 0)) >= 2);
    let late = gw.host.resolve("late.lab.tailnet", Duration::from_secs(10)).expect("late peer resolves");
    assert_eq!(gw.host.echo(late, 7, b"late", Duration::from_secs(30)).unwrap(), b"late");
    // a raw PeersRemoved delta takes it out again
    let ids = go.ids();
    let (_, late_id, _) = ids.iter().find(|(n, _, _)| n.starts_with("late")).cloned().expect("late id");
    assert!(go.rawmap(&gw_node_key(&ids), &format!("{{\"PeersRemoved\":[{late_id}]}}")));
    wait_until("the late peer removed", 30, || gw.sh.with_engine(|e, _| tdongle_tailnet_engine::PeerDirectory::count(e.dir(), 0)) == 1);
    assert!(gw.host.resolve("late.lab.tailnet", Duration::from_secs(5)).is_err(), "removed peer no longer resolves");
    let _ = (late_key, id);
    gw.check_engine();
}

/// The node key of the gateway's membership (the one whose name starts with `tdongle-`).
fn gw_node_key(ids: &[(String, u64, String)]) -> String {
    ids.iter().find(|(n, _, _)| n.starts_with("tdongle-")).map(|(_, _, k)| k.clone()).expect("the dongle's node")
}

#[test]
fn member_actions_while_traffic_flows_leave_no_leak() {
    use std::sync::atomic::AtomicU32;
    let mut go = go_or_skip!();
    go.peer("gopeer").expect("peer");
    let gw = Gateway::start(GatewayOpts::new(&go.control_addr));
    assert!(gw.leaks().is_empty(), "baseline: {:?}", gw.leaks());
    assert!(!gw.host.carrier.load(Ordering::SeqCst), "no carrier before a membership routes");
    let one = gw.add("one", "tskey-fake");
    wait_until("one routing", 60, || gw.is_ready(one));
    wait_until("the NCM carrier up once a membership routes", 10, || gw.host.carrier.load(Ordering::SeqCst));
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let a1 = gw.host.resolve("gopeer.one.tailnet", Duration::from_secs(10)).expect("dns one");
    assert_eq!(gw.host.echo(a1, 7, b"one", Duration::from_secs(30)).unwrap(), b"one");
    // the provisioning key is spent once it joined
    wait_until("the auth key dropped from the registry", 10, || gw.sh.registry.lock(|c| c.borrow().reg.get(one).is_some_and(|m| m.key().is_empty())));
    let stored = String::from_utf8(gw.storage.peek("tn_settings", "members").expect("members saved")).unwrap();
    assert!(stored.contains("\"key\":\"\""), "{stored}");
    let baseline_nodes = go.nodes().len();

    let (ok1, bad1, ok2, bad2) = (AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0));
    let stop = std::sync::atomic::AtomicBool::new(false);
    let two_alias = std::sync::Mutex::new(None::<[u8; 4]>);
    struct StopOnDrop<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst); // a failed assertion must not leave the traffic threads running
        }
    }
    std::thread::scope(|s| {
        let _guard = StopOnDrop(&stop);
        // traffic to membership one's peer and, once it exists, to two's
        s.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                match gw.host.echo(a1, 7, b"ping-one", Duration::from_secs(4)) {
                    Ok(r) if r == b"ping-one" => ok1.fetch_add(1, Ordering::SeqCst),
                    _ => bad1.fetch_add(1, Ordering::SeqCst),
                };
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        s.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                let Some(a2) = *two_alias.lock().unwrap() else {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                };
                match gw.host.echo(a2, 7, b"ping-two", Duration::from_secs(4)) {
                    Ok(r) if r == b"ping-two" => ok2.fetch_add(1, Ordering::SeqCst),
                    _ => bad2.fetch_add(1, Ordering::SeqCst),
                };
                std::thread::sleep(Duration::from_millis(300));
            }
        });

        // 1. add a second membership while one carries traffic
        let two = gw.add("two", "tskey-fake");
        wait_until("two routing", 60, || gw.is_ready(two));
        let a2 = gw.host.resolve("gopeer.two.tailnet", Duration::from_secs(10)).expect("dns two");
        *two_alias.lock().unwrap() = Some(a2);
        wait_until("traffic on both", 30, || ok1.load(Ordering::SeqCst) >= 3 && ok2.load(Ordering::SeqCst) >= 3);
        assert_eq!(gw.sh.counts().configured, 2);

        // 2. disable one: its traffic stops, two's goes on, the slot is freed
        let (ok2_before, bad1_before) = (ok2.load(Ordering::SeqCst), bad1.load(Ordering::SeqCst));
        let r = gw.action(MemberAction::Disable(one));
        assert_eq!(r.error, None);
        wait_until("one's slot freed", 15, || gw.sh.slot_of(one).is_none());
        wait_until("one's traffic failing while it is disabled", 15, || bad1.load(Ordering::SeqCst) > bad1_before);
        assert!(ok2.load(Ordering::SeqCst) > ok2_before, "two's traffic is not disturbed by one's stop");
        assert!(gw.member_status(one).is_none(), "gone from the engine");
        assert_eq!(gw.sh.counts().enabled, 1);

        // 3. enable it again: a new session on the same identity (the key was spent: the control server knows the node)
        let r = gw.action(MemberAction::Enable(one));
        assert_eq!(r.error, None);
        wait_until("one routing again", 60, || gw.is_ready(one));
        let ok1_before = ok1.load(Ordering::SeqCst);
        wait_until("one's traffic again", 30, || ok1.load(Ordering::SeqCst) > ok1_before + 2);
        assert_eq!(go.nodes().len(), baseline_nodes + 1, "re-enabling reused the node (the identity persisted)");

        // 4. remove two: identity erased, registry updated, slot freed, one unaffected
        let ns2 = format!("tn_{two:08x}");
        assert!(gw.storage.namespaces().contains(&ns2));
        let r = gw.action(MemberAction::Remove(two));
        assert_eq!(r.error, None);
        wait_until("two's slot freed", 15, || gw.sh.slot_of(two).is_none());
        assert!(!gw.storage.namespaces().contains(&ns2), "identity namespace erased");
        assert_eq!(gw.sh.counts().configured, 1);
        *two_alias.lock().unwrap() = None;
        let ok1_before = ok1.load(Ordering::SeqCst);
        wait_until("one still carries traffic", 20, || ok1.load(Ordering::SeqCst) > ok1_before + 2);
        // a removed id is not found; double remove is the C's text
        assert_eq!(gw.action(MemberAction::Remove(two)).error, Some("Membership not found"));

        // 5. a "reboot": same storage, new runtime: the enabled membership comes back without being added again
        stop.store(true, Ordering::SeqCst);
    });
    let _ = (ok2.load(Ordering::SeqCst), bad2.load(Ordering::SeqCst));
    gw.check_engine();
    let mut gw2 = gw;
    let storage = gw2.storage.clone();
    gw2.stop();
    drop(gw2);
    let mut opts = GatewayOpts::new(&go.control_addr);
    opts.storage = Some(storage);
    let gw3 = Gateway::start(opts);
    wait_until("the saved membership restarted by itself", 60, || gw3.sh.slot_of(one).is_some() && gw3.is_ready(one));
    assert_eq!(go.nodes().len(), baseline_nodes + 1, "the same node key after a reboot");
    // remove the last one: back to baseline
    assert_eq!(gw3.action(MemberAction::Remove(one)).error, None);
    if !try_wait(20, || gw3.leaks().is_empty()) {
        panic!("not released: {:#?}", gw3.leaks());
    }
    wait_until("the NCM carrier down again", 10, || !gw3.host.carrier.load(Ordering::SeqCst));
    println!("ledger after the last removal: {:?}", gw3.sh.ledger.total());
    gw3.check_engine();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn wifi_bounce_is_recovered_from() {
    let mut go = go_or_skip!();
    let (gw, id, alias) = up(&mut go, "gopeer");
    assert_eq!(gw.host.echo(alias, 7, b"before", Duration::from_secs(30)).unwrap(), b"before");
    let sessions0 = gw.sh.slots[0].status().sessions;
    let gen0 = gw.net.generation.load(Ordering::SeqCst);
    for round in 1..=2 {
        gw.net.bounce();
        assert_ne!(gw.net.generation.load(Ordering::SeqCst), gen0);
        // control restarts at once; the relay reconnects; the tunnel session survives (WireGuard does not care about the underlay)
        wait_until("a new control session", 30, || gw.sh.slots[0].status().sessions > sessions0 + round - 1);
        wait_until("routing again", 60, || gw.is_ready(id) && gw.sh.slots[0].status().connected);
        let m = format!("after bounce {round}");
        assert_eq!(gw.host.echo(alias, 7, m.as_bytes(), Duration::from_secs(40)).unwrap(), m.as_bytes());
    }
    let st = gw.sh.slots[0].status();
    println!("after two bounces: sessions {} (was {sessions0}), derp connects {}, udp port {}", st.sessions, st.derp.connects.get(), st.udp_port);
    assert!(st.derp.connects.get() >= 2, "the relay reconnected");
    gw.check_engine();
}

#[test]
fn control_server_restart_is_recovered_from() {
    let bin = match go_binary() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: the Go interop server is not available: {e}");
            return;
        }
    };
    let (cp, dp) = (free_port(), free_port());
    let env = [("INTEROP_CONTROL_PORT", cp.to_string()), ("INTEROP_DERP_PORT", dp.to_string())];
    let mut go = tdongle_tailnet_host::server::GoServer::spawn_with(&bin, &env).expect("server");
    let (gw, id, alias) = up(&mut go, "gopeer");
    assert_eq!(gw.host.echo(alias, 7, b"before the restart", Duration::from_secs(30)).unwrap(), b"before the restart");
    let sessions0 = gw.sh.slots[0].status().sessions;
    // the server dies: control and relay with it; the gateway notices and backs off
    drop(go);
    wait_until("the session ending", 40, || !gw.sh.slots[0].status().connected);
    std::thread::sleep(Duration::from_secs(2));
    // a new server (a new tailnet, a new DERP certificate) at the same addresses
    let mut go2 = tdongle_tailnet_host::server::GoServer::spawn_with(&bin, &env).expect("restarted server");
    go2.peer("gopeer").expect("peer on the new server");
    wait_until("a new control session", 90, || gw.sh.slots[0].status().sessions > sessions0 && gw.sh.slots[0].status().connected);
    wait_until("routing again (relay reconnected with the new pin)", 90, || gw.is_ready(id));
    // the new tailnet has a new peer under the same name: resolve again (the alias is re-issued) and talk to it
    let alias2 = gw.host.resolve("gopeer.lab.tailnet", Duration::from_secs(10)).expect("dns after the restart");
    let r = gw.host.echo(alias2, 7, b"after the restart", Duration::from_secs(60));
    assert_eq!(r.as_deref(), Ok(&b"after the restart"[..]), "{}", gw.dump());
    println!("recovered: sessions {} -> {}", sessions0, gw.sh.slots[0].status().sessions);
    gw.check_engine();
}

fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().ok();
    out.and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok()).unwrap_or(0)
}

/// The soak: two memberships on two control servers carry steady traffic for `TAILNET_SOAK_SECS` (default 100 s so CI stays under two minutes; the ten-minute run is opt-in, TAILNET_SOAK_SECS=600) while the direct path is
/// flapped every 90 s (UDP cut for 10 s: shorter than the 60 s the C trusts a direct path for, so the connections ride it out; the long cut is
/// `direct_path_falls_back_to_derp_after_the_trust_lapses`). Nothing may leak, nothing may churn, the model heap's floor must never be crossed, and the transactions must succeed.
#[test]
fn soak_ten_minutes_with_two_tailnets() {
    use std::sync::atomic::{AtomicBool, AtomicU32};
    let secs: u64 = std::env::var("TAILNET_SOAK_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(100);
    let mut a = go_or_skip!();
    let mut b = go_or_skip!();
    a.peer("gopeer").expect("peer a");
    b.peer("gopeer").expect("peer b");
    let mut opts = GatewayOpts::new(&a.control_addr);
    opts.control_routes = vec![a.control_addr.clone(), b.control_addr.clone()];
    let gw = Gateway::start(opts);
    let ia = gw.add("alpha", "tskey-fake");
    wait_until("alpha routing", 60, || gw.is_ready(ia));
    let ib = gw.add("beta", "tskey-fake");
    wait_until("beta routing", 60, || gw.is_ready(ib));
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let aa = gw.host.resolve("gopeer.alpha.tailnet", Duration::from_secs(10)).expect("dns alpha");
    let ab = gw.host.resolve("gopeer.beta.tailnet", Duration::from_secs(10)).expect("dns beta");
    let sessions0: Vec<u32> = (0..2).map(|i| gw.sh.slots[i].status().sessions).collect();
    let connects0: Vec<u32> = (0..2).map(|i| gw.sh.slots[i].status().derp.connects.get()).collect();
    let rss0 = rss_kib();

    let (ok, bad) = (std::sync::Arc::new(AtomicU32::new(0)), std::sync::Arc::new(AtomicU32::new(0)));
    let stop = AtomicBool::new(false);
    let started = std::time::Instant::now();
    let mut samples = Vec::new();
    std::thread::scope(|s| {
        // one long-lived connection per tailnet (what real traffic looks like; the router holds 64 flows, so a connection per echo would exhaust it)
        for alias in [aa, ab] {
            let (gw, stop) = (&gw, &stop);
            let (ok, bad) = (ok.clone(), bad.clone());
            s.spawn(move || {
                let arc_stop = std::sync::Arc::new(AtomicBool::new(false));
                let a2 = arc_stop.clone();
                std::thread::scope(|inner| {
                    inner.spawn(move || {
                        while !stop.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(200));
                        }
                        a2.store(true, Ordering::SeqCst);
                    });
                    gw.host.echo_loop(alias, 7, b"soak echo payload", Duration::from_millis(1500), arc_stop.clone(), (ok, bad));
                });
            });
        }
        // and a fresh connection now and then: a 128 KiB download from alpha every 20 s
        {
            let (gw, stop) = (&gw, &stop);
            let (ok, bad) = (ok.clone(), bad.clone());
            s.spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match gw.host.get_bytes(aa, 80, 128 * 1024, Duration::from_secs(30)) {
                        Ok((n, _)) if n == 128 * 1024 => ok.fetch_add(1, Ordering::SeqCst),
                        _ => bad.fetch_add(1, Ordering::SeqCst),
                    };
                    for _ in 0..20 {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            });
        }
        let (mut last_ok, mut last_progress, mut stall_dumped) = (0u32, 0u64, false);
        let mut flap_at = 90u64;
        let mut blocked_until = 0u64;
        while started.elapsed().as_secs() < secs {
            std::thread::sleep(Duration::from_secs(5));
            let t = started.elapsed().as_secs();
            if t >= flap_at && blocked_until == 0 {
                gw.net.udp_blocked.store(true, Ordering::SeqCst);
                blocked_until = t + 10;
            } else if blocked_until != 0 && t >= blocked_until {
                gw.net.udp_blocked.store(false, Ordering::SeqCst);
                blocked_until = 0;
                flap_at = t + 90;
            }
            let hq = gw.sh.host_q.stats().high_water;
            let dq: u32 = gw.sh.slots.iter().map(|s| s.derp_q.stats().high_water).max().unwrap();
            let uq: u32 = gw.sh.slots.iter().map(|s| s.udp_q.stats().high_water).max().unwrap();
            samples.push((t, gw.heap.minimum_free(), hq, dq, uq, rss_kib(), ok.load(Ordering::SeqCst), bad.load(Ordering::SeqCst)));
            // a stall detector: no transaction succeeded for 20 s
            let n = ok.load(Ordering::SeqCst);
            if n != last_ok {
                last_ok = n;
                last_progress = t;
                stall_dumped = false;
            } else if t >= last_progress + 20 && !stall_dumped {
                stall_dumped = true;
                println!("STALL at t={t}s (no success since t={last_progress}s)\n{}", gw.dump());
            }
            if t % 60 < 5 {
                println!(
                    "soak t={t:>4}s min_free {} host_q hw {hq} derp_q hw {dq} udp_q hw {uq} rss {} KiB ok {} bad {}",
                    gw.heap.minimum_free(),
                    rss_kib(),
                    ok.load(Ordering::SeqCst),
                    bad.load(Ordering::SeqCst)
                );
            }
        }
        stop.store(true, Ordering::SeqCst);
    });
    gw.net.udp_blocked.store(false, Ordering::SeqCst);
    let (okn, badn) = (ok.load(Ordering::SeqCst), bad.load(Ordering::SeqCst));
    let floor = tdongle_tailnet_admission::heap::ML_HB_FLOOR;
    let min_free = gw.heap.minimum_free();
    let sessions: Vec<u32> = (0..2).map(|i| gw.sh.slots[i].status().sessions).collect();
    let connects: Vec<u32> = (0..2).map(|i| gw.sh.slots[i].status().derp.connects.get()).collect();
    let rss1 = rss_kib();
    println!(
        "SOAK {secs}s: {okn} ok / {badn} failed transactions; model heap min free {min_free} (floor {floor}); negotiations in flight at most {}; heap_low_events {}; out_refused {}; \
         record leases max {} timeouts {} leases {}; pool high water {} B (denied: cap {} floor {} heap {}, waits {}); sessions {:?} -> {:?}; derp connects {:?} -> {:?}; rss {rss0} -> {rss1} KiB",
        gw.sh.stats.neg_max.load(Ordering::SeqCst),
        gw.sh.heap_low_events.load(Ordering::SeqCst),
        tdongle_tailnet_runtime::shared::RtStats::get(&gw.sh.stats.out_refused),
        gw.sh.lease.max_holders(),
        gw.sh.lease.timeouts(),
        gw.sh.lease.leases(),
        gw.sh.pool.stats().high_water,
        gw.sh.pool.stats().denied_cap,
        gw.sh.pool.stats().denied_floor,
        gw.sh.pool.stats().denied_heap,
        gw.sh.pool.stats().waits,
        sessions0,
        sessions,
        connects0,
        connects
    );
    println!("{}", gw.dump());
    assert!(min_free >= floor, "the heap floor was crossed: {min_free} < {floor}");
    assert_eq!(gw.sh.heap_low_events.load(Ordering::SeqCst), 0, "no heap reading below the floor while a membership routed");
    assert_eq!(gw.sh.stats.neg_max.load(Ordering::SeqCst), 1, "negotiations never overlapped");
    assert_eq!(gw.sh.lease.timeouts(), 0);
    // every pooled byte is accounted for: what the pool holds now is the live sockets' windows (and a record or workspace in flight), never more than the cap
    let ps = gw.sh.pool.stats();
    assert!(ps.high_water as usize <= tdongle_tailnet_runtime::shared::POOL_CAP, "{ps:?}");
    assert_eq!((ps.denied_cap, ps.denied_heap), (0, 0), "the pool was never refused by its cap or the allocator: {ps:?}");
    assert!(badn * 100 <= (okn + badn) * 3, "transactions failed: {badn} of {}", okn + badn);
    assert!(sessions.iter().zip(&sessions0).all(|(n, o)| n <= &(o + 1)), "control sessions churned: {sessions0:?} -> {sessions:?}");
    assert!(connects.iter().zip(&connects0).all(|(n, o)| n <= &(o + 2)), "the relay link churned: {connects0:?} -> {connects:?}");
    assert!(rss1 < rss0 + 64 * 1024, "process memory grew from {rss0} to {rss1} KiB");
    let hq = gw.sh.host_q.stats();
    assert_eq!(hq.refused, 0, "the host queue never refused: {hq:?}");
    gw.check_engine();
    let _ = samples;
}

/// A one-answer A-record DNS server on loopback: every query for any name gets `ip`.
fn spawn_dns_server(ip: [u8; 4]) -> (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicU32>) {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let queries = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let q2 = queries.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if n < 17 {
                continue;
            }
            q2.fetch_add(1, Ordering::SeqCst);
            let mut end = 12;
            while buf[end] != 0 {
                end += buf[end] as usize + 1;
            }
            end += 5; // the root label, QTYPE, QCLASS
            let mut r = buf[..end].to_vec();
            r[2] = 0x81;
            r[3] = 0x80;
            r[6..8].copy_from_slice(&1u16.to_be_bytes());
            r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            r.extend_from_slice(&ip);
            let _ = sock.send_to(&r, from);
        }
    });
    (addr, queries)
}

#[test]
fn internet_passthrough_and_dns_forwarding_work_without_any_membership() {
    let (dns_addr, dns_queries) = spawn_dns_server([93, 184, 216, 34]);
    let mut opts = GatewayOpts::new("127.0.0.1:1");
    opts.local_ip = [192, 168, 1, 50];
    opts.dns = Some([192, 168, 1, 1]);
    let gw = Gateway::start(opts);
    *gw.net.dns_redirect.lock().unwrap() = Some(dns_addr);
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    // an ordinary name is forwarded to the Wi-Fi resolver and answered
    let ip = gw.host.resolve("example.org", Duration::from_secs(10)).expect("forwarded DNS");
    assert_eq!(ip, [93, 184, 216, 34]);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 1);
    assert_eq!(tdongle_tailnet_runtime::shared::RtStats::get(&gw.sh.stats.dns_fwd), 1);
    // UDP to an Internet address goes through the NAT to "Wi-Fi" and the reflected reply comes back through the NAT
    let r = gw.host.udp_echo(ip, 7, b"through the nat", Duration::from_secs(10)).expect("udp through the NAT");
    assert_eq!(r, b"through the nat");
    assert_eq!(gw.wifi.counters.sent.load(Ordering::Relaxed), 1);
    assert_eq!(gw.wifi.seen.lock().unwrap()[0], (u32::from_be_bytes(ip), 7));
    // and a tailnet name with no membership is refused locally, never forwarded
    assert!(gw.host.resolve("anyone.lab.tailnet", Duration::from_secs(3)).is_err());
    assert_eq!(dns_queries.load(Ordering::SeqCst), 1, "a tailnet name is never sent to the Wi-Fi resolver");
    gw.check_engine();
}

#[test]
fn admission_refuses_a_start_when_the_heap_is_short_and_starts_it_when_it_recovers() {
    let mut go = go_or_skip!();
    go.peer("gopeer").expect("peer");
    let mut opts = GatewayOpts::new(&go.control_addr);
    opts.heap_free = 30_000; // below the 32,684 B the Rust task model needs (recovery + one negotiation + the router floor)
    let gw = Gateway::start(opts);
    let id = gw.add("lab", "tskey-fake");
    wait_until("the refusal text", 15, || {
        gw.sh.registry.lock(|c| c.borrow().reg.get(id).is_some_and(|m| m.error.as_bytes() == b"Not enough free memory to activate this membership"))
    });
    assert!(gw.sh.slot_of(id).is_none() && gw.leaks().iter().all(|l| l.starts_with("identity")), "{:?}", gw.leaks());
    assert!(tdongle_tailnet_runtime::shared::RtStats::get(&gw.sh.stats.admission_refused) >= 1);
    // memory comes back (the model heap is charged negatively by releasing a charge that was never made: use a fresh gateway-wide charge instead)
    gw.heap.release(0);
    let mut opts2 = GatewayOpts::new(&go.control_addr);
    opts2.heap_free = 106_000;
    opts2.storage = Some(gw.storage.clone());
    drop(gw);
    let gw2 = Gateway::start(opts2);
    wait_until("the membership starts once the heap allows it", 60, || gw2.is_ready(id));
    assert!(gw2.sh.registry.lock(|c| c.borrow().reg.get(id).is_some_and(|m| m.error.is_empty())), "the refusal text is cleared on a start");
    gw2.check_engine();
}

#[test]
fn stun_learns_the_public_endpoint_and_the_control_plane_is_told() {
    let mut go = go_or_skip!();
    let (gw, id, alias) = up(&mut go, "gopeer");
    assert_ne!(go.stun_port, 0);
    // the engine's STUN schedule asks the DERP node's STUN port (a real responder) from the membership's own socket; the answer is the learned endpoint
    wait_until("the STUN-learned endpoint", 60, || gw.sh.slots[0].status().learned_ep.is_some());
    let st = gw.sh.slots[0].status();
    let learned = st.learned_ep.unwrap();
    assert_eq!(learned.v4_octets(), Some([127, 0, 0, 1]), "on loopback the server sees our own address");
    assert_eq!(Some(learned.port()), Some(st.udp_port), "the mapping of the membership's socket, not some other port");
    assert!(st.eps_gen >= 2, "the endpoint set changed twice: local, then learned");
    assert!(gw.member_status(id).unwrap().has_public_ep);
    // and the control plane was told: its record of our node carries the STUN-learned endpoint (the lite update of the control driver)
    let ids = go.ids();
    let key = gw_node_key(&ids);
    let want = format!("127.0.0.1:{}", learned.port());
    wait_until("the control server to know the endpoint", 30, || go.endpoints(&key).contains(&want));
    assert_eq!(gw.host.echo(alias, 7, b"stun", Duration::from_secs(30)).unwrap(), b"stun");
    gw.check_engine();
}

#[test]
fn direct_path_falls_back_to_derp_after_the_trust_lapses() {
    let mut go = go_or_skip!();
    let (gw, id, alias) = up(&mut go, "gopeer");
    let t0 = std::time::Instant::now();
    while gw.member_status(id).unwrap().direct_paths < 1 {
        assert!(t0.elapsed() < Duration::from_secs(60), "no direct path\n{}", gw.dump());
        let _ = gw.host.echo(alias, 7, b"x", Duration::from_secs(10));
        std::thread::sleep(Duration::from_secs(1));
    }
    let (_, d0) = gw.sent();
    assert!(gw.host.echo(alias, 7, b"direct", Duration::from_secs(20)).is_ok());
    // the underlay's UDP dies: the direct path stays trusted for `trust_ms` (the C's 60 s) after its last pong, then DISCO falls back to the relay
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    let cut = std::time::Instant::now();
    let mut first_ok = None;
    let derp_before = gw.sent().0;
    while cut.elapsed() < Duration::from_secs(100) {
        if gw.host.echo(alias, 7, b"after the cut", Duration::from_secs(8)).as_deref() == Ok(&b"after the cut"[..]) {
            first_ok = Some(cut.elapsed());
            break;
        }
    }
    let first_ok = first_ok.unwrap_or_else(|| panic!("no traffic 100 s after the cut\n{}", gw.dump()));
    println!("direct -> DERP: first echo through the relay {:.1}s after the UDP cut (trust 60 s); direct sends before the cut: {d0}", first_ok.as_secs_f64());
    assert!(first_ok < Duration::from_secs(90), "the fallback took {first_ok:?}");
    assert!(gw.sent().0 > derp_before, "the packets went through DERP");
    // the per-peer pass that clears the direct flag runs once a second (the C's `disco_periodic_probes`): allow for one tick
    wait_until("direct flag cleared by the next tick", 5, || gw.member_status(id).unwrap().direct_paths == 0);
    gw.check_engine();
}

/// The relay must stay up through a quiet period and then carry traffic: the real derper sends a KeepAlive about every 60 s and drops a client that does not read or answer. Idle
/// time is `TN_DERP_IDLE_SECS` (default 300, five minutes: `TN_DERP_IDLE_SECS=300 cargo test -p tdongle-tailnet-host --test e2e derp_survives_idle -- --ignored --nocapture`).
/// The link must reach ready once and never go back to waiting, with its frames-in counter growing from the server's keepalives alone.
#[test]
#[ignore = "five minutes of wall clock: run with --ignored"]
fn derp_survives_idle_then_carries_traffic() {
    let idle: u64 = std::env::var("TN_DERP_IDLE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
    let mut go = go_or_skip!();
    let (gw, _id, alias) = up(&mut go, "gopeer");
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    assert_eq!(gw.host.echo(alias, 7, b"warm", Duration::from_secs(30)).unwrap(), b"warm");
    // what the relay carries before the quiet period (a loopback figure: the point is that it does not fall off after it)
    let (n, d) = gw.host.get_bytes(alias, 80, 512 * 1024, Duration::from_secs(60)).expect("download over derp before idle");
    assert_eq!(n, 512 * 1024);
    let down_before = mbit(n, d);
    let before = gw.sh.slots[0].status().derp;
    let (connects0, frames0) = (before.connects.get(), before.frames_rx.get());
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(idle) {
        std::thread::sleep(Duration::from_secs(5));
        let st = gw.sh.slots[0].status();
        assert_eq!(st.derp_state.name(), "ready", "relay left ready after {:?}\n{}", t0.elapsed(), gw.dump());
    }
    let after = gw.sh.slots[0].status().derp;
    assert_eq!(after.connects.get(), connects0, "the relay reconnected during the idle period\n{}", gw.dump());
    eprintln!(
        "idle {idle} s: frames in {} -> {}, keepalives {}, pings answered {}",
        frames0,
        after.frames_rx.get(),
        after.keepalives.get(),
        after.pings_answered.get()
    );
    assert_eq!(gw.host.echo(alias, 7, b"after idle", Duration::from_secs(30)).unwrap(), b"after idle");
    let (n, d) = gw.host.get_bytes(alias, 80, 512 * 1024, Duration::from_secs(60)).expect("download over derp after idle");
    assert_eq!(n, 512 * 1024);
    let (n, _) = gw.host.upload(alias, 9, 256 * 1024, Duration::from_secs(60)).expect("upload over derp after idle");
    assert_eq!(n, 256 * 1024);
    let down_after = mbit(512 * 1024, d);
    println!("derp after {idle} s idle: down {down_after:.1} Mbit/s (before: {down_before:.1})");
    assert!(down_after > down_before * 0.25, "relay throughput collapsed after {idle} s idle: {down_after:.2} against {down_before:.2} Mbit/s\n{}", gw.dump());
    gw.check_engine();
}

/// Two unmeshed DERP servers (regions 900 and 901) and a peer homed on the region the gateway is **not** homed on: a relay server only forwards to clients connected to it, so
/// the gateway must send the peer's packets to the peer's home region, through a second link of its own, and still receive what the peer sends to the gateway's home region.
/// With one link (before) every packet for the peer was dropped by the wrong server and the flow carried nothing.
fn peer_on_another_region(env: &[(&str, String)], peer_region: u32, expect_index: u8) {
    let bin = match go_binary() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: the Go interop server is not available: {e}");
            return;
        }
    };
    let mut go = tdongle_tailnet_host::server::GoServer::spawn_with(&bin, env).expect("go server with two regions");
    let gw = Gateway::start(GatewayOpts::new(&go.control_addr));
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    // the extra link takes two seconds to come up, as a slow TLS start on the board does: the peer's first packets (the handshake, then the flow's SYNs) arrive before it
    // is ready and must wait for it, not be lost
    gw.net.derp_connect_delay_ms.store(2000, Ordering::Relaxed);
    let id = gw.add("lab", "tskey-fake");
    wait_until("the membership to be routing", 60, || gw.is_ready(id));
    // the region the gateway's own link is on; the peer is started afterwards and may not choose that region as its home
    wait_until("the home link to be ready", 30, || gw.sh.slots[0].status().derp_state.name() == "ready");
    let home = tdongle_tailnet_runtime::derp::DERP_DIAG.region.load(Ordering::Relaxed);
    assert!(home == 900 || home == peer_region, "home region {home}");
    assert_eq!(go.cmd(&format!("nohome {home}")), "OK");
    if home == peer_region {
        // the gateway chose the peer's region: not the scenario (the peer may not use it as its home now), the other tests cover one region
        eprintln!("SKIP: the gateway homed on the region meant for the peer");
        return;
    }
    let (_, _) = go.peer("gopeer").expect("peer");
    // shorter visits for the test: idle 6 s, at least 8 s, 2 s before the next
    use tdongle_tailnet_runtime::derp::VISIT_TIMING;
    VISIT_TIMING[0].store(6000, Ordering::Relaxed);
    VISIT_TIMING[1].store(8000, Ordering::Relaxed);
    VISIT_TIMING[2].store(2000, Ordering::Relaxed);
    let gw_key = go.ids().into_iter().find(|(n, _, _)| n.starts_with("tdongle")).map(|(_, _, k)| k).expect("the gateway's node key");
    assert_eq!(go.home_derp(&gw_key), Some(home), "before the visit the control plane has our real home");
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let alias = gw.host.resolve("gopeer.lab.tailnet", Duration::from_secs(30)).expect("dns");
    let echoed = gw.host.echo(alias, 7, b"across regions", Duration::from_secs(40));
    if echoed.is_err() {
        use tdongle_tailnet_runtime::derp::X_COUNTS;
        eprintln!("{}", gw.dump());
        let mut extra = String::new();
        TailnetApi::serial_status_extra(&*gw.sh, &mut extra);
        eprintln!("{extra}");
        eprintln!("home {home}; visit counts {:?}; peers {:?}", X_COUNTS.iter().map(|c| c.load(Ordering::Relaxed)).collect::<Vec<_>>(), go.ids());
    }
    assert_eq!(echoed.expect("echo to a peer homed on the other region"), b"across regions");
    // the visit is on (it lasts at least 8 s): control has our visited region as home
    wait_until("control to have our visited home", 6, || go.home_derp(&gw_key) == Some(peer_region));
    let (n, d) = gw.host.get_bytes(alias, 80, 256 * 1024, Duration::from_secs(60)).expect("download from a peer on the other region");
    assert_eq!(n, 256 * 1024);
    let (n2, d2) = gw.host.upload(alias, 9, 128 * 1024, Duration::from_secs(60)).expect("upload to a peer on the other region");
    assert_eq!(n2, 128 * 1024);
    // while the link is on the peer's region our advertised home is that region: a node sends to the destination's home relay (tsnet also answers on the region a packet came
    // in by, so this test alone would pass without it; the control plane's view of our home is what a peer that does not do that depends on)
    let visiting = tdongle_tailnet_runtime::derp::VISITING.load(Ordering::Relaxed);
    let _ = visiting;
    // the link stays on the peer's region, and the control plane keeps it as our home, until traffic needs another region: idle time does not bring it back
    std::thread::sleep(Duration::from_secs(12));
    assert_eq!(tdongle_tailnet_runtime::derp::VISITING.load(Ordering::Relaxed), peer_region, "the link stayed on the peer's region while idle");
    assert_eq!(go.home_derp(&gw_key), Some(peer_region), "and our advertised home stayed with it");
    use tdongle_tailnet_runtime::derp::X_COUNTS;
    let c: Vec<u32> = X_COUNTS.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    let (queued, sent, starts) = (c[0], c[1], c[5]);
    println!("counts [queued, sent, full, heap, unknown, visits, expired, dropped_on_leave, refused, rx_while_visiting, home_busy] {c:?}");
    assert!(c[9] > 0, "frames from the extra link's region reach the engine: {c:?}");
    assert_eq!(c[6] + c[2] + c[3] + c[4] + c[8], 0, "nothing was dropped or expired while the link came up: {c:?}");
    println!("home region {home}; visit: queued {queued} sent {sent} visits {starts}; down {:.1} up {:.1} Mbit/s", mbit(n, d), mbit(n2, d2));
    // only the packets that arrived before the link reached the peer's region wait in the queue (the first of the handshake); the rest go straight out on the link
    // one visit, then it stays: the probes of the peer and idle time do not move the link back and forth
    assert!(
        queued >= 1 && sent == queued && starts == 1,
        "the packets that waited for the visit were sent, and the link went there once: queued {queued} sent {sent} visits {starts}"
    );
    let indexed = gw.sh.with_engine(|e, _| e.member(id).map_or(0, |m| m.rt.derp_index.count));
    assert_eq!(indexed, expect_index, "every region of the map is in the compact index");
    gw.check_engine();
}

#[test]
fn a_peer_homed_on_another_derp_region_is_reached_through_a_second_link() {
    peer_on_another_region(&[("INTEROP_DERP2", "1".to_string())], 901, 2);
}

/// The map has five regions, the gateway keeps four of them in full (the netcheck's, the C's bound), and the peer is homed on the fifth: its address comes from the compact index.
#[test]
fn a_peer_homed_on_the_fifth_region_of_the_map_is_reached_through_the_index() {
    peer_on_another_region(&[("INTEROP_DERP2", "1".to_string()), ("INTEROP_DERP2_ID", "905".to_string()), ("INTEROP_DERP_FILLERS", "3".to_string())], 905, 5);
}

/// A relay that writes at about 1.4 Mbit/s (8 ms per 1.4 KB frame): a bulk transfer over DERP only, one relay link, runs at the relay's pace with nothing refused or dropped
/// (the sender is held back by the full relay queue, as the bridge NAKs the host).
#[test]
fn derp_only_bulk_is_paced_by_the_relay_not_dropped() {
    let mut go = go_or_skip!();
    let (gw, _id, alias) = up(&mut go, "gopeer");
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    assert_eq!(gw.host.echo(alias, 7, b"warm", Duration::from_secs(30)).unwrap(), b"warm");
    gw.net.derp_write_delay_ms.store(8, Ordering::Relaxed);
    let refused =
        |gw: &Gateway| gw.sh.with_engine(|e, _| e.stats().tx_count(tdongle_tailnet_engine::TxFate::TxRefused)) + gw.sh.slots[0].derp_q.stats().refused;
    let before = refused(&gw);
    let (n, d) = gw.host.upload(alias, 9, 192 * 1024, Duration::from_secs(90)).expect("upload over a slow relay");
    assert_eq!(n, 192 * 1024);
    let up = mbit(n, d);
    let host_refused0 = gw.sh.host_q.stats().refused;
    let (n, d) = gw.host.get_bytes(alias, 80, 192 * 1024, Duration::from_secs(90)).expect("download over a slow relay");
    assert_eq!(n, 192 * 1024);
    let down = mbit(n, d);
    // the relay reader holds a record back until the host queue has room for it: nothing the relay delivered is refused by the host queue
    assert_eq!(gw.sh.host_q.stats().refused - host_refused0, 0, "no relay frame refused by the host queue during the download");
    let dropped = refused(&gw) - before;
    let hold = &tdongle_tailnet_runtime::usb::HOLD_STATS;
    println!(
        "slow relay (8 ms per frame): up {up:.2} down {down:.2} Mbit/s, egress refused {dropped}; holds {} ran out {}",
        hold[0].load(Ordering::Relaxed),
        hold[1].load(Ordering::Relaxed)
    );
    // (the egress: what the host sends to the relay; the download direction's host queue is another change)
    assert_eq!(dropped, 0, "no relay egress refused at steady state\n{}", gw.dump());
    assert!(up >= 0.8, "upload {up:.2} Mbit/s over a ~1.4 Mbit/s relay");
    gw.check_engine();
}

/// The relay connection's windows follow its traffic: idle windows while it idles, the big ones (a round trip's worth) once it has carried a transfer (at the first lull: the
/// switch is a reconnect), idle again after a long quiet.
/// (The host's tokio sockets have no windows to resize: this checks the decision and the reconnects, and that a transfer survives them.)
#[test]
fn the_relay_windows_are_big_while_it_carries_data_and_idle_after() {
    use tdongle_tailnet_runtime::derp::{WIN_ENABLED, WIN_STATS, WIN_TIMING};
    WIN_ENABLED.store(true, Ordering::Relaxed);
    let mut go = go_or_skip!();
    let (gw, _id, alias) = up(&mut go, "gopeer");
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    assert_eq!(gw.host.echo(alias, 7, b"warm", Duration::from_secs(30)).unwrap(), b"warm");
    // windows of 500 ms, big at 20 frames in one, idle again after 3 quiet ones
    WIN_TIMING[0].store(500, Ordering::Relaxed);
    WIN_TIMING[1].store(20, Ordering::Relaxed);
    WIN_TIMING[2].store(3, Ordering::Relaxed);
    // a relay at about 2.8 Mbit/s (4 ms per frame) so that a transfer lasts seconds, as on the board
    gw.net.derp_write_delay_ms.store(4, Ordering::Relaxed);
    let to_big0 = WIN_STATS[0].load(Ordering::Relaxed);
    let (n, _) = gw.host.get_bytes(alias, 80, 1024 * 1024, Duration::from_secs(60)).expect("a transfer over the relay");
    assert_eq!(n, 1024 * 1024);
    let (n, _) = gw.host.upload(alias, 9, 256 * 1024, Duration::from_secs(60)).expect("and the other way, across the reconnect");
    assert_eq!(n, 256 * 1024);
    gw.net.derp_write_delay_ms.store(0, Ordering::Relaxed);
    // busy all along: the big windows were wanted but waited for a lull (a reconnect in the middle of a transfer is not worth it), and came with the first one
    assert!(WIN_STATS[4].load(Ordering::Relaxed) > 0, "the switch waited for a lull while the transfer ran");
    wait_until("the windows to go big at the lull", 15, || WIN_STATS[0].load(Ordering::Relaxed) > to_big0);
    wait_until("the windows to go back to idle", 30, || WIN_STATS[3].load(Ordering::Relaxed) == 0);
    assert_eq!(gw.host.echo(alias, 7, b"after", Duration::from_secs(30)).unwrap(), b"after", "the relay still works on the idle windows");
    WIN_ENABLED.store(false, Ordering::Relaxed);
    gw.check_engine();
}

/// The board's supervisor resets the chip when the thread executor makes no progress for 8 s. Window switches (reconnects of the relay connection) under load, with the host
/// holding a bulk upload at a paced relay: a heartbeat task on the runtime's thread (one tick per 50 ms) must never go quiet for a second, and the transfers complete.
#[test]
fn window_switches_under_relay_load_do_not_starve_the_executor() {
    use std::sync::atomic::Ordering::Relaxed;
    use tdongle_tailnet_runtime::derp::{WIN_ENABLED, WIN_FORCE, WIN_STATS, WIN_TIMING};
    WIN_ENABLED.store(true, Relaxed);
    let mut go = go_or_skip!();
    let (gw, _id, alias) = up(&mut go, "gopeer");
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    assert_eq!(gw.host.echo(alias, 7, b"warm", Duration::from_secs(30)).unwrap(), b"warm");
    // switch as often as the hysteresis allows, in the middle of the transfers: 300 ms windows, a forced switch (`tn force-derp`'s request) every second
    WIN_TIMING[0].store(300, Relaxed);
    WIN_TIMING[1].store(8, Relaxed);
    WIN_TIMING[2].store(1000, Relaxed);
    gw.net.derp_write_delay_ms.store(6, Relaxed);
    let switches0 = WIN_STATS[0].load(Relaxed) + WIN_STATS[1].load(Relaxed);
    let worst = std::thread::scope(|s| {
        let up = s.spawn(|| gw.host.upload(alias, 9, 320 * 1024, Duration::from_secs(25)));
        let down = s.spawn(|| gw.host.get_bytes(alias, 80, 320 * 1024, Duration::from_secs(25)));
        let mut worst = u64::MAX;
        let mut last = gw.heartbeat.load(Relaxed);
        let mut flip = 1u8;
        let mut ticks = 0;
        while !(up.is_finished() && down.is_finished()) {
            std::thread::sleep(Duration::from_millis(500));
            ticks += 1;
            if ticks % 4 == 0 {
                WIN_FORCE.store(flip, Relaxed);
                flip = 3 - flip;
            }
            let now = gw.heartbeat.load(Relaxed);
            worst = worst.min(now - last);
            last = now;
        }
        println!("upload {:?} download {:?}", up.join().unwrap().map(|(n, d)| (n, d.as_secs_f64())), down.join().unwrap().map(|(n, d)| (n, d.as_secs_f64())));
        worst
    });
    let switches = WIN_STATS[0].load(Relaxed) + WIN_STATS[1].load(Relaxed) - switches0;
    println!("window switches during the transfers: {switches}; fewest heartbeat ticks in 500 ms: {worst} (10 expected)");
    assert!(switches >= 1, "the windows switched under load");
    WIN_ENABLED.store(false, Relaxed);
    assert!(worst >= 5, "the executor kept running through the switches: {worst} ticks in the worst 500 ms");
    gw.check_engine();
}

/// Short of heap the USB receive task waits for room: the channel it would wait on has room (nothing was pushed), so waiting on it returns at once, and a loop on that never
/// yielded: the board's thread executor stalled at the heap floor (`previous_op=usb`). `wait_for_frame_room` must yield (a bounded sleep) whatever the channel says: a heartbeat
/// task on the same executor keeps ticking while a loop waits through it with the heap short and a channel that is always ready.
#[test]
fn waiting_for_heap_with_a_channel_that_is_always_ready_yields() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let ticks = rt.block_on(async {
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t2 = ticks.clone();
        let heartbeat = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                t2.fetch_add(1, Ordering::Relaxed);
            }
        });
        let started = std::time::Instant::now();
        let mut rounds = 0u64;
        while started.elapsed() < Duration::from_secs(1) {
            // heap short, channel ready: the old loop's iteration
            tdongle_tailnet_runtime::usb::wait_for_frame_room(false, std::future::ready(())).await;
            rounds += 1;
        }
        heartbeat.abort();
        println!("{rounds} waits in 1 s");
        assert!(rounds < 500, "the wait is a sleep, not a spin: {rounds} rounds");
        ticks.load(Ordering::Relaxed)
    });
    assert!(ticks >= 15, "the executor's heartbeat kept ticking: {ticks} in 1 s (20 expected)");
}

/// The heap pinned near the floor under a USB upload over the relay: every elastic allocation is refused or waits, and none of it may stall the executor (the heartbeat keeps
/// ticking) or panic; the engine counts what it refused.
#[test]
fn a_heap_at_the_floor_under_a_relay_upload_does_not_starve_the_executor() {
    use std::sync::atomic::Ordering::Relaxed;
    let mut go = go_or_skip!();
    let (_, _) = go.peer("gopeer").expect("peer");
    let mut opts = GatewayOpts::new(&go.control_addr);
    opts.heap_free = tdongle_tailnet_admission::heap::ML_HB_FLOOR + 23_500;
    let gw = Gateway::start(opts);
    gw.net.udp_blocked.store(true, Ordering::SeqCst);
    let id = gw.add("lab", "tskey-fake");
    wait_until("the membership to be routing", 60, || gw.is_ready(id));
    gw.host.wait_dhcp(Duration::from_secs(10)).expect("dhcp");
    let alias = gw.host.resolve("gopeer.lab.tailnet", Duration::from_secs(20)).expect("dns");
    let _ = gw.host.echo(alias, 7, b"warm", Duration::from_secs(30));
    gw.net.derp_write_delay_ms.store(6, Relaxed);
    let worst = std::thread::scope(|s| {
        let up = s.spawn(|| gw.host.upload(alias, 9, 256 * 1024, Duration::from_secs(40)));
        let mut worst = u64::MAX;
        let mut last = gw.heartbeat.load(Relaxed);
        while !up.is_finished() {
            std::thread::sleep(Duration::from_millis(500));
            let now = gw.heartbeat.load(Relaxed);
            worst = worst.min(now - last);
            last = now;
        }
        println!("upload at the heap floor: {:?}; pool {:?}", up.join().unwrap().map(|(n, d)| (n, d.as_secs_f64())), gw.sh.pool.stats());
        worst
    });
    println!("fewest heartbeat ticks in 500 ms: {worst} (10 expected)");
    assert!(worst >= 5, "the executor kept running with the heap at the floor: {worst} ticks in the worst 500 ms");
}
