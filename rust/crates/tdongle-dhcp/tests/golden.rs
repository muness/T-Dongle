//! Replays tests/golden.txt, recorded from the real ESP-IDF v5.5.5 dhcpserver.c by tools/gen_golden.py: every reply must match byte for
//! byte (destination, static ARP entry and the stale request bytes after END included), and the lease list must match after each step.

use tdongle_dhcp::{Config, Dest, Server};

fn ip(s: &str) -> [u8; 4] {
    let mut o = [0u8; 4];
    for (i, p) in s.split('.').enumerate() {
        o[i] = p.parse().unwrap();
    }
    o
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn leases(s: &Server) -> String {
    let mut o = String::from("L");
    for i in 0..s.lease_count() {
        let l = s.lease(i).unwrap();
        o += &format!(" {}.{}.{}.{}={}", l.ip[0], l.ip[1], l.ip[2], l.ip[3], hex(&l.mac));
    }
    o
}

fn config(line: &str) -> Config {
    let f: Vec<&str> = line.split(' ').skip(1).collect();
    let opt = |s: &str| if s == "-" { None } else { Some(ip(s)) };
    Config {
        server_ip: ip(f[0]),
        netmask: ip(f[1]),
        router: opt(f[2]),
        dns: ip(f[3]),
        dns_backup: opt(f[4]),
        pool: opt(f[5]).zip(opt(f[6])),
        lease_secs: f[7].parse::<u32>().unwrap() * 60,
        max_stations: 8,
    }
}

fn replay(start_ms: u32) -> usize {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden.txt")).unwrap();
    let mut lines = text.lines().filter(|l| !l.starts_with('#')).peekable();
    let (mut server, mut now, mut name, mut packets) = (None::<Server>, 0u32, String::new(), 0);
    while let Some(line) = lines.next() {
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "S" => name = w[1].to_string(),
            "CFG" => {
                let s = Server::new(config(line)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
                let pool = lines.next().unwrap();
                let (a, b) = s.pool();
                assert_eq!(pool, format!("POOL {}.{}.{}.{} {}.{}.{}.{}", a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]), "{name}");
                server = Some(s);
                now = start_ms;
            }
            "P" | "T" => {
                let s = server.as_mut().unwrap();
                now = now.wrapping_add(w[1].parse::<u32>().unwrap() * 1000);
                s.expire(now);
                let l = lines.next().unwrap();
                assert_eq!(leases(s), l, "{name}: lease list before step {line:.40}");
                if w[0] == "T" {
                    continue;
                }
                let mut req = unhex(w[3]);
                req.resize(w[2].parse().unwrap(), 0);
                let mut out = [0xA5u8; 1600];
                let r = s.handle(&req, now, &mut out);
                let want: Vec<&str> = lines.next().unwrap().split(' ').collect();
                packets += 1;
                match r {
                    None => assert_eq!(want, ["R", "NONE"], "{name}: expected a reply to {line:.60}"),
                    Some(r) => {
                        assert_ne!(want[1], "NONE", "{name}: unexpected {:?} reply to {line:.60}", r.kind);
                        let (dip, arp_ip, arp_mac) = match r.dest {
                            Dest::Broadcast => ([255; 4], "-".to_string(), "-".to_string()),
                            Dest::Unicast { ip, mac } => (ip, format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), hex(&mac)),
                        };
                        assert_eq!(want[1], format!("{}.{}.{}.{}", dip[0], dip[1], dip[2], dip[3]), "{name}: dest of {line:.60}");
                        assert_eq!(want[2], "68");
                        assert_eq!(want[3].parse::<usize>().unwrap(), r.len, "{name}: length");
                        let mut full = unhex(want[4]);
                        full.resize(r.len, 0);
                        assert_eq!(hex(&out[..r.len]), hex(&full), "{name}: reply bytes for {line:.60}");
                        // Reply::static_arp says whether lwIP installed the temporary static ARP entry.
                        if !r.static_arp {
                            assert_eq!((want[5], want[6]), ("-", "-"), "{name}");
                        } else {
                            assert_eq!((want[5], want[6]), (arp_ip.as_str(), arp_mac.as_str()), "{name}: ARP entry");
                        }
                    }
                }
            }
            _ => panic!("bad golden line {line}"),
        }
    }
    packets
}

#[test]
fn replies_match_real_lwip_dhcpserver() {
    assert!(replay(0) > 500);
}

#[test]
fn clock_wrap_changes_nothing() {
    // The same scripts with the millisecond clock starting just below the wrap and around the signed midpoint.
    replay(0xFFFF_F000);
    replay(0x7FFF_FF00);
    replay(0xFFFF_0000);
}
