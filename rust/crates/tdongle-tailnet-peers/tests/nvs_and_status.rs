//! The NVS peer cache blob (byte layout of `peer_nvs_entry_t`, LRU, compaction) and the `"wg_pool"` fragment against the C.

use tdongle_tailnet_admission::json::{JsonWriter, SliceSink};
use tdongle_tailnet_peers::arbiter::ArbiterStats;
use tdongle_tailnet_peers::nvs_cache::*;
use tdongle_tailnet_peers::pool::PoolStats;
use tdongle_tailnet_peers::record::{DirRecord, Endpoint};
use tdongle_tailnet_peers::status::{PoolStatus, write_wg_pool};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");

fn rec(i: u32) -> DirRecord {
    let mut r = DirRecord { vpn_ip: 0x6440_0000 + i, derp_region: (i % 9) as u16, endpoint_count: 4, ..DirRecord::default() };
    r.public_key[0] = i as u8;
    r.public_key[1] = (i >> 8) as u8 | 0x40;
    r.disco_key[0] = !(i as u8);
    r.endpoints = [
        Endpoint { ip: 0, port: 1, is_ipv6: false },
        Endpoint { ip: 0x0a00_0001, port: 41641, is_ipv6: true },
        Endpoint { ip: 0x0a00_0002, port: 41642, is_ipv6: false },
        Endpoint { ip: 0x0a00_0003, port: 41643, is_ipv6: false },
        Endpoint::default(),
        Endpoint::default(),
        Endpoint::default(),
        Endpoint::default(),
    ];
    r.hostname.set(&format!("tailscale-{i}.tailnet.ts.net"));
    r.is_exit_node = i.is_multiple_of(2);
    r
}

#[test]
fn blob_layout_matches_the_packed_c_struct() {
    let mut c: PeerCache = PeerCache::new();
    c.save(&SaveInput::from_record(&rec(5)));
    let mut buf = [0u8; PeerCache::<64>::MAX_BLOB_BYTES];
    let n = c.to_blob(&mut buf).unwrap();
    assert_eq!(n, 12 + 118);
    // header: magic "MLPR" (0x4D4C5052) LE, version 3, count 1, lru_clock 1, pad 0
    assert_eq!(&buf[..12], &[0x52, 0x50, 0x4C, 0x4D, 3, 0, 1, 0, 1, 0, 0, 0]);
    // entry, assembled by hand from the C struct (packed): vpn_ip, public_key[32], disco_key[32], derp_region, endpoints[2]{ip,port}, endpoint_count,
    // hostname_short[32], lru_counter, is_exit_node
    let r = rec(5);
    let mut want = Vec::new();
    want.extend_from_slice(&r.vpn_ip.to_le_bytes());
    want.extend_from_slice(&r.public_key);
    want.extend_from_slice(&r.disco_key);
    want.extend_from_slice(&r.derp_region.to_le_bytes());
    want.extend_from_slice(&0x0a00_0002u32.to_le_bytes()); // the first IPv4 endpoint with a non-zero address (endpoint 0 has ip 0, endpoint 1 is IPv6)
    want.extend_from_slice(&41642u16.to_le_bytes());
    want.extend_from_slice(&0x0a00_0003u32.to_le_bytes());
    want.extend_from_slice(&41643u16.to_le_bytes());
    want.push(2);
    let mut name = [0u8; 32];
    name[..11].copy_from_slice(b"tailscale-5");
    want.extend_from_slice(&name);
    want.extend_from_slice(&1u16.to_le_bytes());
    want.push(0); // 5 is odd: not an exit node
    assert_eq!(want.len(), ENTRY_BYTES);
    assert_eq!(&buf[12..n], &want[..]);
    // round trip
    let (back, ok) = PeerCache::<64>::from_blob(&buf[..n]);
    assert!(ok && back.len() == 1);
    let p = back.load_all(8, 77).next().unwrap();
    assert!(p.active && p.meta.online && p.wg_slot.is_none() && p.peer_added_ms == 77);
    assert_eq!((p.vpn_ip, p.public_key, p.meta.hostname.as_str(), p.meta.endpoint_count, p.meta.derp_region), (r.vpn_ip, r.public_key, "tailscale-5", 2, 5));
    assert_eq!((p.meta.endpoints[0].ip, p.meta.endpoints[1].port, p.meta.endpoints[0].is_ipv6), (0x0a00_0002, 41643, false));
}

#[test]
fn save_update_lru_evict_remove_and_discard() {
    let mut c: PeerCache = PeerCache::new();
    for i in 1..=64 {
        assert_eq!(c.save(&SaveInput::from_record(&rec(i))), (i - 1) as usize);
    }
    assert_eq!(c.len(), 64);
    // same IP or same key updates in place (and refreshes its LRU counter)
    let mut again = rec(10);
    again.derp_region = 77;
    assert_eq!(c.save(&SaveInput::from_record(&again)), 9);
    let mut rekeyed = rec(11);
    rekeyed.public_key[5] = 9;
    assert_eq!(c.save(&SaveInput::from_record(&rekeyed)), 10);
    let mut by_key = rec(500);
    by_key.public_key = rec(12).public_key;
    assert_eq!(c.save(&SaveInput::from_record(&by_key)), 11, "matched by key: re-addressed");
    assert_eq!(c.len(), 64);
    // full: the least recently saved goes (entry 0, saved first)
    assert_eq!(c.save(&SaveInput::from_record(&rec(100))), 0);
    assert_eq!(c.entries()[0].vpn_ip, rec(100).vpn_ip);
    assert_eq!(c.save(&SaveInput::from_record(&rec(101))), 1);
    // remove compacts and zeroes the tail
    assert!(c.remove(&rec(3).public_key));
    assert!(!c.remove(&rec(3).public_key));
    assert_eq!(c.len(), 63);
    assert_eq!(c.entries()[2].vpn_ip, rec(4).vpn_ip);
    // hostname: first label, cut at 31 bytes
    let mut long = rec(200);
    long.hostname = tdongle_tailnet_types::FixedStr::new();
    long.hostname.set(&format!("{}.tail.ts.net", "x".repeat(40)));
    let i = c.save(&SaveInput::from_record(&long));
    assert_eq!(c.entries()[i].hostname(), "x".repeat(31));
    // wrong magic / version / count / short blob: discarded
    let mut buf = [0u8; PeerCache::<64>::MAX_BLOB_BYTES];
    let n = c.to_blob(&mut buf).unwrap();
    for mutate in [|b: &mut [u8]| b[0] ^= 1, |b: &mut [u8]| b[4] = 2, |b: &mut [u8]| b[6] = 200] {
        let mut b = buf[..n].to_vec();
        mutate(&mut b);
        let (t, ok) = PeerCache::<64>::from_blob(&b);
        assert!(!ok && t.is_empty());
    }
    assert!(!PeerCache::<64>::from_blob(&buf[..n - 1]).1);
    assert!(!PeerCache::<64>::from_blob(&[]).1);
    assert!(c.to_blob(&mut buf[..n - 1]).is_none());
    let (t, ok) = PeerCache::<64>::from_blob(&buf[..n]);
    assert!(ok && t.len() == 64);
    c.clear();
    assert!(c.is_empty());
}

fn render(p: &PoolStatus) -> String {
    let mut buf = [0u8; 1024];
    let mut w = JsonWriter::new(SliceSink::new(&mut buf));
    write_wg_pool(&mut w, p);
    assert!(!w.failed());
    String::from_utf8(w.sink().written().to_vec()).unwrap()
}

#[test]
fn wg_pool_fragment_matches_the_c() {
    let scen = std::fs::read_to_string(format!("{GOLDEN}/wg_pool.scen")).unwrap();
    let gold = std::fs::read_to_string(format!("{GOLDEN}/wg_pool.golden")).unwrap();
    let mut rest = gold.as_str();
    let mut n = 0;
    for line in scen.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let v: Vec<u32> = f[1..].iter().map(|x| x.parse().unwrap()).collect();
        let p = PoolStatus {
            capacity: v[0],
            used: v[1],
            peak: v[2],
            refused_full: v[3],
            refused_nomem: v[4],
            evictions_own: v[5],
            evictions_other: v[6],
            rejected: v[7],
            refused_largest: v[8],
            refused_heap: v[9],
            largest_low: v[10],
            slot_bytes: v[11],
            device_bytes: v[12],
        };
        let start = rest.find("@@@@ SCENARIO ").unwrap();
        rest = &rest[start + 14..];
        let (label, tail) = rest.split_once(" LEN ").unwrap();
        assert_eq!(label, f[0]);
        let (len, tail) = tail.split_once(" @@@@\n").unwrap();
        let len: usize = len.parse().unwrap();
        assert_eq!(render(&p), tail[..len], "scenario {label}");
        rest = &tail[len..];
        n += 1;
    }
    assert_eq!(n, 33);
}

#[test]
fn pool_status_composes_pool_and_arbiter_counters() {
    let pool = PoolStats {
        capacity: 12,
        used: 5,
        peak_used: 9,
        acquired: 20,
        released: 15,
        refused_full: 2,
        refused_nomem: 1,
        refused_heap: 3,
        refused_largest: 4,
        refused_device_full: 0,
        largest_low: u32::MAX,
        commits_refused: 0,
        rx_commits_refused: 0,
    };
    let arb = ArbiterStats { evictions_own: 6, evictions_other: 7, refused: 8 };
    let s = PoolStatus::compose(&pool, &arb, 1096, 236);
    assert_eq!(
        render(&s),
        "\"wg_pool\":{\"capacity\":12,\"used\":5,\"peak\":9,\"refused_full\":2,\"refused_nomem\":1,\"evictions_own\":6,\"evictions_other\":7,\"rejected\":8,\"refused_largest\":4,\"refused_heap\":3,\"largest_low\":null,\"slot_bytes\":1096,\"device_bytes\":236},"
    );
}
