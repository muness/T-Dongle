//! The MapResponse projector on arbitrary bytes: never panics, ends every map with exactly one Commit or Abort, respects its bounds, and does not depend on
//! how the bytes are chunked.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_map::project::{MapConfig, MapEvent, MapProjector, MapSink, SinkError};

#[derive(Default)]
struct Check {
    hash: u64,
    events: u32,
    peers: u32,
    commits: u32,
    aborts: u32,
    last: u8,
}

impl Check {
    fn mix(&mut self, v: u64) {
        self.hash = (self.hash ^ v).wrapping_mul(0x100_0000_01b3);
    }
}

impl MapSink for Check {
    fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
        assert!(self.commits + self.aborts == 0, "event after the end of the map");
        self.events += 1;
        match e {
            MapEvent::Peer(p) => {
                self.peers += 1;
                assert!(p.endpoint_count as usize <= 8 && p.route_count as usize <= 8 && p.name.len() <= 63);
                self.mix(p.node_id.unwrap_or(u64::MAX) ^ ((p.vpn_ip as u64) << 32) ^ p.endpoint_count as u64 ^ ((p.group as u64) << 8) ^ ((p.action as u64) << 16));
                for b in p.name.as_str().bytes() {
                    self.mix(b as u64);
                }
                self.last = 1;
            }
            MapEvent::Derp(d) => {
                assert!(d.count as usize <= 4);
                for r in d.region_list() {
                    assert!(r.node_count as usize <= 2);
                    self.mix(r.region_id as u64);
                }
                self.last = 2;
            }
            MapEvent::SelfNode(n) => {
                self.mix(n.vpn_ip.unwrap_or(0) as u64 ^ n.node_id.unwrap_or(0));
                self.last = 3;
            }
            MapEvent::Commit(s) => {
                self.commits += 1;
                self.mix(s.section_entries.iter().map(|v| *v as u64).sum::<u64>() ^ s.stats.projected_bytes as u64);
            }
            MapEvent::Abort(err) => {
                self.aborts += 1;
                self.mix(err.code() as u64);
            }
            _ => self.last = 4,
        }
        Ok(())
    }
}

fn run(cfg: MapConfig, pieces: &[&[u8]]) -> Check {
    let mut p = MapProjector::new(cfg);
    let mut c = Check::default();
    for piece in pieces {
        if p.feed(piece, &mut c).is_err() {
            break;
        }
    }
    if p.failure().is_none() {
        let _ = p.finish(&mut c);
    }
    assert_eq!(c.commits + c.aborts, 1, "exactly one Commit or Abort");
    if c.aborts == 1 {
        assert!(p.failure().is_some());
    }
    c
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, doc)) = data.split_first() else { return };
    let mut cfg = MapConfig::new(1 + (sel >> 4) as u16);
    if sel & 1 == 1 {
        cfg = cfg.with_flash_directory();
    }
    let whole = run(cfg, &[doc]);
    let cut = if doc.is_empty() { 0 } else { ((sel >> 1) as usize & 7) * doc.len() / 8 };
    let split = run(cfg, &[&doc[..cut], &doc[cut..]]);
    assert_eq!((whole.hash, whole.events, whole.peers, whole.commits), (split.hash, split.events, split.peers, split.commits));
    let singles: Vec<&[u8]> = doc.chunks(1).collect();
    let one = run(cfg, &singles);
    assert_eq!((whole.hash, whole.events, whole.peers, whole.commits), (one.hash, one.events, one.peers, one.commits));
});
