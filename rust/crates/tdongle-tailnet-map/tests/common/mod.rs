//! Test support: a recording sink, a model peer directory that follows the C's commit algorithm, JSON builders.
#![allow(dead_code)]

use tdongle_tailnet_map::directory::{commit_pass, is_effective, is_storable, merge_update, same_peer};
use tdongle_tailnet_map::project::*;
use tdongle_tailnet_map::*;

/// Everything a map produced.
#[derive(Default, Debug, Clone)]
pub struct Rec {
    pub staged: Vec<PeerRecord>,
    pub seen: Vec<(u64, bool)>,
    pub self_node: Option<SelfNode>,
    pub derp: Option<DerpMap>,
    pub derp_index: Option<tdongle_tailnet_map::types::DerpIndex>,
    pub dns: Option<DnsConfig>,
    pub domain: Option<String>,
    pub control_time: Option<(i64, u32)>,
    pub collect: Option<bool>,
    pub keep_alive: bool,
    pub summary: Option<MapSummary>,
    pub aborted: Option<MapError>,
    pub order: Vec<&'static str>,
    pub refuse_stage_at: Option<usize>,
    pub refuse_commit: bool,
}

impl MapSink for Rec {
    fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
        match e {
            MapEvent::Peer(p) => {
                if self.refuse_stage_at == Some(self.staged.len()) {
                    return Err(SinkError);
                }
                self.order.push("peer");
                self.staged.push(p.clone());
            }
            MapEvent::PeerSeen { node_id, seen } => {
                self.order.push("seen");
                self.seen.push((node_id, seen));
            }
            MapEvent::SelfNode(n) => {
                self.order.push("self");
                self.self_node = Some(n.clone());
            }
            MapEvent::Derp(d) => {
                self.order.push("derp");
                self.derp = Some(d.clone());
            }
            MapEvent::DerpRegion { first, region_id, port, host, cert } => {
                let ix = self.derp_index.get_or_insert_with(tdongle_tailnet_map::types::DerpIndex::empty);
                if first {
                    ix.clear();
                }
                ix.push(region_id, port, host, *cert);
            }
            MapEvent::Dns(d) => {
                self.order.push("dns");
                self.dns = Some(d.clone());
            }
            MapEvent::Domain(d) => {
                self.order.push("domain");
                self.domain = Some(d.to_string());
            }
            MapEvent::ControlTime { secs, nanos } => {
                self.order.push("time");
                self.control_time = Some((secs, nanos));
            }
            MapEvent::CollectServices(c) => {
                self.order.push("collect");
                self.collect = Some(c);
            }
            MapEvent::KeepAlive => {
                self.order.push("keepalive");
                self.keep_alive = true;
            }
            MapEvent::Commit(s) => {
                if self.refuse_commit {
                    return Err(SinkError);
                }
                self.order.push("commit");
                self.summary = Some(s.clone());
            }
            MapEvent::Abort(e) => {
                self.order.push("abort");
                self.aborted = Some(e);
            }
        }
        Ok(())
    }
}

/// Project `json` fed in `chunk`-byte pieces (0 = whole).
pub fn run_cfg(cfg: MapConfig, json: &[u8], chunk: usize) -> (Result<(), MapError>, Rec, MapStats) {
    let mut rec = Rec::default();
    run_into(cfg, json, chunk, &mut rec)
}

pub fn run_into(cfg: MapConfig, json: &[u8], chunk: usize, rec: &mut Rec) -> (Result<(), MapError>, Rec, MapStats) {
    let mut p = MapProjector::new(cfg);
    let mut result = Ok(());
    let n = if chunk == 0 { json.len().max(1) } else { chunk };
    for c in json.chunks(n) {
        if let Err(e) = p.feed(c, rec) {
            result = Err(e);
            break;
        }
    }
    if result.is_ok() {
        result = p.finish(rec);
    }
    (result, rec.clone(), p.stats().clone())
}

pub fn run(home: u16, json: &str) -> (Result<(), MapError>, Rec, MapStats) {
    run_cfg(MapConfig::new(home), json.as_bytes(), 0)
}

pub fn run_flash(home: u16, json: &str) -> (Result<(), MapError>, Rec, MapStats) {
    run_cfg(MapConfig::new(home).with_flash_directory(), json.as_bytes(), 0)
}

pub fn ok(home: u16, json: &str) -> Rec {
    let (r, rec, _) = run(home, json);
    assert_eq!(r, Ok(()), "{json}");
    assert!(rec.summary.is_some() && rec.aborted.is_none());
    rec
}

pub fn key_hex(b: u8) -> String {
    format!("{:02x}", b).repeat(32)
}

pub fn key(b: u8) -> tdongle_tailnet_types::Key32 {
    tdongle_tailnet_types::Key32([b; 32])
}

/// A model of the C flash directory: ordered slots, `vpn_ip == 0` is empty, the three-pass commit with the authoritative rules.
#[derive(Default, Clone, Debug)]
pub struct Dir {
    pub slots: Vec<PeerRecord>,
    pub generation: u32,
}

fn blank() -> PeerRecord {
    PeerRecord::new(PeerAction::Add, Group::Peers)
}

impl Dir {
    pub fn count(&self) -> usize {
        self.slots.len()
    }
    pub fn find_id(&self, id: u64) -> Option<&PeerRecord> {
        self.slots.iter().find(|r| r.vpn_ip != 0 && r.node_id == Some(id))
    }
    pub fn find_ip(&self, ip: u32) -> Option<&PeerRecord> {
        self.slots.iter().find(|r| r.vpn_ip != 0 && r.vpn_ip == ip)
    }

    fn apply(out: &mut Vec<PeerRecord>, u: &PeerRecord) {
        let mut found = None;
        let mut empty = None;
        for (i, old) in out.iter().enumerate() {
            if !is_storable(old) {
                if empty.is_none() {
                    empty = Some(i);
                }
                continue;
            }
            if same_peer(old, u) {
                found = Some(i);
                break;
            }
        }
        if u.action != PeerAction::Add && found.is_none() {
            return;
        }
        let mut value = u.clone();
        if u.action == PeerAction::Remove {
            value = blank();
        } else if u.action == PeerAction::Patch {
            value = merge_update(&out[found.unwrap()], u);
        }
        value.action = PeerAction::Add;
        match found.or(empty) {
            Some(i) => out[i] = value,
            None => out.push(value),
        }
    }

    /// `ml_directory_commit`: build the next generation from the staged records.
    pub fn commit(&mut self, staged: &[PeerRecord], authoritative: bool) {
        let mut out: Vec<PeerRecord> = if authoritative { vec![] } else { self.slots.iter().filter(|r| is_storable(r)).cloned().collect() };
        for pass in 0..3 {
            for op in staged {
                if !is_effective(op.group, authoritative) {
                    continue;
                }
                if commit_pass(op.action) == pass {
                    if authoritative && op.group == Group::Peers && op.action == PeerAction::Add {
                        out.push(op.clone());
                    } else {
                        Self::apply(&mut out, op);
                    }
                }
            }
        }
        self.slots = out;
        self.generation += 1;
    }

    /// Apply a map's result as the firmware would: only a committed map changes the directory.
    pub fn apply_map(&mut self, rec: &Rec) {
        if let Some(s) = &rec.summary
            && !s.self_expired
            && (!rec.staged.is_empty() || s.authoritative)
        {
            self.commit(&rec.staged, s.authoritative);
        }
    }
}

/// A map with `n` peers `Peers:[...]`, ids 1..=n, address 100.64.(i/256).(i%256).
pub fn many_peers(n: u32) -> String {
    let mut s = String::from("{\"Peers\":[");
    for i in 1..=n {
        if i > 1 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"ID\":{i},\"Key\":\"nodekey:{:064x}\",\"Name\":\"peer-{i}.example.ts.net\",\"Addresses\":[\"100.64.{}.{}/32\"]}}",
            i,
            i / 256,
            i % 256
        ));
    }
    s.push_str("]}");
    s
}
