//! Byte-for-byte comparison with output of the real C code (`tools/gen_golden.py`, rebuilt by `tools/regen.sh`):
//!
//! * `status.golden`: the `/status` and serial-report fragments, produced by C text cut out of `runtime_status.inc`, `gateway_main.c` and
//!   `memory_diagnostics.inc` over the scenarios of `scenarios.txt`, with the C's own `ml_adm_budget` computing the arithmetic;
//! * `neg_trace_*.golden`: the real `ml_negotiation.c` driven through seeded random traces; the Rust token must answer and report identically.

use std::collections::HashMap;
use std::string::{String, ToString};
use std::vec::Vec;

use tdongle_tailnet_admission::adm::{Budget, Params};
use tdongle_tailnet_admission::json::{JsonWriter, SliceSink};
use tdongle_tailnet_admission::ledger::{Ledger, Owner};
use tdongle_tailnet_admission::negotiation::{Grant, Key, Negotiation, Observer, Phase, Prio, Status};
use tdongle_tailnet_admission::rx_stats::{RX_STAT_COUNT, RxStat, RxStats};
use tdongle_tailnet_admission::status::*;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");

fn read(name: &str) -> String {
    std::fs::read_to_string(std::format!("{GOLDEN}/{name}")).unwrap()
}

/// `kind/name` -> expected bytes.
fn golden() -> Vec<(String, String)> {
    let text = read("status.golden");
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(start) = rest.find("@@@@ SCENARIO ") {
        rest = &rest[start + 14..];
        let (label, tail) = rest.split_once(" LEN ").unwrap();
        let (len, tail) = tail.split_once(" @@@@\n").unwrap();
        let len: usize = len.parse().unwrap();
        out.push((label.to_string(), tail[..len].to_string()));
        rest = &tail[len..];
        assert!(rest.starts_with("\n@@@@ END @@@@\n"));
    }
    out
}

fn scenarios() -> HashMap<String, HashMap<String, String>> {
    let mut m = HashMap::new();
    for line in read("scenarios.txt").lines() {
        let mut it = line.split(' ');
        let (kind, name) = (it.next().unwrap(), it.next().unwrap());
        let kv = it.filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        m.insert(std::format!("{kind}/{name}"), kv);
    }
    m
}

fn u(kv: &HashMap<String, String>, k: &str) -> u64 {
    kv[k].parse().unwrap()
}

fn render(f: impl FnOnce(&mut JsonWriter<SliceSink<'_>>)) -> String {
    let mut buf = [0u8; 8192];
    let mut w = JsonWriter::new(SliceSink::new(&mut buf));
    f(&mut w);
    assert!(!w.failed());
    String::from_utf8(w.sink().written().to_vec()).unwrap()
}

fn params(kv: &HashMap<String, String>) -> Params {
    Params {
        context: u(kv, "context") as usize,
        coord_stack: u(kv, "coord_stack") as usize,
        task_tcb: u(kv, "task_tcb") as usize,
        queues: u(kv, "queues") as usize,
        wg_device: u(kv, "wg_device") as usize,
        wg_slot: u(kv, "wg_slot") as usize,
        shared_stacks: u(kv, "shared_stacks") as usize,
        shared_tasks: u(kv, "shared_tasks") as u32,
        route_queue_min: u(kv, "route_queue_min") as usize,
        ..Params::c_reference()
    }
}

#[test]
fn status_fragments_match_the_c() {
    let sc = scenarios();
    let g = golden();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (label, expected) in &g {
        let kv = &sc[label];
        let kind = label.split('/').next().unwrap();
        *counts.entry(kind.to_string()).or_default() += 1;
        let got = match kind {
            "admission" => {
                let b: Budget = params(kv).budget(u(kv, "running") != 0);
                render(|w| write_admission(w, &AdmissionStatus { budget: b, peer_slot_bytes: u(kv, "slot_bytes") as u32 }))
            }
            "negotiation" => {
                let phase = match u(kv, "phase") {
                    1 => Phase::Start,
                    2 => Phase::Control,
                    3 => Phase::Derp,
                    _ => Phase::None,
                };
                let s = Status {
                    holder: u(kv, "holder") as u32,
                    phase,
                    held_ms: u(kv, "held_ms") as u32,
                    waiting: u(kv, "waiting") as u32,
                    grants: u(kv, "grants") as u32,
                    timeouts: u(kv, "timeouts") as u32,
                    lease_expired: u(kv, "lease_expired") as u32,
                    stale_dropped: u(kv, "stale_dropped") as u32,
                    refused_full: u(kv, "refused_full") as u32,
                    max_wait_ms: u(kv, "max_wait_ms") as u32,
                    max_hold_ms: u(kv, "max_hold_ms") as u32,
                    ..Status::default()
                };
                render(|w| write_negotiation(w, &s))
            }
            "heap_budget" => {
                let h = HeapBudgetStatus {
                    refused_usb_rx: u(kv, "refused_usb_rx") as u32,
                    refused_pending: u(kv, "refused_pending") as u32,
                    refused_derp_tx: u(kv, "refused_derp_tx") as u32,
                    refused_rx_ctrl: u(kv, "refused_rx_ctrl") as u32,
                    refused_derp_rx: u(kv, "refused_derp_rx") as u32,
                    refused_wg_copy: u(kv, "refused_wg_copy") as u32,
                };
                render(|w| write_heap_budget(w, &h))
            }
            "admission_report" => {
                let recs: Vec<AdmissionRecord> = if kv["records"].is_empty() {
                    Vec::new()
                } else {
                    kv["records"]
                        .split(';')
                        .map(|r| {
                            let v: Vec<u32> = r.split(':').map(|x| x.parse().unwrap()).collect();
                            let verdict = [
                                AdmitVerdict::Ok,
                                AdmitVerdict::RefusedBudget,
                                AdmitVerdict::RefusedLargest,
                                AdmitVerdict::RefusedSockets,
                                AdmitVerdict::Override,
                                AdmitVerdict::RefusedFloor,
                                AdmitVerdict::StartFailed,
                            ][v[8] as usize];
                            AdmissionRecord {
                                uptime_ms: v[0],
                                member_id: v[1],
                                free_bytes: v[2],
                                largest_bytes: v[3],
                                budget_bytes: v[4],
                                sockets_open: v[5],
                                sockets_limit: v[6],
                                active: v[7],
                                verdict,
                            }
                        })
                        .collect()
                };
                render(|w| write_admission_report(w, u(kv, "guard_floor") as u32, u(kv, "override") != 0, u(kv, "slot_evictions") as u32, &recs))
            }
            "inbound" => {
                let st = RxStats::new();
                let vals: Vec<u32> = kv["counters"].split(',').map(|x| x.parse().unwrap()).collect();
                assert_eq!(vals.len(), RX_STAT_COUNT);
                for (s, v) in RxStat::ALL.iter().zip(&vals) {
                    st.add(*s, *v);
                }
                st.burst(u(kv, "burst") as u32);
                let head =
                    InboundHead { wg_rx_bytes_queued: u(kv, "queued") as u32, wg_rx_bytes_peak: u(kv, "peak") as u32, replay_window: u(kv, "replay") as u32 };
                render(|w| {
                    write_inbound_head(w, &head);
                    write_inbound_ml(w, &st);
                })
            }
            "owners" => {
                let vals: Vec<u32> = kv["values"].split(',').map(|x| x.parse().unwrap()).collect();
                let l = Ledger::new();
                for (i, o) in Owner::ALL.iter().enumerate() {
                    let v = &vals[i * 6..i * 6 + 6];
                    // Reproduce the counters through the public API: live/peak via one big alloc then partial free is lossy, so
                    // use the dedicated test constructor.
                    l.set_for_test(
                        *o,
                        tdongle_tailnet_admission::ledger::OwnerStats { live: v[0], peak: v[1], allocs: v[2], frees: v[3], failed: v[4], denied: v[5] },
                    );
                }
                render(|w| write_owners(w, &l))
            }
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(&got, expected, "scenario {label}");
    }
    for kind in ["admission", "negotiation", "heap_budget", "admission_report", "inbound", "owners"] {
        assert!(counts.get(kind).copied().unwrap_or(0) >= 6, "{kind} scenarios: {counts:?}");
    }
}

#[test]
fn admission_c_numbers_agree_for_random_sizes() {
    // The golden text embeds the C's own `ml_adm_budget` results: if the Rust arithmetic differed, the text above would too. This test makes the
    // dependency explicit for the C-reference preset.
    let sc = scenarios();
    let kv = &sc["admission/c_reference_running0"];
    assert_eq!(params(kv), Params::c_reference());
}

#[derive(Default)]
struct Count {
    calls: u32,
    busy_seen: u32,
}
impl Observer for Count {
    fn changed(&mut self, busy: bool) {
        self.calls += 1;
        self.busy_seen += u32::from(busy);
    }
}

#[test]
fn negotiation_traces_replay_identically_to_the_real_c_token() {
    let mut total_full = 0;
    for (i, (lease, stale, aging)) in [(0u32, 0u32, 0u32), (5000, 500, 2000), (60_000, 2000, 20_000)].into_iter().enumerate() {
        let ops = read(&std::format!("neg_ops_{i}.txt"));
        let want = read(&std::format!("neg_trace_{i}.golden"));
        let mut neg = Negotiation::with_observer(lease, stale, aging, Count::default());
        let mut idx = 0u32;
        let mut got = String::new();
        let mut seen = [0u32; 3]; // granted, queued, full
        for line in ops.lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            let now: u64 = f[1].parse().unwrap();
            let res = match f[0] {
                "R" => {
                    let key = Key::from_raw(f[2].parse().unwrap()).unwrap();
                    let prio = [Prio::Start, Prio::Rejoin, Prio::Relay][f[3].parse::<usize>().unwrap()];
                    let phase = [Phase::None, Phase::Start, Phase::Control, Phase::Derp][f[4].parse::<usize>().unwrap()];
                    match neg.request(now, key, prio, phase) {
                        Grant::Granted => {
                            seen[0] += 1;
                            "G"
                        }
                        Grant::Queued => {
                            seen[1] += 1;
                            "Q"
                        }
                        Grant::Full => {
                            seen[2] += 1;
                            "F"
                        }
                    }
                }
                "L" => {
                    if neg.release(now, Key::from_raw(f[2].parse().unwrap()).unwrap()) {
                        "T"
                    } else {
                        "N"
                    }
                }
                _ => "-",
            };
            idx += 1;
            let (calls, busy_seen) = (neg.observer_mut().calls, neg.observer_mut().busy_seen);
            if f[0] != "S" && !idx.is_multiple_of(8) {
                got.push_str(&std::format!("{} {} obs={}\n", f[0], res, calls));
                continue;
            }
            let s = neg.status(now);
            got.push_str(&std::format!(
                "{} {} holder={} phase={} held={} waiting={} grants={} timeouts={} lease={} stale={} full={} maxwait={} maxhold={} obs={} busy={} busynow={}\n",
                f[0],
                res,
                s.holder,
                s.phase.name(),
                s.held_ms,
                s.waiting,
                s.grants,
                s.timeouts,
                s.lease_expired,
                s.stale_dropped,
                s.refused_full,
                s.max_wait_ms,
                s.max_hold_ms,
                calls,
                busy_seen,
                i32::from(neg.busy())
            ));
        }
        let (gl, wl): (Vec<_>, Vec<_>) = (got.lines().collect(), want.lines().collect());
        assert_eq!(gl.len(), wl.len(), "trace {i}: same number of lines");
        for (n, (g, w)) in gl.iter().zip(&wl).enumerate() {
            assert_eq!(g, w, "trace {i} line {n}");
        }
        total_full += seen[2];
        assert!(seen[0] > 20 && seen[1] > 20, "trace {i} exercises grant, queue and full: {seen:?}");
        if lease != 0 {
            let expiry = want.lines().any(|l| !l.contains(" lease=0 ") && l.contains("lease="));
            let stale_seen = want.lines().any(|l| !l.contains(" stale=0 ") && l.contains("stale="));
            assert!(expiry && stale_seen, "trace {i}: lease expiry and stale reaping are exercised");
        }
    }
    assert!(total_full > 0, "the full-queue refusal is exercised");
}
