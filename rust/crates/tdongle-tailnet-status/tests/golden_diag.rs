//! The diagnostics-image reports and `gateway_memory_command` against the real C (tests/golden/diag.jsonl: the real report_* functions cut out of
//! memory_diagnostics.inc, behind stubs, by tools/gen_golden.py). Every sink chunk (a `mgmt_write` call) must match.

use serde_json::Value;
use tdongle_tailnet_status::JsonWriter;
use tdongle_tailnet_status::diag::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn kv(sc: &Value, n: &str) -> u32 {
    sc["k"][n].as_u64().unwrap_or_else(|| panic!("k.{n}")) as u32
}
fn ka(sc: &Value, n: &str, i: usize) -> u32 {
    sc["k"][n][i].as_u64().unwrap() as u32
}
fn u32s<const N: usize>(v: &Value) -> [u32; N] {
    let mut out = [0u32; N];
    for (i, x) in v.as_array().unwrap().iter().take(N).enumerate() {
        out[i] = x.as_u64().unwrap() as u32;
    }
    out
}
/// `esp_timer_get_time()` of the harness: the scenario's next value (it counts calls across a whole command).
fn tick(sc: &Value, clock: &std::cell::Cell<usize>) -> u64 {
    let i = clock.get();
    clock.set(i + 1);
    sc["timer"][i.min(7)].as_u64().unwrap()
}

fn with_writer(f: impl FnOnce(&mut JsonWriter<'_>)) -> Vec<String> {
    let mut parts = vec![];
    let mut sink = |c: &[u8]| {
        assert!(c.len() <= 256);
        parts.push(hex(c));
        true
    };
    let mut w = JsonWriter::new(&mut sink);
    f(&mut w);
    parts
}

fn run_report(kind: &str, sc: &Value, lwip: bool, clock: &std::cell::Cell<usize>, marks: &mut Vec<String>) -> Vec<String> {
    let firmware = unhex(sc["firmware"].as_str().unwrap());
    with_writer(|w| match kind {
        "heap" => {
            let mut owners = [OwnerStats::default(); 8];
            for (i, o) in owners.iter_mut().enumerate() {
                *o = OwnerStats {
                    live: ka(sc, "owner_live", i),
                    peak: ka(sc, "owner_peak", i),
                    allocs: ka(sc, "owner_allocs", i),
                    frees: ka(sc, "owner_frees", i),
                    failed: ka(sc, "owner_failed", i),
                    denied: ka(sc, "owner_denied", i),
                };
            }
            write_heap(
                w,
                &Heap {
                    uptime_ms: tick(sc, clock) / 1000,
                    firmware: &firmware,
                    free: kv(sc, "heap_free").into(),
                    min: kv(sc, "heap_min").into(),
                    largest: kv(sc, "heap_largest").into(),
                    total: kv(sc, "heap_total").into(),
                    guard_floor: kv(sc, "guard_floor").into(),
                    underflows: kv(sc, "underflows").into(),
                    ledger_bytes: kv(sc, "ledger_bytes").into(),
                    derp_tx_depth: kv(sc, "q_derp_tx").into(),
                    disco_rx_depth: kv(sc, "q_disco_rx").into(),
                    wg_rx_depth: kv(sc, "q_wg_rx").into(),
                    stun_rx_depth: kv(sc, "q_stun_rx").into(),
                    owners,
                    drops: u32s(&sc["k"]["drops"]),
                },
            );
        }
        "attribution" => {
            let sn = &sc["snapshot"];
            let members: Vec<AttributionMember> = sn["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| AttributionMember {
                    id: m["id"].as_u64().unwrap() as u32,
                    tasks: m["tasks"].as_u64().unwrap() as u32,
                    stacks: m["stacks"].as_u64().unwrap() as u32,
                    tcbs: m["tcbs"].as_u64().unwrap() as u32,
                    h2_acc: m["h2_acc"].as_u64().unwrap() as u32,
                    stack_free: u32s(&m["stack_free"]),
                    lp_acc: m["lp_acc"].as_bool().unwrap(),
                })
                .collect();
            let tagged: u64 = (0..8).map(|i| u64::from(ka(sc, "owner_live", i))).sum();
            write_attribution(
                w,
                &Attribution {
                    busy: sn["busy"].as_bool().unwrap(),
                    members: &members,
                    omitted: sn["omitted"].as_u64().unwrap() as u32,
                    tagged,
                    shared_running: kv(sc, "rt_running") != 0,
                    shared_stack_bytes: u32s(&sc["k"]["rt_stack_bytes"]),
                    task_tcb_bytes: 336,
                    member_queue_bytes: kv(sc, "member_queue_bytes"),
                    heap_total: kv(sc, "heap_total"),
                    heap_free: kv(sc, "heap_free"),
                    lp_acc_capacity: kv(sc, "json_buffer"),
                    h2_window_advertised: kv(sc, "h2_buffer"),
                    gateway_plain_static: kv(sc, "plain_bytes"),
                    gateway_json_static: kv(sc, "json_bytes"),
                },
            );
        }
        "lwip" => write_lwip(
            w,
            &Lwip {
                tcp_wnd: kv(sc, "TCP_WND"),
                tcp_snd_buf: kv(sc, "TCP_SND_BUF"),
                tcp_mss: kv(sc, "TCP_MSS"),
                tcp_snd_queuelen: kv(sc, "TCP_SND_QUEUELEN"),
                wnd_scale: kv(sc, "LWIP_WND_SCALE"),
                pbuf_pool_size: kv(sc, "PBUF_POOL_SIZE"),
                pbuf_pool_bufsize: kv(sc, "PBUF_POOL_BUFSIZE"),
                memp_tcp_pcb: kv(sc, "MEMP_NUM_TCP_PCB"),
                memp_tcp_seg: kv(sc, "MEMP_NUM_TCP_SEG"),
                max_sockets: kv(sc, "max_sockets"),
                tcp_recvmbox: kv(sc, "tcp_recvmbox"),
                udp_recvmbox: kv(sc, "udp_recvmbox"),
                tcpip_recvmbox: kv(sc, "tcpip_recvmbox"),
                wifi_static_rx: kv(sc, "wifi_static_rx"),
                wifi_dynamic_rx: kv(sc, "wifi_dynamic_rx"),
                wifi_dynamic_tx: kv(sc, "wifi_dynamic_tx"),
            },
        ),
        "usb" => {
            let t = |i: usize| ka(sc, "usb_tx", i);
            let tx = UsbTx {
                ring_bytes: t(0),
                base_bytes: t(1),
                max_bytes: t(2),
                elastic_held_bytes: t(3),
                chunks: t(4),
                grow_events: t(5),
                shrink_events: t(6),
                reclaim_events: t(7),
                reclaimed_chunks: t(8),
                grow_denied_gate: t(9),
                grow_denied_heap: t(10),
                grow_denied_largest: t(11),
                grow_denied_nomem: t(12),
                grow_raced: t(13),
                high_water_bytes: t(14),
                high_water_slabs: t(15),
                pm_acquired: t(16),
                pm_released: t(17),
                pm_held: t(18),
                enqueued_frames: t(19),
                enqueued_bytes: t(20),
                sent_frames: t(21),
                sent_bytes: t(22),
                dropped_full: t(23),
                dropped_link_down: t(24),
                dropped_invalid: t(25),
                flushed_link_down: t(26),
                ntb_blocked: t(27),
                xfer_events: t(28),
                worker_stack_free: t(29),
                ntb_xfers: t(30),
                ntb_zlp: t(31),
                ntb_bytes: t(32),
                ntb_max_bytes: t(33),
                drains_sent: u32s(&sc["k"]["usb_drains"]),
                gap_hist: u32s(&sc["k"]["usb_gap_hist"]),
                gap_count: kv(sc, "gap_count"),
                gap_us_sum: kv(sc, "gap_us_sum"),
                gap_us_max: kv(sc, "gap_us_max"),
                cold_starts: kv(sc, "cold_starts"),
                cold_us_sum: kv(sc, "cold_us_sum"),
                cold_us_max: kv(sc, "cold_us_max"),
                worker_demotions: kv(sc, "worker_demotions"),
            };
            let rx = UsbRx {
                tx_ntb_count: kv(sc, "ntb_count"),
                inflight_max: kv(sc, "rx_inflight_max"),
                inflight: kv(sc, "rx_inflight"),
                high_water: kv(sc, "rx_high_water"),
                dropped_busy: kv(sc, "rx_dropped_busy"),
                dropped_nomem: kv(sc, "rx_dropped_nomem"),
                dropped_heap: kv(sc, "rx_dropped_heap"),
                dropped_invalid: kv(sc, "rx_dropped_invalid"),
            };
            write_usb(w, &tx, &rx);
        }
        "locks" => {
            let mut sites = [LockStats::default(); 5];
            for (i, s) in sites.iter_mut().enumerate() {
                let a = &sc["locks"][i];
                *s = LockStats {
                    count: a[0].as_u64().unwrap() as u32,
                    max_us: a[1].as_u64().unwrap() as u32,
                    over_1ms: a[2].as_u64().unwrap() as u32,
                    total_us: a[3].as_u64().unwrap(),
                    bucket: [0; 9],
                };
                for b in 0..9 {
                    s.bucket[b] = a[4 + b].as_u64().unwrap() as u32;
                }
            }
            write_locks(w, &sites);
        }
        "route" => write_route(w, &u32s(&sc["k"]["route_stats"])),
        "phases" => {
            let slots: Vec<MemberPhases> = sc["phases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    let mut phase = [PhaseRecord::default(); 7];
                    for (p, r) in phase.iter_mut().enumerate() {
                        let j = &m["phase"][p];
                        *r = PhaseRecord {
                            valid: j["valid"].as_u64().unwrap() != 0,
                            uptime_ms: j["t"].as_u64().unwrap() as u32,
                            free_bytes: j["free"].as_u64().unwrap() as u32,
                            minimum_bytes: j["min"].as_u64().unwrap() as u32,
                            largest_bytes: j["largest"].as_u64().unwrap() as u32,
                            exact: j["exact"].as_u64().unwrap() != 0,
                            owner_peak: u32s(&j["peak"]),
                        };
                    }
                    MemberPhases { member_id: m["member"].as_u64().unwrap() as u32, attempt: m["attempt"].as_u64().unwrap() as u32, phase }
                })
                .collect();
            write_phases(w, &slots);
        }
        "admission" => {
            let attempts: Vec<AdmissionRecord> = sc["admissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    let v: [u32; 9] = u32s(a);
                    AdmissionRecord {
                        uptime_ms: v[0],
                        member_id: v[1],
                        free_bytes: v[2],
                        largest_bytes: v[3],
                        budget_bytes: v[4],
                        sockets_open: v[5],
                        sockets_limit: v[6],
                        active: v[7],
                        verdict: v[8],
                    }
                })
                .collect();
            write_admission(w, kv(sc, "guard_floor"), false, kv(sc, "slot_evictions"), &attempts);
        }
        "inbound" => {
            let names: Vec<String> = sc["wg_names"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect();
            let wgv: [u32; 5] = u32s(&sc["k"]["wg_values"]);
            let wg: Vec<(&str, u32)> = names.iter().map(String::as_str).zip(wgv).collect();
            let i = Inbound {
                udp_recvmbox: kv(sc, "udp_recvmbox"),
                drain_cap: kv(sc, "drain_cap"),
                wg_rx_queue_depth: kv(sc, "q_wg_rx"),
                wg_rx_queue_bytes: kv(sc, "wg_rx_queue_bytes"),
                wg_rx_bytes_queued: kv(sc, "wg_rx_bytes_queued"),
                wg_rx_bytes_peak: kv(sc, "wg_rx_bytes_peak"),
                wg_rx_batch: kv(sc, "wg_rx_batch"),
                replay_window: kv(sc, "replay_window"),
                lwip: if lwip { Some((16, 0, 0, 0, 0)) } else { None },
                ml: u32s(&sc["k"]["ml_values"]),
                drain_burst_max: kv(sc, "drain_burst_max"),
                wg: &wg,
                route: INBOUND_ROUTE_REASONS.map(|r| ka(sc, "route_stats", r)),
            };
            write_inbound(w, &i);
        }
        "wgperf" => {
            let mut stages = [WgPerfSample::default(); 29];
            for (i, s) in stages.iter_mut().enumerate() {
                let e = &sc["wgperf"][i];
                *s = WgPerfSample { count: e[0].as_u64().unwrap() as u32, total: e[1].as_u64().unwrap(), max: e[2].as_u64().unwrap() as u32 };
            }
            write_wgperf(w, kv(sc, "cpu_mhz"), wgperf_elapsed_ms(tick(sc, clock), kv(sc, "since_us")), &stages, &u32s(&sc["k"]["wgperf_counters"]));
        }
        "cpu" => {
            let existing = kv(sc, "tasks_existing");
            let names: Vec<Vec<u8>> = sc["tasks"].as_array().unwrap().iter().map(|t| unhex(t[0].as_str().unwrap())).collect();
            let tasks: Vec<CpuTask<'_>> = sc["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&names)
                .map(|(t, n)| CpuTask {
                    name: n,
                    runtime: t[1].as_u64().unwrap() as u32,
                    priority: t[2].as_u64().unwrap() as u32,
                    core: t[3].as_i64().unwrap() as i32,
                    stack_free: t[4].as_u64().unwrap() as u32,
                })
                .collect();
            let total = if existing as usize <= CPU_REPORT_TASKS { kv(sc, "cpu_total") } else { 0 };
            write_cpu(w, tick(sc, clock) / 1000, kv(sc, "cpu_mhz"), total, 2, existing, &tasks);
        }
        "bench" => {
            let crypto = if kv(sc, "crypto_ok") != 0 { Some((kv(sc, "aead_ns"), kv(sc, "copy_ns"))) } else { None };
            let (t0, t1, t2, t3) = (tick(sc, clock), tick(sc, clock), tick(sc, clock), tick(sc, clock));
            write_bench(w, &Bench { plain_us: t1.wrapping_sub(t0), tagged_us: t3.wrapping_sub(t2), crypto });
        }
        "logbench" => write_logbench(w, kv(sc, "logbench_ok") != 0, kv(sc, "cycles_per_line")),
        "bridge" => {
            let rows: Vec<(String, String, i64)> = sc["bridge"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (r[0].as_str().unwrap().into(), r[1].as_str().unwrap().into(), r[2].as_i64().unwrap_or_else(|| r[2].as_u64().unwrap() as i64)))
                .collect();
            let rows: Vec<(&str, &str, i64)> = rows.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), *c)).collect();
            write_bridge(w, sc["bridge_active"].as_bool().unwrap(), &rows);
        }
        "wifi_link" => write_wifi_link(w, (tick(sc, clock) / 1000) as u32, sc["link"].as_str().map(unhex).as_deref()),
        "wifi_reset" => write_wifi_reset(w, (tick(sc, clock) / 1000) as u32, kv(sc, "lwip_reset") != 0),
        "wifi_dump" => write_wifi_dump(w, (tick(sc, clock) / 1000) as u32, kv(sc, "wifi_dump_err")),
        "lwip_stats" => {
            let up = (tick(sc, clock) / 1000) as u32;
            write_lwip_stats(w, up, if lwip { Some(16) } else { None });
            if lwip {
                marks.push(format!("@ws_proto udp 16 {up}"));
            }
        }
        "heap_low" => {
            let mut ring = HeapLow::new();
            let floor = kv(sc, "hb_floor");
            for n in sc["notes"].as_array().unwrap() {
                let v: [u32; 12] = u32s(n);
                let rec = HeapLowRecord {
                    uptime_ms: v[0],
                    min_free: v[1],
                    free_now: v[2],
                    free_hi: v[3],
                    largest: v[4],
                    tx_ring_bytes: v[5],
                    tx_elastic_bytes: v[6],
                    wgq_bytes: v[7],
                    rx_inflight: v[8],
                    packet_live: v[9],
                    wifi_rx_pins: v[10],
                    wifi_tx_inflight: v[11],
                };
                marks.push(format!("@note {}", u8::from(ring.note(&rec, floor))));
            }
            ring.write_report(w, floor, kv(sc, "hb_reserve"));
        }
        other => panic!("{other}"),
    })
}

#[test]
fn reports_and_commands_match_the_c() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/diag.jsonl")).unwrap();
    let mut commands = 0;
    for (n, line) in text.lines().enumerate() {
        let case: Value = serde_json::from_str(line).unwrap();
        let sc = &case["scenario"];
        let lwip = case["lwip"].as_bool().unwrap();
        let cmd = unhex(sc["command"].as_str().unwrap());
        let clock = std::cell::Cell::new(0usize);
        let mut marks: Vec<String> = vec![];
        let mut parts: Vec<String> = vec![];
        let ret;
        if cmd.first() == Some(&b'@') {
            parts = run_report(std::str::from_utf8(&cmd[1..]).unwrap(), sc, lwip, &clock, &mut marks);
            ret = true;
        } else {
            commands += 1;
            let run = |kinds: &[&str], parts: &mut Vec<String>, marks: &mut Vec<String>| {
                for k in kinds {
                    parts.extend(run_report(k, sc, lwip, &clock, marks));
                }
            };
            ret = match Command::parse(&cmd) {
                None => false,
                Some(c) => {
                    match c {
                        Command::Memory => run(&["heap", "attribution", "lwip", "usb"], &mut parts, &mut marks),
                        Command::Bridge => run(&["bridge"], &mut parts, &mut marks),
                        Command::BridgeTune => marks.push(format!("@bridgetune[{}]", String::from_utf8_lossy(&cmd[10..]))),
                        Command::MemoryLow => run(&["heap_low"], &mut parts, &mut marks),
                        Command::WifiStats => run(&["wifi_link", "lwip_stats"], &mut parts, &mut marks),
                        Command::WifiStatsReset => run(&["wifi_reset"], &mut parts, &mut marks),
                        Command::WifiStatsDump => run(&["wifi_dump"], &mut parts, &mut marks),
                        Command::Cpu => run(&["cpu"], &mut parts, &mut marks),
                        Command::WgPerf => run(&["wgperf"], &mut parts, &mut marks),
                        Command::WgPerfReset => {
                            marks.push("@wgperf_reset".into());
                            parts.extend(with_writer(write_wgperf_reset));
                        }
                        Command::WgPerfLogbench => run(&["logbench"], &mut parts, &mut marks),
                        Command::Route => run(&["route"], &mut parts, &mut marks),
                        Command::Inbound => run(&["inbound"], &mut parts, &mut marks),
                        Command::Members => run(&["phases", "admission"], &mut parts, &mut marks),
                        Command::Locks => run(&["locks"], &mut parts, &mut marks),
                        Command::Bench => run(&["bench"], &mut parts, &mut marks),
                        Command::Guard(bytes) => {
                            marks.push(format!("@guard {bytes}"));
                            parts.extend(with_writer(|w| write_guard(w, kv(sc, "guard_floor"))));
                        }
                        Command::GuardUsage => parts.push(hex(GUARD_USAGE.as_bytes())),
                    }
                    true
                }
            };
        }
        marks.push(format!("@ret {}", u8::from(ret)));
        let want_parts: Vec<&str> = case["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
        let want_marks: Vec<&str> = case["marks"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
        assert_eq!(parts, want_parts, "case {n} ({}): output", String::from_utf8_lossy(&cmd));
        assert_eq!(marks, want_marks, "case {n} ({}): marks", String::from_utf8_lossy(&cmd));
    }
    assert!(commands >= 35);
}
