//! The writer and the whole `/status` body against the real C (tests/golden/*.jsonl, produced by tools/gen_golden.py from json_writer.inc,
//! runtime_status.inc and status() of gateway_main.c): same bytes, same chunk boundaries, same behaviour when the sink fails.

use serde_json::Value;
use tdongle_tailnet_status::glue::{self, ML_MAX_PEERS, PeerQuery};
use tdongle_tailnet_status::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn lines(name: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn json_writer_matches_the_c() {
    for (n, case) in lines("jw.jsonl").iter().enumerate() {
        let fail_at = case["fail_at"].as_u64().unwrap() as usize;
        let mut seen = 0usize;
        let mut chunks: Vec<Vec<u8>> = vec![];
        let mut sink = |b: &[u8]| {
            seen += 1;
            if fail_at != 0 && seen == fail_at {
                return false;
            }
            chunks.push(b.to_vec());
            true
        };
        let mut w = JsonWriter::new(&mut sink);
        let mut results = String::new();
        for op in case["ops"].as_array().unwrap() {
            let op = op.as_str().unwrap();
            let arg = &op[1..];
            let ok = match op.as_bytes()[0] {
                b'r' => w.raw(&unhex(arg)),
                b's' => w.string(&unhex(arg)),
                b'k' => {
                    let k = unhex(arg);
                    let k = &k[..k.iter().position(|&b| b == 0).unwrap_or(k.len())];
                    w.string(k) && w.ch(b':')
                }
                b'n' => w.number(arg.parse().unwrap()),
                b'b' => w.boolean(arg == "1"),
                b'c' => w.ch(u8::from_str_radix(arg, 16).unwrap()),
                b'f' => w.flush(),
                _ => unreachable!(),
            };
            results.push(if ok { '1' } else { '0' });
        }
        assert_eq!(results, case["results"].as_str().unwrap(), "case {n}");
        assert_eq!(u8::from(w.failed()), case["failed"].as_u64().unwrap() as u8, "case {n}");
        let sizes: Vec<u64> = chunks.iter().map(|c| c.len() as u64).collect();
        assert_eq!(sizes, case["chunks"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect::<Vec<_>>(), "case {n}");
        assert_eq!(hex(&chunks.concat()), case["out"].as_str().unwrap(), "case {n}");
    }
}

// ---- /status ----

fn u(v: &Value, k: &str) -> u32 {
    v[k].as_u64().unwrap_or_else(|| panic!("{k}")) as u32
}
fn i(v: &Value, k: &str) -> i32 {
    v[k].as_i64().unwrap() as i32
}
fn b(v: &Value, k: &str) -> bool {
    v[k].as_bool().unwrap()
}
fn t(v: &Value, k: &str) -> Vec<u8> {
    unhex(v[k].as_str().unwrap())
}
fn arr3(v: &Value, k: &str) -> [u32; 3] {
    let a = v[k].as_array().unwrap();
    [a[0].as_u64().unwrap() as u32, a[1].as_u64().unwrap() as u32, a[2].as_u64().unwrap() as u32]
}

struct OwnedClient {
    c: Client<'static>,
    // storage the borrowed fields point into is leaked per test case (tests only)
}

fn leak<T: ?Sized>(b: Box<T>) -> &'static T {
    Box::leak(b)
}
fn bytes(v: Vec<u8>) -> &'static [u8] {
    leak(v.into_boxed_slice())
}

fn client(cj: &Value, member_id: u32, query: &PeerQuery, stack_values: [u32; 5], states: &[Vec<u8>]) -> OwnedClient {
    let peers_json = cj["peers"].as_array().unwrap();
    let count = u(cj, "directory_records");
    let start = query.page_start(member_id);
    let mut peers = vec![];
    let (_, next) = glue::fill_page(count, start, ML_MAX_PEERS, |idx| {
        if (idx as usize) < peers_json.len() {
            let p = &peers_json[idx as usize];
            peers.push(Peer { name: bytes(t(p, "name")), address: u(p, "address") });
            true
        } else {
            false
        }
    });
    let mut diagnostics = [0u32; 21];
    for (n, d) in cj["diagnostics"].as_array().unwrap().iter().enumerate() {
        diagnostics[n] = d.as_u64().unwrap() as u32;
    }
    let last_error = t(cj, "last_error");
    let transport_error = t(cj, "transport_error");
    let c = Client {
        vpn_ip: u(cj, "vpn_ip"),
        dns: bytes(t(cj, "dns")),
        diagnostics,
        stack_free: glue::stack_free(b(cj, "rt_attached"), b(cj, "stop_incomplete"), b(cj, "coord"), stack_values),
        login_url: bytes(t(cj, "auth_url")),
        protocol_error: bytes(glue::protocol_error(&last_error, &transport_error).to_vec()),
        h2_debug: bytes(t(cj, "h2_debug")),
        control_stage: u(cj, "control_stage"),
        derp_tls_verify_failures: u(cj, "derp_tls_verify_failures"),
        derp_tls_deferred: u(cj, "derp_tls_deferred"),
        derp_state: bytes(states[u(cj, "derp_state_index") as usize].clone()),
        frames_rx: u(cj, "frames_rx"),
        frames_tx: u(cj, "frames_tx"),
        record_timeouts: u(cj, "record_timeouts"),
        write_stalls: u(cj, "write_stalls"),
        alloc_drops: u(cj, "alloc_drops"),
        connects: u(cj, "connects"),
        control_key_auth: u(cj, "control_key_auth"),
        jit_hits: u(cj, "jit_hits"),
        jit_misses: u(cj, "jit_misses"),
        jit_evictions: u(cj, "jit_evictions"),
        jit_rejected: u(cj, "jit_rejected"),
        jit_dropped: u(cj, "jit_dropped"),
        directory_records: count,
        next_peer_offset: next,
        peer_page_start: start,
        peers: leak(peers.into_boxed_slice()),
    };
    OwnedClient { c }
}

fn build(sc: &Value, ctx: u64, socket_recovery: u32) -> Status<'static> {
    let query = match &sc["query"] {
        Value::Null => PeerQuery::parse(None),
        q => PeerQuery::parse(Some(&unhex(q.as_str().unwrap()))),
    };
    let sv: Vec<u32> = sc["stack_values"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
    let stack_values = [sv[0], sv[1], sv[2], sv[3], sv[4]];
    let states: Vec<Vec<u8>> = sc["derp_states"].as_array().unwrap().iter().map(|s| unhex(s.as_str().unwrap())).collect();
    let tj = &sc["temperature"];
    let rt = &sc["shared_runtime"];
    let nj = &rt["negotiation"];
    let holder = match nj["holder"].as_i64().unwrap() {
        -1 => None,
        0 => Some(NegPhase::None),
        1 => Some(NegPhase::Start),
        2 => Some(NegPhase::Control),
        _ => Some(NegPhase::Derp),
    };
    let aj = &sc["admission"];
    let pj = &sc["wg_pool"];
    let pw = &sc["power"];
    let locks: Vec<PmLock<'static>> = pw["locks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| PmLock {
            name: bytes(t(l, "name")),
            depth: u(l, "depth"),
            acquires: u(l, "acquires"),
            releases: u(l, "releases"),
            held_us: u(l, "held_us"),
            max_depth: u(l, "max_depth"),
            underflows: u(l, "underflows"),
            forced_releases: u(l, "forced_releases"),
            backend_failures: u(l, "backend_failures"),
            isr_rejects: u(l, "isr_rejects"),
        })
        .collect();
    let kj = &sc["sockets"];
    let cj = &sc["clock"];
    let hb = &sc["heap_budget"];
    let wp = &sc["wifi_pins"];
    let saved: Vec<&'static [u8]> = sc["saved_wifi"].as_array().unwrap().iter().map(|s| bytes(unhex(s.as_str().unwrap()))).collect();
    let members: Vec<Member<'static>> = sc["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let id = u(m, "id");
            let enabled = b(m, "enabled");
            let (state, ready, client) = match &m["client"] {
                Value::Null => (0, false, None),
                c => {
                    let oc = client(c, id, &query, stack_values, &states);
                    let ready = glue::routing_ready(
                        enabled,
                        b(c, "wg_netif"),
                        u(c, "state") == 4,
                        b(c, "key_expired"),
                        t(c, "last_error").first().is_none_or(|&x| x == 0),
                        b(c, "session_valid"),
                    );
                    (u(c, "state"), ready, Some(oc.c))
                }
            };
            Member {
                id,
                start_heap_before: m["start_heap_before"].as_u64().unwrap(),
                start_heap_after: m["start_heap_after"].as_u64().unwrap(),
                label: bytes(t(m, "label")),
                enabled,
                error: bytes(t(m, "error")),
                state,
                routing_ready: ready,
                client,
            }
        })
        .collect();
    Status {
        firmware: bytes(t(sc, "firmware")),
        mode: bytes(t(sc, "mode")),
        chip_temperature: Temperature {
            valid: b(tj, "valid"),
            current_tenths: i(tj, "current"),
            peak_tenths: i(tj, "peak"),
            sampled_at_ms: u(tj, "sampled"),
            samples: u(tj, "samples"),
            changed_at_ms: u(tj, "changed"),
            age_ms: u(tj, "age"),
            errors: u(tj, "errors"),
        },
        recovery: b(sc, "recovery"),
        membership_start_budget: sc["member_start_budget"].as_u64().unwrap(),
        membership_context_bytes: ctx,
        admission: Admission {
            required: u(aj, "required"),
            shared_runtime: u(aj, "shared_runtime"),
            member_start: u(aj, "member_start"),
            member_growth: u(aj, "member_growth"),
            member_steady: u(aj, "member_steady"),
            negotiation: u(aj, "negotiation"),
            recovery: u(aj, "recovery"),
            largest_block: u(aj, "largest_block"),
            peer_slots_charged: u(aj, "peer_slots_charged"),
            peer_slot_bytes: u(aj, "peer_slot_bytes"),
        },
        shared_runtime: SharedRuntime {
            running: b(rt, "running"),
            members: u(rt, "members"),
            starts: u(rt, "starts"),
            stops: u(rt, "stops"),
            attach_failures: u(rt, "attach_failures"),
            detach_failures: u(rt, "detach_failures"),
            stack_bytes: arr3(rt, "stack_bytes"),
            stack_free: arr3(rt, "stack_free"),
            passes: arr3(rt, "passes"),
            max_service_ms: arr3(rt, "max_service_ms"),
            slow_services: arr3(rt, "slow_services"),
            detach_timeouts: arr3(rt, "detach_timeouts"),
            negotiation: Negotiation {
                holder,
                held_ms: u(nj, "held_ms"),
                waiting: u(nj, "waiting"),
                grants: u(nj, "grants"),
                timeouts: u(nj, "timeouts"),
                lease_expired: u(nj, "lease_expired"),
                stale_dropped: u(nj, "stale_dropped"),
                refused_full: u(nj, "refused_full"),
                max_wait_ms: u(nj, "max_wait_ms"),
                max_hold_ms: u(nj, "max_hold_ms"),
            },
        },
        wg_pool: WgPool {
            capacity: u(pj, "capacity"),
            used: u(pj, "used"),
            peak: u(pj, "peak"),
            refused_full: u(pj, "refused_full"),
            refused_nomem: u(pj, "refused_nomem"),
            evictions_own: u(pj, "evictions_own"),
            evictions_other: u(pj, "evictions_other"),
            rejected: u(pj, "rejected"),
            refused_largest: u(pj, "refused_largest"),
            refused_heap: u(pj, "refused_heap"),
            largest_low: u(pj, "largest_low"),
            slot_bytes: u(pj, "slot_bytes"),
            device_bytes: u(pj, "device_bytes"),
        },
        shared_rng: SharedRng {
            users: u(&sc["shared_rng"], "users"),
            bytes_resident: u(&sc["shared_rng"], "bytes_resident"),
            seedings: u(&sc["shared_rng"], "seedings"),
            failures: u(&sc["shared_rng"], "failures"),
        },
        power: Power {
            scaling: b(pw, "scaling"),
            cpu_mhz: u(pw, "cpu_mhz"),
            max_mhz: u(pw, "max_mhz"),
            min_mhz: u(pw, "min_mhz"),
            configure_error: i(pw, "configure_error"),
            lock_create_failures: u(pw, "lock_create_failures"),
            wifi_ps: i(pw, "wifi_ps"),
            locks: leak(locks.into_boxed_slice()),
        },
        sockets: Sockets {
            limit: u(kj, "limit"),
            recovery_reserve: socket_recovery,
            open: u(kj, "open"),
            peak: u(kj, "peak"),
            failures: u(kj, "failures"),
            last_errno: u(kj, "last_errno"),
            last_operation: u(kj, "last_operation"),
            last_at_ms: u(kj, "last_at_ms"),
        },
        reset_reason: u(sc, "reset_reason"),
        wifi: b(sc, "wifi"),
        wifi_link: sc["wifi_link"].as_str().map(|s| bytes(unhex(s))),
        clock: Clock {
            state: bytes(t(cj, "state")),
            valid: b(cj, "valid"),
            sntp_restarts: u(cj, "sntp_restarts"),
            retry_in_ms: u(cj, "retry_in_ms"),
            server: bytes(t(cj, "server")),
        },
        saved_wifi: leak(saved.into_boxed_slice()),
        route_storage_ok: b(sc, "route_storage_ok"),
        free_memory: u(sc, "free_memory"),
        largest_free_block: u(sc, "largest_free_block"),
        minimum_free_memory: u(sc, "minimum_free_memory"),
        heap_budget: HeapBudget {
            floor: u(hb, "floor"),
            reserve: u(hb, "reserve"),
            pin_buffers: u(hb, "pin_buffers"),
            refused_usb_rx: u(hb, "refused_usb_rx"),
            refused_pending: u(hb, "refused_pending"),
            refused_derp_tx: u(hb, "refused_derp_tx"),
            refused_rx_ctrl: u(hb, "refused_rx_ctrl"),
            refused_derp_rx: u(hb, "refused_derp_rx"),
            refused_wg_copy: u(hb, "refused_wg_copy"),
        },
        wifi_pins: WifiPins {
            installed: b(wp, "installed"),
            tx_done_cb: b(wp, "tx_done_cb"),
            rx_hooked: b(wp, "rx_hooked"),
            tx_pool: u(wp, "tx_pool"),
            band_total: u(wp, "band_total"),
            tx_band_max: u(wp, "tx_band_max"),
            rx_band_max: u(wp, "rx_band_max"),
            tx_inflight: u(wp, "tx_inflight"),
            tx_high_water: u(wp, "tx_high_water"),
            tx_charged: u(wp, "tx_charged"),
            tx_done: u(wp, "tx_done"),
            tx_aborted: u(wp, "tx_aborted"),
            tx_flushed: u(wp, "tx_flushed"),
            tx_stale: u(wp, "tx_stale"),
            tx_unmatched: u(wp, "tx_unmatched"),
            tx_band: u(wp, "tx_band"),
            tx_elastic: u(wp, "tx_elastic"),
            tx_refused_pool: u(wp, "tx_refused_pool"),
            tx_refused_heap: u(wp, "tx_refused_heap"),
            rx_inflight: u(wp, "rx_inflight"),
            rx_high_water: u(wp, "rx_high_water"),
            rx_band: u(wp, "rx_band"),
            rx_elastic: u(wp, "rx_elastic"),
            rx_released: u(wp, "rx_released"),
            rx_unmatched: u(wp, "rx_unmatched"),
            rx_dropped: u(wp, "rx_dropped"),
        },
        members: leak(members.into_boxed_slice()),
    }
}

#[test]
fn status_body_and_chunks_match_the_c() {
    let mut with_peers = 0;
    let mut with_query = 0;
    for (n, case) in lines("status.jsonl").iter().enumerate() {
        let sc = &case["scenario"];
        let st = build(sc, case["const"]["context_bytes"].as_u64().unwrap(), case["const"]["socket_recovery"].as_u64().unwrap() as u32);
        let fail_at = sc.get("fail_at_chunk").and_then(Value::as_u64).unwrap_or(0) as usize;
        let mut chunks: Vec<Vec<u8>> = vec![];
        let mut calls = 0usize;
        let mut sink = |c: &[u8]| {
            calls += 1;
            if fail_at != 0 && calls == fail_at {
                return false;
            }
            assert!(c.len() <= 256);
            chunks.push(c.to_vec());
            true
        };
        let ok = write_status(&mut sink, &st);
        let want_ok = case["rc"].as_i64().unwrap() == 0;
        let body: Vec<u8> = chunks.concat();
        assert_eq!(ok, want_ok, "case {n}: completion");
        assert_eq!(hex(&body), case["body"].as_str().unwrap(), "case {n}: body");
        let sizes: Vec<u64> = chunks.iter().map(|c| c.len() as u64).collect();
        assert_eq!(sizes, case["chunks"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect::<Vec<_>>(), "case {n}: chunks");
        if want_ok {
            // The whole thing is valid JSON whenever the strings are valid UTF-8 (serde would refuse raw 0x80+ bytes otherwise).
            if let Ok(text) = std::str::from_utf8(&body) {
                serde_json::from_str::<Value>(text).unwrap_or_else(|e| panic!("case {n}: not JSON: {e}"));
            }
        }
        if st.members.iter().any(|m| m.client.is_some_and(|c| !c.peers.is_empty())) {
            with_peers += 1;
        }
        if !sc["query"].is_null() {
            with_query += 1;
        }
    }
    assert!(with_peers > 10 && with_query > 20, "{with_peers} {with_query}");
}
