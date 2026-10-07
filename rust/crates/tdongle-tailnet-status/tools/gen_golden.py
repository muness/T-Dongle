#!/usr/bin/env python3
"""Generate tests/golden/{status,jw}.jsonl from the REAL C.

  status.jsonl  the real `status()` of alternative/tailnet/main/gateway_main.c, json_writer.inc and runtime_status.inc, cut out and compiled exactly as
                tools/test-gateway.sh does (status_stream.inc), behind stubs driven by a scenario (tools/harness_status.c). One line per scenario:
                {"scenario": {...}, "const": {"context_bytes": N, "socket_recovery": N}, "rc": R, "status": S, "chunks": [...], "body": "<hex>"}
  jw.jsonl      the real json_writer.inc driven by operation lists (tools/harness_jw.c): {"fail_at": K, "ops": [...], "results": "1101", "failed": 0,
                "chunks": [sizes], "out": "<hex>"}

Needs `cc`, python3 and ESP-IDF's cJSON (IDF_PATH, default ~/esp/esp-idf-v5.5.5). Output is checked in; rerun when the C changes."""
import json, os, random, subprocess, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
REPO = HERE.parents[3]
TAILNET = REPO / "alternative/tailnet"
IDF = Path(os.environ.get("IDF_PATH") or Path.home() / "esp/esp-idf-v5.5.5")
CJSON = IDF / "components/json/cJSON"
GOLDEN = CRATE / "tests/golden"
U32 = 0xFFFFFFFF
rnd = random.Random(20261006)


def build(name, source, extra):
    d = Path(tempfile.mkdtemp())
    exe = d / name
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-w", "-fsanitize=address,undefined", *extra, str(source), "-o", str(exe)], check=True)
    return exe


def build_status():
    s = (TAILNET / "main/gateway_main.c").read_text()
    a = s.index('#include "json_writer.inc"')
    b = s.index("static esp_err_t command(", a)
    d = Path(tempfile.mkdtemp())
    (d / "status_stream.inc").write_text(s[a:b])
    (d / "json_writer.inc").write_text((TAILNET / "main/json_writer.inc").read_text())
    (d / "runtime_status.inc").write_text((TAILNET / "main/runtime_status.inc").read_text())
    inc = ["-I", str(d), "-I", str(TAILNET / "main"), "-I", str(TAILNET / "tests"), "-I", str(TAILNET / "components/microlink/include"),
           "-I", str(REPO / "components/tdongle_runtime/include"), "-I", str(CJSON)]
    exe = d / "status"
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-w", "-fsanitize=address,undefined", *inc, str(HERE / "harness_status.c"), str(CJSON / "cJSON.c"), "-o", str(exe)], check=True)
    return exe


def build_jw():
    d = Path(tempfile.mkdtemp())
    (d / "json_writer.inc").write_text((TAILNET / "main/json_writer.inc").read_text())
    exe = d / "jw"
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-w", "-fsanitize=address,undefined", "-I", str(d), str(HERE / "harness_jw.c"), "-o", str(exe)], check=True)
    return exe


def hx(b):
    return bytes(b).hex()


NASTY = [b'"', b"\\", b"\n", b"\r", b"\t", b"\x01", b"\x1f", b"\x7f", b"\x80", b"\xc3\xa9", b"\xff", b"/", b"'", b"<", b"\x08", b"\x0c"]


def text(maxlen, plain=False, allow_empty=True):
    n = rnd.randint(0 if allow_empty else 1, maxlen)
    out = bytearray()
    while len(out) < n:
        if not plain and rnd.random() < 0.15:
            out += rnd.choice(NASTY)
        else:
            out.append(rnd.choice(b"abcdefghijklmnopqrstuvwxyz0123456789-._ :/"))
    out = out[:n]
    if rnd.random() < 0.03 and out:
        out[rnd.randrange(len(out))] = 0  # an embedded NUL ends the C string
    return hx(out)


def u32():
    return rnd.choice([0, 1, 2, 255, 256, 65535, 65536, 1 << 31, U32 - 1, U32, rnd.randrange(1 << 32), rnd.randrange(1 << 20), rnd.randrange(1000)])


def s32():
    return rnd.choice([0, 1, -1, -5, 550, -270, 2**31 - 1, -(2**31), rnd.randrange(-(2**31), 2**31), rnd.randrange(-1000, 1000)])


def maybe_max():
    return U32 if rnd.random() < 0.25 else u32()


def peer_name():
    base = rnd.choice([b"server", b"phone", b"a", b"x" * 40, b"", b"we\"ird", b"h\xc3\xa9"])
    tail = rnd.choice([b"", b".ts.net", b".tail1234.ts.net", b".", b"..a"])
    return hx((base + tail)[:63])


def client(directory_cap=40):
    peers = [{"name": peer_name(), "address": u32()} for _ in range(rnd.choice([0, 0, 1, 2, 5, 8]))]
    return {
        "state": rnd.choice([0, 1, 2, 3, 4, 5, u32()]), "vpn_ip": rnd.choice([0, 0x64010203, 0xC6120001, u32()]),
        "wg_netif": rnd.random() < 0.7, "key_expired": rnd.random() < 0.2, "rt_attached": rnd.random() < 0.7, "stop_incomplete": rnd.random() < 0.15, "coord": rnd.random() < 0.7,
        "last_error": text(63) if rnd.random() < 0.3 else "", "transport_error": text(63) if rnd.random() < 0.3 else "",
        "auth_url": text(383) if rnd.random() < 0.25 else "", "h2_debug": text(48), "dns": text(127) if rnd.random() < 0.6 else "",
        "control_stage": u32(), "derp_tls_verify_failures": u32(), "derp_tls_deferred": u32(), "control_key_auth": rnd.randrange(256),
        "derp_state_index": rnd.randrange(10), "frames_rx": u32(), "frames_tx": u32(), "record_timeouts": u32(), "write_stalls": u32(), "alloc_drops": u32(), "connects": u32(),
        "diagnostics": [u32() for _ in range(20)] + [rnd.choice([0, 1, -1, -123, 2**31 - 1, -(2**31)]) & U32],
        "jit_hits": u32(), "jit_misses": u32(), "jit_evictions": u32(), "jit_rejected": u32(), "jit_dropped": u32(),
        "directory_records": rnd.choice([len(peers), len(peers), len(peers) + 3, 0, 20]), "session_valid": rnd.random() < 0.8,
        "peers": peers,
    }


def member(i):
    return {
        "id": rnd.choice([i + 1, i + 1, u32() or 1]), "enabled": rnd.random() < 0.7, "start_heap_before": rnd.choice([0, u32()]), "start_heap_after": rnd.choice([0, u32()]),
        "label": text(23), "error": text(63) if rnd.random() < 0.4 else "", "client": client() if rnd.random() < 0.75 else None,
    }


def scenario():
    n_members = rnd.choice([0, 1, 1, 2, 3])
    sc = {
        "firmware": hx(rnd.choice([b"0.3.0-dev", b"1.2.3", b"v\"x\\"])), "mode": hx(rnd.choice([b"tailnet_gateway", b"wifi_bridge"])),
        "temperature": {"valid": rnd.random() < 0.8, "current": s32(), "peak": s32(), "sampled": u32(), "samples": rnd.choice([0, 1, 7, u32()]), "changed": u32(), "age": u32(), "errors": u32()},
        "recovery": rnd.random() < 0.2, "member_start_budget": rnd.choice([0, 78340, u32()]),
        "admission": {k: u32() for k in ["required", "shared_runtime", "member_start", "member_growth", "member_steady", "negotiation", "recovery", "largest_block", "peer_slots_charged", "peer_slot_bytes"]},
        "shared_runtime": {
            "running": rnd.random() < 0.8, "members": u32(), "starts": u32(), "stops": u32(), "attach_failures": u32(), "detach_failures": u32(),
            "stack_bytes": [u32() for _ in range(3)], "stack_free": [maybe_max() for _ in range(3)], "passes": [u32() for _ in range(3)],
            "max_service_ms": [u32() for _ in range(3)], "slow_services": [u32() for _ in range(3)], "detach_timeouts": [u32() for _ in range(3)],
            "negotiation": {"holder": rnd.choice([-1, -1, 0, 1, 2, 3]), **{k: u32() for k in ["held_ms", "waiting", "grants", "timeouts", "lease_expired", "stale_dropped", "refused_full", "max_wait_ms", "max_hold_ms"]}},
        },
        "wg_pool": {**{k: u32() for k in ["capacity", "used", "peak", "refused_full", "refused_nomem", "evictions_own", "evictions_other", "rejected", "refused_largest", "refused_heap", "slot_bytes", "device_bytes"]}, "largest_low": maybe_max()},
        "shared_rng": {k: u32() for k in ["users", "bytes_resident", "seedings", "failures"]},
        "power": {
            "scaling": rnd.random() < 0.5, "cpu_mhz": rnd.choice([80, 240, u32()]), "max_mhz": rnd.choice([0, 240]), "min_mhz": rnd.choice([0, 80]), "configure_error": s32(),
            "lock_create_failures": u32(), "wifi_ps": rnd.choice([-1, 0, 1, 2, s32()]),
            "locks": [{"name": hx(rnd.choice([b"ml_derp", b"usb_routes", b"wifi_rx", b"we\"ird", b"n" * 20])), **{k: u32() for k in ["depth", "acquires", "releases", "held_us", "max_depth", "underflows", "forced_releases", "backend_failures", "isr_rejects"]}} for _ in range(rnd.choice([0, 1, 2, 8]))],
        },
        "sockets": {k: u32() for k in ["limit", "open", "peak", "failures", "last_errno", "last_operation", "last_at_ms"]},
        "reset_reason": rnd.randrange(16), "wifi": rnd.random() < 0.7,
        "wifi_link": hx(b'{"connected":true,"rssi_dbm":-61,"channel":11}') if rnd.random() < 0.7 else None,
        "clock": {"state": hx(rnd.choice([b"synced", b"failing", b"syncing", b"waiting_for_network"])), "valid": rnd.random() < 0.5, "sntp_restarts": u32(), "retry_in_ms": u32(), "server": hx(rnd.choice([b"pool.ntp.org", b"time.google.com"]))},
        "saved_wifi": [text(32, allow_empty=False) for _ in range(rnd.choice([0, 1, 3, 8]))],
        "route_storage_ok": rnd.random() < 0.9, "free_memory": u32(), "largest_free_block": u32(), "minimum_free_memory": u32(),
        "heap_budget": {k: u32() for k in ["floor", "reserve", "pin_buffers", "refused_usb_rx", "refused_pending", "refused_derp_tx", "refused_rx_ctrl", "refused_derp_rx", "refused_wg_copy"]},
        "wifi_pins": {
            "installed": rnd.random() < 0.5, "tx_done_cb": rnd.random() < 0.5, "rx_hooked": rnd.random() < 0.5,
            **{k: u32() for k in ["tx_pool", "band_total", "tx_band_max", "rx_band_max", "tx_inflight", "rx_inflight", "tx_high_water", "tx_charged", "tx_done", "tx_aborted", "tx_flushed", "tx_stale", "tx_unmatched", "tx_band", "tx_elastic", "tx_refused_pool", "tx_refused_heap", "rx_high_water", "rx_band", "rx_elastic", "rx_released", "rx_unmatched", "rx_dropped"]},
        },
        "stack_values": [u32() for _ in range(5)],
        "query": hx(rnd.choice([b"peer_offset=2&peer_member=1", b"peer_member=2&peer_offset=3", b"peer_offset=100001&peer_member=1", b"peer_offset=-1&peer_member=1", b"PEER_OFFSET=1&peer_member=1",
                                b"peer_offset=1", b"x&peer_offset=1&peer_member=1", b"peer_offset=1234567890123456&peer_member=1", b"peer_offset= 4&peer_member=+1", b"peer_offset=0x10&peer_member=1",
                                b"peer_offset=&peer_member=", b"peer_offset=1&peer_member=1&peer_offset=2", b"a=" + b"b" * 70, b"peer_offset=1;peer_member=1", b""])) if rnd.random() < 0.6 else None,
        "derp_states": [hx(x) for x in [b"idle", b"waiting", b"token", b"transport", b"upgrade_tx", b"upgrade_rx", b"server_key", b"client_info", b"server_info", b"ready"]],
        "members": [member(i) for i in range(n_members)],
    }
    if rnd.random() < 0.15:
        sc["fail_at_chunk"] = rnd.randrange(1, 12)
    return sc


def match_close(s, i):
    depth = 0
    while i < len(s):
        c = s[i]
        if c == '"':
            i += 1
            while s[i] != '"':
                i += 2 if s[i] == "\\" else 1
        elif c == "'":
            i += 1
            while s[i] != "'":
                i += 2 if s[i] == "\\" else 1
        elif c == "/" and s[i + 1] == "*":
            i = s.index("*/", i) + 1
        elif c == "/" and s[i + 1] == "/":
            i = s.index("\n", i)
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced")


def replace_function(src, signature, replacement):
    start = src.index(signature)
    brace = src.index("{", start)
    end = match_close(src, brace)
    return src[:start] + replacement + src[end + 1 :]


SNAPSHOT_STUB = r"""
static bool memory_snapshot(memory_member *out, unsigned *count, unsigned *omitted) {
    cJSON *sn = cJSON_GetObjectItemCaseSensitive(g_s, "snapshot");
    if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(sn, "busy"))) return false;
    *omitted = (unsigned)cJSON_GetObjectItemCaseSensitive(sn, "omitted")->valuedouble;
    cJSON *ms = cJSON_GetObjectItemCaseSensitive(sn, "members"), *m; *count = 0;
    cJSON_ArrayForEach(m, ms) {
        memory_member *v = &out[(*count)++]; memset(v, 0, sizeof *v);
#define F(n) v->n = (uint32_t)(uint64_t)cJSON_GetObjectItemCaseSensitive(m, #n)->valuedouble
        F(id); F(tasks); F(stacks); F(tcbs); F(h2_acc);
        for (int t = 0; t < 4; t++) v->stack_free[t] = (uint32_t)(uint64_t)cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(m, "stack_free"), t)->valuedouble;
        v->lp_acc = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(m, "lp_acc"));
    }
    return true;
}
"""


def diag_sources(d):
    src = (TAILNET / "main/memory_diagnostics.inc").read_text()
    src = "\n".join(l for l in src.split("\n") if not l.startswith("#include") and not l.startswith("extern void mgmt_write"))
    src = replace_function(src, "static bool memory_snapshot(", SNAPSHOT_STUB)
    src = replace_function(src, "static bool wifi_stats_reset(", 'static bool wifi_stats_reset(void) { return K("lwip_reset"); }')
    src = replace_function(src, "static void heap_low_tick(", "")
    src = replace_function(src, "static void heap_low_start(", "")
    src = src.replace("static uint32_t wifi_report_uptime_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }", "static uint32_t wifi_report_uptime_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }")
    (d / "diag.inc").write_text(src)
    rt = (TAILNET / "main/route_table.h").read_text()
    a = rt.index("enum {\n    RT_STAT_FORWARDED_OUT")
    b = rt.index("extern atomic_uint rt_stats")
    (d / "route_table_names.h").write_text(rt[a:b])
    rx = (TAILNET / "components/microlink/include/ml_rx_stats.h").read_text()
    a = rx.index("#define ML_RX_COUNTERS(X)")
    b = rx.index("typedef struct {\n    atomic_uint c[ML_RXS_COUNT]")
    c = rx.index("static inline const char *ml_rx_stat_name")
    e = rx.index("static inline void ml_rx_stat_burst")
    (d / "ml_rx_stats_names.h").write_text(rx[a:b] + rx[c:e])
    (d / "json_writer.inc").write_text((TAILNET / "main/json_writer.inc").read_text())


def build_diag(with_lwip):
    d = Path(tempfile.mkdtemp())
    diag_sources(d)
    inc = ["-I", str(d), "-I", str(TAILNET / "main"), "-I", str(TAILNET / "tests"), "-I", str(TAILNET / "components/microlink/include"), "-I", str(REPO / "components/tdongle_runtime/include"), "-I", str(CJSON)]
    exe = d / ("diag_lwip" if with_lwip else "diag")
    flags = ["-DCONFIG_TDONGLE_MEMORY_DIAGNOSTICS=1"] + (["-DWITH_LWIP=1"] if with_lwip else [])
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-w", "-fsanitize=address,undefined", *flags, *inc, str(HERE / "harness_diag.c"), str(CJSON / "cJSON.c"), "-o", str(exe)], check=True)
    return exe


def diag_scenario():
    k = {}
    for n in ["heap_free", "heap_min", "heap_largest", "heap_total", "guard_floor", "underflows", "ledger_bytes", "q_derp_tx", "q_disco_rx", "q_wg_rx", "q_stun_rx", "coord_stack", "json_buffer", "h2_buffer",
              "plain_bytes", "json_bytes", "member_queue_bytes", "TCP_WND", "TCP_SND_BUF", "TCP_MSS", "TCP_SND_QUEUELEN", "LWIP_WND_SCALE", "PBUF_POOL_SIZE", "PBUF_POOL_BUFSIZE", "MEMP_NUM_TCP_PCB",
              "MEMP_NUM_TCP_SEG", "max_sockets", "tcp_recvmbox", "udp_recvmbox", "tcpip_recvmbox", "wifi_static_rx", "wifi_dynamic_rx", "wifi_dynamic_tx", "ntb_count", "rx_inflight_max", "rx_inflight",
              "rx_high_water", "rx_dropped_busy", "rx_dropped_nomem", "rx_dropped_heap", "rx_dropped_invalid", "gap_count", "gap_us_sum", "gap_us_max", "cold_starts", "cold_us_sum", "cold_us_max",
              "worker_demotions", "hb_floor", "hb_reserve", "drain_cap", "wg_rx_queue_bytes", "wg_rx_bytes_queued", "wg_rx_bytes_peak", "wg_rx_batch", "replay_window", "drain_burst_max",
              "slot_evictions", "since_us", "cpu_mhz", "cpu_total", "tasks_existing", "logbench_ok", "cycles_per_line", "crypto_ok", "aead_ns", "copy_ns", "wifi_dump_err", "lwip_reset"]:
        k[n] = u32()
    k["rt_running"] = rnd.randrange(2)
    k["logbench_ok"] = rnd.randrange(2)
    k["crypto_ok"] = rnd.randrange(2)
    k["lwip_reset"] = rnd.randrange(2)
    k["heap_total"] = rnd.choice([k["heap_total"], 300000])
    k["heap_free"] = rnd.choice([k["heap_free"], 100000, 400000])
    k["rt_stack_bytes"] = [u32() for _ in range(3)]
    k["route_stats"] = [u32() for _ in range(30)]
    k["wg_values"] = [u32() for _ in range(5)]
    k["ml_values"] = [u32() for _ in range(23)]
    for n in ["owner_live", "owner_peak", "owner_allocs", "owner_frees", "owner_failed", "owner_denied"]:
        k[n] = [u32() for _ in range(8)]
    k["drops"] = [u32() for _ in range(7)]
    k["usb_tx"] = [u32() for _ in range(34)]
    k["usb_drains"] = [u32() for _ in range(5)]
    k["usb_gap_hist"] = [u32() for _ in range(5)]
    k["wgperf_counters"] = [u32() for _ in range(13)]
    k["tasks_existing"] = rnd.choice([0, 3, 12, 32, 33, 40])
    ntasks = k["tasks_existing"] if k["tasks_existing"] <= 32 else rnd.randrange(0, 33)
    sc = {
        "firmware": hx(rnd.choice([b"0.3.0-dev", b"v\"x"])), "k": k,
        "timer": [rnd.randrange(10**9, 10**10), rnd.randrange(10**9, 10**10), rnd.randrange(10**9, 10**10), rnd.randrange(10**9, 10**10)],
        "snapshot": {"busy": rnd.random() < 0.15, "omitted": rnd.choice([0, 0, 2]), "members": [
            {"id": u32(), "tasks": rnd.randrange(2), "stacks": u32() % 100000, "tcbs": u32() % 5000, "h2_acc": u32() % 40000, "stack_free": [maybe_max() for _ in range(4)], "lp_acc": rnd.random() < 0.5}
            for _ in range(rnd.choice([0, 1, 2, 4]))]},
        "wg_names": [rnd.choice(["rx_data", "rx_handshake", "replay_drop", "bad_mac", "x"]) for _ in range(5)],
        "phases": [{"member": u32(), "attempt": u32(), "phase": [{"valid": rnd.randrange(2), "exact": rnd.randrange(2), "t": u32(), "free": u32(), "min": u32(), "largest": u32(), "peak": [u32() for _ in range(8)]} for _ in range(7)]} for _ in range(rnd.choice([0, 1, 3]))],
        "admissions": [[u32() for _ in range(8)] + [rnd.choice([0, 1, 2, 3, 4, 5, 6, 7, 99])] for _ in range(rnd.choice([0, 1, 6]))],
        "locks": [[u32(), u32(), u32(), rnd.randrange(2**40)] + [u32() for _ in range(9)] for _ in range(5)],
        "notes": [[u32() % 100000, rnd.randrange(0, 60000), rnd.randrange(0, 90000), 0, rnd.randrange(0, 90000)] + [u32() % 5000 for _ in range(7)] for _ in range(rnd.choice([0, 3, 12, 20]))],
        "tasks": [[hx(rnd.choice([b"IDLE0", b"gateway_control", b"net\"io"])), u32(), rnd.randrange(25), rnd.choice([0, 1, -1, 2, -5]), rnd.randrange(5000)] for _ in range(ntasks)],
        "bridge": [[rnd.choice(["rx", "tx", "ring"]), rnd.choice(["frames", "drops", "a_very_long_counter_name_that_goes_on_and_on"]), rnd.choice([0, 5, -5, 2**40, -(2**40), -(2**63)])] for _ in range(rnd.choice([0, 3, 8]))],
        "bridge_active": rnd.random() < 0.5,
        "link": hx(b'{"connected":true,"rssi_dbm":-61}') if rnd.random() < 0.7 else None,
        "wgperf": [[u32(), rnd.randrange(2**44), u32()] for _ in range(29)],
    }
    return sc


COMMANDS = [b"memory", b"bridge", b"bridgetune", b"bridgetune 1 2", b"bridgetuneX", b"memory low", b"wifistats", b"wifistats reset", b"wifistats dump", b"cpu", b"wgperf", b"wgperf reset",
            b"wgperf logbench", b"route", b"inbound", b"members", b"memory locks", b"memory bench", b"memory guard", b"memory guard ", b"memory guard 0", b"memory guard 65536", b"memory guard 65537",
            b"memory guard 12", b"memory guard 12x", b"memory guard x", b"memory guard -1", b"memory guard +5", b"memory guard  7", b"memory guard 99999999999", b"memory guardX", b"memorylow", b"Memory", b"",
            b"memory low ", b"route ", b"status", b"help"]
REPORTS = [b"@heap", b"@attribution", b"@lwip", b"@usb", b"@locks", b"@route", b"@phases", b"@admission", b"@inbound", b"@wgperf", b"@cpu", b"@bench", b"@logbench", b"@bridge", b"@wifi_link",
           b"@wifi_reset", b"@wifi_dump", b"@lwip_stats", b"@heap_low"]


def diag_cases(count_per_report):
    exes = {False: build_diag(False), True: build_diag(True)}
    out = []
    for lw in (False, True):
        cmds = []
        for cmd in REPORTS:
            if lw and cmd not in (b"@inbound", b"@lwip_stats"):
                continue
            if not lw and cmd == b"@inbound":
                pass
            for _ in range(count_per_report):
                cmds.append(cmd)
        if not lw:
            cmds += COMMANDS
        lines = []
        scs = []
        for cmd in cmds:
            sc = diag_scenario()
            sc["command"] = hx(cmd)
            scs.append(sc)
            lines.append(json.dumps(sc))
        for sc, line in zip(scs, lines):
            o = run_lines(exes[lw], [line])
            parts = [l[2:] for l in o if l.startswith("P ")]
            marks = [l for l in o if l.startswith("@")]
            out.append({"lwip": lw, "scenario": sc, "parts": parts, "marks": marks})
    return out


def run_lines(exe, lines):
    p = subprocess.run([str(exe)], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    return p.stdout.splitlines()


def status_cases(exe, count):
    scenarios = [scenario() for _ in range(count)]
    # the member-less, client-less and fully populated edges are always present
    out = []
    for sc in scenarios:
        o = run_lines(exe, [json.dumps(sc)])
        const = o[0].split()
        rc, status = int(o[1].split()[1]), int(o[1].split()[3])
        chunks = [int(x) for x in o[2][len("CHUNKS"):].replace(",", " ").split()]
        body = o[3].split(" ", 1)[1] if " " in o[3] else ""
        out.append({"scenario": sc, "const": {"context_bytes": int(const[1]), "socket_recovery": int(const[2])}, "rc": rc, "status": status, "chunks": chunks, "body": body})
    return out


def jw_ops():
    ops = []
    for _ in range(rnd.randint(1, 40)):
        k = rnd.choice(["r", "s", "s", "k", "n", "b", "c", "f"])
        if k in "rsk":
            b = bytearray()
            for _ in range(rnd.choice([0, 3, 10, 80, 300])):
                b.append(rnd.choice(b"abcxyz019 -_:/") if rnd.random() < 0.8 else rnd.choice(b'"\\\x01\x1f\x7f\x80\xff\n\t'))
            if rnd.random() < 0.05 and b:
                b[rnd.randrange(len(b))] = 0
            ops.append(k + hx(b))
        elif k == "n":
            ops.append("n%d" % rnd.choice([0, 1, 9, 10, 99, 255, 4294967295, 4294967296, 2**63, 2**64 - 1, rnd.randrange(2**64)]))
        elif k == "b":
            ops.append("b%d" % rnd.randrange(2))
        elif k == "c":
            ops.append("c%02x" % rnd.choice([0x41, 0x7b, 0x22, 0x5c, 0x0a]))
        else:
            ops.append("f")
    return ops


def jw_cases(exe, count):
    cases = []
    for _ in range(count):
        ops = jw_ops()
        fail_at = rnd.choice([0, 0, 0, 1, 2, 3, 5])
        line = "%d %s" % (fail_at, " ".join(ops))
        o = run_lines(exe, [line])
        head = o[0].split(" ")
        cases.append({"fail_at": fail_at, "ops": ops, "results": head[0], "failed": int(head[1]), "chunks": [int(x) for x in head[2:]], "out": o[1] if len(o) > 1 else ""})
    return cases


def main():
    GOLDEN.mkdir(parents=True, exist_ok=True)
    cases = status_cases(build_status(), 90)
    with open(GOLDEN / "status.jsonl", "w") as f:
        for c in cases:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    jw = jw_cases(build_jw(), 160)
    with open(GOLDEN / "jw.jsonl", "w") as f:
        for c in jw:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    dg = diag_cases(3)
    with open(GOLDEN / "diag.jsonl", "w") as f:
        for c in dg:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    ok = sum(1 for c in cases if c["rc"] == 0)
    print("diag: %d runs" % len(dg))
    print("status: %d scenarios (%d complete, %d with a failing sink, %d bytes of golden); jw: %d" % (len(cases), ok, len(cases) - ok, sum(len(c["body"]) // 2 for c in cases), len(jw)))


if __name__ == "__main__":
    main()
