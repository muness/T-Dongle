#!/usr/bin/env python3
"""Compile main/memory_diagnostics.inc against host stubs and check that every serial report is one valid JSON line."""
import json
import os
import pathlib
import subprocess
import sys

r = pathlib.Path(__file__).resolve().parents[1]
runtime = r / "../../components/tdongle_runtime"
out = r / "build-host"
out.mkdir(exist_ok=True)
binary = out / "test_memory_report"
subprocess.run(["cc", "-std=gnu11", "-g", "-fsanitize=address,undefined", "-DCONFIG_TDONGLE_MEMORY_DIAGNOSTICS=1",
                "-DCONFIG_TDONGLE_MEMORY_GUARD_FLOOR_BYTES=12288", "-I", str(r / "tests/host"), "-I", str(r / "main"),
                "-I", str(runtime / "tests/stubs"), "-I", str(runtime / "include"), "-I", str(r / "components/microlink/include"), "-I", str(r / "components/microlink/components/wireguard_lwip/src"),
                str(r / "tests/test_memory_report.c"), str(runtime / "memory.c"), str(runtime / "memory_diagnostics.c"),
                "-o", str(binary)], check=True)
text = subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout
sections, current = {}, None
for line in text.splitlines():
    if line.startswith("#> "):
        current = line[3:]
        while current in sections:
            current += "'"   # the same command twice: keep both outputs
        sections[current] = []
    elif line.startswith("#"):
        sections[current].append(line)
    else:
        sections[current].append(json.loads(line) if line.startswith("{") else line)  # raises on a malformed report

def reports(command, kind=None):
    return [x for x in sections[command] if isinstance(x, dict) and (kind is None or x["kind"] == kind)]

memory = reports("memory")
assert [x["kind"] for x in memory] == ["heap", "attribution", "lwip", "usb"], memory
assert all(x["schema"] == 1 for x in memory)
heap, attribution, lwip, usb = memory
assert heap["free"] == 60000 and heap["min"] == 31000 and heap["largest"] == 24576 and heap["total"] == 300000
assert list(heap["owners"]) == ["other", "tls", "control", "map", "peer", "wg", "packet", "context"]
assert heap["owners"]["packet"]["live"] == 1500 and heap["owners"]["map"]["peak"] == 900 and heap["owners"]["packet"]["allocs"] == 1
assert heap["guard_floor"] == 12288 and heap["ledger_bytes"] > 0 and heap["drops"]["derp_tx_full"] == 1
assert heap["queue_depth"] == {"derp_tx": 8, "disco_rx": 8, "wg_rx": 8, "stun_rx": 4}
assert attribution["tagged"] == 2400 and attribution["members"][0]["id"] == 7 and attribution["members"][0]["tasks"] == 1
# A membership keeps ONE task (control); net_io, derp and wg_mgr exist once, counted under shared_runtime.
assert attribution["members"][0]["stacks"] == 8704 and attribution["members"][0]["stack_free"] == [1000, 2000, 3000, 4000]
assert attribution["shared_runtime"] == {"tasks": 3, "stacks": 7168 + 7680 + 8192, "tcbs": 3 * 336}, attribution["shared_runtime"]
assert attribution["synthetic"] == (7168 + 7680 + 8192 + 3 * 336) + (8704 + 336 + 1234) and attribution["unattributed"] == 300000 - 60000 - 2400 - attribution["synthetic"]
assert attribution["n2"] == {"lp_acc_capacity": 65536, "lp_acc_allocated": False, "h2_window_advertised": 65536, "h2_acc_live_max": 0,
                             "gateway_plain_static": 20496, "gateway_json_static": 16384}, attribution["n2"]
assert lwip["tcp_wnd"] == 5760 and lwip["pbuf_pool_size"] == 16
assert usb["tx_ring_bytes"] == 9144 and usb["tx_ring_base_bytes"] == 4572 and usb["tx_ring_max_bytes"] == 35052
assert usb["tx_elastic_held_bytes"] == 6096 and usb["tx_elastic_chunks"] == 2 and usb["tx_high_water_slabs"] == 9
assert (usb["tx_grow_events"], usb["tx_shrink_events"], usb["tx_reclaim_events"], usb["tx_reclaimed_chunks"]) == (11, 12, 13, 14)
assert (usb["tx_grow_denied_gate"], usb["tx_grow_denied_heap"], usb["tx_grow_denied_largest"], usb["tx_grow_denied_nomem"], usb["tx_grow_raced"]) == (15, 16, 17, 18, 19)
assert (usb["tx_pm_acquired"], usb["tx_pm_released"], usb["tx_pm_held"]) == (20, 19, 1)
assert usb["tx_high_water"] == 4212 and usb["tx_dropped_full"] == 7 and usb["tx_ntb_blocked"] == 4
assert usb["tx_xfer_events"] == 55 and usb["tx_worker_stack_free"] == 900
assert usb["tx_ntb_count"] == 2 and usb["rx_inflight_max"] == 22 and usb["rx_inflight"] == 0 and usb["rx_dropped_busy"] == 0

members = sections["members"]
phases = reports("members", "phases")
assert len(phases) == 1 and phases[0]["member"] == 7 and phases[0]["attempt"] == 1 and len(phases[0]["owner_order"]) == 8
assert list(phases[0]["phases"]) == ["start", "control", "steady"]
assert phases[0]["phases"]["control"]["peak"][6] == 1500 and phases[0]["phases"]["start"]["free"] == 60000
admission = reports("members", "admission")[0]
assert admission["override"] is True and len(admission["attempts"]) == 6
assert [a["verdict"] for a in admission["attempts"]] == ["refused_budget", "refused_largest", "refused_sockets", "override", "refused_floor", "start_failed"], admission

locks = reports("memory locks", "locks")[0]
assert locks["bucket_limits_us"] == [100, 250, 500, 1000, 2000, 5000, 10000, 30000]
assert locks["sites"]["wg_periodic"]["count"] == 2 and locks["sites"]["wg_periodic"]["max_us"] == 42000 and locks["sites"]["wg_periodic"]["over_1ms"] == 1
assert locks["sites"]["wg_periodic"]["buckets"] == [0, 0, 0, 1, 0, 0, 0, 0, 1] and locks["sites"]["wg_other"]["count"] == 0
wg = [reports("wgperf", "wgperf")[0], reports("wgperf reset", "wgperf_reset")[0], reports("wgperf'", "wgperf")[0]]
first = wg[0]
assert first["cpu_mhz"] == 240 and list(first["stages"])[:3] == ["q_latency", "prep", "pass"] and len(first["units"]) == len(first["stages"])
assert first["stages"]["lock_wait"] == [2, 350, 250] and first["stages"]["pass"] == [2, 0xffffffff + 5, 0xffffffff], first["stages"]["pass"]
assert first["units"][0] == "us" and first["units"][1] == "cy" and first["units"][-1] == "pkt" and first["counters"]["passes"] == 2
assert all(v == [0, 0, 0] for v in wg[2]["stages"].values()) and all(v == 0 for v in wg[2]["counters"].values())   # after the reset
assert reports("wgperf logbench", "logbench")[0]["cycles_per_line"] == 31000
cpu = reports("cpu", "cpu")[0]
assert cpu["cpu_mhz"] == 240 and cpu["total"] == 4294967295 and cpu["cores"] == 2 and cpu["tasks_listed"] == 3 and cpu["uptime_ms"] == 123456
assert [(t["name"], t["runtime"], t["priority"], t["core"], t["stack_free"]) for t in cpu["tasks"]] == \
    [("IDLE0", 1000, 5, 0, 700), ("ml_wg_mgr", 2000, 6, 1, 701), ("tiT", 3000, 7, -1, 702)], cpu["tasks"]
assert cpu["tasks_existing"] == 3
many = reports("cpu_many", "cpu")[0]
assert many["tasks_existing"] == 40 and many["tasks_listed"] == 0 and many["tasks"] == [], many
route = reports("route", "route")[0]
assert route["forwarded_out"] == 0 and route["alias_miss"] == 9 and route["queue_full"] == 30 and route["queue_depth"] == 16 and route["flow_slots"] == 64, route
assert len([k for k in route if k not in ("schema", "kind")]) == 30 + 4, route
assert route["reply_owner"] == 3 * 26 and route["usb_tx_err"] == 3 * 29, route   # the new tunnel->USB reject reasons are in the report
# The inbound report: every layer's counters, cumulative, with the configuration they are read against.
inbound = reports("inbound", "inbound")[0]
assert inbound["udp_recvmbox"] == 10 and inbound["drain_cap"] == 16 and inbound["wg_rx_queue_depth"] == 8 and inbound["replay_window"] == 480, inbound
assert inbound["lwip"] == {"udp_recv": 5000, "udp_drop": 1, "udp_memerr": 2, "udp_err": 3}, inbound["lwip"]
ml_names = ["udp_rx", "udp_rx_empty", "udp_unclassified", "udp_alloc_fail", "udp_recv_err", "udp_wg", "udp_disco", "udp_stun", "q_wg_full", "q_disco_full",
            "q_stun_full", "derp_rx_wg", "derp_q_wg_full", "drain_calls", "drain_capped", "wg_in", "wg_sender_unknown", "wg_no_netif", "wg_pbuf_fail",
            "wg_to_wireguardif", "drain_burst_max"]
assert list(inbound["ml"]) == ml_names and inbound["ml"]["udp_rx"] == 100 and inbound["ml"]["wg_to_wireguardif"] == 119 and inbound["ml"]["drain_burst_max"] == 13, inbound["ml"]
wg_names = ["rx_data", "rx_bad_type", "rx_no_peer", "rx_keypair_unusable", "rx_expired", "rx_alloc_fail", "rx_session_gone", "rx_decrypt_fail",
            "rx_keepalive", "rx_replay_dup", "rx_replay_old", "rx_replay_limit", "rx_bad_ip", "rx_allowed_ip", "rx_bad_length", "rx_input_fail", "rx_delivered"]
assert list(inbound["wg"]) == wg_names and inbound["wg"]["rx_data"] == 200 and inbound["wg"]["rx_delivered"] == 216, inbound["wg"]
assert list(inbound["route"]) == ["tunnel_malformed", "tunnel_nomem", "bad_packet", "reply_no_member", "reply_not_us", "reply_flow_range", "reply_no_flow",
                                  "reply_generation", "reply_owner", "reply_idle", "forwarded_in", "usb_tx", "usb_tx_err", "tx_fail"], inbound["route"]

bench = reports("memory bench", "bench")[0]
assert bench["rounds"] == 256 and bench["chacha20poly1305_ns_per_packet"] == 2000000 and bench["cipher_ceiling_kbit_s"] == 1400 * 8 * 1000000 // 2000000
assert reports("memory guard 4096", "guard")[0]["guard_floor"] == 4096
for bad in ("memory guard", "memory guard 70000", "memory guard 12x"):
    assert any("ERR" in x for x in sections[bad] if isinstance(x, str)), bad
assert "#handled 0" in sections["memory nonsense"]
busy = reports("busy", "attribution")[0]
assert busy["error"] == "memberships busy"
for command, lines in sections.items():
    for item in lines:
        if isinstance(item, dict):
            assert len(json.dumps(item, separators=(",", ":"))) < 1800, (command, item["kind"])  # bounded, fits the console queue in a few chunks
print("Serial reports: heap, attribution, lwip, usb, route, phases, admission, bench and guard parse as bounded one-line JSON.")
