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
                "-I", str(runtime / "tests/stubs"), "-I", str(runtime / "include"), "-I", str(r / "components/microlink/include"),
                str(r / "tests/test_memory_report.c"), str(runtime / "memory.c"), str(runtime / "memory_diagnostics.c"),
                "-o", str(binary)], check=True)
text = subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout
sections, current = {}, None
for line in text.splitlines():
    if line.startswith("#> "):
        current = line[3:]
        sections[current] = []
    elif line.startswith("#"):
        sections[current].append(line)
    else:
        sections[current].append(json.loads(line) if line.startswith("{") else line)  # raises on a malformed report

def reports(command, kind=None):
    return [x for x in sections[command] if isinstance(x, dict) and (kind is None or x["kind"] == kind)]

memory = reports("memory")
assert [x["kind"] for x in memory] == ["heap", "attribution", "lwip"], memory
assert all(x["schema"] == 1 for x in memory)
heap, attribution, lwip = memory
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

members = sections["members"]
phases = reports("members", "phases")
assert len(phases) == 1 and phases[0]["member"] == 7 and phases[0]["attempt"] == 1 and len(phases[0]["owner_order"]) == 8
assert list(phases[0]["phases"]) == ["start", "control", "steady"]
assert phases[0]["phases"]["control"]["peak"][6] == 1500 and phases[0]["phases"]["start"]["free"] == 60000
admission = reports("members", "admission")[0]
assert admission["override"] is True and len(admission["attempts"]) == 6
assert [a["verdict"] for a in admission["attempts"]] == ["refused_budget", "refused_largest", "refused_sockets", "override", "refused_floor", "start_failed"], admission

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
print("Serial reports: heap, attribution, lwip, phases, admission, bench and guard parse as bounded one-line JSON.")
