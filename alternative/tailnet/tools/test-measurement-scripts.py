#!/usr/bin/env python3
"""Host tests for dongle_serial.py, memory_ladder.py and tailnet_throughput.py (no hardware, no iperf3)."""
import argparse
import contextlib
import io
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import dongle_serial  # noqa: E402
import memory_ladder  # noqa: E402
import tailnet_throughput  # noqa: E402

OWNERS = ["other", "tls", "control", "map", "peer", "wg", "packet", "context"]


def heap(uptime, free, largest=20000, live=1000):
    return json.dumps({"schema": 1, "kind": "heap", "uptime_ms": uptime, "free": free, "min": free - 500, "largest": largest,
                       "total": 300000, "underflows": 0, "queue_depth": {"derp_tx": 8, "disco_rx": 8, "wg_rx": 8, "stun_rx": 4},
                       "drops": {"derp_tx_full": uptime // 1000}, "owners": {n: {"live": live, "peak": live * 2} for n in OWNERS}})


def phases(member, steady):
    p = {"control": {"t": 1, "free": 90000, "min": 88000, "largest": 40000, "exact": 1, "peak": [0] * 8}}
    if steady:
        p["steady"] = {"t": 60, "free": 40000, "min": 31000, "largest": 24000, "exact": 0, "peak": [0] * 8}
    return json.dumps({"schema": 1, "kind": "phases", "member": member, "attempt": 1, "phases": p})


class FakeLink:
    """Answers like the firmware: output lines then done>; no echo."""

    def __init__(self, script, diagnostics=True):
        self.script, self.diagnostics, self.out, self.step = script, diagnostics, [], 0

    def reset_input_buffer(self):
        self.out = []

    def write(self, data):
        line = data.decode().strip()
        if line == "capabilities":
            self.out = ["capabilities schema=1 features=tailnet_gateway" + (",memory_diagnostics" if self.diagnostics else ""), "done>"]
        elif line == "memory":
            uptime, free, steady = self.script[min(self.step, len(self.script) - 1)]
            self.out = ["T-Dongle banner", heap(uptime, free),
                        json.dumps({"schema": 1, "kind": "attribution", "allocated": 200000, "tagged": 50000, "synthetic": 60000, "unattributed": 90000}),
                        json.dumps({"schema": 1, "kind": "lwip", "tcp_wnd": 5760}), "done>"]
        elif line == "members":
            uptime, free, steady = self.script[min(self.step, len(self.script) - 1)]
            self.step += 1
            self.out = [phases(7, steady), json.dumps({"schema": 1, "kind": "admission", "attempts": []}), "done>"]
        elif line == "memory bogus":
            self.out = ["ERR nope", "done>"]
        else:
            self.out = ["done>"]

    def readline(self):
        return (self.out.pop(0) + "\r\n").encode() if self.out else b""


def test_console():
    console = dongle_serial.Console(FakeLink([(1000, 50000, False)]))
    reports = console.json_command("memory")
    assert set(reports) == {"heap", "attribution", "lwip"} and reports["heap"][0]["free"] == 50000
    console.require_diagnostics()
    try:
        dongle_serial.Console(FakeLink([], diagnostics=False)).require_diagnostics()
        raise AssertionError("release firmware accepted")
    except dongle_serial.ConsoleError:
        pass
    try:
        console.json_command("memory bogus")
        raise AssertionError("ERR line ignored")
    except dongle_serial.ConsoleError:
        pass
    silent = dongle_serial.Console(type("L", (FakeLink,), {"write": lambda s, d: None})([]), command_timeout=0.2)
    try:
        silent.command("memory")
        raise AssertionError("missing prompt not detected")
    except dongle_serial.ConsoleError:
        pass


def capture(script, tmp, **kwargs):
    ticks = iter(range(0, 10000, 5))
    args = argparse.Namespace(port=None, label="1m", interval=5, until_steady=1, max_duration=100, out_dir=tmp, note="t", settled=False, **kwargs)
    return memory_ladder.capture(args, console=dongle_serial.Console(FakeLink(script)), sleep=lambda s: None, clock=lambda: next(ticks))


def test_capture():
    with tempfile.TemporaryDirectory() as tmp:
        path, summary = capture([(1000, 90000, False), (6000, 60000, False), (11000, 41000, True), (16000, 40000, True)], tmp)
        records = [json.loads(l) for l in path.read_text().splitlines()]
        assert [r["type"] for r in records] == ["meta", "sample", "sample", "sample", "sample", "summary"], [r["type"] for r in records]
        assert summary["free"] == 40000 and summary["lowest_free_sampled"] == 40000 and summary["unattributed"] == 90000
        assert summary["members"][0]["phases"]["steady"]["min"] == 31000 and "other" in summary["owners_live"]
        assert path.name.startswith("ladder-1m-") and path.suffix == ".jsonl"
        # A reboot between samples is recorded, and a run that never reaches steady stops at max_duration.
        path, summary = capture([(30000, 90000, False), (2000, 90000, False)], tmp)
        events = [json.loads(l) for l in path.read_text().splitlines() if '"event"' in l]
        assert [e["what"] for e in events] == ["device_reset", "max_duration"]


def test_compare():
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for free, largest in ((150000, 110000), (47000, 31000), (20000, 12000)):
            path, _ = capture([(1000, free, True), (6000, free, True)], tmp)
            data = [json.loads(l) for l in path.read_text().splitlines()]
            data[-1]["largest"] = largest
            path.write_text("\n".join(json.dumps(d) for d in data) + "\n")
            paths.append(path.with_name(f"{len(paths)}-{path.name}"))
            path.rename(paths[-1])
        rows = memory_ladder.compare(paths)
        assert [r["free_delta"] for r in rows] == [-103000, -27000] and [r["largest_delta"] for r in rows] == [-79000, -19000], rows


def test_throughput():
    assert tailnet_throughput.percentile(list(range(1, 101)), 0.5) == 50
    assert tailnet_throughput.percentile(list(range(1, 101)), 0.99) == 99
    assert tailnet_throughput.percentile([3, 1, 2], 0.99) == 3 and tailnet_throughput.percentile([7], 0.5) == 7
    assert tailnet_throughput.rtt_stats([]) is None
    calls = []

    def fake_iperf(args, extra):
        calls.append(extra)
        n = len(calls)
        return {"error": "refused"} if n == 4 else {"mbit_s": float(n)}

    tailnet_throughput.iperf = fake_iperf
    tailnet_throughput.measure_rtt = lambda args: ("tcp_connect", [10.0, 20.0, 30.0])
    args = argparse.Namespace(target="198.18.0.86", path="derp", label="q4", repeats=3, duration=1, udp_rate="4M", bind=None, iperf_port=5201)
    result = tailnet_throughput.run(args)
    assert len(result["runs"]) == 3 and calls[:3] == [[], ["-R"], ["-u"]]
    s = result["summary"]
    assert s["tcp_up"]["n"] == 2 and s["tcp_up"]["median_mbit_s"] == 4.0  # the failed run is excluded, not zeroed
    assert s["rtt"]["method"] == "tcp_connect" and s["rtt"]["n"] == 9 and s["rtt"]["p99_ms"] == 30.0
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            tailnet_throughput.main(["198.18.0.86", "--path", "direct", "--repeats", "2"])
        raise AssertionError("fewer than 3 repeats accepted")
    except SystemExit as e:
        assert e.code == 2


for test in (test_console, test_capture, test_compare, test_throughput):
    test()
print("Measurement scripts: serial framing, ladder capture/reset detection, marginal-cost compare, throughput statistics passed.")
