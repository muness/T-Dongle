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
import cpu_profile  # noqa: E402
import inbound_accounting  # noqa: E402

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

    real_iperf = tailnet_throughput.iperf
    tailnet_throughput.iperf = fake_iperf
    tailnet_throughput.measure_rtt = lambda args: ("tcp_connect", [10.0, 20.0, 30.0])
    args = argparse.Namespace(target="198.18.0.86", path="derp", label="q4", repeats=3, duration=1, udp_rate="4M", bind=None, bind_dev=None, iperf_arg=None, iperf_port=5201)
    result = tailnet_throughput.run(args)
    assert len(result["runs"]) == 3 and calls[:3] == [[], ["-R"], ["-u"]]
    s = result["summary"]
    assert s["tcp_up"]["n"] == 2 and s["tcp_up"]["median_mbit_s"] == 4.0  # the failed run is excluded, not zeroed
    assert s["rtt"]["method"] == "tcp_connect" and s["rtt"]["n"] == 9 and s["rtt"]["p99_ms"] == 30.0
    # iperf3 command line: source address and passthrough options reach the client; a hung or missing iperf3 is an error entry, not a crash.
    import subprocess
    seen = []
    real_run = subprocess.run
    def fake_run(command, **kw):
        seen.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"error": "unable to connect"}), stderr="")
    subprocess.run = fake_run
    try:
        bound = argparse.Namespace(**{**vars(args), "bind": "192.168.77.2", "rtt_samples": 3, "iperf_arg": ["--cport", "5300"], "udp_rate": "4M"})
        out = real_iperf(bound, ["-u"])
        assert out == {"error": "unable to connect"}
        cmd = seen[0]
        assert cmd[cmd.index("-B") + 1] == "192.168.77.2" and cmd[cmd.index("-c") + 1] == "198.18.0.86" and "--cport" in cmd and "-b" in cmd, cmd
        def hang(command, **kw): raise subprocess.TimeoutExpired(command, 1)
        subprocess.run = hang
        assert "did not finish" in real_iperf(bound, [])["error"] and tailnet_throughput.icmp_rtt(bound) == []
        def missing(command, **kw): raise FileNotFoundError()
        subprocess.run = missing
        assert "not installed" in real_iperf(bound, [])["error"]
    finally:
        subprocess.run = real_run
    # A console that fails mid-run is recorded per snapshot; the run still completes.
    class Broken:
        def json_command(self, line): raise dongle_serial.ConsoleError("no done>")
    assert "error" in tailnet_throughput.device_snapshot(Broken())
    done = tailnet_throughput.run(args, Broken())
    assert len(done["runs"]) == 3 and "error" in done["summary"]["device"]
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            tailnet_throughput.main(["198.18.0.86", "--path", "direct", "--repeats", "2"])
        raise AssertionError("fewer than 3 repeats accepted")
    except SystemExit as e:
        assert e.code == 2


def cpu(uptime, total, rows, mhz=240):
    return {"schema": 1, "kind": "cpu", "uptime_ms": uptime, "cpu_mhz": mhz, "total": total, "cores": 2,
            "tasks": [{"name": n, "runtime": r, "priority": 5, "core": c, "stack_free": 900} for n, c, r in rows]}


def test_cpu_profile():
    a = cpu(1000, 1_000_000, [("IDLE0", 0, 500_000), ("IDLE1", 1, 600_000), ("ml_wg_mgr", 1, 10_000)], 80)
    # 10 s later: wg_mgr used 3.3 s, IDLE0 5.1 s; usb_routes appeared in between; the counter wrapped for IDLE1.
    b = cpu(11000, 11_000_000, [("IDLE0", 0, 5_600_000), ("IDLE1", 1, (600_000 + 4_600_000) % (1 << 32)),
                                ("ml_wg_mgr", 1, 3_310_000), ("usb_routes", 1, 3_200_000)])
    r = cpu_profile.diff(a, b)
    by = {t["name"]: t["percent_of_core"] for t in r["tasks"]}
    assert abs(by["IDLE0"] - 51.0) < 1e-6 and abs(by["ml_wg_mgr"] - 33.0) < 1e-6 and abs(by["usb_routes"] - 32.0) < 1e-6
    assert abs(by["IDLE1"] - 46.0) < 1e-6 and r["cpu_mhz"] == [80, 240] and r["tasks"][0]["name"] == "IDLE0"
    assert abs(r["counter_per_wall"] - 1.0) < 1e-6 and abs(r["busy_percent_of_cores"] - 65.0) < 1e-6
    wrapped = dict(b, total=(1 << 32) + 5)       # a 32-bit counter that wrapped between snapshots
    assert cpu_profile.diff(dict(a, total=(1 << 32) - 5), wrapped)["counter_per_wall"] > 0
    assert "ml_wg_mgr" in cpu_profile.render(r)
    try:
        cpu_profile.diff(b, a)
        raise AssertionError("out of order snapshots accepted")
    except ValueError:
        pass
    class Link:
        def json_command(self, line): return {"cpu": [a]} if line == "cpu" else {}
    assert cpu_profile.snapshot(Link())["uptime_ms"] == 1000
    class Empty:
        def json_command(self, line): return {}
    try:
        cpu_profile.snapshot(Empty())
        raise AssertionError("empty cpu report accepted")
    except dongle_serial.ConsoleError:
        pass

def test_inbound_accounting():
    from inbound_accounting import ML_LOSS, WG_LOSS, ROUTE_LOSS, USB_LOSS
    def snap(ml_extra=None, wg_extra=None, rt_extra=None, usb_extra=None, base=0):
        ml = {n: base for n in ["udp_rx", "udp_wg", "wg_in", "wg_to_wireguardif"] + ML_LOSS}
        wg = {n: base for n in ["rx_data", "rx_delivered"] + WG_LOSS}
        rt = {n: base for n in ["forwarded_in", "usb_tx"] + ROUTE_LOSS}
        usb = {n: base for n in ["tx_sent"] + USB_LOSS}
        ml.update(ml_extra or {}); wg.update(wg_extra or {}); rt.update(rt_extra or {}); usb.update(usb_extra or {})
        return {"inbound": {"lwip": {"udp_recv": ml["udp_rx"] + (ml_extra or {}).get("_mailbox", 0), "udp_drop": 0, "udp_memerr": 0, "udp_err": 0},
                            "ml": {k: v for k, v in ml.items() if k != "_mailbox"}, "wg": wg, "route": rt}, "usb": usb}
    before = snap()
    # The pre-fix board run: 3,133 sent, 3,228 arrived at lwIP (95 of them control), 2,927 reached USB, 2,905 received. Here the
    # mailbox ate 221 of the WireGuard datagrams and nothing else counted anything.
    after = snap({"udp_rx": 3007, "_mailbox": 221, "udp_wg": 3007 - 95, "wg_in": 2912, "wg_to_wireguardif": 2912},
                 {"rx_data": 2912, "rx_delivered": 2912}, {"forwarded_in": 2912, "usb_tx": 2927}, {"tx_sent": 2927})
    rows, summary = inbound_accounting.reconcile(before, after, 3133, 2905)
    assert summary["mailbox_loss"] == 221 and summary["counted_total"] == 0 and summary["end_to_end_loss"] == 228
    assert summary["unattributed"] == 7 and summary["loss_pct"] == 7.28           # 228 - 221: only the control/DNS noise is left
    text = inbound_accounting.render(rows, summary)
    assert "mailbox loss" in text and "unattributed 7" in text
    # After the fix: every counted drop is named, the mailbox loss is gone.
    after = snap({"udp_rx": 3228, "udp_wg": 3133, "q_wg_full": 4, "wg_in": 3129, "wg_to_wireguardif": 3129},
                 {"rx_data": 3129, "rx_delivered": 3120, "rx_replay_old": 9}, {"forwarded_in": 3120, "usb_tx": 3125, "reply_no_flow": 2}, {"tx_sent": 3125, "tx_dropped_full": 1})
    rows, summary = inbound_accounting.reconcile(before, after, 3133, 3120)
    assert summary["mailbox_loss"] == 0 and summary["counted_losses"] == {"ml.q_wg_full": 4, "wg.rx_replay_old": 9, "route.reply_no_flow": 2, "usb.tx_dropped_full": 1}
    assert summary["counted_total"] == 16 and summary["end_to_end_loss"] == 13 and summary["unattributed"] == -3
    assert inbound_accounting.reconcile(before, after)[1].get("end_to_end_loss") is None   # sent/received are optional
    class Link:
        def json_command(self, line):
            return {"inbound": [after["inbound"]]} if line == "inbound" else {"usb": [after["usb"]], "heap": [{"uptime_ms": 1, "free": 2, "min": 3, "largest": 4}]}
    assert inbound_accounting.snapshot(Link())["usb"]["tx_sent"] == 3125
    assert "lwip_stats" not in inbound_accounting.snapshot(Link()) and "wgperf" not in inbound_accounting.snapshot(Link())   # firmware without the commands

    # ADR 0022: the USB IN pipe and the heap minimum, from the usb counters and `memory low`.
    drain_before = snap(base=0); drain_after = snap({"udp_rx": 100, "udp_wg": 100, "wg_in": 100, "wg_to_wireguardif": 100}, usb_extra={"tx_sent": 200})
    drain_before["usb"].update({"ntb_xfers": 0, "ntb_zlp": 0, "ntb_bytes": 0, "gap_count": 0, "gap_us_sum": 0, "gap_us_max": 0, "cold_starts": 0, "cold_us_sum": 0, "cold_us_max": 0,
                                "drains_sent": [0] * 5, "gap_hist_ms": [0] * 5, "tx_worker_demotions": 0, "rx_dropped_heap": 0})
    drain_after["usb"].update({"ntb_xfers": 100, "ntb_zlp": 2, "ntb_bytes": 254000, "gap_count": 99, "gap_us_sum": 7400 * 99, "gap_us_max": 21000, "cold_starts": 10, "cold_us_sum": 12000,
                               "cold_us_max": 5000, "drains_sent": [3, 90, 4, 2, 1], "gap_hist_ms": [0, 10, 20, 60, 9], "tx_worker_demotions": 3, "rx_dropped_heap": 5})
    drain_after["heap"] = {"uptime_ms": 9, "free": 30000, "min": 17000, "largest": 20000}
    drain_after["heap_low"] = {"floor": 29884, "reserve": 16384, "free_hi": 37000, "events": 1, "records": [
        {"uptime_ms": 9000, "min": 17000, "free": 18000, "largest": 9000, "tx_ring": 7620, "tx_elastic": 3048, "wgq": 5000, "rx_inflight": 2, "packet_live": 1000,
         "wifi_rx_pins": 4, "wifi_tx_inflight": 1}]}
    rows, summary = inbound_accounting.reconcile(drain_before, drain_after, 100, 100)
    d = summary["usb_drain"]
    assert d["ntb_xfers"] == 100 and d["mean_ntb_bytes"] == 2540 and d["frames_per_ntb"] == 2.0 and d["gap_mean_ms"] == 7.4 and d["wake_latency_ms"] > 4.5
    assert d["cold_start_mean_ms"] == 1.2 and d["drains_sent"] == [3, 90, 4, 2, 1] and summary["usb_rx_refused_for_heap"] == 5 and summary["heap_min_free"] == 17000
    text = inbound_accounting.render(rows, summary)
    assert "USB IN pipe: 100 NTBs" in text and "wake latency about" in text and "unexplained" in text and "dropped 19000 B from the peak" in text
    # The wg queue is part of packet_live (its datagrams are packet blocks): 19,000 - (3,048 elastic + 2 x 1,534 usb frames + 1,000 packets) = 11,884, not 6,884.
    assert "unexplained (Wi-Fi buffers pinned by sockets, lwIP) 11884" in text and "wg queue 5000 of them" in text
    assert "Wi-Fi buffers pinned: 4 RX, 1 TX in flight (~8320 B at full size)" in text
    # lwIP's udp.recv is 16 bits wide and wraps: a run that crosses the wrap must not show a negative (or huge) mailbox loss.
    wrap_before, wrap_after = snap(base=0), snap({"udp_rx": 1000, "udp_wg": 990, "wg_in": 990, "wg_to_wireguardif": 990}, {"rx_data": 990, "rx_delivered": 990}, {"forwarded_in": 990, "usb_tx": 990}, {"tx_sent": 990})
    wrap_before["inbound"]["lwip"]["udp_recv"] = 65000
    wrap_before["inbound"]["counter_bits"] = wrap_after["inbound"]["counter_bits"] = 16
    wrap_after["inbound"]["lwip"]["udp_recv"] = (65000 + 1000 + 7) % 65536
    rows, summary = inbound_accounting.reconcile(wrap_before, wrap_after, 1000, 990)
    assert summary["mailbox_loss"] == 7, summary
    wrap_before["inbound"]["counter_bits"] = wrap_after["inbound"]["counter_bits"] = 32       # a 32-bit build: the same numbers, no wrap involved
    wrap_before["inbound"]["lwip"]["udp_recv"] = 70000; wrap_after["inbound"]["lwip"]["udp_recv"] = 71007
    assert inbound_accounting.reconcile(wrap_before, wrap_after, 1000, 990)[1]["mailbox_loss"] == 7
    # firmware that does not report the width (the base image): 16 bits is right for any run of fewer than 65,536 datagrams
    del wrap_before["inbound"]["counter_bits"]; del wrap_after["inbound"]["counter_bits"]
    wrap_before["inbound"]["lwip"]["udp_recv"] = 65000; wrap_after["inbound"]["lwip"]["udp_recv"] = 471
    assert inbound_accounting.reconcile(wrap_before, wrap_after, 1000, 990)[1]["mailbox_loss"] == 7

    # Where the missing datagrams went BEFORE net_io: the sender made 3,137, 3,045 reached net_io. The mailbox and lwIP's own
    # counters are named; what is left is the air, the access point and the driver.
    b = snap(); b["lwip_stats"] = {"counter_bits": 16, "proto": {"link": {"drop": 65530, "recv": 0}, "ip": {"drop": 3, "chkerr": 0}}, "pool": {"PBUF": {"err": 4}}}
    a = snap({"udp_rx": 3045, "_mailbox": 11, "udp_wg": 3045, "wg_in": 3045, "wg_to_wireguardif": 3045}, {"rx_data": 3045, "rx_delivered": 3045}, {"forwarded_in": 3045, "usb_tx": 3045}, {"tx_sent": 3045})
    a["lwip_stats"] = {"counter_bits": 16, "proto": {"link": {"drop": 4, "recv": 0}, "ip": {"drop": 3, "chkerr": 0}}, "pool": {"PBUF": {"err": 4}}}
    rows, summary = inbound_accounting.reconcile(b, a, 3137, 3045)
    assert summary["before_net_io"] == 92 and summary["mailbox_loss"] == 11 and summary["before_lwip_udp"] == 81, summary
    assert summary["lwip_drops"] == {"link.drop": 10}, summary["lwip_drops"]      # 65530 -> 4 across the wrap
    text = inbound_accounting.render(rows, summary)
    assert "lost before net_io" in text and "link.drop" in text

    # wgperf: cycles per datagram, run sizes, queue depth, lock holds
    def perf(scale=1):
        names = ["q_latency", "lock_wait", "lock_hold", "rx_pkt", "rx_prep", "rx_begin", "rx_decrypt", "rx_complete", "rx_route", "rx_deliver", "rx_run", "rx_qdepth", "rt_check", "rt_lock_wait", "rt_emit", "batch"]
        units = ["us", "cy", "cy", "cy", "cy", "cy", "cy", "cy", "cy", "cy", "pkt", "pkt", "cy", "cy", "cy", "pkt"]
        st = {n: [0, 0, 0] for n in names}
        st["rx_pkt"] = [100 * scale, 100 * scale * 8 * 100000, 900000]
        st["rx_decrypt"] = [100 * scale, 100 * scale * 8 * 78000, 700000]
        st["rx_run"] = [100 * scale, 100 * scale * 8, 8]
        st["rx_qdepth"] = [60 * scale, 60 * scale * 5, 12]
        st["lock_hold"] = [200 * scale, 200 * scale * 20000, 90000]
        return {"elapsed_ms": 10000 * scale, "cpu_mhz": 240, "stages": st, "units": units, "counters": {"in_pkts": 800 * scale, "rx_runs": 100 * scale, "rx_runs_full": 90 * scale, "rx_runs_cut": 2 * scale, "passes": 50 * scale}}
    a2 = snap(); a2["wgperf"] = perf()
    rows, summary = inbound_accounting.reconcile(snap(), a2, None, None)
    w = summary["wgperf"]
    assert w["datagrams"] == 800 and w["cycles_per_datagram"] == {"rx_pkt": 100000, "rx_decrypt": 78000}, w
    assert w["run_mean"] == 8.0 and w["run_max"] == 8 and w["queue_depth_mean"] == 5.0 and w["queue_depth_max"] == 12 and w["lock_hold"]["mean_cy"] == 20000
    assert "inbound cost per datagram, 800 datagrams" in inbound_accounting.render(rows, summary) and "rx_decrypt" in inbound_accounting.render(rows, summary)
    b2 = snap(); b2["wgperf"] = perf(1)
    a3 = snap(); a3["wgperf"] = perf(3)                                          # no reset in between: the run is the difference
    w = inbound_accounting.reconcile(b2, a3, None, None)[1]["wgperf"]
    assert w["datagrams"] == 1600 and w["cycles_per_datagram"]["rx_pkt"] == 100000, w
    class PerfLink:
        def __init__(self): self.sent = []
        def command(self, line): self.sent.append(line); return []
        def json_command(self, line):
            if line == "wgperf": return {"wgperf": [perf()]}
            if line == "wifistats": return {"lwip_stats": [{"enabled": 1, "counter_bits": 16}], "lwip_proto": [{"name": "link", "recv": 5, "xmit": 6, "drop": 7}], "lwip_pool": [{"name": "PBUF", "err": 2}, {"name": "TCP_PCB", "err": 9}]}
            return Link().json_command(line)
    link = PerfLink()
    got = inbound_accounting.snapshot(link, wgperf=True, reset_wgperf=True)
    assert link.sent == ["wgperf reset"] and got["wgperf"]["counters"]["in_pkts"] == 800
    assert got["lwip_stats"] == {"counter_bits": 16, "proto": {"link": {"recv": 5, "xmit": 6, "drop": 7, "chkerr": 0, "lenerr": 0, "memerr": 0, "err": 0}}, "pool": {"PBUF": {"err": 2}}}, got["lwip_stats"]


for test in (test_console, test_capture, test_compare, test_throughput, test_cpu_profile, test_inbound_accounting):
    test()
print("Measurement scripts: serial framing, ladder capture/reset detection, per-task CPU shares, marginal-cost compare, throughput statistics, inbound accounting passed.")
