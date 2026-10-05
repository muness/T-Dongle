#!/usr/bin/env python3
"""Tailnet throughput and latency through the dongle (issue #10 baseline).

  tailnet_throughput.py 198.18.0.86 --path direct --bind 192.168.77.2 --serial /dev/cu.usbmodem1101

TARGET is the reference peer as the USB host reaches it (the dongle's alias address); run `iperf3 -s`
there first. --path only labels the result: the dongle chooses the path, so make it true yourself
(direct: both ends on one LAN; derp: run the peer's tailscaled with TS_DEBUG_ALWAYS_USE_DERP=1 or block
its UDP) and confirm with `tailscale ping` on the peer. Every test runs --repeats times (at least 3).

Per repeat: TCP up, TCP down (-R), UDP up at --udp-rate, then RTT. RTT uses ICMP when the tailnet path
answers it (the gateway is TCP/UDP only today, so it usually does not) and falls back to timing TCP
connects to the iperf3 port. With --serial the diagnostics build's heap, drop counters and queue depths
are snapshotted before and after every repeat, so the sweep over queue depths 1/2/4/8 reads from one file.
"""
import argparse
import datetime
import json
import pathlib
import re
import socket
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from dongle_serial import Console, ConsoleError  # noqa: E402

DEFAULT_OUT = pathlib.Path(__file__).resolve().parents[1] / "docs" / "diagnostics"
TESTS = (("tcp_up", []), ("tcp_down", ["-R"]), ("udp_up", ["-u"]))


def percentile(values, fraction):
    """Nearest-rank percentile; p99 of fewer than 100 samples is the maximum."""
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * fraction // 1))
    return ordered[int(min(rank, len(ordered))) - 1]


def rtt_stats(samples):
    if not samples:
        return None
    return {"n": len(samples), "min_ms": min(samples), "p50_ms": percentile(samples, 0.5),
            "p99_ms": percentile(samples, 0.99), "max_ms": max(samples)}


def iperf(args, extra):
    command = ["iperf3", "-c", args.target, "-p", str(args.iperf_port), "-t", str(args.duration), "-J"] + extra
    if args.bind:
        command += ["-B", args.bind]
    if "-u" in extra:
        command += ["-b", args.udp_rate]
    done = subprocess.run(command, capture_output=True, text=True, timeout=args.duration + 30)
    try:
        report = json.loads(done.stdout)
    except json.JSONDecodeError:
        return {"error": (done.stderr or done.stdout).strip()[:300]}
    if "error" in report:
        return {"error": report["error"]}
    end = report["end"]
    if "-u" in extra:
        s = end["sum"]
        return {"mbit_s": s["bits_per_second"] / 1e6, "lost_percent": s.get("lost_percent"), "jitter_ms": s.get("jitter_ms")}
    sent, received = end["sum_sent"], end["sum_received"]
    return {"mbit_s": received["bits_per_second"] / 1e6, "retransmits": sent.get("retransmits")}


def icmp_rtt(args):
    command = ["ping", "-c", str(args.rtt_samples), "-i", "0.2", "-W", "1000" if sys.platform == "darwin" else "1"]
    if args.bind:
        command += ["-S" if sys.platform == "darwin" else "-I", args.bind]
    done = subprocess.run(command + [args.target], capture_output=True, text=True, timeout=args.rtt_samples * 2 + 20)
    return [float(m) for m in re.findall(r"time[=<]([0-9.]+) ms", done.stdout)]


def tcp_rtt(args):
    """Connect time to the iperf3 port is one round trip (SYN, SYN-ACK)."""
    samples = []
    for _ in range(args.rtt_samples):
        s = socket.socket()
        s.settimeout(2)
        if args.bind:
            s.bind((args.bind, 0))
        started = time.perf_counter()
        try:
            s.connect((args.target, args.iperf_port))
            samples.append((time.perf_counter() - started) * 1000)
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(0.05)
    return samples


def measure_rtt(args):
    if args.rtt in ("auto", "icmp"):
        samples = icmp_rtt(args)
        if samples or args.rtt == "icmp":
            return "icmp", samples
    return "tcp_connect", tcp_rtt(args)


def device_snapshot(console):
    if not console:
        return None
    reports = console.json_command("memory")
    heap = reports["heap"][0]
    return {"uptime_ms": heap["uptime_ms"], "free": heap["free"], "min": heap["min"], "largest": heap["largest"],
            "drops": heap["drops"], "queue_depth": heap["queue_depth"],
            "owners_peak": {k: v["peak"] for k, v in heap["owners"].items()}}


def run(args, console=None):
    runs, all_rtt, rtt_kind = [], [], None
    for repeat in range(args.repeats):
        record = {"repeat": repeat + 1, "before": device_snapshot(console)}
        for name, extra in TESTS:
            record[name] = iperf(args, extra)
        kind, samples = measure_rtt(args)
        rtt_kind = rtt_kind or kind
        all_rtt += samples
        record["rtt"] = rtt_stats(samples)
        record["after"] = device_snapshot(console)
        runs.append(record)
    summary = {}
    for name, _ in TESTS:
        values = [r[name]["mbit_s"] for r in runs if "mbit_s" in r[name]]
        summary[name] = ({"n": len(values), "median_mbit_s": statistics.median(values), "min_mbit_s": min(values), "max_mbit_s": max(values)}
                         if values else {"n": 0, "errors": [r[name].get("error") for r in runs]})
    summary["rtt"] = {"method": rtt_kind, **(rtt_stats(all_rtt) or {"n": 0})}
    if console:
        first, last = runs[0]["before"], runs[-1]["after"]
        summary["device"] = {"min_free_during": min(min(r["before"]["free"], r["after"]["free"]) for r in runs),
                             "min_since_boot": last["min"], "queue_depth": last["queue_depth"],
                             "drops_delta": {k: last["drops"][k] - first["drops"][k] for k in last["drops"]},
                             "reset": last["uptime_ms"] < first["uptime_ms"]}
    return {"meta": {"host_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                     "target": args.target, "path": args.path, "label": args.label, "repeats": args.repeats,
                     "duration_s": args.duration, "udp_rate": args.udp_rate, "bind": args.bind},
            "runs": runs, "summary": summary}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", help="reference peer address as seen from the USB host")
    p.add_argument("--path", required=True, choices=("direct", "derp"), help="which path you arranged (label only)")
    p.add_argument("--label", default="", help="free text, e.g. queue depth 4")
    p.add_argument("--repeats", type=int, default=3, help="runs per test (minimum 3)")
    p.add_argument("--duration", type=int, default=10, help="seconds per iperf3 run")
    p.add_argument("--udp-rate", default="4M", help="offered UDP load, iperf3 -b syntax")
    p.add_argument("--iperf-port", type=int, default=5201)
    p.add_argument("--bind", help="local address to bind (the host's USB address)")
    p.add_argument("--rtt", choices=("auto", "icmp", "tcp"), default="auto")
    p.add_argument("--rtt-samples", type=int, default=100)
    p.add_argument("--serial", help="diagnostics-build console port for heap and drop snapshots")
    p.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = p.parse_args(argv)
    if args.repeats < 3:
        p.error("--repeats must be at least 3")
    console = None
    if args.serial:
        try:
            console = Console.open(args.serial)
            console.require_diagnostics()
        except (ConsoleError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    result = run(args, console)
    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"throughput-{args.path}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}.json"
    path.write_text(json.dumps(result, indent=1) + "\n")
    print(f"wrote {path}")
    print(json.dumps(result["summary"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
