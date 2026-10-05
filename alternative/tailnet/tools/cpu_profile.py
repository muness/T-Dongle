#!/usr/bin/env python3
"""Per-task CPU share from two snapshots of the diagnostics build's `cpu` serial command.

  cpu_profile.py --duration 30                 # snapshot, wait 30 s, snapshot
  cpu_profile.py -- iperf3 -c 198.18.0.86 -t 20 # snapshot, run the command, snapshot
  cpu_profile.py --before a.json --after b.json # compare saved `cpu` lines (offline)

Prints % of ONE core per task (two cores: the figures sum to about 200), the CPU clock at both snapshots, and a
cross-check of the counter against the wall clock. Counters are raw and cumulative (32-bit, wrap handled), so any two
snapshots can be compared. Needs a build from tools/build-diagnostics.sh (trace facility and run-time stats on).
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from dongle_serial import Console, ConsoleError  # noqa: E402

WRAP = 1 << 32


def snapshot(console):
    reports = console.json_command("cpu").get("cpu")
    if not reports:
        raise ConsoleError("`cpu` returned nothing: flash a diagnostics image (tools/build-diagnostics.sh)")
    return reports[0]


def diff(a, b):
    """Task shares between two `cpu` reports. A task absent from `a` (started in between) counts from zero; one absent
    from `b` (exited) is omitted. Tasks are matched by name and core."""
    wall_us = (b["uptime_ms"] - a["uptime_ms"]) * 1000
    if wall_us <= 0:
        raise ValueError("snapshots are not in order (uptime did not advance; the device may have rebooted)")
    before = {(t["name"], t["core"]): t for t in a["tasks"]}
    rows = []
    for t in b["tasks"]:
        key = (t["name"], t["core"])
        base = before.get(key, {"runtime": 0})["runtime"]
        delta = (t["runtime"] - base) % WRAP
        rows.append({"name": t["name"], "core": t["core"], "priority": t["priority"], "stack_free": t["stack_free"],
                     "percent_of_core": 100.0 * delta / wall_us, "runtime_delta": delta})
    rows.sort(key=lambda r: -r["percent_of_core"])
    total_delta = (b["total"] - a["total"]) % WRAP
    return {"wall_ms": wall_us // 1000, "cpu_mhz": [a["cpu_mhz"], b["cpu_mhz"]],
            "counter_per_wall": total_delta / wall_us,       # about 1 (one shared time base) or the core count
            "busy_percent_of_cores": sum(r["percent_of_core"] for r in rows if not r["name"].startswith("IDLE")),
            "tasks": rows}


def render(result):
    lines = [f"wall {result['wall_ms']} ms, cpu_mhz {result['cpu_mhz'][0]} -> {result['cpu_mhz'][1]}, "
             f"counter/wall {result['counter_per_wall']:.2f}, non-idle {result['busy_percent_of_cores']:.1f}% of one core",
             f"{'task':<16}{'core':>5}{'prio':>6}{'% of 1 core':>13}{'stack free':>12}"]
    for r in result["tasks"]:
        lines.append(f"{r['name']:<16}{r['core']:>5}{r['priority']:>6}{r['percent_of_core']:>13.1f}{r['stack_free']:>12}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port")
    p.add_argument("--duration", type=float, help="seconds between snapshots when no command is given")
    p.add_argument("--before"), p.add_argument("--after")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run between the snapshots")
    args = p.parse_args(argv)
    if args.before or args.after:
        if not (args.before and args.after):
            p.error("--before and --after go together")
        a, b = (json.loads(pathlib.Path(f).read_text()) for f in (args.before, args.after))
    else:
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command and args.duration is None:
            p.error("give --duration, a command after --, or --before/--after")
        console = Console.open(args.port)
        try:
            a = snapshot(console)
            if command:
                subprocess.run(command, check=False)
            else:
                time.sleep(args.duration)
            b = snapshot(console)
        finally:
            console.close()
    try:
        result = diff(a, b)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    print(json.dumps(result) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
