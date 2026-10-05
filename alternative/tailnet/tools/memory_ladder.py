#!/usr/bin/env python3
"""Capture the diagnostics build's memory reports over the serial console.

  memory_ladder.py capture --label 1m --until-steady 1     # one run at one membership count
  memory_ladder.py compare run0.jsonl run1.jsonl run2.jsonl # marginal cost 0->1, 1->2

The ladder is: flash the diagnostics image, then capture at 0, 1 and 2 enabled memberships (enable the
second one after the first is steady; the override lets it start past the budget). Each capture writes
<out-dir>/ladder-<label>-<UTC>.jsonl: a meta record, one sample per interval and a closing summary.
"""
import argparse
import datetime
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from dongle_serial import Console, ConsoleError  # noqa: E402

DEFAULT_OUT = pathlib.Path(__file__).resolve().parents[1] / "docs" / "diagnostics"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def sample(console):
    """One snapshot: every report the `memory` and `members` commands print."""
    reports = console.json_command("memory")
    reports.update(console.json_command("members"))
    return reports


def steady_members(reports):
    return sum(1 for p in reports.get("phases", []) if "steady" in p.get("phases", {}))


def summarize(samples):
    """Final state plus the lowest point seen in any sample."""
    heap = [s["reports"]["heap"][0] for s in samples if "heap" in s["reports"]]
    if not heap:
        return {"samples": 0}
    last = samples[-1]["reports"]
    summary = {
        "samples": len(samples),
        "free": heap[-1]["free"],
        "largest": heap[-1]["largest"],
        "min": heap[-1]["min"],
        "lowest_free_sampled": min(h["free"] for h in heap),
        "lowest_largest_sampled": min(h["largest"] for h in heap),
        "owners_live": {name: o["live"] for name, o in heap[-1]["owners"].items()},
        "owners_peak": {name: o["peak"] for name, o in heap[-1]["owners"].items()},
        "underflows": heap[-1]["underflows"],
    }
    if "attribution" in last and "unattributed" in last["attribution"][0]:
        a = last["attribution"][0]
        summary.update(allocated=a["allocated"], tagged=a["tagged"], synthetic=a["synthetic"], unattributed=a["unattributed"])
    summary["members"] = [
        {"member": p["member"], "attempt": p["attempt"], "phases": p["phases"]} for p in last.get("phases", [])
    ]
    if "admission" in last:
        summary["admission"] = last["admission"][0]["attempts"]
    return summary


def capture(args, console=None, sleep=time.sleep, clock=time.monotonic):
    owned = console is None
    console = console or Console.open(args.port)
    try:
        return _capture(args, console, sleep, clock)
    finally:
        if owned:
            console.close()


def _capture(args, console, sleep, clock):
    console.require_diagnostics()
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"ladder-{args.label}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}.jsonl"
    samples, started, last_uptime = [], clock(), 0
    with path.open("w") as out:
        def emit(record):
            out.write(json.dumps(record, separators=(",", ":")) + "\n")
            out.flush()

        emit({"type": "meta", "host_time": now_iso(), "label": args.label, "note": args.note,
              "interval_s": args.interval, "until_steady": args.until_steady, "port": args.port,
              "capabilities": console.command("capabilities")})
        while True:
            try:
                reports = sample(console)
            except ConsoleError as error:
                emit({"type": "event", "host_time": now_iso(), "what": "console_error", "detail": str(error)})
                if clock() - started > args.max_duration:
                    break
                sleep(args.interval)
                continue
            uptime = reports.get("heap", [{}])[0].get("uptime_ms", 0)
            if uptime < last_uptime:
                emit({"type": "event", "host_time": now_iso(), "what": "device_reset", "detail": f"uptime {last_uptime} -> {uptime}"})
            last_uptime = uptime
            record = {"type": "sample", "host_time": now_iso(), "elapsed_s": round(clock() - started, 1), "reports": reports}
            samples.append(record)
            emit(record)
            done = args.until_steady and steady_members(reports) >= args.until_steady
            if done and not args.settled:
                args.settled = True  # one more sample after steady so the final numbers are post-join
            elif done:
                break
            if clock() - started > args.max_duration:
                emit({"type": "event", "host_time": now_iso(), "what": "max_duration", "detail": str(args.max_duration)})
                break
            sleep(args.interval)
        summary = summarize(samples)
        emit({"type": "summary", "host_time": now_iso(), **summary})
    return path, summary


def load_summary(path):
    last = None
    for line in pathlib.Path(path).read_text().splitlines():
        record = json.loads(line)
        if record.get("type") == "summary":
            last = record
    if not last or not last.get("samples"):
        raise ConsoleError(f"{path} has no usable summary")
    return last


def compare(paths):
    """Marginal cost between consecutive runs: negative free/largest deltas are the cost of the added membership."""
    runs = [load_summary(p) for p in paths]
    rows = []
    for earlier, later, a, b in zip(paths, paths[1:], runs, runs[1:]):
        row = {"from": str(earlier), "to": str(later),
               "free_delta": b["free"] - a["free"], "largest_delta": b["largest"] - a["largest"],
               "unattributed_delta": b.get("unattributed", 0) - a.get("unattributed", 0),
               "owners_live_delta": {k: b["owners_live"].get(k, 0) - a["owners_live"].get(k, 0) for k in b["owners_live"]},
               "lowest_free_during_run": b["lowest_free_sampled"]}
        rows.append(row)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    cap = sub.add_parser("capture", help="snapshot the memory reports at an interval")
    cap.add_argument("--port", help="serial device (default: the only usbmodem/ttyACM port)")
    cap.add_argument("--label", required=True, help="run name, e.g. 0m, 1m, 2m, storm")
    cap.add_argument("--interval", type=float, default=5.0, help="seconds between samples")
    cap.add_argument("--until-steady", type=int, default=0, metavar="N",
                     help="stop one sample after N memberships have reached the steady phase")
    cap.add_argument("--max-duration", type=float, default=300.0, help="give up after this many seconds")
    cap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    cap.add_argument("--note", default="", help="free text stored in the meta record")
    cap.set_defaults(settled=False)
    cmp_ = sub.add_parser("compare", help="marginal cost between consecutive capture files")
    cmp_.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    if args.mode == "capture":
        try:
            path, summary = capture(args)
        except (ConsoleError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(f"wrote {path}")
        print(json.dumps({k: v for k, v in summary.items() if k not in ("members", "admission")}, indent=1))
        return 0
    if len(args.files) < 2:
        parser.error("compare needs at least two capture files")
    print(json.dumps(compare(args.files), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
