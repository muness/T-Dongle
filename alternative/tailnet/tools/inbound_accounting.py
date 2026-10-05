#!/usr/bin/env python3
"""Where did the inbound datagrams go? Reconcile a UDP `iperf3 -R` run hop by hop from the dongle's cumulative counters.

Diagnostics build only (serial `inbound`, `route` and `memory`; docs/adr/0019-inbound-loss.md). Two steps around the run:

    tools/inbound_accounting.py snapshot before.json [--port /dev/cu.usbmodemXXXX] [--reset-wgperf]
    iperf3 -c <dongle tailnet ip> -u -b 3M -l 1200 -t 10 -R            # on the host; note datagrams sent and received
    tools/inbound_accounting.py snapshot after.json  [--port ...] [--wgperf]
    tools/inbound_accounting.py diff before.json after.json --sent 3133 --received 2905

`--reset-wgperf` zeroes the per-stage cycle counters at the start of the run and `--wgperf` stores them at the end, so the diff also
prints what the inbound path costs per datagram (docs/adr/0020-inbound-pipeline.md): cycles per stage, datagrams per run, how deep
the queue was when wg_mgr started draining, and how long it held the lwIP core lock. `wifistats` (lwIP link / IP / UDP drops and
pool errors) is stored too when the firmware has it, so the loss BEFORE the socket can be told apart: anything lwIP counts is
named, what is left between the sender and lwIP's UDP receive is the air, the access point and the Wi-Fi driver (ESP-IDF
v5.5.5 exposes no driver RX counters).

The diff prints every hop (a delta of a cumulative counter, so other traffic shows up in it: run it on a quiet gateway) and the
sum of every counted loss. A healthy run has `unattributed` near zero and `mailbox` (lwIP's uncounted socket-mailbox loss,
udp_recv - udp_rx) near the number of non-net_io UDP datagrams (DNS), i.e. a handful.
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from dongle_serial import Console  # noqa: E402

# Counters that are a datagram leaving the path without being delivered, by layer.
ML_LOSS = ["udp_rx_empty", "udp_unclassified", "udp_alloc_fail", "q_wg_full", "derp_q_wg_full", "q_wg_bytes", "q_wg_heap", "wg_sender_unknown", "wg_no_netif", "wg_pbuf_fail"]
WG_LOSS = ["rx_no_peer", "rx_keypair_unusable", "rx_expired", "rx_alloc_fail", "rx_session_gone", "rx_decrypt_fail",
           "rx_replay_dup", "rx_replay_old", "rx_replay_limit", "rx_bad_ip", "rx_allowed_ip", "rx_allowed_ip6", "rx_bad_length", "rx_ipv6_unsupported", "rx_input_fail"]
ROUTE_LOSS = ["tunnel_malformed", "tunnel_nomem", "bad_packet", "reply_no_member", "reply_not_us", "reply_flow_range", "reply_no_flow",
              "reply_generation", "reply_owner", "reply_idle", "usb_tx_err", "tx_fail"]
USB_LOSS = ["tx_dropped_full", "tx_dropped_link_down", "tx_dropped_invalid", "tx_flushed_link_down"]


# lwIP's own drop counters, by protocol: what lwIP itself discards BEFORE a datagram reaches a socket.
LWIP_PROTO_DROPS = {"link": ["drop", "chkerr", "lenerr", "memerr", "err"], "etharp": ["drop", "memerr"], "ip": ["drop", "chkerr", "lenerr", "memerr", "proterr", "rterr"],
                    "udp": ["drop", "chkerr", "lenerr", "memerr", "proterr", "err"]}
LWIP_POOL_ERRORS = ["PBUF", "PBUF_POOL", "MEM"]


def snapshot(console, wgperf=False, reset_wgperf=False):
    if reset_wgperf:
        console.command("wgperf reset")
    inbound = console.json_command("inbound")["inbound"][0]
    memory = console.json_command("memory")
    data = {"inbound": inbound, "usb": memory["usb"][0], "heap": {k: memory["heap"][0][k] for k in ("uptime_ms", "free", "min", "largest")}}
    try:
        stats = console.json_command("wifistats")
        meta = (stats.get("lwip_stats") or [{}])[0]
        if meta.get("enabled"):
            data["lwip_stats"] = {"counter_bits": meta.get("counter_bits", 16),
                                  "proto": {r["name"]: {k: r.get(k, 0) for k in ["recv", "xmit"] + LWIP_PROTO_DROPS.get(r["name"], [])} for r in stats.get("lwip_proto", [])},
                                  "pool": {r["name"]: {"err": r.get("err", 0)} for r in stats.get("lwip_pool", []) if r["name"] in LWIP_POOL_ERRORS}}
    except Exception:  # older firmware, or a build without the command: the rest of the snapshot stands
        pass
    if wgperf:
        report = console.json_command("wgperf").get("wgperf")
        if report:
            data["wgperf"] = report[0]
    return data


def delta(before, after, layer, name):
    """A counter that moved. A counter the older firmware does not have reads 0 on both sides."""
    return after["inbound"][layer].get(name, 0) - before["inbound"][layer].get(name, 0)


def wrap_delta(after, before, bits):
    """Difference of two readings of a counter that wraps at 2**bits (lwIP's are 16 bits unless LWIP_STATS_LARGE)."""
    return (after - before) % (1 << bits)


def lwip_drops(before, after):
    """lwIP's own drop and error counters that moved during the run (the loss lwIP admits to, ahead of the socket)."""
    a, b = after.get("lwip_stats"), before.get("lwip_stats")
    if not a or not b:
        return {}
    bits = a.get("counter_bits") or 16
    moved = {}
    for proto, fields in LWIP_PROTO_DROPS.items():
        for field in fields:
            value = wrap_delta(a["proto"].get(proto, {}).get(field, 0), b["proto"].get(proto, {}).get(field, 0), bits)
            if value:
                moved[f"{proto}.{field}"] = value
    for pool in LWIP_POOL_ERRORS:
        value = wrap_delta(a["pool"].get(pool, {}).get("err", 0), b["pool"].get(pool, {}).get("err", 0), 32)
        if value:
            moved[f"pool.{pool}.err"] = value
    return moved


# What the inbound path costs per datagram, from `wgperf` (cumulative since `wgperf reset`).
RX_STAGES = ["rx_pkt", "rx_prep", "rx_begin", "rx_decrypt", "rx_complete", "rx_route", "rx_deliver", "rt_check", "rt_lock_wait", "rt_emit"]


def wgperf_summary(before, after):
    w = after.get("wgperf")
    if not w:
        return {}
    stages = {k: list(v) for k, v in w["stages"].items()}
    counters = dict(w["counters"])
    b = before.get("wgperf")
    if b and b.get("elapsed_ms", 0) <= w.get("elapsed_ms", 0) and b["counters"].get("passes", 0) <= counters.get("passes", 0):   # no reset in between: subtract
        for k, v in stages.items():
            if k in b["stages"]:
                v[0] -= b["stages"][k][0]
                v[1] -= b["stages"][k][1]
        for k in counters:
            counters[k] -= b["counters"].get(k, 0)
    packets = counters.get("in_pkts", 0)
    out = {"datagrams": packets, "elapsed_ms": w.get("elapsed_ms"), "cycles_per_datagram": {}, "units": dict(zip(w["stages"], w.get("units", [])))}
    if packets:
        for name in RX_STAGES:
            if name in stages and stages[name][0] and out["units"].get(name) == "cy":
                out["cycles_per_datagram"][name] = round(stages[name][1] / packets)
    run = stages.get("rx_run")
    if run and run[0]:
        out["run_mean"] = round(run[1] / run[0], 2)
        out["run_max"] = run[2]
        out["runs"] = run[0]
    depth = stages.get("rx_qdepth")
    if depth and depth[0]:
        out["queue_depth_mean"] = round(depth[1] / depth[0], 2)
        out["queue_depth_max"] = depth[2]
    for name in ("lock_wait", "lock_hold"):
        if name in stages and stages[name][0]:
            out[name] = {"count": stages[name][0], "mean_cy": round(stages[name][1] / stages[name][0]), "max_cy": stages[name][2]}
    out["counters"] = {k: counters[k] for k in ("in_pkts", "rx_runs", "rx_runs_full", "rx_runs_cut") if k in counters}
    return out


def reconcile(before, after, sent=None, received=None):
    """Returns (rows, summary): rows are (label, value, note); summary is a dict of the totals."""
    ml = lambda n: delta(before, after, "ml", n)          # noqa: E731
    wg = lambda n: delta(before, after, "wg", n)          # noqa: E731
    rt = lambda n: delta(before, after, "route", n)       # noqa: E731
    bits = after["inbound"].get("counter_bits") or before["inbound"].get("counter_bits") or 16   # a delta below 65,536 is the same modulo 2**16 and 2**32
    lw = lambda n: wrap_delta(after["inbound"]["lwip"][n], before["inbound"]["lwip"][n], bits)  # noqa: E731
    usb = lambda n: after["usb"][n] - before["usb"][n]    # noqa: E731
    mailbox = lw("udp_recv") - ml("udp_rx")
    rows = []
    if sent is not None:
        rows.append(("sent by iperf3", sent, "datagrams the sender reports"))
    rows += [
        ("lwip udp_recv", lw("udp_recv"), "every UDP datagram lwIP accepted, counted before the socket mailbox"),
        ("net_io udp_rx", ml("udp_rx"), "read from the sockets by net_io"),
        ("  drains >= 4 deep", ml("drain_deep"), f"of {ml('drain_calls')} drains: the mailbox (6 slots) was within two datagrams of the silent overflow"),
        ("mailbox loss", mailbox, "udp_recv - udp_rx: lwIP's uncounted drop (plus a few non-net_io datagrams, DNS); must be ~0"),
        ("net_io -> wg_rx_queue", ml("udp_wg"), "classified WireGuard"),
        ("  queue full", ml("q_wg_full") + ml("derp_q_wg_full"), "wg_rx_queue overflow (was invisible without diagnostics)"),
        ("wg_mgr took", ml("wg_in"), "off the queue (includes DERP and handshakes)"),
        ("-> wireguardif", ml("wg_to_wireguardif"), "after sender admission, netif and pbuf checks"),
        ("wireguard rx_data", wg("rx_data"), "transport datagrams in the receive path"),
        ("  delivered", wg("rx_delivered"), "to the router"),
        ("router forwarded_in", rt("forwarded_in"), "rewritten and handed to the USB netif"),
        ("usb_tx frames", rt("usb_tx"), "every frame the USB netif transmit saw (includes ARP, DNS)"),
        ("usb tx_sent", usb("tx_sent"), "frames copied into an NTB"),
    ]
    if received is not None:
        rows.append(("received by host", received, "datagrams the receiver reports"))
    losses = {}
    for layer, names in (("ml", ML_LOSS), ("wg", WG_LOSS), ("route", ROUTE_LOSS)):
        for name in names:
            value = delta(before, after, layer, name)
            if value:
                losses[f"{layer}.{name}"] = value
    for name in USB_LOSS:
        if usb(name):
            losses[f"usb.{name}"] = usb(name)
    counted = sum(losses.values())
    summary = {"mailbox_loss": mailbox, "counted_losses": losses, "counted_total": counted, "delivered_to_usb": usb("tx_sent")}
    if sent is not None:
        # Datagrams the sender made that never reached net_io and that no counter between lwIP's UDP receive and net_io explains.
        # `udp_wg` also counts WireGuard control datagrams (handshakes, keepalives: a handful), and the mailbox loss counts every
        # class, so this is an estimate, good to a few datagrams.
        summary["before_net_io"] = sent - ml("udp_wg")
        summary["before_lwip_udp"] = max(0, sent - ml("udp_wg") - mailbox)
        rows.insert(1, ("lost before net_io", summary["before_net_io"], "sent - udp_wg: the mailbox (below) plus everything ahead of lwIP's UDP receive"))
        rows.insert(2, ("  of it before lwIP UDP", summary["before_lwip_udp"], "after subtracting the mailbox loss: air, access point, Wi-Fi driver, lwIP link/IP drops (rows below)"))
    lwip = lwip_drops(before, after)
    if lwip:
        summary["lwip_drops"] = lwip
    perf = wgperf_summary(before, after)
    if perf:
        summary["wgperf"] = perf
    if sent is not None and received is not None:
        summary["end_to_end_loss"] = sent - received
        summary["loss_pct"] = round(100.0 * (sent - received) / sent, 2) if sent else 0.0
        summary["unattributed"] = (sent - received) - mailbox - counted
    return rows, summary


def render(rows, summary):
    lines = [f"{label:<26}{value:>10}  {note}" for label, value, note in rows]
    lines.append("counted losses (cumulative counters that moved):")
    lines += [f"  {name:<28}{value:>8}" for name, value in sorted(summary["counted_losses"].items())] or ["  none"]
    lines.append(f"  total counted drops        {summary['counted_total']:>8}   plus mailbox loss {summary['mailbox_loss']}")
    if summary.get("lwip_drops"):
        lines.append("lwIP's own drops during the run (ahead of the socket):")
        lines += [f"  {name:<28}{value:>8}" for name, value in sorted(summary["lwip_drops"].items())]
    perf = summary.get("wgperf")
    if perf:
        lines.append(f"inbound cost per datagram, {perf['datagrams']} datagrams in {perf['elapsed_ms']} ms (CPU cycles; 240 MHz = 240 cycles per microsecond):")
        for name, cycles in perf["cycles_per_datagram"].items():
            lines.append(f"  {name:<28}{cycles:>8}")
        if "run_mean" in perf:
            lines.append(f"  datagrams per run: mean {perf['run_mean']}, max {perf['run_max']} over {perf['runs']} runs")
        if "queue_depth_mean" in perf:
            lines.append(f"  wg_rx_queue depth when a drain started: mean {perf['queue_depth_mean']}, max {perf['queue_depth_max']}")
        for name in ("lock_wait", "lock_hold"):
            if name in perf:
                lines.append(f"  core lock, {name:<9} {perf[name]['count']:>8} times, mean {perf[name]['mean_cy']} cycles, max {perf[name]['max_cy']}")
    if "end_to_end_loss" in summary:
        lines.append(f"end to end: lost {summary['end_to_end_loss']} ({summary['loss_pct']} %), unattributed {summary['unattributed']} "
                     "(sent - received - mailbox - counted; DNS and control datagrams make a few of either sign)")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("output")
    snap.add_argument("--port")
    snap.add_argument("--reset-wgperf", action="store_true", help="zero the wgperf stage counters now (use on the BEFORE snapshot)")
    snap.add_argument("--wgperf", action="store_true", help="store the wgperf stage counters (use on the AFTER snapshot)")
    diff = sub.add_parser("diff")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--sent", type=int)
    diff.add_argument("--received", type=int)
    diff.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "snapshot":
        console = Console.open(args.port)
        try:
            console.require_diagnostics()
            data = snapshot(console, wgperf=args.wgperf, reset_wgperf=args.reset_wgperf)
        finally:
            console.close()
        pathlib.Path(args.output).write_text(json.dumps(data, indent=1) + "\n")
        print(f"wrote {args.output}")
        return 0
    before = json.loads(pathlib.Path(args.before).read_text())
    after = json.loads(pathlib.Path(args.after).read_text())
    rows, summary = reconcile(before, after, args.sent, args.received)
    print(json.dumps({"rows": rows, "summary": summary}, indent=1) if args.json else render(rows, summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
