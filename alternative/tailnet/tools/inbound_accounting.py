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
    try:
        low = console.json_command("memory low").get("heap_low")
        if low:
            data["heap_low"] = low[0]
    except Exception:  # firmware without `memory low`
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


def usb_drain(before, after, bus_ms_per_kb=0.85):
    """The USB IN pipe over the run (ADR 0022), from the usb counters: NTBs, datagrams per NTB, the gap between IN completions while
    frames were queued against the bus time of the mean NTB (what is left is the TinyUSB task's wake latency), and the cold start."""
    u = lambda n: after["usb"].get(n, 0) - before["usb"].get(n, 0)      # noqa: E731
    hist = lambda n: [a - b for a, b in zip(after["usb"].get(n, []), before["usb"].get(n, []))]      # noqa: E731
    xfers = u("ntb_xfers")
    if not xfers:
        return {}
    out = {"ntb_xfers": xfers, "ntb_zlp": u("ntb_zlp"), "mean_ntb_bytes": round(u("ntb_bytes") / xfers),
           "frames_per_ntb": round(u("tx_sent") / xfers, 2), "drains_sent": hist("drains_sent"), "worker_demotions": u("tx_worker_demotions")}
    if u("gap_count"):
        gap = u("gap_us_sum") / u("gap_count") / 1000.0
        bus = out["mean_ntb_bytes"] / 1024.0 * bus_ms_per_kb
        out.update({"gap_mean_ms": round(gap, 2), "gap_max_ms": after["usb"].get("gap_us_max", 0) / 1000.0, "gap_hist_ms": hist("gap_hist_ms"),
                    "bus_ms_of_mean_ntb": round(bus, 2), "wake_latency_ms": round(max(0.0, gap - bus), 2)})
    if u("cold_starts"):
        out["cold_start_mean_ms"] = round(u("cold_us_sum") / u("cold_starts") / 1000.0, 2)
        out["cold_start_max_ms"] = after["usb"].get("cold_us_max", 0) / 1000.0
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
    drain = usb_drain(before, after)
    if drain:
        summary["usb_drain"] = drain
    summary["heap_min_free"] = after.get("heap", {}).get("min")
    heap_refused = (after["usb"].get("rx_dropped_heap", 0) - before["usb"].get("rx_dropped_heap", 0))
    if heap_refused:
        summary["usb_rx_refused_for_heap"] = heap_refused
    if after.get("heap_low"):
        summary["heap_low"] = after["heap_low"]
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
    drain = summary.get("usb_drain")
    if drain:
        lines.append(f"USB IN pipe: {drain['ntb_xfers']} NTBs ({drain['ntb_zlp']} ZLPs), mean {drain['mean_ntb_bytes']} B = {drain['frames_per_ntb']} frames per NTB; "
                     f"frames per drain pass (1,2,3,4,5+) {drain['drains_sent']}")
        if "gap_mean_ms" in drain:
            lines.append(f"  gap between IN completions with a backlog: mean {drain['gap_mean_ms']} ms (max {drain['gap_max_ms']}), histogram <1,<2,<4,<8,>=8 ms {drain['gap_hist_ms']}; "
                         f"bus time of the mean NTB {drain['bus_ms_of_mean_ntb']} ms, so wake latency about {drain['wake_latency_ms']} ms")
        if "cold_start_mean_ms" in drain:
            lines.append(f"  first frame of a burst waited {drain['cold_start_mean_ms']} ms (max {drain['cold_start_max_ms']}) for its hand-over")
    if summary.get("heap_min_free") is not None:
      lines.append(f"heap minimum since boot {summary['heap_min_free']} B (recovery reserve 16,384 B)"
                 + (f"; USB frames refused for the heap floor {summary['usb_rx_refused_for_heap']}" if summary.get("usb_rx_refused_for_heap") else ""))
    low = summary.get("heap_low")
    if low and low.get("records"):
        lines.append(f"heap minimum records (new minima below the {low['floor']} B elastic floor; highest free seen {low['free_hi']} B):")
        for r in low["records"]:
            # The WireGuard queue's datagrams are packet blocks: wgq is a part of packet_live, not a second term.
            held = r["tx_elastic"] + r["rx_inflight"] * 1534 + r["packet_live"]
            dropped = low["free_hi"] - r["free"]
            pins = ""
            if "wifi_rx_pins" in r:
                pins = f"; Wi-Fi buffers pinned: {r['wifi_rx_pins']} RX, {r['wifi_tx_inflight']} TX in flight (~{r['wifi_rx_pins'] * 1664 + r['wifi_tx_inflight'] * 1664} B at full size)"
            lines.append(f"  t={r['uptime_ms']} ms min {r['min']} B free {r['free']} B: dropped {dropped} B from the peak, of which ring elastic {r['tx_elastic']}, "
                         f"usb rx {r['rx_inflight']} frames, tagged packets {r['packet_live']} (wg queue {r['wgq']} of them); "
                         f"unexplained (Wi-Fi buffers pinned by sockets, lwIP) {dropped - held}{pins}")
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
