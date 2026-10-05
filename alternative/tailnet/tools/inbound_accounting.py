#!/usr/bin/env python3
"""Where did the inbound datagrams go? Reconcile a UDP `iperf3 -R` run hop by hop from the dongle's cumulative counters.

Diagnostics build only (serial `inbound`, `route` and `memory`; docs/adr/0019-inbound-loss.md). Two steps around the run:

    tools/inbound_accounting.py snapshot before.json [--port /dev/cu.usbmodemXXXX]
    iperf3 -c <dongle tailnet ip> -u -b 3M -l 1200 -t 10 -R            # on the host; note datagrams sent and received
    tools/inbound_accounting.py snapshot after.json  [--port ...]
    tools/inbound_accounting.py diff before.json after.json --sent 3133 --received 2905

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
ML_LOSS = ["udp_rx_empty", "udp_unclassified", "udp_alloc_fail", "q_wg_full", "derp_q_wg_full", "wg_sender_unknown", "wg_no_netif", "wg_pbuf_fail"]
WG_LOSS = ["rx_no_peer", "rx_keepalive_skipped", "rx_keypair_unusable", "rx_expired", "rx_alloc_fail", "rx_session_gone", "rx_decrypt_fail",
           "rx_replay_dup", "rx_replay_old", "rx_replay_limit", "rx_bad_ip", "rx_allowed_ip", "rx_bad_length", "rx_input_fail"]
ROUTE_LOSS = ["tunnel_malformed", "tunnel_nomem", "bad_packet", "reply_no_member", "reply_not_us", "reply_flow_range", "reply_no_flow",
              "reply_generation", "reply_owner", "reply_idle", "usb_tx_err", "tx_fail"]
USB_LOSS = ["tx_dropped_full", "tx_dropped_link_down", "tx_dropped_invalid", "tx_flushed_link_down"]


def snapshot(console):
    inbound = console.json_command("inbound")["inbound"][0]
    memory = console.json_command("memory")
    return {"inbound": inbound, "usb": memory["usb"][0], "heap": {k: memory["heap"][0][k] for k in ("uptime_ms", "free", "min", "largest")}}


def delta(before, after, layer, name):
    return after["inbound"][layer][name] - before["inbound"][layer][name]


def reconcile(before, after, sent=None, received=None):
    """Returns (rows, summary): rows are (label, value, note); summary is a dict of the totals."""
    ml = lambda n: delta(before, after, "ml", n)          # noqa: E731
    wg = lambda n: delta(before, after, "wg", n)          # noqa: E731
    rt = lambda n: delta(before, after, "route", n)       # noqa: E731
    lw = lambda n: after["inbound"]["lwip"][n] - before["inbound"]["lwip"][n]  # noqa: E731
    usb = lambda n: after["usb"][n] - before["usb"][n]    # noqa: E731
    mailbox = lw("udp_recv") - ml("udp_rx")
    rows = []
    if sent is not None:
        rows.append(("sent by iperf3", sent, "datagrams the sender reports"))
    rows += [
        ("lwip udp_recv", lw("udp_recv"), "every UDP datagram lwIP accepted, counted before the socket mailbox"),
        ("net_io udp_rx", ml("udp_rx"), "read from the sockets by net_io"),
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
            data = snapshot(console)
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
