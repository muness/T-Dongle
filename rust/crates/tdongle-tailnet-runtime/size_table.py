#!/usr/bin/env python3
"""Reads the `-Zprint-type-sizes` output of size-table.sh and prints the M-elf table: what each membership costs and what the gateway costs once.

Total RAM of the runtime = the joined `run` future + the `Shared` static (without the test directory) + the socket buffer set. Everything else is
flash, stack or the image's own.
"""
import re
import sys

outdir = sys.argv[1]
slots = [int(x) for x in sys.argv[2:]]


def load(n):
    rows = {}
    for line in open(f"{outdir}/tdongle-runtime-typesizes-{n}.txt", errors="replace"):
        m = re.match(r"print-type-size type: `(.*)`: (\d+) bytes", line)
        if m:
            rows.setdefault(m.group(1), int(m.group(2)))
    return rows


def exact(rows, prefix):
    for name, size in rows.items():
        if name.startswith(prefix):
            return size
    return 0


def biggest(rows, pat):
    best = [(b, n) for n, b in rows.items() if re.search(pat, n)]
    return max(best)[0] if best else 0


tot = {}
for n in slots:
    r = load(n)
    fut = lambda name: exact(r, "{async fn body of " + name)
    ramdir = biggest(r, r"^tdongle_tailnet_engine::RamDirectory<%d, 16, 32>$" % n)
    engine = exact(r, "tdongle_tailnet_engine::Engine<tdongle_tailnet_engine::RamDirectory<%d, 16, 32>" % n)
    shared_full = exact(r, "shared::Shared<embassy_sync")
    shared_fw = shared_full - ramdir
    run = exact(r, "{async fn body of runner::run") or biggest(r, r"async fn body of runner::run")
    slot = exact(r, "shared::Slot<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex>")
    member = exact(r, "tdongle_tailnet_engine::member::Member<8>")
    net = exact(r, "net_embassy::NetBuffers<")
    net_m = exact(r, "net_embassy::NetBuffers<")
    ctl, derp, udp = fut("control::control_slot"), fut("derp::derp_slot"), fut("udp::udp_slot")
    total = run + shared_fw + net
    tot[n] = dict(run=run, shared_fw=shared_fw, net=net, total=total, slot=slot, member=member, ctl=ctl, derp=derp, udp=udp, engine=engine, ramdir=ramdir,
                  bulk=exact(r, "tdongle_tailnet_ctl::driver::Bulk") or exact(r, "tdongle_tailnet_ctl::Bulk"),
                  sessbuf=exact(r, "tdongle_tailnet_ctl::driver::SessionBuf") or exact(r, "tdongle_tailnet_ctl::SessionBuf"),
                  lease=exact(r, "tdongle_tailnet_tls::lease::LeasePool<"), link=exact(r, "tdongle_tailnet_derp::Link<"),
                  usb=fut("usb::usb_pump"), dns=fut("tasks::dns_upstream"), sup=fut("members::supervisor"),
                  ws=exact(r, "tdongle_tailnet_ctl::Workspace"))

print("M-elf (xtensa-esp32s3-none-elf), bytes; total = joined run future + Shared (firmware estimate, without the test directory) + socket buffers")
hdr = "".join(f"{('MAX_RUN=%d' % n):>12}" for n in slots)
print(f"  {'':<42}{hdr}")
def row(label, key):
    print(f"  {label:<42}" + "".join(f"{tot[n][key]:>12}" for n in slots))
row("joined run future", "run")
row("Shared static (firmware estimate)", "shared_fw")
row("socket buffers (NetBuffers)", "net")
row("TOTAL static RAM of the runtime", "total")
if len(slots) > 1:
    print("  marginal per extra membership: " + ", ".join(f"{a}->{b}: {tot[b]['total'] - tot[a]['total']}" for a, b in zip(slots, slots[1:])))
print("  per membership slot (one each):")
row("control future", "ctl")
row("derp future", "derp")
row("udp future", "udp")
row("Slot static", "slot")
row("engine Member<8> record", "member")
print("  once for the gateway:")
row("ctl Bulk (leased control buffers)", "bulk")
row("ctl SessionBuf (inside each Slot)", "sessbuf")
row("TLS record lease", "lease")
row("usb pump future", "usb")
row("dns upstream future", "dns")
row("supervisor future", "sup")
row("DERP Link (inside the derp future)", "link")
