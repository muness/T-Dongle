#!/usr/bin/env python3
"""Regenerates tests/golden.txt from the REAL ESP-IDF v5.5.5 components/lwip/apps/dhcpserver/dhcpserver.c.

The C file is compiled unmodified into tools/harness.c with host stubs for the lwIP symbols it uses (tools/stubs), scripted scenarios
(hand written ones for every lwIP code path plus seeded random ones) are run through it, and its replies, destinations, static ARP
entries and lease list after every step are recorded. tests/golden.rs replays the scripts against the Rust crate and compares them.

    python3 tools/gen_golden.py [--idf ~/.cache/tdongle/esp-idf-v5.5.5]
"""
import argparse, os, random, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COOKIE = "63825363"


def ipx(s):
    return "".join("%02x" % int(x) for x in s.split("."))


def pkt(opts="", flags=0, ci="0.0.0.0", gi="0.0.0.0", yi="0.0.0.0", mac=1, op=1, xid="deadbeef", total=None, tail=""):
    """A BOOTP request: 236 byte header, cookie, `opts` (hex), optionally zero padded to `total` bytes."""
    m = "02000000%04x" % mac
    h = "%02x010600" % op + xid + "0000" + "%04x" % flags + ipx(ci) + ipx(yi) + "00000000" + ipx(gi) + m + "00" * 10 + "00" * 192
    p = h + COOKIE + opts + tail
    if total:
        p += "00" * max(0, total - len(p) // 2)
    return p


def t(v):
    return "3501%02x" % v


def req_ip(a):
    return "3204" + ipx(a)


END = "ff"


def scenarios():
    S = []
    base = "CFG 192.168.4.1 255.255.255.0 192.168.4.1 192.168.4.1 - - - 120"

    # 1. DORA, broadcast and unicast flavours, renew, release, inform
    s = [base]
    s += ["P 1 " + pkt(t(1) + END, 0x8000, total=300)]
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.2") + "3604c0a80401" + END, 0x8000, total=300)]
    s += ["P 1 " + pkt(t(1) + END, 0x0000, mac=2, total=300)]          # unicast flag: reply goes to yiaddr
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.3") + END, 0x0000, mac=2, total=300)]
    s += ["P 5 " + pkt(t(3) + END, 0, ci="192.168.4.2", total=300)]    # renew: ciaddr = lease
    s += ["P 5 " + pkt(t(3) + END, 0, ci="192.168.4.9", total=300)]    # not our lease: NAK
    s += ["P 5 " + pkt(t(3) + END, 0x8000, total=300, mac=3)]          # request without 50 or ciaddr from a stranger: NAK
    s += ["P 5 " + pkt(t(7) + END, 0, ci="192.168.4.2", total=300)]    # release
    s += ["P 5 " + pkt(t(1) + END, 0x8000, mac=4, total=300)]
    s += ["T 10"]
    S.append(("dora_renew_release", s))

    # 2. INFORM
    s = [base]
    s += ["P 1 " + pkt(t(8) + END, 0, ci="192.168.4.50", total=300)]
    s += ["P 1 " + pkt(t(8) + END, 0, ci="0.0.0.0", total=300)]
    s += ["P 1 " + pkt(t(8) + END, 0, ci="10.0.0.5", total=300)]
    s += ["P 1 " + pkt(t(8) + END, 0, ci="192.168.4.50", gi="192.168.4.7", total=300)]
    s += ["T 1"]
    S.append(("inform", s))

    # 3. decline then the declined address comes back around
    s = [base]
    s += ["P 1 " + pkt(t(1) + END, mac=1, total=300)]
    s += ["P 1 " + pkt(t(1) + END, mac=2, total=300)]
    s += ["P 1 " + pkt(t(4) + req_ip("192.168.4.2") + END, mac=1, total=300)]
    s += ["P 1 " + pkt(t(1) + END, mac=3, total=300)]
    s += ["P 1 " + pkt(t(1) + END, mac=4, total=300)]
    s += ["P 1 " + pkt(t(7) + END, mac=2, ci="192.168.4.3", total=300)]
    s += ["P 1 " + pkt(t(1) + END, mac=5, total=300)]
    s += ["P 1 " + pkt(t(1) + END, mac=6, total=300)]
    s += ["T 1"]
    S.append(("decline_reuse", s))

    # 4. relay agent and ciaddr destinations
    s = [base]
    s += ["P 1 " + pkt(t(1) + END, 0x8000, gi="192.168.4.99", total=300)]
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.2") + END, 0x8000, gi="192.168.4.99", total=300)]
    s += ["P 1 " + pkt(t(3) + END, 0, ci="192.168.4.2", gi="192.168.4.99", total=300)]
    s += ["P 1 " + pkt(t(3) + END, 0, ci="192.168.4.2", total=300)]
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.77") + END, 0, gi="192.168.4.99", total=300, mac=2)]   # NAK via relay
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.77") + END, 0x8000, total=300, mac=2)]                # NAK broadcast
    s += ["T 1"]
    S.append(("relay_destinations", s))

    # 5. expiry: lease runs out exactly at 7200 s, address handed on in order
    s = [base]
    s += ["P 1 " + pkt(t(1) + END, mac=1, total=300)]
    s += ["P 7198 " + pkt(t(1) + END, mac=2, total=300)]
    s += ["T 1"]
    s += ["P 1 " + pkt(t(1) + END, mac=3, total=300)]
    s += ["P 7198 " + pkt(t(3) + req_ip("192.168.4.2") + END, mac=2, total=300)]
    s += ["T 2"]
    s += ["P 1 " + pkt(t(1) + END, mac=1, total=300)]
    S.append(("expiry", s))

    # 6. more clients than stations: the oldest goes
    s = [base]
    for i in range(1, 14):
        s += ["P 3 " + pkt(t(1) + END, mac=i, total=300)]
        s += ["P 3 " + pkt(t(3) + req_ip("192.168.4.%d" % 0) + END, mac=i, total=300)] if False else []
    s += ["P 2 " + pkt(t(3) + END, ci="192.168.4.5", mac=2, total=300)]
    s += ["T 2"]
    S.append(("station_limit", s))

    # 7. options: pad, truncated, repeated, odd lengths, no END, unknown types, stale tail, big packets
    s = [base]
    s += ["P 1 " + pkt("0000" + t(1) + "0000", total=300)]
    s += ["P 1 " + pkt("3501", total=244, mac=2)]                             # truncated type option: no type -> idle, lease kept
    s += ["P 1 " + pkt("350103" + "3204c0a80402", total=300, mac=3)]          # request, option 50 for someone else's address
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.2") + req_ip("192.168.4.9") + END, total=300, mac=1)]   # last option 50 wins
    s += ["P 1 " + pkt(t(1) + t(3) + req_ip("192.168.4.2") + END, total=300, mac=1)]                  # last type wins
    s += ["P 1 " + pkt(t(2) + req_ip("192.168.4.3") + END, total=300, mac=4)]                         # unknown type with option 50
    s += ["P 1 " + pkt(t(5) + END, total=300, mac=5)]
    s += ["P 1 " + pkt("3204c0a804" , total=244, mac=6)]                                              # cut-off option 50
    s += ["P 1 " + pkt("0c05" + "aa" * 5 + t(1) + END, total=300, mac=7)]
    s += ["P 1 " + pkt("3702010305" + t(1) + END + "fe" * 40, total=300, mac=8)]                      # junk after END copies into the reply tail
    s += ["P 1 " + pkt(t(1) + END, total=700, mac=9, tail="ab" * 50)]
    s += ["P 1 " + pkt(t(1) + END, total=1500, mac=10)]
    s += ["P 1 " + pkt(t(1) + END, total=240 + 4 + 0, mac=11)]
    s += ["P 1 " + pkt("", total=240, mac=12)]
    s += ["P 1 " + pkt(t(1), total=243, mac=13)]
    s += ["P 1 " + pkt("0501ff35" + "01" + "01", total=250, mac=14)]
    s += ["T 1"]
    S.append(("options", s))

    # 8. other configurations
    s = ["CFG 192.168.4.1 255.255.255.0 - 192.168.4.1 8.8.8.8 192.168.4.10 192.168.4.12 30"]
    for i in range(1, 6):
        s += ["P 1 " + pkt(t(1) + END, 0x8000, mac=i, total=300)]
    s += ["P 1 " + pkt(t(3) + req_ip("192.168.4.11") + END, 0, mac=2, total=300)]
    s += ["P 1800 " + pkt(t(1) + END, 0x8000, mac=6, total=300)]
    S.append(("custom_pool_no_router_backup_dns", s))
    s = ["CFG 10.1.2.200 255.255.255.0 10.1.2.1 1.1.1.1 - - - 5"]
    for i in range(1, 5):
        s += ["P 1 " + pkt(t(1) + END, 0x8000, mac=i, total=300)]
    S.append(("default_pool_server_high", s))
    s = ["CFG 172.16.0.1 255.255.255.240 172.16.0.1 172.16.0.1 - 172.16.1.2 172.16.1.9 120"]   # pool outside the subnet: default pool
    for i in range(1, 17):
        s += ["P 1 " + pkt(t(1) + END, 0x8000, mac=i, total=300)]
    S.append(("small_subnet_bad_pool", s))
    return S


def random_scenario(seed, n=150):
    r = random.Random(seed)
    s = ["CFG 192.168.4.1 255.255.255.0 192.168.4.1 192.168.4.1 - - - 120"]
    leased = {}
    for _ in range(n):
        mac = r.randint(1, 13)
        ty = r.choice([1, 1, 3, 3, 3, 3, 4, 7, 7, 8, 2, 5, 0])
        opts = ""
        if ty:
            opts += t(ty)
        ip = "192.168.4.%d" % r.choice([r.randint(1, 4), r.randint(2, 20), r.randint(2, 101), r.randint(100, 110), 255])
        if r.random() < 0.5:
            opts += req_ip(ip)
        if r.random() < 0.2:
            opts += r.choice(["0000", "3702010305", "0c03616263", "3d07010200000000" + "01"])
        if r.random() < 0.05:
            opts += req_ip("192.168.4.%d" % r.randint(2, 30))
        if r.random() < 0.8:
            opts += END
        ci = ip if r.random() < 0.3 else "0.0.0.0"
        gi = "192.168.4.99" if r.random() < 0.08 else "0.0.0.0"
        fl = r.choice([0, 0x8000, 0x8000, 0x0000, 0x4000])
        total = r.choice([300, 300, 300, 244, 600])
        d = r.choice([1, 1, 1, 2, 3, 20, 700, 3600, 7199, 7200])
        s.append("P %d %s" % (d, pkt(opts, fl, ci=ci, gi=gi, mac=mac, total=total, xid="%08x" % r.getrandbits(32))))
    s.append("T 1")
    return ("random_%d" % seed, s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--idf", default=os.path.expanduser("~/.cache/tdongle/esp-idf-v5.5.5"))
    ap.add_argument("--out", default=os.path.join(HERE, "..", "tests", "golden.txt"))
    a = ap.parse_args()
    lwip = os.path.join(a.idf, "components", "lwip")
    with tempfile.TemporaryDirectory() as d:
        exe = os.path.join(d, "harness")
        subprocess.run(["cc", "-std=gnu11", "-O1", "-w", "-I" + os.path.join(HERE, "stubs"), "-I" + os.path.join(lwip, "include", "apps"),
                        "-I" + os.path.join(lwip, "apps", "dhcpserver"), "-o", exe, os.path.join(HERE, "harness.c")], check=True)
        all_s = scenarios() + [random_scenario(seed) for seed in (1, 2, 3, 4)]
        out = ["# Generated by tools/gen_golden.py from the real dhcpserver.c of ESP-IDF v5.5.5 (see that script). Do not edit."]
        for name, lines in all_s:
            res = subprocess.run([exe], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True).stdout.splitlines()
            out.append("S " + name)
            it = iter(res)
            for ln in lines:
                if ln.startswith("CFG"):
                    out.append(ln)
                    out.append(next(it))   # POOL
                else:
                    if ln.startswith("P"):
                        _, dl, hx = ln.split()
                        ln = "P %s %d %s" % (dl, len(hx) // 2, hx.rstrip("0") + ("0" if len(hx.rstrip("0")) % 2 else ""))   # zero tail elided
                    out.append(ln)
                    out.append(next(it))   # L
                    if ln.startswith("P"):
                        out.append(next(it))   # R
        with open(a.out, "w") as f:
            f.write("\n".join(out) + "\n")
    print("wrote", a.out, len(out), "lines")


if __name__ == "__main__":
    main()
