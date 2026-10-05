#!/usr/bin/env python3
"""The lwIP TCP window settings in sdkconfig.defaults must satisfy main/tcp_window_budget.h.

Compiles the real header against the values parsed from sdkconfig.defaults (so a bad edit fails
here, on the host, before a 20-minute firmware build), then proves the assertions are live by
compiling it against deliberately wrong values and requiring each to be rejected. Also prints the
throughput ceiling each window gives at the measured DERP round-trip times.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
cfg = {}
for line in (root / "sdkconfig.defaults").read_text().splitlines():
    m = re.match(r"(CONFIG_\w+)=(.*)", line)
    if m:
        cfg[m.group(1)] = m.group(2).strip('"')

# IDF v5.5.5 defaults for anything sdkconfig.defaults leaves alone (components/lwip/Kconfig, lwip opt.h).
IDF_DEFAULTS = {"CONFIG_LWIP_TCP_MSS": 1440, "CONFIG_LWIP_TCP_WND_DEFAULT": 5760, "CONFIG_LWIP_TCP_SND_BUF_DEFAULT": 5760,
                "CONFIG_LWIP_TCP_RECVMBOX_SIZE": 6, "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM": 32, "MEMP_NUM_TCP_SEG": 16}

def value(key, override):
    if key in override:
        return override[key]
    return int(cfg.get(key, IDF_DEFAULTS[key]))

def compiles(override=None):
    override = override or {}
    wnd, snd, mss = value("CONFIG_LWIP_TCP_WND_DEFAULT", override), value("CONFIG_LWIP_TCP_SND_BUF_DEFAULT", override), value("CONFIG_LWIP_TCP_MSS", override)
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "lwip").mkdir()
        (d / "lwip/opt.h").write_text(f"""#pragma once
#define TCP_WND {wnd}
#define TCP_SND_BUF {snd}
#define TCP_MSS {mss}
#define LWIP_WND_SCALE {override.get('scale', 0)}
#define DEFAULT_TCP_RECVMBOX_SIZE {value('CONFIG_LWIP_TCP_RECVMBOX_SIZE', override)}
#define CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM {value('CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM', override)}
#define MEMP_NUM_TCP_SEG {value('MEMP_NUM_TCP_SEG', override)}
""")
        (d / "t.c").write_text('#include "tcp_window_budget.h"\nint main(void){return 0;}\n')
        r = subprocess.run(["cc", "-std=c11", "-fsyntax-only", "-I", str(d), "-I", str(root / "main"), str(d / "t.c")], capture_output=True, text=True)
        return r.returncode == 0, r.stderr

ok, err = compiles()
if not ok:
    sys.exit("sdkconfig.defaults violates main/tcp_window_budget.h:\n" + err)

# Each wrong configuration must be refused by its own assertion.
refused = {
    "window over 64 KB without scaling": {"CONFIG_LWIP_TCP_WND_DEFAULT": 70000},
    "receive mailbox smaller than window/MSS + 2": {"CONFIG_LWIP_TCP_RECVMBOX_SIZE": 6},
    "window can pin over half the Wi-Fi RX pool": {"CONFIG_LWIP_TCP_WND_DEFAULT": 17280, "CONFIG_LWIP_TCP_RECVMBOX_SIZE": 14},
    "send buffer larger than the segment pool": {"CONFIG_LWIP_TCP_SND_BUF_DEFAULT": 40 * 1440},
    "window below two segments": {"CONFIG_LWIP_TCP_WND_DEFAULT": 1440},
}
for name, override in refused.items():
    accepted, _ = compiles(override)
    assert not accepted, f"build assertion did not reject: {name}"
# Window scaling would lift the 64 KB bound, so the check must follow the option, not the value.
assert compiles({"CONFIG_LWIP_TCP_WND_DEFAULT": 70000, "CONFIG_LWIP_TCP_RECVMBOX_SIZE": 60, "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM": 128, "scale": 1})[0]

wnd = int(cfg["CONFIG_LWIP_TCP_WND_DEFAULT"])
assert wnd > 5760 and wnd % int(cfg.get("CONFIG_LWIP_TCP_MSS", 1440)) == 0, "window should be a whole number of segments and larger than the 5,760 B baseline"
print("TCP window: sdkconfig.defaults satisfies the build assertions; 5 wrong configurations are rejected.")
for rtt in (36, 64):
    print(f"  window {wnd} B at {rtt} ms RTT caps one connection at {wnd * 8 / rtt / 1000:.2f} Mbit/s (baseline 5,760 B: {5760 * 8 / rtt / 1000:.2f})")
