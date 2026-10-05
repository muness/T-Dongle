#!/usr/bin/env python3
"""ADR 0022: the lwIP and Wi-Fi settings in sdkconfig.defaults must satisfy the heap budget in components/microlink/include/ml_heap_budget.h.

Each setting that lets a socket pin Wi-Fi buffers (the UDP receive mailbox, the TCP window in segments) is compiled against the real
header, which refuses a build where the largest burst does not fit between the elastic floor and the recovery reserve. The Wi-Fi TX
pool is no longer one of them (amendment 2): the driver's buffers are counted at run time (main/wifi_pin_budget.h), so the pool only
has to hold the band and fit the budget's FIFO, which is compiled against the real header too. Then each limit is shown to be live by
compiling one step past it, and the sanitized adversarial simulations (tests/test_heap_budget.c, tests/test_wifi_pin_budget.c, the
latter also under ThreadSanitizer) are built and run.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
cfg = {}
for name in ("sdkconfig.defaults", "sdkconfig.diagnostics"):
    path = root / name
    if path.exists():
        for line in path.read_text().splitlines():
            m = re.match(r"(CONFIG_\w+)=(.*)", line)
            if m:
                cfg[m.group(1)] = m.group(2).strip('"')
MSS = int(cfg.get("CONFIG_LWIP_TCP_MSS", 1440))          # IDF default
udp = int(cfg["CONFIG_LWIP_UDP_RECVMBOX_SIZE"])
tx = int(cfg["CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM"])
segs = int(cfg["CONFIG_LWIP_TCP_WND_DEFAULT"]) // MSS
assert int(cfg["CONFIG_LWIP_TCP_WND_DEFAULT"]) % MSS == 0

def compiles(udp_slots, tx_buffers, tcp_segments):
    with tempfile.TemporaryDirectory() as d:
        src = pathlib.Path(d) / "t.c"
        src.write_text(f"""#define CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM {tx_buffers}
#include "wifi_pin_budget.h"
_Static_assert({udp_slots} <= ML_HB_PIN_BUFFERS, "udp mailbox");
_Static_assert({tcp_segments} <= ML_HB_PIN_BUFFERS, "tcp window");
int main(void) {{ return 0; }}
""")
        r = subprocess.run(["cc", "-std=c11", "-fsyntax-only", "-I", str(root / "components/microlink/include"), "-I", str(root / "main"), str(src)], capture_output=True, text=True)
        return r.returncode == 0, r.stderr

with tempfile.TemporaryDirectory() as d:
    probe = pathlib.Path(d) / "limit.c"
    probe.write_text('#include <stdio.h>\n#include "ml_heap_budget.h"\nint main(void) { printf("%u\\n", ML_HB_PIN_BUFFERS); return 0; }\n')
    subprocess.run(["cc", "-std=c11", "-I", str(root / "components/microlink/include"), str(probe), "-o", str(pathlib.Path(d) / "limit")], check=True)
    limit = subprocess.run([str(pathlib.Path(d) / "limit")], capture_output=True, text=True, check=True).stdout.strip()
limit = int(limit)
ok, err = compiles(udp, tx, segs)
if not ok:
    sys.exit(f"sdkconfig.defaults violates the heap budget (limit {limit} pinned Wi-Fi buffers per socket; UDP mailbox {udp}, TCP window {segs} segments; TX pool {tx} against a FIFO of 16 and a band of 1):\n{err}")
# The TX pool: no longer limited to the pin burst, but it must hold the band and fit the FIFO. 16 is the driver's size and the FIFO's: 17 and 0 are rejected.
for name, args in (("UDP mailbox", (limit + 1, tx, segs)), ("TCP window", (udp, tx, limit + 1)), ("Wi-Fi TX pool above the budget's FIFO", (udp, 17, segs)),
                   ("Wi-Fi TX pool below its band", (udp, 0, segs))):
    accepted, _ = compiles(*args)
    assert not accepted, f"the heap budget did not reject a {name} one past the limit"
accepted, _ = compiles(udp, 16, segs)
assert accepted, "a TX pool of 16 (the driver's size, runtime-bounded) must be accepted"
print(f"heap budget: UDP mailbox {udp} and TCP window {segs} segments within {limit} pinned Wi-Fi buffers; Wi-Fi TX pool {tx} within the budget's FIFO (16); each limit is live (one past it is rejected).")

binary = root / "build-host" / "test_heap_budget"
binary.parent.mkdir(exist_ok=True)
subprocess.run(["cc", "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-Wall", "-Wextra",
                "-I", str(root / "components/microlink/include"), "-I", str(root / "main"), str(root / "tests/test_heap_budget.c"), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
for name, sanitizers in (("test_wifi_pin_budget", "address,undefined"), ("test_wifi_pin_budget_tsan", "thread")):
    binary = root / "build-host" / name
    subprocess.run(["cc", "-std=c11", "-O1", "-g", f"-fsanitize={sanitizers}", "-fno-sanitize-recover=all", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-I", str(root / "components/microlink/include"), "-I", str(root / "main"), str(root / "tests/test_wifi_pin_budget.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
