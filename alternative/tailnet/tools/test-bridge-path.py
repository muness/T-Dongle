#!/usr/bin/env python3
"""The transparent bridge end to end on the host (ADR 0023): the real USB transmit ring, bridge, Wi-Fi TX budget, burst/activity code and
status counters in one translation unit over the strict mocks of tests/mocks/net.h. Assembled like tools/test_net.py assembles the ring:
only #include lines are removed from the production sources, their function bodies are compiled unchanged.

  python3 tools/test-bridge-path.py          (from alternative/tailnet; TEST_CFLAGS / CC as in tools/test.sh)

Programs: test_bridge_path (deterministic cases and seeded random runs, ASan/UBSan, at a 1 ms and the firmware's 10 ms tick) and
test_bridge_threads (five real threads, ThreadSanitizer when the compiler has it)."""
import os, shlex, subprocess, sys
from pathlib import Path

here = Path(__file__).resolve().parents[1]          # alternative/tailnet
root = here.parents[1]
out = here / 'build-host'
out.mkdir(exist_ok=True)

def stripped(path):
    return '\n'.join(l for l in Path(path).read_text().splitlines() if not l.startswith('#include')) + '\n'

mock = (root / 'tests/mocks/net.h').read_text()
ring = stripped(root / 'components/esp_tinyusb/tinyusb_net.c')
l2 = stripped(root / 'components/tdongle_runtime/l2.c').replace('ulTaskNotifyTake', 'l2_notify_take')   # the retry wait: see bridge_prelude.inc
inc = ['-I', str(root / 'tests/mocks/include'), '-I', str(root / 'components/esp_tinyusb/include'), '-I', str(root / 'components/tdongle_runtime/include'),
       '-I', str(here / 'tests/host_pins'), '-I', str(here / 'components/microlink/include'), '-I', str(here / 'main'), '-I', str(here / 'tests')]
pm = str(root / 'components/tdongle_runtime/tdongle_pm_burst.c')
cc = shlex.split(os.environ.get('CC', 'cc'))
warn = ['-std=gnu11', '-pthread', '-DGATEWAY_BRIDGE_TUNE=1', '-Wall', '-Wextra', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter', '-Wno-unused-but-set-variable']

def assemble(name, case):
    # The order matters: mocks, the stand-ins the sources name, the real sources, the helpers and the cases.
    text = '\n'.join([
        mock,
        '#include "bridge_prelude.inc"',
        ring,
        l2,
        '#include "wifi_pins.inc"',
        '#include "bridge_status.inc"',
        '#include "bridge_world.inc"',
        (here / 'tests' / case).read_text(),
    ])
    src = out / (name + '.c')
    src.write_text(text)
    return src

def build_run(name, case, flags, env=None, args=()):
    src = assemble(name, case)
    exe = out / name
    subprocess.run(cc + warn + flags + inc + [str(src), pm, '-o', str(exe)], check=True)
    subprocess.run([str(exe), *args], check=True, env={**os.environ, **(env or {})})

# BRIDGE_ONLY=path1,path10,threads runs a subset (the mutation checks in ADR 0023 use path1).
only = set((os.environ.get('BRIDGE_ONLY') or 'path1,path10,threads').split(','))
user = shlex.split(os.environ.get('TEST_CFLAGS', '')) or ['-fsanitize=address,undefined', '-g']
for tick in (1, 10):
    if 'path%d' % tick in only: build_run('test_bridge_path_t%d' % tick, 'test_bridge_path.c', user + ['-fno-sanitize-recover=all', '-g', '-O1', '-DTEST_TICK_MS=%d' % tick])

if 'threads' not in only:
    sys.exit(0)
# Threads: ThreadSanitizer cannot share a binary with AddressSanitizer, so this program ignores TEST_CFLAGS.
probe = out / 'tsan_probe.c'
probe.write_text('int main(void){return 0;}\n')
tsan = ['-fsanitize=thread', '-g', '-O1']
if subprocess.run(cc + tsan + [str(probe), '-o', str(out / 'tsan_probe')], capture_output=True).returncode != 0:
    print('ThreadSanitizer unavailable: running the multi-thread bridge test without it')
    tsan = ['-O1', '-g']
build_run('test_bridge_threads', 'test_bridge_threads.c', tsan + ['-DBRIDGE_THREADS=1', '-DTEST_TICK_MS=1'], env={'TSAN_OPTIONS': 'halt_on_error=1'})
