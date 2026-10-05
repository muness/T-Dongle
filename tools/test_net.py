#!/usr/bin/env python3
"""Compile the actual vendored send wrapper against a deterministic scheduler.
Only includes are replaced; production function bodies are unchanged.
"""
import os, shlex, subprocess
from pathlib import Path
src = Path('components/esp_tinyusb/tinyusb_net.c').read_text()
src = '\n'.join(line for line in src.splitlines() if not line.startswith('#include'))
Path('build-host').mkdir(exist_ok=True)
# Same production source, two programs: the original sync-send ownership cases and the
# non-blocking transmit ring cases.
for name in ('net_cases', 'net_ring_cases'):
    exe = 'build-host/test_' + name
    Path(exe + '.c').write_text(Path('tests/mocks/net.h').read_text() + '\n' + src + '\n' + Path('tests/mocks/%s.c' % name).read_text())
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + shlex.split(os.environ.get('TEST_CFLAGS', '')) + ['-std=c11', exe + '.c', '-o', exe], check=True)
    subprocess.run([exe], check=True)
# The same ring with two real threads, under ThreadSanitizer when the compiler has it
# (it cannot share a binary with AddressSanitizer, so this program ignores TEST_CFLAGS).
exe = 'build-host/test_net_ring_threads'
Path(exe + '.c').write_text(Path('tests/mocks/net.h').read_text() + '\n' + src + '\n' + Path('tests/mocks/net_ring_threads.c').read_text())
cc = shlex.split(os.environ.get('CC', 'cc'))
tsan = ['-fsanitize=thread', '-g', '-O1']
probe = Path('build-host/tsan_probe.c'); probe.write_text('int main(void){return 0;}\n')
if subprocess.run(cc + tsan + [str(probe), '-o', 'build-host/tsan_probe'], capture_output=True).returncode != 0:
    print('ThreadSanitizer unavailable: running the two-thread ring test without it'); tsan = ['-O1']
subprocess.run(cc + tsan + ['-pthread', '-std=c11', exe + '.c', '-o', exe], check=True)
subprocess.run([exe], check=True, env={**os.environ, 'TSAN_OPTIONS': 'halt_on_error=1'})
