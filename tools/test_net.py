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
