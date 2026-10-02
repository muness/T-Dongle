#!/usr/bin/env python3
"""Compile the actual vendored send wrapper against a deterministic scheduler.
Only includes are replaced; production function bodies are unchanged.
"""
import os, shlex, subprocess
from pathlib import Path
src = Path('components/esp_tinyusb/tinyusb_net.c').read_text()
src = '\n'.join(line for line in src.splitlines() if not line.startswith('#include'))
Path('build-host').mkdir(exist_ok=True)
Path('build-host/test_net.c').write_text(Path('tests/mocks/net.h').read_text() + '\n' + src + '\n' + Path('tests/mocks/net_cases.c').read_text())
subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + shlex.split(os.environ.get('TEST_CFLAGS', '')) + ['-std=c11', 'build-host/test_net.c', '-o', 'build-host/test_net'], check=True)
subprocess.run(['build-host/test_net'], check=True)
