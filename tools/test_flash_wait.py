#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""flash_wait.py must only ever return the target dongle's own ROM port."""
import importlib.util
import pathlib
import sys
import types

spec = importlib.util.spec_from_file_location('flash_wait', pathlib.Path(__file__).with_name('flash_wait.py'))
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)

def port(dev, pid, sn):
    return types.SimpleNamespace(device=dev, vid=0x303A, pid=pid, serial_number=sn)

DONGLE_APP = port('/dev/cu.usbmodem30EDA0D788BC1', 0x4001, '30EDA0D788BC')
DONGLE_ROM = port('/dev/cu.usbmodem101', 0x1001, '30:ED:A0:D7:88:BC')
OTHER_ROM = port('/dev/cu.usbmodem21401', 0x1001, '80:B5:4E:F9:E1:A8')  # unrelated dev board (2026-10-05)
OTHER_APP = port('/dev/cu.usbmodemOTHER', 0x4001, '80B54EF9E1A8')
CH340 = types.SimpleNamespace(device='/dev/cu.usbserial-2130', vid=0x1A86, pid=0x7523, serial_number=None)

class FakeSerial:
    poked = []
    def __init__(self, device, *a, **k): self.device = device
    def write(self, data):
        if data == b'bootloader\r\n': FakeSerial.poked.append(self.device)
    def flush(self): pass
    def read(self, n): return b'mode=tailnet'
    def close(self): pass

def run(sequence, argv=('5',)):
    """sequence: list of port lists returned by successive scans; the last one repeats."""
    FakeSerial.poked = []
    state = {'i': 0, 't': 0.0}
    def comports():
        ports = sequence[min(state['i'], len(sequence) - 1)]
        state['i'] += 1
        return ports
    def clock(): return state['t']
    def sleep(s): state['t'] += s
    out = []
    real_print = print
    def capture(*a, **k):
        if k.get('file') is None: out.append(' '.join(map(str, a)))
    fw.print = capture
    try:
        rc = fw.main(list(argv), list_ports=comports, serial_module=types.SimpleNamespace(Serial=FakeSerial),
                     clock=clock, sleep=sleep)
    finally:
        fw.print = real_print
    return rc, out, list(FakeSerial.poked)

# The 2026-10-05 failure: another board already in ROM/JTAG mode must never be chosen.
rc, out, poked = run([[DONGLE_APP, OTHER_ROM, CH340], [OTHER_ROM, DONGLE_ROM, CH340]])
assert rc == 0 and out == [DONGLE_ROM.device], (rc, out)
assert poked == [DONGLE_APP.device], poked

# If the dongle never reaches ROM, time out rather than settle for the other board.
rc, out, poked = run([[DONGLE_APP, OTHER_ROM]])
assert rc == 1 and out == [], (rc, out)
assert set(poked) == {DONGLE_APP.device}

# Two T-Dongles and no explicit serial: refuse to guess, poke nothing.
rc, out, poked = run([[DONGLE_APP, OTHER_APP]])
assert rc == 2 and out == [] and poked == [], (rc, out, poked)

# Explicit serial selects that dongle and never pokes the other one (both formats accepted).
for sn in ('30:ed:a0:d7:88:bc', '30EDA0D788BC'):
    rc, out, poked = run([[DONGLE_APP, OTHER_APP], [OTHER_APP, DONGLE_ROM]], argv=('5', '--serial', sn))
    assert rc == 0 and out == [DONGLE_ROM.device] and poked == [DONGLE_APP.device], (sn, rc, out, poked)

# An explicit serial for a board in ROM mode is accepted directly (no app console needed).
rc, out, poked = run([[DONGLE_ROM, OTHER_ROM]], argv=('5', '--serial', '30EDA0D788BC'))
assert rc == 0 and out == [DONGLE_ROM.device] and poked == []

# Only unrelated ROM ports and no dongle: never return them.
rc, out, poked = run([[OTHER_ROM, CH340]])
assert rc == 1 and out == [] and poked == []

# Invalid explicit serial is rejected up front.
rc, out, poked = run([[DONGLE_APP]], argv=('5', '--serial', 'not-a-mac'))
assert rc == 2 and out == [] and poked == []

assert fw.normalize('80:b5:4e:f9:e1:a8') == '80B54EF9E1A8' and fw.normalize(None) is None and fw.normalize('1234') is None
print('flash_wait: only the target dongle ROM port is returned; unrelated and ambiguous devices are refused')
