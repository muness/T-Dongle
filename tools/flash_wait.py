#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retry the `bootloader` console command until the dongle shows up in ROM download mode.

Prints the ROM serial port on success. The app console is only reliably alive shortly after a
boot, so this keeps trying every ~1.5 s (also while the dongle is unplugged and replugged).
The ROM loader is any Espressif port that is not the app (303a:4000/4001). macOS pyserial reports
the ROM's USB-Serial-JTAG as pid 0x9 rather than 0x1001, so matching the ROM pid directly misses it.
"""
import sys
import time

import serial
from serial.tools import list_ports

ESPRESSIF = 0x303A
APP_PIDS = (0x4000, 0x4001)


def scan():
    rom, app = [], []
    for p in list_ports.comports():
        if p.vid == ESPRESSIF:
            (app if p.pid in APP_PIDS else rom).append(p.device)
    return rom, app


def main():
    deadline = time.time() + float(sys.argv[1])
    seen = None
    print('waiting for the dongle console; a plain unplug/replug helps...', file=sys.stderr)
    while time.time() < deadline:
        rom, app = scan()
        if rom:
            print(rom[0])
            return 0
        for p in app:
            seen = seen or time.time()
            try:
                s = serial.Serial(p, 115200, timeout=0.2)
                s.write(b'status\r\n')
                s.flush()
                time.sleep(0.6)
                reply = s.read(4096)
                alive = b'mode=' in reply
                print(f'[{time.time() - seen:5.1f}s after port appeared] console '
                      f'{"REPLIED" if alive else "silent"}', file=sys.stderr, flush=True)
                s.write(b'bootloader\r\n')
                s.flush()
                time.sleep(0.4)
                s.close()
            except Exception as e:
                print(f'[open failed: {e}]', file=sys.stderr, flush=True)
        if not app:
            seen = None
        time.sleep(0.8)
    return 1


sys.exit(main())
