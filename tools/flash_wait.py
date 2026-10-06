#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Put one specific T-Dongle into ROM download mode and print that ROM serial port.

Usage: flash_wait.py SECONDS [--serial MAC]

The dongle is identified by its chip MAC. Its app console reports it as the USB serial number
(12 hex digits, e.g. 30EDA0D788BC), and its ROM USB-Serial-JTAG loader reports the same MAC
(e.g. 30:ED:A0:D7:88:BC). Only a ROM port whose serial matches the target MAC is ever returned,
and `bootloader` is only sent to the target's own app port, so another Espressif board on the
same host is never selected. (An earlier version returned the first Espressif port that was not
an app port and flashed an unrelated dev board.)

The target is --serial, else $TDONGLE_SERIAL, else the single T-Dongle app port present.
Zero or several candidates without an explicit serial is an error: the script refuses to guess.
The app console is only reliably alive shortly after a boot, so this retries every ~1.5 s (also
while the dongle is unplugged and replugged).
"""
import argparse
import os
import sys
import time

ESPRESSIF = 0x303A
APP_PIDS = (0x4000, 0x4001)


def normalize(serial_number):
    """Chip MAC as 12 uppercase hex digits, or None if the serial is not a MAC."""
    if not serial_number:
        return None
    s = serial_number.replace(':', '').replace('-', '').upper()
    return s if len(s) == 12 and all(c in '0123456789ABCDEF' for c in s) else None


def scan(ports):
    """Split Espressif ports into app consoles and ROM loaders, keyed by normalized MAC."""
    app, rom = [], []
    for p in ports:
        if p.vid != ESPRESSIF:
            continue
        (app if p.pid in APP_PIDS else rom).append((normalize(p.serial_number), p.device))
    return app, rom


def choose_target(explicit, app_ports):
    """Return (mac, error). An explicit serial wins; otherwise exactly one app port must exist."""
    if explicit:
        mac = normalize(explicit)
        return (mac, None) if mac else (None, f'not a chip MAC: {explicit!r}')
    macs = sorted({mac for mac, _ in app_ports if mac})
    if len(macs) == 1:
        return macs[0], None
    if not macs:
        return None, None  # keep waiting for the dongle to appear
    return None, ('several T-Dongles are attached (' + ', '.join(macs) +
                  '); pass --serial or set TDONGLE_SERIAL')


def target_rom(mac, rom_ports):
    return next((dev for m, dev in rom_ports if m == mac), None)


def poke_bootloader(device, serial_module):
    s = serial_module.Serial(device, 115200, timeout=0.2)
    try:
        s.write(b'status\r\n')
        s.flush()
        time.sleep(0.6)
        alive = b'mode=' in s.read(4096)
        s.write(b'bootloader\r\n')
        s.flush()
        time.sleep(0.4)
    finally:
        s.close()
    return alive


def main(argv=None, list_ports=None, serial_module=None, clock=time.time, sleep=time.sleep):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('seconds', type=float)
    parser.add_argument('--serial', default=os.environ.get('TDONGLE_SERIAL'))
    args = parser.parse_args(argv)
    if list_ports is None:
        from serial.tools import list_ports as lp
        list_ports = lp.comports
    if serial_module is None:
        import serial as serial_module
    deadline = clock() + args.seconds
    mac = normalize(args.serial) if args.serial else None
    if args.serial and not mac:
        print(f'not a chip MAC: {args.serial!r}', file=sys.stderr)
        return 2
    print('waiting for the dongle console; a plain unplug/replug helps...', file=sys.stderr)
    ignored = set()
    while clock() < deadline:
        app, rom = scan(list_ports())
        if mac is None:
            mac, error = choose_target(None, app)
            if error:
                print(error, file=sys.stderr)
                return 2
        if mac:
            for m, dev in rom + app:
                if m != mac and dev not in ignored:
                    ignored.add(dev)
                    print(f'ignoring unrelated Espressif device {dev} (serial {m or "unknown"})',
                          file=sys.stderr)
            port = target_rom(mac, rom)
            if port:
                print(port)
                return 0
            for m, dev in app:
                if m != mac:
                    continue
                try:
                    alive = poke_bootloader(dev, serial_module)
                    print(f'{dev}: console {"REPLIED" if alive else "silent"}; requested ROM mode',
                          file=sys.stderr, flush=True)
                except Exception as e:  # port may vanish mid-reboot
                    print(f'[{dev} open failed: {e}]', file=sys.stderr, flush=True)
        sleep(0.8)
    print(f'T-Dongle {mac or "(none found)"} did not enter ROM download mode in time', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
