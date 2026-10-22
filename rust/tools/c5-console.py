#!/usr/bin/env python3
"""Owner console for C5 serial-ip/2 (pip install pyserial). Never flashes hardware."""
import argparse
import binascii
import getpass
import json
import secrets
import struct
import threading
import time

END, ESC = 0xC0, 0xDB
HELLO, IDENTITY, JOIN, STATUS, IP, STOP, PING, COMMAND, REPLY = range(1, 10)
BOARD = b'TDONGLE-C5 0.4.0-rc2 serial-ip/2'


def encode(kind, session, payload=b''):
    if len(payload) > 1500:
        raise ValueError('Payload too large')
    raw = struct.pack('>2sBBQH', b'TD', 1, kind, session, len(payload)) + payload
    raw += struct.pack('>H', binascii.crc_hqx(raw, 0xFFFF))
    return bytes([END]) + raw.replace(bytes([ESC]), b'\xdb\xdd').replace(bytes([END]), b'\xdb\xdc') + bytes([END])


class Decoder:
    def __init__(self):
        self.raw = bytearray()
        self.escaped = False
        self.discard = True

    def feed(self, byte):
        if byte == END:
            raw = bytes(self.raw)
            valid = not self.discard and not self.escaped
            self.raw.clear()
            self.escaped = self.discard = False
            if not valid or len(raw) < 16 or raw[:3] != b'TD\x01':
                return None
            _, _, kind, session, size = struct.unpack('>2sBBQH', raw[:14])
            if len(raw) != size + 16 or binascii.crc_hqx(raw[:-2], 0xFFFF) != int.from_bytes(raw[-2:], 'big'):
                return None
            return kind, session, raw[14:-2]
        if self.discard:
            return None
        if self.escaped:
            self.escaped = False
            if byte not in (0xDC, 0xDD):
                self.discard = True
                return None
            byte = END if byte == 0xDC else ESC
        elif byte == ESC:
            self.escaped = True
            return None
        if len(self.raw) >= 1516:
            self.discard = True
        else:
            self.raw.append(byte)
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', help='C5 serial device; disconnect Android VPN first')
    args = parser.parse_args()
    import serial
    session = secrets.randbits(64) or 1
    stop, identified = threading.Event(), threading.Event()
    write_lock = threading.Lock()
    with serial.Serial(args.port, 115200, timeout=0.2, write_timeout=2) as port:
        def send(kind, payload=b''):
            with write_lock:
                port.write(encode(kind, session, payload))

        def receive():
            decoder = Decoder()
            ping_at = 0
            try:
                while not stop.is_set():
                    if time.monotonic() >= ping_at:
                        send(PING if identified.is_set() else HELLO)
                        ping_at = time.monotonic() + 1
                    for byte in port.read(256):
                        frame = decoder.feed(byte)
                        if frame is None or frame[1] != session:
                            continue
                        kind, _, body = frame
                        if kind == IDENTITY and body == BOARD:
                            identified.set()
                        elif kind == REPLY and identified.is_set():
                            print(body.decode('utf-8', errors='replace'), end='', flush=True)
            except (serial.SerialException, OSError):
                stop.set()
                print('\nUSB connection ended.')

        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        try:
            if not identified.wait(5):
                raise SystemExit('No matching C5 firmware. No device was flashed.')
            print('C5 verified. Commands: help, gateway, gateway ap, gateway usb|wireless, quit.')
            print('Type wifi for private password entry; credentials are saved on the dongle.')
            while not stop.is_set():
                line = input('c5> ')
                if line == 'quit':
                    break
                if line == 'wifi':
                    ssid = input('Network name: ')
                    password = getpass.getpass('Wi-Fi password (empty for open): ')
                    line = 'profile ' + json.dumps({'ssid': ssid, 'password': password, 'priority': 50}, ensure_ascii=True)
                    password = None
                payload = line.encode('ascii')
                if not payload or len(payload) > 511 or any(b < 32 or b > 126 for b in payload):
                    print('Use one printable command, at most 511 bytes.')
                    continue
                send(COMMAND, payload)
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            stop.set()
            reader.join(3)
            try:
                send(STOP)
            except (serial.SerialException, OSError):
                pass


if __name__ == '__main__':
    main()
