#!/usr/bin/env python3
"""Bounded CDC console exchanges without modem-control resets or held ports."""
import os
import re
import select
import sys
import time
import tty

STATUS = re.compile(rb"(?m)^mode=(?:adapter|tailnet|setup) trial=\d+ active=\d+ wifi=(?:up|joining|AP not found|auth failed) rssi=(?:unknown|-?\d+) usb_enumerated=[01] usb_transport_ready=[01](?: [^\r\n]*)?\r?$")


def exchange(port, command, timeout=2.0):
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        tty.setraw(fd)
        # Discard unsolicited boot/status output before sending our own request.
        for _ in range(16):
            if not select.select([fd], [], [], 0)[0] or not os.read(fd, 4096):
                break
        os.write(fd, b"\r\n" + command + b"\r\n")
        deadline = time.monotonic() + timeout
        reply = bytearray()
        while time.monotonic() < deadline:
            if not select.select([fd], [], [], min(0.1, max(0, deadline - time.monotonic())))[0]:
                continue
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                continue
            if not chunk:
                break
            reply.extend(chunk)
            if len(reply) > 65536:
                break
            if STATUS.search(reply):
                break
        return bytes(reply)
    finally:
        os.close(fd)


def main():
    action, port = sys.argv[1:]
    try:
        if action == "poke":
            exchange(port, b"bootloader", 0.3)
            return 0
        if action == "ready":
            return 0 if STATUS.search(exchange(port, b"status")) else 1
        raise ValueError("expected poke or ready")
    except (OSError, ValueError):
        # A reset can remove the port mid-exchange; the caller bounds retries.
        return 1


if __name__ == "__main__":
    sys.exit(main())
