#!/usr/bin/env python3
"""Bounded CDC console exchanges without modem-control resets or held ports."""
import json
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
            if command == b"status" and STATUS.search(reply):
                break
            if command == b"boot-status" and boot_report(reply) is not None:
                break
        return bytes(reply)
    finally:
        os.close(fd)


def boot_report(reply):
    for line in reply.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == 1 and isinstance(value.get("rescue"), dict):
            return value
    return None


class BootProgress:
    """Reject resets and require sustained, supervisor-proven boot health."""
    def __init__(self):
        self.previous_uptime = None
        self.identity = None
        self.healthy_uptime = None

    def observe(self, report):
        uptime = report.get("uptime_ms")
        identity = (report.get("elf"), report.get("reset_reason"), report["rescue"].get("count"))
        if not isinstance(uptime, int) or isinstance(uptime, bool) or uptime < 0:
            return False
        if self.previous_uptime is not None and (uptime < self.previous_uptime or identity != self.identity):
            raise RuntimeError("firmware reset while waiting for healthy boot")
        self.previous_uptime = uptime
        self.identity = identity
        healthy = (report.get("stage") == "running" and report["rescue"].get("state") == "healthy"
                   and report.get("safe_mode") is False and report.get("recovery") is False and uptime >= 30000)
        if not healthy:
            self.healthy_uptime = None
            return False
        if self.healthy_uptime is None:
            self.healthy_uptime = uptime
            return False
        return uptime - self.healthy_uptime >= 1000


def wait_healthy(port, timeout=120, sample=None, sleep=time.sleep, now=time.monotonic):
    progress = BootProgress()
    def console_sample():
        if not STATUS.search(exchange(port, b"status")):
            return None
        return boot_report(exchange(port, b"boot-status"))
    sample = sample or console_sample
    deadline = now() + timeout
    while now() < deadline:
        try:
            report = sample()
            if report is not None:
                if progress.observe(report):
                    return True
            else:
                progress.healthy_uptime = None
        except OSError:
            # Enumeration/open errors can happen before the first successful boot.
            progress.healthy_uptime = None
        sleep(1)
    return False


def main():
    action, port = sys.argv[1:]
    try:
        if action == "poke":
            exchange(port, b"bootloader", 0.3)
            return 0
        if action == "ready":
            if wait_healthy(port):
                print("healthy running boot: fresh status and advancing uptime")
                return 0
            print("firmware did not reach a sustained healthy boot within 120 s", file=sys.stderr)
            return 1
        raise ValueError("expected poke or ready")
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
