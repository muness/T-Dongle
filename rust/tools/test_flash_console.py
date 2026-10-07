#!/usr/bin/env python3
"""Host-only flash helper tests: never enumerate or open a physical device."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("flash_console", Path(__file__).with_name("flash_console.py"))
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


class ConsoleTests(unittest.TestCase):
    def test_status_goldens_are_recognized(self):
        goldens = Path(__file__).parents[1] / "crates/tdongle-serial/tests/golden/status.golden"
        lines = [line for line in goldens.read_bytes().splitlines() if line.startswith(b"mode=")]
        self.assertGreater(len(lines), 10)
        for line in lines:
            self.assertIsNotNone(console.STATUS.search(line + b"\r\n"), line)
        for bad in [b"USB ready", b"ESP-ROM:esp32s3", b"mode=tailnet", b"panic: reboot"]:
            self.assertIsNone(console.STATUS.search(bad))

    def test_fd_closed_if_raw_or_write_fails(self):
        for where in ["tty.setraw", "os.write"]:
            with self.subTest(where=where), patch.object(console.os, "open", return_value=123), patch.object(console.os, "close") as close, patch.object(console.tty, "setraw"), patch.object(console.select, "select", return_value=([], [], [])), patch.object(console.os, "write"), patch("flash_console." + where, side_effect=OSError("port disappeared")):
                with self.assertRaises(OSError):
                    console.exchange("FAKE-PORT", b"status")
                close.assert_called_once_with(123)

    def test_fresh_status_request_and_close(self):
        reply = b"mode=tailnet trial=0 active=1 wifi=up rssi=-42 usb_enumerated=1 usb_transport_ready=1\r\n"
        with patch.object(console.os, "open", return_value=123) as opened, patch.object(console.os, "close") as close, patch.object(console.tty, "setraw"), patch.object(console.os, "write") as write, patch.object(console.os, "read", return_value=reply), patch.object(console.select, "select", side_effect=[([], [], []), ([123], [], [])]):
            self.assertEqual(console.exchange("FAKE-PORT", b"status"), reply)
            opened.assert_called_once_with("FAKE-PORT", console.os.O_RDWR | console.os.O_NOCTTY | console.os.O_NONBLOCK)
            write.assert_called_once_with(123, b"\r\nstatus\r\n")
            close.assert_called_once_with(123)

    def test_stale_status_is_drained(self):
        with patch.object(console.os, "open", return_value=123), patch.object(console.os, "close") as close, patch.object(console.tty, "setraw"), patch.object(console.os, "write"), patch.object(console.os, "read", side_effect=[b"mode=tailnet trial=0 active=1 wifi=up rssi=-42 usb_enumerated=1 usb_transport_ready=1\r\n", b""]), patch.object(console.select, "select", side_effect=[([123], [], []), ([], [], []), ([123], [], [])]):
            self.assertEqual(console.exchange("FAKE-PORT", b"status"), b"")
            close.assert_called_once_with(123)

    @staticmethod
    def report(uptime, healthy=False, stage="running", count=0):
        return {"schema": 1, "elf": "abc", "reset_reason": "Software", "rescue": {"state": "healthy" if healthy else "armed", "count": count}, "safe_mode": False, "recovery": False, "stage": stage, "uptime_ms": uptime}

    def test_early_replies_then_crash_never_ready(self):
        progress = console.BootProgress()
        self.assertFalse(progress.observe(self.report(1000)))
        self.assertFalse(progress.observe(self.report(2000)))
        self.assertFalse(progress.observe(self.report(10000)))
        with self.assertRaisesRegex(RuntimeError, "reset"):
            progress.observe(self.report(1000, count=1))

    def test_health_requires_running_not_recovery_and_advancing_uptime(self):
        progress = console.BootProgress()
        self.assertFalse(progress.observe(self.report(1000, healthy=True)))
        self.assertFalse(progress.observe(self.report(31000, healthy=True, stage="wifi")))
        recovery = self.report(32000, healthy=True)
        recovery["recovery"] = True
        self.assertFalse(progress.observe(recovery))
        self.assertFalse(progress.observe(self.report(33000, healthy=True)))
        self.assertFalse(progress.observe(self.report(33000, healthy=True)))
        self.assertTrue(progress.observe(self.report(34000, healthy=True)))

    def test_boot_json_is_complete_and_not_console_noise(self):
        encoded = console.json.dumps(self.report(35000, healthy=True)).encode()
        self.assertEqual(console.boot_report(b"boot-status\r\n" + encoded + b"\r\ndone>"), self.report(35000, healthy=True))
        self.assertIsNone(console.boot_report(encoded[:-1]))
        self.assertIsNone(console.boot_report(b"ESP-ROM:esp32s3"))

    def test_wait_healthy_early_responses_disappear(self):
        clock = [0]
        samples = iter([self.report(1000), self.report(2000), None])
        def sleep(seconds):
            clock[0] += seconds
        self.assertFalse(console.wait_healthy("FAKE-PORT", timeout=5, sample=lambda: next(samples, None), sleep=sleep, now=lambda: clock[0]))
        self.assertEqual(clock[0], 5)

    def test_wait_healthy_requires_consecutive_fresh_health_after_disconnect(self):
        clock = [0]
        samples = iter([self.report(1000), self.report(31000, True), None, self.report(34000, True), self.report(35000, True)])
        def sleep(seconds):
            clock[0] += seconds
        self.assertTrue(console.wait_healthy("FAKE-PORT", timeout=10, sample=lambda: next(samples, None), sleep=sleep, now=lambda: clock[0]))
        self.assertEqual(clock[0], 4)


if __name__ == "__main__":
    # The patch target needs this name even when launched as a script.
    import sys
    sys.modules["flash_console"] = console
    unittest.main()
