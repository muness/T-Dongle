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


if __name__ == "__main__":
    # The patch target needs this name even when launched as a script.
    import sys
    sys.modules["flash_console"] = console
    unittest.main()
