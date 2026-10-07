#!/usr/bin/env python3
"""Execute a copied flash script exclusively against fake commands and paths."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).with_name("flash.sh")


class FlashTests(unittest.TestCase):
    def run_flash(self, failures="", override=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "FAKE-APP"
            app.touch()
            script = root / "flash.sh"
            # The tested copy cannot reference a real serial device.
            text = SOURCE.read_text()
            app_line = next(line for line in text.splitlines() if line.startswith("APP_PORT="))
            script.write_text(text.replace(app_line, 'APP_PORT="' + str(app) + '"'))
            (root / "app.bin").write_bytes(b"not firmware")
            def executable(name, body):
                path = root / name
                path.write_text("#!/bin/sh\n" + body)
                path.chmod(0o755)
                return path
            executable("sleep", "exit 0\n")
            executable("lsof", "exit 0\n")
            executable("python", '''if [ "$1" = "-" ]; then
  cat >/dev/null
  echo FAKE-ROM
else
  echo ready >> "$TEST_LOG"
fi
''')
            esptool = executable("esptool", '''echo "$*" >> "$TEST_LOG"
case "$*" in
  *read_mac*) echo 'MAC: 30:ed:a0:d7:88:bc'; exit 0;;
esac
n=0
[ ! -f "$TEST_COUNT" ] || n=$(cat "$TEST_COUNT")
n=$((n+1)); echo "$n" > "$TEST_COUNT"
if [ "$n" -le "$TEST_FAILURE_COUNT" ]; then echo "$TEST_FAILURE" >&2; exit 1; fi
exit 0
''')
            env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], ESPTOOL=str(esptool), TEST_LOG=str(root / "log"), TEST_COUNT=str(root / "count"), TEST_FAILURE=failures, TEST_FAILURE_COUNT="1" if failures else "0")
            env.pop("TDONGLE_MAC", None)
            if override:
                env["TDONGLE_MAC"] = override
            result = subprocess.run(["bash", str(script), str(root / "app.bin")], env=env, capture_output=True, text=True, timeout=5)
            calls = (root / "log").read_text() if (root / "log").exists() else ""
            return result, calls

    def test_success_checks_sustained_health_without_hard_reset(self):
        result, calls = self.run_flash()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("ready\n"), 1)
        self.assertNotIn("hard_reset", calls)
        self.assertIn("--before no_reset --after watchdog_reset write_flash", calls)
        self.assertNotIn("/dev/", calls)

    def test_busy_retries(self):
        result, calls = self.run_flash("Could not open port: [Errno 16] Resource busy")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("write_flash"), 2)

    def test_write_failure_is_not_repeated(self):
        result, calls = self.run_flash("Hash of data does not match")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls.count("write_flash"), 1)
        self.assertNotIn("ready\n", calls)

    def test_other_board_override_refused_before_discovery(self):
        result, calls = self.run_flash(override="28:84:85:43:ae:88")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, "")
        self.assertIn("pinned", result.stderr)


if __name__ == "__main__":
    unittest.main()
