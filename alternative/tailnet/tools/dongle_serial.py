"""Line-oriented access to the T-Dongle USB serial console (shared by the measurement scripts).

The console does not echo, answers every command with its output followed by a "done>" line,
and prints one JSON object per line for the diagnostics commands. Needs pyserial (tools/requirements.txt).
"""
import glob
import json
import time

PROMPT = "done>"


class ConsoleError(RuntimeError):
    pass


def find_port():
    ports = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*"))
    if len(ports) != 1:
        raise ConsoleError(f"pass --port: found {len(ports)} candidate serial ports {ports}")
    return ports[0]


class Console:
    """`link` is any object with write(bytes), readline() -> bytes and reset_input_buffer() (a pyserial Serial)."""

    def __init__(self, link, command_timeout=20.0):
        self.link = link
        self.command_timeout = command_timeout

    @classmethod
    def open(cls, port=None, **kwargs):
        import serial  # imported late so --help and the unit test work without hardware

        link = serial.Serial(port or find_port(), 115200, timeout=0.5, write_timeout=2)
        return cls(link, **kwargs)

    def close(self):
        close = getattr(self.link, "close", None)
        if close:
            close()

    def command(self, line):
        """Send one command and return its output lines (without the prompt)."""
        self.link.reset_input_buffer()
        self.link.write(line.encode("ascii") + b"\n")
        lines, deadline = [], time.monotonic() + self.command_timeout
        while time.monotonic() < deadline:
            raw = self.link.readline()
            if not raw:
                continue
            text = raw.decode("utf-8", "replace").strip()
            if text == PROMPT:
                return lines
            if text:
                lines.append(text)
        raise ConsoleError(f"no {PROMPT} after {line!r}; got {lines[-3:]}")

    def json_command(self, line):
        """Run a diagnostics command and return {kind: object, or list of objects for repeated kinds}."""
        reports = {}
        for text in self.command(line):
            if not text.startswith("{"):
                if text.startswith("ERR"):
                    raise ConsoleError(f"{line!r}: {text}")
                continue
            try:
                report = json.loads(text)
            except json.JSONDecodeError as error:
                raise ConsoleError(f"{line!r} returned broken JSON ({error}): {text[:120]}") from error
            reports.setdefault(report.get("kind", "unknown"), []).append(report)
        return reports

    def require_diagnostics(self):
        features = " ".join(self.command("capabilities"))
        if "memory_diagnostics" not in features:
            raise ConsoleError("this firmware is not a diagnostics build (capabilities lacks memory_diagnostics); "
                               "flash the image from tools/build-diagnostics.sh")
        return features
