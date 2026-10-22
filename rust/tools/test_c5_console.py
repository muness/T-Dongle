"""Cross-language vector, escaping, bounds and resynchronization for the owner console."""
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('console', Path(__file__).with_name('c5-console.py'))
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)

class ConsoleWireTest(unittest.TestCase):
    def decode(self, data):
        decoder = console.Decoder()
        return [f for b in data if (f := decoder.feed(b)) is not None]

    def test_shared_rust_java_vector(self):
        vector = Path(__file__).parents[1] / 'crates/tdongle-serial-ip/tests/wire.hex'
        self.assertEqual(console.encode(5, 0x0102030405060708, bytes([0xc0,0xdb,0,255])).hex(), vector.read_text().strip())

    def test_roundtrip_and_bounds(self):
        for payload in [b'',b'gateway',bytes(range(256)),bytes([0xc0,0xdb])*750]:
            self.assertEqual(self.decode(console.encode(8,42,payload)),[(8,42,payload)])
        with self.assertRaises(ValueError): console.encode(8,42,b'x'*1501)

    def test_corrupt_and_truncated_frames_resynchronize(self):
        good=console.encode(8,42,b'status')
        bad=bytearray(good);bad[4]^=1
        self.assertEqual(self.decode(bytes(bad)+good[:-5]+good),[(8,42,b'status')])

    def test_boot_noise_and_oversize_frame_do_not_become_commands(self):
        good=console.encode(8,42,b'status')
        self.assertEqual(self.decode(b'boot message'+bytes([console.END])+b'x'*2000+good),[(8,42,b'status')])

if __name__ == '__main__': unittest.main()
