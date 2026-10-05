import importlib.util,json,tempfile,unittest,hashlib
from pathlib import Path
spec=importlib.util.spec_from_file_location("android_manifest",Path(__file__).resolve().parents[1]/"tools/android_manifest.py")
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Manifest(unittest.TestCase):
    def test_actual_images_and_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            for name in ("bootloader.bin","partition-table.bin","app.bin"): (p/name).write_bytes(name.encode())
            manifest=module.descriptor(p,"1.2.3")
            self.assertEqual([0,32768,131072],[image["offset"] for image in manifest["images"]])
            self.assertEqual(hashlib.sha256(b"app.bin").hexdigest(),manifest["images"][2]["sha256"])
            self.assertEqual("factory-nvs-v1",manifest["layout"])
            with self.assertRaises(ValueError): module.descriptor(p,"1.2.3-beta")
            (p/"app.bin").write_bytes(b"")
            with self.assertRaises(ValueError): module.descriptor(p,"1.2.3")
