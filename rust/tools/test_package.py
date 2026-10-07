#!/usr/bin/env python3
"""Host-only packaging provenance tests with synthetic app/ELF bytes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('package.py').resolve()
REPO = SCRIPT.parents[2]


class ProvenanceTests(unittest.TestCase):
    def package(self, source=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        app, elf, out = root / 'app.bin', root / 'app.elf', root / 'package'
        app.write_bytes(b'\xe9\x00\x02\x40firmware=0.4.0-rc2')
        elf.write_bytes(b'synthetic host test ELF')
        env = dict(os.environ)
        env.pop('TDONGLE_FIRMWARE_SOURCE', None)
        if source is not None:
            env['TDONGLE_FIRMWARE_SOURCE'] = source
        result = subprocess.run([sys.executable, str(SCRIPT), '0.4.0-rc2', str(app), str(elf), str(out)], cwd=root, env=env, capture_output=True, text=True)
        return result, out

    def test_default_uses_head_even_from_outside_repo(self):
        result, out = self.package()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((out / 'manifest.json').read_text())
        head = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
        self.assertEqual(manifest['git_commit'], head)
        self.assertEqual(manifest['firmware_git_commit'], head)

    def test_explicit_source_is_resolved_separately(self):
        result, out = self.package('HEAD~1')
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((out / 'manifest.json').read_text())
        expected = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD~1'], text=True).strip()
        self.assertEqual(manifest['firmware_git_commit'], expected)
        self.assertNotEqual(manifest['firmware_git_commit'], manifest['git_commit'])

    def test_invalid_source_fails_before_package_creation(self):
        result, out = self.package('tdongle-invalid-build-source-for-host-test')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
