# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

def load(name):
    spec = importlib.util.spec_from_file_location(name, Path('tools') / (name + '.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

provision, host = load('provision'), load('host_diagnostics')
class Tools(unittest.TestCase):
    def profile(self):
        return dict(slot=1, name='Home', ssid='A'*32, password='x'*63, priority=100)
    def test_limits(self):
        self.assertEqual(provision.validate_profile(self.profile())['slot'], 1)
        for key, value in [('slot', 0), ('slot', True), ('ssid', 'x'*33), ('ssid', ''), ('name', 'x'*25), ('password', 'short'), ('password', 'x'*64), ('ssid', 'bad\nSSID'), ('priority', 101), ('password', 'cafépassword')]:
            with self.subTest(key=key, value=value):
                p=self.profile();p[key]=value
                with self.assertRaises(ValueError):provision.validate_profile(p)
    def test_open(self):
        p=self.profile();p['password']='';provision.validate_profile(p)
    def test_missing_tool(self):
        with patch.object(host.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertIn('unavailable', host.capture(['missing']))
    def test_permission_denied(self):
        with patch.object(host.subprocess, 'run', return_value=host.subprocess.CompletedProcess([], 1, '', 'Permission denied')):
            self.assertEqual(host.capture(['ip'])['exit'], 1)
    def test_read_only(self):
        for cmd in host.commands(True)+host.commands(False, 'Darwin')+host.commands(False, 'Linux'):
            self.assertFalse({'sudo','root','reboot','setprop','install','flash','dhclient'} & set(cmd))
    def test_no_secret_arguments(self):
        source=Path('tools/provision.py').read_text()
        self.assertNotIn("add_argument('--password'",source)
        self.assertIn('getpass.getpass',source)

class Packaging(unittest.TestCase):
    def test_virtual_component_cannot_recurse_into_artifacts(self):
        import tempfile
        package = load('package')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            component=root/'components'/'driver';component.mkdir(parents=True)
            (component/'LICENSE').write_text('fixture')
            output=root/'dist'/'artifact';output.mkdir(parents=True)
            (output/'LICENSE').write_text('must not collect')
            found=list(package.notice_sources(['',str(root),str(output),str(component)],root,root/'idf'))
            self.assertEqual([p.name for _,p in found],['LICENSE'])
            self.assertEqual(found[0][0],component)

    def test_archive_names_preserve_version_and_variant(self):
        package=load('package')
        self.assertEqual(str(package.archive_path(Path('dist/tdongle-0.1.0-full'))),'dist/tdongle-0.1.0-full.tar.gz')
        self.assertNotEqual(package.archive_path(Path('full')),package.archive_path(Path('network-only')))
