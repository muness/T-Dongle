# SPDX-License-Identifier: MIT
"""The setup access point's page (alternative/tailnet/main/setup_ap.html) against the server that serves it.

The page is the only client the open setup access point has, so what it may ask for is checked from both sides: every request the
page makes must be one setup_access.h allows on the access point, the page must carry the per-boot token on all of them, it must
not reach anything off the dongle, and the server must register the endpoints it uses. The page's script must at least parse."""
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / 'alternative/tailnet/main/setup_ap.html').read_text()
SERVER = (ROOT / 'alternative/tailnet/main/gateway_main.c').read_text()
SCRIPT = re.search(r'<script>(.*)</script>', HTML, re.S).group(1)

ENDPOINTS = {'/': 'EP_HOME', '/wifi-scan': 'EP_WIFI_SCAN', '/wifi-saved': 'EP_WIFI_SAVED', '/command': 'EP_COMMAND',
             '/status': 'EP_STATUS', '/diagnostics': 'EP_DIAGNOSTICS', '/boot-status': 'EP_BOOT_STATUS'}
ACTIONS = ['mode', 'wifi', 'wifi_remove', 'add', 'remove', 'enable', 'setup_done']


def allowed_on_access_point(tmp):
    """Ask the real access rules (main/setup_access.c) what the setup access point may reach."""
    lines = ['#include "setup_access.h"', '#include <stdio.h>', 'int main(void){']
    for path, ep in ENDPOINTS.items():
        lines.append(f'printf("endpoint %s %d\\n","{path}",access_endpoint_allowed(ACCESS_SETUP_AP,{ep}));')
    for a in ACTIONS:
        lines.append(f'printf("action %s %d\\n","{a}",access_action_allowed(ACCESS_SETUP_AP,access_action_parse("{a}")));')
    lines.append('return 0;}')
    source = tmp / 'matrix.c'
    source.write_text('\n'.join(lines))
    subprocess.run(['cc', '-std=c11', '-I', str(ROOT / 'main'), str(source), str(ROOT / 'main/setup_access.c'), '-o', str(tmp / 'matrix')], check=True)
    out = subprocess.run([str(tmp / 'matrix')], check=True, capture_output=True, text=True).stdout.split('\n')
    endpoints = {l.split()[1] for l in out if l.startswith('endpoint') and l.endswith(' 1')}
    actions = {l.split()[1] for l in out if l.startswith('action') and l.endswith(' 1')}
    return endpoints, actions


class SetupPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = ROOT / 'build-host'
        tmp.mkdir(exist_ok=True)
        cls.endpoints, cls.actions = allowed_on_access_point(tmp)

    def test_what_the_access_point_may_reach_is_the_wifi_pages(self):
        self.assertEqual(self.endpoints, {'/', '/wifi-scan', '/wifi-saved', '/command'})
        self.assertEqual(self.actions, {'wifi', 'wifi_remove', 'setup_done'})

    def test_every_request_the_page_makes_is_allowed(self):
        paths = set(re.findall(r"""(?:api|send)\(\s*['"](/[a-z-]*)""", SCRIPT)) | {'/command'}   # send() posts to /command
        self.assertTrue(paths >= {'/wifi-scan', '/wifi-saved', '/command'}, paths)
        for path in paths:
            self.assertIn(path, self.endpoints, f'the page asks for {path}, which the setup access point may not reach')
        used = set(re.findall(r"""action\s*[:=]\s*['"]([a-z_]+)['"]""", SCRIPT))
        self.assertTrue(used >= {'wifi', 'wifi_remove', 'setup_done'}, used)
        for action in used:
            self.assertIn(action, self.actions, f'the page sends action {action}, which the setup access point may not use')

    def test_the_token_travels_with_every_request(self):
        self.assertEqual(HTML.count('@@TOKEN@@'), 1)
        self.assertRegex(HTML, r"const token='@@TOKEN@@';")
        self.assertIn("const H={'X-Setup-Token':token}", SCRIPT)
        # api() is the only caller of fetch, and it always starts from the token header (send() adds Content-Type to it, not instead of it).
        self.assertEqual(len(re.findall(r'\bfetch\(', SCRIPT)), 1)
        self.assertIn('Object.assign({headers:H},opt||{})', SCRIPT)
        self.assertIn("headers:Object.assign({'Content-Type':'application/json'},H)", SCRIPT)

    def test_the_page_stays_on_the_dongle(self):
        self.assertNotRegex(HTML, r'(?i)(https?:)?//[a-z0-9.-]+\.[a-z]{2,}')
        for forbidden in ('eval(', 'document.write', 'new Function', 'XMLHttpRequest', 'WebSocket', '<iframe', '<link', 'src='):
            self.assertNotIn(forbidden, HTML)
        # Server data (network names) only ever reaches the page as text, never as markup.
        for inner in re.findall(r'innerHTML\s*=\s*([^;]+);', SCRIPT):
            self.assertRegex(inner.strip(), r"^(''|\"<svg viewBox='0 0 52 52' aria-hidden=true>.*)$", inner)

    def test_the_server_serves_what_the_page_uses(self):
        for uri in ('/wifi-scan', '/wifi-saved', '/command', '/'):
            self.assertRegex(SERVER, r'\.uri\s*=\s*"' + re.escape(uri) + '"')
        self.assertIn('"/wifi-saved"', SERVER)
        self.assertIn('X-Setup-Token', SERVER)
        self.assertIn('setup_ap_html_start', SERVER)

    @unittest.skipUnless(shutil.which('node'), 'node is needed to parse the page script')
    def test_the_script_parses(self):
        out = subprocess.run(['node', '--check', '-'], input=SCRIPT, text=True, capture_output=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_the_markup_the_script_relies_on_exists(self):
        for element in re.findall(r"\$\('([a-z]+)'\)", SCRIPT):
            self.assertRegex(HTML, r'id=["\']?' + element + r'\b', f'the script uses #{element}, which the page does not have')


if __name__ == '__main__':
    unittest.main()
