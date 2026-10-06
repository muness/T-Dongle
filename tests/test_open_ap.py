# SPDX-License-Identifier: MIT
"""Guard: the setup Wi-Fi AP must never require a password.

Owner decision (repeated, explicit): setup mode is an open network. This is a preprocessor-aware
scan of legacy/portal.c (archived reference, see legacy/README.md), not a full C AST (that would need the whole ESP-IDF header tree). It fails
if any WPA/password configuration of the AP can be reached while CONFIG_ADAPTER_OPEN_SETUP_AP is on,
if the option defaults off, or if a defaults file turns it off.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLAG = 'CONFIG_ADAPTER_OPEN_SETUP_AP'
FORBIDDEN_WHEN_OPEN = re.compile(r'WIFI_AUTH_(?!OPEN)\w+|pmf_cfg|strcpy\s*\(\s*\(char\s*\*\)\s*c\.ap\.password')


def branches(source):
    """Yield (line_no, text, open_active) where open_active is True if the line is compiled
    only/also when the open-AP flag is on. #else of the flag is the password branch."""
    stack = []  # each entry: None (unrelated #if) or True/False = flag-on state of current branch
    for n, line in enumerate(source.splitlines(), 1):
        m = re.match(r'\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)', line)
        if m:
            kind, rest = m.groups()
            if kind in ('if', 'ifdef', 'ifndef'):
                stack.append(True if (FLAG in rest and kind != 'ifndef' and '!' not in rest) else
                             False if (FLAG in rest) else None)
            elif kind == 'else' and stack and stack[-1] is not None:
                stack[-1] = not stack[-1]
            elif kind == 'endif' and stack:
                stack.pop()
            continue
        flag_states = [s for s in stack if s is not None]
        yield n, line, (all(flag_states) if flag_states else None)


class OpenSetupAp(unittest.TestCase):
    def test_kconfig_and_defaults_enable_open_ap(self):
        kconfig = (ROOT / 'legacy/Kconfig.projbuild').read_text()
        block = kconfig[kconfig.index('config ADAPTER_OPEN_SETUP_AP'):]
        block = block.split('\n config ', 1)[0].split('endmenu', 1)[0]
        for f in ROOT.glob('sdkconfig.*'):
            self.assertNotRegex(f.read_text(), r'(?m)^CONFIG_ADAPTER_OPEN_SETUP_AP=n',
                                f'{f.name} disables the open setup AP')
        self.assertIn('bool', block)
        self.assertRegex(block, r'default\s+y', 'Kconfig default for the open setup AP must be y')

    def test_no_password_reachable_when_open(self):
        src = (ROOT / 'legacy/portal.c').read_text()
        seen_open_auth = False
        for n, line, open_active in branches(src):
            code = line.split('//')[0]
            if open_active is True:
                self.assertFalse(FORBIDDEN_WHEN_OPEN.search(code),
                                 f'portal.c:{n} configures a password/WPA on the open-AP branch: {line.strip()}')
                seen_open_auth |= 'WIFI_AUTH_OPEN' in code
        self.assertTrue(seen_open_auth, 'open-AP branch must set WIFI_AUTH_OPEN')

    def test_password_authmode_only_in_disabled_branch(self):
        src = (ROOT / 'legacy/portal.c').read_text()
        for n, line, open_active in branches(src):
            if 'WIFI_AUTH_WPA' in line.split('//')[0]:
                self.assertIs(open_active, False,
                              f'portal.c:{n} sets WPA outside the CONFIG_ADAPTER_OPEN_SETUP_AP=n branch')

    def test_identity_clears_password_when_open(self):
        src = (ROOT / 'legacy/portal.c').read_text()
        self.assertTrue(any(open_active is True and re.search(r'ap_pass\[0\]\s*=\s*0', line)
                            for _, line, open_active in branches(src)),
                        'portal_identity must blank the AP password under the open flag')

    def test_guard_detects_a_regression(self):
        bad = '#if CONFIG_ADAPTER_OPEN_SETUP_AP\nc.ap.authmode = WIFI_AUTH_WPA2_PSK;\n#endif\n'
        self.assertTrue(any(a is True and FORBIDDEN_WHEN_OPEN.search(l) for _, l, a in branches(bad)))
        good = '#if CONFIG_ADAPTER_OPEN_SETUP_AP\nc.ap.authmode = WIFI_AUTH_OPEN;\n#else\nc.ap.authmode = WIFI_AUTH_WPA2_PSK;\n#endif\n'
        self.assertFalse(any(a is True and FORBIDDEN_WHEN_OPEN.search(l) for _, l, a in branches(good)))


if __name__ == '__main__':
    unittest.main()
