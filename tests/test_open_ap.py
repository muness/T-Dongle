# SPDX-License-Identifier: MIT
"""Guard: the setup Wi-Fi AP must never require a password.

Owner decision (repeated, explicit): setup mode is an open network. This is a preprocessor-aware
scan of alternative/tailnet/main/setup_ap.inc, not a full C AST (that would need the whole ESP-IDF header tree). It fails
if any WPA/password configuration of the AP can be reached while CONFIG_TDONGLE_SETUP_AP_OPEN is on,
if the option defaults off, or if a defaults file turns it off.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLAG = 'CONFIG_TDONGLE_SETUP_AP_OPEN'
SOURCE = 'alternative/tailnet/main/setup_ap.inc'
KCONFIG = 'main/Kconfig.projbuild'
FORBIDDEN_WHEN_OPEN = re.compile(r'WIFI_AUTH_(?!OPEN)\w+|pmf_cfg|(?:strcpy|memcpy|strlcpy)\s*\(\s*(?:\(char\s*\*\)\s*)?config\.ap\.password')


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
        kconfig = (ROOT / KCONFIG).read_text()
        block = kconfig[kconfig.index('config TDONGLE_SETUP_AP_OPEN'):]
        block = block.split('\n config ', 1)[0].split('endmenu', 1)[0]
        for f in ROOT.glob('sdkconfig.*'):
            self.assertNotRegex(f.read_text(), r'(?m)^CONFIG_TDONGLE_SETUP_AP_OPEN=n',
                                f'{f.name} disables the open setup AP')
        self.assertIn('bool', block)
        self.assertRegex(block, r'default\s+y', 'Kconfig default for the open setup AP must be y')

    def test_no_password_reachable_when_open(self):
        src = (ROOT / SOURCE).read_text()
        seen_open_auth = False
        for n, line, open_active in branches(src):
            code = line.split('//')[0]
            if open_active is True:
                self.assertFalse(FORBIDDEN_WHEN_OPEN.search(code),
                                 f'setup_ap.inc:{n} configures a password/WPA on the open-AP branch: {line.strip()}')
                seen_open_auth |= 'WIFI_AUTH_OPEN' in code
        self.assertTrue(seen_open_auth, 'open-AP branch must set WIFI_AUTH_OPEN')

    def test_password_authmode_only_in_disabled_branch(self):
        src = (ROOT / SOURCE).read_text()
        for n, line, open_active in branches(src):
            if 'WIFI_AUTH_WPA' in line.split('//')[0]:
                self.assertIs(open_active, False,
                              f'setup_ap.inc:{n} sets WPA outside the CONFIG_TDONGLE_SETUP_AP_OPEN=n branch')

    def test_identity_clears_password_when_open(self):
        src = (ROOT / SOURCE).read_text()
        self.assertTrue(any(open_active is True and re.search(r'setup_ap_password\[0\]\s*=\s*0', line)
                            for _, line, open_active in branches(src)),
                        'start_setup must blank the AP password under the open flag')

    def test_guard_detects_a_regression(self):
        bad = '#if CONFIG_TDONGLE_SETUP_AP_OPEN\nconfig.ap.authmode = WIFI_AUTH_WPA2_PSK;\n#endif\n'
        self.assertTrue(any(a is True and FORBIDDEN_WHEN_OPEN.search(l) for _, l, a in branches(bad)))
        good = '#if CONFIG_TDONGLE_SETUP_AP_OPEN\nconfig.ap.authmode = WIFI_AUTH_OPEN;\n#else\nconfig.ap.authmode = WIFI_AUTH_WPA2_PSK;\n#endif\n'
        self.assertFalse(any(a is True and FORBIDDEN_WHEN_OPEN.search(l) for _, l, a in branches(good)))


if __name__ == '__main__':
    unittest.main()
