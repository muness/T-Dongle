# SPDX-License-Identifier: MIT
"""The setup access point and a tailnet never run together (ADR 0024).

The access point is not charged to tailnet admission (ml_admission.h) or to ADR 0022's elastic floor (ml_heap_budget.h): it is allowed to
exist only because nothing that those budgets protect is running while it does. This pins the three places that guarantee it, beyond
the behavioural check in alternative/tailnet/tests/test_startup.c: no membership starts in a setup boot, the setup start does not
appear in a normal boot's sequence (so the access point cannot be started inside a running dongle), and the only thing that sets the
flag is the boot decision."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / 'alternative/tailnet/main'
GATEWAY = (MAIN / 'gateway_main.c').read_text()
SEQUENCE = (MAIN / 'startup_sequence.inc').read_text()
SETUP = (MAIN / 'setup_ap.inc').read_text()


class SetupExclusion(unittest.TestCase):
    def test_no_membership_starts_in_a_setup_boot(self):
        body = GATEWAY[GATEWAY.index('static void start_member(membership_t *m) {'):]
        guard = body[:body.index('return;')]
        self.assertRegex(guard, r'if \(setup_active \|\|')

    def test_the_tailnet_stages_are_only_in_the_normal_branch(self):
        setup_branch = SEQUENCE[SEQUENCE.index('if(setup_active) {'):SEQUENCE.index('} else {')]
        normal_branch = SEQUENCE[SEQUENCE.index('} else {'):]
        for stage in ('start_directory', 'start_routes', 'start_wifi', 'start_dns', 'start_manager'):
            self.assertNotIn(stage, setup_branch, f'{stage} would run beside the access point')
            self.assertIn(stage, normal_branch)
        self.assertIn('start_setup', setup_branch)
        self.assertNotIn('start_setup', normal_branch)

    def test_recovery_outranks_a_setup_request(self):
        self.assertRegex(SEQUENCE, r'if\(gateway_boot_recovery\(\)\)setup_active=false;')
        self.assertRegex(SEQUENCE, r'if\(!gateway_boot_recovery\(\)\) \{\s*if\(setup_active\)')

    def test_the_flag_is_set_only_by_the_boot_decision(self):
        assigned = re.findall(r'\bsetup_active\s*=\s*([^;=]+);', GATEWAY + SEQUENCE + SETUP + (MAIN / 'device_ui.inc').read_text() + (MAIN / 'serial_setup.inc').read_text())
        self.assertEqual(sorted(a.strip() for a in assigned), ['boot.setup', 'false'])

    def test_the_bridge_pool_is_not_started_for_setup(self):
        # tdongle_l2_start belongs to start_wifi, which a setup boot never runs.
        self.assertEqual(GATEWAY.count('tdongle_l2_start('), 1)
        start_wifi = GATEWAY[GATEWAY.index('static esp_err_t start_wifi(void) {'):]
        self.assertLess(start_wifi.index('tdongle_l2_start('), start_wifi.index('static esp_err_t start_dns'))
        self.assertNotIn('tdongle_l2_start', SETUP)

    def test_no_usb_netif_in_a_setup_boot(self):
        # lwIP forwards (CONFIG_LWIP_IP_FORWARD=y): a USB netif beside the open access point would route the setup network to the USB host.
        body = GATEWAY[GATEWAY.index('static esp_err_t start_network(void) {'):]
        body = body[:body.index('esp_netif_inherent_config_t')]
        self.assertRegex(body, r'if\(!gateway_tailnet_mode\(\) \|\| setup_active\)return ESP_OK;')
        self.assertNotIn('esp_netif_new', GATEWAY[:GATEWAY.index('static esp_err_t start_network(void) {')])
        self.assertEqual(GATEWAY.count('esp_netif_new('), 1)
        self.assertEqual(GATEWAY.count('esp_netif_napt_enable('), 1)
        self.assertNotIn('esp_netif_napt_enable', SETUP)   # and NAPT lives in start_dns, which a setup boot never runs

    def test_the_failsafe_timer_is_armed_for_every_setup_boot(self):
        self.assertRegex(GATEWAY, r'if\(setup_active\)\{setup_session_start\(&setup_clock,[^;]*;setup_failsafe_arm\(\);\}')
        self.assertIn('setup_session_failsafe_delay_ms', SETUP)

    def test_pm_scaling_is_not_started_for_setup(self):
        self.assertRegex(GATEWAY, r'if\(!setup_active\)tdongle_pm_start\(\);')


if __name__ == '__main__':
    unittest.main()
