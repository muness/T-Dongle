import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location("audit", Path(__file__).parents[1] / "tools/audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class MemoryEvidenceTest(unittest.TestCase):
    def test_counts_are_dynamic_and_zero_is_empty(self):
        m = dict(zip(audit.NAMES, [23936, 456, 47104, 65536, 65536, 6544, 288]))
        r = audit.memory_report(m, [0, 1, 2, 3, 7])
        self.assertEqual([x["count"] for x in r["memberships"]], [0, 1, 2, 3, 7])
        self.assertEqual(r["memberships"][0]["lower_bound_bytes"], 0)
        self.assertFalse(r["hardware_qualified"])
        self.assertTrue(r["memberships"][3]["exceeds_entire_chip_sram"])

    def test_smaller_exchange_buffer_cannot_hide_retained_h2_buffer(self):
        m = dict(zip(audit.NAMES, [23936, 456, 47104, 16384, 16384, 6544, 288]))
        r = audit.memory_report(m, [3])
        self.assertEqual(r["per_member_lower_bound_bytes"], 77584 + 65536 + 16384)
        self.assertIn("TLS allocations", r["excluded"])

if __name__ == "__main__":
    unittest.main()
