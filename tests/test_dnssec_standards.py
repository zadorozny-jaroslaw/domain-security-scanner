from __future__ import annotations

import unittest

from domain_security_scanner.standards.registry import get_standard


class DnssecStandardsRegistryTest(unittest.TestCase):
    def test_dnssec_core_and_policy_rfcs_are_registered(self):
        for number in (4033, 4034, 4035, 9904, 9905, 9906):
            ref = get_standard(f"RFC{number}")
            self.assertEqual(ref.number, number)
            self.assertIn("DNS", ref.scope)


if __name__ == "__main__":
    unittest.main()
