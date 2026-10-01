from __future__ import annotations

import unittest

from domain_security_scanner.standards.registry import get_standard


class NegativeDnsStandardsRegistryTests(unittest.TestCase):
    def test_negative_dns_and_open_recursion_rfcs_are_registered(self):
        rfc2308 = get_standard("RFC2308")
        self.assertEqual(rfc2308.number, 2308)
        self.assertIn("Negative Caching", rfc2308.title)
        self.assertIn("DNS", rfc2308.scope)

        rfc5358 = get_standard("RFC5358")
        self.assertEqual(rfc5358.number, 5358)
        self.assertIn("Recursive Nameservers", rfc5358.title)
        self.assertIn("recurs", rfc5358.scope.lower())


if __name__ == "__main__":
    unittest.main()
