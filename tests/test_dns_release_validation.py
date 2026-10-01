from __future__ import annotations

import json
import unittest
from pathlib import Path

from domain_security_scanner.domains.domain.dns_scoring import (
    AUTHORITATIVE_RRSET_WEIGHT,
    AUTHORITATIVE_TCP_WEIGHT,
    CAA_MALFORMED_WEIGHT,
    DELEGATED_AUTHORITY_WEIGHT,
    DELEGATION_CONSISTENCY_WEIGHT,
    DNSSEC_SCORE_WEIGHT,
    DNSSEC_UNSIGNED_EARNED,
    NAMESERVER_ADDRESSABILITY_WEIGHT,
    NAME_SERVER_REDUNDANCY_WEIGHT,
    OPEN_RECURSION_WEIGHT,
)
from domain_security_scanner.standards.registry import get_standard


REQUIRED_SCENARIOS = {
    "normal_unsigned_public_domain",
    "correctly_signed_public_domain",
    "multiple_authoritative_servers",
    "broken_dnssec",
    "lame_delegation",
    "parent_child_ns_mismatch",
    "tcp_failure",
    "effective_caa_intermediate_ancestor",
    "wildcard_dns",
    "open_recursion",
    "direct_dns_path_interception",
}


class DnsV13ReleaseContractTest(unittest.TestCase):
    def _matrix(self):
        path = Path(__file__).parent / "fixtures" / "dns_v1_3_release_matrix.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_release_matrix_covers_issue_20_required_cases(self):
        matrix = self._matrix()
        self.assertEqual(matrix["release"], "v1.3.0")
        self.assertTrue(REQUIRED_SCENARIOS <= set(matrix["scenarios"]))

    def test_release_matrix_references_existing_automated_tests(self):
        root = Path(__file__).resolve().parents[1]
        for name, scenario in self._matrix()["scenarios"].items():
            with self.subTest(name=name):
                self.assertIn(scenario["mode"], {"controlled_fixture", "authorized_smoke"})
                automated = scenario.get("automated") or []
                self.assertTrue(automated)
                for relative in automated:
                    self.assertTrue((root / relative).is_file(), relative)

    def test_v13_dns_weight_contract_is_stable(self):
        self.assertEqual(NAME_SERVER_REDUNDANCY_WEIGHT, 3)
        self.assertEqual(DELEGATION_CONSISTENCY_WEIGHT, 6)
        self.assertEqual(DELEGATED_AUTHORITY_WEIGHT, 7)
        self.assertEqual(NAMESERVER_ADDRESSABILITY_WEIGHT, 7)
        self.assertEqual(DNSSEC_SCORE_WEIGHT, 10)
        self.assertEqual(DNSSEC_UNSIGNED_EARNED, 5)
        self.assertEqual(OPEN_RECURSION_WEIGHT, 8)
        self.assertEqual(AUTHORITATIVE_TCP_WEIGHT, 2)
        self.assertEqual(AUTHORITATIVE_RRSET_WEIGHT, 3)
        self.assertEqual(CAA_MALFORMED_WEIGHT, 2)

    def test_rfc_8659_is_registered_for_effective_caa_policy(self):
        ref = get_standard("RFC8659")
        self.assertEqual(ref.number, 8659)
        self.assertIn("CAA", ref.scope)


if __name__ == "__main__":
    unittest.main()
