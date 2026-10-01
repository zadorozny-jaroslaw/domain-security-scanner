from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dns_scoring import DNSSEC_UNSIGNED_EARNED
from domain_security_scanner.domains.domain.dnssec import DnssecEvidence
from domain_security_scanner.domains.domain.dnssec_analysis import (
    DnssecAnalysis,
    DnssecState,
)
from domain_security_scanner.domains.domain.dnssec_findings import (
    DNSSEC_SCORE_WEIGHT,
    build_dnssec_findings,
)


class DnssecFindingsTest(unittest.TestCase):
    def _finding(self, state: DnssecState, reason: str = "reason"):
        evidence = DnssecEvidence(zone="example.com")
        analysis = DnssecAnalysis(state=state, reason=reason)
        findings = build_dnssec_findings(evidence, analysis)
        self.assertEqual(len(findings), 1)
        return findings[0]

    def test_secure_is_scored_pass(self):
        finding = self._finding(DnssecState.SECURE)
        self.assertEqual(finding.status, "pass")
        self.assertEqual(finding.weight, DNSSEC_SCORE_WEIGHT)
        self.assertEqual(finding.earned, DNSSEC_SCORE_WEIGHT)
        self.assertTrue(finding.applicable)
        self.assertIn("poprawnie zwalidowany", finding.message)
        self.assertIn("example.com", finding.message)

    def test_unsigned_is_scored_warn(self):
        finding = self._finding(DnssecState.UNSIGNED)
        self.assertEqual(finding.status, "warn")
        self.assertEqual(finding.weight, DNSSEC_SCORE_WEIGHT)
        self.assertEqual(finding.earned, DNSSEC_UNSIGNED_EARNED)
        self.assertTrue(finding.applicable)
        self.assertIn("nie używa DNSSEC", finding.message)

    def test_broken_is_scored_fail_with_customer_friendly_message(self):
        finding = self._finding(
            DnssecState.BROKEN,
            "Parent DS records do not match any child DNSKEY record.",
        )
        self.assertEqual(finding.status, "fail")
        self.assertEqual(finding.earned, 0)
        self.assertIn("nie powiodła się", finding.message)
        self.assertNotIn("Parent DS records", finding.message)

    def test_unknown_is_non_applicable(self):
        finding = self._finding(DnssecState.UNKNOWN, "timeout")
        self.assertEqual(finding.status, "unknown")
        self.assertFalse(finding.applicable)
        self.assertEqual(finding.earned, 0)
        self.assertIn("Nie można jednoznacznie zweryfikować", finding.message)
        self.assertNotIn("timeout", finding.message)


if __name__ == "__main__":
    unittest.main()
