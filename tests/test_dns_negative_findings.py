from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dns_scoring import OPEN_RECURSION_WEIGHT
from domain_security_scanner.domains.domain.negative_dns import (
    NegativeDnsEvidence,
    NegativeDnsServerEvidence,
)
from domain_security_scanner.domains.domain.negative_dns_analysis import analyze_negative_dns
from domain_security_scanner.domains.domain.negative_dns_findings import build_negative_dns_findings
from domain_security_scanner.models import DnsQueryResult, DnsQueryState


def _negative(name: str, state: DnsQueryState) -> DnsQueryResult:
    return DnsQueryResult(
        name,
        "A",
        state,
        rcode="NXDOMAIN" if state == DnsQueryState.NXDOMAIN else "NOERROR",
        aa=True,
        authority_section=(
            "target.test. 300 IN SOA ns1.target.test. hostmaster.target.test. 1 3600 600 86400 300",
        ),
    )


def _positive(name: str) -> DnsQueryResult:
    return DnsQueryResult(
        name,
        "A",
        DnsQueryState.ANSWER,
        ("192.0.2.10",),
        rcode="NOERROR",
        aa=True,
        answer_section=(f"{name}. 300 IN A 192.0.2.10",),
    )


def _recursion(*, open_: bool = False, refused: bool = False, timeout: bool = False):
    if timeout:
        return DnsQueryResult(
            "example.com",
            "A",
            DnsQueryState.TIMEOUT,
            request_recursion_desired=True,
        )
    if refused:
        return DnsQueryResult(
            "example.com",
            "A",
            DnsQueryState.ERROR,
            rcode="REFUSED",
            aa=False,
            rd=True,
            ra=False,
            request_recursion_desired=True,
        )
    return DnsQueryResult(
        "example.com",
        "A",
        DnsQueryState.ANSWER,
        ("192.0.2.20",),
        rcode="NOERROR",
        aa=False,
        rd=True,
        ra=True if open_ else False,
        request_recursion_desired=True,
    )


def _build(negative_results, recursion_result):
    evidence = NegativeDnsEvidence(
        zone="target.test",
        negative_names=(
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        ),
        recursion_probe_name="example.com",
        servers=(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                tuple(negative_results),
                recursion_result,
            ),
        ),
    )
    return evidence, analyze_negative_dns(evidence)


class NegativeDnsFindingTests(unittest.TestCase):
    def test_nxdomain_and_refused_produce_pass_findings(self):
        names = ("dssnx0-fixed.target.test", "dssnx1-fixed.target.test")
        evidence, analysis = _build(
            [_negative(name, DnsQueryState.NXDOMAIN) for name in names],
            _recursion(refused=True),
        )

        findings = build_negative_dns_findings(evidence, analysis)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].name, "Authoritative negative DNS")
        self.assertEqual(findings[0].status, "pass")
        self.assertEqual(findings[1].name, "Authoritative open recursion")
        self.assertEqual(findings[1].status, "pass")

    def test_wildcard_is_info_and_non_scoring(self):
        names = ("dssnx0-fixed.target.test", "dssnx1-fixed.target.test")
        evidence, analysis = _build(
            [_positive(name) for name in names],
            _recursion(refused=True),
        )

        findings = build_negative_dns_findings(evidence, analysis)
        wildcard = next(finding for finding in findings if finding.name == "Wildcard DNS")

        self.assertEqual(wildcard.status, "info")
        self.assertEqual(wildcard.weight, 0)
        self.assertEqual(wildcard.earned, 0)
        self.assertFalse(wildcard.applicable)

    def test_confirmed_open_recursion_is_fail(self):
        names = ("dssnx0-fixed.target.test", "dssnx1-fixed.target.test")
        evidence, analysis = _build(
            [_negative(name, DnsQueryState.NXDOMAIN) for name in names],
            _recursion(open_=True),
        )

        findings = build_negative_dns_findings(evidence, analysis)
        recursion = next(
            finding for finding in findings if finding.name == "Authoritative open recursion"
        )

        self.assertEqual(recursion.status, "fail")
        self.assertEqual(recursion.weight, OPEN_RECURSION_WEIGHT)
        self.assertEqual(recursion.earned, 0)
        self.assertTrue(recursion.applicable)
        self.assertIn("ns1.target.test", recursion.message)

    def test_timeout_recursion_is_unknown_not_pass(self):
        names = ("dssnx0-fixed.target.test", "dssnx1-fixed.target.test")
        evidence, analysis = _build(
            [_negative(name, DnsQueryState.NXDOMAIN) for name in names],
            _recursion(timeout=True),
        )

        findings = build_negative_dns_findings(evidence, analysis)
        recursion = next(
            finding for finding in findings if finding.name == "Authoritative open recursion"
        )

        self.assertEqual(recursion.status, "unknown")
        self.assertFalse(recursion.applicable)


if __name__ == "__main__":
    unittest.main()
