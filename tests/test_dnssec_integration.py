from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecScanMixin,
    dnssec_report_data,
)
from domain_security_scanner.domains.domain.dnssec_analysis import (
    DnssecAnalysis,
    DnssecState,
    DnssecStepOutcome,
    DnssecValidationStep,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


class _TailMixin:
    def collect_domain_dns(self):
        self.events.append("domain")
        return "done"


class _DnssecHarness(DnssecScanMixin, _TailMixin):
    def __init__(self):
        self.events = []
        self.delegation = object()
        self.checks = []

    def collect_dnssec_evidence(self, delegation):
        self.events.append("dnssec")
        return DnssecEvidence(zone="example.com")

    def add_check(self, *args):
        self.checks.append(args)


class DnssecIntegrationTest(unittest.TestCase):
    def test_mixin_collects_before_domain_and_emits_finding_afterwards(self):
        harness = _DnssecHarness()
        result = harness.collect_domain_dns()
        self.assertEqual(result, "done")
        self.assertEqual(harness.events, ["dnssec", "domain"])
        self.assertEqual(harness.dnssec_analysis.state, DnssecState.UNKNOWN)
        self.assertEqual(len(harness.checks), 1)
        self.assertEqual(harness.checks[0][1], "DNSSEC")
        self.assertEqual(harness.checks[0][2], "unknown")
        self.assertFalse(harness.checks[0][-1])

    def test_report_is_additive_structured_and_explicitly_bounded(self):
        ds = DnsQueryResult(
            "example.com",
            "DS",
            DnsQueryState.ANSWER,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_ip="192.0.2.1",
            aa=True,
            rcode="NOERROR",
            answer_section=(
                "example.com. 300 IN DS 12345 13 2 AABBCCDD",
            ),
            request_want_dnssec=True,
        )
        from domain_security_scanner.domains.domain.dnssec import DnssecQueryEvidence

        evidence = DnssecEvidence(
            zone="example.com",
            parent_ds=DnssecQueryEvidence(
                qtype="DS",
                server_name="parent.example",
                server_ip="192.0.2.1",
                udp_result=ds,
            ),
        )
        analysis = DnssecAnalysis(
            state=DnssecState.BROKEN,
            reason="fixture failure",
            ds_count=1,
            matched_key_tags=(12345,),
            steps=(
                DnssecValidationStep(
                    "DNSKEY RRset",
                    DnssecStepOutcome.PASS,
                    "validated",
                ),
                DnssecValidationStep(
                    "Apex SOA",
                    DnssecStepOutcome.FAIL,
                    "invalid signature",
                ),
            ),
        )
        report = dnssec_report_data(evidence, analysis)
        self.assertEqual(report["status"], "broken")
        self.assertEqual(report["ds"], ["12345 13 2 AABBCCDD"])
        self.assertEqual(report["matching_key_tags"], [12345])
        self.assertTrue(report["queries"]["parent_ds"]["want_dnssec"])
        self.assertFalse(report["scope"]["complete_zone_validation"])
        self.assertEqual(
            report["scope"]["validation_targets"],
            ["DNSKEY", "SOA", "NS"],
        )
        self.assertEqual(report["scope"]["validated_rrsets"], ["DNSKEY"])

    def test_unsigned_report_has_targets_but_no_validated_rrsets(self):
        analysis = DnssecAnalysis(
            state=DnssecState.UNSIGNED,
            reason="No DS record exists at the parent delegation.",
            steps=(
                DnssecValidationStep(
                    "Parent DS",
                    DnssecStepOutcome.NOT_APPLICABLE,
                    "Parent delegation contains no DS RRset.",
                ),
            ),
        )
        report = dnssec_report_data(DnssecEvidence(zone="example.com"), analysis)
        self.assertEqual(report["scope"]["validation_targets"], ["DNSKEY", "SOA", "NS"])
        self.assertEqual(report["scope"]["validated_rrsets"], [])


if __name__ == "__main__":
    unittest.main()
