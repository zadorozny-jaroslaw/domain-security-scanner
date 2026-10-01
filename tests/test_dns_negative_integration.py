from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.negative_dns import (
    NegativeDnsEvidence,
    NegativeDnsScanMixin,
    NegativeDnsServerEvidence,
    negative_dns_report_data,
)
from domain_security_scanner.domains.domain.negative_dns_analysis import analyze_negative_dns
from domain_security_scanner.models import DnsQueryResult, DnsQueryState, DnsTransport


def _soa() -> tuple[str, ...]:
    return (
        "target.test. 300 IN SOA ns1.target.test. hostmaster.target.test. 1 3600 600 86400 300",
    )


def _negative(name: str) -> DnsQueryResult:
    return DnsQueryResult(
        name,
        "A",
        DnsQueryState.NXDOMAIN,
        rcode="NXDOMAIN",
        aa=True,
        transport=DnsTransport.UDP,
        server_name="ns1.target.test",
        server_ip="192.0.2.53",
        authority_section=_soa(),
    )


def _refused() -> DnsQueryResult:
    return DnsQueryResult(
        "example.com",
        "A",
        DnsQueryState.ERROR,
        rcode="REFUSED",
        aa=False,
        rd=True,
        ra=False,
        transport=DnsTransport.UDP,
        server_name="ns1.target.test",
        server_ip="192.0.2.53",
        request_recursion_desired=True,
    )


def _open_recursion() -> DnsQueryResult:
    return DnsQueryResult(
        "example.com",
        "A",
        DnsQueryState.ANSWER,
        ("192.0.2.10",),
        rcode="NOERROR",
        aa=False,
        rd=True,
        ra=True,
        transport=DnsTransport.UDP,
        server_name="ns1.target.test",
        server_ip="192.0.2.53",
        request_recursion_desired=True,
        answer_section=("example.com. 300 IN A 192.0.2.10",),
    )


def _evidence(recursion_result: DnsQueryResult) -> NegativeDnsEvidence:
    names = (
        "dssnx0-fixed.target.test",
        "dssnx1-fixed.target.test",
    )
    return NegativeDnsEvidence(
        zone="target.test",
        negative_names=names,
        recursion_probe_name="example.com",
        servers=(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                tuple(_negative(name) for name in names),
                recursion_result,
            ),
        ),
    )


class _TailMixin:
    def collect_domain_dns(self):
        self.events.append("domain")
        return "done"


class _NegativeDnsHarness(NegativeDnsScanMixin, _TailMixin):
    def __init__(self):
        self.events = []
        self.authoritative_dns = object()
        self.checks = []

    def collect_negative_dns_evidence(self, authoritative_dns):
        self.asserted_authoritative = authoritative_dns
        self.events.append("negative_dns")
        return _evidence(_refused())

    def add_check(self, *args):
        self.checks.append(args)


class NegativeDnsIntegrationTests(unittest.TestCase):
    def test_mixin_collects_after_authoritative_context_before_domain_and_emits_findings(self):
        harness = _NegativeDnsHarness()

        result = harness.collect_domain_dns()

        self.assertEqual(result, "done")
        self.assertIs(harness.asserted_authoritative, harness.authoritative_dns)
        self.assertEqual(harness.events, ["negative_dns", "domain"])
        self.assertEqual(harness.negative_dns_analysis.negative_state.value, "nxdomain")
        self.assertEqual(harness.negative_dns_analysis.recursion_state.value, "closed")
        self.assertEqual(
            [check[1] for check in harness.checks],
            ["Authoritative negative DNS", "Authoritative open recursion"],
        )
        self.assertEqual([check[2] for check in harness.checks], ["pass", "pass"])

    def test_report_preserves_negative_soa_and_positive_recursion_evidence(self):
        evidence = _evidence(_open_recursion())
        analysis = analyze_negative_dns(evidence)

        report = negative_dns_report_data(evidence, analysis)

        negative = report["negative_response"]
        self.assertEqual(negative["status"], "nxdomain")
        self.assertTrue(negative["complete"])
        self.assertEqual(len(negative["servers"]), 1)
        self.assertEqual(len(negative["servers"][0]["probes"]), 2)
        self.assertFalse(negative["generated_probe_names_serialized"])
        first_probe = negative["servers"][0]["probes"][0]
        self.assertEqual(first_probe["probe_index"], 1)
        self.assertIn(" SOA ", first_probe["soa_records"][0])
        self.assertNotIn("qname", first_probe["query"])

        wildcard = report["wildcard"]
        self.assertEqual(wildcard["status"], "not_observed")
        self.assertEqual(wildcard["servers"], [])

        recursion = report["open_recursion"]
        self.assertEqual(recursion["status"], "open")
        self.assertEqual(recursion["open_servers"], ["ns1.target.test"])
        query = recursion["servers"][0]["query"]
        self.assertTrue(query["request_recursion_desired"])
        self.assertTrue(query["response_recursion_desired"])
        self.assertTrue(query["recursion_available"])
        self.assertFalse(query["authoritative"])

    def test_empty_report_is_explicitly_unknown(self):
        report = negative_dns_report_data(None, None)

        self.assertEqual(report["negative_response"]["status"], "unknown")
        self.assertFalse(report["negative_response"]["complete"])
        self.assertEqual(report["wildcard"]["status"], "unknown")
        self.assertEqual(report["open_recursion"]["status"], "unknown")
        self.assertEqual(report["open_recursion"]["servers"], [])


if __name__ == "__main__":
    unittest.main()
