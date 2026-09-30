from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecQueryEvidence,
    DnssecScanMixin,
    dnssec_report_data,
)
from domain_security_scanner.domains.domain.dnssec_analysis import (
    DnssecAnalysis,
    DnssecState,
    DnssecStepOutcome,
    DnssecValidationStep,
)
from domain_security_scanner.domains.domain.dnssec_denial_analysis import (
    analyze_dnssec_denial,
)
from domain_security_scanner.domains.domain.dnssec_findings import (
    build_dnssec_findings,
)
from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
    analyze_dnssec_algorithm_posture,
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


def _authoritative_result(
    qname: str,
    qtype: str,
    *,
    answer=(),
    authority=(),
    state=DnsQueryState.ANSWER,
    rcode="NOERROR",
):
    return DnsQueryResult(
        qname,
        qtype,
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        rcode=rcode,
        aa=True,
        answer_section=tuple(answer),
        authority_section=tuple(authority),
        request_edns_version=0,
        request_edns_payload=1232,
        request_want_dnssec=True,
    )


def _query_evidence(qtype: str, result: DnsQueryResult):
    return DnssecQueryEvidence(
        qtype=qtype,
        server_name=result.server_name,
        server_ip=result.server_ip,
        udp_result=result,
    )


class DnssecIntegrationTest(unittest.TestCase):
    def test_mixin_collects_before_domain_and_emits_findings_afterwards(self):
        harness = _DnssecHarness()
        result = harness.collect_domain_dns()
        self.assertEqual(result, "done")
        self.assertEqual(harness.events, ["dnssec", "domain"])
        self.assertEqual(harness.dnssec_analysis.state, DnssecState.UNKNOWN)
        self.assertEqual(harness.dnssec_policy_analysis.posture.value, "unknown")
        self.assertEqual(harness.dnssec_denial_analysis.posture.value, "unknown")
        self.assertEqual(len(harness.checks), 3)
        self.assertEqual(
            [item[1] for item in harness.checks],
            ["DNSSEC", "DNSSEC algorithm policy", "DNSSEC denial of existence"],
        )
        self.assertTrue(all(item[2] == "unknown" for item in harness.checks))
        self.assertTrue(all(item[-1] is False for item in harness.checks))

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
        self.assertIsNone(report["queries"]["denial_probe"])
        self.assertEqual(report["algorithm_policy"]["status"], "unknown")
        self.assertEqual(report["denial"]["posture"], "unknown")
        self.assertFalse(report["scope"]["complete_zone_validation"])
        self.assertEqual(
            report["scope"]["validation_targets"],
            ["DNSKEY", "SOA", "NS"],
        )
        self.assertEqual(report["scope"]["validated_rrsets"], ["DNSKEY"])
        self.assertEqual(report["scope"]["denial_probe_limit"], 1)

    def test_report_exposes_policy_and_denial_posture_without_probe_name(self):
        parent = _query_evidence(
            "DS",
            _authoritative_result(
                "example.com",
                "DS",
                answer=("example.com. 300 IN DS 12345 13 2 AABBCCDD",),
            ),
        )
        dnskey = _query_evidence(
            "DNSKEY",
            _authoritative_result(
                "example.com",
                "DNSKEY",
                answer=("example.com. 300 IN DNSKEY 257 3 13 AQIDBA==",),
            ),
        )
        denial = _query_evidence(
            "A",
            _authoritative_result(
                "dssnx0-deadbeef.example.com",
                "A",
                state=DnsQueryState.NXDOMAIN,
                authority=(
                    "ABC.example.com. 300 IN NSEC3 1 0 0 - DEF A NS SOA RRSIG",
                ),
                rcode="NXDOMAIN",
            ),
        )
        evidence = DnssecEvidence(
            zone="example.com",
            parent_ds=parent,
            dnskey_attempts=(dnskey,),
            selected_dnskey=dnskey,
            denial_probe=denial,
        )
        report = dnssec_report_data(
            evidence,
            DnssecAnalysis(state=DnssecState.UNKNOWN, reason="fixture"),
            analyze_dnssec_algorithm_posture(evidence),
            analyze_dnssec_denial(evidence),
        )

        self.assertEqual(report["algorithm_policy"]["status"], "recommended")
        self.assertEqual(
            report["algorithm_policy"]["snapshot_version"],
            "2026-08-10-iana-dnssec-policy",
        )
        self.assertEqual(report["denial"]["mechanism"], "nsec3")
        self.assertEqual(report["denial"]["posture"], "current")
        self.assertTrue(report["queries"]["denial_probe"]["want_dnssec"])
        self.assertNotIn("qname", report["queries"]["denial_probe"])
        self.assertNotIn("dssnx0-deadbeef", str(report))

    def test_unknown_dnssec_finding_keeps_independent_signing_context(self):
        dnskey = _query_evidence(
            "DNSKEY",
            _authoritative_result(
                "example.com",
                "DNSKEY",
                answer=("example.com. 300 IN DNSKEY 257 3 13 AQIDBA==",),
            ),
        )
        evidence = DnssecEvidence(
            zone="example.com",
            selected_dnskey=dnskey,
            dnskey_attempts=(dnskey,),
        )
        finding = build_dnssec_findings(
            evidence,
            DnssecAnalysis(state=DnssecState.UNKNOWN, reason="fixture"),
            rdap={"secureDNS": {"delegationSigned": True}},
            dns_records={"example.com": {"DS": ["12345 13 2 AABB"]}},
        )[0]

        self.assertEqual(finding.status, "unknown")
        self.assertFalse(finding.applicable)
        self.assertIn("RDAP wskazuje podpisaną delegację", finding.message)
        self.assertIn("autorytatywny DNSKEY", finding.message)
        self.assertIn("nie wpływa na scoring", finding.message)

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
