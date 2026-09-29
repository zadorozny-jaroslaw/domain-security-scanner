from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecQueryEvidence,
    dnssec_report_data,
)
from domain_security_scanner.domains.domain.dnssec_analysis import DnssecAnalysis, DnssecState
from domain_security_scanner.domains.domain.dnssec_denial_analysis import analyze_dnssec_denial
from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
    analyze_dnssec_algorithm_posture,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


def _result(host, qtype, state, *, answer=(), authority=(), rcode="NOERROR"):
    return DnsQueryResult(
        host,
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


def _query(qtype, result):
    return DnssecQueryEvidence(
        qtype=qtype,
        server_name=result.server_name,
        server_ip=result.server_ip,
        udp_result=result,
    )


class DnssecIssue17IntegrationTest(unittest.TestCase):
    def test_report_exposes_versioned_algorithm_and_denial_posture(self):
        parent = _query(
            "DS",
            _result(
                "example.com",
                "DS",
                DnsQueryState.ANSWER,
                answer=("example.com. 300 IN DS 12345 13 2 AABBCCDD",),
            ),
        )
        dnskey = _query(
            "DNSKEY",
            _result(
                "example.com",
                "DNSKEY",
                DnsQueryState.ANSWER,
                answer=("example.com. 300 IN DNSKEY 257 3 13 AQIDBA==",),
            ),
        )
        denial = _query(
            "A",
            _result(
                "dssnx0-deadbeef.example.com",
                "A",
                DnsQueryState.NXDOMAIN,
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
        algorithm_analysis = analyze_dnssec_algorithm_posture(evidence)
        denial_analysis = analyze_dnssec_denial(evidence)
        report = dnssec_report_data(
            evidence,
            DnssecAnalysis(state=DnssecState.UNKNOWN, reason="fixture"),
            algorithm_analysis,
            denial_analysis,
        )

        self.assertEqual(report["algorithm_policy"]["status"], "recommended")
        self.assertEqual(
            report["algorithm_policy"]["snapshot_version"],
            "2026-08-10-iana-dnssec-policy",
        )
        self.assertEqual(
            report["algorithm_policy"]["algorithm_registry_updated"],
            "2026-08-10",
        )
        self.assertEqual(report["algorithm_policy"]["dnskey_algorithms"][0]["number"], 13)
        self.assertEqual(report["algorithm_policy"]["ds_digests"][0]["number"], 2)
        self.assertEqual(report["denial"]["mechanism"], "nsec3")
        self.assertEqual(report["denial"]["posture"], "current")
        self.assertEqual(report["denial"]["nsec3"]["iterations"], [0])
        self.assertEqual(report["scope"]["denial_probe_limit"], 1)
        self.assertTrue(report["queries"]["denial_probe"]["want_dnssec"])
        self.assertNotIn("qname", report["queries"]["denial_probe"])
        self.assertNotIn("dssnx0-deadbeef", str(report))

    def test_unknown_future_algorithm_is_serialized_as_unknown(self):
        dnskey = _query(
            "DNSKEY",
            _result(
                "example.com",
                "DNSKEY",
                DnsQueryState.ANSWER,
                answer=("example.com. 300 IN DNSKEY 257 3 99 AQIDBA==",),
            ),
        )
        evidence = DnssecEvidence(
            zone="example.com",
            selected_dnskey=dnskey,
            dnskey_attempts=(dnskey,),
        )
        policy = analyze_dnssec_algorithm_posture(evidence)
        report = dnssec_report_data(
            evidence,
            DnssecAnalysis(state=DnssecState.UNKNOWN, reason="fixture"),
            policy,
            analyze_dnssec_denial(evidence),
        )
        self.assertEqual(report["algorithm_policy"]["status"], "unknown")
        self.assertEqual(
            report["algorithm_policy"]["dnskey_algorithms"][0]["signing_posture"],
            "unknown",
        )


if __name__ == "__main__":
    unittest.main()
