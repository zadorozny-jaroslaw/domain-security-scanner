from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.authoritative import AuthoritativeDnsEvidence
from domain_security_scanner.domains.domain.authoritative_analysis import (
    EDNS_OK,
    SOA_AUTHORITY_AUTHORITATIVE,
    TRANSPORT_BOTH_RESPOND,
    TRANSPORT_UDP_ONLY,
    AuthoritativeDnsAnalysis,
    AuthoritativeServerAnalysis,
    EndpointTransportAnalysis,
)
from domain_security_scanner.domains.domain.authoritative_findings import (
    build_authoritative_dns_findings,
)
from domain_security_scanner.domains.domain.dns_scoring import (
    AUTHORITATIVE_RRSET_WEIGHT,
    AUTHORITATIVE_TCP_WEIGHT,
    CAA_MALFORMED_WEIGHT,
    DNSSEC_SCORE_WEIGHT,
    DNSSEC_UNSIGNED_EARNED,
    OPEN_RECURSION_WEIGHT,
)
from domain_security_scanner.domains.domain.dnssec import DnssecEvidence
from domain_security_scanner.domains.domain.dnssec_analysis import DnssecAnalysis, DnssecState
from domain_security_scanner.domains.domain.dnssec_findings import build_dnssec_findings
from domain_security_scanner.domains.domain.negative_dns import NegativeDnsEvidence
from domain_security_scanner.domains.domain.negative_dns_analysis import (
    NegativeDnsAnalysis,
    NegativeDnsState,
    RecursionState,
)
from domain_security_scanner.domains.domain.negative_dns_findings import (
    build_negative_dns_findings,
)
from domain_security_scanner.domains.domain.scanner import DomainScanMixin
from domain_security_scanner.models import DnsQueryState


def _endpoint(name, ip, status, udp_state, tcp_state):
    return EndpointTransportAnalysis(
        server_name=name,
        server_ip=ip,
        status=status,
        udp_state=udp_state,
        tcp_state=tcp_state,
        udp_responded=status in {TRANSPORT_BOTH_RESPOND, TRANSPORT_UDP_ONLY},
        tcp_responded=status == TRANSPORT_BOTH_RESPOND,
        udp_authoritative_soa=True,
        tcp_authoritative_soa=status == TRANSPORT_BOTH_RESPOND,
    )


def _authoritative_analysis(*, first_transport, ns_consistent=True):
    healthy = _endpoint(
        "ns2.example.net",
        "192.0.2.54",
        TRANSPORT_BOTH_RESPOND,
        DnsQueryState.ANSWER,
        DnsQueryState.ANSWER,
    )
    servers = (
        AuthoritativeServerAnalysis(
            name="ns1.example.net",
            transport=(first_transport,),
            soa_authority_status=SOA_AUTHORITY_AUTHORITATIVE,
            soa_records=(),
            apex_nameservers=("ns1.example.net", "ns2.example.net"),
            edns_status=EDNS_OK,
        ),
        AuthoritativeServerAnalysis(
            name="ns2.example.net",
            transport=(healthy,),
            soa_authority_status=SOA_AUTHORITY_AUTHORITATIVE,
            soa_records=(),
            apex_nameservers=("ns1.example.net", "ns2.example.net"),
            edns_status=EDNS_OK,
        ),
    )
    rrsets = (
        ("ns1.example.net", ("ns1.example.net", "ns2.example.net")),
        (
            "ns2.example.net",
            ("ns1.example.net", "ns2.example.net")
            if ns_consistent
            else ("ns1.example.net", "ns3.example.net"),
        ),
    )
    return AuthoritativeDnsAnalysis(
        zone="example.com",
        servers=servers,
        soa_configuration_consistent=None,
        soa_serial_consistent=None,
        soa_differing_fields=(),
        soa_serials=(),
        ns_rrset_consistent=ns_consistent,
        observed_ns_rrsets=rrsets,
    )


class DnsScoringCalibrationTest(unittest.TestCase):
    def test_dnssec_broken_is_more_severe_than_unsigned_and_unknown_is_excluded(self):
        evidence = DnssecEvidence(zone="example.com")
        secure = build_dnssec_findings(
            evidence, DnssecAnalysis(DnssecState.SECURE, "ok")
        )[0]
        unsigned = build_dnssec_findings(
            evidence, DnssecAnalysis(DnssecState.UNSIGNED, "no DS")
        )[0]
        broken = build_dnssec_findings(
            evidence, DnssecAnalysis(DnssecState.BROKEN, "validation failed")
        )[0]
        unknown = build_dnssec_findings(
            evidence, DnssecAnalysis(DnssecState.UNKNOWN, "unavailable")
        )[0]

        self.assertEqual((secure.weight, secure.earned), (DNSSEC_SCORE_WEIGHT, DNSSEC_SCORE_WEIGHT))
        self.assertEqual((unsigned.weight, unsigned.earned), (DNSSEC_SCORE_WEIGHT, DNSSEC_UNSIGNED_EARNED))
        self.assertEqual((broken.weight, broken.earned), (DNSSEC_SCORE_WEIGHT, 0))
        self.assertEqual(unknown.weight, DNSSEC_SCORE_WEIGHT)
        self.assertFalse(unknown.applicable)

    def test_confirmed_open_recursion_scores_and_unknown_does_not(self):
        evidence = NegativeDnsEvidence("example.com", (), "example.net", ())
        open_analysis = NegativeDnsAnalysis(
            zone="example.com",
            negative_state=NegativeDnsState.UNKNOWN,
            negative_complete=False,
            servers=(),
            wildcard_servers=(),
            recursion_state=RecursionState.OPEN,
            recursion_open_servers=("ns1.example.net",),
            recursion_closed_servers=(),
            recursion_unknown_servers=(),
        )
        unknown_analysis = NegativeDnsAnalysis(
            zone="example.com",
            negative_state=NegativeDnsState.UNKNOWN,
            negative_complete=False,
            servers=(),
            wildcard_servers=(),
            recursion_state=RecursionState.UNKNOWN,
            recursion_open_servers=(),
            recursion_closed_servers=(),
            recursion_unknown_servers=("ns1.example.net",),
        )
        opened = build_negative_dns_findings(evidence, open_analysis)[-1]
        unknown = build_negative_dns_findings(evidence, unknown_analysis)[-1]
        self.assertEqual((opened.status, opened.weight, opened.earned), ("fail", OPEN_RECURSION_WEIGHT, 0))
        self.assertEqual(unknown.weight, OPEN_RECURSION_WEIGHT)
        self.assertFalse(unknown.applicable)

    def test_explicit_tcp_transport_error_scores_but_timeout_remains_unknown(self):
        explicit_error = _endpoint(
            "ns1.example.net",
            "192.0.2.53",
            TRANSPORT_UDP_ONLY,
            DnsQueryState.ANSWER,
            DnsQueryState.TRANSPORT_ERROR,
        )
        timeout = _endpoint(
            "ns1.example.net",
            "192.0.2.53",
            TRANSPORT_UDP_ONLY,
            DnsQueryState.ANSWER,
            DnsQueryState.TIMEOUT,
        )
        evidence = AuthoritativeDnsEvidence(zone="example.com", servers=())

        explicit_findings = {
            item.name: item
            for item in build_authoritative_dns_findings(
                evidence, _authoritative_analysis(first_transport=explicit_error)
            )
        }
        timeout_findings = {
            item.name: item
            for item in build_authoritative_dns_findings(
                evidence, _authoritative_analysis(first_transport=timeout)
            )
        }
        scored = explicit_findings["Authoritative DNS transport"]
        unknown = timeout_findings["Authoritative DNS transport"]
        self.assertEqual((scored.status, scored.weight, scored.earned), ("warn", AUTHORITATIVE_TCP_WEIGHT, 0))
        self.assertEqual(unknown.status, "unknown")
        self.assertEqual(unknown.weight, AUTHORITATIVE_TCP_WEIGHT)
        self.assertFalse(unknown.applicable)

    def test_material_authoritative_ns_rrset_disagreement_is_low_weight(self):
        endpoint = _endpoint(
            "ns1.example.net",
            "192.0.2.53",
            TRANSPORT_BOTH_RESPOND,
            DnsQueryState.ANSWER,
            DnsQueryState.ANSWER,
        )
        findings = {
            item.name: item
            for item in build_authoritative_dns_findings(
                AuthoritativeDnsEvidence(zone="example.com", servers=()),
                _authoritative_analysis(first_transport=endpoint, ns_consistent=False),
            )
        }
        rrset = findings["Authoritative NS RRset consistency"]
        self.assertEqual((rrset.status, rrset.weight, rrset.earned), ("warn", AUTHORITATIVE_RRSET_WEIGHT, 0))
        self.assertEqual(findings["Authoritative SOA serial"].weight, 0)
        self.assertEqual(findings["Authoritative EDNS(0)"].weight, 0)


class _CaaHarness(DomainScanMixin):
    target_domain = "example.com"

    def __init__(self, caa):
        self.caa = caa
        self.checks = []

    def add_check(self, *args):
        self.checks.append(args)


class CaaScoringTest(unittest.TestCase):
    def test_unparseable_effective_caa_is_unknown_plus_scored_syntax_warning(self):
        harness = _CaaHarness(
            {
                "effective_name": "example.com",
                "records": [{"raw": "bad"}],
                "analysis": {
                    "state": "effective",
                    "syntax_error_records": ["bad"],
                },
            }
        )
        harness._add_caa_findings()
        self.assertEqual([item[1] for item in harness.checks], ["CAA", "CAA policy syntax"])
        self.assertFalse(harness.checks[0][-1])
        self.assertEqual(harness.checks[1][2], "warn")
        self.assertEqual(harness.checks[1][4], CAA_MALFORMED_WEIGHT)
        self.assertEqual(harness.checks[1][5], 0)

    def test_semantically_malformed_effective_caa_has_low_weight_warning(self):
        harness = _CaaHarness(
            {
                "effective_name": "example.com",
                "records": [{"raw": '0 issue "%%%%%"'}],
                "analysis": {
                    "state": "effective",
                    "syntax_error_records": [],
                    "malformed_value_records": ['0 issue "%%%%%"'],
                    "fqdn_issuance_restricted": True,
                    "fqdn_issuance_forbidden": True,
                    "fqdn_issuers": [],
                    "critical_unknown_tags": [],
                },
            }
        )
        harness._add_caa_findings()
        syntax = next(item for item in harness.checks if item[1] == "CAA policy syntax")
        self.assertEqual((syntax[2], syntax[4], syntax[5]), ("warn", CAA_MALFORMED_WEIGHT, 0))


if __name__ == "__main__":
    unittest.main()
