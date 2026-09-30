from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.authoritative import (
    AuthoritativeDnsEvidence,
    AuthoritativeEndpointEvidence,
    AuthoritativeServerEvidence,
    apex_ns_from_result,
    soa_observation,
)
from domain_security_scanner.domains.domain.authoritative_analysis import (
    SOA_AUTHORITY_AUTHORITATIVE,
    TRANSPORT_PATH_UNTRUSTED,
    analyze_authoritative_dns,
)
from domain_security_scanner.domains.domain.authoritative_findings import (
    build_authoritative_dns_findings,
)
from domain_security_scanner.domains.domain.dns_path_integrity import (
    DIRECT_PATH_MIXED,
    DIRECT_PATH_SUSPECTED_INTERCEPTION,
    DIRECT_PATH_USABLE,
    assess_direct_dns_result,
    summarize_authoritative_path,
)
from domain_security_scanner.domains.domain.reporting import (
    dns_infrastructure_report_data,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


def _result(
    qtype: str,
    *,
    transport: DnsTransport = DnsTransport.UDP,
    state: DnsQueryState = DnsQueryState.ANSWER,
    aa: bool = True,
    ra: bool | None = False,
    rd: bool | None = False,
    answer_section: tuple[str, ...] = (),
    authority_section: tuple[str, ...] = (),
    server_ip: str = "192.0.2.53",
) -> DnsQueryResult:
    return DnsQueryResult(
        "example.com",
        qtype,
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=transport,
        server_name="ns1.example.net",
        server_ip=server_ip,
        rcode="NOERROR",
        aa=aa,
        tc=False,
        answer_section=answer_section,
        authority_section=authority_section,
        request_recursion_desired=False,
        rd=rd,
        ra=ra,
    )


def _clean_soa(*, transport=DnsTransport.TCP, server_ip="192.0.2.53"):
    return _result(
        "SOA",
        transport=transport,
        server_ip=server_ip,
        answer_section=(
            "example.com. 300 IN SOA ns1.example.net. hostmaster.example.com. "
            "42 3600 600 86400 300",
        ),
    )


def _intercepted_soa(*, transport=DnsTransport.UDP, aa=False, server_ip="192.0.2.53"):
    return _result(
        "SOA",
        transport=transport,
        state=DnsQueryState.NOT_AUTHORITATIVE if not aa else DnsQueryState.ERROR,
        aa=aa,
        ra=True,
        rd=False,
        server_ip=server_ip,
        authority_section=(
            "example.com. 5 IN NS ns1.example.net.\n"
            "example.com. 5 IN NS ns2.example.net.",
        ),
    )


class DirectDnsPathIntegrityTest(unittest.TestCase):
    def test_rd0_ra_referral_like_soa_is_suspected_interception(self):
        assessment = assess_direct_dns_result(_intercepted_soa())

        self.assertEqual(assessment.status, DIRECT_PATH_SUSPECTED_INTERCEPTION)
        self.assertIn("unexpected_ra_on_rd0", assessment.signals)
        self.assertIn("referral_like_apex_response", assessment.signals)

    def test_clean_authoritative_soa_is_usable(self):
        assessment = assess_direct_dns_result(_clean_soa())

        self.assertEqual(assessment.status, DIRECT_PATH_USABLE)

    def test_apex_ns_rejects_suspected_intercepted_response(self):
        result = _result(
            "NS",
            state=DnsQueryState.ERROR,
            aa=True,
            ra=True,
            authority_section=(
                "example.com. 5 IN NS ns1.example.net.\n"
                "example.com. 5 IN NS ns2.example.net.",
            ),
        )

        self.assertEqual(apex_ns_from_result(result, "example.com"), ())

    def test_intercepted_udp_and_tcp_do_not_produce_transport_pass(self):
        udp = _intercepted_soa(transport=DnsTransport.UDP, aa=False)
        tcp = _intercepted_soa(transport=DnsTransport.TCP, aa=True)
        endpoint = AuthoritativeEndpointEvidence(
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            udp_soa=soa_observation(udp, "example.com"),
            tcp_soa=soa_observation(tcp, "example.com"),
        )
        evidence = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                AuthoritativeServerEvidence(
                    name="ns1.example.net",
                    candidate_addresses=("192.0.2.53",),
                    probe_addresses=("192.0.2.53",),
                    unprobed_addresses=(),
                    endpoints=(endpoint,),
                ),
            ),
        )
        analysis = analyze_authoritative_dns(evidence)
        transport = analysis.servers[0].transport[0]
        findings = {f.name: f for f in build_authoritative_dns_findings(evidence, analysis)}

        self.assertEqual(transport.status, TRANSPORT_PATH_UNTRUSTED)
        self.assertEqual(findings["Authoritative DNS transport"].status, "unknown")
        self.assertFalse(findings["Authoritative DNS transport"].applicable)
        self.assertEqual(findings["Authoritative SOA service"].status, "unknown")

    def test_clean_tcp_can_still_prove_soa_when_udp_path_is_suspect(self):
        udp = _intercepted_soa(transport=DnsTransport.UDP)
        tcp = _clean_soa(transport=DnsTransport.TCP)
        endpoint = AuthoritativeEndpointEvidence(
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            udp_soa=soa_observation(udp, "example.com"),
            tcp_soa=soa_observation(tcp, "example.com"),
        )
        evidence = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                AuthoritativeServerEvidence(
                    name="ns1.example.net",
                    candidate_addresses=("192.0.2.53",),
                    probe_addresses=("192.0.2.53",),
                    unprobed_addresses=(),
                    endpoints=(endpoint,),
                ),
            ),
        )
        analysis = analyze_authoritative_dns(evidence)

        self.assertEqual(
            analysis.servers[0].soa_authority_status,
            SOA_AUTHORITY_AUTHORITATIVE,
        )
        self.assertEqual(analysis.servers[0].soa_records[0].serial, 42)
        self.assertEqual(
            summarize_authoritative_path(evidence)["status"],
            DIRECT_PATH_MIXED,
        )

    def test_report_exposes_direct_path_integrity_diagnostics(self):
        udp = _intercepted_soa(transport=DnsTransport.UDP, aa=False)
        tcp = _intercepted_soa(transport=DnsTransport.TCP, aa=True)
        endpoint = AuthoritativeEndpointEvidence(
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            udp_soa=soa_observation(udp, "example.com"),
            tcp_soa=soa_observation(tcp, "example.com"),
        )
        evidence = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                AuthoritativeServerEvidence(
                    name="ns1.example.net",
                    candidate_addresses=("192.0.2.53",),
                    probe_addresses=("192.0.2.53",),
                    unprobed_addresses=(),
                    endpoints=(endpoint,),
                ),
            ),
        )
        analysis = analyze_authoritative_dns(evidence)

        report = dns_infrastructure_report_data(None, None, evidence, analysis, {})

        self.assertEqual(
            report["path_integrity"]["status"],
            DIRECT_PATH_SUSPECTED_INTERCEPTION,
        )
        self.assertEqual(
            report["path_integrity"]["transports"]["udp"]["status"],
            DIRECT_PATH_SUSPECTED_INTERCEPTION,
        )
        endpoint_report = report["authoritative_servers"][0]["endpoints"][0]
        self.assertEqual(
            endpoint_report["path_integrity"]["tcp"]["status"],
            DIRECT_PATH_SUSPECTED_INTERCEPTION,
        )
        self.assertEqual(
            endpoint_report["tcp_soa"]["query"]["path_integrity"]["status"],
            DIRECT_PATH_SUSPECTED_INTERCEPTION,
        )


if __name__ == "__main__":
    unittest.main()
