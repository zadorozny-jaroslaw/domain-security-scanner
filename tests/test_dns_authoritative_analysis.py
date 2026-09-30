from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.authoritative import (
    AuthoritativeDnsEvidence,
    AuthoritativeEndpointEvidence,
    AuthoritativeServerEvidence,
    SoaObservation,
    SoaRecord,
)
from domain_security_scanner.domains.domain.authoritative_analysis import (
    EDNS_ANOMALY,
    EDNS_OK,
    SOA_AUTHORITY_AUTHORITATIVE,
    SOA_AUTHORITY_NOT_AUTHORITATIVE,
    SOA_AUTHORITY_UNKNOWN,
    TRANSPORT_BOTH_RESPOND,
    TRANSPORT_UDP_ONLY,
    analyze_authoritative_dns,
)
from domain_security_scanner.domains.domain.authoritative_findings import (
    build_authoritative_dns_findings,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


def _soa(serial=1, *, mname="ns1.example.net", refresh=3600):
    return SoaRecord(
        mname=mname,
        rname="hostmaster.example.com",
        serial=serial,
        refresh=refresh,
        retry=600,
        expire=86400,
        minimum=300,
    )


def _result(
    server,
    ip,
    transport,
    *,
    state=DnsQueryState.ANSWER,
    rcode="NOERROR",
    aa=True,
    edns=False,
):
    return DnsQueryResult(
        "example.com",
        "SOA",
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=transport,
        server_name=server,
        server_ip=ip,
        request_edns_version=0 if edns else None,
        request_edns_payload=1232 if edns else None,
        rcode=rcode,
        aa=aa,
        tc=False,
    )


def _obs(server, ip, transport, *, serial=1, state=DnsQueryState.ANSWER, rcode="NOERROR", aa=True, edns=False, soa=True):
    result = _result(server, ip, transport, state=state, rcode=rcode, aa=aa, edns=edns)
    value = _soa(serial) if soa and state == DnsQueryState.ANSWER and aa and rcode == "NOERROR" else None
    return SoaObservation(result=result, soa=value)


def _server(
    name,
    ip,
    *,
    serial=1,
    ns=("ns1.example.net", "ns2.example.net"),
    tcp_state=DnsQueryState.ANSWER,
    tcp_rcode="NOERROR",
    tcp_aa=True,
    udp_state=DnsQueryState.ANSWER,
    udp_rcode="NOERROR",
    udp_aa=True,
    edns_state=DnsQueryState.ANSWER,
    edns_rcode="NOERROR",
    edns_aa=True,
):
    udp = _obs(
        name, ip, DnsTransport.UDP,
        serial=serial, state=udp_state, rcode=udp_rcode, aa=udp_aa,
        soa=(udp_state == DnsQueryState.ANSWER and udp_aa and udp_rcode == "NOERROR"),
    )
    tcp = _obs(
        name, ip, DnsTransport.TCP,
        serial=serial, state=tcp_state, rcode=tcp_rcode, aa=tcp_aa,
        soa=(tcp_state == DnsQueryState.ANSWER and tcp_aa and tcp_rcode == "NOERROR"),
    )
    edns = _obs(
        name, ip, DnsTransport.UDP,
        serial=serial, state=edns_state, rcode=edns_rcode, aa=edns_aa, edns=True,
        soa=(edns_state == DnsQueryState.ANSWER and edns_aa and edns_rcode == "NOERROR"),
    )
    return AuthoritativeServerEvidence(
        name=name,
        candidate_addresses=(ip,),
        probe_addresses=(ip,),
        unprobed_addresses=(),
        apex_nameservers=ns,
        endpoints=(
            AuthoritativeEndpointEvidence(
                server_name=name,
                server_ip=ip,
                udp_soa=udp,
                tcp_soa=tcp,
                edns_soa=edns,
            ),
        ),
    )


def _findings(analysis, evidence):
    return {item.name: item for item in build_authoritative_dns_findings(evidence, analysis)}


class AuthoritativeAnalysisTest(unittest.TestCase):
    def test_healthy_servers_are_consistent(self):
        evidence = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                _server("ns1.example.net", "192.0.2.53"),
                _server("ns2.example.net", "192.0.2.54"),
            ),
        )
        analysis = analyze_authoritative_dns(evidence)
        self.assertTrue(analysis.soa_configuration_consistent)
        self.assertTrue(analysis.soa_serial_consistent)
        self.assertTrue(analysis.ns_rrset_consistent)
        self.assertTrue(all(s.soa_authority_status == SOA_AUTHORITY_AUTHORITATIVE for s in analysis.servers))
        self.assertTrue(all(s.edns_status == EDNS_OK for s in analysis.servers))
        self.assertTrue(all(s.transport[0].status == TRANSPORT_BOTH_RESPOND for s in analysis.servers))

        findings = _findings(analysis, evidence)
        self.assertEqual({item.status for item in findings.values()}, {"pass"})

    def test_udp_success_tcp_timeout_is_identified_but_verify_compatible(self):
        server = _server(
            "ns1.example.net",
            "192.0.2.53",
            tcp_state=DnsQueryState.TIMEOUT,
            tcp_rcode=None,
            tcp_aa=False,
        )
        evidence = AuthoritativeDnsEvidence(zone="example.com", servers=(server,))
        analysis = analyze_authoritative_dns(evidence)
        self.assertEqual(analysis.servers[0].transport[0].status, TRANSPORT_UDP_ONLY)
        self.assertEqual(analysis.servers[0].soa_authority_status, SOA_AUTHORITY_AUTHORITATIVE)
        findings = _findings(analysis, evidence)
        self.assertEqual(findings["Authoritative DNS transport"].status, "unknown")
        self.assertFalse(findings["Authoritative DNS transport"].applicable)

    def test_non_authoritative_soa_is_positive_failure_evidence(self):
        server = _server(
            "ns1.example.net",
            "192.0.2.53",
            udp_state=DnsQueryState.NOT_AUTHORITATIVE,
            udp_rcode="NOERROR",
            udp_aa=False,
            tcp_state=DnsQueryState.NOT_AUTHORITATIVE,
            tcp_rcode="NOERROR",
            tcp_aa=False,
            edns_state=DnsQueryState.NOT_AUTHORITATIVE,
            edns_rcode="NOERROR",
            edns_aa=False,
        )
        evidence = AuthoritativeDnsEvidence(zone="example.com", servers=(server,))
        analysis = analyze_authoritative_dns(evidence)
        self.assertEqual(analysis.servers[0].soa_authority_status, SOA_AUTHORITY_NOT_AUTHORITATIVE)
        findings = _findings(analysis, evidence)
        self.assertEqual(findings["Authoritative SOA service"].status, "fail")

    def test_no_usable_soa_is_verify_not_warning(self):
        server = _server(
            "ns1.example.net",
            "192.0.2.53",
            udp_state=DnsQueryState.ERROR,
            udp_rcode="NOERROR",
            udp_aa=True,
            tcp_state=DnsQueryState.ERROR,
            tcp_rcode="NOERROR",
            tcp_aa=True,
            edns_state=DnsQueryState.ERROR,
            edns_rcode="NOERROR",
            edns_aa=True,
        )
        evidence = AuthoritativeDnsEvidence(zone="example.com", servers=(server,))
        analysis = analyze_authoritative_dns(evidence)
        finding = _findings(analysis, evidence)["Authoritative SOA service"]

        self.assertEqual(finding.status, "unknown")
        self.assertFalse(finding.applicable)

    def test_serial_skew_is_advisory_and_independent_from_configuration(self):
        evidence = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                _server("ns1.example.net", "192.0.2.53", serial=100),
                _server("ns2.example.net", "192.0.2.54", serial=101),
            ),
        )
        analysis = analyze_authoritative_dns(evidence)
        self.assertTrue(analysis.soa_configuration_consistent)
        self.assertFalse(analysis.soa_serial_consistent)
        findings = _findings(analysis, evidence)
        self.assertEqual(findings["Authoritative SOA consistency"].status, "pass")
        self.assertEqual(findings["Authoritative SOA serial"].status, "info")

    def test_ns_disagreement_is_reported_independently_from_serial(self):
        evidence = AuthoritativeDnsEvidence(
            zone="example.com",
            servers=(
                _server("ns1.example.net", "192.0.2.53", ns=("ns1.example.net", "ns2.example.net")),
                _server("ns2.example.net", "192.0.2.54", ns=("ns1.example.net", "ns3.example.net")),
            ),
        )
        analysis = analyze_authoritative_dns(evidence)
        self.assertTrue(analysis.soa_serial_consistent)
        self.assertFalse(analysis.ns_rrset_consistent)
        findings = _findings(analysis, evidence)
        self.assertEqual(findings["Authoritative SOA serial"].status, "pass")
        self.assertEqual(findings["Authoritative NS RRset consistency"].status, "warn")

    def test_edns_servfail_after_plain_udp_success_is_advisory_anomaly(self):
        server = _server(
            "ns1.example.net",
            "192.0.2.53",
            edns_state=DnsQueryState.SERVFAIL,
            edns_rcode="SERVFAIL",
            edns_aa=False,
        )
        evidence = AuthoritativeDnsEvidence(zone="example.com", servers=(server,))
        analysis = analyze_authoritative_dns(evidence)
        self.assertEqual(analysis.servers[0].edns_status, EDNS_ANOMALY)
        findings = _findings(analysis, evidence)
        self.assertEqual(findings["Authoritative EDNS(0)"].status, "warn")

    def test_empty_evidence_produces_unknown_findings_excluded_from_score(self):
        evidence = AuthoritativeDnsEvidence(zone="example.com", servers=())
        analysis = analyze_authoritative_dns(evidence)
        findings = build_authoritative_dns_findings(evidence, analysis)
        self.assertEqual(len(findings), 6)
        self.assertTrue(all(item.status == "unknown" for item in findings))
        self.assertTrue(all(item.earned == 0 for item in findings))
        self.assertTrue(all(item.applicable is False for item in findings))


if __name__ == "__main__":
    unittest.main()
