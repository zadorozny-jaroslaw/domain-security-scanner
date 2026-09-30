from __future__ import annotations

import unittest
from types import SimpleNamespace

from domain_security_scanner.domains.domain.authoritative import (
    AuthoritativeDnsScanMixin,
    AuthoritativeEndpointEvidence,
    AuthoritativeServerEvidence,
    SoaObservation,
    SoaRecord,
)
from domain_security_scanner.domains.domain.delegation import (
    DelegatedNameserverEvidence,
    NameserverAddressEvidence,
    ParentDelegationEvidence,
)
from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidenceCollectorMixin,
    dnssec_child_endpoints,
    dnssec_parent_endpoints,
)
from domain_security_scanner.domains.domain.negative_dns import (
    NegativeDnsEvidenceCollectorMixin,
)
from domain_security_scanner.domains.domain.negative_dns_analysis import (
    RecursionState,
    analyze_recursion_result,
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
    state: DnsQueryState = DnsQueryState.ANSWER,
    server_name: str | None = "ns1.example.net",
    server_ip: str = "192.0.2.53",
    aa: bool | None = True,
    answer_section: tuple[str, ...] = (),
    rcode: str | None = "NOERROR",
    transport: DnsTransport = DnsTransport.UDP,
    request_recursion_desired: bool = False,
    rd: bool | None = None,
    ra: bool | None = None,
) -> DnsQueryResult:
    return DnsQueryResult(
        "example.com",
        qtype,
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=transport,
        server_name=server_name,
        server_ip=server_ip,
        rcode=rcode,
        aa=aa,
        answer_section=answer_section,
        request_recursion_desired=request_recursion_desired,
        rd=rd,
        ra=ra,
    )


class _DnssecHarness(DnssecEvidenceCollectorMixin):
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.root_domain = "example.com"
        self.negative_dns = None

    def authoritative_dns_query_result(self, host, rtype, **kwargs):
        key = (
            kwargs.get("server_name"),
            kwargs["server_ip"],
            rtype.upper(),
            DnsTransport(kwargs.get("transport", DnsTransport.UDP)),
        )
        self.calls.append((host, rtype.upper(), dict(kwargs)))
        return self.responses[key]


class DnssecRobustnessTest(unittest.TestCase):
    def test_parent_endpoints_keep_source_first_then_spread_across_parents(self):
        delegation = SimpleNamespace(
            source_server_name="a.parent.test",
            source_server_ip="192.0.2.1",
            parent_server_addresses=(
                SimpleNamespace(
                    name="a.parent.test",
                    addresses=("192.0.2.1", "192.0.2.11"),
                ),
                SimpleNamespace(
                    name="b.parent.test",
                    addresses=("192.0.2.2", "192.0.2.12"),
                ),
            ),
        )

        self.assertEqual(
            dnssec_parent_endpoints(delegation, limit=3),
            (
                ("a.parent.test", "192.0.2.1"),
                ("b.parent.test", "192.0.2.2"),
                ("a.parent.test", "192.0.2.11"),
            ),
        )

    def test_child_fallback_is_breadth_first_across_nameservers(self):
        delegation = SimpleNamespace(
            delegated_servers=(
                SimpleNamespace(
                    name="ns1.example.net",
                    candidate_addresses=("192.0.2.53", "192.0.2.54"),
                    authority_queries=(),
                ),
                SimpleNamespace(
                    name="ns2.example.net",
                    candidate_addresses=("192.0.2.63", "192.0.2.64"),
                    authority_queries=(),
                ),
            )
        )

        self.assertEqual(
            dnssec_child_endpoints(delegation, limit=4),
            (
                ("ns1.example.net", "192.0.2.53"),
                ("ns2.example.net", "192.0.2.63"),
                ("ns1.example.net", "192.0.2.54"),
                ("ns2.example.net", "192.0.2.64"),
            ),
        )

    def test_parent_ds_falls_back_after_non_authoritative_source(self):
        parent_addresses = (
            NameserverAddressEvidence(
                name="a.parent.test",
                ipv4=("192.0.2.1",),
            ),
            NameserverAddressEvidence(
                name="b.parent.test",
                ipv4=("192.0.2.2",),
            ),
        )
        child = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53",),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            source_server_name="a.parent.test",
            source_server_ip="192.0.2.1",
            parent_server_addresses=parent_addresses,
            delegated_servers=(child,),
        )
        responses = {
            ("a.parent.test", "192.0.2.1", "DS", DnsTransport.UDP): _result(
                "DS",
                state=DnsQueryState.NOT_AUTHORITATIVE,
                server_name="a.parent.test",
                server_ip="192.0.2.1",
                aa=False,
            ),
            ("b.parent.test", "192.0.2.2", "DS", DnsTransport.UDP): _result(
                "DS",
                server_name="b.parent.test",
                server_ip="192.0.2.2",
            ),
            ("ns1.example.net", "192.0.2.53", "DNSKEY", DnsTransport.UDP): _result(
                "DNSKEY"
            ),
            ("ns1.example.net", "192.0.2.53", "SOA", DnsTransport.UDP): _result(
                "SOA"
            ),
            ("ns1.example.net", "192.0.2.53", "NS", DnsTransport.UDP): _result(
                "NS"
            ),
        }
        harness = _DnssecHarness(responses)

        evidence = harness.collect_dnssec_evidence(delegation)

        self.assertEqual(evidence.parent_ds.server_name, "b.parent.test")
        self.assertEqual(len(evidence.parent_ds_attempts), 2)
        self.assertEqual(
            [call[2]["server_ip"] for call in harness.calls[:2]],
            ["192.0.2.1", "192.0.2.2"],
        )

    def test_apex_rrsets_can_fall_back_independently_of_dnskey_endpoint(self):
        child1 = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53",),
        )
        child2 = DelegatedNameserverEvidence(
            name="ns2.example.net",
            addresses=NameserverAddressEvidence(name="ns2.example.net"),
            candidate_addresses=("192.0.2.54",),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            source_server_name="a.parent.test",
            source_server_ip="192.0.2.1",
            delegated_servers=(child1, child2),
        )
        responses = {
            ("a.parent.test", "192.0.2.1", "DS", DnsTransport.UDP): _result(
                "DS", server_name="a.parent.test", server_ip="192.0.2.1"
            ),
            ("ns1.example.net", "192.0.2.53", "DNSKEY", DnsTransport.UDP): _result(
                "DNSKEY"
            ),
            ("ns1.example.net", "192.0.2.53", "SOA", DnsTransport.UDP): _result(
                "SOA", state=DnsQueryState.NOT_AUTHORITATIVE, aa=False
            ),
            ("ns2.example.net", "192.0.2.54", "SOA", DnsTransport.UDP): _result(
                "SOA", server_name="ns2.example.net", server_ip="192.0.2.54"
            ),
            ("ns1.example.net", "192.0.2.53", "NS", DnsTransport.UDP): _result(
                "NS", state=DnsQueryState.NOT_AUTHORITATIVE, aa=False
            ),
            ("ns2.example.net", "192.0.2.54", "NS", DnsTransport.UDP): _result(
                "NS", server_name="ns2.example.net", server_ip="192.0.2.54"
            ),
        }
        harness = _DnssecHarness(responses)

        evidence = harness.collect_dnssec_evidence(delegation)

        self.assertEqual(evidence.selected_dnskey.server_name, "ns1.example.net")
        self.assertEqual(
            [(item.qtype, item.server_name) for item in evidence.apex_rrsets],
            [("SOA", "ns2.example.net"), ("NS", "ns2.example.net")],
        )


class _AuthoritativeHarness(AuthoritativeDnsScanMixin):
    def __init__(self):
        self.calls = []

    def authoritative_dns_query_result(self, host, rtype, **kwargs):
        server_ip = kwargs["server_ip"]
        transport = DnsTransport(kwargs.get("transport", DnsTransport.UDP))
        self.calls.append((host, rtype, server_ip, transport, kwargs.get("edns_version")))

        if server_ip == "192.0.2.53":
            return DnsQueryResult(
                host,
                rtype,
                DnsQueryState.NOT_AUTHORITATIVE,
                query_mode=DnsQueryMode.AUTHORITATIVE,
                transport=transport,
                server_name=kwargs.get("server_name"),
                server_ip=server_ip,
                rcode="NOERROR",
                aa=False,
            )

        if rtype == "SOA":
            answer = (
                f"{host}. 300 IN SOA ns1.example.net. hostmaster.{host}. "
                "42 3600 600 86400 300",
            )
        else:
            answer = (
                f"{host}. 300 IN NS ns1.example.net.\n"
                f"{host}. 300 IN NS ns2.example.net.",
            )
        return DnsQueryResult(
            host,
            rtype,
            DnsQueryState.ANSWER,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=transport,
            server_name=kwargs.get("server_name"),
            server_ip=server_ip,
            rcode="NOERROR",
            aa=True,
            answer_section=answer,
        )


class AuthoritativeRobustnessTest(unittest.TestCase):
    def test_inconclusive_primary_replaces_family_peer_with_same_family_fallback(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=(
                "192.0.2.53",
                "192.0.2.54",
                "2001:db8::53",
            ),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_servers=(server,),
        )
        harness = _AuthoritativeHarness()

        evidence = harness.collect_authoritative_dns_evidence(delegation)
        server_evidence = evidence.servers[0]

        self.assertEqual(
            server_evidence.probe_addresses,
            ("192.0.2.53", "192.0.2.54"),
        )
        self.assertEqual(server_evidence.endpoints[1].udp_soa.soa.serial, 42)
        self.assertEqual(
            server_evidence.apex_nameservers,
            ("ns1.example.net", "ns2.example.net"),
        )
        self.assertIn("2001:db8::53", server_evidence.unprobed_addresses)


class RecursionAttributionTest(unittest.TestCase):
    def test_open_recursion_requires_confirmed_authoritative_target_path(self):
        result = DnsQueryResult(
            "example.com",
            "A",
            DnsQueryState.ANSWER,
            ("192.0.2.10",),
            rcode="NOERROR",
            aa=False,
            rd=True,
            ra=True,
            request_recursion_desired=True,
        )

        state, reason = analyze_recursion_result(
            result,
            authority_confirmed=False,
        )
        self.assertEqual(state, RecursionState.UNKNOWN)
        self.assertIn("not independently confirmed", reason)

        state, _ = analyze_recursion_result(
            result,
            authority_confirmed=True,
        )
        self.assertEqual(state, RecursionState.OPEN)

    def test_negative_probe_prefers_endpoint_with_positive_authoritative_soa(self):
        bad_result = _result(
            "SOA",
            state=DnsQueryState.NOT_AUTHORITATIVE,
            server_ip="192.0.2.53",
            aa=False,
        )
        good_result = _result(
            "SOA",
            server_ip="192.0.2.54",
            answer_section=(
                "example.com. 300 IN SOA ns1.example.net. hostmaster.example.com. "
                "42 3600 600 86400 300",
            ),
        )
        good_soa = SoaRecord(
            mname="ns1.example.net",
            rname="hostmaster.example.com",
            serial=42,
            refresh=3600,
            retry=600,
            expire=86400,
            minimum=300,
        )
        server = AuthoritativeServerEvidence(
            name="ns1.example.net",
            candidate_addresses=("192.0.2.53", "192.0.2.54"),
            probe_addresses=("192.0.2.53", "192.0.2.54"),
            unprobed_addresses=(),
            endpoints=(
                AuthoritativeEndpointEvidence(
                    server_name="ns1.example.net",
                    server_ip="192.0.2.53",
                    udp_soa=SoaObservation(bad_result),
                    tcp_soa=SoaObservation(bad_result),
                ),
                AuthoritativeEndpointEvidence(
                    server_name="ns1.example.net",
                    server_ip="192.0.2.54",
                    udp_soa=SoaObservation(good_result, soa=good_soa),
                    tcp_soa=SoaObservation(good_result, soa=good_soa),
                ),
            ),
        )

        endpoint = NegativeDnsEvidenceCollectorMixin._negative_dns_primary_endpoint(server)

        self.assertEqual(endpoint, "192.0.2.54")
        self.assertTrue(
            NegativeDnsEvidenceCollectorMixin._negative_dns_authority_confirmed(
                server,
                endpoint,
            )
        )


if __name__ == "__main__":
    unittest.main()
