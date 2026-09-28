from __future__ import annotations

import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from domain_security_scanner.dns_evidence import DnsEvidenceMixin
from domain_security_scanner.domains.domain.authoritative import (
    AUTHORITATIVE_EDNS_PAYLOAD,
    AuthoritativeDnsScanMixin,
    SoaRecord,
    apex_ns_from_result,
    soa_from_result,
)
from domain_security_scanner.domains.domain.delegation import (
    DelegatedNameserverEvidence,
    NameserverAddressEvidence,
    ParentDelegationEvidence,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


class _DnsHarness(DnsEvidenceMixin):
    def __init__(self):
        self.dns_query_cache = {}


def _response(qname, qtype, *, answer=(), aa=True, use_edns=False):
    query = dns.message.make_query(qname, qtype, use_edns=0 if use_edns else None)
    response = dns.message.make_response(query)
    if aa:
        response.flags |= dns.flags.AA
    else:
        response.flags &= ~dns.flags.AA
    response.set_rcode(dns.rcode.NOERROR)
    for rrset in answer:
        response.answer.append(rrset)
    if not use_edns:
        response.use_edns(edns=-1)
    return response


class DnsProfileTest(unittest.TestCase):
    def test_cache_separates_plain_and_edns_queries(self):
        harness = _DnsHarness()
        plain = harness._authoritative_dns_cache_key(
            "example.com", "SOA", server_ip="192.0.2.53"
        )
        edns = harness._authoritative_dns_cache_key(
            "example.com",
            "SOA",
            server_ip="192.0.2.53",
            edns_version=0,
            edns_payload=1232,
        )
        self.assertNotEqual(plain, edns)
        self.assertIsNone(plain.edns_version)
        self.assertEqual(edns.edns_version, 0)
        self.assertEqual(edns.edns_payload, 1232)

    def test_plain_query_has_no_edns_and_edns_probe_is_bounded(self):
        harness = _DnsHarness()
        soa = dns.rrset.from_text(
            "example.com.", 300, "IN", "SOA",
            "NS1.Example.NET. Hostmaster.Example.COM. 10 3600 600 86400 300",
        )
        plain_response = _response("example.com", "SOA", answer=(soa,), use_edns=False)
        edns_response = _response("example.com", "SOA", answer=(soa,), use_edns=True)

        with patch("domain_security_scanner.dns_evidence.dns.query.udp") as udp:
            udp.side_effect = [plain_response, edns_response]
            plain = harness.authoritative_dns_query_result(
                "example.com", "SOA", server_ip="192.0.2.53"
            )
            edns = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_ip="192.0.2.53",
                edns_version=0,
                edns_payload=AUTHORITATIVE_EDNS_PAYLOAD,
            )

        plain_query = udp.call_args_list[0].args[0]
        edns_query = udp.call_args_list[1].args[0]
        self.assertEqual(plain_query.edns, -1)
        self.assertEqual(edns_query.edns, 0)
        self.assertEqual(edns_query.payload, AUTHORITATIVE_EDNS_PAYLOAD)
        self.assertIsNone(plain.request_edns_version)
        self.assertEqual(edns.request_edns_version, 0)
        self.assertEqual(edns.request_edns_payload, AUTHORITATIVE_EDNS_PAYLOAD)


class ParsingTest(unittest.TestCase):
    def test_soa_is_normalized_for_deterministic_comparison(self):
        answer = (
            "Example.COM. 300 IN SOA NS1.Example.NET. HostMaster.Example.COM. "
            "2026092801 3600 600 1209600 300",
        )
        result = DnsQueryResult(
            "example.com",
            "SOA",
            DnsQueryState.ANSWER,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=True,
            tc=False,
            answer_section=answer,
        )
        soa, error = soa_from_result(result, "EXAMPLE.COM.")
        self.assertIsNone(error)
        self.assertEqual(
            soa,
            SoaRecord(
                mname="ns1.example.net",
                rname="hostmaster.example.com",
                serial=2026092801,
                refresh=3600,
                retry=600,
                expire=1209600,
                minimum=300,
            ),
        )

    def test_apex_ns_requires_authoritative_answer(self):
        result = DnsQueryResult(
            "example.com",
            "NS",
            DnsQueryState.ANSWER,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=True,
            tc=False,
            answer_section=(
                "example.com. 300 IN NS NS2.Example.NET.\n"
                "example.com. 300 IN NS ns1.example.net.",
            ),
        )
        self.assertEqual(
            apex_ns_from_result(result, "example.com"),
            ("ns1.example.net", "ns2.example.net"),
        )
    def test_apex_ns_accepts_authoritative_rrset_from_authority_section(self):
        result = DnsQueryResult(
            "example.com",
            "NS",
            DnsQueryState.ERROR,
            error="Authoritative negative response did not include SOA evidence",
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.TCP,
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=True,
            tc=False,
            authority_section=(
                "example.com. 300 IN NS NS2.Example.NET.\n"
                "example.com. 300 IN NS ns1.example.net.",
            ),
        )
        self.assertEqual(
            apex_ns_from_result(result, "example.com"),
            ("ns1.example.net", "ns2.example.net"),
        )

    def test_apex_ns_rejects_non_authoritative_authority_section(self):
        result = DnsQueryResult(
            "example.com",
            "NS",
            DnsQueryState.NOT_AUTHORITATIVE,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=False,
            tc=False,
            authority_section=(
                "example.com. 300 IN NS ns1.example.net.\n"
                "example.com. 300 IN NS ns2.example.net.",
            ),
        )
        self.assertEqual(apex_ns_from_result(result, "example.com"), ())


class _TerminalMixin:
    def collect_domain_dns(self):
        self.terminal_called = True
        return "done"


class _CollectionHarness(AuthoritativeDnsScanMixin, _TerminalMixin):
    def __init__(self, delegation):
        self.delegation = delegation
        self.calls = []
        self.terminal_called = False

    def authoritative_dns_query_result(
        self,
        host,
        rtype,
        *,
        server_ip,
        server_name=None,
        transport=DnsTransport.UDP,
        timeout=3.0,
        edns_version=None,
        edns_payload=None,
    ):
        self.calls.append(
            (host, rtype, server_name, server_ip, DnsTransport(transport), edns_version, edns_payload)
        )
        if rtype == "SOA":
            answer = (
                f"{host}. 300 IN SOA {server_name}. hostmaster.{host}. "
                "1 3600 600 86400 300",
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
            transport=DnsTransport(transport),
            server_name=server_name,
            server_ip=server_ip,
            request_edns_version=edns_version,
            request_edns_payload=edns_payload,
            rcode="NOERROR",
            aa=True,
            tc=False,
            answer_section=answer,
        )


class CollectionTest(unittest.TestCase):
    def test_collects_udp_tcp_edns_and_one_apex_ns_per_server(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53", "192.0.2.54", "2001:db8::53"),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_servers=(server,),
        )
        harness = _CollectionHarness(delegation)
        result = harness.collect_domain_dns()

        self.assertEqual(result, "done")
        self.assertTrue(harness.terminal_called)
        evidence = harness.authoritative_dns
        self.assertEqual(evidence.zone, "example.com")
        self.assertEqual(
            evidence.servers[0].probe_addresses,
            ("192.0.2.53", "2001:db8::53"),
        )
        self.assertEqual(len(evidence.servers[0].endpoints), 2)

        soa_calls = [call for call in harness.calls if call[1] == "SOA"]
        ns_calls = [call for call in harness.calls if call[1] == "NS"]
        self.assertEqual(len(soa_calls), 5)
        self.assertEqual(len(ns_calls), 1)
        self.assertEqual(
            [(call[4], call[5], call[6]) for call in soa_calls[:3]],
            [
                (DnsTransport.UDP, None, None),
                (DnsTransport.TCP, None, None),
                (DnsTransport.UDP, 0, AUTHORITATIVE_EDNS_PAYLOAD),
            ],
        )
        self.assertEqual(
            evidence.servers[0].endpoints[0].udp_soa.soa.serial,
            1,
        )
    def test_apex_ns_falls_back_to_tcp_when_udp_is_not_authoritative(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53",),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_servers=(server,),
        )

        class Harness(_CollectionHarness):
            def authoritative_dns_query_result(self, host, rtype, **kwargs):
                transport = DnsTransport(kwargs.get("transport", DnsTransport.UDP))
                if rtype == "NS":
                    self.calls.append(
                        (host, rtype, kwargs.get("server_name"), kwargs["server_ip"],
                         transport, kwargs.get("edns_version"), kwargs.get("edns_payload"))
                    )
                    if transport == DnsTransport.UDP:
                        return DnsQueryResult(
                            host, rtype, DnsQueryState.NOT_AUTHORITATIVE,
                            query_mode=DnsQueryMode.AUTHORITATIVE,
                            transport=transport,
                            server_name=kwargs.get("server_name"),
                            server_ip=kwargs["server_ip"],
                            rcode="NOERROR", aa=False, tc=False,
                            authority_section=(
                                f"{host}. 300 IN NS ns1.example.net.\n"
                                f"{host}. 300 IN NS ns2.example.net.",
                            ),
                        )
                    return DnsQueryResult(
                        host, rtype, DnsQueryState.ERROR,
                        error="Authoritative negative response did not include SOA evidence",
                        query_mode=DnsQueryMode.AUTHORITATIVE,
                        transport=transport,
                        server_name=kwargs.get("server_name"),
                        server_ip=kwargs["server_ip"],
                        rcode="NOERROR", aa=True, tc=False,
                        authority_section=(
                            f"{host}. 300 IN NS ns1.example.net.\n"
                            f"{host}. 300 IN NS ns2.example.net.",
                        ),
                    )
                return super().authoritative_dns_query_result(host, rtype, **kwargs)

        harness = Harness(delegation)
        harness.collect_domain_dns()
        evidence = harness.authoritative_dns.servers[0]
        ns_calls = [call for call in harness.calls if call[1] == "NS"]
        self.assertEqual([call[4] for call in ns_calls], [DnsTransport.UDP, DnsTransport.TCP])
        self.assertEqual(evidence.apex_nameservers, ("ns1.example.net", "ns2.example.net"))
        self.assertEqual(evidence.apex_ns_result.transport, DnsTransport.TCP)


class CollectionFailureTest(unittest.TestCase):
    def test_tcp_failure_is_preserved_without_overwriting_udp_or_edns(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53",),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_servers=(server,),
        )

        class Harness(_CollectionHarness):
            def authoritative_dns_query_result(self, host, rtype, **kwargs):
                transport = DnsTransport(kwargs.get("transport", DnsTransport.UDP))
                if rtype == "SOA" and transport == DnsTransport.TCP:
                    return DnsQueryResult(
                        host,
                        rtype,
                        DnsQueryState.TIMEOUT,
                        error="timed out",
                        query_mode=DnsQueryMode.AUTHORITATIVE,
                        transport=transport,
                        server_name=kwargs.get("server_name"),
                        server_ip=kwargs["server_ip"],
                        request_edns_version=kwargs.get("edns_version"),
                        request_edns_payload=kwargs.get("edns_payload"),
                    )
                return super().authoritative_dns_query_result(host, rtype, **kwargs)

        harness = Harness(delegation)
        harness.collect_domain_dns()
        endpoint = harness.authoritative_dns.servers[0].endpoints[0]
        self.assertEqual(endpoint.udp_soa.result.state, DnsQueryState.ANSWER)
        self.assertEqual(endpoint.tcp_soa.result.state, DnsQueryState.TIMEOUT)
        self.assertEqual(endpoint.edns_soa.result.state, DnsQueryState.ANSWER)

    def test_edns_anomaly_is_kept_separate_from_plain_udp(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53",),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_servers=(server,),
        )

        class Harness(_CollectionHarness):
            def authoritative_dns_query_result(self, host, rtype, **kwargs):
                if rtype == "SOA" and kwargs.get("edns_version") == 0:
                    return DnsQueryResult(
                        host,
                        rtype,
                        DnsQueryState.SERVFAIL,
                        error="DNS RCODE SERVFAIL",
                        query_mode=DnsQueryMode.AUTHORITATIVE,
                        transport=DnsTransport.UDP,
                        server_name=kwargs.get("server_name"),
                        server_ip=kwargs["server_ip"],
                        request_edns_version=0,
                        request_edns_payload=kwargs.get("edns_payload"),
                        rcode="SERVFAIL",
                        aa=False,
                        tc=False,
                    )
                return super().authoritative_dns_query_result(host, rtype, **kwargs)

        harness = Harness(delegation)
        harness.collect_domain_dns()
        endpoint = harness.authoritative_dns.servers[0].endpoints[0]
        self.assertEqual(endpoint.udp_soa.result.state, DnsQueryState.ANSWER)
        self.assertEqual(endpoint.edns_soa.result.state, DnsQueryState.SERVFAIL)
        self.assertEqual(endpoint.edns_soa.result.request_edns_version, 0)

    def test_known_authoritative_endpoint_from_delegation_is_preferred(self):
        authority = DnsQueryResult(
            "example.com",
            "NS",
            DnsQueryState.ANSWER,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.net",
            server_ip="192.0.2.54",
            rcode="NOERROR",
            aa=True,
            tc=False,
        )
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=NameserverAddressEvidence(name="ns1.example.net"),
            candidate_addresses=("192.0.2.53", "192.0.2.54"),
            authority_queries=(authority,),
        )
        delegation = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_servers=(server,),
        )
        harness = _CollectionHarness(delegation)
        harness.collect_domain_dns()
        self.assertEqual(
            harness.authoritative_dns.servers[0].probe_addresses,
            ("192.0.2.54",),
        )


if __name__ == "__main__":
    unittest.main()
