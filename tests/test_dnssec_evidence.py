from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rrset

from domain_security_scanner.dns_evidence import DnsEvidenceMixin
from domain_security_scanner.domains.domain.dnssec import (
    DNSSEC_APEX_RRTYPES,
    DNSSEC_EDNS_PAYLOAD,
    DnssecEvidenceCollectorMixin,
    dnssec_child_endpoints,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


class _EvidenceHarness(DnsEvidenceMixin):
    def __init__(self):
        self.dns_query_cache = {}


class _CollectorHarness(DnssecEvidenceCollectorMixin):
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.root_domain = "example.com"

    def authoritative_dns_query_result(self, host, rtype, **kwargs):
        key = (
            kwargs.get("server_name"),
            kwargs["server_ip"],
            rtype.upper(),
            DnsTransport(kwargs.get("transport", DnsTransport.UDP)),
        )
        self.calls.append((host, rtype.upper(), dict(kwargs)))
        return self.responses[key]


def _result(
    qtype,
    *,
    state=DnsQueryState.ANSWER,
    server_name="ns1.example.net",
    server_ip="192.0.2.53",
    aa=True,
):
    return DnsQueryResult(
        "example.com",
        qtype,
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name=server_name,
        server_ip=server_ip,
        rcode="NOERROR",
        aa=aa,
    )


def _delegation():
    server1 = SimpleNamespace(
        name="ns1.example.net",
        candidate_addresses=("192.0.2.53", "2001:db8::53"),
        authority_queries=(
            _result("NS", server_name="ns1.example.net", server_ip="192.0.2.53"),
        ),
    )
    server2 = SimpleNamespace(
        name="ns2.example.net",
        candidate_addresses=("192.0.2.54",),
        authority_queries=(
            _result("NS", server_name="ns2.example.net", server_ip="192.0.2.54"),
        ),
    )
    return SimpleNamespace(
        zone="example.com",
        source_server_name="a.gtld-servers.net",
        source_server_ip="192.0.2.1",
        delegated_servers=(server1, server2),
    )


class DnssecQueryProfileTest(unittest.TestCase):
    def test_dnssec_flag_is_part_of_authoritative_cache_identity(self):
        harness = _EvidenceHarness()
        ordinary = harness._authoritative_dns_cache_key(
            "example.com",
            "DNSKEY",
            server_ip="192.0.2.53",
            edns_version=0,
        )
        dnssec = harness._authoritative_dns_cache_key(
            "example.com",
            "DNSKEY",
            server_ip="192.0.2.53",
            want_dnssec=True,
        )
        self.assertNotEqual(ordinary, dnssec)
        self.assertFalse(ordinary.want_dnssec)
        self.assertTrue(dnssec.want_dnssec)
        self.assertEqual(dnssec.edns_version, 0)

    def test_authoritative_dnssec_query_sets_do_and_records_request_profile(self):
        harness = _EvidenceHarness()
        answer = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "DNSKEY",
            "257 3 8 AQIDBA==",
        )
        query = dns.message.make_query("example.com", "DNSKEY", use_edns=0)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.answer.append(answer)

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ) as udp:
            result = harness.authoritative_dns_query_result(
                "example.com",
                "DNSKEY",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
                edns_version=0,
                edns_payload=DNSSEC_EDNS_PAYLOAD,
                want_dnssec=True,
            )

        sent = udp.call_args.args[0]
        self.assertTrue(bool(sent.ednsflags & dns.flags.DO))
        self.assertFalse(bool(sent.flags & dns.flags.RD))
        self.assertTrue(result.request_want_dnssec)
        self.assertEqual(result.request_edns_version, 0)
        self.assertEqual(result.request_edns_payload, DNSSEC_EDNS_PAYLOAD)


class DnssecCollectorTest(unittest.TestCase):
    def test_endpoint_selection_prefers_proven_authoritative_addresses(self):
        endpoints = dnssec_child_endpoints(_delegation(), limit=2)
        self.assertEqual(
            endpoints,
            (
                ("ns1.example.net", "192.0.2.53"),
                ("ns2.example.net", "192.0.2.54"),
            ),
        )

    def test_collector_requests_parent_ds_dnskey_and_deterministic_apex_rrsets(self):
        delegation = _delegation()
        responses = {
            ("a.gtld-servers.net", "192.0.2.1", "DS", DnsTransport.UDP): _result(
                "DS", server_name="a.gtld-servers.net", server_ip="192.0.2.1"
            ),
            ("ns1.example.net", "192.0.2.53", "DNSKEY", DnsTransport.UDP): _result(
                "DNSKEY"
            ),
            ("ns1.example.net", "192.0.2.53", "SOA", DnsTransport.UDP): _result(
                "SOA"
            ),
            ("ns1.example.net", "192.0.2.53", "NS", DnsTransport.UDP): _result("NS"),
        }
        harness = _CollectorHarness(responses)

        evidence = harness.collect_dnssec_evidence(delegation)

        self.assertIsNotNone(evidence.parent_ds)
        self.assertIsNotNone(evidence.selected_dnskey)
        self.assertEqual(
            tuple(item.qtype for item in evidence.apex_rrsets),
            DNSSEC_APEX_RRTYPES,
        )
        self.assertEqual(len(harness.calls), 4)
        for _host, _rtype, kwargs in harness.calls:
            self.assertTrue(kwargs["want_dnssec"])
            self.assertEqual(kwargs["edns_version"], 0)
            self.assertEqual(kwargs["edns_payload"], DNSSEC_EDNS_PAYLOAD)

    def test_unsigned_parent_ds_short_circuits_child_dnssec_queries(self):
        delegation = _delegation()
        parent_no_ds = _result(
            "DS",
            state=DnsQueryState.NO_ANSWER,
            server_name="a.gtld-servers.net",
            server_ip="192.0.2.1",
        )
        responses = {
            ("a.gtld-servers.net", "192.0.2.1", "DS", DnsTransport.UDP): parent_no_ds,
        }
        harness = _CollectorHarness(responses)

        evidence = harness.collect_dnssec_evidence(delegation)

        self.assertIsNotNone(evidence.parent_ds)
        self.assertEqual(evidence.dnskey_attempts, ())
        self.assertIsNone(evidence.selected_dnskey)
        self.assertEqual(evidence.apex_rrsets, ())
        self.assertEqual(len(harness.calls), 1)
        self.assertEqual(harness.calls[0][1], "DS")

    def test_collector_uses_second_child_endpoint_after_unavailable_dnskey(self):
        delegation = _delegation()
        timeout = _result(
            "DNSKEY",
            state=DnsQueryState.TIMEOUT,
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            aa=None,
        )
        responses = {
            ("a.gtld-servers.net", "192.0.2.1", "DS", DnsTransport.UDP): _result(
                "DS", server_name="a.gtld-servers.net", server_ip="192.0.2.1"
            ),
            ("ns1.example.net", "192.0.2.53", "DNSKEY", DnsTransport.UDP): timeout,
            ("ns2.example.net", "192.0.2.54", "DNSKEY", DnsTransport.UDP): _result(
                "DNSKEY", server_name="ns2.example.net", server_ip="192.0.2.54"
            ),
            ("ns2.example.net", "192.0.2.54", "SOA", DnsTransport.UDP): _result(
                "SOA", server_name="ns2.example.net", server_ip="192.0.2.54"
            ),
            ("ns2.example.net", "192.0.2.54", "NS", DnsTransport.UDP): _result(
                "NS", server_name="ns2.example.net", server_ip="192.0.2.54"
            ),
        }
        harness = _CollectorHarness(responses)

        evidence = harness.collect_dnssec_evidence(delegation)

        self.assertEqual(len(evidence.dnskey_attempts), 2)
        self.assertEqual(evidence.selected_dnskey.server_name, "ns2.example.net")
        self.assertEqual(evidence.selected_dnskey.server_ip, "192.0.2.54")

    def test_truncated_dnssec_query_has_one_explicit_tcp_fallback(self):
        delegation = _delegation()
        truncated = _result("DNSKEY", state=DnsQueryState.TRUNCATED)
        complete = DnsQueryResult(
            "example.com",
            "DNSKEY",
            DnsQueryState.ANSWER,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.TCP,
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=True,
        )
        responses = {
            ("a.gtld-servers.net", "192.0.2.1", "DS", DnsTransport.UDP): _result(
                "DS", server_name="a.gtld-servers.net", server_ip="192.0.2.1"
            ),
            ("ns1.example.net", "192.0.2.53", "DNSKEY", DnsTransport.UDP): truncated,
            ("ns1.example.net", "192.0.2.53", "DNSKEY", DnsTransport.TCP): complete,
            ("ns1.example.net", "192.0.2.53", "SOA", DnsTransport.UDP): _result(
                "SOA"
            ),
            ("ns1.example.net", "192.0.2.53", "NS", DnsTransport.UDP): _result("NS"),
        }
        harness = _CollectorHarness(responses)

        evidence = harness.collect_dnssec_evidence(delegation)

        self.assertIsNotNone(evidence.selected_dnskey.tcp_result)
        dnskey_calls = [call for call in harness.calls if call[1] == "DNSKEY"]
        self.assertEqual(len(dnskey_calls), 2)
        self.assertEqual(dnskey_calls[0][2]["transport"], DnsTransport.UDP)
        self.assertEqual(dnskey_calls[1][2]["transport"], DnsTransport.TCP)


if __name__ == "__main__":
    unittest.main()
