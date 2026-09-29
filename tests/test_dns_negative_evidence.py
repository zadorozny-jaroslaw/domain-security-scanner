from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns.flags
import dns.message
import dns.query
import dns.rrset

from domain_security_scanner.dns_evidence import DnsEvidenceMixin
from domain_security_scanner.domains.domain.negative_dns import (
    NEGATIVE_DNS_PROBE_COUNT,
    NegativeDnsEvidenceCollectorMixin,
)
from domain_security_scanner.models import (
    DnsQueryCacheKey,
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
)


class _DnsHarness(DnsEvidenceMixin):
    def __init__(self):
        self.dns_query_cache = {}


class _CollectorHarness(NegativeDnsEvidenceCollectorMixin):
    def __init__(self):
        self.calls = []

    def _negative_dns_probe_names(self, zone: str):
        return (
            f"dssnx0-fixed.{zone}",
            f"dssnx1-fixed.{zone}",
        )

    def authoritative_dns_query_result(self, host, rtype, **kwargs):
        self.calls.append((host, rtype, kwargs))
        return DnsQueryResult(
            host,
            rtype,
            DnsQueryState.NOT_AUTHORITATIVE
            if kwargs.get("recursion_desired")
            else DnsQueryState.NXDOMAIN,
            server_name=kwargs.get("server_name"),
            server_ip=kwargs.get("server_ip"),
            request_recursion_desired=kwargs.get("recursion_desired", False),
        )


class DnsIssue19EvidenceTests(unittest.TestCase):
    def test_cache_key_separates_recursion_desired_profile(self):
        base = dict(
            qname="Example.COM.",
            qtype="a",
            mode=DnsQueryMode.AUTHORITATIVE,
            server_name="NS1.EXAMPLE.COM.",
            server_ip="192.0.2.53",
        )
        ordinary = DnsQueryCacheKey.build(**base)
        recursive = DnsQueryCacheKey.build(**base, recursion_desired=True)

        self.assertFalse(ordinary.recursion_desired)
        self.assertTrue(recursive.recursion_desired)
        self.assertNotEqual(ordinary, recursive)

    def test_cache_key_rejects_non_boolean_recursion_flag(self):
        with self.assertRaises(TypeError):
            DnsQueryCacheKey.build(
                "example.com",
                "A",
                mode=DnsQueryMode.AUTHORITATIVE,
                server_ip="192.0.2.53",
                recursion_desired=1,
            )

    def test_direct_recursion_probe_sets_rd_and_preserves_rd_ra(self):
        harness = _DnsHarness()
        observed_queries = []

        def fake_udp(query, where, timeout, raise_on_truncation):
            observed_queries.append(query)
            response = dns.message.make_response(query)
            response.flags |= dns.flags.RA
            response.answer.append(
                dns.rrset.from_text(
                    "example.com.",
                    300,
                    "IN",
                    "A",
                    "192.0.2.10",
                )
            )
            return response

        with patch.object(dns.query, "udp", side_effect=fake_udp):
            result = harness.authoritative_dns_query_result(
                "example.com",
                "A",
                server_name="ns1.target.test",
                server_ip="192.0.2.53",
                recursion_desired=True,
            )

        self.assertEqual(len(observed_queries), 1)
        self.assertTrue(bool(observed_queries[0].flags & dns.flags.RD))
        self.assertTrue(result.request_recursion_desired)
        self.assertTrue(result.rd)
        self.assertTrue(result.ra)
        self.assertEqual(result.state, DnsQueryState.ANSWER)
        self.assertEqual(result.records, ("192.0.2.10",))
        self.assertIsNone(result.error)

    def test_normal_direct_query_still_clears_rd(self):
        harness = _DnsHarness()
        observed_queries = []

        def fake_udp(query, where, timeout, raise_on_truncation):
            observed_queries.append(query)
            response = dns.message.make_response(query)
            response.flags |= dns.flags.AA
            response.answer.append(
                dns.rrset.from_text(
                    "target.test.",
                    300,
                    "IN",
                    "A",
                    "192.0.2.20",
                )
            )
            return response

        with patch.object(dns.query, "udp", side_effect=fake_udp):
            result = harness.authoritative_dns_query_result(
                "target.test",
                "A",
                server_name="ns1.target.test",
                server_ip="192.0.2.53",
            )

        self.assertFalse(bool(observed_queries[0].flags & dns.flags.RD))
        self.assertFalse(result.request_recursion_desired)
        self.assertFalse(result.rd)
        self.assertFalse(result.ra)
        self.assertEqual(result.state, DnsQueryState.ANSWER)

    def test_collector_adds_exactly_two_negative_and_one_recursion_probe_per_server(self):
        harness = _CollectorHarness()
        authoritative = SimpleNamespace(
            zone="target.test",
            servers=(
                SimpleNamespace(
                    name="ns1.target.test",
                    endpoints=(SimpleNamespace(server_ip="192.0.2.53"),),
                    probe_addresses=("192.0.2.53",),
                ),
                SimpleNamespace(
                    name="ns2.target.test",
                    endpoints=(SimpleNamespace(server_ip="192.0.2.54"),),
                    probe_addresses=("192.0.2.54",),
                ),
            ),
        )

        evidence = harness.collect_negative_dns_evidence(authoritative)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.zone, "target.test")
        self.assertEqual(evidence.negative_probe_count, NEGATIVE_DNS_PROBE_COUNT)
        self.assertEqual(len(evidence.negative_names), 2)
        self.assertEqual(len(evidence.servers), 2)
        self.assertEqual(len(harness.calls), 6)

        for server_index, server in enumerate(evidence.servers):
            calls = harness.calls[server_index * 3 : server_index * 3 + 3]
            self.assertEqual(len(server.negative_results), 2)
            self.assertIsNotNone(server.recursion_result)
            self.assertFalse(calls[0][2].get("recursion_desired", False))
            self.assertFalse(calls[1][2].get("recursion_desired", False))
            self.assertTrue(calls[2][2]["recursion_desired"])
            self.assertNotEqual(calls[2][0], evidence.zone)
            self.assertFalse(calls[2][0].endswith("." + evidence.zone))

    def test_collector_does_not_create_extra_endpoint_fallbacks(self):
        harness = _CollectorHarness()
        authoritative = SimpleNamespace(
            zone="target.test",
            servers=(
                SimpleNamespace(
                    name="ns1.target.test",
                    endpoints=(),
                    probe_addresses=(),
                ),
            ),
        )

        evidence = harness.collect_negative_dns_evidence(authoritative)

        self.assertEqual(harness.calls, [])
        self.assertEqual(len(evidence.servers), 1)
        self.assertIsNone(evidence.servers[0].server_ip)
        self.assertEqual(evidence.servers[0].negative_results, ())
        self.assertIsNone(evidence.servers[0].recursion_result)

    def test_recursion_probe_name_is_outside_assessed_zone(self):
        harness = _CollectorHarness()

        self.assertEqual(
            harness._negative_dns_recursion_probe_name("example.com"),
            "example.net",
        )
        self.assertEqual(
            harness._negative_dns_recursion_probe_name("com"),
            "example.net",
        )
        self.assertEqual(
            harness._negative_dns_recursion_probe_name("target.test"),
            "example.com",
        )

    def test_default_negative_names_are_distinct_bounded_children(self):
        harness = NegativeDnsEvidenceCollectorMixin()
        names = harness._negative_dns_probe_names("target.test")

        self.assertEqual(len(names), NEGATIVE_DNS_PROBE_COUNT)
        self.assertEqual(len(set(names)), NEGATIVE_DNS_PROBE_COUNT)
        for name in names:
            self.assertTrue(name.endswith(".target.test"))
            self.assertLessEqual(len(name), 253)
            self.assertLessEqual(len(name.split(".", 1)[0]), 63)


if __name__ == "__main__":
    unittest.main()
