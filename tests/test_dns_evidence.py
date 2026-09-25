from __future__ import annotations

import unittest

import dns.exception

from domain_security_scanner.dns_evidence import DnsEvidenceMixin
from domain_security_scanner.domains.mail import MailScanMixin
from domain_security_scanner.models import (
    DnsQueryCacheKey,
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)
from domain_security_scanner.scanner import Scanner


class _FakeRecord:
    def __init__(self, value: str):
        self.value = value

    def to_text(self) -> str:
        return self.value


class _FakeAnswer(list):
    def __init__(self, records=()):
        super().__init__(_FakeRecord(value) for value in records)
        self.rrset = object() if records else None


class _FakeResolver:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def resolve(self, host, rtype, raise_on_no_answer=False):
        key = (host.lower().rstrip("."), rtype.upper())
        self.calls.append(key)
        response = self.responses.get(key, _FakeAnswer())
        if isinstance(response, BaseException):
            raise response
        return response


class _DnsEvidenceHarness(DnsEvidenceMixin):
    def __init__(self):
        self.resolver = _FakeResolver()
        self.dns_query_cache = {}


class SharedDnsEvidenceTest(unittest.TestCase):
    def test_scanner_resolves_dns_helpers_from_shared_layer(self):
        self.assertIs(Scanner.dns_query_result, DnsEvidenceMixin.dns_query_result)
        self.assertIs(Scanner.dns_query, DnsEvidenceMixin.dns_query)
        self.assertIs(
            Scanner._dns_unavailable_message,
            DnsEvidenceMixin._dns_unavailable_message,
        )

    def test_mail_mixin_no_longer_owns_generic_dns_helpers(self):
        self.assertNotIn("dns_query_result", MailScanMixin.__dict__)
        self.assertNotIn("dns_query", MailScanMixin.__dict__)
        self.assertNotIn("_dns_unavailable_message", MailScanMixin.__dict__)

    def test_legacy_dns_result_construction_remains_compatible(self):
        result = DnsQueryResult(
            "example.com",
            "MX",
            DnsQueryState.ANSWER,
            ("10 mail.example.com.",),
        )

        self.assertEqual(result.host, "example.com")
        self.assertEqual(result.rtype, "MX")
        self.assertEqual(result.qname, "example.com")
        self.assertEqual(result.qtype, "MX")
        self.assertEqual(result.query_mode, DnsQueryMode.RECURSIVE)
        self.assertIsNone(result.transport)
        self.assertIsNone(result.server_name)
        self.assertIsNone(result.server_ip)

    def test_recursive_cache_key_is_normalized_and_context_complete(self):
        harness = _DnsEvidenceHarness()

        key = harness._recursive_dns_cache_key("Example.COM.", "mx")

        self.assertIsInstance(key, DnsQueryCacheKey)
        self.assertEqual(key.qname, "example.com")
        self.assertEqual(key.qtype, "MX")
        self.assertEqual(key.mode, DnsQueryMode.RECURSIVE)
        self.assertIsNone(key.transport)
        self.assertIsNone(key.server_name)
        self.assertIsNone(key.server_ip)

    def test_cache_keys_separate_mode_transport_and_authoritative_server(self):
        harness = _DnsEvidenceHarness()

        recursive = harness._dns_cache_key(
            "example.com",
            "SOA",
            mode=DnsQueryMode.RECURSIVE,
        )
        auth_udp_a = harness._dns_cache_key(
            "example.com",
            "SOA",
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="NS1.Example.NET.",
            server_ip="192.0.2.53",
        )
        auth_tcp_a = harness._dns_cache_key(
            "example.com",
            "SOA",
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.TCP,
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
        )
        auth_udp_b = harness._dns_cache_key(
            "example.com",
            "SOA",
            mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns2.example.net",
            server_ip="192.0.2.54",
        )

        self.assertEqual(len({
            recursive,
            auth_udp_a,
            auth_tcp_a,
            auth_udp_b,
        }), 4)
        self.assertEqual(auth_udp_a.server_name, "ns1.example.net")

    def test_shared_recursive_query_preserves_records_and_cache_behavior(self):
        harness = _DnsEvidenceHarness()
        harness.resolver = _FakeResolver(
            {
                ("example.com", "MX"): _FakeAnswer(
                    ["10 mail.example.com."]
                )
            }
        )

        first = harness.dns_query_result("Example.COM.", "mx")
        second = harness.dns_query("example.com", "MX")

        self.assertEqual(first.state, DnsQueryState.ANSWER)
        self.assertEqual(first.records, ("10 mail.example.com.",))
        self.assertEqual(first.query_mode, DnsQueryMode.RECURSIVE)
        self.assertEqual(second, ["10 mail.example.com."])
        self.assertEqual(
            harness.resolver.calls,
            [("example.com", "MX")],
        )
        self.assertIs(
            harness.dns_cached_result("EXAMPLE.COM.", "mx"),
            first,
        )

    def test_shared_recursive_no_answer_remains_conclusive_absence(self):
        harness = _DnsEvidenceHarness()

        result = harness.dns_query_result("example.com", "CAA")

        self.assertEqual(result.state, DnsQueryState.NO_ANSWER)
        self.assertTrue(result.absent)
        self.assertFalse(result.failed)

    def test_shared_recursive_timeout_remains_failure_not_absence(self):
        harness = _DnsEvidenceHarness()
        harness.resolver = _FakeResolver(
            {
                ("example.com", "TXT"): dns.exception.Timeout(timeout=1)
            }
        )

        result = harness.dns_query_result("example.com", "TXT")

        self.assertEqual(result.state, DnsQueryState.TIMEOUT)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(
            harness._dns_unavailable_message(result),
            "timeout",
        )

    def test_transport_error_is_failure_not_absence(self):
        result = DnsQueryResult(
            "example.com",
            "SOA",
            DnsQueryState.TRANSPORT_ERROR,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.TCP,
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
        )

        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(
            DnsEvidenceMixin._dns_unavailable_message(result),
            "transport error",
        )


if __name__ == "__main__":
    unittest.main()
