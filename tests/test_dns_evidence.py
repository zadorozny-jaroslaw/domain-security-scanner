from __future__ import annotations

import unittest

import dns.exception

from domain_security_scanner.dns_evidence import DnsEvidenceMixin
from domain_security_scanner.models import DnsQueryState
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

    def test_recursive_cache_key_preserves_existing_identity(self):
        harness = _DnsEvidenceHarness()

        self.assertEqual(
            harness._recursive_dns_cache_key("Example.COM.", "mx"),
            ("example.com", "MX"),
        )

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
        self.assertEqual(second, ["10 mail.example.com."])
        self.assertEqual(
            harness.resolver.calls,
            [("example.com", "MX")],
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


if __name__ == "__main__":
    unittest.main()
