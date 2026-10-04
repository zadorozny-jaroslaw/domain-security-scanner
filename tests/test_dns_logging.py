from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rrset

from domain_security_scanner.dns_evidence import DnsEvidenceMixin
from domain_security_scanner.models import DnsQueryState, DnsTransport
from domain_security_scanner.runtime_logging import configure_cli_logging


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
    def __init__(self, response):
        self.response = response
        self.calls = []

    def resolve(self, host, rtype, raise_on_no_answer=False):
        self.calls.append((host, rtype))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class _DnsEvidenceHarness(DnsEvidenceMixin):
    def __init__(self, response=None):
        self.resolver = _FakeResolver(response or _FakeAnswer())
        self.dns_query_cache = {}


def _authoritative_answer(qname: str, qtype: str, value: str):
    query = dns.message.make_query(qname, qtype, use_edns=0)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    response.answer.append(
        dns.rrset.from_text(qname + ".", 300, "IN", qtype, value)
    )
    return response


class DnsTraceLoggingTest(unittest.TestCase):
    def test_recursive_trace_logs_state_and_timing_without_record_payload(self):
        harness = _DnsEvidenceHarness(_FakeAnswer(["203.0.113.7"]))
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            result = harness.dns_query_result("Example.COM.", "a")

        output = stderr.getvalue()
        self.assertEqual(result.state, DnsQueryState.ANSWER)
        self.assertIn("DNS recursive: example.com A -> answer (", output)
        self.assertIn("ms)", output)
        self.assertNotIn("203.0.113.7", output)

    def test_recursive_trace_reports_cache_hit_without_network_retry(self):
        harness = _DnsEvidenceHarness(_FakeAnswer(["203.0.113.7"]))
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            first = harness.dns_query_result("example.com", "A")
            second = harness.dns_query_result("example.com", "A")

        output = stderr.getvalue()
        self.assertIs(first, second)
        self.assertEqual(harness.resolver.calls, [("example.com", "A")])
        self.assertIn(
            "DNS cache hit: recursive example.com A -> answer",
            output,
        )

    def test_recursive_trace_does_not_log_exception_message(self):
        harness = _DnsEvidenceHarness(RuntimeError("secret-token-must-not-be-logged"))
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            result = harness.dns_query_result("example.com", "TXT")

        output = stderr.getvalue()
        self.assertEqual(result.state, DnsQueryState.ERROR)
        self.assertIn("DNS recursive: example.com TXT -> error", output)
        self.assertNotIn("secret-token-must-not-be-logged", output)

    def test_authoritative_trace_logs_transport_server_state_and_cache_hit(self):
        harness = _DnsEvidenceHarness()
        response = _authoritative_answer("example.com", "A", "203.0.113.7")
        stderr = io.StringIO()

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ) as udp, redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            first = harness.authoritative_dns_query_result(
                "example.com",
                "A",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
                transport=DnsTransport.UDP,
            )
            second = harness.authoritative_dns_query_result(
                "example.com",
                "A",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
                transport=DnsTransport.UDP,
            )

        output = stderr.getvalue()
        self.assertIs(first, second)
        self.assertEqual(udp.call_count, 1)
        self.assertIn(
            "DNS authoritative: example.com A via udp 192.0.2.53 -> answer (",
            output,
        )
        self.assertIn(
            "DNS cache hit: authoritative example.com A via udp 192.0.2.53 -> answer",
            output,
        )
        self.assertNotIn("203.0.113.7", output)

    def test_authoritative_trace_does_not_log_transport_exception_message(self):
        harness = _DnsEvidenceHarness()
        stderr = io.StringIO()

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.tcp",
            side_effect=ConnectionRefusedError("secret-transport-detail"),
        ), redirect_stderr(stderr):
            configure_cli_logging(verbose=2)
            result = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_ip="192.0.2.53",
                transport=DnsTransport.TCP,
            )

        output = stderr.getvalue()
        self.assertEqual(result.state, DnsQueryState.TRANSPORT_ERROR)
        self.assertIn(
            "DNS authoritative: example.com SOA via tcp 192.0.2.53 -> transport_error",
            output,
        )
        self.assertNotIn("secret-transport-detail", output)

    def test_single_verbose_level_does_not_emit_dns_trace_details(self):
        harness = _DnsEvidenceHarness(_FakeAnswer(["203.0.113.7"]))
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            configure_cli_logging(verbose=1)
            harness.dns_query_result("example.com", "A")

        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
