from __future__ import annotations

import unittest
from unittest.mock import patch

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

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


def _response(
    qname: str,
    qtype: str,
    *,
    rcode: int = dns.rcode.NOERROR,
    aa: bool = True,
    tc: bool = False,
    answer=(),
    authority=(),
    additional=(),
    use_edns: bool = True,
):
    query = dns.message.make_query(qname, qtype, use_edns=0)
    response = dns.message.make_response(query)

    if aa:
        response.flags |= dns.flags.AA
    else:
        response.flags &= ~dns.flags.AA

    if tc:
        response.flags |= dns.flags.TC

    response.set_rcode(rcode)

    for rrset in answer:
        response.answer.append(rrset)
    for rrset in authority:
        response.authority.append(rrset)
    for rrset in additional:
        response.additional.append(rrset)

    if not use_edns:
        response.use_edns(edns=-1)

    return response


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
        self.assertEqual(result.query_mode, DnsQueryMode.RECURSIVE)
        self.assertIsNone(result.rcode)
        self.assertIsNone(result.aa)
        self.assertIsNone(result.tc)

    def test_recursive_cache_key_is_normalized_and_context_complete(self):
        harness = _DnsEvidenceHarness()
        key = harness._recursive_dns_cache_key("Example.COM.", "mx")
        self.assertIsInstance(key, DnsQueryCacheKey)
        self.assertEqual(key.qname, "example.com")
        self.assertEqual(key.qtype, "MX")
        self.assertEqual(key.mode, DnsQueryMode.RECURSIVE)

    def test_cache_keys_separate_mode_transport_and_authoritative_server(self):
        harness = _DnsEvidenceHarness()
        recursive = harness._dns_cache_key(
            "example.com", "SOA", mode=DnsQueryMode.RECURSIVE
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
        self.assertEqual(len({recursive, auth_udp_a, auth_tcp_a, auth_udp_b}), 4)

    def test_authoritative_ipv6_cache_key_is_canonical(self):
        harness = _DnsEvidenceHarness()
        a = harness._authoritative_dns_cache_key(
            "example.com",
            "SOA",
            server_ip="2001:0db8:0:0:0:0:0:53",
        )
        b = harness._authoritative_dns_cache_key(
            "example.com",
            "SOA",
            server_ip="2001:db8::53",
        )
        self.assertEqual(a, b)
        self.assertEqual(a.server_ip, "2001:db8::53")

    def test_authoritative_server_target_must_be_literal_ip(self):
        harness = _DnsEvidenceHarness()
        with self.assertRaises(ValueError):
            harness._authoritative_dns_cache_key(
                "example.com",
                "SOA",
                server_ip="ns1.example.net",
            )

    def test_shared_recursive_query_preserves_records_and_cache_behavior(self):
        harness = _DnsEvidenceHarness()
        harness.resolver = _FakeResolver({
            ("example.com", "MX"): _FakeAnswer(["10 mail.example.com."])
        })
        first = harness.dns_query_result("Example.COM.", "mx")
        second = harness.dns_query("example.com", "MX")
        self.assertEqual(first.state, DnsQueryState.ANSWER)
        self.assertEqual(second, ["10 mail.example.com."])
        self.assertEqual(harness.resolver.calls, [("example.com", "MX")])

    def test_shared_recursive_no_answer_remains_conclusive_absence(self):
        harness = _DnsEvidenceHarness()
        result = harness.dns_query_result("example.com", "CAA")
        self.assertEqual(result.state, DnsQueryState.NO_ANSWER)
        self.assertTrue(result.absent)
        self.assertFalse(result.failed)

    def test_shared_recursive_timeout_remains_failure_not_absence(self):
        harness = _DnsEvidenceHarness()
        harness.resolver = _FakeResolver({
            ("example.com", "TXT"): dns.exception.Timeout(timeout=1)
        })
        result = harness.dns_query_result("example.com", "TXT")
        self.assertEqual(result.state, DnsQueryState.TIMEOUT)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)


class AuthoritativeDnsQueryTest(unittest.TestCase):
    def test_udp_query_captures_server_flags_sections_and_cache(self):
        harness = _DnsEvidenceHarness()
        answer = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "SOA",
            "ns1.example.net. hostmaster.example.com. 1 3600 600 86400 300",
        )
        authority = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "NS",
            "ns1.example.net.",
            "ns2.example.net.",
        )
        additional = dns.rrset.from_text(
            "ns1.example.net.",
            300,
            "IN",
            "A",
            "192.0.2.53",
        )
        response = _response(
            "example.com",
            "SOA",
            answer=(answer,),
            authority=(authority,),
            additional=(additional,),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ) as udp:
            first = harness.authoritative_dns_query_result(
                "Example.COM.",
                "soa",
                server_name="NS1.Example.NET.",
                server_ip="192.0.2.53",
                transport="udp",
            )
            second = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
                transport=DnsTransport.UDP,
            )

        self.assertIs(first, second)
        self.assertEqual(udp.call_count, 1)
        self.assertEqual(first.state, DnsQueryState.ANSWER)
        self.assertEqual(first.rcode, "NOERROR")
        self.assertTrue(first.aa)
        self.assertFalse(first.tc)
        self.assertEqual(len(first.answer_section), 1)
        self.assertEqual(len(first.authority_section), 1)
        self.assertEqual(len(first.additional_section), 1)

        sent_query = udp.call_args.args[0]
        self.assertFalse(bool(sent_query.flags & dns.flags.RD))

    def test_conclusive_no_answer_requires_soa_negative_evidence(self):
        harness = _DnsEvidenceHarness()
        soa = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "SOA",
            "ns1.example.net. hostmaster.example.com. 1 3600 600 86400 300",
        )
        response = _response(
            "example.com",
            "CAA",
            answer=(),
            authority=(soa,),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ):
            result = harness.authoritative_dns_query_result(
                "example.com",
                "CAA",
                server_ip="192.0.2.53",
            )

        self.assertEqual(result.state, DnsQueryState.NO_ANSWER)
        self.assertTrue(result.absent)
        self.assertFalse(result.failed)
        self.assertFalse(result.tc)

    def test_authoritative_empty_answer_without_soa_is_inconclusive(self):
        harness = _DnsEvidenceHarness()
        ns = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "NS",
            "ns1.example.net.",
            "ns2.example.net.",
        )
        response = _response(
            "example.com",
            "SOA",
            aa=True,
            answer=(),
            authority=(ns,),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.tcp",
            return_value=response,
        ):
            result = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_ip="192.0.2.53",
                transport=DnsTransport.TCP,
            )

        self.assertEqual(result.state, DnsQueryState.ERROR)
        self.assertTrue(result.aa)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(
            result.error,
            "Authoritative negative response did not include SOA evidence",
        )

    def test_authoritative_nxdomain_without_soa_is_inconclusive(self):
        harness = _DnsEvidenceHarness()
        response = _response(
            "missing.example.com",
            "A",
            rcode=dns.rcode.NXDOMAIN,
            aa=True,
            answer=(),
            authority=(),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ):
            result = harness.authoritative_dns_query_result(
                "missing.example.com",
                "A",
                server_ip="192.0.2.53",
            )

        self.assertEqual(result.state, DnsQueryState.ERROR)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(result.rcode, "NXDOMAIN")

    def test_non_authoritative_noerror_is_inconclusive_not_absence(self):
        harness = _DnsEvidenceHarness()
        response = _response(
            "example.com",
            "SOA",
            aa=False,
            answer=(),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ):
            result = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
            )

        self.assertEqual(result.state, DnsQueryState.NOT_AUTHORITATIVE)
        self.assertFalse(result.aa)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(
            result.error,
            "DNS response was not authoritative (AA=0)",
        )
        self.assertEqual(
            harness._dns_unavailable_message(result),
            "non-authoritative response",
        )

    def test_non_authoritative_nxdomain_is_not_conclusive_absence(self):
        harness = _DnsEvidenceHarness()
        response = _response(
            "missing.example.com",
            "A",
            rcode=dns.rcode.NXDOMAIN,
            aa=False,
            answer=(),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ):
            result = harness.authoritative_dns_query_result(
                "missing.example.com",
                "A",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
            )

        self.assertEqual(result.state, DnsQueryState.NOT_AUTHORITATIVE)
        self.assertFalse(result.aa)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertEqual(result.rcode, "NXDOMAIN")

    def test_udp_truncation_is_inconclusive_and_not_absence(self):
        harness = _DnsEvidenceHarness()
        response = _response(
            "example.com",
            "DNSKEY",
            tc=True,
            answer=(),
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            return_value=response,
        ) as udp, patch(
            "domain_security_scanner.dns_evidence.dns.query.tcp",
        ) as tcp:
            result = harness.authoritative_dns_query_result(
                "example.com",
                "DNSKEY",
                server_ip="192.0.2.53",
                transport=DnsTransport.UDP,
            )

        self.assertEqual(udp.call_count, 1)
        tcp.assert_not_called()
        self.assertTrue(result.tc)
        self.assertEqual(result.state, DnsQueryState.TRUNCATED)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)
        self.assertIn("retry explicitly over TCP", result.error)
        self.assertEqual(
            harness._dns_unavailable_message(result),
            "truncated response",
        )

    def test_explicit_tcp_query_uses_tcp_transport(self):
        harness = _DnsEvidenceHarness()
        answer = dns.rrset.from_text(
            "example.com.", 300, "IN", "NS", "ns1.example.net."
        )
        response = _response("example.com", "NS", answer=(answer,))

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.tcp",
            return_value=response,
        ) as tcp, patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
        ) as udp:
            result = harness.authoritative_dns_query_result(
                "example.com",
                "NS",
                server_ip="192.0.2.53",
                transport=DnsTransport.TCP,
            )

        self.assertEqual(tcp.call_count, 1)
        udp.assert_not_called()
        self.assertEqual(result.transport, DnsTransport.TCP)
        self.assertEqual(result.state, DnsQueryState.ANSWER)

    def test_nxdomain_and_servfail_remain_distinct_states(self):
        harness = _DnsEvidenceHarness()
        soa = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "SOA",
            "ns1.example.net. hostmaster.example.com. 1 3600 600 86400 300",
        )
        nx = _response(
            "missing.example.com",
            "A",
            rcode=dns.rcode.NXDOMAIN,
            answer=(),
            authority=(soa,),
        )
        sf = _response(
            "example.com", "SOA", rcode=dns.rcode.SERVFAIL, answer=()
        )

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            side_effect=[nx, sf],
        ):
            nx_result = harness.authoritative_dns_query_result(
                "missing.example.com", "A", server_ip="192.0.2.53"
            )
            sf_result = harness.authoritative_dns_query_result(
                "example.com", "SOA", server_ip="192.0.2.54"
            )

        self.assertEqual(nx_result.state, DnsQueryState.NXDOMAIN)
        self.assertTrue(nx_result.absent)
        self.assertEqual(sf_result.state, DnsQueryState.SERVFAIL)
        self.assertTrue(sf_result.failed)
        self.assertFalse(sf_result.absent)

    def test_timeout_on_one_server_does_not_poison_another_server_cache(self):
        harness = _DnsEvidenceHarness()
        answer = dns.rrset.from_text(
            "example.com.",
            300,
            "IN",
            "SOA",
            "ns2.example.net. hostmaster.example.com. 1 3600 600 86400 300",
        )
        good_response = _response("example.com", "SOA", answer=(answer,))

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp",
            side_effect=[dns.exception.Timeout(timeout=1), good_response],
        ):
            failed = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_name="ns1.example.net",
                server_ip="192.0.2.53",
            )
            good = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_name="ns2.example.net",
                server_ip="192.0.2.54",
            )

        self.assertEqual(failed.state, DnsQueryState.TIMEOUT)
        self.assertTrue(failed.failed)
        self.assertFalse(failed.absent)
        self.assertEqual(good.state, DnsQueryState.ANSWER)

    def test_transport_failure_is_not_record_absence(self):
        harness = _DnsEvidenceHarness()

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.tcp",
            side_effect=ConnectionRefusedError("connection refused"),
        ):
            result = harness.authoritative_dns_query_result(
                "example.com",
                "SOA",
                server_ip="192.0.2.53",
                transport=DnsTransport.TCP,
            )

        self.assertEqual(result.state, DnsQueryState.TRANSPORT_ERROR)
        self.assertTrue(result.failed)
        self.assertFalse(result.absent)

    def test_invalid_server_name_is_rejected_before_network_io(self):
        harness = _DnsEvidenceHarness()

        with patch(
            "domain_security_scanner.dns_evidence.dns.query.udp"
        ) as udp:
            with self.assertRaises(ValueError):
                harness.authoritative_dns_query_result(
                    "example.com",
                    "SOA",
                    server_ip="ns1.example.net",
                )

        udp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
