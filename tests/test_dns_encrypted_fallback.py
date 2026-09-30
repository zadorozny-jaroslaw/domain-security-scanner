from __future__ import annotations

import unittest
from types import SimpleNamespace

import dns.flags
import dns.message
import dns.rdatatype
import dns.rrset

from domain_security_scanner.domains.domain.encrypted_dns import (
    ENCRYPTED_DNS_DISAGREEMENT,
    ENCRYPTED_DNS_USABLE,
    RRSET_CONSENSUS,
    collect_encrypted_dns_evidence,
    encrypted_dns_fallback_needed,
    encrypted_dns_finding,
    encrypted_dns_report_data,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)
from domain_security_scanner.reporting.dns_pdf import dns_posture_rows


class _HttpResponse:
    def __init__(self, content: bytes):
        self.content = content

    def raise_for_status(self):
        return None


class _FakeDohSession:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def post(self, url, *, data, headers, timeout):
        query = dns.message.from_wire(data)
        qtype = dns.rdatatype.to_text(query.question[0].rdtype)
        self.calls.append((url, qtype, headers, timeout))
        spec = self.answers[(url, qtype)]
        if isinstance(spec, BaseException):
            raise spec

        ttl, values = spec
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.answer.append(
            dns.rrset.from_text(
                query.question[0].name.to_text(),
                ttl,
                "IN",
                qtype,
                *values,
            )
        )
        return _HttpResponse(response.to_wire())


def _direct_soa_result(*, suspect: bool) -> DnsQueryResult:
    if suspect:
        return DnsQueryResult(
            "example.com",
            "SOA",
            DnsQueryState.ERROR,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.net",
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=True,
            rd=False,
            ra=True,
            answer_section=(),
            authority_section=(
                "example.com. 300 IN NS ns1.example.net.\n"
                "example.com. 300 IN NS ns2.example.net.",
            ),
        )
    return DnsQueryResult(
        "example.com",
        "SOA",
        DnsQueryState.ANSWER,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        rcode="NOERROR",
        aa=True,
        rd=False,
        ra=False,
        answer_section=(
            "example.com. 300 IN SOA ns1.example.net. hostmaster.example.com. "
            "42 3600 600 86400 300",
        ),
    )


def _authoritative_evidence(*, suspect: bool):
    result = _direct_soa_result(suspect=suspect)
    observation = SimpleNamespace(result=result)
    endpoint = SimpleNamespace(
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        udp_soa=observation,
        tcp_soa=observation,
    )
    server = SimpleNamespace(endpoints=(endpoint,))
    return SimpleNamespace(zone="example.com", servers=(server,))


def _answers(*, disagreement: bool = False, ttl_difference: bool = False):
    cloudflare = "https://cloudflare-dns.com/dns-query"
    google = "https://dns.google/dns-query"
    soa = "ns1.example.net. hostmaster.example.com. 42 3600 600 86400 300"
    ns = ("ns1.example.net.", "ns2.example.net.")
    google_ns = ("ns1.example.net.", "ns3.example.net.") if disagreement else ns
    return {
        (cloudflare, "SOA"): (300, (soa,)),
        (google, "SOA"): (120 if ttl_difference else 300, (soa,)),
        (cloudflare, "NS"): (300, ns),
        (google, "NS"): (120 if ttl_difference else 300, google_ns),
    }


class EncryptedDnsFallbackTest(unittest.TestCase):
    def test_fallback_triggers_only_when_direct_path_is_suspect(self):
        needed, status = encrypted_dns_fallback_needed(
            _authoritative_evidence(suspect=True)
        )
        self.assertTrue(needed)
        self.assertEqual(status, "suspected_interception")

        needed, status = encrypted_dns_fallback_needed(
            _authoritative_evidence(suspect=False)
        )
        self.assertFalse(needed)
        self.assertEqual(status, "usable")

    def test_two_doh_resolvers_reach_zone_level_consensus(self):
        scanner = SimpleNamespace(
            root_domain="example.com",
            session=_FakeDohSession(_answers()),
        )
        evidence = collect_encrypted_dns_evidence(
            scanner,
            _authoritative_evidence(suspect=True),
        )

        self.assertTrue(evidence.attempted)
        self.assertEqual(evidence.status, ENCRYPTED_DNS_USABLE)
        self.assertEqual(
            {item.qtype: item.status for item in evidence.rrsets},
            {"SOA": RRSET_CONSENSUS, "NS": RRSET_CONSENSUS},
        )
        self.assertEqual(len(scanner.session.calls), 4)

    def test_consensus_ignores_recursive_cache_ttl_differences(self):
        scanner = SimpleNamespace(
            root_domain="example.com",
            session=_FakeDohSession(_answers(ttl_difference=True)),
        )
        evidence = collect_encrypted_dns_evidence(
            scanner,
            _authoritative_evidence(suspect=True),
        )

        self.assertEqual(evidence.status, ENCRYPTED_DNS_USABLE)

    def test_resolver_rrset_disagreement_is_not_promoted(self):
        scanner = SimpleNamespace(
            root_domain="example.com",
            session=_FakeDohSession(_answers(disagreement=True)),
        )
        evidence = collect_encrypted_dns_evidence(
            scanner,
            _authoritative_evidence(suspect=True),
        )

        self.assertEqual(evidence.status, ENCRYPTED_DNS_DISAGREEMENT)
        by_type = {item.qtype: item for item in evidence.rrsets}
        self.assertEqual(by_type["NS"].status, "disagreement")
        self.assertEqual(by_type["NS"].rdata, ())

    def test_report_marks_fallback_as_zone_level_only(self):
        scanner = SimpleNamespace(
            root_domain="example.com",
            session=_FakeDohSession(_answers()),
        )
        evidence = collect_encrypted_dns_evidence(
            scanner,
            _authoritative_evidence(suspect=True),
        )
        report = encrypted_dns_report_data(evidence)

        self.assertEqual(report["status"], "usable")
        self.assertEqual(report["channel"], "doh")
        self.assertEqual(report["transport"], "https")
        self.assertTrue(report["scope"]["zone_level_only"])
        self.assertFalse(report["scope"]["per_authoritative_server_attribution"])
        self.assertEqual(report["rrsets"]["SOA"]["status"], "consensus")
        self.assertEqual(len(report["rrsets"]["SOA"]["observations"]), 2)

    def test_successful_fallback_finding_is_non_scoring(self):
        scanner = SimpleNamespace(
            root_domain="example.com",
            session=_FakeDohSession(_answers()),
        )
        evidence = collect_encrypted_dns_evidence(
            scanner,
            _authoritative_evidence(suspect=True),
        )
        finding = encrypted_dns_finding(evidence)

        self.assertIsNotNone(finding)
        self.assertEqual(finding[1], "pass")
        self.assertEqual(finding[3:5], (0, 0))

    def test_pdf_summary_surfaces_encrypted_consensus_without_hiding_verify(self):
        report = {
            "root_domain": "example.com",
            "target_domain": "example.com",
            "rdap": {},
            "dns_records": {},
            "dns": {
                "dnssec": {"status": "unknown"},
                "delegation": {"available": True, "consistent": None, "complete": False},
                "soa": {"ns_rrset_consistent": None},
                "open_recursion": {"status": "unknown", "open_servers": []},
                "caa": {"analysis": {"state": "effective"}, "effective_name": "example.com"},
                "encrypted_recursive": {"status": "usable", "attempted": True},
            },
        }

        rows = dns_posture_rows(report)

        self.assertEqual(rows[1]["status"], "unknown")
        self.assertIn("Encrypted DNS: OK", rows[1]["value"])
        self.assertIn("VERIFY items are excluded", rows[1]["value"])


if __name__ == "__main__":
    unittest.main()
