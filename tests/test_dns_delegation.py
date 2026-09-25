import unittest

from domain_security_scanner.domains.domain.delegation import (
    MAX_PARENT_DELEGATION_ATTEMPTS,
    DelegationScanMixin,
    parent_zone_name,
    referral_from_result,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


def _result(
    host,
    rtype,
    state,
    records=(),
    *,
    error=None,
    query_mode=DnsQueryMode.RECURSIVE,
    transport=None,
    server_name=None,
    server_ip=None,
    rcode=None,
    aa=None,
    tc=None,
    authority_section=(),
    additional_section=(),
):
    return DnsQueryResult(
        host,
        rtype,
        state,
        tuple(records),
        error=error,
        query_mode=query_mode,
        transport=transport,
        server_name=server_name,
        server_ip=server_ip,
        rcode=rcode,
        aa=aa,
        tc=tc,
        authority_section=tuple(authority_section),
        additional_section=tuple(additional_section),
    )


class _Harness(DelegationScanMixin):
    def __init__(self, root_domain, recursive=None, direct=None):
        self.root_domain = root_domain
        self.recursive = recursive or {}
        self.direct = list(direct or ())
        self.recursive_calls = []
        self.direct_calls = []
        self.delegation = None

    def dns_query_result(self, host, rtype):
        key = (host.lower().rstrip("."), rtype.upper())
        self.recursive_calls.append(key)
        return self.recursive.get(
            key,
            _result(key[0], key[1], DnsQueryState.NO_ANSWER),
        )

    def authoritative_dns_query_result(
        self,
        host,
        rtype,
        *,
        server_ip,
        server_name=None,
        transport=DnsTransport.UDP,
        timeout=3.0,
    ):
        self.direct_calls.append(
            (
                host.lower().rstrip("."),
                rtype.upper(),
                server_name,
                server_ip,
                DnsTransport(transport),
            )
        )
        if self.direct:
            return self.direct.pop(0)
        return _result(
            host,
            rtype,
            DnsQueryState.TRANSPORT_ERROR,
            error="unreachable",
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport(transport),
            server_name=server_name,
            server_ip=server_ip,
        )

    @staticmethod
    def _dns_unavailable_message(result):
        return {
            DnsQueryState.TIMEOUT: "timeout",
            DnsQueryState.SERVFAIL: "SERVFAIL",
            DnsQueryState.TRANSPORT_ERROR: "transport error",
            DnsQueryState.ERROR: "resolver error",
        }.get(result.state, result.state.value)


class ParentDelegationHelpersTest(unittest.TestCase):
    def test_parent_zone_uses_immediate_dns_parent(self):
        self.assertEqual(parent_zone_name("example.com"), "com")
        self.assertEqual(parent_zone_name("example.co.uk"), "co.uk")
        self.assertEqual(parent_zone_name("Example.CO.UK."), "co.uk")
        self.assertIsNone(parent_zone_name("com"))

    def test_referral_extracts_parent_ns_and_glue_from_raw_sections(self):
        result = _result(
            "example.com",
            "NS",
            DnsQueryState.NOT_AUTHORITATIVE,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="a.gtld-servers.net",
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=False,
            tc=False,
            authority_section=(
                "example.com. 172800 IN NS ns2.example.net.\n"
                "example.com. 172800 IN NS ns1.example.net.",
            ),
            additional_section=(
                "ns1.example.net. 172800 IN A 192.0.2.10",
                "ns1.example.net. 172800 IN AAAA 2001:0db8::10",
                "unrelated.example.net. 172800 IN A 192.0.2.99",
            ),
        )

        referral = referral_from_result(result, "example.com")

        self.assertIsNotNone(referral)
        self.assertEqual(
            referral.nameservers,
            ("ns1.example.net", "ns2.example.net"),
        )
        self.assertEqual(len(referral.glue), 1)
        self.assertEqual(referral.glue[0].name, "ns1.example.net")
        self.assertEqual(referral.glue[0].ipv4, ("192.0.2.10",))
        self.assertEqual(referral.glue[0].ipv6, ("2001:db8::10",))

    def test_truncated_parent_response_is_not_accepted_as_delegation(self):
        result = _result(
            "example.com",
            "NS",
            DnsQueryState.TRUNCATED,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=False,
            tc=True,
            authority_section=(
                "example.com. 172800 IN NS ns1.example.net.",
            ),
        )

        self.assertIsNone(referral_from_result(result, "example.com"))


class ParentDelegationCollectionTest(unittest.TestCase):
    def test_collects_parent_referral_independently_from_child_apex_ns(self):
        referral_result = _result(
            "example.com",
            "NS",
            DnsQueryState.NOT_AUTHORITATIVE,
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="a.gtld-servers.net",
            server_ip="192.0.2.53",
            rcode="NOERROR",
            aa=False,
            tc=False,
            authority_section=(
                "example.com. 172800 IN NS ns1.example.net.\n"
                "example.com. 172800 IN NS ns2.example.net.",
            ),
            additional_section=(
                "ns1.example.net. 172800 IN A 192.0.2.10",
            ),
        )
        harness = _Harness(
            "example.com",
            recursive={
                ("com", "NS"): _result(
                    "com",
                    "NS",
                    DnsQueryState.ANSWER,
                    ("a.gtld-servers.net.", "b.gtld-servers.net."),
                ),
                ("a.gtld-servers.net", "A"): _result(
                    "a.gtld-servers.net",
                    "A",
                    DnsQueryState.ANSWER,
                    ("192.0.2.53",),
                ),
                ("a.gtld-servers.net", "AAAA"): _result(
                    "a.gtld-servers.net",
                    "AAAA",
                    DnsQueryState.NO_ANSWER,
                ),
            },
            direct=(referral_result,),
        )

        evidence = harness.collect_parent_delegation()

        self.assertTrue(evidence.available)
        self.assertEqual(evidence.zone, "example.com")
        self.assertEqual(evidence.parent_zone, "com")
        self.assertEqual(
            evidence.parent_nameservers,
            ("a.gtld-servers.net", "b.gtld-servers.net"),
        )
        self.assertEqual(
            evidence.delegated_nameservers,
            ("ns1.example.net", "ns2.example.net"),
        )
        self.assertEqual(evidence.source_server_name, "a.gtld-servers.net")
        self.assertEqual(evidence.source_server_ip, "192.0.2.53")
        self.assertEqual(len(evidence.delegation_queries), 1)
        self.assertNotIn(("example.com", "NS"), harness.recursive_calls)
        self.assertEqual(
            harness.direct_calls,
            [
                (
                    "example.com",
                    "NS",
                    "a.gtld-servers.net",
                    "192.0.2.53",
                    DnsTransport.UDP,
                )
            ],
        )
        self.assertIs(harness.delegation, evidence)

    def test_parent_ns_lookup_failure_stays_unavailable(self):
        harness = _Harness(
            "example.com",
            recursive={
                ("com", "NS"): _result(
                    "com",
                    "NS",
                    DnsQueryState.TIMEOUT,
                    error="timeout",
                )
            },
        )

        evidence = harness.collect_parent_delegation()

        self.assertFalse(evidence.available)
        self.assertEqual(evidence.error, "timeout")
        self.assertEqual(evidence.delegation_queries, ())
        self.assertEqual(harness.direct_calls, [])

    def test_parent_referral_attempts_are_bounded(self):
        parent_nameservers = tuple(
            f"p{i}.parent.example." for i in range(1, 7)
        )
        recursive = {
            ("com", "NS"): _result(
                "com",
                "NS",
                DnsQueryState.ANSWER,
                parent_nameservers,
            )
        }
        for i in range(1, 7):
            name = f"p{i}.parent.example"
            recursive[(name, "A")] = _result(
                name,
                "A",
                DnsQueryState.ANSWER,
                (f"192.0.2.{i}",),
            )
            recursive[(name, "AAAA")] = _result(
                name,
                "AAAA",
                DnsQueryState.NO_ANSWER,
            )

        harness = _Harness("example.com", recursive=recursive)

        evidence = harness.collect_parent_delegation()

        self.assertFalse(evidence.available)
        self.assertEqual(
            len(evidence.delegation_queries),
            MAX_PARENT_DELEGATION_ATTEMPTS,
        )
        self.assertEqual(
            len(harness.direct_calls),
            MAX_PARENT_DELEGATION_ATTEMPTS,
        )
        self.assertNotIn(("p5.parent.example", "A"), harness.recursive_calls)


class _ExistingDomainDnsStep:
    def collect_domain_dns(self):
        self.events.append("domain_dns")
        return "existing-domain-result"


class _ChainedDelegationHarness(DelegationScanMixin, _ExistingDomainDnsStep):
    def __init__(self):
        self.events = []

    def collect_parent_delegation(self):
        self.events.append("parent_delegation")


class DelegationCompositionTest(unittest.TestCase):
    def test_domain_dns_step_collects_parent_evidence_first(self):
        harness = _ChainedDelegationHarness()

        result = harness.collect_domain_dns()

        self.assertEqual(result, "existing-domain-result")
        self.assertEqual(harness.events, ["parent_delegation", "domain_dns"])


if __name__ == "__main__":
    unittest.main()
