import unittest

from domain_security_scanner.domains.domain.delegation import (
    DELEGATION_DIRECT_TIMEOUT,
    MAX_DELEGATED_ADDRESS_PROBES_PER_NS,
    MAX_DELEGATED_AUTHORITY_PROBES,
    MAX_PARENT_DELEGATION_ATTEMPTS,
    DelegationGlueEvidence,
    DelegationScanMixin,
    ParentDelegationEvidence,
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
    def __init__(
        self,
        root_domain,
        recursive=None,
        direct=None,
        direct_map=None,
    ):
        self.root_domain = root_domain
        self.recursive = recursive or {}
        self.direct = list(direct or ())
        self.direct_map = direct_map or {}
        self.recursive_calls = []
        self.direct_calls = []
        self.direct_timeouts = []
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
        key = (
            host.lower().rstrip("."),
            rtype.upper(),
            server_name,
            server_ip,
            DnsTransport(transport),
        )
        self.direct_calls.append(key)
        self.direct_timeouts.append(timeout)
        if key in self.direct_map:
            return self.direct_map[key]
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
        self.assertEqual(harness.direct_timeouts, [DELEGATION_DIRECT_TIMEOUT])
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


class DelegatedNameserverCollectionTest(unittest.TestCase):
    @staticmethod
    def _base_evidence(*, glue=()):
        return ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=("ns1.example.net", "ns2.example.net"),
            glue=tuple(glue),
            source_server_name="a.gtld-servers.net",
            source_server_ip="192.0.2.53",
        )

    def test_collects_a_aaaa_and_direct_authority_per_delegated_ns(self):
        evidence = self._base_evidence()
        recursive = {
            ("ns1.example.net", "A"): _result(
                "ns1.example.net", "A", DnsQueryState.ANSWER,
                ("192.0.2.10",),
            ),
            ("ns1.example.net", "AAAA"): _result(
                "ns1.example.net", "AAAA", DnsQueryState.ANSWER,
                ("2001:db8::10",),
            ),
            ("ns2.example.net", "A"): _result(
                "ns2.example.net", "A", DnsQueryState.ANSWER,
                ("192.0.2.20",),
            ),
            ("ns2.example.net", "AAAA"): _result(
                "ns2.example.net", "AAAA", DnsQueryState.NO_ANSWER,
            ),
        }
        direct_map = {}
        for name, address in (
            ("ns1.example.net", "192.0.2.10"),
            ("ns1.example.net", "2001:db8::10"),
            ("ns2.example.net", "192.0.2.20"),
        ):
            key = (
                "example.com", "NS", name, address, DnsTransport.UDP
            )
            direct_map[key] = _result(
                "example.com",
                "NS",
                DnsQueryState.ANSWER,
                ("ns1.example.net.", "ns2.example.net."),
                query_mode=DnsQueryMode.AUTHORITATIVE,
                transport=DnsTransport.UDP,
                server_name=name,
                server_ip=address,
                rcode="NOERROR",
                aa=True,
                tc=False,
            )

        harness = _Harness(
            "example.com",
            recursive=recursive,
            direct_map=direct_map,
        )
        enriched = harness.collect_delegated_nameserver_evidence(evidence)

        self.assertEqual(len(enriched.delegated_servers), 2)
        first, second = enriched.delegated_servers

        self.assertEqual(first.name, "ns1.example.net")
        self.assertEqual(first.addresses.ipv4, ("192.0.2.10",))
        self.assertEqual(first.addresses.ipv6, ("2001:db8::10",))
        self.assertEqual(
            first.candidate_addresses,
            ("192.0.2.10", "2001:db8::10"),
        )
        self.assertEqual(first.probe_addresses, ("192.0.2.10",))
        self.assertEqual(first.unprobed_addresses, ("2001:db8::10",))
        self.assertEqual(len(first.authority_queries), 1)
        self.assertTrue(first.has_authoritative_answer)

        self.assertEqual(second.addresses.ipv4, ("192.0.2.20",))
        self.assertEqual(second.addresses.ipv6, ())
        self.assertEqual(second.probe_addresses, ("192.0.2.20",))
        self.assertEqual(len(second.authority_queries), 1)
        self.assertTrue(second.has_authoritative_answer)
        self.assertEqual(harness.direct_timeouts, [DELEGATION_DIRECT_TIMEOUT] * 2)

        self.assertEqual(
            harness.recursive_calls,
            [
                ("ns1.example.net", "A"),
                ("ns1.example.net", "AAAA"),
                ("ns1.example.net", "CNAME"),
                ("ns2.example.net", "A"),
                ("ns2.example.net", "AAAA"),
                ("ns2.example.net", "CNAME"),
            ],
        )
        self.assertIs(harness.delegation, enriched)

    def test_glue_can_supply_endpoint_when_recursive_lookup_is_unavailable(self):
        glue = DelegationGlueEvidence(
            name="ns1.example.net",
            ipv4=("192.0.2.10",),
        )
        evidence = self._base_evidence(glue=(glue,))
        recursive = {
            ("ns1.example.net", "A"): _result(
                "ns1.example.net",
                "A",
                DnsQueryState.TIMEOUT,
                error="timeout",
            ),
            ("ns1.example.net", "AAAA"): _result(
                "ns1.example.net",
                "AAAA",
                DnsQueryState.TIMEOUT,
                error="timeout",
            ),
            ("ns2.example.net", "A"): _result(
                "ns2.example.net", "A", DnsQueryState.NO_ANSWER,
            ),
            ("ns2.example.net", "AAAA"): _result(
                "ns2.example.net", "AAAA", DnsQueryState.NO_ANSWER,
            ),
        }
        authority = _result(
            "example.com",
            "NS",
            DnsQueryState.ANSWER,
            ("ns1.example.net.", "ns2.example.net."),
            query_mode=DnsQueryMode.AUTHORITATIVE,
            transport=DnsTransport.UDP,
            server_name="ns1.example.net",
            server_ip="192.0.2.10",
            rcode="NOERROR",
            aa=True,
            tc=False,
        )
        harness = _Harness(
            "example.com",
            recursive=recursive,
            direct_map={
                (
                    "example.com",
                    "NS",
                    "ns1.example.net",
                    "192.0.2.10",
                    DnsTransport.UDP,
                ): authority
            },
        )

        enriched = harness.collect_delegated_nameserver_evidence(evidence)
        first, second = enriched.delegated_servers

        self.assertTrue(first.addresses.lookup_failed)
        self.assertFalse(first.addresses.conclusively_no_address)
        self.assertEqual(first.addresses.addresses, ())
        self.assertEqual(first.candidate_addresses, ("192.0.2.10",))
        self.assertEqual(first.probe_addresses, ("192.0.2.10",))
        self.assertTrue(first.has_authoritative_answer)

        self.assertFalse(second.addresses.lookup_failed)
        self.assertTrue(second.addresses.conclusively_no_address)
        self.assertFalse(second.has_usable_address)
        self.assertEqual(second.authority_queries, ())

    def test_non_authoritative_and_timeout_results_remain_distinct(self):
        evidence = self._base_evidence()
        recursive = {
            ("ns1.example.net", "A"): _result(
                "ns1.example.net", "A", DnsQueryState.ANSWER,
                ("192.0.2.10",),
            ),
            ("ns1.example.net", "AAAA"): _result(
                "ns1.example.net", "AAAA", DnsQueryState.NO_ANSWER,
            ),
            ("ns2.example.net", "A"): _result(
                "ns2.example.net", "A", DnsQueryState.ANSWER,
                ("192.0.2.20",),
            ),
            ("ns2.example.net", "AAAA"): _result(
                "ns2.example.net", "AAAA", DnsQueryState.NO_ANSWER,
            ),
        }
        harness = _Harness(
            "example.com",
            recursive=recursive,
            direct_map={
                (
                    "example.com",
                    "NS",
                    "ns1.example.net",
                    "192.0.2.10",
                    DnsTransport.UDP,
                ): _result(
                    "example.com",
                    "NS",
                    DnsQueryState.NOT_AUTHORITATIVE,
                    error="DNS response was not authoritative (AA=0)",
                    query_mode=DnsQueryMode.AUTHORITATIVE,
                    transport=DnsTransport.UDP,
                    server_name="ns1.example.net",
                    server_ip="192.0.2.10",
                    rcode="NOERROR",
                    aa=False,
                    tc=False,
                ),
                (
                    "example.com",
                    "NS",
                    "ns2.example.net",
                    "192.0.2.20",
                    DnsTransport.UDP,
                ): _result(
                    "example.com",
                    "NS",
                    DnsQueryState.TIMEOUT,
                    error="timeout",
                    query_mode=DnsQueryMode.AUTHORITATIVE,
                    transport=DnsTransport.UDP,
                    server_name="ns2.example.net",
                    server_ip="192.0.2.20",
                ),
            },
        )

        enriched = harness.collect_delegated_nameserver_evidence(evidence)

        self.assertEqual(
            enriched.delegated_servers[0].authority_queries[0].state,
            DnsQueryState.NOT_AUTHORITATIVE,
        )
        self.assertEqual(
            enriched.delegated_servers[1].authority_queries[0].state,
            DnsQueryState.TIMEOUT,
        )
        self.assertFalse(
            enriched.delegated_servers[0].has_authoritative_answer
        )
        self.assertFalse(
            enriched.delegated_servers[1].has_authoritative_answer
        )

    def test_failed_first_probe_uses_one_bounded_fallback(self):
        evidence = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=("ns1.example.net",),
            source_server_name="a.gtld-servers.net",
            source_server_ip="192.0.2.53",
        )
        recursive = {
            ("ns1.example.net", "A"): _result(
                "ns1.example.net",
                "A",
                DnsQueryState.ANSWER,
                ("192.0.2.10", "192.0.2.11", "192.0.2.12"),
            ),
            ("ns1.example.net", "AAAA"): _result(
                "ns1.example.net", "AAAA", DnsQueryState.NO_ANSWER,
            ),
        }
        harness = _Harness(
            "example.com",
            recursive=recursive,
            direct_map={
                (
                    "example.com", "NS", "ns1.example.net", "192.0.2.10",
                    DnsTransport.UDP,
                ): _result(
                    "example.com", "NS", DnsQueryState.TIMEOUT,
                    error="timeout",
                    query_mode=DnsQueryMode.AUTHORITATIVE,
                    transport=DnsTransport.UDP,
                    server_name="ns1.example.net",
                    server_ip="192.0.2.10",
                ),
                (
                    "example.com", "NS", "ns1.example.net", "192.0.2.11",
                    DnsTransport.UDP,
                ): _result(
                    "example.com", "NS", DnsQueryState.ANSWER,
                    ("ns1.example.net.",),
                    query_mode=DnsQueryMode.AUTHORITATIVE,
                    transport=DnsTransport.UDP,
                    server_name="ns1.example.net",
                    server_ip="192.0.2.11",
                    rcode="NOERROR",
                    aa=True,
                    tc=False,
                ),
            },
        )

        enriched = harness.collect_delegated_nameserver_evidence(evidence)
        server = enriched.delegated_servers[0]

        self.assertEqual(
            server.probe_addresses,
            ("192.0.2.10", "192.0.2.11"),
        )
        self.assertEqual(server.unprobed_addresses, ("192.0.2.12",))
        self.assertEqual(len(server.authority_queries), 2)
        self.assertTrue(server.has_authoritative_answer)
        self.assertEqual(
            harness.direct_timeouts,
            [DELEGATION_DIRECT_TIMEOUT, DELEGATION_DIRECT_TIMEOUT],
        )

    def test_authority_probes_are_adaptive_globally_bounded_and_breadth_first(self):
        nameservers = tuple(
            f"ns{i}.example.net" for i in range(1, 11)
        )
        evidence = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=nameservers,
            source_server_name="a.gtld-servers.net",
            source_server_ip="192.0.2.53",
        )
        recursive = {}
        for index, name in enumerate(nameservers, start=1):
            recursive[(name, "A")] = _result(
                name,
                "A",
                DnsQueryState.ANSWER,
                (f"192.0.{index}.1", f"192.0.{index}.2"),
            )
            recursive[(name, "AAAA")] = _result(
                name,
                "AAAA",
                DnsQueryState.NO_ANSWER,
            )

        harness = _Harness("example.com", recursive=recursive)
        enriched = harness.collect_delegated_nameserver_evidence(evidence)

        total = sum(
            len(server.authority_queries)
            for server in enriched.delegated_servers
        )
        self.assertEqual(total, MAX_DELEGATED_AUTHORITY_PROBES)
        self.assertEqual(len(harness.direct_calls), MAX_DELEGATED_AUTHORITY_PROBES)
        self.assertTrue(
            all(
                len(server.probe_addresses) <= MAX_DELEGATED_ADDRESS_PROBES_PER_NS
                for server in enriched.delegated_servers
            )
        )
        # First round covers every delegated NS before any fallback probe.
        self.assertTrue(
            all(server.probe_addresses for server in enriched.delegated_servers)
        )
        self.assertEqual(
            [len(server.probe_addresses) for server in enriched.delegated_servers],
            [2, 2, 2, 2, 2, 2, 1, 1, 1, 1],
        )



class _ExistingDomainDnsStep:
    def collect_domain_dns(self):
        self.events.append("domain_dns")
        return "existing-domain-result"


class _ChainedDelegationHarness(DelegationScanMixin, _ExistingDomainDnsStep):
    def __init__(self):
        self.events = []

    def collect_parent_delegation(self):
        self.events.append("parent_delegation")
        return ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
        )

    def collect_delegated_nameserver_evidence(self, evidence):
        self.events.append("delegated_nameservers")
        return evidence

    def analyze_delegation_evidence(self, evidence):
        self.events.append("delegation_analysis")
        return None


class DelegationCompositionTest(unittest.TestCase):
    def test_domain_dns_step_collects_delegation_evidence_first(self):
        harness = _ChainedDelegationHarness()

        result = harness.collect_domain_dns()

        self.assertEqual(result, "existing-domain-result")
        self.assertEqual(
            harness.events,
            [
                "parent_delegation",
                "delegated_nameservers",
                "delegation_analysis",
                "domain_dns",
            ],
        )


if __name__ == "__main__":
    unittest.main()
