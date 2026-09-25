import unittest

from domain_security_scanner.domains.domain.delegation import (
    DelegatedNameserverEvidence,
    DelegationGlueEvidence,
    NameserverAddressEvidence,
    ParentDelegationEvidence,
)
from domain_security_scanner.domains.domain.delegation_analysis import (
    ADDRESS_NO_ADDRESS,
    ADDRESS_UNKNOWN,
    ALIAS_ALIAS,
    ALIAS_DIRECT,
    ALIAS_UNKNOWN,
    AUTHORITY_AUTHORITATIVE,
    AUTHORITY_LAME,
    AUTHORITY_MIXED,
    AUTHORITY_NO_ADDRESS,
    AUTHORITY_UNKNOWN,
    GLUE_MISSING,
    GLUE_NOT_REQUIRED,
    GLUE_PRESENT,
    analyze_delegation,
    analyze_nameserver,
    child_ns_from_result,
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
    answer_section=(),
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
        answer_section=tuple(answer_section),
    )


def _address_evidence(
    name,
    *,
    ipv4=(),
    ipv6=(),
    a_state=DnsQueryState.NO_ANSWER,
    aaaa_state=DnsQueryState.NO_ANSWER,
    cname_state=DnsQueryState.NO_ANSWER,
    cname_records=(),
):
    return NameserverAddressEvidence(
        name=name,
        ipv4=tuple(ipv4),
        ipv6=tuple(ipv6),
        a_result=_result(name, "A", a_state, tuple(ipv4)),
        aaaa_result=_result(name, "AAAA", aaaa_state, tuple(ipv6)),
        cname_result=_result(
            name,
            "CNAME",
            cname_state,
            tuple(cname_records),
        ),
    )


def _authority_result(
    server_name,
    server_ip,
    *,
    child_ns=(),
    state=DnsQueryState.ANSWER,
    aa=True,
):
    answer_section = ()
    if child_ns:
        answer_section = (
            "\n".join(
                f"example.com. 300 IN NS {name}."
                for name in child_ns
            ),
        )
    return _result(
        "example.com",
        "NS",
        state,
        tuple(f"{name}." for name in child_ns),
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name=server_name,
        server_ip=server_ip,
        rcode="NOERROR" if state != DnsQueryState.TIMEOUT else None,
        aa=aa if state != DnsQueryState.TIMEOUT else None,
        tc=False if state != DnsQueryState.TIMEOUT else None,
        answer_section=answer_section,
        error="timeout" if state == DnsQueryState.TIMEOUT else None,
    )


class DelegationAnalysisHelpersTest(unittest.TestCase):
    def test_child_ns_requires_positive_authoritative_answer(self):
        positive = _authority_result(
            "ns1.example.net",
            "192.0.2.10",
            child_ns=("ns1.example.net", "ns2.example.net"),
        )
        non_authoritative = _authority_result(
            "ns1.example.net",
            "192.0.2.10",
            child_ns=("ns1.example.net",),
            state=DnsQueryState.NOT_AUTHORITATIVE,
            aa=False,
        )

        self.assertEqual(
            child_ns_from_result(positive, "example.com"),
            ("ns1.example.net", "ns2.example.net"),
        )
        self.assertEqual(
            child_ns_from_result(non_authoritative, "example.com"),
            (),
        )

    def test_ns_alias_is_distinguished_from_direct_name_and_lookup_failure(self):
        alias_server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=_address_evidence(
                "ns1.example.net",
                ipv4=("192.0.2.10",),
                a_state=DnsQueryState.ANSWER,
                cname_state=DnsQueryState.ANSWER,
                cname_records=("alias.example.net.",),
            ),
            candidate_addresses=("192.0.2.10",),
        )
        direct_server = DelegatedNameserverEvidence(
            name="ns2.example.net",
            addresses=_address_evidence(
                "ns2.example.net",
                ipv4=("192.0.2.20",),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=("192.0.2.20",),
        )
        unknown_server = DelegatedNameserverEvidence(
            name="ns3.example.net",
            addresses=NameserverAddressEvidence(
                name="ns3.example.net",
                a_result=_result(
                    "ns3.example.net",
                    "A",
                    DnsQueryState.TIMEOUT,
                    error="timeout",
                ),
                aaaa_result=_result(
                    "ns3.example.net",
                    "AAAA",
                    DnsQueryState.TIMEOUT,
                    error="timeout",
                ),
                cname_result=_result(
                    "ns3.example.net",
                    "CNAME",
                    DnsQueryState.TIMEOUT,
                    error="timeout",
                ),
            ),
        )

        alias = analyze_nameserver(alias_server, "example.com")
        direct = analyze_nameserver(direct_server, "example.com")
        unknown = analyze_nameserver(unknown_server, "example.com")

        self.assertEqual(alias.alias_status, ALIAS_ALIAS)
        self.assertEqual(alias.alias_targets, ("alias.example.net",))
        self.assertEqual(direct.alias_status, ALIAS_DIRECT)
        self.assertEqual(unknown.alias_status, ALIAS_UNKNOWN)
        self.assertEqual(unknown.address_status, ADDRESS_UNKNOWN)

    def test_lame_response_is_distinct_from_timeout(self):
        lame_server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=_address_evidence(
                "ns1.example.net",
                ipv4=("192.0.2.10",),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=("192.0.2.10",),
            probe_addresses=("192.0.2.10",),
            authority_queries=(
                _authority_result(
                    "ns1.example.net",
                    "192.0.2.10",
                    state=DnsQueryState.NOT_AUTHORITATIVE,
                    aa=False,
                ),
            ),
        )
        timeout_server = DelegatedNameserverEvidence(
            name="ns2.example.net",
            addresses=_address_evidence(
                "ns2.example.net",
                ipv4=("192.0.2.20",),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=("192.0.2.20",),
            probe_addresses=("192.0.2.20",),
            authority_queries=(
                _authority_result(
                    "ns2.example.net",
                    "192.0.2.20",
                    state=DnsQueryState.TIMEOUT,
                ),
            ),
        )

        lame = analyze_nameserver(lame_server, "example.com")
        timeout = analyze_nameserver(timeout_server, "example.com")

        self.assertEqual(lame.authority_status, AUTHORITY_LAME)
        self.assertEqual(timeout.authority_status, AUTHORITY_UNKNOWN)

    def test_mixed_address_authority_is_not_collapsed_to_healthy(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=_address_evidence(
                "ns1.example.net",
                ipv4=("192.0.2.10", "192.0.2.11"),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=("192.0.2.10", "192.0.2.11"),
            probe_addresses=("192.0.2.10", "192.0.2.11"),
            authority_queries=(
                _authority_result(
                    "ns1.example.net",
                    "192.0.2.10",
                    child_ns=("ns1.example.net", "ns2.example.net"),
                ),
                _authority_result(
                    "ns1.example.net",
                    "192.0.2.11",
                    state=DnsQueryState.NOT_AUTHORITATIVE,
                    aa=False,
                ),
            ),
        )

        analysis = analyze_nameserver(server, "example.com")

        self.assertEqual(analysis.authority_status, AUTHORITY_MIXED)
        self.assertEqual(len(analysis.authoritative_child_views), 1)


class GlueAnalysisTest(unittest.TestCase):
    def test_in_bailiwick_glue_presence_and_consistency_are_observed(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.com",
            addresses=_address_evidence(
                "ns1.example.com",
                ipv4=("192.0.2.10",),
                a_state=DnsQueryState.ANSWER,
            ),
            glue=DelegationGlueEvidence(
                name="ns1.example.com",
                ipv4=("192.0.2.10",),
            ),
            candidate_addresses=("192.0.2.10",),
        )

        analysis = analyze_nameserver(server, "example.com")

        self.assertTrue(analysis.in_bailiwick)
        self.assertEqual(analysis.glue_status, GLUE_PRESENT)
        self.assertTrue(analysis.glue_consistent)
        self.assertEqual(analysis.glue_only_addresses, ())
        self.assertEqual(analysis.resolved_only_addresses, ())

    def test_missing_in_bailiwick_glue_is_explicit(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.com",
            addresses=_address_evidence(
                "ns1.example.com",
                ipv4=("192.0.2.10",),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=("192.0.2.10",),
        )

        analysis = analyze_nameserver(server, "example.com")

        self.assertEqual(analysis.glue_status, GLUE_MISSING)
        self.assertIsNone(analysis.glue_consistent)

    def test_glue_mismatch_is_descriptive_not_failure_scoring(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.com",
            addresses=_address_evidence(
                "ns1.example.com",
                ipv4=("192.0.2.20",),
                a_state=DnsQueryState.ANSWER,
            ),
            glue=DelegationGlueEvidence(
                name="ns1.example.com",
                ipv4=("192.0.2.10",),
            ),
            candidate_addresses=("192.0.2.10", "192.0.2.20"),
        )

        analysis = analyze_nameserver(server, "example.com")

        self.assertFalse(analysis.glue_consistent)
        self.assertEqual(analysis.glue_only_addresses, ("192.0.2.10",))
        self.assertEqual(analysis.resolved_only_addresses, ("192.0.2.20",))

    def test_out_of_bailiwick_glue_is_not_required(self):
        server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=_address_evidence(
                "ns1.example.net",
                ipv4=("192.0.2.10",),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=("192.0.2.10",),
        )

        analysis = analyze_nameserver(server, "example.com")

        self.assertFalse(analysis.in_bailiwick)
        self.assertEqual(analysis.glue_status, GLUE_NOT_REQUIRED)
        self.assertIsNone(analysis.glue_consistent)


class ParentChildConsistencyTest(unittest.TestCase):
    def _server(self, name, address, child_ns, *, state=DnsQueryState.ANSWER, aa=True):
        return DelegatedNameserverEvidence(
            name=name,
            addresses=_address_evidence(
                name,
                ipv4=(address,),
                a_state=DnsQueryState.ANSWER,
            ),
            candidate_addresses=(address,),
            probe_addresses=(address,),
            authority_queries=(
                _authority_result(
                    name,
                    address,
                    child_ns=child_ns,
                    state=state,
                    aa=aa,
                ),
            ),
        )

    def test_healthy_parent_child_sets_are_explicitly_consistent(self):
        child_ns = ("ns1.example.net", "ns2.example.net")
        evidence = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=child_ns,
            delegated_servers=(
                self._server("ns1.example.net", "192.0.2.10", child_ns),
                self._server("ns2.example.net", "192.0.2.20", child_ns),
            ),
        )

        analysis = analyze_delegation(evidence)

        self.assertTrue(analysis.parent_child_complete)
        self.assertTrue(analysis.parent_child_consistent)
        self.assertEqual(analysis.observed_child_nameservers, child_ns)
        self.assertEqual(analysis.missing_from_child, ())
        self.assertEqual(analysis.extra_in_child, ())
        self.assertTrue(
            all(
                server.authority_status == AUTHORITY_AUTHORITATIVE
                for server in analysis.nameservers
            )
        )

    def test_stale_parent_nameserver_is_positive_mismatch_evidence(self):
        evidence = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=(
                "ns1.example.net",
                "old.example.net",
            ),
            delegated_servers=(
                self._server(
                    "ns1.example.net",
                    "192.0.2.10",
                    ("ns1.example.net",),
                ),
                self._server(
                    "old.example.net",
                    "192.0.2.30",
                    ("ns1.example.net",),
                ),
            ),
        )

        analysis = analyze_delegation(evidence)

        self.assertFalse(analysis.parent_child_consistent)
        self.assertEqual(analysis.missing_from_child, ("old.example.net",))
        self.assertEqual(analysis.extra_in_child, ())

    def test_partial_equal_evidence_remains_unknown_not_consistent(self):
        parent_ns = ("ns1.example.net", "ns2.example.net")
        timeout_server = self._server(
            "ns2.example.net",
            "192.0.2.20",
            (),
            state=DnsQueryState.TIMEOUT,
            aa=False,
        )
        evidence = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=parent_ns,
            delegated_servers=(
                self._server(
                    "ns1.example.net",
                    "192.0.2.10",
                    parent_ns,
                ),
                timeout_server,
            ),
        )

        analysis = analyze_delegation(evidence)

        self.assertFalse(analysis.parent_child_complete)
        self.assertIsNone(analysis.parent_child_consistent)

    def test_confirmed_no_address_is_not_lame(self):
        no_address_server = DelegatedNameserverEvidence(
            name="ns1.example.net",
            addresses=_address_evidence("ns1.example.net"),
        )
        evidence = ParentDelegationEvidence(
            zone="example.com",
            parent_zone="com",
            delegated_nameservers=("ns1.example.net",),
            delegated_servers=(no_address_server,),
        )

        analysis = analyze_delegation(evidence)

        self.assertEqual(analysis.nameservers[0].address_status, ADDRESS_NO_ADDRESS)
        self.assertEqual(
            analysis.nameservers[0].authority_status,
            AUTHORITY_NO_ADDRESS,
        )
        self.assertIsNone(analysis.parent_child_consistent)


if __name__ == "__main__":
    unittest.main()
