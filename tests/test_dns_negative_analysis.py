from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.negative_dns import (
    NegativeDnsEvidence,
    NegativeDnsServerEvidence,
)
from domain_security_scanner.domains.domain.negative_dns_analysis import (
    NegativeDnsState,
    NegativeProbeOutcome,
    RecursionState,
    analyze_negative_dns,
    analyze_negative_probe,
    analyze_recursion_result,
)
from domain_security_scanner.models import DnsQueryResult, DnsQueryState


def _soa_authority(zone: str = "target.test") -> tuple[str, ...]:
    return (
        f"{zone}. 300 IN SOA ns1.{zone}. hostmaster.{zone}. 1 3600 600 86400 300",
    )


def _negative_result(name: str, state: DnsQueryState) -> DnsQueryResult:
    return DnsQueryResult(
        name,
        "A",
        state,
        rcode="NXDOMAIN" if state == DnsQueryState.NXDOMAIN else "NOERROR",
        aa=True,
        authority_section=_soa_authority(),
    )


def _positive_result(name: str, address: str) -> DnsQueryResult:
    return DnsQueryResult(
        name,
        "A",
        DnsQueryState.ANSWER,
        (address,),
        rcode="NOERROR",
        aa=True,
        answer_section=(f"{name}. 300 IN A {address}",),
    )


def _recursion_result(
    *,
    state: DnsQueryState = DnsQueryState.ANSWER,
    rcode: str | None = "NOERROR",
    ra: bool | None = True,
    aa: bool | None = False,
) -> DnsQueryResult:
    records = ("192.0.2.10",) if state == DnsQueryState.ANSWER else ()
    return DnsQueryResult(
        "example.com",
        "A",
        state,
        records,
        rcode=rcode,
        aa=aa,
        rd=True,
        ra=ra,
        request_recursion_desired=True,
    )


def _evidence(
    *servers: NegativeDnsServerEvidence,
) -> NegativeDnsEvidence:
    return NegativeDnsEvidence(
        zone="target.test",
        negative_names=(
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        ),
        recursion_probe_name="example.com",
        servers=tuple(servers),
    )


class NegativeDnsAnalysisTests(unittest.TestCase):
    def test_probe_distinguishes_nxdomain_and_retains_soa(self):
        result = _negative_result(
            "dssnx0-fixed.target.test",
            DnsQueryState.NXDOMAIN,
        )
        analysis = analyze_negative_probe(result)

        self.assertEqual(analysis.outcome, NegativeProbeOutcome.NXDOMAIN)
        self.assertEqual(analysis.rcode, "NXDOMAIN")
        self.assertTrue(analysis.authoritative)
        self.assertEqual(len(analysis.soa_records), 1)
        self.assertIn(" SOA ", analysis.soa_records[0])

    def test_zone_classifies_consistent_nxdomain(self):
        names = (
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        )
        evidence = _evidence(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                tuple(_negative_result(name, DnsQueryState.NXDOMAIN) for name in names),
                _recursion_result(state=DnsQueryState.ERROR, rcode="REFUSED", ra=False),
            ),
            NegativeDnsServerEvidence(
                "ns2.target.test",
                "192.0.2.54",
                tuple(_negative_result(name, DnsQueryState.NXDOMAIN) for name in names),
                _recursion_result(state=DnsQueryState.ERROR, rcode="REFUSED", ra=False),
            ),
        )

        analysis = analyze_negative_dns(evidence)

        self.assertEqual(analysis.negative_state, NegativeDnsState.NXDOMAIN)
        self.assertTrue(analysis.negative_complete)
        self.assertEqual(analysis.wildcard_servers, ())
        self.assertEqual(analysis.recursion_state, RecursionState.CLOSED)

    def test_zone_distinguishes_consistent_nodata(self):
        names = (
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        )
        evidence = _evidence(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                tuple(_negative_result(name, DnsQueryState.NO_ANSWER) for name in names),
                None,
            ),
        )

        analysis = analyze_negative_dns(evidence)

        self.assertEqual(analysis.negative_state, NegativeDnsState.NODATA)
        self.assertTrue(analysis.negative_complete)

    def test_two_positive_random_names_are_likely_wildcard_even_when_answers_differ(self):
        names = (
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        )
        evidence = _evidence(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                (
                    _positive_result(names[0], "192.0.2.10"),
                    _positive_result(names[1], "192.0.2.11"),
                ),
                None,
            ),
        )

        analysis = analyze_negative_dns(evidence)

        self.assertEqual(analysis.negative_state, NegativeDnsState.WILDCARD)
        self.assertEqual(analysis.wildcard_servers, ("ns1.target.test",))
        self.assertFalse(analysis.servers[0].wildcard_answer_sets_equal)

    def test_mixed_or_unavailable_negative_evidence_remains_unknown(self):
        names = (
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        )
        timeout = DnsQueryResult(
            names[1],
            "A",
            DnsQueryState.TIMEOUT,
            error="timeout",
        )
        evidence = _evidence(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                (
                    _negative_result(names[0], DnsQueryState.NXDOMAIN),
                    timeout,
                ),
                None,
            ),
        )

        analysis = analyze_negative_dns(evidence)

        self.assertEqual(analysis.negative_state, NegativeDnsState.UNKNOWN)
        self.assertFalse(analysis.negative_complete)

    def test_open_recursion_requires_positive_non_authoritative_resolution(self):
        state, reason = analyze_recursion_result(_recursion_result())

        self.assertEqual(state, RecursionState.OPEN)
        self.assertIn("non-authoritative", reason)

        ra_only = _recursion_result(state=DnsQueryState.ERROR, rcode="NOERROR", ra=True)
        state, _ = analyze_recursion_result(ra_only)
        self.assertEqual(state, RecursionState.UNKNOWN)

        cached_without_ra = _recursion_result(ra=False)
        state, _ = analyze_recursion_result(cached_without_ra)
        self.assertEqual(state, RecursionState.UNKNOWN)

    def test_explicit_refused_is_closed(self):
        state, reason = analyze_recursion_result(
            _recursion_result(state=DnsQueryState.ERROR, rcode="REFUSED", ra=False)
        )

        self.assertEqual(state, RecursionState.CLOSED)
        self.assertIn("refused", reason.lower())

    def test_timeout_and_ambiguous_recursion_remain_unknown(self):
        timeout = _recursion_result(
            state=DnsQueryState.TIMEOUT,
            rcode=None,
            ra=None,
            aa=None,
        )
        state, _ = analyze_recursion_result(timeout)
        self.assertEqual(state, RecursionState.UNKNOWN)

        authoritative_answer = _recursion_result(ra=True, aa=True)
        state, _ = analyze_recursion_result(authoritative_answer)
        self.assertEqual(state, RecursionState.UNKNOWN)

    def test_any_confirmed_open_server_makes_zone_recursion_open(self):
        names = (
            "dssnx0-fixed.target.test",
            "dssnx1-fixed.target.test",
        )
        negative = tuple(_negative_result(name, DnsQueryState.NXDOMAIN) for name in names)
        evidence = _evidence(
            NegativeDnsServerEvidence(
                "ns1.target.test",
                "192.0.2.53",
                negative,
                _recursion_result(),
            ),
            NegativeDnsServerEvidence(
                "ns2.target.test",
                "192.0.2.54",
                negative,
                _recursion_result(state=DnsQueryState.TIMEOUT, rcode=None, ra=None, aa=None),
            ),
        )

        analysis = analyze_negative_dns(evidence)

        self.assertEqual(analysis.recursion_state, RecursionState.OPEN)
        self.assertEqual(analysis.recursion_open_servers, ("ns1.target.test",))
        self.assertEqual(analysis.recursion_unknown_servers, ("ns2.target.test",))


if __name__ == "__main__":
    unittest.main()
