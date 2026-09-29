from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecQueryEvidence,
)
from domain_security_scanner.domains.domain.dnssec_denial_analysis import (
    DnssecDenialMechanism,
    DnssecDenialPosture,
    analyze_dnssec_denial,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


def _result(
    *,
    state=DnsQueryState.NXDOMAIN,
    answer=(),
    authority=(),
    aa=True,
):
    return DnsQueryResult(
        "dssnx0-deadbeef.example.com",
        "A",
        state,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        rcode="NXDOMAIN" if state == DnsQueryState.NXDOMAIN else "NOERROR",
        aa=aa,
        answer_section=tuple(answer),
        authority_section=tuple(authority),
        request_edns_version=0,
        request_edns_payload=1232,
        request_want_dnssec=True,
    )


def _evidence(result: DnsQueryResult | None):
    probe = None
    if result is not None:
        probe = DnssecQueryEvidence(
            qtype="A",
            server_name=result.server_name,
            server_ip=result.server_ip,
            udp_result=result,
        )
    return DnssecEvidence(zone="example.com", denial_probe=probe)


class DnssecDenialAnalysisTest(unittest.TestCase):
    def test_missing_probe_is_unknown(self):
        result = analyze_dnssec_denial(DnssecEvidence(zone="example.com"))
        self.assertEqual(result.mechanism, DnssecDenialMechanism.UNKNOWN)
        self.assertEqual(result.posture, DnssecDenialPosture.UNKNOWN)
        self.assertFalse(result.observable)

    def test_timeout_is_unknown(self):
        result = analyze_dnssec_denial(
            _evidence(_result(state=DnsQueryState.TIMEOUT, authority=()))
        )
        self.assertEqual(result.posture, DnssecDenialPosture.UNKNOWN)

    def test_nsec_is_current_and_observable(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "example.com. 300 IN NSEC zzz.example.com. A NS SOA RRSIG NSEC DNSKEY",
                    )
                )
            )
        )
        self.assertEqual(result.mechanism, DnssecDenialMechanism.NSEC)
        self.assertEqual(result.posture, DnssecDenialPosture.CURRENT)
        self.assertTrue(result.observable)
        self.assertEqual(result.nsec_count, 1)

    def test_nsec3_rfc9276_baseline_is_current(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "ABC.example.com. 300 IN NSEC3 1 0 0 - DEF A NS SOA RRSIG DNSKEY NSEC3PARAM",
                        "DEF.example.com. 300 IN NSEC3 1 0 0 - GHI A RRSIG",
                    )
                )
            )
        )
        self.assertEqual(result.mechanism, DnssecDenialMechanism.NSEC3)
        self.assertEqual(result.posture, DnssecDenialPosture.CURRENT)
        self.assertEqual(result.nsec3.algorithms, (1,))
        self.assertTrue(result.nsec3.zero_iterations)
        self.assertTrue(result.nsec3.empty_salt)
        self.assertFalse(result.nsec3.opt_out_observed)
        self.assertEqual(result.advisories, ())

    def test_nsec3_nonzero_iterations_salt_and_optout_are_advisory(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "ABC.example.com. 300 IN NSEC3 1 1 5 A1B2 DEF A NS SOA RRSIG",
                    )
                )
            )
        )
        self.assertEqual(result.posture, DnssecDenialPosture.ADVISORY)
        self.assertFalse(result.nsec3.zero_iterations)
        self.assertFalse(result.nsec3.empty_salt)
        self.assertTrue(result.nsec3.opt_out_observed)
        self.assertIn("nonzero_iterations", result.advisories)
        self.assertIn("salt_present", result.advisories)
        self.assertIn("opt_out_observed", result.advisories)

    def test_nsec3_reserved_flags_require_review(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "ABC.example.com. 300 IN NSEC3 1 2 0 - DEF A NS SOA RRSIG",
                    )
                )
            )
        )
        self.assertEqual(result.posture, DnssecDenialPosture.REVIEW)
        self.assertEqual(result.nsec3.reserved_flag_values, (2,))
        self.assertIn("reserved_nsec3_flags", result.advisories)

    def test_unknown_future_nsec3_hash_algorithm_stays_unknown(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "ABC.example.com. 300 IN NSEC3 2 0 0 - DEF A NS SOA RRSIG",
                    )
                )
            )
        )
        self.assertEqual(result.mechanism, DnssecDenialMechanism.NSEC3)
        self.assertEqual(result.posture, DnssecDenialPosture.UNKNOWN)
        self.assertIn("unknown_nsec3_hash_algorithm", result.advisories)

    def test_mixed_nsec_and_nsec3_requires_review(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "example.com. 300 IN NSEC zzz.example.com. A NS SOA RRSIG NSEC DNSKEY",
                        "ABC.example.com. 300 IN NSEC3 1 0 0 - DEF A NS SOA RRSIG",
                    )
                )
            )
        )
        self.assertEqual(result.mechanism, DnssecDenialMechanism.UNKNOWN)
        self.assertEqual(result.posture, DnssecDenialPosture.REVIEW)
        self.assertIn("mixed_nsec_nsec3", result.advisories)

    def test_nsec3param_mismatch_requires_review(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    authority=(
                        "ABC.example.com. 300 IN NSEC3 1 0 0 - DEF A NS SOA RRSIG",
                        "example.com. 300 IN NSEC3PARAM 1 0 1 -",
                    )
                )
            )
        )
        self.assertEqual(result.posture, DnssecDenialPosture.REVIEW)
        self.assertIn("nsec3param_mismatch", result.advisories)

    def test_wildcard_answer_can_still_expose_nsec3_mechanism(self):
        result = analyze_dnssec_denial(
            _evidence(
                _result(
                    state=DnsQueryState.ANSWER,
                    answer=("dssnx0-deadbeef.example.com. 60 IN A 192.0.2.80",),
                    authority=(
                        "ABC.example.com. 300 IN NSEC3 1 0 0 - DEF A NS SOA RRSIG",
                    ),
                )
            )
        )
        self.assertEqual(result.mechanism, DnssecDenialMechanism.NSEC3)
        self.assertEqual(result.posture, DnssecDenialPosture.CURRENT)


if __name__ == "__main__":
    unittest.main()
