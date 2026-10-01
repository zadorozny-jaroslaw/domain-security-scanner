from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec import (
    DnssecEvidence,
    DnssecQueryEvidence,
)
from domain_security_scanner.domains.domain.dnssec_policy import DnssecPolicyPosture
from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
    analyze_dnssec_algorithm_posture,
)
from domain_security_scanner.models import (
    DnsQueryMode,
    DnsQueryResult,
    DnsQueryState,
    DnsTransport,
)


def _answer(qtype: str, rrsets: tuple[str, ...]) -> DnsQueryResult:
    return DnsQueryResult(
        "example.com",
        qtype,
        DnsQueryState.ANSWER,
        query_mode=DnsQueryMode.AUTHORITATIVE,
        transport=DnsTransport.UDP,
        server_name="ns1.example.net",
        server_ip="192.0.2.53",
        rcode="NOERROR",
        aa=True,
        answer_section=rrsets,
        request_want_dnssec=True,
    )


def _evidence(*, dnskey_algorithm: int | None, ds_algorithm: int | None, digest: int | None):
    dnskey = None
    parent_ds = None
    if dnskey_algorithm is not None:
        result = _answer(
            "DNSKEY",
            (
                f"example.com. 300 IN DNSKEY 257 3 {dnskey_algorithm} AQIDBA==",
            ),
        )
        dnskey = DnssecQueryEvidence(
            qtype="DNSKEY",
            server_name=result.server_name,
            server_ip=result.server_ip,
            udp_result=result,
        )
    if ds_algorithm is not None and digest is not None:
        result = _answer(
            "DS",
            (
                f"example.com. 300 IN DS 12345 {ds_algorithm} {digest} AABBCCDD",
            ),
        )
        parent_ds = DnssecQueryEvidence(
            qtype="DS",
            server_name="parent.example",
            server_ip="192.0.2.1",
            udp_result=result,
        )
    return DnssecEvidence(
        zone="example.com",
        parent_ds=parent_ds,
        selected_dnskey=dnskey,
        dnskey_attempts=(dnskey,) if dnskey is not None else (),
    )


class DnssecAlgorithmPostureAnalysisTest(unittest.TestCase):
    def test_recommended_algorithm_and_digest_are_recommended(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=13, ds_algorithm=13, digest=2)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.RECOMMENDED)
        self.assertTrue(result.observable)
        self.assertEqual(result.dnskey_algorithms[0].mnemonic, "ECDSAP256SHA256")
        self.assertEqual(result.ds_digests[0].delegation_posture.value, "recommended")

    def test_permitted_algorithm_remains_permitted(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=18, ds_algorithm=18, digest=4)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.PERMITTED)
        self.assertEqual(result.dnskey_algorithms[0].signing_posture.value, "permitted")

    def test_not_recommended_signing_is_review_posture_not_prohibited(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=10, ds_algorithm=10, digest=2)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.NOT_RECOMMENDED)
        self.assertEqual(result.dnskey_algorithms[0].validation_posture.value, "recommended")

    def test_sha1_signing_and_sha1_digest_are_explicitly_prohibited_for_new_use(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=5, ds_algorithm=5, digest=1)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.PROHIBITED)
        self.assertEqual(result.sha1_signing_algorithms, (5,))
        self.assertEqual(result.sha1_delegation_digests, (1,))
        self.assertEqual(result.dnskey_algorithms[0].validation_posture.value, "recommended")
        self.assertEqual(result.ds_digests[0].validation_posture.value, "recommended")

    def test_retired_gost_algorithm_and_digest_are_explicit(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=12, ds_algorithm=12, digest=3)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.PROHIBITED)
        self.assertEqual(result.retired_algorithms, (12,))
        self.assertEqual(result.retired_digests, (3,))

    def test_unknown_future_algorithm_is_unknown_not_prohibited(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=99, ds_algorithm=99, digest=2)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.UNKNOWN)
        self.assertIsNone(result.dnskey_algorithms[0].description)
        self.assertEqual(result.dnskey_algorithms[0].signing_posture.value, "unknown")

    def test_unknown_future_digest_is_unknown_not_prohibited(self):
        result = analyze_dnssec_algorithm_posture(
            _evidence(dnskey_algorithm=13, ds_algorithm=13, digest=99)
        )
        self.assertEqual(result.posture, DnssecPolicyPosture.UNKNOWN)
        self.assertIsNone(result.ds_digests[0].description)

    def test_missing_algorithm_material_is_unknown(self):
        result = analyze_dnssec_algorithm_posture(DnssecEvidence(zone="example.com"))
        self.assertEqual(result.posture, DnssecPolicyPosture.UNKNOWN)
        self.assertFalse(result.observable)


if __name__ == "__main__":
    unittest.main()
