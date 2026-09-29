from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec_policy import (
    DNSSEC_ALGORITHM_REGISTRY_UPDATED,
    DNSSEC_DS_DIGEST_REGISTRY_UPDATED,
    DNSSEC_POLICY_SNAPSHOT,
    DNSSEC_POLICY_SNAPSHOT_VERSION,
    DnssecPolicyPosture,
    DnssecRequirement,
    dnssec_algorithm_policy,
    dnssec_algorithm_signing_posture,
    dnssec_algorithm_validation_posture,
    dnssec_digest_delegation_posture,
    dnssec_digest_policy,
    dnssec_digest_validation_posture,
    posture_allows_use,
)


class DnssecPolicySnapshotTest(unittest.TestCase):
    def test_snapshot_version_and_registry_dates_are_explicit(self):
        self.assertEqual(
            DNSSEC_POLICY_SNAPSHOT_VERSION,
            "2026-08-10-iana-dnssec-policy",
        )
        self.assertEqual(DNSSEC_ALGORITHM_REGISTRY_UPDATED, "2026-08-10")
        self.assertEqual(DNSSEC_DS_DIGEST_REGISTRY_UPDATED, "2026-01-13")
        self.assertEqual(DNSSEC_POLICY_SNAPSHOT.version, DNSSEC_POLICY_SNAPSHOT_VERSION)

    def test_recommended_algorithm_is_distinguished(self):
        entry = dnssec_algorithm_policy(13)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.mnemonic, "ECDSAP256SHA256")
        self.assertEqual(entry.signing_posture, DnssecPolicyPosture.RECOMMENDED)
        self.assertEqual(entry.validation_posture, DnssecPolicyPosture.RECOMMENDED)

    def test_permitted_algorithm_is_not_promoted_to_recommended(self):
        entry = dnssec_algorithm_policy(18)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.mnemonic, "MLDSA44")
        self.assertEqual(entry.use_for_signing, DnssecRequirement.MAY)
        self.assertEqual(entry.signing_posture, DnssecPolicyPosture.PERMITTED)
        self.assertEqual(entry.validation_posture, DnssecPolicyPosture.PERMITTED)

    def test_not_recommended_signing_is_distinct_from_validation(self):
        entry = dnssec_algorithm_policy(10)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.signing_posture, DnssecPolicyPosture.NOT_RECOMMENDED)
        self.assertEqual(entry.validation_posture, DnssecPolicyPosture.RECOMMENDED)

    def test_sha1_rsa_is_prohibited_for_signing_but_supported_for_validation(self):
        for number in (5, 7):
            with self.subTest(number=number):
                entry = dnssec_algorithm_policy(number)
                self.assertIsNotNone(entry)
                self.assertTrue(entry.sha1_based)
                self.assertEqual(
                    dnssec_algorithm_signing_posture(number),
                    DnssecPolicyPosture.PROHIBITED,
                )
                self.assertEqual(
                    dnssec_algorithm_validation_posture(number),
                    DnssecPolicyPosture.RECOMMENDED,
                )
                self.assertEqual(
                    entry.implement_for_validation,
                    DnssecRequirement.MUST,
                )

    def test_retired_ecc_gost_is_prohibited(self):
        entry = dnssec_algorithm_policy(12)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.retired)
        self.assertEqual(entry.signing_posture, DnssecPolicyPosture.PROHIBITED)
        self.assertEqual(entry.validation_posture, DnssecPolicyPosture.PROHIBITED)

    def test_sha1_ds_is_prohibited_for_delegation_but_recommended_for_validation(self):
        entry = dnssec_digest_policy(1)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.sha1_based)
        self.assertEqual(
            dnssec_digest_delegation_posture(1),
            DnssecPolicyPosture.PROHIBITED,
        )
        self.assertEqual(
            dnssec_digest_validation_posture(1),
            DnssecPolicyPosture.RECOMMENDED,
        )
        self.assertEqual(entry.implement_for_validation, DnssecRequirement.MUST)

    def test_recommended_and_permitted_ds_digests_are_distinct(self):
        self.assertEqual(
            dnssec_digest_delegation_posture(2),
            DnssecPolicyPosture.RECOMMENDED,
        )
        self.assertEqual(
            dnssec_digest_delegation_posture(4),
            DnssecPolicyPosture.PERMITTED,
        )
        self.assertEqual(
            dnssec_digest_validation_posture(4),
            DnssecPolicyPosture.RECOMMENDED,
        )

    def test_retired_gost_digest_is_prohibited(self):
        entry = dnssec_digest_policy(3)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.retired)
        self.assertEqual(entry.delegation_posture, DnssecPolicyPosture.PROHIBITED)
        self.assertEqual(entry.validation_posture, DnssecPolicyPosture.PROHIBITED)

    def test_unknown_future_values_remain_unknown(self):
        self.assertIsNone(dnssec_algorithm_policy(99))
        self.assertIsNone(dnssec_digest_policy(99))
        self.assertEqual(
            dnssec_algorithm_signing_posture(99),
            DnssecPolicyPosture.UNKNOWN,
        )
        self.assertEqual(
            dnssec_digest_delegation_posture(99),
            DnssecPolicyPosture.UNKNOWN,
        )
        self.assertIsNone(posture_allows_use(DnssecPolicyPosture.UNKNOWN))

    def test_private_dnssec_algorithms_remain_permitted_not_recommended(self):
        for number in (253, 254):
            with self.subTest(number=number):
                entry = dnssec_algorithm_policy(number)
                self.assertIsNotNone(entry)
                self.assertTrue(entry.private_use)
                self.assertEqual(entry.signing_posture, DnssecPolicyPosture.PERMITTED)
                self.assertEqual(entry.validation_posture, DnssecPolicyPosture.PERMITTED)

    def test_policy_maps_are_immutable(self):
        with self.assertRaises(TypeError):
            DNSSEC_POLICY_SNAPSHOT.algorithms[13] = None
        with self.assertRaises(TypeError):
            DNSSEC_POLICY_SNAPSHOT.digests[2] = None


if __name__ == "__main__":
    unittest.main()
