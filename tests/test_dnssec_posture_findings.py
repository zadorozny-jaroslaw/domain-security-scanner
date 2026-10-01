from __future__ import annotations

import unittest

from domain_security_scanner.domains.domain.dnssec_denial_analysis import (
    DnssecDenialAnalysis,
    DnssecDenialMechanism,
    DnssecDenialPosture,
)
from domain_security_scanner.domains.domain.dnssec_policy import DnssecPolicyPosture
from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
    DnssecAlgorithmPostureAnalysis,
)
from domain_security_scanner.domains.domain.dnssec_posture_findings import (
    build_dnssec_posture_findings,
)


class DnssecPostureFindingsTest(unittest.TestCase):
    def _findings(self, algorithm_posture, denial_posture):
        algorithm = DnssecAlgorithmPostureAnalysis(
            posture=algorithm_posture,
            reason="fixture",
        )
        denial = DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.NSEC3,
            posture=denial_posture,
            reason="fixture",
            observable=(denial_posture != DnssecDenialPosture.UNKNOWN),
        )
        return build_dnssec_posture_findings(algorithm, denial)

    def test_all_issue17_findings_are_non_scoring(self):
        findings = self._findings(
            DnssecPolicyPosture.PROHIBITED,
            DnssecDenialPosture.REVIEW,
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item.weight == 0 for item in findings))
        self.assertTrue(all(item.earned == 0 for item in findings))

    def test_prohibited_algorithm_is_fail_but_non_scoring(self):
        from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
            DnssecAlgorithmObservation,
        )
        algorithm = DnssecAlgorithmPostureAnalysis(
            posture=DnssecPolicyPosture.PROHIBITED,
            reason="fixture",
            dnskey_algorithms=(
                DnssecAlgorithmObservation(
                    number=5,
                    source="dnskey",
                    description="RSA/SHA-1",
                    mnemonic="RSASHA1",
                    signing_posture=DnssecPolicyPosture.PROHIBITED,
                    validation_posture=DnssecPolicyPosture.RECOMMENDED,
                    sha1_based=True,
                ),
            ),
        )
        denial = DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.UNKNOWN,
            posture=DnssecDenialPosture.UNKNOWN,
            reason="fixture",
        )
        finding = build_dnssec_posture_findings(algorithm, denial)[0]
        self.assertEqual(finding.status, "fail")
        self.assertEqual(finding.weight, 0)

    def test_not_recommended_algorithm_maps_to_warn_when_observed(self):
        from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
            DnssecAlgorithmObservation,
        )
        algorithm = DnssecAlgorithmPostureAnalysis(
            posture=DnssecPolicyPosture.NOT_RECOMMENDED,
            reason="fixture",
            dnskey_algorithms=(
                DnssecAlgorithmObservation(
                    number=10,
                    source="dnskey",
                    description="RSA/SHA-512",
                    mnemonic="RSASHA512",
                    signing_posture=DnssecPolicyPosture.NOT_RECOMMENDED,
                    validation_posture=DnssecPolicyPosture.RECOMMENDED,
                ),
            ),
        )
        denial = DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.UNKNOWN,
            posture=DnssecDenialPosture.UNKNOWN,
            reason="fixture",
        )
        finding = build_dnssec_posture_findings(algorithm, denial)[0]
        self.assertEqual(finding.status, "warn")
        self.assertEqual(finding.weight, 0)

    def test_permitted_algorithm_maps_to_info_when_observed(self):
        from domain_security_scanner.domains.domain.dnssec_posture_analysis import (
            DnssecAlgorithmObservation,
        )
        algorithm = DnssecAlgorithmPostureAnalysis(
            posture=DnssecPolicyPosture.PERMITTED,
            reason="fixture",
            dnskey_algorithms=(
                DnssecAlgorithmObservation(
                    number=18,
                    source="dnskey",
                    description="ML-DSA-44",
                    mnemonic="MLDSA44",
                    signing_posture=DnssecPolicyPosture.PERMITTED,
                    validation_posture=DnssecPolicyPosture.PERMITTED,
                ),
            ),
        )
        denial = DnssecDenialAnalysis(
            mechanism=DnssecDenialMechanism.UNKNOWN,
            posture=DnssecDenialPosture.UNKNOWN,
            reason="fixture",
        )
        finding = build_dnssec_posture_findings(algorithm, denial)[0]
        self.assertEqual(finding.status, "info")
        self.assertFalse(finding.applicable)

    def test_nsec3_advisory_is_info_and_non_applicable(self):
        finding = self._findings(
            DnssecPolicyPosture.UNKNOWN,
            DnssecDenialPosture.ADVISORY,
        )[1]
        self.assertEqual(finding.status, "info")
        self.assertEqual(finding.weight, 0)
        self.assertFalse(finding.applicable)

    def test_denial_review_maps_to_warn_without_score(self):
        finding = self._findings(
            DnssecPolicyPosture.UNKNOWN,
            DnssecDenialPosture.REVIEW,
        )[1]
        self.assertEqual(finding.status, "warn")
        self.assertEqual(finding.weight, 0)


if __name__ == "__main__":
    unittest.main()
