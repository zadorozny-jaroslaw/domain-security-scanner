from __future__ import annotations

from dataclasses import dataclass

from .dnssec_denial_analysis import DnssecDenialAnalysis, DnssecDenialPosture
from .dnssec_policy import DnssecPolicyPosture
from .dnssec_posture_analysis import DnssecAlgorithmPostureAnalysis


@dataclass(frozen=True)
class DnssecPostureFinding:
    """One non-scoring issue #17 DNSSEC posture finding."""

    name: str
    status: str
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True


def _algorithm_names(analysis: DnssecAlgorithmPostureAnalysis) -> str:
    values = []
    for item in analysis.dnskey_algorithms:
        label = item.mnemonic or f"algorithm {item.number}"
        values.append(f"{label} ({item.number}: {item.signing_posture.value})")
    return ", ".join(values) or "niezaobserwowany bezpośrednio"


def _digest_names(analysis: DnssecAlgorithmPostureAnalysis) -> str:
    values = []
    for item in analysis.ds_digests:
        label = item.description or f"digest {item.number}"
        values.append(f"{label} ({item.number}: {item.delegation_posture.value})")
    return ", ".join(values) or "niezaobserwowany bezpośrednio"


def algorithm_policy_finding(
    analysis: DnssecAlgorithmPostureAnalysis,
) -> DnssecPostureFinding:
    details = (
        f"DNSKEY: {_algorithm_names(analysis)}; DS digest (direct): {_digest_names(analysis)}. "
        f"Snapshot: {analysis.snapshot_version}."
    )
    if not analysis.observable or analysis.posture == DnssecPolicyPosture.UNKNOWN:
        return DnssecPostureFinding(
            "DNSSEC algorithm policy",
            "unknown",
            "Nie można jednoznacznie ocenić bieżącej polityki algorytmów DNSSEC. "
            + details,
            applicable=False,
        )
    if analysis.posture == DnssecPolicyPosture.PROHIBITED:
        return DnssecPostureFinding(
            "DNSSEC algorithm policy",
            "fail",
            "Zaobserwowano algorytm podpisu lub digest DS oznaczony przez bieżącą "
            "politykę jako niedozwolony dla nowego użycia. "
            + details,
        )
    if analysis.posture == DnssecPolicyPosture.NOT_RECOMMENDED:
        return DnssecPostureFinding(
            "DNSSEC algorithm policy",
            "warn",
            "Zaobserwowano algorytm dozwolony do walidacji, ale niewskazany do bieżącego podpisywania DNSSEC. "
            + details,
        )
    if analysis.posture == DnssecPolicyPosture.PERMITTED:
        return DnssecPostureFinding(
            "DNSSEC algorithm policy",
            "info",
            "Zaobserwowane bezpośrednio parametry DNSSEC są dozwolone przez bieżący snapshot polityki, "
            "ale nie wszystkie mają status recommended. "
            + details,
            applicable=False,
        )
    return DnssecPostureFinding(
        "DNSSEC algorithm policy",
        "pass",
        "Zaobserwowane bezpośrednio parametry DNSSEC należą do bieżącego recommended set. "
        + details,
    )


def denial_posture_finding(analysis: DnssecDenialAnalysis) -> DnssecPostureFinding:
    if analysis.posture == DnssecDenialPosture.UNKNOWN:
        return DnssecPostureFinding(
            "DNSSEC denial of existence",
            "unknown",
            "Nie udało się wiarygodnie sklasyfikować mechanizmu NSEC/NSEC3 z ograniczonej próbki: "
            + analysis.reason,
            applicable=False,
        )
    if analysis.posture == DnssecDenialPosture.REVIEW:
        return DnssecPostureFinding(
            "DNSSEC denial of existence",
            "warn",
            "Zaobserwowane dane NSEC/NSEC3 wymagają przeglądu: " + analysis.reason,
        )
    if analysis.posture == DnssecDenialPosture.ADVISORY:
        return DnssecPostureFinding(
            "DNSSEC denial of existence",
            "info",
            "NSEC3 działa, ale parametry odbiegają od advisory baseline RFC 9276: "
            + analysis.reason,
            applicable=False,
        )
    return DnssecPostureFinding(
        "DNSSEC denial of existence",
        "pass",
        "Zaobserwowany mechanizm authenticated denial odpowiada bieżącej baseline: "
        + analysis.reason,
    )


def build_dnssec_posture_findings(
    algorithm_analysis: DnssecAlgorithmPostureAnalysis,
    denial_analysis: DnssecDenialAnalysis,
) -> tuple[DnssecPostureFinding, ...]:
    return (
        algorithm_policy_finding(algorithm_analysis),
        denial_posture_finding(denial_analysis),
    )


__all__ = [
    "DnssecPostureFinding",
    "algorithm_policy_finding",
    "build_dnssec_posture_findings",
    "denial_posture_finding",
]
