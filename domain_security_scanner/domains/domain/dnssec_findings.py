from __future__ import annotations

from dataclasses import dataclass

from .dnssec import DnssecEvidence
from .dnssec_analysis import DnssecAnalysis, DnssecState


DNSSEC_SCORE_WEIGHT = 7


@dataclass(frozen=True)
class DnssecFinding:
    """One customer-facing DNSSEC finding derived from structured validation."""

    name: str
    status: str
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True


def build_dnssec_findings(
    evidence: DnssecEvidence,
    analysis: DnssecAnalysis,
) -> tuple[DnssecFinding, ...]:
    """Convert issue #16 validation state into one conservative scored check."""
    zone = evidence.zone or "domena rejestrowana"

    if analysis.state == DnssecState.SECURE:
        primary = DnssecFinding(
            "DNSSEC",
            "pass",
            f"DNSSEC dla {zone} został poprawnie zwalidowany: DS rodzica pasuje do "
            "uwierzytelnionego materiału DNSKEY, a wybrane apex RRsety SOA/NS mają "
            "poprawne i aktualne podpisy.",
            DNSSEC_SCORE_WEIGHT,
            DNSSEC_SCORE_WEIGHT,
        )
    elif analysis.state == DnssecState.UNSIGNED:
        primary = DnssecFinding(
            "DNSSEC",
            "warn",
            f"Strefa {zone} nie używa DNSSEC: delegacja rodzica nie zawiera rekordu DS.",
            DNSSEC_SCORE_WEIGHT,
            0,
        )
    elif analysis.state == DnssecState.BROKEN:
        primary = DnssecFinding(
            "DNSSEC",
            "fail",
            f"Walidacja DNSSEC dla {zone} nie powiodła się: kompletne dowody wskazują "
            "na błąd łańcucha DS/DNSKEY lub podpisu wymaganego RRsetu.",
            DNSSEC_SCORE_WEIGHT,
            0,
        )
    else:
        primary = DnssecFinding(
            "DNSSEC",
            "unknown",
            f"Nie można jednoznacznie zweryfikować DNSSEC dla {zone}: wymagane dowody "
            "są niedostępne, niekompletne lub lokalna walidacja kryptograficzna nie "
            "była możliwa.",
            DNSSEC_SCORE_WEIGHT,
            0,
            False,
        )

    return (primary,)


__all__ = [
    "DNSSEC_SCORE_WEIGHT",
    "DnssecFinding",
    "build_dnssec_findings",
]
