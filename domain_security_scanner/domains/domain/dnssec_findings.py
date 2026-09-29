from __future__ import annotations

from dataclasses import dataclass

from .dns_scoring import DNSSEC_SCORE_WEIGHT, DNSSEC_UNSIGNED_EARNED
from .dnssec import DnssecEvidence
from .dnssec_analysis import DnssecAnalysis, DnssecState


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
    """Convert DNSSEC state into one impact-calibrated scored check.

    A correctly validated zone receives full credit. An unsigned zone remains a
    security-hardening gap, but is materially less severe than a broken signed
    delegation, so it receives half credit. Unknown evidence is excluded from
    scoring entirely.
    """
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
            f"Strefa {zone} nie używa DNSSEC: delegacja rodzica nie zawiera rekordu DS. "
            "Brak DNSSEC obniża ochronę integralności odpowiedzi, ale nie oznacza awarii DNS.",
            DNSSEC_SCORE_WEIGHT,
            DNSSEC_UNSIGNED_EARNED,
        )
    elif analysis.state == DnssecState.BROKEN:
        primary = DnssecFinding(
            "DNSSEC",
            "fail",
            f"Walidacja DNSSEC dla {zone} nie powiodła się: kompletne dowody wskazują "
            "na błąd łańcucha DS/DNSKEY lub podpisu wymaganego RRsetu. Taki stan może "
            "powodować odrzucanie odpowiedzi przez walidujące resolvery.",
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
