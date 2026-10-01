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


def _signed_context(rdap, dns_records, zone: str) -> tuple[bool, bool]:
    rdap = rdap if isinstance(rdap, dict) else {}
    secure_dns = rdap.get("secureDNS") if isinstance(rdap.get("secureDNS"), dict) else {}
    rdap_signed = secure_dns.get("delegationSigned") is True
    zone_records = (dns_records or {}).get(zone, {}) if isinstance(dns_records, dict) else {}
    recursive_ds = bool(zone_records.get("DS")) if isinstance(zone_records, dict) else False
    return rdap_signed, recursive_ds


def build_dnssec_findings(
    evidence: DnssecEvidence,
    analysis: DnssecAnalysis,
    *,
    rdap=None,
    dns_records=None,
) -> tuple[DnssecFinding, ...]:
    """Convert DNSSEC state into one impact-calibrated scored check.

    A correctly validated zone receives full credit. An unsigned zone remains a
    security-hardening gap, but is materially less severe than a broken signed
    delegation, so it receives half credit. Unknown evidence is excluded from
    scoring entirely.
    """
    zone = evidence.zone or "domena rejestrowana"

    if analysis.state == DnssecState.SECURE:
        source = getattr(evidence, "source", "direct_authoritative")
        if source == "encrypted_recursive":
            message = (
                f"DNSSEC dla {zone} został poprawnie zwalidowany kryptograficznie z materiału "
                "DS/DNSKEY/SOA/NS pozyskanego przez dwa niezależne, walidujące resolvery "
                "DNS-over-HTTPS. Scanner lokalnie potwierdził dopasowanie DS do DNSKEY oraz "
                "aktualne podpisy DNSKEY/SOA/NS; encrypted fallback nie zastępuje testów "
                "konkretnego autorytatywnego endpointu."
            )
        else:
            message = (
                f"DNSSEC dla {zone} został poprawnie zwalidowany: DS rodzica pasuje do "
                "uwierzytelnionego materiału DNSKEY, a wybrane apex RRsety SOA/NS mają "
                "poprawne i aktualne podpisy."
            )
        primary = DnssecFinding(
            "DNSSEC",
            "pass",
            message,
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
        rdap_signed, recursive_ds = _signed_context(rdap, dns_records, zone)
        selected = getattr(evidence, "selected_dnskey", None)
        selected_result = getattr(selected, "result", None)
        selected_state = getattr(selected_result, "state", None)
        selected_state = getattr(selected_state, "value", selected_state)
        child_dnskey = bool(
            selected_result is not None
            and selected_state == "answer"
            and getattr(selected_result, "aa", None) is True
        )

        context_parts = []
        if rdap_signed:
            context_parts.append("RDAP wskazuje podpisaną delegację")
        if recursive_ds:
            context_parts.append("rekurencyjny inventory widzi rekord DS")
        if child_dnskey:
            context_parts.append("bezpośrednio zaobserwowano autorytatywny DNSKEY dziecka")

        if context_parts:
            message = (
                f"DNSSEC dla {zone} ma oznaki aktywnego podpisania ({'; '.join(context_parts)}), "
                "ale z bieżącej lokalizacji skanera nie udało się domknąć bezpośredniej "
                "walidacji parent-to-child. Wynik pozostaje VERIFY i nie wpływa na scoring."
            )
        else:
            message = (
                f"Nie można jednoznacznie zweryfikować DNSSEC dla {zone}: wymagane dowody "
                "są niedostępne, niekompletne lub lokalna walidacja kryptograficzna nie "
                "była możliwa."
            )

        primary = DnssecFinding(
            "DNSSEC",
            "unknown",
            message,
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
