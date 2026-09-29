from __future__ import annotations

from dataclasses import dataclass

from .negative_dns import NegativeDnsEvidence
from .negative_dns_analysis import (
    NegativeDnsAnalysis,
    NegativeDnsState,
    RecursionState,
)


@dataclass(frozen=True)
class NegativeDnsFinding:
    """One issue #19 finding; scoring is intentionally deferred to integration."""

    name: str
    status: str
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True


def _names(values: tuple[str, ...]) -> str:
    return ", ".join(value for value in values if value) or "brak"


def _negative_behavior_finding(analysis: NegativeDnsAnalysis) -> NegativeDnsFinding:
    if analysis.negative_state == NegativeDnsState.NXDOMAIN:
        return NegativeDnsFinding(
            "Authoritative negative DNS",
            "pass",
            "Wszystkie testowane serwery autorytatywne zwróciły spójne NXDOMAIN dla losowych, nieistniejących nazw wraz z użytecznym evidence odpowiedzi negatywnej.",
        )

    if analysis.negative_state == NegativeDnsState.NODATA:
        return NegativeDnsFinding(
            "Authoritative negative DNS",
            "info",
            "Losowe nazwy otrzymały spójne autorytatywne odpowiedzi NODATA (NOERROR bez rekordu żądanego typu). Zachowanie jest raportowane diagnostycznie.",
            applicable=False,
        )

    if analysis.negative_state == NegativeDnsState.WILDCARD:
        return NegativeDnsFinding(
            "Authoritative negative DNS",
            "info",
            "Losowe nazwy otrzymały spójne pozytywne odpowiedzi autorytatywne; zachowanie wskazuje na prawdopodobny wildcard DNS.",
            applicable=False,
        )

    details = "; ".join(
        f"{server.server_name or server.server_ip or 'unknown'}={server.negative_state.value}"
        for server in analysis.servers
    )
    suffix = f" ({details})" if details else ""
    return NegativeDnsFinding(
        "Authoritative negative DNS",
        "unknown",
        "Nie udało się jednoznacznie sklasyfikować zachowania dla losowych nazw jako NXDOMAIN, NODATA lub wildcard"
        + suffix
        + ".",
        applicable=False,
    )


def _wildcard_finding(analysis: NegativeDnsAnalysis) -> NegativeDnsFinding | None:
    if not analysis.wildcard_servers:
        return None
    return NegativeDnsFinding(
        "Wildcard DNS",
        "info",
        "Zaobserwowano prawdopodobne zachowanie wildcard DNS dla losowych nazw na: "
        + _names(analysis.wildcard_servers)
        + ". Wildcard sam w sobie nie jest traktowany jako luka bezpieczeństwa.",
        applicable=False,
    )


def _recursion_finding(analysis: NegativeDnsAnalysis) -> NegativeDnsFinding:
    if analysis.recursion_state == RecursionState.OPEN:
        return NegativeDnsFinding(
            "Authoritative open recursion",
            "fail",
            "Potwierdzono zewnętrznie dostępną rekurencję DNS na serwerach autorytatywnych: "
            + _names(analysis.recursion_open_servers)
            + ". Serwery zwróciły rozstrzygający wynik dla kontrolowanego zapytania poza ocenianą strefą.",
        )

    if analysis.recursion_state == RecursionState.CLOSED:
        return NegativeDnsFinding(
            "Authoritative open recursion",
            "pass",
            "Każdy testowany serwer autorytatywny jawnie odmówił kontrolowanego zapytania rekurencyjnego spoza strefy.",
        )

    details = []
    if analysis.recursion_closed_servers:
        details.append("jawna odmowa: " + _names(analysis.recursion_closed_servers))
    if analysis.recursion_unknown_servers:
        details.append("brak rozstrzygającego evidence: " + _names(analysis.recursion_unknown_servers))
    suffix = "; " + "; ".join(details) if details else ""
    return NegativeDnsFinding(
        "Authoritative open recursion",
        "unknown",
        "Nie udało się wiarygodnie potwierdzić ani wykluczyć zewnętrznie dostępnej rekurencji"
        + suffix
        + ". Timeout lub same flagi DNS nie są traktowane jako dowód zamkniętej rekurencji.",
        applicable=False,
    )


def build_negative_dns_findings(
    evidence: NegativeDnsEvidence,
    analysis: NegativeDnsAnalysis,
) -> tuple[NegativeDnsFinding, ...]:
    """Translate pure issue #19 analysis into conservative findings."""
    _ = evidence
    findings = [_negative_behavior_finding(analysis)]
    wildcard = _wildcard_finding(analysis)
    if wildcard is not None:
        findings.append(wildcard)
    findings.append(_recursion_finding(analysis))
    return tuple(findings)


__all__ = [
    "NegativeDnsFinding",
    "build_negative_dns_findings",
]
