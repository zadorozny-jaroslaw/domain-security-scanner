from __future__ import annotations

from dataclasses import dataclass

from .delegation import ParentDelegationEvidence
from .delegation_analysis import (
    ADDRESS_NO_ADDRESS,
    ADDRESS_UNKNOWN,
    ALIAS_ALIAS,
    ALIAS_UNKNOWN,
    AUTHORITY_AUTHORITATIVE,
    AUTHORITY_AUTHORITATIVE_NO_NS,
    AUTHORITY_LAME,
    AUTHORITY_MIXED,
    AUTHORITY_NO_ADDRESS,
    AUTHORITY_UNKNOWN,
    AUTHORITY_UNPROBED,
    GLUE_MISSING,
    GLUE_PRESENT,
    DelegationAnalysis,
)
from .dns_scoring import (
    DELEGATED_AUTHORITY_WEIGHT,
    DELEGATION_CONSISTENCY_WEIGHT,
    NAME_SERVER_REDUNDANCY_WEIGHT,
    NAMESERVER_ADDRESSABILITY_WEIGHT,
)


@dataclass(frozen=True)
class DelegationFinding:
    """One user-facing Domain check derived from delegation analysis."""

    name: str
    status: str
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True


def _names(values: list[str] | tuple[str, ...]) -> str:
    return ", ".join(values)


def _by_authority_status(
    analysis: DelegationAnalysis,
    *states: str,
) -> tuple[str, ...]:
    return tuple(
        item.name
        for item in analysis.nameservers
        if item.authority_status in states
    )


def build_delegation_findings(
    evidence: ParentDelegationEvidence,
    analysis: DelegationAnalysis,
) -> tuple[DelegationFinding, ...]:
    """Convert delegation analysis into impact-calibrated Domain checks.

    Only findings backed by positive, sufficiently complete evidence reduce the
    score. Missing/timeout evidence remains unknown and is excluded by setting
    ``applicable=False``.
    """
    findings: list[DelegationFinding] = []

    if not evidence.available or not analysis.parent_nameservers:
        findings.append(
            DelegationFinding(
                "Name server redundancy",
                "unknown",
                "Nie udało się wiarygodnie ustalić delegowanego zestawu NS po stronie rodzica.",
                NAME_SERVER_REDUNDANCY_WEIGHT,
                0,
                False,
            )
        )
    elif len(analysis.parent_nameservers) >= 2:
        findings.append(
            DelegationFinding(
                "Name server redundancy",
                "pass",
                f"Delegacja rodzica wskazuje {len(analysis.parent_nameservers)} serwery NS.",
                NAME_SERVER_REDUNDANCY_WEIGHT,
                NAME_SERVER_REDUNDANCY_WEIGHT,
            )
        )
    else:
        findings.append(
            DelegationFinding(
                "Name server redundancy",
                "warn",
                f"Delegacja rodzica wskazuje tylko jeden serwer NS: {analysis.parent_nameservers[0]}.",
                NAME_SERVER_REDUNDANCY_WEIGHT,
                0,
            )
        )

    if not evidence.available:
        findings.append(
            DelegationFinding(
                "DNS delegation consistency",
                "unknown",
                "Brak wiarygodnej odpowiedzi delegacyjnej rodzica; zgodność parent/child nie może zostać oceniona.",
                DELEGATION_CONSISTENCY_WEIGHT,
                0,
                False,
            )
        )
    elif analysis.parent_child_consistent is True:
        findings.append(
            DelegationFinding(
                "DNS delegation consistency",
                "pass",
                "Delegacja rodzica jest zgodna z potwierdzonymi autorytatywnymi zestawami NS strefy.",
                DELEGATION_CONSISTENCY_WEIGHT,
                DELEGATION_CONSISTENCY_WEIGHT,
            )
        )
    elif analysis.parent_child_consistent is False:
        details: list[str] = []
        if analysis.missing_from_child:
            details.append(
                "brak po stronie dziecka: " + _names(analysis.missing_from_child)
            )
        if analysis.extra_in_child:
            details.append(
                "tylko po stronie dziecka: " + _names(analysis.extra_in_child)
            )
        suffix = "; ".join(details)
        if suffix:
            suffix = " " + suffix + "."

        if analysis.parent_child_complete:
            findings.append(
                DelegationFinding(
                    "DNS delegation consistency",
                    "fail",
                    "Potwierdzone autorytatywne odpowiedzi wszystkich ocenionych delegowanych NS nie są zgodne z delegacją rodzica."
                    + suffix,
                    DELEGATION_CONSISTENCY_WEIGHT,
                    0,
                )
            )
        else:
            findings.append(
                DelegationFinding(
                    "DNS delegation consistency",
                    "warn",
                    "Zaobserwowano różnicę między delegacją rodzica a dostępnym autorytatywnym zestawem NS."
                    + suffix
                    + " Materiał child NS jest niepełny, więc wynik może odzwierciedlać stan przejściowy podczas migracji DNS.",
                    DELEGATION_CONSISTENCY_WEIGHT,
                    DELEGATION_CONSISTENCY_WEIGHT / 2,
                )
            )
    else:
        findings.append(
            DelegationFinding(
                "DNS delegation consistency",
                "unknown",
                "Dostępne dowody child NS są niepełne; nie potwierdzono ani zgodności, ani trwałej niezgodności delegacji.",
                DELEGATION_CONSISTENCY_WEIGHT,
                0,
                False,
            )
        )

    if not evidence.available or not analysis.nameservers:
        findings.append(
            DelegationFinding(
                "Delegated nameserver authority",
                "unknown",
                "Brak wystarczających dowodów do oceny autorytatywności delegowanych serwerów NS.",
                DELEGATED_AUTHORITY_WEIGHT,
                0,
                False,
            )
        )
    else:
        lame = _by_authority_status(analysis, AUTHORITY_LAME)
        mixed = _by_authority_status(analysis, AUTHORITY_MIXED)
        no_ns = _by_authority_status(
            analysis,
            AUTHORITY_AUTHORITATIVE_NO_NS,
        )
        unknown = _by_authority_status(
            analysis,
            AUTHORITY_UNKNOWN,
            AUTHORITY_NO_ADDRESS,
            AUTHORITY_UNPROBED,
        )

        if lame:
            findings.append(
                DelegationFinding(
                    "Delegated nameserver authority",
                    "fail",
                    "Potwierdzono delegowane serwery, które odpowiadają dla strefy bez autorytatywnej obsługi: "
                    + _names(lame)
                    + ".",
                    DELEGATED_AUTHORITY_WEIGHT,
                    0,
                )
            )
        elif mixed or no_ns:
            details: list[str] = []
            if mixed:
                details.append(
                    "mieszane wyniki między adresami: " + _names(mixed)
                )
            if no_ns:
                details.append(
                    "autorytatywna odpowiedź bez oczekiwanego apex NS: " + _names(no_ns)
                )
            findings.append(
                DelegationFinding(
                    "Delegated nameserver authority",
                    "warn",
                    "Nie wszystkie potwierdzone odpowiedzi delegowanych NS mają spójny stan autorytatywny; "
                    + "; ".join(details)
                    + ".",
                    DELEGATED_AUTHORITY_WEIGHT,
                    DELEGATED_AUTHORITY_WEIGHT / 2,
                )
            )
        elif unknown:
            findings.append(
                DelegationFinding(
                    "Delegated nameserver authority",
                    "unknown",
                    "Nie udało się potwierdzić autorytatywności wszystkich delegowanych NS; niepełne dowody dotyczą: "
                    + _names(unknown)
                    + ".",
                    DELEGATED_AUTHORITY_WEIGHT,
                    0,
                    False,
                )
            )
        elif all(
            item.authority_status == AUTHORITY_AUTHORITATIVE
            for item in analysis.nameservers
        ):
            findings.append(
                DelegationFinding(
                    "Delegated nameserver authority",
                    "pass",
                    "Każdy oceniony delegowany serwer NS potwierdził autorytatywną odpowiedź dla strefy.",
                    DELEGATED_AUTHORITY_WEIGHT,
                    DELEGATED_AUTHORITY_WEIGHT,
                )
            )
        else:
            findings.append(
                DelegationFinding(
                    "Delegated nameserver authority",
                    "unknown",
                    "Stan autorytatywności delegowanych serwerów NS jest niejednoznaczny.",
                    DELEGATED_AUTHORITY_WEIGHT,
                    0,
                    False,
                )
            )

    if not evidence.available or not analysis.nameservers:
        findings.append(
            DelegationFinding(
                "Nameserver addressability",
                "unknown",
                "Brak wystarczających dowodów do oceny adresów A/AAAA delegowanych NS.",
                NAMESERVER_ADDRESSABILITY_WEIGHT,
                0,
                False,
            )
        )
    else:
        missing = tuple(
            item.name
            for item in analysis.nameservers
            if item.address_status == ADDRESS_NO_ADDRESS
        )
        unknown = tuple(
            item.name
            for item in analysis.nameservers
            if item.address_status == ADDRESS_UNKNOWN
        )
        if missing:
            findings.append(
                DelegationFinding(
                    "Nameserver addressability",
                    "fail",
                    "Potwierdzono delegowane serwery NS bez użytecznego adresu A/AAAA ani delegacyjnego glue: "
                    + _names(missing)
                    + ".",
                    NAMESERVER_ADDRESSABILITY_WEIGHT,
                    0,
                )
            )
        elif unknown:
            findings.append(
                DelegationFinding(
                    "Nameserver addressability",
                    "unknown",
                    "Nie udało się wiarygodnie ustalić adresów wszystkich delegowanych NS: "
                    + _names(unknown)
                    + ".",
                    NAMESERVER_ADDRESSABILITY_WEIGHT,
                    0,
                    False,
                )
            )
        else:
            findings.append(
                DelegationFinding(
                    "Nameserver addressability",
                    "pass",
                    "Każdy delegowany serwer NS ma co najmniej jeden użyteczny adres z DNS lub delegacyjnego glue.",
                    NAMESERVER_ADDRESSABILITY_WEIGHT,
                    NAMESERVER_ADDRESSABILITY_WEIGHT,
                )
            )

    if not evidence.available:
        findings.append(
            DelegationFinding(
                "Delegation glue",
                "unknown",
                "Brak wiarygodnej odpowiedzi delegacyjnej rodzica; glue nie może zostać oceniony.",
                applicable=False,
            )
        )
    else:
        in_bailiwick = tuple(
            item for item in analysis.nameservers if item.in_bailiwick
        )
        if not in_bailiwick:
            findings.append(
                DelegationFinding(
                    "Delegation glue",
                    "info",
                    "Delegowane NS są poza ocenianą strefą; delegacyjne glue nie jest dla nich wymagane.",
                    applicable=False,
                )
            )
        else:
            missing_glue = tuple(
                item.name
                for item in in_bailiwick
                if item.glue_status == GLUE_MISSING
            )
            mismatch = tuple(
                item.name
                for item in in_bailiwick
                if item.glue_status == GLUE_PRESENT
                and item.glue_consistent is False
            )
            inconclusive = tuple(
                item.name
                for item in in_bailiwick
                if item.glue_status == GLUE_PRESENT
                and item.glue_consistent is None
            )
            if missing_glue or mismatch:
                details: list[str] = []
                if missing_glue:
                    details.append(
                        "brak glue: " + _names(missing_glue)
                    )
                if mismatch:
                    details.append(
                        "glue różni się od aktualnych A/AAAA: " + _names(mismatch)
                    )
                findings.append(
                    DelegationFinding(
                        "Delegation glue",
                        "warn",
                        "Zaobserwowano problem z glue dla NS wewnątrz strefy; "
                        + "; ".join(details)
                        + ".",
                    )
                )
            elif inconclusive:
                findings.append(
                    DelegationFinding(
                        "Delegation glue",
                        "unknown",
                        "Glue jest obecny, ale aktualnych adresów nie udało się wiarygodnie porównać dla: "
                        + _names(inconclusive)
                        + ".",
                        applicable=False,
                    )
                )
            else:
                findings.append(
                    DelegationFinding(
                        "Delegation glue",
                        "pass",
                        "Wymagane glue dla delegowanych NS wewnątrz strefy jest obecne i zgodne z obserwowanymi adresami.",
                    )
                )

    if not evidence.available or not analysis.nameservers:
        findings.append(
            DelegationFinding(
                "Nameserver target aliasing",
                "unknown",
                "Brak wystarczających dowodów do oceny aliasowania delegowanych nazw NS.",
                applicable=False,
            )
        )
    else:
        aliases = tuple(
            item.name
            for item in analysis.nameservers
            if item.alias_status == ALIAS_ALIAS
        )
        unknown_alias = tuple(
            item.name
            for item in analysis.nameservers
            if item.alias_status == ALIAS_UNKNOWN
        )
        if aliases:
            findings.append(
                DelegationFinding(
                    "Nameserver target aliasing",
                    "warn",
                    "Delegowane cele NS zależą od rekordów CNAME: "
                    + _names(aliases)
                    + ". Cele NS powinny wskazywać bezpośrednio na nazwy z adresami.",
                )
            )
        elif unknown_alias:
            findings.append(
                DelegationFinding(
                    "Nameserver target aliasing",
                    "unknown",
                    "Nie udało się potwierdzić braku CNAME dla wszystkich delegowanych celów NS: "
                    + _names(unknown_alias)
                    + ".",
                    applicable=False,
                )
            )
        else:
            findings.append(
                DelegationFinding(
                    "Nameserver target aliasing",
                    "pass",
                    "Nie wykryto zależności CNAME dla delegowanych celów NS.",
                )
            )

    return tuple(findings)


__all__ = [
    "DelegationFinding",
    "build_delegation_findings",
]
