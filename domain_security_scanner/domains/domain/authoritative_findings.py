from __future__ import annotations

from dataclasses import dataclass

from ...models import DnsQueryState
from .authoritative import AuthoritativeDnsEvidence
from .authoritative_analysis import (
    EDNS_ANOMALY,
    EDNS_NOT_TESTED,
    EDNS_OK,
    EDNS_UNKNOWN,
    SOA_AUTHORITY_AUTHORITATIVE,
    SOA_AUTHORITY_MIXED,
    SOA_AUTHORITY_NOT_AUTHORITATIVE,
    SOA_AUTHORITY_NO_SOA,
    SOA_AUTHORITY_UNKNOWN,
    SOA_AUTHORITY_UNPROBED,
    TRANSPORT_BOTH_RESPOND,
    TRANSPORT_NO_RESPONSE,
    TRANSPORT_PATH_UNTRUSTED,
    TRANSPORT_TCP_ONLY,
    TRANSPORT_UDP_ONLY,
    AuthoritativeDnsAnalysis,
)
from .dns_scoring import AUTHORITATIVE_RRSET_WEIGHT, AUTHORITATIVE_TCP_WEIGHT


@dataclass(frozen=True)
class AuthoritativeDnsFinding:
    """One issue #15 Domain finding."""

    name: str
    status: str
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True


def _names(values) -> str:
    return ", ".join(values)


def _servers_by_authority(analysis: AuthoritativeDnsAnalysis, *states: str) -> tuple[str, ...]:
    return tuple(server.name for server in analysis.servers if server.soa_authority_status in states)


def _transport_finding(analysis: AuthoritativeDnsAnalysis) -> AuthoritativeDnsFinding:
    endpoints = [endpoint for server in analysis.servers for endpoint in server.transport]
    if not endpoints:
        return AuthoritativeDnsFinding(
            "Authoritative DNS transport",
            "unknown",
            "Brak bezpośrednich odpowiedzi z autorytatywnych endpointów; transport UDP/TCP nie może zostać oceniony.",
            AUTHORITATIVE_TCP_WEIGHT,
            0,
            False,
        )

    path_untrusted = [
        f"{endpoint.server_name} ({endpoint.server_ip})"
        for endpoint in endpoints
        if endpoint.status == TRANSPORT_PATH_UNTRUSTED
    ]
    if path_untrusted:
        return AuthoritativeDnsFinding(
            "Authoritative DNS transport",
            "unknown",
            "Odpowiedź DNS dotarła przez UDP/TCP, ale wzorzec odpowiedzi wskazuje, że bezpośrednia ścieżka do części docelowych IP może być przechwytywana lub przepisywana: "
            + _names(path_untrusted)
            + ". Dostępność transportu do zamierzonej usługi autorytatywnej pozostaje VERIFY.",
            AUTHORITATIVE_TCP_WEIGHT,
            0,
            False,
        )

    healthy_servers = {
        endpoint.server_name
        for endpoint in endpoints
        if endpoint.status == TRANSPORT_BOTH_RESPOND
    }
    confirmed_tcp_failure = [
        f"{endpoint.server_name} ({endpoint.server_ip})"
        for endpoint in endpoints
        if endpoint.status == TRANSPORT_UDP_ONLY
        and endpoint.tcp_state in {DnsQueryState.TRANSPORT_ERROR, DnsQueryState.ERROR}
        and any(name != endpoint.server_name for name in healthy_servers)
    ]
    if confirmed_tcp_failure:
        return AuthoritativeDnsFinding(
            "Authoritative DNS transport",
            "warn",
            "UDP działał, ale bezpośrednie połączenie TCP zakończyło się błędem transportu na części infrastruktury, podczas gdy inne serwery odpowiedziały poprawnie: "
            + _names(confirmed_tcp_failure)
            + ".",
            AUTHORITATIVE_TCP_WEIGHT,
            0,
        )

    asymmetric = [
        f"{endpoint.server_name} ({endpoint.server_ip})"
        for endpoint in endpoints
        if endpoint.status in {TRANSPORT_UDP_ONLY, TRANSPORT_TCP_ONLY}
    ]
    no_response = [
        f"{endpoint.server_name} ({endpoint.server_ip})"
        for endpoint in endpoints
        if endpoint.status == TRANSPORT_NO_RESPONSE
    ]
    if asymmetric or no_response:
        details = []
        if asymmetric:
            details.append("odpowiedź uzyskano tylko jednym transportem: " + _names(asymmetric))
        if no_response:
            details.append("brak odpowiedzi UDP i TCP: " + _names(no_response))
        return AuthoritativeDnsFinding(
            "Authoritative DNS transport",
            "unknown",
            "Nie potwierdzono pełnej dostępności UDP/TCP dla wszystkich testowanych endpointów; "
            + "; ".join(details)
            + ". Timeout lub brak odpowiedzi nie są automatycznie traktowane jako awaria serwera.",
            AUTHORITATIVE_TCP_WEIGHT,
            0,
            False,
        )

    if all(endpoint.status == TRANSPORT_BOTH_RESPOND for endpoint in endpoints):
        return AuthoritativeDnsFinding(
            "Authoritative DNS transport",
            "pass",
            "Każdy testowany endpoint autorytatywny zwrócił odpowiedź zarówno przez UDP, jak i TCP.",
            AUTHORITATIVE_TCP_WEIGHT,
            AUTHORITATIVE_TCP_WEIGHT,
        )

    return AuthoritativeDnsFinding(
        "Authoritative DNS transport",
        "unknown",
        "Stan transportu UDP/TCP jest niejednoznaczny.",
        AUTHORITATIVE_TCP_WEIGHT,
        0,
        False,
    )


def _soa_authority_finding(analysis: AuthoritativeDnsAnalysis) -> AuthoritativeDnsFinding:
    if not analysis.servers:
        return AuthoritativeDnsFinding(
            "Authoritative SOA service",
            "unknown",
            "Brak użytecznych delegowanych serwerów do bezpośredniego testu SOA.",
            applicable=False,
        )

    not_authoritative = _servers_by_authority(analysis, SOA_AUTHORITY_NOT_AUTHORITATIVE)
    no_soa = _servers_by_authority(analysis, SOA_AUTHORITY_NO_SOA)
    mixed = _servers_by_authority(analysis, SOA_AUTHORITY_MIXED)
    unknown = _servers_by_authority(
        analysis,
        SOA_AUTHORITY_UNKNOWN,
        SOA_AUTHORITY_UNPROBED,
    )

    if not_authoritative:
        return AuthoritativeDnsFinding(
            "Authoritative SOA service",
            "fail",
            "Delegowane serwery odpowiedziały bez autorytatywnej odpowiedzi SOA dla strefy: "
            + _names(not_authoritative)
            + ".",
        )
    if no_soa:
        return AuthoritativeDnsFinding(
            "Authoritative SOA service",
            "unknown",
            "Bezpośrednie odpowiedzi DNS z delegowanych NS nie dostarczyły użytecznego apex SOA dla: "
            + _names(no_soa)
            + ". Sam brak użytecznego RRsetu w tej ścieżce pomiarowej nie jest traktowany jako potwierdzona awaria usługi SOA.",
            applicable=False,
        )
    if mixed:
        return AuthoritativeDnsFinding(
            "Authoritative SOA service",
            "warn",
            "Zaobserwowano mieszane wyniki SOA między endpointami/transportami delegowanych NS: "
            + _names(mixed)
            + ". Co najmniej jedna ścieżka potwierdziła autorytatywne SOA, ale zachowanie nie było spójne.",
        )
    if unknown:
        return AuthoritativeDnsFinding(
            "Authoritative SOA service",
            "unknown",
            "Nie udało się wiarygodnie potwierdzić autorytatywnego SOA dla: "
            + _names(unknown)
            + ".",
            applicable=False,
        )
    if all(server.soa_authority_status == SOA_AUTHORITY_AUTHORITATIVE for server in analysis.servers):
        return AuthoritativeDnsFinding(
            "Authoritative SOA service",
            "pass",
            "Każdy testowany delegowany serwer zwrócił autorytatywne SOA dla strefy.",
        )
    return AuthoritativeDnsFinding(
        "Authoritative SOA service",
        "unknown",
        "Stan autorytatywnej obsługi SOA jest niejednoznaczny.",
        applicable=False,
    )


def _soa_config_finding(analysis: AuthoritativeDnsAnalysis) -> AuthoritativeDnsFinding:
    if analysis.soa_configuration_consistent is True:
        return AuthoritativeDnsFinding(
            "Authoritative SOA consistency",
            "pass",
            "Zaobserwowane serwery autorytatywne mają zgodne pola SOA MNAME/refresh/retry/expire/minimum.",
        )
    if analysis.soa_configuration_consistent is False:
        fields = _names(analysis.soa_differing_fields) or "pola SOA"
        return AuthoritativeDnsFinding(
            "Authoritative SOA consistency",
            "warn",
            "Zaobserwowano różnice konfiguracji SOA między odpowiedziami autorytatywnymi; różniące się pola: "
            + fields
            + ".",
        )
    return AuthoritativeDnsFinding(
        "Authoritative SOA consistency",
        "unknown",
        "Brak wystarczająco kompletnego zestawu autorytatywnych SOA do wiarygodnego porównania konfiguracji.",
        applicable=False,
    )


def _serial_finding(analysis: AuthoritativeDnsAnalysis) -> AuthoritativeDnsFinding:
    if analysis.soa_serial_consistent is True:
        return AuthoritativeDnsFinding(
            "Authoritative SOA serial",
            "pass",
            "Zaobserwowane serwery autorytatywne zwróciły ten sam numer seryjny SOA.",
        )
    if analysis.soa_serial_consistent is False:
        details = "; ".join(
            f"{name}: {', '.join(str(value) for value in serials)}"
            for name, serials in analysis.soa_serials
        )
        suffix = f" ({details})" if details else ""
        return AuthoritativeDnsFinding(
            "Authoritative SOA serial",
            "info",
            "Zaobserwowano różne numery seryjne SOA między serwerami autorytatywnymi"
            + suffix
            + ". Może to być przejściowy stan propagacji strefy.",
        )
    return AuthoritativeDnsFinding(
        "Authoritative SOA serial",
        "unknown",
        "Brak wystarczająco kompletnego zestawu SOA do porównania numerów seryjnych.",
        applicable=False,
    )


def _ns_finding(analysis: AuthoritativeDnsAnalysis) -> AuthoritativeDnsFinding:
    if analysis.ns_rrset_consistent is True:
        return AuthoritativeDnsFinding(
            "Authoritative NS RRset consistency",
            "pass",
            "Testowane serwery autorytatywne zwróciły zgodny apex NS RRset.",
            AUTHORITATIVE_RRSET_WEIGHT,
            AUTHORITATIVE_RRSET_WEIGHT,
        )
    if analysis.ns_rrset_consistent is False:
        details = "; ".join(
            f"{name}: {', '.join(values)}"
            for name, values in analysis.observed_ns_rrsets
        )
        suffix = f" ({details})" if details else ""
        return AuthoritativeDnsFinding(
            "Authoritative NS RRset consistency",
            "warn",
            "Zaobserwowano materialną różnicę apex NS RRset między serwerami autorytatywnymi"
            + suffix
            + ".",
            AUTHORITATIVE_RRSET_WEIGHT,
            0,
        )
    return AuthoritativeDnsFinding(
        "Authoritative NS RRset consistency",
        "unknown",
        "Brak kompletnego zestawu autorytatywnych odpowiedzi NS do porównania RRsetów.",
        AUTHORITATIVE_RRSET_WEIGHT,
        0,
        False,
    )


def _edns_finding(analysis: AuthoritativeDnsAnalysis) -> AuthoritativeDnsFinding:
    if not analysis.servers:
        return AuthoritativeDnsFinding(
            "Authoritative EDNS(0)",
            "unknown",
            "Brak użytecznych serwerów do ograniczonej obserwacji EDNS(0).",
            applicable=False,
        )

    anomalies = tuple(server.name for server in analysis.servers if server.edns_status == EDNS_ANOMALY)
    unknown = tuple(
        server.name
        for server in analysis.servers
        if server.edns_status in {EDNS_UNKNOWN, EDNS_NOT_TESTED}
    )
    if anomalies:
        return AuthoritativeDnsFinding(
            "Authoritative EDNS(0)",
            "warn",
            "Zwykłe zapytanie UDP SOA działało, ale ograniczone zapytanie EDNS(0) zwróciło anomalię dla: "
            + _names(anomalies)
            + ". Obserwacja jest doradcza i nie stanowi pełnego testu EDNS.",
        )
    if unknown:
        return AuthoritativeDnsFinding(
            "Authoritative EDNS(0)",
            "unknown",
            "Nie udało się jednoznacznie porównać zwykłego UDP z EDNS(0) dla: "
            + _names(unknown)
            + ".",
            applicable=False,
        )
    if all(server.edns_status == EDNS_OK for server in analysis.servers):
        return AuthoritativeDnsFinding(
            "Authoritative EDNS(0)",
            "pass",
            "Ograniczone zapytanie EDNS(0) SOA zakończyło się poprawnie na każdym testowanym serwerze.",
        )
    return AuthoritativeDnsFinding(
        "Authoritative EDNS(0)",
        "unknown",
        "Stan obserwacji EDNS(0) jest niejednoznaczny.",
        applicable=False,
    )


def build_authoritative_dns_findings(
    evidence: AuthoritativeDnsEvidence,
    analysis: AuthoritativeDnsAnalysis,
) -> tuple[AuthoritativeDnsFinding, ...]:
    """Convert issue #15 analysis into conservative impact-calibrated checks."""
    _ = evidence
    return (
        _transport_finding(analysis),
        _soa_authority_finding(analysis),
        _soa_config_finding(analysis),
        _serial_finding(analysis),
        _ns_finding(analysis),
        _edns_finding(analysis),
    )


__all__ = [
    "AuthoritativeDnsFinding",
    "build_authoritative_dns_findings",
]
