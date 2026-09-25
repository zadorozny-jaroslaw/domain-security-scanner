from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ...models import DnsQueryResult, DnsQueryState
from .delegation import (
    DelegatedNameserverEvidence,
    ParentDelegationEvidence,
    normalize_dns_name,
)


AUTHORITY_AUTHORITATIVE = "authoritative"
AUTHORITY_MIXED = "mixed"
AUTHORITY_LAME = "lame"
AUTHORITY_AUTHORITATIVE_NO_NS = "authoritative_no_ns"
AUTHORITY_UNKNOWN = "unknown"
AUTHORITY_NO_ADDRESS = "no_address"
AUTHORITY_UNPROBED = "unprobed"

ADDRESS_AVAILABLE = "available"
ADDRESS_NO_ADDRESS = "no_address"
ADDRESS_UNKNOWN = "unknown"

ALIAS_DIRECT = "direct"
ALIAS_ALIAS = "alias"
ALIAS_UNKNOWN = "unknown"

GLUE_NOT_REQUIRED = "not_required"
GLUE_PRESENT = "present"
GLUE_MISSING = "missing"


@dataclass(frozen=True)
class ChildNameserverView:
    """One authoritative server/address view of the child apex NS RRset."""

    server_name: str
    server_ip: str | None
    nameservers: tuple[str, ...]


@dataclass(frozen=True)
class NameserverDelegationAnalysis:
    """Pure analysis for one parent-delegated nameserver."""

    name: str
    in_bailiwick: bool
    address_status: str
    alias_status: str
    alias_targets: tuple[str, ...]
    authority_status: str
    authoritative_child_views: tuple[ChildNameserverView, ...]
    glue_status: str
    glue_consistent: bool | None
    glue_only_addresses: tuple[str, ...]
    resolved_only_addresses: tuple[str, ...]


@dataclass(frozen=True)
class DelegationAnalysis:
    """Pure parent/child delegation analysis suitable for later findings."""

    zone: str
    parent_nameservers: tuple[str, ...]
    child_views: tuple[ChildNameserverView, ...]
    observed_child_nameservers: tuple[str, ...]
    parent_child_consistent: bool | None
    parent_child_complete: bool
    missing_from_child: tuple[str, ...]
    extra_in_child: tuple[str, ...]
    nameservers: tuple[NameserverDelegationAnalysis, ...]


def _section_records(
    section: tuple[str, ...],
) -> tuple[tuple[str, str, str], ...]:
    parsed: list[tuple[str, str, str]] = []
    for rrset_text in section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            owner, _ttl, _rdclass, rtype, rdata = parts
            parsed.append(
                (
                    normalize_dns_name(owner),
                    rtype.upper(),
                    rdata.strip(),
                )
            )
    return tuple(parsed)


def child_ns_from_result(
    result: DnsQueryResult,
    zone: str,
) -> tuple[str, ...]:
    """Extract a positively authoritative child apex NS RRset."""

    if (
        result.state != DnsQueryState.ANSWER
        or result.aa is not True
        or result.rcode != "NOERROR"
        or result.tc is True
    ):
        return ()

    zone_name = normalize_dns_name(zone)
    return tuple(
        sorted(
            {
                normalize_dns_name(rdata)
                for owner, rtype, rdata in _section_records(result.answer_section)
                if owner == zone_name and rtype == "NS"
            }
        )
    )


def _canonical_ip_set(values: tuple[str, ...]) -> set[str]:
    addresses: set[str] = set()
    for value in values:
        try:
            addresses.add(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    return addresses


def _is_in_bailiwick(name: str, zone: str) -> bool:
    normalized_name = normalize_dns_name(name)
    normalized_zone = normalize_dns_name(zone)
    return (
        normalized_name == normalized_zone
        or normalized_name.endswith("." + normalized_zone)
    )


def _address_status(server: DelegatedNameserverEvidence) -> str:
    if server.candidate_addresses:
        return ADDRESS_AVAILABLE
    if server.addresses.conclusively_no_address:
        return ADDRESS_NO_ADDRESS
    return ADDRESS_UNKNOWN


def _alias_analysis(
    server: DelegatedNameserverEvidence,
) -> tuple[str, tuple[str, ...]]:
    result = server.addresses.cname_result
    if result is None or result.failed:
        return ALIAS_UNKNOWN, ()
    if result.state == DnsQueryState.ANSWER and result.records:
        targets = tuple(
            sorted(
                {
                    normalize_dns_name(record)
                    for record in result.records
                    if normalize_dns_name(record)
                }
            )
        )
        return ALIAS_ALIAS, targets
    if result.absent:
        return ALIAS_DIRECT, ()
    return ALIAS_UNKNOWN, ()


def _authority_analysis(
    server: DelegatedNameserverEvidence,
    zone: str,
) -> tuple[str, tuple[ChildNameserverView, ...]]:
    if not server.candidate_addresses:
        if server.addresses.conclusively_no_address:
            return AUTHORITY_NO_ADDRESS, ()
        return AUTHORITY_UNKNOWN, ()

    if not server.authority_queries:
        return AUTHORITY_UNPROBED, ()

    views: list[ChildNameserverView] = []
    saw_not_authoritative = False
    saw_unknown = False
    saw_authoritative_without_ns = False

    for result in server.authority_queries:
        child_ns = child_ns_from_result(result, zone)
        if child_ns:
            views.append(
                ChildNameserverView(
                    server_name=server.name,
                    server_ip=result.server_ip,
                    nameservers=child_ns,
                )
            )
            continue

        if result.state == DnsQueryState.NOT_AUTHORITATIVE:
            saw_not_authoritative = True
        elif result.state == DnsQueryState.ANSWER and result.aa is True:
            saw_authoritative_without_ns = True
        else:
            saw_unknown = True

    if views:
        if saw_not_authoritative or saw_unknown or saw_authoritative_without_ns:
            return AUTHORITY_MIXED, tuple(views)
        return AUTHORITY_AUTHORITATIVE, tuple(views)

    if saw_not_authoritative and not saw_unknown and not saw_authoritative_without_ns:
        return AUTHORITY_LAME, ()

    if saw_authoritative_without_ns and not saw_not_authoritative and not saw_unknown:
        return AUTHORITY_AUTHORITATIVE_NO_NS, ()

    return AUTHORITY_UNKNOWN, ()


def _glue_analysis(
    server: DelegatedNameserverEvidence,
    zone: str,
) -> tuple[str, bool | None, tuple[str, ...], tuple[str, ...]]:
    if not _is_in_bailiwick(server.name, zone):
        return GLUE_NOT_REQUIRED, None, (), ()

    glue_addresses = _canonical_ip_set(
        server.glue.addresses if server.glue else ()
    )
    if not glue_addresses:
        return GLUE_MISSING, None, (), ()

    # Resolver/network failure makes current-address comparison inconclusive.
    if server.addresses.lookup_failed:
        return GLUE_PRESENT, None, (), ()

    resolved_addresses = _canonical_ip_set(server.addresses.addresses)
    glue_only = tuple(sorted(glue_addresses - resolved_addresses))
    resolved_only = tuple(sorted(resolved_addresses - glue_addresses))
    return (
        GLUE_PRESENT,
        not glue_only and not resolved_only,
        glue_only,
        resolved_only,
    )


def analyze_nameserver(
    server: DelegatedNameserverEvidence,
    zone: str,
) -> NameserverDelegationAnalysis:
    """Analyze one delegated NS without performing network I/O."""

    alias_status, alias_targets = _alias_analysis(server)
    authority_status, views = _authority_analysis(server, zone)
    glue_status, glue_consistent, glue_only, resolved_only = _glue_analysis(
        server,
        zone,
    )
    return NameserverDelegationAnalysis(
        name=server.name,
        in_bailiwick=_is_in_bailiwick(server.name, zone),
        address_status=_address_status(server),
        alias_status=alias_status,
        alias_targets=alias_targets,
        authority_status=authority_status,
        authoritative_child_views=views,
        glue_status=glue_status,
        glue_consistent=glue_consistent,
        glue_only_addresses=glue_only,
        resolved_only_addresses=resolved_only,
    )


def analyze_delegation(
    evidence: ParentDelegationEvidence,
) -> DelegationAnalysis:
    """Analyze collected delegation evidence without issuing DNS queries."""

    parent_ns = tuple(
        sorted({normalize_dns_name(name) for name in evidence.delegated_nameservers})
    )
    nameserver_analysis = tuple(
        analyze_nameserver(server, evidence.zone)
        for server in evidence.delegated_servers
    )
    child_views = tuple(
        view
        for server in nameserver_analysis
        for view in server.authoritative_child_views
    )

    observed_sets = [set(view.nameservers) for view in child_views]
    observed_union = set().union(*observed_sets) if observed_sets else set()
    observed_intersection = (
        set.intersection(*observed_sets)
        if observed_sets
        else set()
    )

    complete = bool(nameserver_analysis) and all(
        server.authority_status == AUTHORITY_AUTHORITATIVE
        for server in nameserver_analysis
    )

    parent_set = set(parent_ns)
    any_mismatch = any(child_set != parent_set for child_set in observed_sets)

    if any_mismatch:
        parent_child_consistent: bool | None = False
    elif complete and observed_sets:
        parent_child_consistent = True
    else:
        parent_child_consistent = None

    missing_from_child = tuple(sorted(parent_set - observed_intersection)) if observed_sets else ()
    extra_in_child = tuple(sorted(observed_union - parent_set)) if observed_sets else ()

    # A single stable value is exposed only when every observed child view agrees.
    unique_child_sets = {tuple(sorted(child_set)) for child_set in observed_sets}
    observed_child_nameservers = (
        next(iter(unique_child_sets))
        if len(unique_child_sets) == 1
        else ()
    )

    return DelegationAnalysis(
        zone=normalize_dns_name(evidence.zone),
        parent_nameservers=parent_ns,
        child_views=child_views,
        observed_child_nameservers=observed_child_nameservers,
        parent_child_consistent=parent_child_consistent,
        parent_child_complete=complete,
        missing_from_child=missing_from_child,
        extra_in_child=extra_in_child,
        nameservers=nameserver_analysis,
    )


__all__ = [
    "ADDRESS_AVAILABLE",
    "ADDRESS_NO_ADDRESS",
    "ADDRESS_UNKNOWN",
    "ALIAS_ALIAS",
    "ALIAS_DIRECT",
    "ALIAS_UNKNOWN",
    "AUTHORITY_AUTHORITATIVE",
    "AUTHORITY_AUTHORITATIVE_NO_NS",
    "AUTHORITY_LAME",
    "AUTHORITY_MIXED",
    "AUTHORITY_NO_ADDRESS",
    "AUTHORITY_UNKNOWN",
    "AUTHORITY_UNPROBED",
    "GLUE_MISSING",
    "GLUE_NOT_REQUIRED",
    "GLUE_PRESENT",
    "ChildNameserverView",
    "DelegationAnalysis",
    "NameserverDelegationAnalysis",
    "analyze_delegation",
    "analyze_nameserver",
    "child_ns_from_result",
]
