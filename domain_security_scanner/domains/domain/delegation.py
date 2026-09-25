from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ...models import DnsQueryResult, DnsTransport


MAX_PARENT_DELEGATION_ATTEMPTS = 4


def normalize_dns_name(value: str) -> str:
    """Normalize a DNS owner/target name for deterministic comparisons."""
    return str(value).strip().lower().rstrip(".")


def parent_zone_name(zone: str) -> str | None:
    """Return the immediate DNS parent of a registered/root domain."""
    normalized = normalize_dns_name(zone)
    labels = [label for label in normalized.split(".") if label]
    if len(labels) < 2:
        return None
    return ".".join(labels[1:])


@dataclass(frozen=True)
class NameserverAddressEvidence:
    """Recursive address evidence used to reach one parent authoritative server."""

    name: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    a_result: DnsQueryResult | None = None
    aaaa_result: DnsQueryResult | None = None

    @property
    def addresses(self) -> tuple[str, ...]:
        return self.ipv4 + self.ipv6


@dataclass(frozen=True)
class DelegationGlueEvidence:
    """Address records carried in a parent referral's additional section."""

    name: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()


@dataclass(frozen=True)
class DelegationReferral:
    """Structured NS/glue data extracted from one parent referral response."""

    nameservers: tuple[str, ...]
    glue: tuple[DelegationGlueEvidence, ...] = ()


@dataclass(frozen=True)
class ParentDelegationEvidence:
    """Internal parent-side delegation evidence for one registered/root domain."""

    zone: str
    parent_zone: str | None
    parent_ns_result: DnsQueryResult | None = None
    parent_nameservers: tuple[str, ...] = ()
    parent_server_addresses: tuple[NameserverAddressEvidence, ...] = ()
    delegation_queries: tuple[DnsQueryResult, ...] = ()
    delegated_nameservers: tuple[str, ...] = ()
    glue: tuple[DelegationGlueEvidence, ...] = ()
    source_server_name: str | None = None
    source_server_ip: str | None = None
    error: str | None = None

    @property
    def available(self) -> bool:
        """Whether a usable parent referral was collected."""
        return bool(
            self.delegated_nameservers
            and self.source_server_ip
            and self.parent_zone
        )


def _canonical_ip_records(
    records: tuple[str, ...],
    *,
    version: int,
) -> tuple[str, ...]:
    values: set[str] = set()
    for record in records:
        try:
            address = ipaddress.ip_address(str(record).strip())
        except ValueError:
            continue
        if address.version == version:
            values.add(str(address))
    return tuple(sorted(values))


def _section_records(
    section: tuple[str, ...],
) -> tuple[tuple[str, str, str], ...]:
    """Parse stored RRset text into owner/type/RDATA triples.

    ``DnsQueryResult`` deliberately stores DNS sections as text so the shared
    evidence layer remains serialization-agnostic. RRset ``to_text()`` output is
    stable enough for the focused NS/A/AAAA extraction needed here.
    """
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


def referral_from_result(
    result: DnsQueryResult,
    zone: str,
) -> DelegationReferral | None:
    """Extract an NS referral for ``zone`` from direct parent-server evidence.

    A normal parent referral has ``AA=0`` for the child name, so the shared
    authoritative query layer correctly labels it ``NOT_AUTHORITATIVE`` when
    interpreted as child-authority evidence. For delegation discovery, the raw
    NOERROR authority/additional sections are the relevant evidence instead.
    """
    zone_name = normalize_dns_name(zone)
    if result.rcode != "NOERROR" or result.tc is True:
        return None

    authority = _section_records(result.authority_section)
    nameservers = tuple(
        sorted(
            {
                normalize_dns_name(rdata)
                for owner, rtype, rdata in authority
                if owner == zone_name and rtype == "NS"
            }
        )
    )
    if not nameservers:
        return None

    additional = _section_records(result.additional_section)
    glue_by_name: dict[str, dict[int, set[str]]] = {
        name: {4: set(), 6: set()} for name in nameservers
    }
    for owner, rtype, rdata in additional:
        if owner not in glue_by_name or rtype not in {"A", "AAAA"}:
            continue
        try:
            address = ipaddress.ip_address(rdata)
        except ValueError:
            continue
        expected_version = 4 if rtype == "A" else 6
        if address.version != expected_version:
            continue
        glue_by_name[owner][address.version].add(str(address))

    glue = tuple(
        DelegationGlueEvidence(
            name=name,
            ipv4=tuple(sorted(glue_by_name[name][4])),
            ipv6=tuple(sorted(glue_by_name[name][6])),
        )
        for name in nameservers
        if glue_by_name[name][4] or glue_by_name[name][6]
    )
    return DelegationReferral(nameservers=nameservers, glue=glue)


class DelegationScanMixin:
    """Collect parent-side delegation evidence without emitting findings yet."""

    def collect_domain_dns(self):
        """Collect delegation evidence before the existing Domain DNS step."""
        self.collect_parent_delegation()
        return super().collect_domain_dns()

    def collect_parent_delegation(self) -> ParentDelegationEvidence:
        """Collect a bounded, direct parent referral for ``root_domain``.

        This first #14 slice intentionally stops at parent-side evidence. Child
        nameserver addressability, per-delegated-server authority checks, and
        delegation findings are added in later slices.
        """
        zone = normalize_dns_name(self.root_domain)
        parent_zone = parent_zone_name(zone)
        if parent_zone is None:
            evidence = ParentDelegationEvidence(
                zone=zone,
                parent_zone=None,
                error="Registered/root domain has no queryable DNS parent",
            )
            self.delegation = evidence
            return evidence

        parent_ns_result = self.dns_query_result(parent_zone, "NS")
        parent_nameservers = tuple(
            sorted(
                {
                    normalize_dns_name(record)
                    for record in parent_ns_result.records
                    if normalize_dns_name(record)
                }
            )
        )
        if parent_ns_result.failed or not parent_nameservers:
            reason = (
                self._dns_unavailable_message(parent_ns_result)
                if parent_ns_result.failed
                else "parent NS set unavailable"
            )
            evidence = ParentDelegationEvidence(
                zone=zone,
                parent_zone=parent_zone,
                parent_ns_result=parent_ns_result,
                parent_nameservers=parent_nameservers,
                error=reason,
            )
            self.delegation = evidence
            return evidence

        address_evidence: list[NameserverAddressEvidence] = []
        delegation_queries: list[DnsQueryResult] = []
        attempts = 0

        for parent_ns in parent_nameservers:
            a_result = self.dns_query_result(parent_ns, "A")
            aaaa_result = self.dns_query_result(parent_ns, "AAAA")
            ipv4 = _canonical_ip_records(a_result.records, version=4)
            ipv6 = _canonical_ip_records(aaaa_result.records, version=6)
            addresses = NameserverAddressEvidence(
                name=parent_ns,
                ipv4=ipv4,
                ipv6=ipv6,
                a_result=a_result,
                aaaa_result=aaaa_result,
            )
            address_evidence.append(addresses)

            for server_ip in addresses.addresses:
                if attempts >= MAX_PARENT_DELEGATION_ATTEMPTS:
                    break
                attempts += 1
                result = self.authoritative_dns_query_result(
                    zone,
                    "NS",
                    server_name=parent_ns,
                    server_ip=server_ip,
                    transport=DnsTransport.UDP,
                )
                delegation_queries.append(result)
                referral = referral_from_result(result, zone)
                if referral is not None:
                    evidence = ParentDelegationEvidence(
                        zone=zone,
                        parent_zone=parent_zone,
                        parent_ns_result=parent_ns_result,
                        parent_nameservers=parent_nameservers,
                        parent_server_addresses=tuple(address_evidence),
                        delegation_queries=tuple(delegation_queries),
                        delegated_nameservers=referral.nameservers,
                        glue=referral.glue,
                        source_server_name=parent_ns,
                        source_server_ip=server_ip,
                    )
                    self.delegation = evidence
                    return evidence

            if attempts >= MAX_PARENT_DELEGATION_ATTEMPTS:
                break

        evidence = ParentDelegationEvidence(
            zone=zone,
            parent_zone=parent_zone,
            parent_ns_result=parent_ns_result,
            parent_nameservers=parent_nameservers,
            parent_server_addresses=tuple(address_evidence),
            delegation_queries=tuple(delegation_queries),
            error="No usable parent delegation referral was obtained",
        )
        self.delegation = evidence
        return evidence


__all__ = [
    "MAX_PARENT_DELEGATION_ATTEMPTS",
    "DelegationGlueEvidence",
    "DelegationReferral",
    "DelegationScanMixin",
    "NameserverAddressEvidence",
    "ParentDelegationEvidence",
    "normalize_dns_name",
    "parent_zone_name",
    "referral_from_result",
]
