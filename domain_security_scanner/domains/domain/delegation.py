from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace

from ...models import DnsQueryResult, DnsQueryState, DnsTransport


MAX_PARENT_DELEGATION_ATTEMPTS = 4
DELEGATION_DIRECT_TIMEOUT = 1.5
MAX_DELEGATED_ADDRESS_PROBES_PER_NS = 2
MAX_DELEGATED_AUTHORITY_PROBES = 16


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
    """Recursive A/AAAA evidence for one DNS server name."""

    name: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    a_result: DnsQueryResult | None = None
    aaaa_result: DnsQueryResult | None = None
    cname_result: DnsQueryResult | None = None

    @property
    def addresses(self) -> tuple[str, ...]:
        return self.ipv4 + self.ipv6

    @property
    def lookup_failed(self) -> bool:
        """Whether either address-family lookup produced unavailable evidence."""
        return any(
            result is not None and result.failed
            for result in (self.a_result, self.aaaa_result)
        )

    @property
    def conclusively_no_address(self) -> bool:
        """Whether both A and AAAA are conclusively absent."""
        results = (self.a_result, self.aaaa_result)
        return (
            not self.addresses
            and all(result is not None and result.absent for result in results)
        )


@dataclass(frozen=True)
class DelegationGlueEvidence:
    """Address records carried in a parent referral's additional section."""

    name: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()

    @property
    def addresses(self) -> tuple[str, ...]:
        return self.ipv4 + self.ipv6


@dataclass(frozen=True)
class DelegationReferral:
    """Structured NS/glue data extracted from one parent referral response."""

    nameservers: tuple[str, ...]
    glue: tuple[DelegationGlueEvidence, ...] = ()


@dataclass(frozen=True)
class DelegatedNameserverEvidence:
    """Reachability and direct-authority evidence for one delegated NS name."""

    name: str
    addresses: NameserverAddressEvidence
    glue: DelegationGlueEvidence | None = None
    candidate_addresses: tuple[str, ...] = ()
    probe_addresses: tuple[str, ...] = ()
    unprobed_addresses: tuple[str, ...] = ()
    authority_queries: tuple[DnsQueryResult, ...] = ()

    @property
    def has_usable_address(self) -> bool:
        return bool(self.candidate_addresses)

    @property
    def has_authoritative_answer(self) -> bool:
        """Whether at least one tested address positively served authoritative NS."""
        return any(
            result.state == DnsQueryState.ANSWER and result.aa is True
            for result in self.authority_queries
        )


@dataclass(frozen=True)
class ParentDelegationEvidence:
    """Internal delegation evidence for one registered/root domain."""

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
    delegated_servers: tuple[DelegatedNameserverEvidence, ...] = ()
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


def _canonical_address_union(*groups: tuple[str, ...]) -> tuple[str, ...]:
    """Return unique canonical IP addresses with IPv4 before IPv6."""
    ipv4: set[str] = set()
    ipv6: set[str] = set()

    for group in groups:
        for value in group:
            try:
                address = ipaddress.ip_address(str(value).strip())
            except ValueError:
                continue
            if address.version == 4:
                ipv4.add(str(address))
            else:
                ipv6.add(str(address))

    return tuple(sorted(ipv4)) + tuple(sorted(ipv6))


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
    """Collect delegation evidence without emitting delegation findings yet."""

    def collect_domain_dns(self):
        """Collect and analyze delegation evidence before the existing Domain DNS step."""
        evidence = self.collect_parent_delegation()
        if evidence is not None:
            evidence = self.collect_delegated_nameserver_evidence(evidence)
            self.analyze_delegation_evidence(evidence)
        return super().collect_domain_dns()

    def collect_parent_delegation(self) -> ParentDelegationEvidence:
        """Collect a bounded, direct parent referral for ``root_domain``."""
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
                    timeout=DELEGATION_DIRECT_TIMEOUT,
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

    def collect_delegated_nameserver_evidence(
        self,
        evidence: ParentDelegationEvidence,
    ) -> ParentDelegationEvidence:
        """Collect per-delegated-NS A/AAAA and direct authority evidence.

        Recursive A/AAAA results are retained even when they fail so later
        analysis can distinguish a confirmed lack of addresses from unavailable
        resolver evidence. Parent-referral glue is also retained and can provide
        a usable direct-query endpoint when recursive resolution is unavailable.

        Direct authority testing is intentionally UDP-only here. TCP/UDP
        transport comparison belongs to issue #15.
        """
        if not evidence.delegated_nameservers:
            self.delegation = evidence
            return evidence

        glue_by_name = {item.name: item for item in evidence.glue}
        prepared: list[
            tuple[
                str,
                NameserverAddressEvidence,
                DelegationGlueEvidence | None,
                tuple[str, ...],
            ]
        ] = []

        for nameserver in evidence.delegated_nameservers:
            name = normalize_dns_name(nameserver)
            a_result = self.dns_query_result(name, "A")
            aaaa_result = self.dns_query_result(name, "AAAA")
            cname_result = self.dns_query_result(name, "CNAME")
            ipv4 = _canonical_ip_records(a_result.records, version=4)
            ipv6 = _canonical_ip_records(aaaa_result.records, version=6)
            addresses = NameserverAddressEvidence(
                name=name,
                ipv4=ipv4,
                ipv6=ipv6,
                a_result=a_result,
                aaaa_result=aaaa_result,
                cname_result=cname_result,
            )
            glue = glue_by_name.get(name)
            candidates = _canonical_address_union(
                addresses.ipv4,
                addresses.ipv6,
                glue.ipv4 if glue else (),
                glue.ipv6 if glue else (),
            )
            prepared.append((name, addresses, glue, candidates))

        # Issue #14 needs server-level authority proof, not exhaustive endpoint
        # testing. Probe one deterministic endpoint per delegated NS first, then
        # use at most one fallback endpoint only when the first probe did not
        # positively establish authoritative service. This keeps every NS in the
        # first round while avoiding slow duplicate IPv4/IPv6 probes on healthy
        # multi-address providers. Exhaustive transport/family consistency belongs
        # to issue #15.
        probes_by_name: dict[str, list[str]] = {
            name: [] for name, *_ in prepared
        }
        queries_by_name: dict[str, list[DnsQueryResult]] = {
            name: [] for name, *_ in prepared
        }
        total_probes = 0

        for address_index in range(MAX_DELEGATED_ADDRESS_PROBES_PER_NS):
            if total_probes >= MAX_DELEGATED_AUTHORITY_PROBES:
                break
            for name, _addresses, _glue, candidates in prepared:
                if total_probes >= MAX_DELEGATED_AUTHORITY_PROBES:
                    break
                if address_index >= len(candidates):
                    continue
                if any(
                    result.state == DnsQueryState.ANSWER and result.aa is True
                    for result in queries_by_name[name]
                ):
                    continue

                server_ip = candidates[address_index]
                result = self.authoritative_dns_query_result(
                    evidence.zone,
                    "NS",
                    server_name=name,
                    server_ip=server_ip,
                    transport=DnsTransport.UDP,
                    timeout=DELEGATION_DIRECT_TIMEOUT,
                )
                probes_by_name[name].append(server_ip)
                queries_by_name[name].append(result)
                total_probes += 1

        delegated_servers: list[DelegatedNameserverEvidence] = []
        for name, addresses, glue, candidates in prepared:
            probe_addresses = tuple(probes_by_name[name])
            probe_set = set(probe_addresses)
            unprobed = tuple(
                address for address in candidates if address not in probe_set
            )
            delegated_servers.append(
                DelegatedNameserverEvidence(
                    name=name,
                    addresses=addresses,
                    glue=glue,
                    candidate_addresses=candidates,
                    probe_addresses=probe_addresses,
                    unprobed_addresses=unprobed,
                    authority_queries=tuple(queries_by_name[name]),
                )
            )

        enriched = replace(
            evidence,
            delegated_servers=tuple(delegated_servers),
        )
        self.delegation = enriched
        return enriched


    def analyze_delegation_evidence(
        self,
        evidence: ParentDelegationEvidence,
    ):
        """Run pure delegation analysis over already-collected DNS evidence."""
        from .delegation_analysis import analyze_delegation

        analysis = analyze_delegation(evidence)
        self.delegation_analysis = analysis
        return analysis


__all__ = [
    "MAX_PARENT_DELEGATION_ATTEMPTS",
    "DELEGATION_DIRECT_TIMEOUT",
    "MAX_DELEGATED_ADDRESS_PROBES_PER_NS",
    "MAX_DELEGATED_AUTHORITY_PROBES",
    "DelegatedNameserverEvidence",
    "DelegationGlueEvidence",
    "DelegationReferral",
    "DelegationScanMixin",
    "NameserverAddressEvidence",
    "ParentDelegationEvidence",
    "normalize_dns_name",
    "parent_zone_name",
    "referral_from_result",
]
