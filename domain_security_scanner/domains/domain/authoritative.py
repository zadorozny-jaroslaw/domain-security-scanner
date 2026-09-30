from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import dns.rdata
import dns.rdataclass
import dns.rdatatype

from ...models import DnsQueryResult, DnsQueryState, DnsTransport
from .delegation import DelegatedNameserverEvidence, ParentDelegationEvidence, normalize_dns_name


AUTHORITATIVE_DIRECT_TIMEOUT = 1.5
AUTHORITATIVE_EDNS_PAYLOAD = 1232
MAX_AUTHORITATIVE_ENDPOINTS_PER_NS = 2
MAX_AUTHORITATIVE_ENDPOINT_PROBES = 16


@dataclass(frozen=True)
class SoaRecord:
    """Normalized SOA fields suitable for deterministic comparison."""

    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass(frozen=True)
class SoaObservation:
    """One direct SOA query plus its normalized record when parseable."""

    result: DnsQueryResult
    soa: SoaRecord | None = None
    parse_error: str | None = None


@dataclass(frozen=True)
class AuthoritativeEndpointEvidence:
    """Transport and EDNS evidence for one authoritative server address."""

    server_name: str
    server_ip: str
    udp_soa: SoaObservation
    tcp_soa: SoaObservation
    edns_soa: SoaObservation | None = None


@dataclass(frozen=True)
class AuthoritativeServerEvidence:
    """Issue #15 collection evidence for one delegated nameserver name."""

    name: str
    candidate_addresses: tuple[str, ...]
    probe_addresses: tuple[str, ...]
    unprobed_addresses: tuple[str, ...]
    apex_ns_result: DnsQueryResult | None = None
    apex_nameservers: tuple[str, ...] = ()
    endpoints: tuple[AuthoritativeEndpointEvidence, ...] = ()


@dataclass(frozen=True)
class AuthoritativeDnsEvidence:
    """Structured authoritative transport/zone evidence for one DNS zone."""

    zone: str
    servers: tuple[AuthoritativeServerEvidence, ...]
    endpoint_probe_limit: int = MAX_AUTHORITATIVE_ENDPOINT_PROBES
    endpoint_probe_limit_reached: bool = False


def _section_records(
    section: tuple[str, ...],
) -> tuple[tuple[str, str, str], ...]:
    """Parse stored RRset text into owner/type/RDATA triples."""
    parsed: list[tuple[str, str, str]] = []
    for rrset_text in section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            owner, _ttl, _rdclass, rtype, rdata = parts
            parsed.append(
                (normalize_dns_name(owner), rtype.upper(), rdata.strip())
            )
    return tuple(parsed)


def soa_from_result(result: DnsQueryResult, zone: str) -> tuple[SoaRecord | None, str | None]:
    """Extract one authoritative apex SOA from stored query evidence."""
    if (
        result.state != DnsQueryState.ANSWER
        or result.aa is not True
        or result.rcode != "NOERROR"
        or result.tc is True
    ):
        return None, None

    zone_name = normalize_dns_name(zone)
    records = [
        rdata
        for owner, rtype, rdata in _section_records(result.answer_section)
        if owner == zone_name and rtype == "SOA"
    ]
    if not records:
        return None, "Authoritative SOA answer did not contain an apex SOA RRset"
    if len(records) != 1:
        return None, f"Authoritative SOA answer contained {len(records)} apex SOA records"

    try:
        record = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            records[0],
        )
        return (
            SoaRecord(
                mname=normalize_dns_name(record.mname.to_text()),
                rname=normalize_dns_name(record.rname.to_text()),
                serial=int(record.serial),
                refresh=int(record.refresh),
                retry=int(record.retry),
                expire=int(record.expire),
                minimum=int(record.minimum),
            ),
            None,
        )
    except Exception as exc:
        text = " ".join(str(exc).split()).strip() or exc.__class__.__name__
        return None, f"Unable to parse authoritative SOA: {text[:180]}"


def soa_observation(result: DnsQueryResult, zone: str) -> SoaObservation:
    soa, parse_error = soa_from_result(result, zone)
    return SoaObservation(result=result, soa=soa, parse_error=parse_error)


def apex_ns_from_result(result: DnsQueryResult, zone: str) -> tuple[str, ...]:
    """Extract a positively authoritative apex NS RRset from query evidence.

    Some authoritative implementations return an apex NS RRset in the DNS
    authority section even for a direct NS query. Treat that as usable child
    evidence only when the response itself is positively authoritative (AA=1),
    NOERROR, and not truncated. The generic query state may still be ERROR
    because the shared evidence layer intentionally does not reinterpret
    authority-section data as an answer for arbitrary RR types.
    """
    if (
        result.aa is not True
        or result.rcode != "NOERROR"
        or result.tc is True
    ):
        return ()

    zone_name = normalize_dns_name(zone)
    sections = result.answer_section + result.authority_section
    return tuple(
        sorted(
            {
                normalize_dns_name(rdata)
                for owner, rtype, rdata in _section_records(sections)
                if owner == zone_name and rtype == "NS"
            }
        )
    )


def _family_probe_addresses(
    server: DelegatedNameserverEvidence,
) -> tuple[str, ...]:
    """Choose at most one deterministic endpoint from each available IP family.

    Prefer an endpoint that issue #14 already proved authoritative. This both
    improves the quality of the transport comparison and maximizes reuse of the
    cached apex-NS query. Fall back to the first canonical address in each family.
    """
    by_family: dict[int, list[str]] = {4: [], 6: []}
    authoritative_by_family: dict[int, list[str]] = {4: [], 6: []}
    seen: set[str] = set()

    for value in server.candidate_addresses:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        canonical = str(address)
        if canonical in seen:
            continue
        seen.add(canonical)
        by_family[address.version].append(canonical)

    for result in server.authority_queries:
        if (
            result.state != DnsQueryState.ANSWER
            or result.aa is not True
            or not result.server_ip
        ):
            continue
        try:
            address = ipaddress.ip_address(result.server_ip)
        except ValueError:
            continue
        canonical = str(address)
        if canonical in by_family[address.version]:
            authoritative_by_family[address.version].append(canonical)

    selected: list[str] = []
    for version in (4, 6):
        preferred = sorted(set(authoritative_by_family[version]))
        available = sorted(by_family[version])
        if preferred:
            selected.append(preferred[0])
        elif available:
            selected.append(available[0])

    return tuple(selected[:MAX_AUTHORITATIVE_ENDPOINTS_PER_NS])


def _same_family_fallback(
    server: DelegatedNameserverEvidence,
    primary_ip: str,
    attempted: set[str],
) -> str | None:
    """Return one unused candidate in the primary endpoint's address family."""
    try:
        primary_version = ipaddress.ip_address(primary_ip).version
    except ValueError:
        return None

    for value in server.candidate_addresses:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        canonical = str(address)
        if address.version != primary_version or canonical in attempted:
            continue
        return canonical
    return None


def _probe_plan(
    servers: tuple[DelegatedNameserverEvidence, ...],
) -> dict[str, tuple[str, ...]]:
    """Build a fair, bounded endpoint plan with every NS getting first chance."""
    candidates = {
        server.name: _family_probe_addresses(server)
        for server in servers
    }
    selected: dict[str, list[str]] = {server.name: [] for server in servers}
    total = 0

    for address_index in range(MAX_AUTHORITATIVE_ENDPOINTS_PER_NS):
        for server in servers:
            if total >= MAX_AUTHORITATIVE_ENDPOINT_PROBES:
                break
            addresses = candidates[server.name]
            if address_index >= len(addresses):
                continue
            selected[server.name].append(addresses[address_index])
            total += 1
        if total >= MAX_AUTHORITATIVE_ENDPOINT_PROBES:
            break

    return {name: tuple(values) for name, values in selected.items()}


class AuthoritativeDnsScanMixin:
    """Collect and analyze issue #15 authoritative transport/SOA evidence."""

    def collect_domain_dns(self):
        delegation = getattr(self, "delegation", None)
        self.authoritative_dns = self.collect_authoritative_dns_evidence(delegation)
        self.authoritative_dns_analysis = self.analyze_authoritative_dns_evidence(
            self.authoritative_dns
        )
        result = super().collect_domain_dns()
        self._add_authoritative_dns_findings()
        return result

    def analyze_authoritative_dns_evidence(self, evidence):
        """Run pure issue #15 analysis over already-collected evidence."""
        if evidence is None:
            return None
        from .authoritative_analysis import analyze_authoritative_dns

        return analyze_authoritative_dns(evidence)

    def _add_authoritative_dns_findings(self):
        """Emit conservative, non-scoring issue #15 Domain checks."""
        evidence = getattr(self, "authoritative_dns", None)
        analysis = getattr(self, "authoritative_dns_analysis", None)
        if evidence is None or analysis is None or not hasattr(self, "add_check"):
            return

        from .authoritative_findings import build_authoritative_dns_findings

        for finding in build_authoritative_dns_findings(evidence, analysis):
            self.add_check(
                "Domain",
                finding.name,
                finding.status,
                finding.message,
                finding.weight,
                finding.earned,
                finding.applicable,
            )

    def collect_authoritative_dns_evidence(
        self,
        delegation: ParentDelegationEvidence | None,
    ) -> AuthoritativeDnsEvidence | None:
        """Collect bounded per-server UDP/TCP/EDNS SOA and apex NS evidence."""
        if delegation is None:
            return None

        servers = delegation.delegated_servers
        plan = _probe_plan(servers)
        collected: list[AuthoritativeServerEvidence] = []
        total_planned = sum(len(addresses) for addresses in plan.values())
        available_family_endpoints = sum(
            len(_family_probe_addresses(server)) for server in servers
        )

        for server in servers:
            probe_queue = list(plan.get(server.name, ()))
            canonical_candidates: list[str] = []
            seen_candidates: set[str] = set()
            for value in server.candidate_addresses:
                try:
                    canonical = str(ipaddress.ip_address(str(value).strip()))
                except ValueError:
                    continue
                if canonical in seen_candidates:
                    continue
                seen_candidates.add(canonical)
                canonical_candidates.append(canonical)

            endpoints: list[AuthoritativeEndpointEvidence] = []
            actual_probe_addresses: list[str] = []
            apex_ns_result: DnsQueryResult | None = None
            apex_nameservers: tuple[str, ...] = ()

            while (
                probe_queue
                and len(actual_probe_addresses) < MAX_AUTHORITATIVE_ENDPOINTS_PER_NS
            ):
                server_ip = probe_queue.pop(0)
                if server_ip in actual_probe_addresses:
                    continue
                probe_index = len(actual_probe_addresses)

                udp_result = self.authoritative_dns_query_result(
                    delegation.zone,
                    "SOA",
                    server_name=server.name,
                    server_ip=server_ip,
                    transport=DnsTransport.UDP,
                    timeout=AUTHORITATIVE_DIRECT_TIMEOUT,
                )
                tcp_result = self.authoritative_dns_query_result(
                    delegation.zone,
                    "SOA",
                    server_name=server.name,
                    server_ip=server_ip,
                    transport=DnsTransport.TCP,
                    timeout=AUTHORITATIVE_DIRECT_TIMEOUT,
                )
                udp_observation = soa_observation(udp_result, delegation.zone)
                tcp_observation = soa_observation(tcp_result, delegation.zone)
                edns_result = None

                # EDNS remains one server-level observation on the primary
                # endpoint. Apex NS may move to a bounded fallback if the primary
                # endpoint could not establish authoritative child evidence.
                if probe_index == 0:
                    edns_result = self.authoritative_dns_query_result(
                        delegation.zone,
                        "SOA",
                        server_name=server.name,
                        server_ip=server_ip,
                        transport=DnsTransport.UDP,
                        timeout=AUTHORITATIVE_DIRECT_TIMEOUT,
                        edns_version=0,
                        edns_payload=AUTHORITATIVE_EDNS_PAYLOAD,
                    )

                if probe_index == 0 or not apex_nameservers:
                    ns_result = self.authoritative_dns_query_result(
                        delegation.zone,
                        "NS",
                        server_name=server.name,
                        server_ip=server_ip,
                        transport=DnsTransport.UDP,
                        timeout=AUTHORITATIVE_DIRECT_TIMEOUT,
                    )
                    nameservers = apex_ns_from_result(ns_result, delegation.zone)

                    if not nameservers:
                        tcp_ns_result = self.authoritative_dns_query_result(
                            delegation.zone,
                            "NS",
                            server_name=server.name,
                            server_ip=server_ip,
                            transport=DnsTransport.TCP,
                            timeout=AUTHORITATIVE_DIRECT_TIMEOUT,
                        )
                        tcp_nameservers = apex_ns_from_result(
                            tcp_ns_result,
                            delegation.zone,
                        )
                        if tcp_nameservers:
                            ns_result = tcp_ns_result
                            nameservers = tcp_nameservers

                    if nameservers:
                        apex_ns_result = ns_result
                        apex_nameservers = nameservers
                    elif apex_ns_result is None:
                        apex_ns_result = ns_result

                actual_probe_addresses.append(server_ip)
                endpoints.append(
                    AuthoritativeEndpointEvidence(
                        server_name=server.name,
                        server_ip=server_ip,
                        udp_soa=udp_observation,
                        tcp_soa=tcp_observation,
                        edns_soa=(
                            soa_observation(edns_result, delegation.zone)
                            if edns_result is not None
                            else None
                        ),
                    )
                )

                # If the primary address did not provide any parseable
                # authoritative SOA, spend the already-bounded second endpoint on
                # another address in the same reachable family before trying an
                # IPv6 path that may simply be unavailable from the scanner host.
                if (
                    probe_index == 0
                    and udp_observation.soa is None
                    and tcp_observation.soa is None
                    and len(actual_probe_addresses) < MAX_AUTHORITATIVE_ENDPOINTS_PER_NS
                ):
                    fallback = _same_family_fallback(
                        server,
                        server_ip,
                        set(actual_probe_addresses),
                    )
                    if fallback:
                        if probe_queue:
                            probe_queue[0] = fallback
                        else:
                            probe_queue.append(fallback)

            probe_addresses = tuple(actual_probe_addresses)
            probe_set = set(probe_addresses)
            unprobed = tuple(
                address for address in canonical_candidates if address not in probe_set
            )

            collected.append(
                AuthoritativeServerEvidence(
                    name=server.name,
                    candidate_addresses=server.candidate_addresses,
                    probe_addresses=probe_addresses,
                    unprobed_addresses=unprobed,
                    apex_ns_result=apex_ns_result,
                    apex_nameservers=apex_nameservers,
                    endpoints=tuple(endpoints),
                )
            )

        return AuthoritativeDnsEvidence(
            zone=normalize_dns_name(delegation.zone),
            servers=tuple(collected),
            endpoint_probe_limit=MAX_AUTHORITATIVE_ENDPOINT_PROBES,
            endpoint_probe_limit_reached=(
                available_family_endpoints > total_planned
                and total_planned >= MAX_AUTHORITATIVE_ENDPOINT_PROBES
            ),
        )


__all__ = [
    "AUTHORITATIVE_DIRECT_TIMEOUT",
    "AUTHORITATIVE_EDNS_PAYLOAD",
    "MAX_AUTHORITATIVE_ENDPOINTS_PER_NS",
    "MAX_AUTHORITATIVE_ENDPOINT_PROBES",
    "AuthoritativeDnsEvidence",
    "AuthoritativeDnsScanMixin",
    "AuthoritativeEndpointEvidence",
    "AuthoritativeServerEvidence",
    "SoaObservation",
    "SoaRecord",
    "apex_ns_from_result",
    "soa_from_result",
    "soa_observation",
]
