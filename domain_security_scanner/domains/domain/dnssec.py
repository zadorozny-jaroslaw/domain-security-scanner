from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from ...models import DnsQueryResult, DnsQueryState, DnsTransport


DNSSEC_DIRECT_TIMEOUT = 1.5
DNSSEC_EDNS_PAYLOAD = 1232
DNSSEC_APEX_RRTYPES = ("SOA", "NS")
MAX_DNSSEC_CHILD_ENDPOINT_PROBES = 2


def normalize_dnssec_name(value: str) -> str:
    """Normalize a DNS owner/server name for deterministic evidence."""
    return str(value).strip().lower().rstrip(".")


@dataclass(frozen=True)
class DnssecQueryEvidence:
    """One DNSSEC-aware direct query, including an optional TCP retry."""

    qtype: str
    server_name: str | None
    server_ip: str
    udp_result: DnsQueryResult
    tcp_result: DnsQueryResult | None = None

    @property
    def result(self) -> DnsQueryResult:
        """Return the most complete result available for later analysis."""
        return self.tcp_result or self.udp_result


@dataclass(frozen=True)
class DnssecEvidence:
    """Bounded DNSSEC evidence collected before cryptographic analysis."""

    zone: str
    parent_ds: DnssecQueryEvidence | None = None
    dnskey_attempts: tuple[DnssecQueryEvidence, ...] = ()
    selected_dnskey: DnssecQueryEvidence | None = None
    apex_rrsets: tuple[DnssecQueryEvidence, ...] = ()
    child_probe_limit: int = MAX_DNSSEC_CHILD_ENDPOINT_PROBES
    child_probe_limit_reached: bool = False


def _canonical_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def dnssec_child_endpoints(
    delegation: Any,
    *,
    limit: int = MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
) -> tuple[tuple[str, str], ...]:
    """Choose a small deterministic set of child-authoritative endpoints.

    Endpoints already proven authoritative by issue #14 are preferred. Remaining
    candidate addresses are only used as bounded fallbacks. This function is
    pure and intentionally accepts the existing delegation evidence by shape so
    the DNSSEC module does not create a circular dependency on the collector.
    """
    if delegation is None or limit <= 0:
        return ()

    preferred: list[tuple[str, str]] = []
    fallback: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for server in getattr(delegation, "delegated_servers", ()) or ():
        server_name = normalize_dnssec_name(getattr(server, "name", ""))
        if not server_name:
            continue

        for result in getattr(server, "authority_queries", ()) or ():
            if (
                getattr(result, "state", None) != DnsQueryState.ANSWER
                or getattr(result, "aa", None) is not True
            ):
                continue
            server_ip = _canonical_ip(getattr(result, "server_ip", ""))
            if not server_ip:
                continue
            key = (server_name, server_ip)
            if key not in seen:
                seen.add(key)
                preferred.append(key)

        for value in getattr(server, "candidate_addresses", ()) or ():
            server_ip = _canonical_ip(value)
            if not server_ip:
                continue
            key = (server_name, server_ip)
            if key not in seen:
                seen.add(key)
                fallback.append(key)

    return tuple((preferred + fallback)[:limit])


class DnssecEvidenceCollectorMixin:
    """Collect issue #16 DNSSEC evidence without deciding validation state yet."""

    def _dnssec_direct_query(
        self,
        zone: str,
        qtype: str,
        *,
        server_name: str | None,
        server_ip: str,
    ) -> DnssecQueryEvidence:
        """Issue one DNSSEC-aware UDP query and retry only truncation over TCP."""
        common = dict(
            server_name=server_name,
            server_ip=server_ip,
            timeout=DNSSEC_DIRECT_TIMEOUT,
            edns_version=0,
            edns_payload=DNSSEC_EDNS_PAYLOAD,
            want_dnssec=True,
        )
        udp_result = self.authoritative_dns_query_result(
            zone,
            qtype,
            transport=DnsTransport.UDP,
            **common,
        )
        tcp_result = None
        if udp_result.state == DnsQueryState.TRUNCATED:
            tcp_result = self.authoritative_dns_query_result(
                zone,
                qtype,
                transport=DnsTransport.TCP,
                **common,
            )
        return DnssecQueryEvidence(
            qtype=qtype.upper(),
            server_name=(
                normalize_dnssec_name(server_name) if server_name else None
            ),
            server_ip=str(ipaddress.ip_address(server_ip)),
            udp_result=udp_result,
            tcp_result=tcp_result,
        )

    def collect_dnssec_evidence(self, delegation: Any) -> DnssecEvidence:
        """Collect parent DS, child DNSKEY, and selected signed apex RRsets.

        This is collection only. DS matching, RRSIG time checks, cryptographic
        validation, and the ``unsigned/secure/broken/unknown`` state machine are
        deliberately left to the next implementation iteration.
        """
        zone = normalize_dnssec_name(
            getattr(delegation, "zone", None) or getattr(self, "root_domain", "")
        )
        parent_ds = None

        parent_ip = _canonical_ip(getattr(delegation, "source_server_ip", ""))
        parent_name = getattr(delegation, "source_server_name", None)
        if zone and parent_ip:
            parent_ds = self._dnssec_direct_query(
                zone,
                "DS",
                server_name=parent_name,
                server_ip=parent_ip,
            )

        all_available = dnssec_child_endpoints(
            delegation,
            limit=max(
                MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
                len(getattr(delegation, "delegated_servers", ()) or ()) * 2,
            ),
        )
        endpoints = all_available[:MAX_DNSSEC_CHILD_ENDPOINT_PROBES]
        dnskey_attempts: list[DnssecQueryEvidence] = []
        selected_dnskey = None

        for server_name, server_ip in endpoints:
            attempt = self._dnssec_direct_query(
                zone,
                "DNSKEY",
                server_name=server_name,
                server_ip=server_ip,
            )
            dnskey_attempts.append(attempt)
            if not attempt.result.failed:
                selected_dnskey = attempt
                break

        apex_rrsets: list[DnssecQueryEvidence] = []
        if selected_dnskey is not None:
            for qtype in DNSSEC_APEX_RRTYPES:
                apex_rrsets.append(
                    self._dnssec_direct_query(
                        zone,
                        qtype,
                        server_name=selected_dnskey.server_name,
                        server_ip=selected_dnskey.server_ip,
                    )
                )

        return DnssecEvidence(
            zone=zone,
            parent_ds=parent_ds,
            dnskey_attempts=tuple(dnskey_attempts),
            selected_dnskey=selected_dnskey,
            apex_rrsets=tuple(apex_rrsets),
            child_probe_limit=MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
            child_probe_limit_reached=(
                len(all_available) > MAX_DNSSEC_CHILD_ENDPOINT_PROBES
                and len(dnskey_attempts) >= MAX_DNSSEC_CHILD_ENDPOINT_PROBES
            ),
        )


__all__ = [
    "DNSSEC_APEX_RRTYPES",
    "DNSSEC_DIRECT_TIMEOUT",
    "DNSSEC_EDNS_PAYLOAD",
    "MAX_DNSSEC_CHILD_ENDPOINT_PROBES",
    "DnssecEvidence",
    "DnssecEvidenceCollectorMixin",
    "DnssecQueryEvidence",
    "dnssec_child_endpoints",
]
