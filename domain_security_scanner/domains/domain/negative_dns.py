from __future__ import annotations

import secrets
from dataclasses import dataclass

from ...models import DnsQueryResult, DnsTransport


NEGATIVE_DNS_DIRECT_TIMEOUT = 1.5
NEGATIVE_DNS_QUERY_TYPE = "A"
NEGATIVE_DNS_PROBE_COUNT = 2
RECURSION_PROBE_QUERY_TYPE = "A"
RECURSION_PROBE_CANDIDATES = (
    "example.com",
    "example.net",
    "example.org",
)


def _normalize_dns_name(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _is_within_zone(name: str, zone: str) -> bool:
    name_key = _normalize_dns_name(name)
    zone_key = _normalize_dns_name(zone)
    if not zone_key:
        return True
    return name_key == zone_key or name_key.endswith("." + zone_key)


def _default_recursion_probe_name(zone: str) -> str | None:
    """Choose a stable RFC 2606 example name outside the assessed zone."""
    for candidate in RECURSION_PROBE_CANDIDATES:
        if not _is_within_zone(candidate, zone):
            return candidate
    return None


def _generated_negative_names(zone: str) -> tuple[str, ...]:
    """Generate two bounded, high-entropy names below the assessed zone."""
    zone_key = _normalize_dns_name(zone)
    if not zone_key:
        return ()

    # RFC 1035 labels are limited to 63 octets and the presentation form of a
    # full domain name is bounded. If the zone leaves too little room for a
    # meaningful randomized child label, preserve uncertainty instead of
    # constructing an invalid query name.
    max_label_length = min(63, 253 - len(zone_key) - 1)
    minimum_label_length = len("dssnx0-") + 8
    if max_label_length < minimum_label_length:
        return ()

    names: list[str] = []
    for index in range(NEGATIVE_DNS_PROBE_COUNT):
        prefix = f"dssnx{index}-"
        available_token_chars = max_label_length - len(prefix)
        token_chars = min(16, available_token_chars)
        token = secrets.token_hex(8)[:token_chars]
        label = prefix + token
        names.append(f"{label}.{zone_key}")
    return tuple(names)


@dataclass(frozen=True)
class NegativeDnsServerEvidence:
    """Bounded issue #19 observations for one delegated authoritative server."""

    server_name: str
    server_ip: str | None
    negative_results: tuple[DnsQueryResult, ...] = ()
    recursion_result: DnsQueryResult | None = None


@dataclass(frozen=True)
class NegativeDnsEvidence:
    """Raw negative/wildcard/open-recursion evidence for one DNS zone."""

    zone: str
    negative_names: tuple[str, ...]
    recursion_probe_name: str | None
    servers: tuple[NegativeDnsServerEvidence, ...]
    negative_query_type: str = NEGATIVE_DNS_QUERY_TYPE
    negative_probe_count: int = NEGATIVE_DNS_PROBE_COUNT
    recursion_query_type: str = RECURSION_PROBE_QUERY_TYPE


class NegativeDnsEvidenceCollectorMixin:
    """Collect bounded evidence for issue #19 without interpreting findings."""

    def _negative_dns_probe_names(self, zone: str) -> tuple[str, ...]:
        """Hook kept overridable so tests can use deterministic probe names."""
        return _generated_negative_names(zone)

    def _negative_dns_recursion_probe_name(self, zone: str) -> str | None:
        """Hook kept overridable for deterministic/sandboxed recursion tests."""
        return _default_recursion_probe_name(zone)

    @staticmethod
    def _negative_dns_primary_endpoint(server) -> str | None:
        """Reuse issue #15's first bounded endpoint for each authoritative NS."""
        endpoints = tuple(getattr(server, "endpoints", ()) or ())
        if endpoints:
            value = getattr(endpoints[0], "server_ip", None)
            if value:
                return str(value)

        # The authoritative collector may retain a planned address even when no
        # transport evidence was produced. Do not create an extra fallback tree;
        # use at most its first already-selected probe address.
        probe_addresses = tuple(getattr(server, "probe_addresses", ()) or ())
        if probe_addresses:
            return str(probe_addresses[0])
        return None

    def collect_negative_dns_evidence(self, authoritative_dns) -> NegativeDnsEvidence | None:
        """Collect two negative-name probes and one recursion probe per NS.

        Negative-name observations use RD=0 and one existing primary endpoint per
        delegated server. The recursion observation uses RD=1 exactly once per
        server against a stable out-of-zone name. This collector performs no
        amplification measurement, retry loop, enumeration, or scoring.
        """
        if authoritative_dns is None:
            return None

        zone = _normalize_dns_name(getattr(authoritative_dns, "zone", ""))
        negative_names = self._negative_dns_probe_names(zone)
        recursion_probe_name = self._negative_dns_recursion_probe_name(zone)
        collected: list[NegativeDnsServerEvidence] = []

        for server in tuple(getattr(authoritative_dns, "servers", ()) or ()):
            server_name = _normalize_dns_name(getattr(server, "name", ""))
            server_ip = self._negative_dns_primary_endpoint(server)
            if not server_ip:
                collected.append(
                    NegativeDnsServerEvidence(
                        server_name=server_name,
                        server_ip=None,
                    )
                )
                continue

            negative_results = tuple(
                self.authoritative_dns_query_result(
                    name,
                    NEGATIVE_DNS_QUERY_TYPE,
                    server_name=server_name or None,
                    server_ip=server_ip,
                    transport=DnsTransport.UDP,
                    timeout=NEGATIVE_DNS_DIRECT_TIMEOUT,
                )
                for name in negative_names
            )

            recursion_result = None
            if recursion_probe_name is not None:
                recursion_result = self.authoritative_dns_query_result(
                    recursion_probe_name,
                    RECURSION_PROBE_QUERY_TYPE,
                    server_name=server_name or None,
                    server_ip=server_ip,
                    transport=DnsTransport.UDP,
                    timeout=NEGATIVE_DNS_DIRECT_TIMEOUT,
                    recursion_desired=True,
                )

            collected.append(
                NegativeDnsServerEvidence(
                    server_name=server_name,
                    server_ip=server_ip,
                    negative_results=negative_results,
                    recursion_result=recursion_result,
                )
            )

        return NegativeDnsEvidence(
            zone=zone,
            negative_names=negative_names,
            recursion_probe_name=recursion_probe_name,
            servers=tuple(collected),
        )


def _query_report(
    result: DnsQueryResult | None,
    *,
    include_qname: bool = True,
) -> dict | None:
    """Serialize one direct DNS observation without reinterpreting it."""
    if result is None:
        return None
    data = {
        "qtype": result.qtype,
        "server_name": result.server_name,
        "server_ip": result.server_ip,
        "transport": result.transport.value if result.transport is not None else None,
        "state": result.state.value,
        "rcode": result.rcode,
        "authoritative": result.aa,
        "truncated": result.tc,
        "request_recursion_desired": result.request_recursion_desired,
        "response_recursion_desired": result.rd,
        "recursion_available": result.ra,
        "error": result.error,
    }
    if include_qname:
        data["qname"] = result.qname
    return data


def negative_dns_report_data(evidence, analysis) -> dict:
    """Return additive structured JSON evidence for issue #19."""
    empty = {
        "negative_response": {
            "status": "unknown",
            "complete": False,
            "zone": None,
            "query_type": NEGATIVE_DNS_QUERY_TYPE,
            "probe_count": NEGATIVE_DNS_PROBE_COUNT,
            "generated_probe_names_serialized": False,
            "servers": [],
        },
        "wildcard": {
            "status": "unknown",
            "servers": [],
        },
        "open_recursion": {
            "status": "unknown",
            "probe_name": None,
            "query_type": RECURSION_PROBE_QUERY_TYPE,
            "probes_per_server": 1,
            "amplification_measurement": False,
            "open_servers": [],
            "closed_servers": [],
            "unknown_servers": [],
            "servers": [],
        },
    }
    if evidence is None or analysis is None:
        return empty

    negative_servers = []
    recursion_servers = []
    for raw_server, server_analysis in zip(evidence.servers, analysis.servers):
        probes = []
        for probe_index, (raw_result, probe_analysis) in enumerate(
            zip(raw_server.negative_results, server_analysis.probes),
            start=1,
        ):
            probes.append(
                {
                    "probe_index": probe_index,
                    "outcome": probe_analysis.outcome.value,
                    "rcode": probe_analysis.rcode,
                    "authoritative": probe_analysis.authoritative,
                    "answer_records": list(raw_result.records),
                    "soa_records": list(probe_analysis.soa_records),
                    "query": _query_report(raw_result, include_qname=False),
                }
            )
        negative_servers.append(
            {
                "server_name": server_analysis.server_name,
                "server_ip": server_analysis.server_ip,
                "status": server_analysis.negative_state.value,
                "complete": server_analysis.negative_complete,
                "wildcard_answer_sets_equal": server_analysis.wildcard_answer_sets_equal,
                "probes": probes,
            }
        )
        recursion_servers.append(
            {
                "server_name": server_analysis.server_name,
                "server_ip": server_analysis.server_ip,
                "status": server_analysis.recursion_state.value,
                "reason": server_analysis.recursion_reason,
                "query": _query_report(raw_server.recursion_result),
            }
        )

    if analysis.wildcard_servers:
        wildcard_status = "observed"
    elif analysis.negative_complete:
        wildcard_status = "not_observed"
    else:
        wildcard_status = "unknown"

    return {
        "negative_response": {
            "status": analysis.negative_state.value,
            "complete": analysis.negative_complete,
            "zone": evidence.zone,
            "query_type": evidence.negative_query_type,
            "probe_count": evidence.negative_probe_count,
            "generated_probe_names_serialized": False,
            "servers": negative_servers,
        },
        "wildcard": {
            "status": wildcard_status,
            "servers": list(analysis.wildcard_servers),
        },
        "open_recursion": {
            "status": analysis.recursion_state.value,
            "probe_name": evidence.recursion_probe_name,
            "query_type": evidence.recursion_query_type,
            "probes_per_server": 1,
            "amplification_measurement": False,
            "open_servers": list(analysis.recursion_open_servers),
            "closed_servers": list(analysis.recursion_closed_servers),
            "unknown_servers": list(analysis.recursion_unknown_servers),
            "servers": recursion_servers,
        },
    }


class NegativeDnsScanMixin(NegativeDnsEvidenceCollectorMixin):
    """Collect, analyze, report, and emit issue #19 DNS findings."""

    def collect_domain_dns(self):
        authoritative_dns = getattr(self, "authoritative_dns", None)
        self.negative_dns = self.collect_negative_dns_evidence(authoritative_dns)

        if self.negative_dns is None:
            self.negative_dns_analysis = None
        else:
            from .negative_dns_analysis import analyze_negative_dns

            self.negative_dns_analysis = analyze_negative_dns(self.negative_dns)

        result = super().collect_domain_dns()
        self._add_negative_dns_findings()
        return result

    def _add_negative_dns_findings(self):
        evidence = getattr(self, "negative_dns", None)
        analysis = getattr(self, "negative_dns_analysis", None)
        if evidence is None or analysis is None or not hasattr(self, "add_check"):
            return

        from .negative_dns_findings import build_negative_dns_findings

        for finding in build_negative_dns_findings(evidence, analysis):
            self.add_check(
                "Domain",
                finding.name,
                finding.status,
                finding.message,
                finding.weight,
                finding.earned,
                finding.applicable,
            )


__all__ = [
    "NEGATIVE_DNS_DIRECT_TIMEOUT",
    "NEGATIVE_DNS_QUERY_TYPE",
    "NEGATIVE_DNS_PROBE_COUNT",
    "RECURSION_PROBE_QUERY_TYPE",
    "RECURSION_PROBE_CANDIDATES",
    "NegativeDnsEvidence",
    "NegativeDnsEvidenceCollectorMixin",
    "NegativeDnsScanMixin",
    "NegativeDnsServerEvidence",
    "negative_dns_report_data",
]
