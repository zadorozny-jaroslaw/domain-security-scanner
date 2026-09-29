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
    # Appended for issue #17 to preserve the positional layout of issue #16.
    denial_probe: DnssecQueryEvidence | None = None


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

        # An authoritative parent NODATA response for DS conclusively means the
        # delegation is unsigned. Do not query child DNSKEY/SOA/NS in that case:
        # those queries cannot change the DNSSEC state and would add unnecessary
        # network traffic to the low-impact scan.
        if (
            parent_ds is not None
            and parent_ds.result.state == DnsQueryState.NO_ANSWER
        ):
            return DnssecEvidence(
                zone=zone,
                parent_ds=parent_ds,
                child_probe_limit=MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
                child_probe_limit_reached=False,
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
        denial_probe = None
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

            # Issue #17 reuses one high-entropy negative name already generated
            # by issue #19 instead of creating a second random-name mechanism.
            # The extra query is DNSSEC-aware (DO=1) and targets only the same
            # selected authoritative endpoint used for DNSKEY/SOA/NS evidence.
            # This keeps denial-of-existence collection bounded to one query.
            if selected_dnskey.result.state == DnsQueryState.ANSWER:
                negative_dns = getattr(self, "negative_dns", None)
                negative_names = tuple(
                    getattr(negative_dns, "negative_names", ()) or ()
                )
                if negative_names:
                    candidate = normalize_dnssec_name(negative_names[0])
                    if (
                        candidate
                        and candidate != zone
                        and candidate.endswith("." + zone)
                    ):
                        denial_probe = self._dnssec_direct_query(
                            candidate,
                            "A",
                            server_name=selected_dnskey.server_name,
                            server_ip=selected_dnskey.server_ip,
                        )

        return DnssecEvidence(
            zone=zone,
            parent_ds=parent_ds,
            dnskey_attempts=tuple(dnskey_attempts),
            selected_dnskey=selected_dnskey,
            apex_rrsets=tuple(apex_rrsets),
            denial_probe=denial_probe,
            child_probe_limit=MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
            child_probe_limit_reached=(
                len(all_available) > MAX_DNSSEC_CHILD_ENDPOINT_PROBES
                and len(dnskey_attempts) >= MAX_DNSSEC_CHILD_ENDPOINT_PROBES
            ),
        )


def _rrset_rdata(result: DnsQueryResult | None, rdtype: str) -> list[str]:
    """Return RDATA values of one type from stored answer-section RRsets."""
    if result is None:
        return []
    target = rdtype.upper()
    values: list[str] = []
    for rrset_text in result.answer_section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) == 5 and parts[3].upper() == target:
                values.append(parts[4].strip())
    return values


def _query_report(evidence: DnssecQueryEvidence | None) -> dict | None:
    if evidence is None:
        return None
    result = evidence.result
    return {
        "qtype": evidence.qtype,
        "server_name": evidence.server_name,
        "server_ip": evidence.server_ip,
        "transport": result.transport.value if result.transport else None,
        "state": result.state.value,
        "rcode": result.rcode,
        "authoritative": result.aa,
        "truncated": result.tc,
        "want_dnssec": result.request_want_dnssec,
        "error": result.error,
    }


def dnssec_report_data(
    evidence: DnssecEvidence | None,
    analysis=None,
) -> dict:
    """Serialize bounded issue #16 evidence without claiming whole-zone validation."""
    if evidence is None or analysis is None:
        return {
            "status": "unknown",
            "policy_version": None,
            "scope": {
                "validation_targets": ["DNSKEY", "SOA", "NS"],
                "validated_rrsets": [],
                "complete_zone_validation": False,
            },
        }

    parent_result = evidence.parent_ds.result if evidence.parent_ds else None
    dnskey_result = (
        evidence.selected_dnskey.result if evidence.selected_dnskey else None
    )
    signatures = {}
    steps = []
    for step in analysis.steps:
        item = {
            "name": step.name,
            "outcome": step.outcome.value,
            "message": step.message,
        }
        if step.signatures is not None:
            summary = {
                "total": step.signatures.total,
                "current": step.signatures.current,
                "expired": step.signatures.expired,
                "not_yet_valid": step.signatures.not_yet_valid,
                "valid": step.signatures.valid,
                "invalid": step.signatures.invalid,
                "unsupported": step.signatures.unsupported,
            }
            item["signatures"] = summary
            signatures[step.name] = summary
        steps.append(item)

    validation_targets = ["DNSKEY", *DNSSEC_APEX_RRTYPES]
    validated_by_step = {
        "DNSKEY RRset": "DNSKEY",
        "Apex SOA": "SOA",
        "Apex NS": "NS",
    }
    validated_rrsets = [
        validated_by_step[step.name]
        for step in analysis.steps
        if step.name in validated_by_step
        and getattr(step.outcome, "value", step.outcome) == "pass"
    ]

    return {
        "status": analysis.state.value,
        "reason": analysis.reason,
        "zone": evidence.zone,
        "policy_version": analysis.policy_version,
        "ds": _rrset_rdata(parent_result, "DS"),
        "dnskeys": _rrset_rdata(dnskey_result, "DNSKEY"),
        "matching_key_tags": list(analysis.matched_key_tags),
        "rrsig": signatures,
        "queries": {
            "parent_ds": _query_report(evidence.parent_ds),
            "dnskey_attempts": [
                _query_report(item) for item in evidence.dnskey_attempts
            ],
            "apex_rrsets": [
                _query_report(item) for item in evidence.apex_rrsets
            ],
        },
        "validation_steps": steps,
        "scope": {
            "validation_targets": validation_targets,
            "validated_rrsets": validated_rrsets,
            "complete_zone_validation": False,
            "child_probe_limit": evidence.child_probe_limit,
            "child_probe_limit_reached": evidence.child_probe_limit_reached,
        },
    }


class DnssecScanMixin(DnssecEvidenceCollectorMixin):
    """Collect, analyze, report, and emit findings for issue #16 DNSSEC."""

    def collect_domain_dns(self):
        delegation = getattr(self, "delegation", None)
        self.dnssec = self.collect_dnssec_evidence(delegation)

        from .dnssec_analysis import analyze_dnssec_evidence

        self.dnssec_analysis = analyze_dnssec_evidence(self.dnssec)
        result = super().collect_domain_dns()
        self._add_dnssec_findings()
        return result

    def _add_dnssec_findings(self):
        evidence = getattr(self, "dnssec", None)
        analysis = getattr(self, "dnssec_analysis", None)
        if evidence is None or analysis is None or not hasattr(self, "add_check"):
            return

        from .dnssec_findings import build_dnssec_findings

        for finding in build_dnssec_findings(evidence, analysis):
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
    "DNSSEC_APEX_RRTYPES",
    "DNSSEC_DIRECT_TIMEOUT",
    "DNSSEC_EDNS_PAYLOAD",
    "MAX_DNSSEC_CHILD_ENDPOINT_PROBES",
    "DnssecEvidence",
    "DnssecEvidenceCollectorMixin",
    "DnssecScanMixin",
    "DnssecQueryEvidence",
    "dnssec_child_endpoints",
    "dnssec_report_data",
]
