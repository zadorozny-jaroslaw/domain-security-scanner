from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from ...models import DnsQueryResult, DnsQueryState, DnsTransport


DNSSEC_DIRECT_TIMEOUT = 1.5
DNSSEC_EDNS_PAYLOAD = 1232
DNSSEC_APEX_RRTYPES = ("SOA", "NS")
MAX_DNSSEC_PARENT_ENDPOINT_PROBES = 4
MAX_DNSSEC_CHILD_ENDPOINT_PROBES = 4


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
    # Appended for issue #20 stabilization. The selected parent_ds remains the
    # compatibility field; attempts explain bounded fallback decisions.
    parent_ds_attempts: tuple[DnssecQueryEvidence, ...] = ()


def _canonical_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def dnssec_parent_endpoints(
    delegation: Any,
    *,
    limit: int = MAX_DNSSEC_PARENT_ENDPOINT_PROBES,
) -> tuple[tuple[str | None, str], ...]:
    """Return a bounded, breadth-first set of parent authoritative endpoints.

    The parent server that produced the delegation referral is tried first so a
    healthy scan normally adds no extra traffic. When that endpoint cannot give
    conclusive DS evidence, other already-resolved parent nameservers are tried
    breadth-first instead of turning one path anomaly into DNSSEC UNKNOWN.
    """
    if delegation is None or limit <= 0:
        return ()

    selected: list[tuple[str | None, str]] = []
    seen: set[tuple[str | None, str]] = set()

    def add(server_name, server_ip) -> None:
        if len(selected) >= limit:
            return
        canonical = _canonical_ip(server_ip)
        if not canonical:
            return
        normalized_name = (
            normalize_dnssec_name(server_name) if server_name else None
        )
        key = (normalized_name, canonical)
        if key in seen:
            return
        seen.add(key)
        selected.append(key)

    add(
        getattr(delegation, "source_server_name", None),
        getattr(delegation, "source_server_ip", None),
    )
    if len(selected) >= limit:
        return tuple(selected)

    parent_servers = tuple(
        getattr(delegation, "parent_server_addresses", ()) or ()
    )
    max_addresses = max(
        (len(tuple(getattr(item, "addresses", ()) or ())) for item in parent_servers),
        default=0,
    )
    for address_index in range(max_addresses):
        for item in parent_servers:
            addresses = tuple(getattr(item, "addresses", ()) or ())
            if address_index >= len(addresses):
                continue
            add(getattr(item, "name", None), addresses[address_index])
            if len(selected) >= limit:
                return tuple(selected)

    return tuple(selected)


def dnssec_child_endpoints(
    delegation: Any,
    *,
    limit: int = MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
) -> tuple[tuple[str, str], ...]:
    """Choose a fair, bounded set of child-authoritative endpoints.

    Within each delegated server, endpoints already proven authoritative by
    issue #14 are preferred. Across servers, selection is breadth-first so one
    multi-address nameserver cannot consume the whole DNSSEC probe budget before
    another delegated nameserver receives a first chance.
    """
    if delegation is None or limit <= 0:
        return ()

    per_server: list[tuple[str, tuple[str, ...]]] = []
    for server in getattr(delegation, "delegated_servers", ()) or ():
        server_name = normalize_dnssec_name(getattr(server, "name", ""))
        if not server_name:
            continue

        preferred: list[str] = []
        fallback: list[str] = []
        seen: set[str] = set()

        for result in getattr(server, "authority_queries", ()) or ():
            if (
                getattr(result, "state", None) != DnsQueryState.ANSWER
                or getattr(result, "aa", None) is not True
            ):
                continue
            server_ip = _canonical_ip(getattr(result, "server_ip", ""))
            if not server_ip or server_ip in seen:
                continue
            seen.add(server_ip)
            preferred.append(server_ip)

        for value in getattr(server, "candidate_addresses", ()) or ():
            server_ip = _canonical_ip(value)
            if not server_ip or server_ip in seen:
                continue
            seen.add(server_ip)
            fallback.append(server_ip)

        ordered = tuple(preferred + fallback)
        if ordered:
            per_server.append((server_name, ordered))

    selected: list[tuple[str, str]] = []
    max_addresses = max((len(addresses) for _, addresses in per_server), default=0)
    for address_index in range(max_addresses):
        for server_name, addresses in per_server:
            if address_index >= len(addresses):
                continue
            selected.append((server_name, addresses[address_index]))
            if len(selected) >= limit:
                return tuple(selected)

    return tuple(selected)


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

        Collection stays bounded, but it does not bind the whole DNSSEC decision
        to one parent or one child address. Conclusive evidence from independent
        authoritative endpoints may be combined and is later cryptographically
        validated by ``dnssec_analysis.py``.
        """
        zone = normalize_dnssec_name(
            getattr(delegation, "zone", None) or getattr(self, "root_domain", "")
        )
        parent_ds = None
        parent_ds_attempts: list[DnssecQueryEvidence] = []

        if zone:
            for parent_name, parent_ip in dnssec_parent_endpoints(delegation):
                attempt = self._dnssec_direct_query(
                    zone,
                    "DS",
                    server_name=parent_name,
                    server_ip=parent_ip,
                )
                parent_ds_attempts.append(attempt)
                if attempt.result.state in {
                    DnsQueryState.ANSWER,
                    DnsQueryState.NO_ANSWER,
                }:
                    parent_ds = attempt
                    break

        if parent_ds is None and parent_ds_attempts:
            parent_ds = parent_ds_attempts[0]

        # An authoritative parent NODATA response for DS conclusively means the
        # delegation is unsigned. Do not query child DNSKEY/SOA/NS in that case.
        if (
            parent_ds is not None
            and parent_ds.result.state == DnsQueryState.NO_ANSWER
        ):
            return DnssecEvidence(
                zone=zone,
                parent_ds=parent_ds,
                child_probe_limit=MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
                child_probe_limit_reached=False,
                parent_ds_attempts=tuple(parent_ds_attempts),
            )

        delegated_servers = tuple(
            getattr(delegation, "delegated_servers", ()) or ()
        )
        all_available = dnssec_child_endpoints(
            delegation,
            limit=max(
                MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
                len(delegated_servers) * MAX_DNSSEC_CHILD_ENDPOINT_PROBES,
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
            if attempt.result.state == DnsQueryState.ANSWER:
                selected_dnskey = attempt
                break

        # Preserve conclusive broken-chain evidence only when every bounded child
        # endpoint that was tried agrees that DNSKEY is absent. A single anomalous
        # NODATA response must not override other unavailable paths.
        if selected_dnskey is None and dnskey_attempts:
            if all(
                item.result.state in {
                    DnsQueryState.NO_ANSWER,
                    DnsQueryState.NXDOMAIN,
                }
                for item in dnskey_attempts
            ):
                selected_dnskey = dnskey_attempts[0]

        apex_rrsets: list[DnssecQueryEvidence] = []
        denial_probe = None
        if selected_dnskey is not None and selected_dnskey.result.state == DnsQueryState.ANSWER:
            selected_endpoint = (
                selected_dnskey.server_name or "",
                selected_dnskey.server_ip,
            )
            ordered_endpoints = [selected_endpoint]
            ordered_endpoints.extend(
                item for item in endpoints if item != selected_endpoint
            )

            # SOA and NS may be served successfully by a different authoritative
            # anycast/address path than DNSKEY. Each RRset gets a bounded fallback
            # across the same child endpoint budget; cryptographic validation is
            # what ultimately decides whether the evidence is trustworthy.
            for qtype in DNSSEC_APEX_RRTYPES:
                attempts: list[DnssecQueryEvidence] = []
                chosen = None
                for server_name, server_ip in ordered_endpoints:
                    attempt = self._dnssec_direct_query(
                        zone,
                        qtype,
                        server_name=server_name or None,
                        server_ip=server_ip,
                    )
                    attempts.append(attempt)
                    if attempt.result.state == DnsQueryState.ANSWER:
                        chosen = attempt
                        break
                if chosen is None and attempts:
                    chosen = attempts[0]
                if chosen is not None:
                    apex_rrsets.append(chosen)

            # Issue #17 reuses one high-entropy negative name already generated
            # by issue #19. Keep this to one DNSSEC-aware query on the DNSKEY
            # endpoint; inability to observe denial remains advisory/unknown.
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
            parent_ds_attempts=tuple(parent_ds_attempts),
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


def _algorithm_observation_report(item) -> dict:
    return {
        "number": item.number,
        "source": getattr(item, "source", None),
        "description": item.description,
        "mnemonic": getattr(item, "mnemonic", None),
        "signing_posture": getattr(item, "signing_posture", None).value
        if getattr(item, "signing_posture", None) is not None
        else None,
        "validation_posture": getattr(item, "validation_posture", None).value
        if getattr(item, "validation_posture", None) is not None
        else None,
        "use_for_signing": getattr(item, "use_for_signing", None),
        "use_for_validation": getattr(item, "use_for_validation", None),
        "sha1_based": bool(getattr(item, "sha1_based", False)),
        "retired": bool(getattr(item, "retired", False)),
        "private_use": bool(getattr(item, "private_use", False)),
    }


def _digest_observation_report(item) -> dict:
    return {
        "number": item.number,
        "description": item.description,
        "delegation_posture": item.delegation_posture.value,
        "validation_posture": item.validation_posture.value,
        "use_for_delegation": item.use_for_delegation,
        "use_for_validation": item.use_for_validation,
        "sha1_based": item.sha1_based,
        "retired": item.retired,
        "private_use": item.private_use,
    }


def _algorithm_policy_report(analysis) -> dict:
    if analysis is None:
        return {
            "status": "unknown",
            "snapshot_version": None,
            "algorithm_registry_updated": None,
            "digest_registry_updated": None,
            "dnskey_algorithms": [],
            "ds_algorithms": [],
            "ds_digests": [],
        }
    return {
        "status": analysis.posture.value,
        "reason": analysis.reason,
        "snapshot_version": analysis.snapshot_version,
        "algorithm_registry_updated": analysis.algorithm_registry_updated,
        "digest_registry_updated": analysis.digest_registry_updated,
        "dnskey_algorithms": [
            _algorithm_observation_report(item) for item in analysis.dnskey_algorithms
        ],
        "ds_algorithms": [
            _algorithm_observation_report(item) for item in analysis.ds_algorithms
        ],
        "ds_digests": [
            _digest_observation_report(item) for item in analysis.ds_digests
        ],
        "sha1": {
            "signing_algorithms": list(analysis.sha1_signing_algorithms),
            "delegation_digests": list(analysis.sha1_delegation_digests),
        },
        "retired": {
            "algorithms": list(analysis.retired_algorithms),
            "digests": list(analysis.retired_digests),
        },
    }


def _denial_report(analysis) -> dict:
    if analysis is None:
        return {
            "mechanism": "unknown",
            "posture": "unknown",
            "observable": False,
            "advisories": [],
            "nsec3": None,
        }
    nsec3 = None
    if analysis.nsec3 is not None:
        nsec3 = {
            "algorithms": list(analysis.nsec3.algorithms),
            "flags": list(analysis.nsec3.flags),
            "iterations": list(analysis.nsec3.iterations),
            "salts": list(analysis.nsec3.salts),
            "opt_out_observed": analysis.nsec3.opt_out_observed,
            "reserved_flag_values": list(analysis.nsec3.reserved_flag_values),
            "zero_iterations": analysis.nsec3.zero_iterations,
            "empty_salt": analysis.nsec3.empty_salt,
            "chain_parameters_consistent": analysis.nsec3.chain_parameters_consistent,
        }
    return {
        "mechanism": analysis.mechanism.value,
        "posture": analysis.posture.value,
        "reason": analysis.reason,
        "observable": analysis.observable,
        "nsec_count": analysis.nsec_count,
        "nsec3_count": analysis.nsec3_count,
        "nsec3param_count": analysis.nsec3param_count,
        "advisories": list(analysis.advisories),
        "nsec3": nsec3,
    }


def dnssec_report_data(
    evidence: DnssecEvidence | None,
    analysis=None,
    algorithm_analysis=None,
    denial_analysis=None,
) -> dict:
    """Serialize bounded issue #16 evidence without claiming whole-zone validation."""
    if evidence is None or analysis is None:
        return {
            "status": "unknown",
            "policy_version": None,
            "algorithm_policy": _algorithm_policy_report(algorithm_analysis),
            "denial": _denial_report(denial_analysis),
            "scope": {
                "validation_targets": ["DNSKEY", "SOA", "NS"],
                "validated_rrsets": [],
                "complete_zone_validation": False,
                "denial_probe_limit": 1,
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

    algorithm_policy = _algorithm_policy_report(algorithm_analysis)
    denial = _denial_report(denial_analysis)

    return {
        "status": analysis.state.value,
        "reason": analysis.reason,
        "zone": evidence.zone,
        # Kept for backward compatibility with issue #16. Issue #17 publishes
        # the current IANA snapshot separately under algorithm_policy.
        "policy_version": analysis.policy_version,
        "algorithm_policy": algorithm_policy,
        "denial": denial,
        "ds": _rrset_rdata(parent_result, "DS"),
        "dnskeys": _rrset_rdata(dnskey_result, "DNSKEY"),
        "matching_key_tags": list(analysis.matched_key_tags),
        "rrsig": signatures,
        "queries": {
            "parent_ds": _query_report(evidence.parent_ds),
            "parent_ds_attempts": [
                _query_report(item) for item in evidence.parent_ds_attempts
            ],
            "dnskey_attempts": [
                _query_report(item) for item in evidence.dnskey_attempts
            ],
            "apex_rrsets": [
                _query_report(item) for item in evidence.apex_rrsets
            ],
            "denial_probe": _query_report(evidence.denial_probe),
        },
        "validation_steps": steps,
        "scope": {
            "validation_targets": validation_targets,
            "validated_rrsets": validated_rrsets,
            "complete_zone_validation": False,
            "parent_probe_limit": MAX_DNSSEC_PARENT_ENDPOINT_PROBES,
            "child_probe_limit": evidence.child_probe_limit,
            "child_probe_limit_reached": evidence.child_probe_limit_reached,
            "denial_probe_limit": 1,
        },
    }


class DnssecScanMixin(DnssecEvidenceCollectorMixin):
    """Collect, analyze, report, and emit findings for issue #16 DNSSEC."""

    def collect_domain_dns(self):
        delegation = getattr(self, "delegation", None)
        self.dnssec = self.collect_dnssec_evidence(delegation)

        from .dnssec_analysis import analyze_dnssec_evidence
        from .dnssec_denial_analysis import analyze_dnssec_denial
        from .dnssec_posture_analysis import analyze_dnssec_algorithm_posture

        self.dnssec_analysis = analyze_dnssec_evidence(self.dnssec)
        self.dnssec_policy_analysis = analyze_dnssec_algorithm_posture(self.dnssec)
        self.dnssec_denial_analysis = analyze_dnssec_denial(self.dnssec)
        result = super().collect_domain_dns()
        self._add_dnssec_findings()
        self._add_dnssec_posture_findings()
        return result

    def _add_dnssec_findings(self):
        evidence = getattr(self, "dnssec", None)
        analysis = getattr(self, "dnssec_analysis", None)
        if evidence is None or analysis is None or not hasattr(self, "add_check"):
            return

        from .dnssec_findings import build_dnssec_findings

        for finding in build_dnssec_findings(
            evidence,
            analysis,
            rdap=getattr(self, "rdap", None),
            dns_records=getattr(self, "dns_records", None),
        ):
            self.add_check(
                "Domain",
                finding.name,
                finding.status,
                finding.message,
                finding.weight,
                finding.earned,
                finding.applicable,
            )

    def _add_dnssec_posture_findings(self):
        algorithm_analysis = getattr(self, "dnssec_policy_analysis", None)
        denial_analysis = getattr(self, "dnssec_denial_analysis", None)
        if (
            algorithm_analysis is None
            or denial_analysis is None
            or not hasattr(self, "add_check")
        ):
            return

        from .dnssec_posture_findings import build_dnssec_posture_findings

        for finding in build_dnssec_posture_findings(
            algorithm_analysis, denial_analysis
        ):
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
    "MAX_DNSSEC_PARENT_ENDPOINT_PROBES",
    "MAX_DNSSEC_CHILD_ENDPOINT_PROBES",
    "DnssecEvidence",
    "DnssecEvidenceCollectorMixin",
    "DnssecScanMixin",
    "DnssecQueryEvidence",
    "dnssec_parent_endpoints",
    "dnssec_child_endpoints",
    "dnssec_report_data",
]
