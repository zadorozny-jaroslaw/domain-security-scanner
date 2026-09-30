from __future__ import annotations

from copy import deepcopy
from typing import Any

from .dns_reconciliation import reconcile_delegation
from .dns_path_integrity import assess_direct_dns_result, summarize_authoritative_path


def _enum_value(value: Any) -> Any:
    """Return a stable serialized value for Enum/StrEnum-like objects."""
    return getattr(value, "value", value)


def _query_report(result: Any) -> dict[str, Any] | None:
    """Serialize one DNS observation without exposing internal cache objects."""
    if result is None:
        return None

    transport = getattr(result, "transport", None)
    query_mode = getattr(result, "query_mode", None)
    state = getattr(result, "state", None)
    data = {
        "qname": getattr(result, "qname", getattr(result, "host", None)),
        "qtype": getattr(result, "qtype", getattr(result, "rtype", None)),
        "query_mode": _enum_value(query_mode),
        "server_name": getattr(result, "server_name", None),
        "server_ip": getattr(result, "server_ip", None),
        "transport": _enum_value(transport) if transport is not None else None,
        "state": _enum_value(state),
        "rcode": getattr(result, "rcode", None),
        "authoritative": getattr(result, "aa", None),
        "truncated": getattr(result, "tc", None),
        "records": list(getattr(result, "records", ()) or ()),
        "error": getattr(result, "error", None),
    }
    if data["query_mode"] == "authoritative" and not bool(
        getattr(result, "request_recursion_desired", False)
    ):
        path = assess_direct_dns_result(result)
        data["path_integrity"] = {
            "status": path.status,
            "signals": list(path.signals),
        }
    return data


def _soa_record_report(record: Any) -> dict[str, Any] | None:
    if record is None:
        return None
    return {
        "mname": getattr(record, "mname", None),
        "rname": getattr(record, "rname", None),
        "serial": getattr(record, "serial", None),
        "refresh": getattr(record, "refresh", None),
        "retry": getattr(record, "retry", None),
        "expire": getattr(record, "expire", None),
        "minimum": getattr(record, "minimum", None),
    }


def _soa_observation_report(observation: Any) -> dict[str, Any] | None:
    if observation is None:
        return None
    return {
        "query": _query_report(getattr(observation, "result", None)),
        "soa": _soa_record_report(getattr(observation, "soa", None)),
        "parse_error": getattr(observation, "parse_error", None),
    }


def delegation_report_data(
    evidence: Any,
    analysis: Any,
    authoritative_analysis: Any = None,
) -> dict[str, Any]:
    """Return additive parent/child delegation evidence for the public report."""
    reconciled = reconcile_delegation(analysis, authoritative_analysis)
    parent_ns = list(
        getattr(analysis, "parent_nameservers", ())
        if analysis is not None
        else getattr(evidence, "delegated_nameservers", ()) if evidence is not None else ()
    )
    child_ns = list(reconciled.child_nameservers)
    confirmed_authority = set(reconciled.authority_confirmed_servers)

    analysis_by_name = {
        str(getattr(item, "name", "")).strip().lower().rstrip("."): item
        for item in (getattr(analysis, "nameservers", ()) or ())
        if getattr(item, "name", "")
    }

    nameservers: list[dict[str, Any]] = []
    for server in getattr(evidence, "delegated_servers", ()) or ():
        server_name_key = str(getattr(server, "name", "")).strip().lower().rstrip(".")
        item = analysis_by_name.get(server_name_key)
        addresses = getattr(server, "addresses", None)
        glue = getattr(server, "glue", None)
        nameservers.append(
            {
                "name": getattr(server, "name", None),
                "in_bailiwick": getattr(item, "in_bailiwick", None),
                "address_status": getattr(item, "address_status", "unknown"),
                "authority_status": (
                    "authoritative"
                    if server_name_key in confirmed_authority
                    and getattr(item, "authority_status", "unknown")
                    in {"unknown", "no_address", "unprobed"}
                    else getattr(item, "authority_status", "unknown")
                ),
                "authority_source": (
                    "authoritative_apex_ns"
                    if server_name_key in confirmed_authority
                    else "delegation_probe"
                ),
                "alias_status": getattr(item, "alias_status", "unknown"),
                "alias_targets": list(getattr(item, "alias_targets", ()) or ()),
                "glue_status": getattr(item, "glue_status", "unknown"),
                "glue_consistent": getattr(item, "glue_consistent", None),
                "candidate_addresses": list(
                    getattr(server, "candidate_addresses", ()) or ()
                ),
                "probe_addresses": list(getattr(server, "probe_addresses", ()) or ()),
                "unprobed_addresses": list(
                    getattr(server, "unprobed_addresses", ()) or ()
                ),
                "recursive_addresses": {
                    "query_mode": "recursive",
                    "ipv4": list(getattr(addresses, "ipv4", ()) or ()),
                    "ipv6": list(getattr(addresses, "ipv6", ()) or ()),
                    "queries": {
                        "A": _query_report(getattr(addresses, "a_result", None)),
                        "AAAA": _query_report(getattr(addresses, "aaaa_result", None)),
                        "CNAME": _query_report(getattr(addresses, "cname_result", None)),
                    },
                },
                "glue": {
                    "ipv4": list(getattr(glue, "ipv4", ()) or ()),
                    "ipv6": list(getattr(glue, "ipv6", ()) or ()),
                },
                "authoritative_queries": [
                    _query_report(result)
                    for result in (getattr(server, "authority_queries", ()) or ())
                ],
            }
        )

    glue = {
        getattr(item, "name", ""): {
            "ipv4": list(getattr(item, "ipv4", ()) or ()),
            "ipv6": list(getattr(item, "ipv6", ()) or ()),
        }
        for item in (getattr(evidence, "glue", ()) or ())
        if getattr(item, "name", "")
    }

    return {
        "zone": getattr(evidence, "zone", None) if evidence is not None else None,
        "parent_zone": (
            getattr(evidence, "parent_zone", None) if evidence is not None else None
        ),
        "available": bool(getattr(evidence, "available", False)) if evidence is not None else False,
        "parent_ns": parent_ns,
        "child_ns": child_ns,
        "consistent": reconciled.consistent,
        "complete": reconciled.complete,
        "consistency_source": reconciled.consistency_source,
        "missing_from_child": list(reconciled.missing_from_child),
        "extra_in_child": list(reconciled.extra_in_child),
        "glue": glue,
        "source": {
            "server_name": getattr(evidence, "source_server_name", None)
            if evidence is not None else None,
            "server_ip": getattr(evidence, "source_server_ip", None)
            if evidence is not None else None,
            "query_mode": "authoritative",
        },
        "parent_ns_lookup": _query_report(
            getattr(evidence, "parent_ns_result", None) if evidence is not None else None
        ),
        "referral_queries": [
            _query_report(result)
            for result in (getattr(evidence, "delegation_queries", ()) or ())
        ] if evidence is not None else [],
        "nameservers": nameservers,
        "error": getattr(evidence, "error", None) if evidence is not None else None,
    }


def authoritative_report_data(
    evidence: Any,
    analysis: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Serialize bounded per-server authoritative and SOA consistency evidence."""
    analysis_by_name = {
        getattr(item, "name", ""): item
        for item in (getattr(analysis, "servers", ()) or ())
        if getattr(item, "name", "")
    }

    servers: list[dict[str, Any]] = []
    for raw_server in getattr(evidence, "servers", ()) or ():
        server_analysis = analysis_by_name.get(getattr(raw_server, "name", ""))
        transport_by_ip = {
            getattr(item, "server_ip", ""): item
            for item in (getattr(server_analysis, "transport", ()) or ())
            if getattr(item, "server_ip", "")
        }
        endpoints = []
        for endpoint in getattr(raw_server, "endpoints", ()) or ():
            transport = transport_by_ip.get(getattr(endpoint, "server_ip", ""))
            endpoints.append(
                {
                    "server_ip": getattr(endpoint, "server_ip", None),
                    "transport_status": getattr(transport, "status", "unknown"),
                    "path_integrity": {
                        "udp": {
                            "status": getattr(transport, "udp_path_integrity", "unknown"),
                            "signals": list(getattr(transport, "udp_path_signals", ()) or ()),
                        },
                        "tcp": {
                            "status": getattr(transport, "tcp_path_integrity", "unknown"),
                            "signals": list(getattr(transport, "tcp_path_signals", ()) or ()),
                        },
                    },
                    "udp_soa": _soa_observation_report(
                        getattr(endpoint, "udp_soa", None)
                    ),
                    "tcp_soa": _soa_observation_report(
                        getattr(endpoint, "tcp_soa", None)
                    ),
                    "edns_soa": _soa_observation_report(
                        getattr(endpoint, "edns_soa", None)
                    ),
                }
            )

        servers.append(
            {
                "name": getattr(raw_server, "name", None),
                "candidate_addresses": list(
                    getattr(raw_server, "candidate_addresses", ()) or ()
                ),
                "probe_addresses": list(
                    getattr(raw_server, "probe_addresses", ()) or ()
                ),
                "unprobed_addresses": list(
                    getattr(raw_server, "unprobed_addresses", ()) or ()
                ),
                "soa_authority_status": getattr(
                    server_analysis, "soa_authority_status", "unknown"
                ),
                "edns_status": getattr(server_analysis, "edns_status", "unknown"),
                "apex_nameservers": list(
                    getattr(server_analysis, "apex_nameservers", ())
                    if server_analysis is not None
                    else getattr(raw_server, "apex_nameservers", ())
                ),
                "apex_ns_query": _query_report(
                    getattr(raw_server, "apex_ns_result", None)
                ),
                "soa_records": [
                    _soa_record_report(record)
                    for record in (getattr(server_analysis, "soa_records", ()) or ())
                ],
                "endpoints": endpoints,
            }
        )

    serials = {
        name: list(values)
        for name, values in (getattr(analysis, "soa_serials", ()) or ())
    }
    ns_rrsets = {
        name: list(values)
        for name, values in (getattr(analysis, "observed_ns_rrsets", ()) or ())
    }
    configuration_consistent = (
        getattr(analysis, "soa_configuration_consistent", None)
        if analysis is not None else None
    )
    soa = {
        "zone": (
            getattr(analysis, "zone", None)
            if analysis is not None
            else getattr(evidence, "zone", None) if evidence is not None else None
        ),
        "consistent": configuration_consistent,
        "configuration_consistent": configuration_consistent,
        "serial_consistent": (
            getattr(analysis, "soa_serial_consistent", None)
            if analysis is not None else None
        ),
        "differing_fields": list(
            getattr(analysis, "soa_differing_fields", ()) or ()
        ) if analysis is not None else [],
        "serials": serials,
        "ns_rrset_consistent": (
            getattr(analysis, "ns_rrset_consistent", None)
            if analysis is not None else None
        ),
        "observed_ns_rrsets": ns_rrsets,
        "scope": {
            "endpoint_probe_limit": getattr(evidence, "endpoint_probe_limit", None)
            if evidence is not None else None,
            "endpoint_probe_limit_reached": bool(
                getattr(evidence, "endpoint_probe_limit_reached", False)
            ) if evidence is not None else False,
        },
    }
    return servers, soa


def caa_report_data(caa: Any) -> dict[str, Any]:
    """Mirror existing CAA evidence under dns.caa with explicit recursive context."""
    source = caa if isinstance(caa, dict) else {}
    lookup_chain = []
    for step in source.get("lookup_chain", []) or []:
        item = deepcopy(step)
        if isinstance(item, dict):
            item.setdefault("query_mode", "recursive")
        lookup_chain.append(item)

    analysis = deepcopy(source.get("analysis", {}))
    if not isinstance(analysis, dict):
        analysis = {}
    analysis.setdefault("state", "unknown")

    return {
        "query_mode": "recursive",
        "lookup_chain": lookup_chain,
        "effective_name": source.get("effective_name"),
        "records": deepcopy(source.get("records", []) or []),
        "analysis": analysis,
        "lookup_failure": deepcopy(source.get("lookup_failure")),
    }


def dns_infrastructure_report_data(
    delegation: Any,
    delegation_analysis: Any,
    authoritative_dns: Any,
    authoritative_dns_analysis: Any,
    caa: Any,
) -> dict[str, Any]:
    """Build the additive v1.3 DNS infrastructure report sections."""
    authoritative_servers, soa = authoritative_report_data(
        authoritative_dns,
        authoritative_dns_analysis,
    )
    return {
        "path_integrity": summarize_authoritative_path(authoritative_dns),
        "delegation": delegation_report_data(
            delegation,
            delegation_analysis,
            authoritative_dns_analysis,
        ),
        "authoritative_servers": authoritative_servers,
        "soa": soa,
        "caa": caa_report_data(caa),
    }


__all__ = [
    "authoritative_report_data",
    "caa_report_data",
    "delegation_report_data",
    "dns_infrastructure_report_data",
]
