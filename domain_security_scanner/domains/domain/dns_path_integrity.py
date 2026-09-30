from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...models import DnsQueryMode


DIRECT_PATH_USABLE = "usable"
DIRECT_PATH_SUSPECTED_INTERCEPTION = "suspected_interception"
DIRECT_PATH_PARTIAL = "partial"
DIRECT_PATH_MIXED = "mixed"
DIRECT_PATH_UNKNOWN = "unknown"

SIGNAL_UNEXPECTED_RA_ON_RD0 = "unexpected_ra_on_rd0"
SIGNAL_UNEXPECTED_RD_ECHO = "unexpected_rd_echo"
SIGNAL_REFERRAL_LIKE_APEX_RESPONSE = "referral_like_apex_response"
SIGNAL_REFERRAL_OWNER_DIFFERS = "referral_owner_differs_from_qname"
SIGNAL_AA_WITHOUT_REQUESTED_RRSET = "aa_without_requested_apex_rrset"


@dataclass(frozen=True)
class DirectDnsPathAssessment:
    """Integrity assessment for one direct DNS response.

    The assessment is deliberately narrow. It detects response patterns that are
    inconsistent with the direct authoritative query profile and therefore make
    attribution to the requested server IP unsafe. It does not attempt to prove
    that a specific middlebox (Pi-hole, router, VPN, ISP, etc.) performed the
    interception.
    """

    status: str
    signals: tuple[str, ...] = ()



def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)



def _normalize_name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")



def _section_rows(section: tuple[str, ...] | list[str] | None):
    """Yield normalized owner/type pairs from stored RRset text."""
    for rrset_text in tuple(section or ()):
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            owner, _ttl, _rdclass, rtype, _rdata = parts
            yield _normalize_name(owner), rtype.upper()



def assess_direct_dns_result(result: Any) -> DirectDnsPathAssessment:
    """Assess whether one direct DNS response can be attributed to its target.

    A single RA flag is only a signal: some DNS implementations can advertise
    recursion while also serving authoritative data. We classify interception as
    suspected only when an RD=0 direct apex query also looks referral-like rather
    than returning the requested apex RRset. This matches transparent DNS
    redirection without turning normal recursive or timeout behavior into a
    failure.
    """
    if result is None:
        return DirectDnsPathAssessment(DIRECT_PATH_UNKNOWN)

    if _enum_value(getattr(result, "query_mode", None)) != DnsQueryMode.AUTHORITATIVE.value:
        return DirectDnsPathAssessment(DIRECT_PATH_UNKNOWN)

    # RD=1 queries are deliberate open-recursion probes. Their RA flag cannot be
    # used to infer whether the path to the intended authoritative IP was clean.
    if bool(getattr(result, "request_recursion_desired", False)):
        return DirectDnsPathAssessment(DIRECT_PATH_UNKNOWN)

    if getattr(result, "rcode", None) is None:
        return DirectDnsPathAssessment(DIRECT_PATH_UNKNOWN)

    signals: list[str] = []
    if getattr(result, "ra", None) is True:
        signals.append(SIGNAL_UNEXPECTED_RA_ON_RD0)
    if getattr(result, "rd", None) is True:
        signals.append(SIGNAL_UNEXPECTED_RD_ECHO)

    qtype = str(getattr(result, "qtype", getattr(result, "rtype", "")) or "").upper()
    qname = _normalize_name(getattr(result, "qname", getattr(result, "host", "")))
    answer_rows = tuple(_section_rows(getattr(result, "answer_section", ())))
    authority_rows = tuple(_section_rows(getattr(result, "authority_section", ())))

    requested_in_answer = any(rtype == qtype for _owner, rtype in answer_rows)
    authority_has_ns = any(rtype == "NS" for _owner, rtype in authority_rows)
    authority_has_soa = any(rtype == "SOA" for _owner, rtype in authority_rows)

    referral_like = (
        qtype in {"SOA", "NS"}
        and not requested_in_answer
        and authority_has_ns
        and not authority_has_soa
    )
    if referral_like:
        signals.append(SIGNAL_REFERRAL_LIKE_APEX_RESPONSE)
        ns_owners = {
            owner for owner, rtype in authority_rows if rtype == "NS" and owner
        }
        if qname and any(owner != qname for owner in ns_owners):
            signals.append(SIGNAL_REFERRAL_OWNER_DIFFERS)
        if getattr(result, "aa", None) is True:
            signals.append(SIGNAL_AA_WITHOUT_REQUESTED_RRSET)

    # Requiring the referral-like response as well as an RD=0 recursion signal
    # avoids treating the RA bit alone as proof of interception.
    if referral_like and (
        SIGNAL_UNEXPECTED_RA_ON_RD0 in signals
        or SIGNAL_UNEXPECTED_RD_ECHO in signals
    ):
        return DirectDnsPathAssessment(
            DIRECT_PATH_SUSPECTED_INTERCEPTION,
            tuple(signals),
        )

    return DirectDnsPathAssessment(DIRECT_PATH_USABLE, tuple(signals))



def _aggregate_status(assessments: tuple[DirectDnsPathAssessment, ...]) -> str:
    if not assessments:
        return DIRECT_PATH_UNKNOWN

    statuses = [item.status for item in assessments]
    has_suspect = DIRECT_PATH_SUSPECTED_INTERCEPTION in statuses
    has_usable = DIRECT_PATH_USABLE in statuses
    has_unknown = DIRECT_PATH_UNKNOWN in statuses

    if has_suspect and has_usable:
        return DIRECT_PATH_MIXED
    if has_suspect:
        return DIRECT_PATH_SUSPECTED_INTERCEPTION
    if has_usable and has_unknown:
        return DIRECT_PATH_PARTIAL
    if has_usable:
        return DIRECT_PATH_USABLE
    return DIRECT_PATH_UNKNOWN



def summarize_authoritative_path(evidence: Any) -> dict[str, Any]:
    """Summarize ordinary direct SOA path integrity by transport.

    This intentionally uses only the already-bounded issue #15 SOA probes and
    performs no additional network I/O.
    """
    observations: list[dict[str, Any]] = []
    by_transport: dict[str, list[DirectDnsPathAssessment]] = {"udp": [], "tcp": []}

    for server in tuple(getattr(evidence, "servers", ()) or ()):
        for endpoint in tuple(getattr(server, "endpoints", ()) or ()):
            for transport_name, attr in (("udp", "udp_soa"), ("tcp", "tcp_soa")):
                observation = getattr(endpoint, attr, None)
                result = getattr(observation, "result", None) if observation is not None else None
                assessment = assess_direct_dns_result(result)
                by_transport[transport_name].append(assessment)
                observations.append(
                    {
                        "server_name": getattr(endpoint, "server_name", None),
                        "server_ip": getattr(endpoint, "server_ip", None),
                        "transport": transport_name,
                        "status": assessment.status,
                        "signals": list(assessment.signals),
                    }
                )

    all_assessments = tuple(
        assessment
        for values in by_transport.values()
        for assessment in values
    )
    signals = sorted(
        {
            signal
            for assessment in all_assessments
            for signal in assessment.signals
        }
    )
    return {
        "status": _aggregate_status(all_assessments),
        "basis": "direct_authoritative_soa",
        "transports": {
            name: {
                "status": _aggregate_status(tuple(values)),
                "observations": len(values),
            }
            for name, values in by_transport.items()
        },
        "signals": signals,
        "observations": observations,
    }


def summarize_delegation_path(evidence: Any) -> dict[str, Any]:
    """Summarize direct parent/child delegation query path integrity.

    This catches interception that prevents issue #14 from ever producing
    delegated-server evidence. In that case issue #15 has no SOA endpoints to
    summarize, so the fallback trigger must still be able to use the earlier
    direct delegation probes.
    """
    observations: list[dict[str, Any]] = []
    assessments: list[DirectDnsPathAssessment] = []

    def add(result: Any, stage: str) -> None:
        assessment = assess_direct_dns_result(result)
        assessments.append(assessment)
        observations.append(
            {
                "stage": stage,
                "server_name": getattr(result, "server_name", None),
                "server_ip": getattr(result, "server_ip", None),
                "transport": _enum_value(getattr(result, "transport", None)),
                "qtype": getattr(result, "qtype", getattr(result, "rtype", None)),
                "status": assessment.status,
                "signals": list(assessment.signals),
            }
        )

    for result in tuple(getattr(evidence, "delegation_queries", ()) or ()):
        add(result, "parent_delegation")
    for server in tuple(getattr(evidence, "delegated_servers", ()) or ()):
        for result in tuple(getattr(server, "authority_queries", ()) or ()):
            add(result, "child_authority")

    signals = sorted(
        {signal for assessment in assessments for signal in assessment.signals}
    )
    return {
        "status": _aggregate_status(tuple(assessments)),
        "basis": "direct_delegation_queries",
        "signals": signals,
        "observations": observations,
    }


def summarize_dns_path(delegation: Any, authoritative_evidence: Any) -> dict[str, Any]:
    """Combine issue #14 and issue #15 direct-path integrity observations.

    The authoritative SOA view remains preferred when it exists, but a suspect
    parent/child delegation path must not disappear merely because interception
    prevented authoritative endpoint evidence from being built.
    """
    authoritative = summarize_authoritative_path(authoritative_evidence)
    delegation_summary = summarize_delegation_path(delegation)

    combined_observations = [
        *delegation_summary.get("observations", []),
        *authoritative.get("observations", []),
    ]
    combined_assessments = tuple(
        DirectDnsPathAssessment(
            str(item.get("status") or DIRECT_PATH_UNKNOWN),
            tuple(item.get("signals", ()) or ()),
        )
        for item in combined_observations
    )
    if not combined_observations:
        return authoritative

    signals = sorted(
        {
            signal
            for assessment in combined_assessments
            for signal in assessment.signals
        }
    )
    authoritative_count = len(authoritative.get("observations", []))
    delegation_count = len(delegation_summary.get("observations", []))
    if authoritative_count and delegation_count:
        basis = "direct_delegation_and_authoritative"
    elif delegation_count:
        basis = "direct_delegation_queries"
    else:
        basis = "direct_authoritative_soa"

    by_transport: dict[str, list[DirectDnsPathAssessment]] = {"udp": [], "tcp": []}
    for item in combined_observations:
        transport = str(item.get("transport") or "").lower()
        if transport not in by_transport:
            continue
        by_transport[transport].append(
            DirectDnsPathAssessment(
                str(item.get("status") or DIRECT_PATH_UNKNOWN),
                tuple(item.get("signals", ()) or ()),
            )
        )

    return {
        "status": _aggregate_status(combined_assessments),
        "basis": basis,
        "transports": {
            name: {
                "status": _aggregate_status(tuple(values)),
                "observations": len(values),
            }
            for name, values in by_transport.items()
        },
        "signals": signals,
        "observations": combined_observations,
    }


__all__ = [
    "DIRECT_PATH_MIXED",
    "DIRECT_PATH_PARTIAL",
    "DIRECT_PATH_SUSPECTED_INTERCEPTION",
    "DIRECT_PATH_UNKNOWN",
    "DIRECT_PATH_USABLE",
    "DirectDnsPathAssessment",
    "assess_direct_dns_result",
    "summarize_authoritative_path",
    "summarize_delegation_path",
    "summarize_dns_path",
]
