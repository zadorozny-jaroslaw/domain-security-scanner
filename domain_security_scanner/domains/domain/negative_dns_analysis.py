from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ...models import DnsQueryResult, DnsQueryState
from .negative_dns import NegativeDnsEvidence, NegativeDnsServerEvidence


class NegativeProbeOutcome(StrEnum):
    """Interpretation of one generated-name authoritative observation."""

    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    POSITIVE = "positive_answer"
    UNKNOWN = "unknown"


class NegativeDnsState(StrEnum):
    """Conservative server/zone interpretation of generated-name behavior."""

    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    WILDCARD = "wildcard"
    UNKNOWN = "unknown"


class RecursionState(StrEnum):
    """Externally observable recursion state for an authoritative server."""

    OPEN = "open"
    CLOSED = "closed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NegativeProbeAnalysis:
    qname: str
    outcome: NegativeProbeOutcome
    rcode: str | None
    authoritative: bool | None
    answer_records: tuple[str, ...]
    soa_records: tuple[str, ...]


@dataclass(frozen=True)
class NegativeDnsServerAnalysis:
    server_name: str
    server_ip: str | None
    negative_state: NegativeDnsState
    negative_complete: bool
    probes: tuple[NegativeProbeAnalysis, ...]
    wildcard_answer_sets_equal: bool | None
    recursion_state: RecursionState
    recursion_reason: str


@dataclass(frozen=True)
class NegativeDnsAnalysis:
    zone: str
    negative_state: NegativeDnsState
    negative_complete: bool
    servers: tuple[NegativeDnsServerAnalysis, ...]
    wildcard_servers: tuple[str, ...]
    recursion_state: RecursionState
    recursion_open_servers: tuple[str, ...]
    recursion_closed_servers: tuple[str, ...]
    recursion_unknown_servers: tuple[str, ...]


def _normalize_rr_text(value: str) -> str:
    return " ".join(str(value).split()).strip().lower()


def _soa_records(result: DnsQueryResult) -> tuple[str, ...]:
    records: set[str] = set()
    for rrset_text in result.authority_section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            if parts[3].upper() == "SOA":
                records.add(" ".join(parts))
    return tuple(sorted(records))


def _answer_fingerprint(result: DnsQueryResult) -> tuple[str, ...]:
    if result.answer_section:
        return tuple(
            sorted(
                _normalize_rr_text(line)
                for rrset_text in result.answer_section
                for line in str(rrset_text).splitlines()
                if str(line).strip()
            )
        )
    return tuple(sorted(_normalize_rr_text(value) for value in result.records))


def analyze_negative_probe(result: DnsQueryResult) -> NegativeProbeAnalysis:
    """Classify one already-collected generated-name observation."""
    if result.state == DnsQueryState.NXDOMAIN:
        outcome = NegativeProbeOutcome.NXDOMAIN
    elif result.state == DnsQueryState.NO_ANSWER:
        outcome = NegativeProbeOutcome.NODATA
    elif (
        result.state == DnsQueryState.ANSWER
        and result.rcode == "NOERROR"
        and result.aa is True
    ):
        outcome = NegativeProbeOutcome.POSITIVE
    else:
        outcome = NegativeProbeOutcome.UNKNOWN

    return NegativeProbeAnalysis(
        qname=result.qname,
        outcome=outcome,
        rcode=result.rcode,
        authoritative=result.aa,
        answer_records=_answer_fingerprint(result),
        soa_records=_soa_records(result),
    )


def _server_negative_state(
    evidence: NegativeDnsEvidence,
    probes: tuple[NegativeProbeAnalysis, ...],
) -> tuple[NegativeDnsState, bool, bool | None]:
    expected = len(evidence.negative_names)
    if expected < 1 or len(probes) != expected:
        return NegativeDnsState.UNKNOWN, False, None

    outcomes = tuple(probe.outcome for probe in probes)
    if any(outcome == NegativeProbeOutcome.UNKNOWN for outcome in outcomes):
        return NegativeDnsState.UNKNOWN, False, None

    if all(outcome == NegativeProbeOutcome.NXDOMAIN for outcome in outcomes):
        return NegativeDnsState.NXDOMAIN, True, None

    if all(outcome == NegativeProbeOutcome.NODATA for outcome in outcomes):
        return NegativeDnsState.NODATA, True, None

    if (
        expected >= 2
        and all(outcome == NegativeProbeOutcome.POSITIVE for outcome in outcomes)
    ):
        fingerprints = tuple(probe.answer_records for probe in probes)
        return (
            NegativeDnsState.WILDCARD,
            True,
            len(set(fingerprints)) == 1,
        )

    # Mixed conclusive observations (for example NXDOMAIN on one randomized
    # label and a positive answer on another) are deliberately not generalized
    # into wildcard or negative behavior.
    return NegativeDnsState.UNKNOWN, False, None


def analyze_recursion_result(result: DnsQueryResult | None) -> tuple[RecursionState, str]:
    """Require positive resolution evidence before declaring open recursion."""
    if result is None:
        return RecursionState.UNKNOWN, "No recursion observation was collected."

    if not result.request_recursion_desired:
        return RecursionState.UNKNOWN, "The observation did not request recursion."

    rcode = (result.rcode or "").upper()
    if rcode == "REFUSED":
        return RecursionState.CLOSED, "The server explicitly refused the recursive query."

    # RA by itself is only a capability advertisement.  Open recursion requires
    # a usable non-authoritative resolution result for the out-of-zone query.
    if (
        result.ra is True
        and result.aa is False
        and result.state
        in {
            DnsQueryState.ANSWER,
            DnsQueryState.NXDOMAIN,
            DnsQueryState.NO_ANSWER,
        }
    ):
        return (
            RecursionState.OPEN,
            "The server returned a conclusive non-authoritative result with recursion available for the out-of-zone query.",
        )

    if result.state in {
        DnsQueryState.TIMEOUT,
        DnsQueryState.SERVFAIL,
        DnsQueryState.TRUNCATED,
        DnsQueryState.TRANSPORT_ERROR,
    }:
        return RecursionState.UNKNOWN, "The recursive query did not produce conclusive evidence."

    if result.ra is True:
        return (
            RecursionState.UNKNOWN,
            "The server advertised recursion availability, but the response did not prove recursive resolution.",
        )

    return (
        RecursionState.UNKNOWN,
        "The response did not positively prove either recursive service or an explicit refusal.",
    )


def analyze_negative_dns_server(
    evidence: NegativeDnsEvidence,
    server: NegativeDnsServerEvidence,
) -> NegativeDnsServerAnalysis:
    probes = tuple(analyze_negative_probe(result) for result in server.negative_results)
    negative_state, negative_complete, wildcard_equal = _server_negative_state(
        evidence,
        probes,
    )
    recursion_state, recursion_reason = analyze_recursion_result(server.recursion_result)
    return NegativeDnsServerAnalysis(
        server_name=server.server_name,
        server_ip=server.server_ip,
        negative_state=negative_state,
        negative_complete=negative_complete,
        probes=probes,
        wildcard_answer_sets_equal=wildcard_equal,
        recursion_state=recursion_state,
        recursion_reason=recursion_reason,
    )


def _zone_negative_state(
    servers: tuple[NegativeDnsServerAnalysis, ...],
) -> tuple[NegativeDnsState, bool]:
    if not servers:
        return NegativeDnsState.UNKNOWN, False
    if not all(server.negative_complete for server in servers):
        return NegativeDnsState.UNKNOWN, False

    states = {server.negative_state for server in servers}
    if len(states) == 1:
        state = next(iter(states))
        if state != NegativeDnsState.UNKNOWN:
            return state, True
    return NegativeDnsState.UNKNOWN, False


def analyze_negative_dns(evidence: NegativeDnsEvidence) -> NegativeDnsAnalysis:
    """Analyze issue #19 evidence without performing any network I/O."""
    servers = tuple(
        analyze_negative_dns_server(evidence, server)
        for server in evidence.servers
    )
    negative_state, negative_complete = _zone_negative_state(servers)

    wildcard_servers = tuple(
        server.server_name
        for server in servers
        if server.negative_state == NegativeDnsState.WILDCARD
    )
    open_servers = tuple(
        server.server_name
        for server in servers
        if server.recursion_state == RecursionState.OPEN
    )
    closed_servers = tuple(
        server.server_name
        for server in servers
        if server.recursion_state == RecursionState.CLOSED
    )
    unknown_servers = tuple(
        server.server_name
        for server in servers
        if server.recursion_state == RecursionState.UNKNOWN
    )

    if open_servers:
        recursion_state = RecursionState.OPEN
    elif servers and len(closed_servers) == len(servers):
        recursion_state = RecursionState.CLOSED
    else:
        recursion_state = RecursionState.UNKNOWN

    return NegativeDnsAnalysis(
        zone=evidence.zone,
        negative_state=negative_state,
        negative_complete=negative_complete,
        servers=servers,
        wildcard_servers=wildcard_servers,
        recursion_state=recursion_state,
        recursion_open_servers=open_servers,
        recursion_closed_servers=closed_servers,
        recursion_unknown_servers=unknown_servers,
    )


__all__ = [
    "NegativeDnsAnalysis",
    "NegativeDnsServerAnalysis",
    "NegativeDnsState",
    "NegativeProbeAnalysis",
    "NegativeProbeOutcome",
    "RecursionState",
    "analyze_negative_dns",
    "analyze_negative_dns_server",
    "analyze_negative_probe",
    "analyze_recursion_result",
]
