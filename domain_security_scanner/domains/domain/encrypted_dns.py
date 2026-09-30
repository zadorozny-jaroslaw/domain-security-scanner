from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from ...models import DnsQueryMode, DnsQueryResult, DnsQueryState
from .dns_path_integrity import (
    DIRECT_PATH_MIXED,
    DIRECT_PATH_SUSPECTED_INTERCEPTION,
    summarize_dns_path,
)

DOH_TIMEOUT = 3.0
DOH_EDNS_PAYLOAD = 1232
ENCRYPTED_DNS_RRTYPES = ("SOA", "NS")
DOH_RESOLVERS = (
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/dns-query"),
)

RRSET_CONSENSUS = "consensus"
RRSET_DISAGREEMENT = "disagreement"
RRSET_PARTIAL = "partial"
RRSET_UNAVAILABLE = "unavailable"

ENCRYPTED_DNS_USABLE = "usable"
ENCRYPTED_DNS_PARTIAL = "partial"
ENCRYPTED_DNS_DISAGREEMENT = "disagreement"
ENCRYPTED_DNS_UNAVAILABLE = "unavailable"
ENCRYPTED_DNS_NOT_NEEDED = "not_needed"


@dataclass(frozen=True)
class EncryptedDnsObservation:
    """One DNS-over-HTTPS recursive observation from an external resolver."""

    resolver_name: str
    resolver_url: str
    qtype: str
    result: DnsQueryResult


@dataclass(frozen=True)
class EncryptedDnsRrsetEvidence:
    """Consensus view for one zone-level RRset across bounded DoH resolvers."""

    qtype: str
    status: str
    rdata: tuple[str, ...]
    observations: tuple[EncryptedDnsObservation, ...]


@dataclass(frozen=True)
class EncryptedDnsEvidence:
    """Bounded encrypted recursive fallback evidence for one zone."""

    zone: str
    status: str
    trigger: str
    attempted: bool
    rrsets: tuple[EncryptedDnsRrsetEvidence, ...] = ()
    resolvers: tuple[tuple[str, str], ...] = DOH_RESOLVERS


def _normalize_name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _sanitize_error(exc: BaseException) -> str:
    text = " ".join(str(exc or "").split()).strip()
    return (text or exc.__class__.__name__)[:240]


def _section_text(section) -> tuple[str, ...]:
    return tuple(rrset.to_text() for rrset in section)


def _answer_records(response) -> tuple[str, ...]:
    return tuple(
        rdata.to_text()
        for rrset in response.answer
        for rdata in rrset
    )


def _response_state(response) -> DnsQueryState:
    if response.flags & dns.flags.TC:
        return DnsQueryState.TRUNCATED
    rcode = response.rcode()
    if rcode == dns.rcode.SERVFAIL:
        return DnsQueryState.SERVFAIL
    if rcode == dns.rcode.NXDOMAIN:
        return DnsQueryState.NXDOMAIN
    if rcode == dns.rcode.NOERROR:
        return DnsQueryState.ANSWER if response.answer else DnsQueryState.NO_ANSWER
    return DnsQueryState.ERROR


def _normalize_rdata(qtype: str, value: str) -> str:
    text = str(value or "").strip()
    target = str(qtype).upper()
    if target == "NS":
        return text.lower()
    if target == "SOA":
        parts = text.split()
        if len(parts) == 7:
            parts[0] = parts[0].lower()
            parts[1] = parts[1].lower()
            return " ".join(parts)
    return text


def _requested_rdata(result: DnsQueryResult, qtype: str) -> tuple[str, ...]:
    target = str(qtype).upper()
    values: list[str] = []
    for rrset_text in result.answer_section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) == 5 and parts[3].upper() == target:
                values.append(_normalize_rdata(target, parts[4]))
    return tuple(sorted(values))


def _doh_query(
    session,
    *,
    zone: str,
    qtype: str,
    resolver_name: str,
    resolver_url: str,
    timeout: float = DOH_TIMEOUT,
) -> EncryptedDnsObservation:
    """Issue one RFC 8484 wire-format DNS query over HTTPS."""
    query = dns.message.make_query(
        zone,
        qtype,
        use_edns=0,
        want_dnssec=True,
        payload=DOH_EDNS_PAYLOAD,
        request_payload=DOH_EDNS_PAYLOAD,
    )
    query.flags |= dns.flags.RD

    response = None
    error = None
    state = DnsQueryState.ERROR
    try:
        http_response = session.post(
            resolver_url,
            data=query.to_wire(),
            headers={
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message",
            },
            timeout=timeout,
        )
        http_response.raise_for_status()
        response = dns.message.from_wire(http_response.content)
        if response.id != query.id:
            raise ValueError("DNS-over-HTTPS response ID did not match the request")
        if not (response.flags & dns.flags.QR):
            raise ValueError("DNS-over-HTTPS response did not set QR")
        state = _response_state(response)
        if state == DnsQueryState.ERROR:
            error = f"DNS RCODE {dns.rcode.to_text(response.rcode())}"
        elif state == DnsQueryState.TRUNCATED:
            error = "DNS-over-HTTPS response was unexpectedly truncated"
    except Exception as exc:
        error = _sanitize_error(exc)
        response = None
        state = DnsQueryState.ERROR

    common = dict(
        error=error,
        query_mode=DnsQueryMode.RECURSIVE,
        server_name=resolver_name,
        server_ip=None,
        request_edns_version=0,
        request_edns_payload=DOH_EDNS_PAYLOAD,
        request_want_dnssec=True,
        request_recursion_desired=True,
    )
    if response is None:
        result = DnsQueryResult(zone, qtype, state, **common)
    else:
        has_edns = response.edns >= 0
        result = DnsQueryResult(
            zone,
            qtype,
            state,
            _answer_records(response),
            rcode=dns.rcode.to_text(response.rcode()),
            aa=bool(response.flags & dns.flags.AA),
            tc=bool(response.flags & dns.flags.TC),
            edns_version=response.edns if has_edns else None,
            edns_payload=response.payload if has_edns else None,
            edns_flags=response.ednsflags if has_edns else None,
            answer_section=_section_text(response.answer),
            authority_section=_section_text(response.authority),
            additional_section=_section_text(response.additional),
            rd=bool(response.flags & dns.flags.RD),
            ra=bool(response.flags & dns.flags.RA),
            **common,
        )

    return EncryptedDnsObservation(
        resolver_name=resolver_name,
        resolver_url=resolver_url,
        qtype=str(qtype).upper(),
        result=result,
    )


def _consensus_for_qtype(
    qtype: str,
    observations: tuple[EncryptedDnsObservation, ...],
) -> EncryptedDnsRrsetEvidence:
    usable: list[tuple[EncryptedDnsObservation, tuple[str, ...]]] = []
    for observation in observations:
        result = observation.result
        values = _requested_rdata(result, qtype)
        if result.state == DnsQueryState.ANSWER and values:
            usable.append((observation, values))

    if len(usable) >= 2:
        fingerprints = {values for _observation, values in usable}
        if len(fingerprints) == 1:
            return EncryptedDnsRrsetEvidence(
                qtype=str(qtype).upper(),
                status=RRSET_CONSENSUS,
                rdata=usable[0][1],
                observations=observations,
            )
        return EncryptedDnsRrsetEvidence(
            qtype=str(qtype).upper(),
            status=RRSET_DISAGREEMENT,
            rdata=(),
            observations=observations,
        )

    if len(usable) == 1:
        return EncryptedDnsRrsetEvidence(
            qtype=str(qtype).upper(),
            status=RRSET_PARTIAL,
            rdata=usable[0][1],
            observations=observations,
        )

    return EncryptedDnsRrsetEvidence(
        qtype=str(qtype).upper(),
        status=RRSET_UNAVAILABLE,
        rdata=(),
        observations=observations,
    )


def _overall_status(rrsets: tuple[EncryptedDnsRrsetEvidence, ...]) -> str:
    by_type = {item.qtype: item.status for item in rrsets}
    required = [by_type.get(qtype, RRSET_UNAVAILABLE) for qtype in ENCRYPTED_DNS_RRTYPES]
    if all(status == RRSET_CONSENSUS for status in required):
        return ENCRYPTED_DNS_USABLE
    if any(status == RRSET_DISAGREEMENT for status in required):
        return ENCRYPTED_DNS_DISAGREEMENT
    if any(status in {RRSET_CONSENSUS, RRSET_PARTIAL} for status in required):
        return ENCRYPTED_DNS_PARTIAL
    return ENCRYPTED_DNS_UNAVAILABLE


def encrypted_dns_fallback_needed(
    authoritative_dns: Any,
    delegation: Any = None,
) -> tuple[bool, str]:
    path = summarize_dns_path(delegation, authoritative_dns)
    status = str(path.get("status") or "unknown")
    return status in {
        DIRECT_PATH_SUSPECTED_INTERCEPTION,
        DIRECT_PATH_MIXED,
    }, status


def collect_encrypted_dns_evidence(
    scanner,
    authoritative_dns: Any,
    delegation: Any = None,
) -> EncryptedDnsEvidence:
    """Collect SOA/NS consensus over HTTPS only when direct DNS attribution is suspect."""
    zone = _normalize_name(
        getattr(authoritative_dns, "zone", None)
        or getattr(delegation, "zone", None)
        or getattr(scanner, "root_domain", "")
    )
    needed, trigger = encrypted_dns_fallback_needed(authoritative_dns, delegation)
    if not needed or not zone:
        return EncryptedDnsEvidence(
            zone=zone,
            status=ENCRYPTED_DNS_NOT_NEEDED,
            trigger=trigger,
            attempted=False,
        )

    session = getattr(scanner, "session", None)
    if session is None:
        raise RuntimeError("Encrypted DNS fallback requires the scanner HTTP session")

    rrsets: list[EncryptedDnsRrsetEvidence] = []
    for qtype in ENCRYPTED_DNS_RRTYPES:
        observations = tuple(
            _doh_query(
                session,
                zone=zone,
                qtype=qtype,
                resolver_name=resolver_name,
                resolver_url=resolver_url,
            )
            for resolver_name, resolver_url in DOH_RESOLVERS
        )
        rrsets.append(_consensus_for_qtype(qtype, observations))

    evidence = tuple(rrsets)
    return EncryptedDnsEvidence(
        zone=zone,
        status=_overall_status(evidence),
        trigger=trigger,
        attempted=True,
        rrsets=evidence,
    )


def encrypted_dns_report_data(evidence: EncryptedDnsEvidence | None) -> dict[str, Any]:
    if evidence is None:
        return {
            "status": ENCRYPTED_DNS_NOT_NEEDED,
            "attempted": False,
            "trigger": None,
            "channel": "doh",
            "transport": "https",
            "resolvers": [],
            "rrsets": {},
        }

    rrsets = {}
    for rrset in evidence.rrsets:
        rrsets[rrset.qtype] = {
            "status": rrset.status,
            "rdata": list(rrset.rdata),
            "observations": [
                {
                    "resolver": observation.resolver_name,
                    "endpoint": observation.resolver_url,
                    "state": observation.result.state.value,
                    "rcode": observation.result.rcode,
                    "authoritative": observation.result.aa,
                    "recursion_available": observation.result.ra,
                    "error": observation.result.error,
                    "rdata": list(
                        _requested_rdata(observation.result, rrset.qtype)
                    ),
                }
                for observation in rrset.observations
            ],
        }

    return {
        "status": evidence.status,
        "attempted": evidence.attempted,
        "trigger": evidence.trigger,
        "zone": evidence.zone,
        "channel": "doh",
        "transport": "https",
        "resolvers": [
            {"name": name, "endpoint": url}
            for name, url in evidence.resolvers
        ],
        "rrsets": rrsets,
        "scope": {
            "zone_level_only": True,
            "per_authoritative_server_attribution": False,
            "qtypes": list(ENCRYPTED_DNS_RRTYPES),
        },
    }


def encrypted_dns_finding(evidence: EncryptedDnsEvidence | None):
    """Return one non-scoring customer-facing fallback finding when attempted."""
    if evidence is None or not evidence.attempted:
        return None
    if evidence.status == ENCRYPTED_DNS_USABLE:
        return (
            "Encrypted DNS fallback",
            "pass",
            "Dwa niezależne resolvery DNS-over-HTTPS zwróciły zgodne zone-level RRsety SOA i NS przez HTTPS/443. Ten fallback potwierdza zewnętrzną obserwowalność strefy, ale nie zastępuje bezpośrednich testów konkretnego serwera autorytatywnego.",
            0,
            0,
            True,
        )
    if evidence.status == ENCRYPTED_DNS_DISAGREEMENT:
        message = (
            "Niezależne resolvery DNS-over-HTTPS zwróciły różne zone-level RRsety SOA/NS. Wynik pozostaje VERIFY i nie wpływa na scoring."
        )
    else:
        message = (
            "Encrypted DNS fallback przez HTTPS/443 nie dostarczył kompletnego konsensusu SOA/NS z dwóch resolverów. Wynik pozostaje VERIFY i nie wpływa na scoring."
        )
    return (
        "Encrypted DNS fallback",
        "unknown",
        message,
        0,
        0,
        False,
    )


class EncryptedDnsScanMixin:
    """Collect encrypted recursive fallback after direct path assessment exists."""

    def collect_domain_dns(self):
        self.encrypted_dns = collect_encrypted_dns_evidence(
            self,
            getattr(self, "authoritative_dns", None),
            getattr(self, "delegation", None),
        )
        result = super().collect_domain_dns()
        finding = encrypted_dns_finding(self.encrypted_dns)
        if finding is not None and hasattr(self, "add_check"):
            self.add_check("Domain", *finding)
        return result


__all__ = [
    "DOH_RESOLVERS",
    "ENCRYPTED_DNS_RRTYPES",
    "ENCRYPTED_DNS_USABLE",
    "EncryptedDnsEvidence",
    "EncryptedDnsObservation",
    "EncryptedDnsRrsetEvidence",
    "EncryptedDnsScanMixin",
    "collect_encrypted_dns_evidence",
    "encrypted_dns_fallback_needed",
    "encrypted_dns_finding",
    "encrypted_dns_report_data",
]
