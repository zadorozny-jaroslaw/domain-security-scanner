from __future__ import annotations

from dataclasses import dataclass
import ipaddress
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
ENCRYPTED_DNS_BASE_RRTYPES = ("SOA", "NS")
ENCRYPTED_DNS_RRTYPES = ("SOA", "NS", "DS", "DNSKEY")
ENCRYPTED_NS_HOST_RRTYPES = ("A", "AAAA")
MAX_ENCRYPTED_NAMESERVER_HOSTS = 4
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
    authenticated_data: bool | None = None


@dataclass(frozen=True)
class EncryptedDnsRrsetEvidence:
    """Consensus view for one zone-level RRset across bounded DoH resolvers."""

    qtype: str
    status: str
    rdata: tuple[str, ...]
    observations: tuple[EncryptedDnsObservation, ...]


@dataclass(frozen=True)
class EncryptedDnsNameserverEvidence:
    """Encrypted recursive address/alias evidence for one recovered apex NS."""

    name: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cname_targets: tuple[str, ...] = ()
    addressable_resolvers: tuple[str, ...] = ()
    confirmed_addressable: bool = False
    alias_status: str = "unknown"
    a_observations: tuple[EncryptedDnsObservation, ...] = ()
    aaaa_observations: tuple[EncryptedDnsObservation, ...] = ()


@dataclass(frozen=True)
class EncryptedDnsEvidence:
    """Bounded encrypted recursive fallback evidence for one zone."""

    zone: str
    status: str
    trigger: str
    attempted: bool
    rrsets: tuple[EncryptedDnsRrsetEvidence, ...] = ()
    nameservers: tuple[EncryptedDnsNameserverEvidence, ...] = ()
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


def _owner_rdata(
    result: DnsQueryResult,
    owner: str,
    qtype: str,
) -> tuple[str, ...]:
    """Return only RDATA owned by ``owner`` from one encrypted DNS answer."""
    owner_name = _normalize_name(owner)
    target = str(qtype).upper()
    values: list[str] = []
    for rrset_text in result.answer_section:
        for line in str(rrset_text).splitlines():
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            row_owner, _ttl, _rdclass, row_type, rdata = parts
            if _normalize_name(row_owner) != owner_name or row_type.upper() != target:
                continue
            values.append(_normalize_rdata(target, rdata))
    return tuple(sorted(values))


def _canonical_ip_values(values: tuple[str, ...], version: int) -> tuple[str, ...]:
    found: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if address.version == version:
            found.add(str(address))
    return tuple(sorted(found))


def _nameserver_host_evidence(
    name: str,
    a_observations: tuple[EncryptedDnsObservation, ...],
    aaaa_observations: tuple[EncryptedDnsObservation, ...],
) -> EncryptedDnsNameserverEvidence:
    """Summarize bounded DoH A/AAAA evidence without requiring geo-identical IP sets."""
    normalized = _normalize_name(name)
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    cname_targets: set[str] = set()
    addressable_resolvers: set[str] = set()
    alias_resolvers: set[str] = set()

    by_resolver: dict[str, list[EncryptedDnsObservation]] = {}
    for observation in (*a_observations, *aaaa_observations):
        by_resolver.setdefault(observation.resolver_name, []).append(observation)

    for resolver_name, observations in by_resolver.items():
        resolver_has_address = False
        resolver_aliases: set[str] = set()
        for observation in observations:
            result = observation.result
            a_values = _canonical_ip_values(_owner_rdata(result, normalized, "A"), 4)
            aaaa_values = _canonical_ip_values(_owner_rdata(result, normalized, "AAAA"), 6)
            aliases = tuple(
                _normalize_name(value)
                for value in _owner_rdata(result, normalized, "CNAME")
                if _normalize_name(value)
            )
            ipv4.update(a_values)
            ipv6.update(aaaa_values)
            resolver_aliases.update(aliases)
            if a_values or aaaa_values:
                resolver_has_address = True
        if resolver_has_address:
            addressable_resolvers.add(resolver_name)
        if resolver_aliases:
            alias_resolvers.add(resolver_name)
            cname_targets.update(resolver_aliases)

    expected_resolvers = {name for name, _url in DOH_RESOLVERS}
    confirmed_addressable = bool(expected_resolvers) and expected_resolvers <= addressable_resolvers

    if confirmed_addressable and not cname_targets:
        alias_status = "direct"
    elif expected_resolvers and expected_resolvers <= alias_resolvers and cname_targets:
        alias_status = "alias"
    else:
        alias_status = "unknown"

    return EncryptedDnsNameserverEvidence(
        name=normalized,
        ipv4=tuple(sorted(ipv4)),
        ipv6=tuple(sorted(ipv6)),
        cname_targets=tuple(sorted(cname_targets)),
        addressable_resolvers=tuple(sorted(addressable_resolvers)),
        confirmed_addressable=confirmed_addressable,
        alias_status=alias_status,
        a_observations=a_observations,
        aaaa_observations=aaaa_observations,
    )


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
        authenticated_data=(
            bool(response.flags & dns.flags.AD) if response is not None else None
        ),
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
    required = [by_type.get(qtype, RRSET_UNAVAILABLE) for qtype in ENCRYPTED_DNS_BASE_RRTYPES]
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
    by_type = {item.qtype: item for item in evidence}
    recovered_nameservers: list[EncryptedDnsNameserverEvidence] = []
    ns_rrset = by_type.get("NS")
    if ns_rrset is not None and ns_rrset.status == RRSET_CONSENSUS:
        for nameserver in ns_rrset.rdata[:MAX_ENCRYPTED_NAMESERVER_HOSTS]:
            name = _normalize_name(nameserver)
            a_observations = tuple(
                _doh_query(
                    session,
                    zone=name,
                    qtype="A",
                    resolver_name=resolver_name,
                    resolver_url=resolver_url,
                )
                for resolver_name, resolver_url in DOH_RESOLVERS
            )
            aaaa_observations = tuple(
                _doh_query(
                    session,
                    zone=name,
                    qtype="AAAA",
                    resolver_name=resolver_name,
                    resolver_url=resolver_url,
                )
                for resolver_name, resolver_url in DOH_RESOLVERS
            )
            recovered_nameservers.append(
                _nameserver_host_evidence(name, a_observations, aaaa_observations)
            )

    return EncryptedDnsEvidence(
        zone=zone,
        status=_overall_status(evidence),
        trigger=trigger,
        attempted=True,
        rrsets=evidence,
        nameservers=tuple(recovered_nameservers),
    )


def encrypted_dns_report_data(
    evidence: EncryptedDnsEvidence | None,
    dnssec_validation=None,
) -> dict[str, Any]:
    if evidence is None:
        return {
            "status": ENCRYPTED_DNS_NOT_NEEDED,
            "attempted": False,
            "trigger": None,
            "channel": "doh",
            "transport": "https",
            "resolvers": [],
            "rrsets": {},
            "nameservers": [],
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
                    "authenticated_data": observation.authenticated_data,
                    "error": observation.result.error,
                    "rdata": list(
                        _requested_rdata(observation.result, rrset.qtype)
                    ),
                }
                for observation in rrset.observations
            ],
        }

    nameservers = []
    for nameserver in evidence.nameservers:
        observations = {}
        for qtype, items in (("A", nameserver.a_observations), ("AAAA", nameserver.aaaa_observations)):
            observations[qtype] = [
                {
                    "resolver": observation.resolver_name,
                    "endpoint": observation.resolver_url,
                    "state": observation.result.state.value,
                    "rcode": observation.result.rcode,
                    "authenticated_data": observation.authenticated_data,
                    "error": observation.result.error,
                    "rdata": list(_owner_rdata(observation.result, nameserver.name, qtype)),
                    "cname": list(_owner_rdata(observation.result, nameserver.name, "CNAME")),
                }
                for observation in items
            ]
        nameservers.append(
            {
                "name": nameserver.name,
                "confirmed_addressable": nameserver.confirmed_addressable,
                "addressable_resolvers": list(nameserver.addressable_resolvers),
                "ipv4": list(nameserver.ipv4),
                "ipv6": list(nameserver.ipv6),
                "alias_status": nameserver.alias_status,
                "cname_targets": list(nameserver.cname_targets),
                "observations": observations,
            }
        )

    report = {
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
        "nameservers": nameservers,
        "scope": {
            "zone_level_only": True,
            "per_authoritative_server_attribution": False,
            "qtypes": list(ENCRYPTED_DNS_RRTYPES),
            "nameserver_host_qtypes": list(ENCRYPTED_NS_HOST_RRTYPES),
            "nameserver_host_limit": MAX_ENCRYPTED_NAMESERVER_HOSTS,
        },
    }
    if dnssec_validation is not None:
        from .encrypted_dnssec import encrypted_dnssec_validation_report_data

        report["dnssec_validation"] = encrypted_dnssec_validation_report_data(
            dnssec_validation
        )
    return report


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
    "ENCRYPTED_DNS_BASE_RRTYPES",
    "ENCRYPTED_DNS_RRTYPES",
    "ENCRYPTED_NS_HOST_RRTYPES",
    "MAX_ENCRYPTED_NAMESERVER_HOSTS",
    "ENCRYPTED_DNS_USABLE",
    "EncryptedDnsEvidence",
    "EncryptedDnsNameserverEvidence",
    "EncryptedDnsObservation",
    "EncryptedDnsRrsetEvidence",
    "EncryptedDnsScanMixin",
    "collect_encrypted_dns_evidence",
    "encrypted_dns_fallback_needed",
    "encrypted_dns_finding",
    "encrypted_dns_report_data",
]
