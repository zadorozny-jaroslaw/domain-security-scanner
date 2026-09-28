from __future__ import annotations

from dataclasses import dataclass

from ...models import DnsQueryResult, DnsQueryState
from .authoritative import (
    AuthoritativeDnsEvidence,
    AuthoritativeEndpointEvidence,
    AuthoritativeServerEvidence,
    SoaRecord,
)


TRANSPORT_BOTH_RESPOND = "both_respond"
TRANSPORT_UDP_ONLY = "udp_only"
TRANSPORT_TCP_ONLY = "tcp_only"
TRANSPORT_NO_RESPONSE = "no_response"

SOA_AUTHORITY_AUTHORITATIVE = "authoritative"
SOA_AUTHORITY_MIXED = "mixed"
SOA_AUTHORITY_NOT_AUTHORITATIVE = "not_authoritative"
SOA_AUTHORITY_NO_SOA = "no_soa"
SOA_AUTHORITY_UNKNOWN = "unknown"
SOA_AUTHORITY_UNPROBED = "unprobed"

EDNS_OK = "ok"
EDNS_ANOMALY = "anomaly"
EDNS_UNKNOWN = "unknown"
EDNS_NOT_TESTED = "not_tested"


@dataclass(frozen=True)
class EndpointTransportAnalysis:
    """Observed UDP/TCP behavior for one selected authoritative endpoint."""

    server_name: str
    server_ip: str
    status: str
    udp_state: DnsQueryState
    tcp_state: DnsQueryState
    udp_responded: bool
    tcp_responded: bool
    udp_authoritative_soa: bool
    tcp_authoritative_soa: bool


@dataclass(frozen=True)
class AuthoritativeServerAnalysis:
    """Pure issue #15 analysis for one delegated nameserver."""

    name: str
    transport: tuple[EndpointTransportAnalysis, ...]
    soa_authority_status: str
    soa_records: tuple[SoaRecord, ...]
    apex_nameservers: tuple[str, ...]
    edns_status: str


@dataclass(frozen=True)
class AuthoritativeDnsAnalysis:
    """Zone-level authoritative transport and consistency analysis."""

    zone: str
    servers: tuple[AuthoritativeServerAnalysis, ...]
    soa_configuration_consistent: bool | None
    soa_serial_consistent: bool | None
    soa_differing_fields: tuple[str, ...]
    soa_serials: tuple[tuple[str, tuple[int, ...]], ...]
    ns_rrset_consistent: bool | None
    observed_ns_rrsets: tuple[tuple[str, tuple[str, ...]], ...]


def _has_dns_response(result: DnsQueryResult) -> bool:
    """Whether a direct query produced a DNS message rather than no response."""
    return result.rcode is not None


def _has_authoritative_soa(observation) -> bool:
    result = observation.result
    return (
        observation.soa is not None
        and result.state == DnsQueryState.ANSWER
        and result.aa is True
        and result.rcode == "NOERROR"
        and result.tc is not True
    )


def analyze_endpoint_transport(
    endpoint: AuthoritativeEndpointEvidence,
) -> EndpointTransportAnalysis:
    """Compare ordinary UDP and TCP response availability for one endpoint."""
    udp = endpoint.udp_soa.result
    tcp = endpoint.tcp_soa.result
    udp_responded = _has_dns_response(udp)
    tcp_responded = _has_dns_response(tcp)

    if udp_responded and tcp_responded:
        status = TRANSPORT_BOTH_RESPOND
    elif udp_responded:
        status = TRANSPORT_UDP_ONLY
    elif tcp_responded:
        status = TRANSPORT_TCP_ONLY
    else:
        status = TRANSPORT_NO_RESPONSE

    return EndpointTransportAnalysis(
        server_name=endpoint.server_name,
        server_ip=endpoint.server_ip,
        status=status,
        udp_state=udp.state,
        tcp_state=tcp.state,
        udp_responded=udp_responded,
        tcp_responded=tcp_responded,
        udp_authoritative_soa=_has_authoritative_soa(endpoint.udp_soa),
        tcp_authoritative_soa=_has_authoritative_soa(endpoint.tcp_soa),
    )


def _ordinary_observations(server: AuthoritativeServerEvidence):
    for endpoint in server.endpoints:
        yield endpoint.udp_soa
        yield endpoint.tcp_soa


def _server_soa_authority_status(server: AuthoritativeServerEvidence) -> str:
    observations = tuple(_ordinary_observations(server))
    if not observations:
        return SOA_AUTHORITY_UNPROBED

    positive = [obs for obs in observations if _has_authoritative_soa(obs)]
    response_observations = [obs for obs in observations if _has_dns_response(obs.result)]
    uncertain = [obs for obs in observations if not _has_dns_response(obs.result)]
    not_authoritative = [
        obs for obs in response_observations
        if obs.result.state == DnsQueryState.NOT_AUTHORITATIVE
    ]

    if positive:
        # One positive SOA is enough to establish that the delegated server can
        # serve the zone authoritatively. Transport timeouts on another path are
        # analyzed separately and must not erase that positive authority proof.
        if len(positive) != len(response_observations):
            return SOA_AUTHORITY_MIXED
        return SOA_AUTHORITY_AUTHORITATIVE

    if uncertain:
        # A timeout, local connectivity problem, or transport error prevents a
        # confident negative conclusion even when another endpoint looked bad.
        return SOA_AUTHORITY_UNKNOWN

    if response_observations and len(not_authoritative) == len(response_observations):
        return SOA_AUTHORITY_NOT_AUTHORITATIVE

    if response_observations:
        return SOA_AUTHORITY_NO_SOA

    return SOA_AUTHORITY_UNKNOWN


def _server_soa_records(server: AuthoritativeServerEvidence) -> tuple[SoaRecord, ...]:
    values = {
        obs.soa
        for obs in _ordinary_observations(server)
        if _has_authoritative_soa(obs)
    }
    return tuple(
        sorted(
            values,
            key=lambda item: (
                item.mname,
                item.rname,
                item.serial,
                item.refresh,
                item.retry,
                item.expire,
                item.minimum,
            ),
        )
    )


def _server_edns_status(server: AuthoritativeServerEvidence) -> str:
    primary = next((endpoint for endpoint in server.endpoints if endpoint.edns_soa is not None), None)
    if primary is None or primary.edns_soa is None:
        return EDNS_NOT_TESTED

    plain = primary.udp_soa
    edns = primary.edns_soa
    if not _has_authoritative_soa(plain):
        return EDNS_UNKNOWN
    if _has_authoritative_soa(edns):
        return EDNS_OK

    # Only a returned DNS message is treated as an observable EDNS protocol
    # anomaly. Timeout/transport failure remains inconclusive because it could
    # be caused by the scanner's network path.
    if _has_dns_response(edns.result):
        return EDNS_ANOMALY
    return EDNS_UNKNOWN


def analyze_server(server: AuthoritativeServerEvidence) -> AuthoritativeServerAnalysis:
    return AuthoritativeServerAnalysis(
        name=server.name,
        transport=tuple(analyze_endpoint_transport(endpoint) for endpoint in server.endpoints),
        soa_authority_status=_server_soa_authority_status(server),
        soa_records=_server_soa_records(server),
        apex_nameservers=tuple(sorted(set(server.apex_nameservers))),
        edns_status=_server_edns_status(server),
    )


def _soa_config(record: SoaRecord) -> tuple[str, int, int, int, int]:
    # Issue #15 calls out MNAME + timing/minimum fields separately from serial.
    return (
        record.mname,
        record.refresh,
        record.retry,
        record.expire,
        record.minimum,
    )


def _consistency(
    servers: tuple[AuthoritativeServerAnalysis, ...],
    value_getter,
) -> bool | None:
    observed = [value_getter(server) for server in servers if server.soa_records]
    if len(observed) >= 2 and len(set(observed)) > 1:
        return False
    complete = len(servers) >= 2 and all(server.soa_records for server in servers)
    if complete and observed and len(set(observed)) == 1:
        return True
    return None


def _soa_differing_fields(servers: tuple[AuthoritativeServerAnalysis, ...]) -> tuple[str, ...]:
    records = [record for server in servers for record in server.soa_records]
    if len(records) < 2:
        return ()
    fields = (
        ("mname", lambda r: r.mname),
        ("refresh", lambda r: r.refresh),
        ("retry", lambda r: r.retry),
        ("expire", lambda r: r.expire),
        ("minimum", lambda r: r.minimum),
    )
    return tuple(name for name, getter in fields if len({getter(record) for record in records}) > 1)


def _ns_consistency(servers: tuple[AuthoritativeServerAnalysis, ...]) -> bool | None:
    observed = [server.apex_nameservers for server in servers if server.apex_nameservers]
    if len(observed) >= 2 and len(set(observed)) > 1:
        return False
    complete = len(servers) >= 2 and all(server.apex_nameservers for server in servers)
    if complete and observed and len(set(observed)) == 1:
        return True
    return None


def analyze_authoritative_dns(evidence: AuthoritativeDnsEvidence) -> AuthoritativeDnsAnalysis:
    """Analyze already-collected issue #15 evidence without network I/O."""
    servers = tuple(analyze_server(server) for server in evidence.servers)

    config_consistent = _consistency(
        servers,
        lambda server: tuple(sorted({_soa_config(record) for record in server.soa_records})),
    )
    serial_consistent = _consistency(
        servers,
        lambda server: tuple(sorted({record.serial for record in server.soa_records})),
    )

    serials = tuple(
        (server.name, tuple(sorted({record.serial for record in server.soa_records})))
        for server in servers
        if server.soa_records
    )
    ns_rrsets = tuple(
        (server.name, server.apex_nameservers)
        for server in servers
        if server.apex_nameservers
    )

    return AuthoritativeDnsAnalysis(
        zone=evidence.zone,
        servers=servers,
        soa_configuration_consistent=config_consistent,
        soa_serial_consistent=serial_consistent,
        soa_differing_fields=_soa_differing_fields(servers),
        soa_serials=serials,
        ns_rrset_consistent=_ns_consistency(servers),
        observed_ns_rrsets=ns_rrsets,
    )


__all__ = [
    "TRANSPORT_BOTH_RESPOND",
    "TRANSPORT_UDP_ONLY",
    "TRANSPORT_TCP_ONLY",
    "TRANSPORT_NO_RESPONSE",
    "SOA_AUTHORITY_AUTHORITATIVE",
    "SOA_AUTHORITY_MIXED",
    "SOA_AUTHORITY_NOT_AUTHORITATIVE",
    "SOA_AUTHORITY_NO_SOA",
    "SOA_AUTHORITY_UNKNOWN",
    "SOA_AUTHORITY_UNPROBED",
    "EDNS_OK",
    "EDNS_ANOMALY",
    "EDNS_UNKNOWN",
    "EDNS_NOT_TESTED",
    "AuthoritativeDnsAnalysis",
    "AuthoritativeServerAnalysis",
    "EndpointTransportAnalysis",
    "analyze_authoritative_dns",
    "analyze_endpoint_transport",
    "analyze_server",
]
