from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class CheckStatus(StrEnum):
    """Supported check outcomes used across scanner modules."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    UNKNOWN = "unknown"


class CheckCategory(StrEnum):
    """Top-level report categories currently emitted by the scanner."""

    DOMAIN = "Domain"
    MAIL = "Mail"
    WEB = "Web"


class DnsQueryState(StrEnum):
    """Outcome of one DNS lookup, separating absence from query failure."""

    ANSWER = "answer"
    NO_ANSWER = "no_answer"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    SERVFAIL = "servfail"
    TRUNCATED = "truncated"
    TRANSPORT_ERROR = "transport_error"
    ERROR = "error"


class DnsQueryMode(StrEnum):
    """How DNS evidence was obtained."""

    RECURSIVE = "recursive"
    AUTHORITATIVE = "authoritative"


class DnsTransport(StrEnum):
    """Explicit DNS transport for direct queries."""

    UDP = "udp"
    TCP = "tcp"


@dataclass(frozen=True)
class DnsQueryCacheKey:
    """Context-complete cache identity for recursive and direct DNS queries."""

    qname: str
    qtype: str
    mode: DnsQueryMode
    transport: DnsTransport | None = None
    server_name: str | None = None
    server_ip: str | None = None

    @classmethod
    def build(
        cls,
        qname: str,
        qtype: str,
        *,
        mode: DnsQueryMode | str,
        transport: DnsTransport | str | None = None,
        server_name: str | None = None,
        server_ip: str | None = None,
    ) -> "DnsQueryCacheKey":
        """Normalize DNS query context into a stable cache key."""
        normalized_server_name = (
            str(server_name).strip().lower().rstrip(".")
            if server_name
            else None
        )
        normalized_server_ip = (
            str(ipaddress.ip_address(str(server_ip).strip()))
            if server_ip is not None
            else None
        )
        return cls(
            qname=str(qname).strip().lower().rstrip("."),
            qtype=str(qtype).strip().upper(),
            mode=DnsQueryMode(mode),
            transport=DnsTransport(transport) if transport is not None else None,
            server_name=normalized_server_name,
            server_ip=normalized_server_ip,
        )


@dataclass(frozen=True)
class DnsQueryResult:
    """Typed DNS evidence used internally without changing report record lists."""

    host: str
    rtype: str
    state: DnsQueryState
    records: tuple[str, ...] = ()
    error: str | None = None
    query_mode: DnsQueryMode = DnsQueryMode.RECURSIVE
    transport: DnsTransport | None = None
    server_name: str | None = None
    server_ip: str | None = None

    # Rich response metadata is optional so all existing recursive construction
    # and callers remain source-compatible.
    rcode: str | None = None
    aa: bool | None = None
    tc: bool | None = None
    edns_version: int | None = None
    edns_payload: int | None = None
    edns_flags: int | None = None
    answer_section: tuple[str, ...] = ()
    authority_section: tuple[str, ...] = ()
    additional_section: tuple[str, ...] = ()
    elapsed_ms: float | None = None

    @property
    def qname(self) -> str:
        """Standards-oriented alias retained alongside the legacy host field."""
        return self.host

    @property
    def qtype(self) -> str:
        """Standards-oriented alias retained alongside the legacy rtype field."""
        return self.rtype

    @property
    def answer_records(self) -> tuple[str, ...]:
        """Compatibility-friendly flattened answer records."""
        return self.records

    @property
    def authoritative(self) -> bool | None:
        """Descriptive alias for the DNS AA flag."""
        return self.aa

    @property
    def truncated(self) -> bool | None:
        """Descriptive alias for the DNS TC flag."""
        return self.tc

    @property
    def failed(self) -> bool:
        return self.state in {
            DnsQueryState.TIMEOUT,
            DnsQueryState.SERVFAIL,
            DnsQueryState.TRUNCATED,
            DnsQueryState.TRANSPORT_ERROR,
            DnsQueryState.ERROR,
        }

    @property
    def absent(self) -> bool:
        return self.state in {DnsQueryState.NO_ANSWER, DnsQueryState.NXDOMAIN}


@dataclass
class Check:
    category: CheckCategory
    name: str
    status: CheckStatus
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True

    def __post_init__(self) -> None:
        self.category = CheckCategory(self.category)
        self.status = CheckStatus(self.status)

        if not isinstance(self.weight, (int, float)) or isinstance(self.weight, bool):
            raise TypeError("Check weight must be numeric.")
        if not isinstance(self.earned, (int, float)) or isinstance(self.earned, bool):
            raise TypeError("Check earned points must be numeric.")
        if not isinstance(self.applicable, bool):
            raise TypeError("Check applicable must be a boolean.")

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON/report representation used before this refactor."""
        data = asdict(self)
        data["category"] = self.category.value
        data["status"] = self.status.value
        return data


@dataclass(frozen=True)
class ScoreResult:
    """Typed internal representation of the existing score payload."""

    score: int
    label: str
    earned_points: float
    possible_points: float

    def to_dict(self) -> dict[str, int | float | str]:
        return asdict(self)
