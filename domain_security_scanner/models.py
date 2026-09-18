from __future__ import annotations

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
    """Outcome of one DNS lookup, separating absence from resolver failure."""

    ANSWER = "answer"
    NO_ANSWER = "no_answer"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    SERVFAIL = "servfail"
    ERROR = "error"


@dataclass(frozen=True)
class DnsQueryResult:
    """Typed DNS evidence used internally without changing report record lists."""

    host: str
    rtype: str
    state: DnsQueryState
    records: tuple[str, ...] = ()
    error: str | None = None

    @property
    def failed(self) -> bool:
        return self.state in {
            DnsQueryState.TIMEOUT,
            DnsQueryState.SERVFAIL,
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
        # Accept the existing string-based constructor/API while storing validated,
        # typed values internally. StrEnum remains string-compatible for callers.
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
