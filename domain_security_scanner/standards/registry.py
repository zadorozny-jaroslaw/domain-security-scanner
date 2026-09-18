from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StandardReference:
    """Stable metadata for a standards-based scanner check."""

    key: str
    number: int
    title: str
    url: str
    scope: str

    @property
    def label(self) -> str:
        return f"RFC {self.number}"


RFC_7505 = StandardReference(
    key="RFC7505",
    number=7505,
    title='A "Null MX" No Service Resource Record for Domains That Accept No Mail',
    url="https://www.rfc-editor.org/info/rfc7505",
    scope="Mail receiving / Null MX",
)


STANDARD_REFERENCES: dict[str, StandardReference] = {
    RFC_7505.key: RFC_7505,
}


def get_standard(key: str) -> StandardReference:
    """Return a registered standard by stable key."""

    return STANDARD_REFERENCES[key.upper()]
