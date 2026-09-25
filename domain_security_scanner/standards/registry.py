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


RFC_1034 = StandardReference(
    key="RFC1034",
    number=1034,
    title="Domain names - concepts and facilities",
    url="https://www.rfc-editor.org/info/rfc1034",
    scope="DNS / delegation, zone cuts, referrals, and glue",
)

RFC_1035 = StandardReference(
    key="RFC1035",
    number=1035,
    title="Domain names - implementation and specification",
    url="https://www.rfc-editor.org/info/rfc1035",
    scope="DNS / message and resource-record semantics",
)

RFC_1912 = StandardReference(
    key="RFC1912",
    number=1912,
    title="Common DNS Operational and Configuration Errors",
    url="https://www.rfc-editor.org/info/rfc1912",
    scope="DNS / operational delegation and lame-server guidance",
)

RFC_2181 = StandardReference(
    key="RFC2181",
    number=2181,
    title="Clarifications to the DNS Specification",
    url="https://www.rfc-editor.org/info/rfc2181",
    scope="DNS / NS target canonical-name requirements",
)

RFC_2182 = StandardReference(
    key="RFC2182",
    number=2182,
    title="Selection and Operation of Secondary DNS Servers",
    url="https://www.rfc-editor.org/info/rfc2182",
    scope="DNS / authoritative-server redundancy and reachability",
)


RFC_3986 = StandardReference(
    key="RFC3986",
    number=3986,
    title="Uniform Resource Identifier (URI): Generic Syntax",
    url="https://www.rfc-editor.org/info/rfc3986",
    scope="Web / URI and URI-reference validation",
)

RFC_6797 = StandardReference(
    key="RFC6797",
    number=6797,
    title="HTTP Strict Transport Security (HSTS)",
    url="https://www.rfc-editor.org/info/rfc6797",
    scope="Web / HSTS",
)

RFC_7505 = StandardReference(
    key="RFC7505",
    number=7505,
    title='A "Null MX" No Service Resource Record for Domains That Accept No Mail',
    url="https://www.rfc-editor.org/info/rfc7505",
    scope="Mail receiving / Null MX",
)

RFC_7838 = StandardReference(
    key="RFC7838",
    number=7838,
    title="HTTP Alternative Services",
    url="https://www.rfc-editor.org/info/rfc7838",
    scope="Web / Alt-Svc alternative service advertisements",
)

RFC_8288 = StandardReference(
    key="RFC8288",
    number=8288,
    title="Web Linking",
    url="https://www.rfc-editor.org/info/rfc8288",
    scope="Web / HTTP Link header and link relation serialization",
)

RFC_8460 = StandardReference(
    key="RFC8460",
    number=8460,
    title="SMTP TLS Reporting",
    url="https://www.rfc-editor.org/info/rfc8460",
    scope="Mail receiving / TLS-RPT",
)

RFC_8461 = StandardReference(
    key="RFC8461",
    number=8461,
    title="SMTP MTA Strict Transport Security (MTA-STS)",
    url="https://www.rfc-editor.org/info/rfc8461",
    scope="Mail receiving / MTA-STS",
)

RFC_8615 = StandardReference(
    key="RFC8615",
    number=8615,
    title="Well-Known Uniform Resource Identifiers (URIs)",
    url="https://www.rfc-editor.org/info/rfc8615",
    scope="Web / well-known security.txt location",
)

RFC_9110 = StandardReference(
    key="RFC9110",
    number=9110,
    title="HTTP Semantics",
    url="https://www.rfc-editor.org/info/rfc9110",
    scope="Web / redirect status and Location semantics",
)

RFC_9111 = StandardReference(
    key="RFC9111",
    number=9111,
    title="HTTP Caching",
    url="https://www.rfc-editor.org/info/rfc9111",
    scope="Web / HTTP cache policy and response caching metadata",
)

RFC_9112 = StandardReference(
    key="RFC9112",
    number=9112,
    title="HTTP/1.1",
    url="https://www.rfc-editor.org/info/rfc9112",
    scope="Web / passive HTTP/1.1 response framing metadata",
)

RFC_9116 = StandardReference(
    key="RFC9116",
    number=9116,
    title="A File Format to Aid in Security Vulnerability Disclosure",
    url="https://www.rfc-editor.org/info/rfc9116",
    scope="Web / security.txt",
)

RFC_9471 = StandardReference(
    key="RFC9471",
    number=9471,
    title="DNS Glue Requirements in Referral Responses",
    url="https://www.rfc-editor.org/info/rfc9471",
    scope="DNS / glue requirements in referral responses",
)

RFC_10025 = StandardReference(
    key="RFC10025",
    number=10025,
    title="Cookies: HTTP State Management Mechanism",
    url="https://www.rfc-editor.org/info/rfc10025",
    scope="Web / Cookie and Set-Cookie security semantics",
)


STANDARD_REFERENCES: dict[str, StandardReference] = {
    ref.key: ref
    for ref in (
        RFC_1034,
        RFC_1035,
        RFC_1912,
        RFC_2181,
        RFC_2182,
        RFC_3986,
        RFC_6797,
        RFC_7505,
        RFC_7838,
        RFC_8288,
        RFC_8460,
        RFC_8461,
        RFC_8615,
        RFC_9110,
        RFC_9111,
        RFC_9112,
        RFC_9116,
        RFC_9471,
        RFC_10025,
    )
}


def get_standard(key: str) -> StandardReference:
    """Return a registered standard by stable key."""

    return STANDARD_REFERENCES[key.upper()]
