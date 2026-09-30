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


RFC_1034 = StandardReference("RFC1034", 1034, "Domain names - concepts and facilities", "https://www.rfc-editor.org/info/rfc1034", "DNS / delegation, zone cuts, referrals, and glue")
RFC_1035 = StandardReference("RFC1035", 1035, "Domain names - implementation and specification", "https://www.rfc-editor.org/info/rfc1035", "DNS / message and resource-record semantics")
RFC_1912 = StandardReference("RFC1912", 1912, "Common DNS Operational and Configuration Errors", "https://www.rfc-editor.org/info/rfc1912", "DNS / operational delegation and lame-server guidance")
RFC_2181 = StandardReference("RFC2181", 2181, "Clarifications to the DNS Specification", "https://www.rfc-editor.org/info/rfc2181", "DNS / NS target canonical-name requirements")
RFC_2182 = StandardReference("RFC2182", 2182, "Selection and Operation of Secondary DNS Servers", "https://www.rfc-editor.org/info/rfc2182", "DNS / authoritative-server redundancy and reachability")
RFC_2308 = StandardReference("RFC2308", 2308, "Negative Caching of DNS Queries (DNS NCACHE)", "https://www.rfc-editor.org/info/rfc2308", "DNS / authoritative NXDOMAIN, NODATA, and negative SOA evidence")
RFC_5358 = StandardReference("RFC5358", 5358, "Preventing Use of Recursive Nameservers in Reflector Attacks", "https://www.rfc-editor.org/info/rfc5358", "DNS / externally available recursive service and open-recursion hardening")
RFC_4033 = StandardReference("RFC4033", 4033, "DNS Security Introduction and Requirements", "https://www.rfc-editor.org/info/rfc4033", "DNSSEC / validation model and resolver security states")
RFC_4034 = StandardReference("RFC4034", 4034, "Resource Records for the DNS Security Extensions", "https://www.rfc-editor.org/info/rfc4034", "DNSSEC / DNSKEY, RRSIG, DS records and signature timing")
RFC_4035 = StandardReference("RFC4035", 4035, "Protocol Modifications for the DNS Security Extensions", "https://www.rfc-editor.org/info/rfc4035", "DNSSEC / authenticated delegation and validation processing")
RFC_3986 = StandardReference("RFC3986", 3986, "Uniform Resource Identifier (URI): Generic Syntax", "https://www.rfc-editor.org/info/rfc3986", "Web / URI and URI-reference validation")
RFC_6797 = StandardReference("RFC6797", 6797, "HTTP Strict Transport Security (HSTS)", "https://www.rfc-editor.org/info/rfc6797", "Web / HSTS")
RFC_7505 = StandardReference("RFC7505", 7505, 'A "Null MX" No Service Resource Record for Domains That Accept No Mail', "https://www.rfc-editor.org/info/rfc7505", "Mail receiving / Null MX")
RFC_7838 = StandardReference("RFC7838", 7838, "HTTP Alternative Services", "https://www.rfc-editor.org/info/rfc7838", "Web / Alt-Svc alternative service advertisements")
RFC_8288 = StandardReference("RFC8288", 8288, "Web Linking", "https://www.rfc-editor.org/info/rfc8288", "Web / HTTP Link header and link relation serialization")
RFC_8460 = StandardReference("RFC8460", 8460, "SMTP TLS Reporting", "https://www.rfc-editor.org/info/rfc8460", "Mail receiving / TLS-RPT")
RFC_8461 = StandardReference("RFC8461", 8461, "SMTP MTA Strict Transport Security (MTA-STS)", "https://www.rfc-editor.org/info/rfc8461", "Mail receiving / MTA-STS")
RFC_8615 = StandardReference("RFC8615", 8615, "Well-Known Uniform Resource Identifiers (URIs)", "https://www.rfc-editor.org/info/rfc8615", "Web / registered well-known security.txt location")
RFC_8659 = StandardReference("RFC8659", 8659, "DNS Certification Authority Authorization (CAA) Resource Record", "https://www.rfc-editor.org/info/rfc8659", "DNS / effective CAA policy lookup and record processing")
RFC_9110 = StandardReference("RFC9110", 9110, "HTTP Semantics", "https://www.rfc-editor.org/info/rfc9110", "Web / redirect status and Location semantics")
RFC_9111 = StandardReference("RFC9111", 9111, "HTTP Caching", "https://www.rfc-editor.org/info/rfc9111", "Web / HTTP cache policy and response caching metadata")
RFC_9112 = StandardReference("RFC9112", 9112, "HTTP/1.1", "https://www.rfc-editor.org/info/rfc9112", "Web / passive HTTP/1.1 response framing metadata")
RFC_9116 = StandardReference("RFC9116", 9116, "A File Format to Aid in Security Vulnerability Disclosure", "https://www.rfc-editor.org/info/rfc9116", "Web / security.txt")
RFC_9276 = StandardReference("RFC9276", 9276, "Guidance for NSEC3 Parameter Settings", "https://www.rfc-editor.org/info/rfc9276", "DNSSEC / NSEC3 iteration, salt, and Opt-Out deployment guidance")
RFC_9471 = StandardReference("RFC9471", 9471, "DNS Glue Requirements in Referral Responses", "https://www.rfc-editor.org/info/rfc9471", "DNS / glue requirements in referral responses")
RFC_9904 = StandardReference("RFC9904", 9904, "DNSSEC Cryptographic Algorithm Recommendation Update Process", "https://www.rfc-editor.org/info/rfc9904", "DNSSEC / algorithm recommendation policy")
RFC_9905 = StandardReference("RFC9905", 9905, "Deprecating RSASHA1 and RSASHA1-NSEC3-SHA1 in DNSSEC", "https://www.rfc-editor.org/info/rfc9905", "DNSSEC / validation policy for SHA-1 RSA algorithms")
RFC_9906 = StandardReference("RFC9906", 9906, "Deprecating ECC-GOST and GOST R 34.11-94 in DNSSEC", "https://www.rfc-editor.org/info/rfc9906", "DNSSEC / validation policy for legacy GOST algorithms")
RFC_10025 = StandardReference("RFC10025", 10025, "Cookies: HTTP State Management Mechanism", "https://www.rfc-editor.org/info/rfc10025", "Web / Cookie and Set-Cookie security semantics")


STANDARD_REFERENCES: dict[str, StandardReference] = {
    ref.key: ref
    for ref in (
        RFC_1034, RFC_1035, RFC_1912, RFC_2181, RFC_2182, RFC_2308, RFC_5358,
        RFC_4033, RFC_4034, RFC_4035,
        RFC_3986, RFC_6797, RFC_7505, RFC_7838, RFC_8288,
        RFC_8460, RFC_8461, RFC_8615, RFC_8659, RFC_9110, RFC_9111,
        RFC_9112, RFC_9116, RFC_9276, RFC_9471, RFC_9904, RFC_9905,
        RFC_9906, RFC_10025,
    )
}


def get_standard(key: str) -> StandardReference:
    """Return a registered standard by stable key."""
    return STANDARD_REFERENCES[key.upper()]
