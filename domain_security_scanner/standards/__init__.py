"""Standards metadata and protocol-specific validation helpers."""

from .mail import (
    analyze_mta_sts_mx_coverage,
    analyze_mta_sts_txt,
    analyze_mx_records,
    analyze_tls_rpt_txt,
    mta_sts_mx_matches,
    parse_mta_sts_policy,
)
from .registry import (
    RFC_3986,
    RFC_6797,
    RFC_7505,
    RFC_8460,
    RFC_8461,
    RFC_8615,
    RFC_9110,
    RFC_9116,
    RFC_10025,
    STANDARD_REFERENCES,
    StandardReference,
    get_standard,
)
from .web import (
    analyze_hsts,
    analyze_redirect,
    analyze_security_txt,
    analyze_set_cookie_header,
    is_well_formed_uri_reference,
)

__all__ = [
    "StandardReference",
    "STANDARD_REFERENCES",
    "get_standard",
    "RFC_3986",
    "RFC_6797",
    "RFC_7505",
    "RFC_8460",
    "RFC_8461",
    "RFC_8615",
    "RFC_9110",
    "RFC_9116",
    "RFC_10025",
    "analyze_mx_records",
    "analyze_tls_rpt_txt",
    "analyze_mta_sts_txt",
    "parse_mta_sts_policy",
    "mta_sts_mx_matches",
    "analyze_mta_sts_mx_coverage",
    "analyze_hsts",
    "analyze_redirect",
    "analyze_security_txt",
    "analyze_set_cookie_header",
    "is_well_formed_uri_reference",
]
