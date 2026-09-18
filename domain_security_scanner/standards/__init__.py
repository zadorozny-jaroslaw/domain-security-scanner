"""Standards metadata and protocol-specific validation helpers."""

from .mail import (
    analyze_mta_sts_mx_coverage,
    analyze_mta_sts_txt,
    analyze_mx_records,
    analyze_tls_rpt_txt,
    mta_sts_mx_matches,
    parse_mta_sts_policy,
)
from .registry import RFC_7505, RFC_8460, RFC_8461, STANDARD_REFERENCES, StandardReference, get_standard

__all__ = [
    "StandardReference",
    "STANDARD_REFERENCES",
    "get_standard",
    "RFC_7505",
    "RFC_8460",
    "RFC_8461",
    "analyze_mx_records",
    "analyze_tls_rpt_txt",
    "analyze_mta_sts_txt",
    "parse_mta_sts_policy",
    "mta_sts_mx_matches",
    "analyze_mta_sts_mx_coverage",
]
