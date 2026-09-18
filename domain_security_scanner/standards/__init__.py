"""Standards metadata and protocol-specific validation helpers."""

from .mail import analyze_mx_records
from .registry import RFC_7505, STANDARD_REFERENCES, StandardReference, get_standard

__all__ = [
    "StandardReference",
    "STANDARD_REFERENCES",
    "get_standard",
    "RFC_7505",
    "analyze_mx_records",
]
