#!/usr/bin/env python3
"""Backward-compatible entry point for Domain Security Scanner."""

from domain_security_scanner import (
    Check,
    Scanner,
    __version__,
    days_until,
    fallback_root_domain,
    is_in_scope_host,
    normalize_domain,
)
from domain_security_scanner.cli import main
from domain_security_scanner.constants import (
    COMMON_DKIM_SELECTORS,
    COMMON_DNS_TYPES,
    COPYRIGHT_NOTICE,
    EMAIL_RE,
    LICENSE_NOTICE,
    SECURITY_HEADERS,
    TIMEOUT,
    USER_AGENT,
)
from domain_security_scanner.reporting.pdf import (
    _impact,
    _recommendation,
    _score_palette,
    _status_palette,
    _technical_status,
    generate_pdf,
    p,
    register_pdf_fonts,
)


if __name__ == "__main__":
    raise SystemExit(main())
