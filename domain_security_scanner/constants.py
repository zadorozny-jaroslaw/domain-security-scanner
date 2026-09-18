from __future__ import annotations

import re

from .version import __version__

USER_AGENT = f"DomainSecurityScanner/{__version__} (authorized external assessment)"
COPYRIGHT_NOTICE = "Copyright (c) 2026 Jarosław Zadorożny"
LICENSE_NOTICE = "Non-commercial use only - see LICENSE"
TIMEOUT = 6
COMMON_DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA")
COMMON_DKIM_SELECTORS = (
    "default", "selector1", "selector2", "google",
    "s1", "s2", "k1", "k2", "mail", "dkim"
)

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-frame-options": "X-Frame-Options",
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
