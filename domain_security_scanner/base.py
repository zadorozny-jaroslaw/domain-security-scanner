from __future__ import annotations

from typing import Any

import dns.resolver
import requests

from .constants import USER_AGENT
from .models import Check, CheckCategory, CheckStatus, DnsQueryResult
from .utils import fallback_root_domain, normalize_domain


class BaseScanner:
    """Shared scanner state and check collection."""

    def __init__(self, domain: str, max_pages: int = 20, max_hosts: int = 25):
        # domain = exact web host supplied by the user. root_domain = registered/apex
        # domain used for registration, DNSSEC and mail-security checks.
        self.domain = normalize_domain(domain)
        self.target_domain = self.domain
        self.root_domain = fallback_root_domain(self.domain)
        self.max_pages = max_pages
        self.max_hosts = max_hosts
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

        self.checks: list[Check] = []
        self.subdomains: set[str] = {self.target_domain, self.root_domain}
        # Names learned from Certificate Transparency are historical evidence until
        # current DNS confirms that they still resolve.
        self.ct_subdomains: set[str] = set()
        self.emails: set[str] = set()
        self.crawl_mixed_content: set[str] = set()
        self.dns_records: dict[str, dict[str, list[str]]] = {}
        self.dns_query_cache: dict[tuple[str, str], DnsQueryResult] = {}
        self.rdap: dict[str, Any] = {}
        self.http: dict[str, Any] = {}
        self.tls: dict[str, Any] = {}
        self.mail: dict[str, Any] = {}

    def add_check(
        self,
        category: CheckCategory | str,
        name: str,
        status: CheckStatus | str,
        message: str,
        weight: float = 0,
        earned: float = 0,
        applicable: bool = True,
    ) -> None:
        self.checks.append(Check(category, name, status, message, weight, earned, applicable))
