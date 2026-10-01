from __future__ import annotations

import time
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ...constants import COMMON_DNS_TYPES, EMAIL_RE, TIMEOUT
from ...models import DnsQueryState
from ...utils import is_in_scope_host


class DiscoveryScanMixin:
    """Passive Certificate Transparency discovery, crawling, and host inventory."""

    def discover_ct_subdomains(self):
        # Inventory the whole registered domain, even when the website itself is
        # hosted only on a deeper subdomain. Certificate Transparency is passive.
        try:
            r = self.session.get(
                "https://crt.sh/",
                params={"q": f"%.{self.root_domain}", "output": "json"},
                timeout=10,
            )
            r.raise_for_status()
            rows = r.json()
            for row in rows[:1000]:
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if is_in_scope_host(name, self.root_domain):
                        self.subdomains.add(name)
                        self.ct_subdomains.add(name)
        except Exception:
            pass

    def crawl(self):
        # Crawl only the explicitly supplied web host. Do not automatically crawl
        # sibling subdomains discovered under the registered root.
        seeds = [f"https://{self.target_domain}"]
        if self.target_domain == self.root_domain:
            seeds.append(f"https://www.{self.root_domain}")
        queue = deque(seeds)
        seen_urls = set()

        while queue and len(seen_urls) < self.max_pages:
            url = queue.popleft()
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
            except Exception:
                continue

            ctype = r.headers.get("content-type", "")
            if "text/html" not in ctype.lower():
                continue

            final_host = (urlparse(r.url).hostname or "").lower()
            if is_in_scope_host(final_host, self.root_domain):
                self.subdomains.add(final_host)

            text = r.text[:2_000_000]
            self.emails.update(x.lower() for x in EMAIL_RE.findall(text))
            for mixed in self._extract_mixed_content(text, r.url):
                self.crawl_mixed_content.add(mixed)

            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all(["a", "link", "script", "img"]):
                value = tag.get("href") or tag.get("src")
                if not value:
                    continue
                if value.startswith("mailto:"):
                    email = value[7:].split("?", 1)[0].strip().lower()
                    if EMAIL_RE.fullmatch(email):
                        self.emails.add(email)
                    continue
                nxt = urljoin(r.url, value)
                parsed = urlparse(nxt)
                host = (parsed.hostname or "").lower()
                if host and is_in_scope_host(host, self.root_domain):
                    self.subdomains.add(host)
                    if parsed.scheme in ("http", "https") and len(seen_urls) + len(queue) < self.max_pages * 3:
                        clean = parsed._replace(fragment="").geturl()
                        queue.append(clean)
            time.sleep(0.10)

    def collect_subdomain_dns(self):
        # Prioritize the target host and root-domain infrastructure.
        preferred = {
            self.target_domain: 0,
            self.root_domain: 1,
            f"www.{self.root_domain}": 2,
            f"mail.{self.root_domain}": 3,
            f"mta-sts.{self.root_domain}": 4,
        }
        hosts = sorted(self.subdomains, key=lambda h: (preferred.get(h, 10), h))[: self.max_hosts]

        for host in hosts:
            if host in self.dns_records:
                continue
            rows = {}
            for rt in COMMON_DNS_TYPES:
                rows[rt] = self.dns_query(host, rt)
            self.dns_records[host] = rows

    def host_inventory(self) -> dict[str, list[str]]:
        """Classify discovered hosts using current DNS evidence.

        Certificate Transparency is historical by design. A CT-only name is only
        labelled historical when current DNS returned NXDOMAIN conclusively. Names
        with no common records but without NXDOMAIN stay in a separate unresolved
        bucket, and resolver failures remain unknown rather than being called dead.
        """
        live: list[str] = []
        historical: list[str] = []
        unresolved: list[str] = []
        dns_unknown: list[str] = []
        not_assessed: list[str] = []

        for host in sorted(self.subdomains):
            records = self.dns_records.get(host)
            if records is None:
                not_assessed.append(host)
                continue

            if any(values for values in records.values()):
                live.append(host)
                continue

            results = [
                self.dns_cached_result(host, rtype)
                for rtype in COMMON_DNS_TYPES
            ]
            results = [result for result in results if result is not None]

            if any(result.failed for result in results):
                dns_unknown.append(host)
                continue

            is_ct_history = (
                host in self.ct_subdomains
                and host not in {self.target_domain, self.root_domain}
                and any(result.state == DnsQueryState.NXDOMAIN for result in results)
            )
            if is_ct_history:
                historical.append(host)
            else:
                unresolved.append(host)

        return {
            "live": live,
            "historical": historical,
            "unresolved": unresolved,
            "dns_unknown": dns_unknown,
            "not_assessed": not_assessed,
        }
