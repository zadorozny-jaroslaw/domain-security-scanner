from __future__ import annotations

from datetime import datetime, timezone

from .base import BaseScanner
from .domains.cms import CmsScanMixin
from .domains.discovery import DiscoveryScanMixin
from .domains.domain import DomainScanMixin
from .domains.mail import MailScanMixin
from .domains.tls import TlsScanMixin
from .domains.web import WebScanMixin
from .models import ScoreResult
from .version import __version__


SCAN_GROUPS = ("domain", "discovery", "mail", "tls", "web", "cms")


class Scanner(DomainScanMixin, MailScanMixin, DiscoveryScanMixin, TlsScanMixin, WebScanMixin, CmsScanMixin, BaseScanner):
    """Orchestrates scan groups while preserving the existing default behavior."""

    def __init__(
        self,
        domain: str,
        max_pages: int = 20,
        max_hosts: int = 25,
        scan_groups=None,
    ):
        self._active_scan_group = None
        super().__init__(domain, max_pages=max_pages, max_hosts=max_hosts)

        if scan_groups is None:
            requested = SCAN_GROUPS
        elif isinstance(scan_groups, str):
            requested = (scan_groups,)
        else:
            requested = tuple(scan_groups)

        unknown = sorted(set(requested) - set(SCAN_GROUPS))
        if unknown:
            raise ValueError(
                "Unknown scan group(s): "
                + ", ".join(unknown)
                + ". Valid groups: "
                + ", ".join(SCAN_GROUPS)
            )

        requested_set = set(requested)
        self.scan_groups = tuple(group for group in SCAN_GROUPS if group in requested_set)
        self.scan_selection = {
            "requested": None,
            "skipped": [],
            "overlap": [],
            "effective": list(self.scan_groups),
            "warnings": [],
        }

    def set_scan_selection_context(
        self,
        requested=None,
        skipped=None,
        warnings_list=None,
    ) -> None:
        requested_tuple = None if requested is None else tuple(requested)
        skipped_tuple = tuple(skipped or ())
        requested_set = set(SCAN_GROUPS if requested_tuple is None else requested_tuple)
        skipped_set = set(skipped_tuple)
        overlap = [
            group for group in SCAN_GROUPS
            if group in requested_set and group in skipped_set
        ]
        self.scan_selection = {
            "requested": None if requested_tuple is None else list(requested_tuple),
            "skipped": [group for group in SCAN_GROUPS if group in skipped_set],
            "overlap": overlap,
            "effective": list(self.scan_groups),
            "warnings": list(warnings_list or ()),
        }

    def scan_group_selected(self, group: str) -> bool:
        return group in self.scan_groups

    def _run_group_step(self, group: str, func, *args, **kwargs):
        previous = self._active_scan_group
        self._active_scan_group = group
        try:
            return func(*args, **kwargs)
        finally:
            self._active_scan_group = previous

    def add_check(self, *args, **kwargs):
        if (
            self._active_scan_group is not None
            and not self.scan_group_selected(self._active_scan_group)
        ):
            return None
        return super().add_check(*args, **kwargs)

    def run(self):
        # Domain registration lookup is prerequisite context for domain, discovery,
        # and mail scans. When domain is not selected, its findings are suppressed.
        needs_root_context = any(
            self.scan_group_selected(group)
            for group in ("domain", "discovery", "mail")
        )
        if needs_root_context:
            self._run_group_step("domain", self.rdap_lookup)

        if self.scan_group_selected("domain"):
            self._run_group_step("domain", self.collect_domain_dns)

        if self.scan_group_selected("mail"):
            self._run_group_step("mail", self.collect_mail_dns)

        if self.scan_group_selected("discovery"):
            self._run_group_step("discovery", self.discover_ct_subdomains)
            self._run_group_step("discovery", self.crawl)
            self._run_group_step("discovery", self.collect_subdomain_dns)

        if self.scan_group_selected("tls"):
            self._run_group_step("tls", self.check_tls)

        if self.scan_group_selected("web") or self.scan_group_selected("cms"):
            self._run_group_step(
                "web",
                self.check_http,
                run_web_checks=self.scan_group_selected("web"),
            )

        if self.scan_group_selected("cms"):
            self._run_group_step("cms", self.check_cms_currency)

    def _score_result(self) -> ScoreResult:
        applicable = [c for c in self.checks if c.applicable and c.weight > 0]
        possible = sum(c.weight for c in applicable)
        earned = sum(c.earned for c in applicable)
        value = round(100 * earned / possible) if possible else 0
        if value >= 90:
            label = "Strong"
        elif value >= 75:
            label = "Good"
        elif value >= 60:
            label = "Needs improvement"
        else:
            label = "Priority remediation"
        return ScoreResult(
            score=value,
            label=label,
            earned_points=round(earned, 1),
            possible_points=round(possible, 1),
        )

    def score(self) -> dict[str, int | float | str]:
        """Return the same public score dictionary as before the model refactor."""
        return self._score_result().to_dict()

    def to_dict(self):
        return {
            "domain": self.target_domain,
            "target_domain": self.target_domain,
            "root_domain": self.root_domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner_version": __version__,
            "scan_groups": list(self.scan_groups),
            "scan_selection": dict(self.scan_selection),
            "score": self.score(),
            "checks": [c.to_dict() for c in self.checks],
            "rdap": self.rdap,
            "mail": self.mail,
            "tls": self.tls,
            "http": self.http,
            "subdomains": sorted(self.subdomains),
            "host_inventory": self.host_inventory(),
            "emails": sorted(self.emails),
            "dns_records": self.dns_records,
            "limitations": [
                "To jest zewnętrzny, niskoinwazyjny health check, a nie pełny pentest.",
                "Brak wyniku DKIM dla popularnych selektorów nie oznacza braku DKIM.",
                "Certificate Transparency jest historyczne; nazwa jest oznaczana jako historyczna tylko przy aktualnym NXDOMAIN, a błędy resolvera pozostają jako stan nieznany.",
                "DNSSEC jest wykrywany na podstawie delegacji/DS/RDAP; skrypt nie wykonuje pełnej walidacji kryptograficznej łańcucha.",
                "Dla .pl brak informacji o Registry Lock w RDAP nie oznacza, że blokady nie ma.",
                "Wynik nie obejmuje bezpieczeństwa kont, MFA, endpointów, backupu, uprawnień ani konfiguracji wewnętrznej.",
                "CMS/platforma jest wykrywana pasywnie. Brak detekcji nie oznacza braku CMS, a wersja jest raportowana tylko wtedy, gdy jest jawnie ujawniona.",
                "Porównanie wersji CMS korzysta z aktualnych źródeł projektu w czasie skanu; brak najnowszej wersji nie oznacza automatycznie podatności bezpieczeństwa.",
                "Analiza cookies dotyczy nagłówków Set-Cookie widocznych podczas zewnętrznego skanu; nie widzi cookies tworzonych wyłącznie po logowaniu lub przez późniejszy JavaScript.",
                "Licznik SPF jest statycznym oszacowaniem najgorszej ścieżki i uwzględnia zagnieżdżone include/redirect, gdy ich rekordy są dostępne bez makr.",
                "Test legacy TLS wykonuje pojedyncze handshaki dla wersji protokołu; lokalne ograniczenia biblioteki TLS mogą dać wynik VERIFY zamiast oceny.",
            ],
        }
