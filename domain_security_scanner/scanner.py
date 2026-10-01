from __future__ import annotations

from datetime import datetime, timezone

from .base import BaseScanner
from .dns_evidence import DnsEvidenceMixin
from .domains.cms import CmsScanMixin
from .domains.discovery import DiscoveryScanMixin
from .domains.domain import DomainScanMixin
from .domains.domain.authoritative import AuthoritativeDnsScanMixin
from .domains.domain.dns_customer_reporting import (
    enrich_dns_records_for_report,
    recover_customer_dns_checks,
)
from .domains.domain.delegation import DelegationScanMixin
from .domains.domain.dnssec import DnssecScanMixin, dnssec_report_data
from .domains.domain.encrypted_dns import (
    EncryptedDnsScanMixin,
    encrypted_dns_report_data,
)
from .domains.domain.negative_dns import NegativeDnsScanMixin, negative_dns_report_data
from .domains.domain.reporting import dns_infrastructure_report_data
from .domains.domain.dns_zone_recovery import dns_zone_recovery_report_data
from .domains.mail import MailScanMixin
from .domains.tls import TlsScanMixin
from .domains.web import WebScanMixin
from .models import ScoreResult
from .orchestration import (
    SCAN_GROUPS,
    build_scan_plan,
    build_scan_selection_context,
    normalize_scan_groups,
)
from .version import __version__


class Scanner(
    DnsEvidenceMixin,
    DelegationScanMixin,
    AuthoritativeDnsScanMixin,
    EncryptedDnsScanMixin,
    NegativeDnsScanMixin,
    DnssecScanMixin,
    DomainScanMixin,
    MailScanMixin,
    DiscoveryScanMixin,
    TlsScanMixin,
    WebScanMixin,
    CmsScanMixin,
    BaseScanner,
):
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
        self.delegation = None
        self.delegation_analysis = None
        self.authoritative_dns = None
        self.authoritative_dns_analysis = None
        self.encrypted_dns = None
        self.encrypted_dnssec_validation = None
        self.dns_zone_recovery = None
        self.negative_dns = None
        self.negative_dns_analysis = None
        self.dnssec = None
        self.dnssec_direct = None
        self.dnssec_analysis = None
        self.dnssec_direct_analysis = None
        self.dnssec_policy_analysis = None
        self.dnssec_denial_analysis = None

        self.scan_groups = normalize_scan_groups(scan_groups)
        self.scan_selection = build_scan_selection_context(self.scan_groups)

    def set_scan_selection_context(
        self,
        requested=None,
        skipped=None,
        warnings_list=None,
    ) -> None:
        self.scan_selection = build_scan_selection_context(
            self.scan_groups,
            requested=requested,
            skipped=skipped,
            warnings_list=warnings_list,
        )

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
        for step in build_scan_plan(self.scan_groups):
            method = getattr(self, step.method_name)
            self._run_group_step(
                step.active_group,
                method,
                **step.call_kwargs(),
            )

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
        dns = {
            **dns_infrastructure_report_data(
                getattr(self, "delegation", None),
                getattr(self, "delegation_analysis", None),
                getattr(self, "authoritative_dns", None),
                getattr(self, "authoritative_dns_analysis", None),
                getattr(self, "caa", {}),
            ),
            "encrypted_recursive": encrypted_dns_report_data(
                getattr(self, "encrypted_dns", None),
                getattr(self, "encrypted_dnssec_validation", None),
            ),
            "zone_recovery": dns_zone_recovery_report_data(
                getattr(self, "dns_zone_recovery", None),
            ),
            "dnssec": dnssec_report_data(
                getattr(self, "dnssec", None),
                getattr(self, "dnssec_analysis", None),
                getattr(self, "dnssec_policy_analysis", None),
                getattr(self, "dnssec_denial_analysis", None),
            ),
            **negative_dns_report_data(
                getattr(self, "negative_dns", None),
                getattr(self, "negative_dns_analysis", None),
            ),
        }
        checks = recover_customer_dns_checks(
            [c.to_dict() for c in self.checks],
            dns,
        )
        dns_records = enrich_dns_records_for_report(
            self.dns_records,
            self.root_domain,
            dns,
        )

        return {
            "domain": self.target_domain,
            "target_domain": self.target_domain,
            "root_domain": self.root_domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner_version": __version__,
            "scan_groups": list(self.scan_groups),
            "scan_selection": dict(self.scan_selection),
            "score": self.score(),
            "checks": checks,
            "rdap": self.rdap,
            "caa": getattr(self, "caa", {}),
            "mail": self.mail,
            "tls": self.tls,
            "http": self.http,
            "subdomains": sorted(self.subdomains),
            "host_inventory": self.host_inventory(),
            "emails": sorted(self.emails),
            "dns_records": dns_records,
            "dns": dns,
            "limitations": [
                "To jest zewnętrzny, niskoinwazyjny health check, a nie pełny pentest.",
                "Brak wyniku DKIM dla popularnych selektorów nie oznacza braku DKIM.",
                "Certificate Transparency jest historyczne; nazwa jest oznaczana jako historyczna tylko przy aktualnym NXDOMAIN, a błędy resolvera pozostają jako stan nieznany.",
                "Walidacja DNSSEC jest ograniczona do parent DS, DNSKEY oraz wybranych apex RRsetów SOA/NS; wynik secure nie oznacza pełnej walidacji każdego RRsetu w strefie.",
                "Obserwacje negative DNS, wildcard i open recursion są ograniczone do małej próbki z bieżącej lokalizacji skanera; timeout ani wynik niejednoznaczny nie potwierdzają wyłączenia rekurencji.",
                "Dla .pl brak informacji o Registry Lock w RDAP nie oznacza, że blokady nie ma.",
                "Wynik nie obejmuje bezpieczeństwa kont, MFA, endpointów, backupu, uprawnień ani konfiguracji wewnętrznej.",
                "CMS/platforma jest wykrywana pasywnie. Brak detekcji nie oznacza braku CMS, a wersja jest raportowana tylko wtedy, gdy jest jawnie ujawniona.",
                "Porównanie wersji CMS korzysta z aktualnych źródeł projektu w czasie skanu; brak najnowszej wersji nie oznacza automatycznie podatności bezpieczeństwa.",
                "Analiza cookies dotyczy nagłówków Set-Cookie widocznych podczas zewnętrznego skanu; nie widzi cookies tworzonych wyłącznie po logowaniu lub przez późniejszy JavaScript.",
                "Licznik SPF jest statycznym oszacowaniem najgorszej ścieżki i uwzględnia zagnieżdżone include/redirect, gdy ich rekordy są dostępne bez makr.",
                "Test legacy TLS wykonuje pojedyncze handshaki dla wersji protokołu; lokalne ograniczenia biblioteki TLS mogą dać wynik VERIFY zamiast oceny.",
            ],
        }
