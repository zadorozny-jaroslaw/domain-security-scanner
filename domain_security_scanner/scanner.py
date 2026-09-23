from __future__ import annotations

from datetime import datetime, timezone

from .base import BaseScanner
from .cms import CmsMixin
from .dns_mail import DnsMailMixin
from .domains.discovery import DiscoveryScanMixin
from .domains.domain import DomainScanMixin
from .models import ScoreResult
from .web_tls import WebTlsMixin
from .version import __version__


class Scanner(DomainScanMixin, DnsMailMixin, DiscoveryScanMixin, WebTlsMixin, CmsMixin, BaseScanner):
    """Orchestrates the existing scanner modules without changing scan behavior."""

    def run(self):
        self.rdap_lookup()
        self.collect_dns()
        self.discover_ct_subdomains()
        self.crawl()
        self.collect_subdomain_dns()
        self.check_tls()
        self.check_http()
        self.check_cms_currency()

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
