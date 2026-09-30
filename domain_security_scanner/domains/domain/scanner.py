from __future__ import annotations

from typing import Optional

from ...constants import COMMON_DNS_TYPES, TIMEOUT
from ...utils import days_until, fallback_root_domain
from .caa import collect_caa_policy
from .delegation_findings import build_delegation_findings
from .dns_scoring import CAA_MALFORMED_WEIGHT


class DomainScanMixin:
    """Registered-domain and authoritative DNS checks."""

    def _rdap_base_for_tld(self) -> Optional[str]:
        """Return an RDAP base URL for the target TLD using the IANA bootstrap."""
        tld = self.target_domain.rsplit(".", 1)[-1].lower()
        try:
            bootstrap = self.session.get(
                "https://data.iana.org/rdap/dns.json", timeout=TIMEOUT
            )
            bootstrap.raise_for_status()
            for tlds, urls in bootstrap.json().get("services", []):
                if tld in [x.lower() for x in tlds] and urls:
                    return urls[0].rstrip("/") + "/"
        except Exception:
            pass
        if tld == "pl":
            return "https://rdap.dns.pl/"
        return None

    def rdap_lookup(self):
        """Resolve the registered/root domain first, then parse its RDAP data.

        This intentionally walks upward from a supplied subdomain. Example:
        new.home.example.pl -> home.example.pl -> example.pl. The first RDAP
        object that exists becomes root_domain. A 404 for a subdomain is normal
        and is not reported as an RDAP failure.
        """
        base = self._rdap_base_for_tld()
        data = None
        url = None
        errors = []

        labels = self.target_domain.split(".")
        candidates = [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]

        if base:
            for candidate in candidates:
                candidate_url = base + "domain/" + candidate
                try:
                    r = self.session.get(
                        candidate_url, timeout=TIMEOUT,
                        headers={"Accept": "application/rdap+json"}
                    )
                    if r.status_code == 404:
                        continue
                    r.raise_for_status()
                    body = r.json()
                    if isinstance(body, dict):
                        data = body
                        url = candidate_url
                        self.root_domain = candidate
                        break
                except Exception as e:
                    errors.append(f"{candidate}: {e}")

        if data is None:
            self.root_domain = fallback_root_domain(self.target_domain)
            self.subdomains.add(self.root_domain)
            self.rdap = {
                "error": "; ".join(errors) if errors else "RDAP unavailable",
                "url": url,
                "root_domain": self.root_domain,
            }
            self.add_check(
                "Domain", "RDAP", "unknown",
                f"Nie udało się potwierdzić domeny rejestrowanej przez RDAP; "
                f"używam {self.root_domain} jako domeny bazowej.",
                weight=0, earned=0, applicable=False
            )
            return

        self.subdomains.add(self.root_domain)
        events = {}
        for ev in data.get("events", []):
            action = ev.get("eventAction")
            date = ev.get("eventDate")
            if action and date:
                events[action] = date

        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [])
                if isinstance(vcard, list) and len(vcard) == 2:
                    for item in vcard[1]:
                        if item and item[0] == "fn":
                            registrar = item[3]
                            break

        nameservers = [x.get("ldhName") for x in data.get("nameservers", []) if x.get("ldhName")]
        statuses = data.get("status", [])
        secure_dns = data.get("secureDNS", {})
        nask_state = data.get("nask0_state")

        self.rdap = {
            "url": url,
            "root_domain": self.root_domain,
            "registrar": registrar,
            "events": events,
            "nameservers": nameservers,
            "status": statuses,
            "secureDNS": secure_dns,
            "nask0_state": nask_state,
        }

        expiry = (
            events.get("expiration")
            or events.get("expiry")
            or events.get("registration expiration")
            or events.get("registrar expiration")
        )
        if expiry:
            days = days_until(expiry)
            self.rdap["expiry_days"] = days
            if days is None:
                self.add_check("Domain", "Domain expiry", "unknown", f"Data wygaśnięcia: {expiry}",
                               3, 0, False)
            elif days >= 30:
                self.add_check("Domain", "Domain expiry", "pass",
                               f"Domena {self.root_domain} ważna jeszcze ok. {days} dni.", 3, 3)
            elif days >= 7:
                self.add_check("Domain", "Domain expiry", "warn",
                               f"Domena {self.root_domain} wygasa za ok. {days} dni.", 3, 1.5)
            else:
                self.add_check("Domain", "Domain expiry", "fail",
                               f"Domena {self.root_domain} wygasa za ok. {days} dni.", 3, 0)
        else:
            self.add_check("Domain", "Domain expiry", "unknown",
                           "RDAP nie zwrócił daty wygaśnięcia.", 3, 0, False)

        status_text = " ".join(statuses).lower()
        transfer_locked = any(x in status_text for x in (
            "client transfer prohibited", "clienttransferprohibited",
            "server transfer prohibited", "servertransferprohibited"
        ))
        if transfer_locked:
            self.add_check("Domain", "Transfer lock", "pass",
                           "RDAP wskazuje blokadę transferu domeny.", 4, 4)
            self.rdap["transfer_lock"] = "detected"
        else:
            if self.root_domain.endswith(".pl"):
                self.add_check(
                    "Domain", "Transfer lock", "unknown",
                    "Dla .pl brak statusu w RDAP nie potwierdza braku .pl Registry Lock; "
                    "zweryfikuj blokadę u rejestratora.",
                    4, 0, False
                )
                self.rdap["transfer_lock"] = "unknown"
            else:
                self.add_check("Domain", "Transfer lock", "warn",
                               "Nie wykryto statusu transfer-prohibited w RDAP.", 4, 0)
                self.rdap["transfer_lock"] = "not_detected"

        signed = secure_dns.get("delegationSigned")
        if signed is True:
            self.rdap["dnssec_rdap"] = True
        elif signed is False:
            self.rdap["dnssec_rdap"] = False

    def _add_delegation_findings(self):
        """Emit #14 Domain checks from previously collected delegation evidence."""
        evidence = getattr(self, "delegation", None)
        analysis = getattr(self, "delegation_analysis", None)
        if evidence is None or analysis is None:
            return

        for finding in build_delegation_findings(
            evidence,
            analysis,
            getattr(self, "authoritative_dns_analysis", None),
        ):
            self.add_check(
                "Domain",
                finding.name,
                finding.status,
                finding.message,
                finding.weight,
                finding.earned,
                finding.applicable,
            )

    def _add_caa_findings(self):
        """Emit CAA posture from the RFC 8659 effective-policy evidence."""
        evidence = getattr(self, "caa", {}) or {}
        analysis = evidence.get("analysis", {})
        state = analysis.get("state")

        if state == "unknown":
            failure = evidence.get("lookup_failure") or {}
            failed_name = failure.get("name", "nieznanej nazwie")
            failed_state = failure.get("state", "resolver_error")
            self.add_check(
                "Domain", "CAA", "unknown",
                f"Nie można wiarygodnie ustalić efektywnej polityki CAA: "
                f"zapytanie dla {failed_name} zakończyło się stanem {failed_state}.",
                3, 0, False
            )
            return

        if state == "absent":
            self.add_check(
                "Domain", "CAA", "warn",
                f"Nie wykryto rekordu CAA w łańcuchu RFC 8659 od "
                f"{self.target_domain} do korzenia DNS.",
                3, 0
            )
            return

        effective_name = evidence.get("effective_name")
        records = evidence.get("records", [])
        syntax_errors = analysis.get("syntax_error_records", [])
        if syntax_errors:
            self.add_check(
                "Domain", "CAA", "unknown",
                f"Wykryto efektywny RRset CAA dla {effective_name}, ale nie wszystkie "
                f"rekordy udało się bezpiecznie sparsować.",
                3, 0, False
            )
            self.add_check(
                "Domain", "CAA policy syntax", "warn",
                f"W efektywnym RRset CAA dla {effective_name} wykryto {len(syntax_errors)} "
                "rekord(y) o nieprawidłowej składni. Polityka wymaga korekty i ponownej weryfikacji.",
                CAA_MALFORMED_WEIGHT, 0
            )
            return

        if analysis.get("fqdn_issuance_restricted"):
            issuers = analysis.get("fqdn_issuers", [])
            if analysis.get("fqdn_issuance_forbidden"):
                policy_text = "polityka zabrania wystawiania certyfikatów dla zwykłego FQDN"
            elif issuers:
                policy_text = "issuer-domain-name: " + ", ".join(issuers)
            else:
                policy_text = "polityka ogranicza wystawianie certyfikatów dla zwykłego FQDN"
            self.add_check(
                "Domain", "CAA", "pass",
                f"Wykryto {len(records)} rekord(y) CAA; efektywna polityka pochodzi z "
                f"{effective_name} ({policy_text}).",
                3, 3
            )
        elif analysis.get("has_issuewild"):
            self.add_check(
                "Domain", "CAA", "warn",
                f"Efektywny RRset CAA dla {effective_name} zawiera issuewild, ale nie "
                "zawiera issue; dla zwykłego FQDN nie ogranicza wystawiania certyfikatów.",
                3, 0
            )
        elif analysis.get("critical_unknown_tags"):
            self.add_check(
                "Domain", "CAA", "unknown",
                f"Efektywny RRset CAA dla {effective_name} nie zawiera rozpoznanego issue, "
                "a zawiera krytyczne nierozpoznane właściwości; skutku polityki nie można "
                "jednoznacznie ocenić.",
                3, 0, False
            )
        else:
            self.add_check(
                "Domain", "CAA", "warn",
                f"Efektywny RRset CAA dla {effective_name} nie zawiera właściwości issue; "
                "sama obecność iodef lub nierozpoznanych niekrytycznych tagów nie ogranicza "
                "wystawiania certyfikatów dla zwykłego FQDN.",
                3, 0
            )

        malformed_values = analysis.get("malformed_value_records", [])
        if malformed_values:
            self.add_check(
                "Domain", "CAA policy syntax", "warn",
                f"W efektywnym RRset CAA wykryto {len(malformed_values)} nieprawidłowe "
                "wartości rozpoznanych właściwości. Nieprawidłowe issue/issuewild są "
                "traktowane przez RFC 8659 jak pusty issuer-domain-name.",
                CAA_MALFORMED_WEIGHT, 0
            )

        critical_unknown = analysis.get("critical_unknown_tags", [])
        if critical_unknown:
            self.add_check(
                "Domain", "CAA critical properties", "warn",
                "Efektywny RRset CAA zawiera krytyczne nierozpoznane tagi: "
                + ", ".join(critical_unknown)
                + ". CA, która nie obsługuje takiego tagu, nie może wystawić certyfikatu.",
                0, 0
            )

    def collect_domain_dns(self):
        """Collect root/target DNS inventory and evaluate domain-level DNS posture."""
        self._add_delegation_findings()

        self.caa = collect_caa_policy(
            self.target_domain,
            self.dns_query_result,
        )
        self.rdap["caa_source"] = self.caa.get("effective_name")

        root = {}
        for rt in COMMON_DNS_TYPES:
            result = self.dns_query_result(self.root_domain, rt)
            root[rt] = list(result.records)
        ds_result = self.dns_query_result(self.root_domain, "DS")
        root["DS"] = list(ds_result.records)
        self.dns_records[self.root_domain] = root

        if self.target_domain != self.root_domain:
            target = {}
            for rt in COMMON_DNS_TYPES:
                result = self.dns_query_result(self.target_domain, rt)
                target[rt] = list(result.records)
            self.dns_records[self.target_domain] = target

        # DNSSEC scoring is emitted by DnssecScanMixin from direct parent/child
        # evidence and cryptographic validation. Recursive DS and RDAP metadata
        # remain inventory/context only and must not imply a secure state.
        self._add_caa_findings()
