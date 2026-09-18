from __future__ import annotations

from typing import Optional

from .constants import TIMEOUT
from .utils import days_until, fallback_root_domain


class RdapMixin:
    """RDAP and registered-domain checks."""

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
        # At least two labels remain. RDAP decides the real registration boundary.
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
            # Continue scanning with a conservative fallback even when RDAP is
            # unavailable. This is especially useful during temporary network issues.
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

        if nameservers:
            if len(set(nameservers)) >= 2:
                self.add_check("Domain", "Name server redundancy", "pass",
                               f"Wykryto {len(set(nameservers))} serwery NS.", 3, 3)
            else:
                self.add_check("Domain", "Name server redundancy", "warn",
                               "Wykryto tylko jeden serwer NS.", 3, 0)
