#!/usr/bin/env python3
"""
Low-impact external domain security hygiene scanner.

Copyright (c) 2026 Jarosław Zadorożny.
Licensed for non-commercial use; see LICENSE.

Intended for domains you own or have explicit authorization to assess.
It performs passive / low-impact checks only:
- RDAP registration metadata
- DNS records
- passive CT subdomain discovery via crt.sh
- same-site crawl for hostnames and public email addresses
- HTTPS/TLS certificate checks
- HTTP security headers, cookie flags and mixed-content checks
- legacy TLS protocol support checks
- passive CMS / web-platform fingerprinting from already-fetched HTML and headers
- live CMS release-currency comparison for common CMS platforms
- SPF syntax / duplicate / DNS-lookup-budget analysis
- extended DMARC policy / reporting / alignment analysis
- common-selector DKIM checks
- HTTP server/version disclosure checks
- MTA-STS / TLS-RPT
- DNSSEC indication

It does NOT exploit vulnerabilities, brute-force credentials, scan port ranges,
perform DoS tests, or attempt to access non-public data.
"""

from __future__ import annotations

__version__ = "1.0.1"

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import warnings
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)

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


@dataclass
class Check:
    category: str
    name: str
    status: str        # pass / warn / fail / info / unknown
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True


class Scanner:
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
        self.emails: set[str] = set()
        self.crawl_mixed_content: set[str] = set()
        self.dns_records: dict[str, dict[str, list[str]]] = {}
        self.rdap: dict[str, Any] = {}
        self.http: dict[str, Any] = {}
        self.tls: dict[str, Any] = {}
        self.mail: dict[str, Any] = {}

    def add_check(self, category, name, status, message, weight=0, earned=0, applicable=True):
        self.checks.append(Check(category, name, status, message, weight, earned, applicable))

    # ---------------- RDAP / domain ----------------

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

    # ---------------- DNS ----------------

    def dns_query(self, host: str, rtype: str) -> list[str]:
        try:
            ans = self.resolver.resolve(host, rtype, raise_on_no_answer=False)
            if ans.rrset is None:
                return []
            return [r.to_text() for r in ans]
        except Exception:
            return []

    @staticmethod
    def _normalize_txt_record(value: str) -> str:
        """Join quoted DNS TXT chunks into one logical record."""
        value = str(value or "").strip()
        chunks = re.findall(r'"((?:\\.|[^"\\])*)"', value)
        if chunks:
            return "".join(chunk.replace(r'\\"', '"').replace(r'\\\\', '\\') for chunk in chunks)
        return value.strip('"')

    def _txt_records(self, host: str) -> list[str]:
        return [self._normalize_txt_record(x) for x in self.dns_query(host, "TXT")]

    @staticmethod
    def _spf_terms(record: str) -> list[str]:
        return [x for x in str(record).strip().split() if x]

    def _analyze_spf_syntax(self, record: str) -> dict[str, Any]:
        """Practical SPF syntax validation; intentionally not a full RFC parser."""
        terms = self._spf_terms(record)
        errors: list[str] = []
        warnings_list: list[str] = []
        redirect_count = 0
        exp_count = 0
        if not terms or terms[0].lower() != "v=spf1":
            errors.append("record must start with v=spf1")
            return {"valid": False, "errors": errors, "warnings": warnings_list, "terms": terms}

        for raw in terms[1:]:
            token = raw
            qualifier = ""
            if token and token[0] in "+-~?":
                qualifier, token = token[0], token[1:]
            low = token.lower()

            if "=" in token and not low.startswith(("ip4:", "ip6:")):
                if qualifier:
                    errors.append(f"modifier cannot use qualifier: {raw}")
                    continue
                key, value = token.split("=", 1)
                key_l = key.lower()
                if not key or not value:
                    errors.append(f"invalid modifier: {raw}")
                if key_l == "redirect":
                    redirect_count += 1
                elif key_l == "exp":
                    exp_count += 1
                # Unknown modifiers are permitted by SPF extensibility rules.
                continue

            mechanism = re.split(r"[:/]", low, maxsplit=1)[0]
            if mechanism == "all":
                if low != "all":
                    errors.append(f"invalid all mechanism: {raw}")
                # RFC 7208: mechanisms after `all` are ignored during evaluation.
                break
            elif mechanism in ("include", "exists"):
                if ":" not in token or not token.split(":", 1)[1]:
                    errors.append(f"{mechanism} requires a domain-spec: {raw}")
            elif mechanism in ("a", "mx", "ptr"):
                if mechanism == "ptr":
                    warnings_list.append("ptr mechanism is deprecated and should generally be avoided")
            elif mechanism in ("ip4", "ip6"):
                if ":" not in token:
                    errors.append(f"{mechanism} requires an address: {raw}")
                    continue
                addr = token.split(":", 1)[1]
                try:
                    ipaddress.ip_network(addr, strict=False)
                    if mechanism == "ip4" and ":" in addr:
                        errors.append(f"ip4 contains an IPv6 value: {raw}")
                    if mechanism == "ip6" and ":" not in addr:
                        errors.append(f"ip6 contains an IPv4 value: {raw}")
                except ValueError:
                    errors.append(f"invalid {mechanism} network: {raw}")
            else:
                errors.append(f"unknown SPF mechanism: {raw}")

        if redirect_count > 1:
            errors.append("more than one redirect modifier")
        if exp_count > 1:
            errors.append("more than one exp modifier")
        return {"valid": not errors, "errors": errors, "warnings": warnings_list, "terms": terms}

    def _estimate_spf_dns_lookups(self, domain: str, record: str, visited: Optional[set[str]] = None, depth: int = 0) -> dict[str, Any]:
        """Estimate worst-case SPF DNS-querying terms, including nested include/redirect.

        RFC 7208 limits include/a/mx/ptr/exists plus redirect to 10 terms during
        evaluation, including nested include/redirect processing. Mechanisms after
        the first `all` are ignored, and `redirect` is ignored when an `all`
        mechanism exists anywhere in the record. Macro-based targets are counted
        but cannot always be expanded statically.
        """
        if visited is None:
            visited = set()
        key = domain.lower().rstrip(".")
        if key in visited:
            return {"count": 0, "breakdown": [], "notes": [f"cycle detected at {domain}"]}
        if depth > 12:
            return {"count": 0, "breakdown": [], "notes": ["SPF recursion depth limit reached"]}
        visited = set(visited)
        visited.add(key)

        count = 0
        breakdown: list[str] = []
        notes: list[str] = []
        terms = self._spf_terms(record)[1:]

        def bare_token(raw: str) -> str:
            return raw[1:] if raw and raw[0] in "+-~?" else raw

        has_all = any(re.split(r"[:/]", bare_token(x).lower(), maxsplit=1)[0] == "all" for x in terms if "=" not in bare_token(x))

        for raw in terms:
            token = bare_token(raw)
            low = token.lower()

            if low.startswith("redirect="):
                if has_all:
                    continue
                target = token.split("=", 1)[1].strip().rstrip(".")
                count += 1
                breakdown.append(f"redirect={target}")
                if target and "%" not in target and count <= 20:
                    child_records = [x for x in self._txt_records(target) if x.lower().startswith("v=spf1")]
                    if len(child_records) == 1:
                        child = self._estimate_spf_dns_lookups(target, child_records[0], visited, depth + 1)
                        count += child["count"]
                        breakdown.extend([f"  {x}" for x in child["breakdown"]])
                        notes.extend(child["notes"])
                    elif len(child_records) == 0:
                        notes.append(f"redirect target {target} has no SPF record")
                    else:
                        notes.append(f"redirect target {target} has multiple SPF records")
                elif target and "%" in target:
                    notes.append(f"cannot recursively evaluate macro-based redirect target: {target}")
                if count > 20:
                    notes.append("lookup expansion stopped after clearly exceeding the SPF limit")
                    break
                continue

            if "=" in token:
                # Other modifiers, including exp, do not count toward the 10-term limit.
                continue

            mechanism = re.split(r"[:/]", low, maxsplit=1)[0]
            if mechanism == "all":
                break

            if mechanism in ("include", "a", "mx", "ptr", "exists"):
                count += 1
                breakdown.append(token)
                if mechanism == "include":
                    target = token.split(":", 1)[1].strip().rstrip(".") if ":" in token else ""
                    if target and "%" not in target and count <= 20:
                        child_records = [x for x in self._txt_records(target) if x.lower().startswith("v=spf1")]
                        if len(child_records) == 1:
                            child = self._estimate_spf_dns_lookups(target, child_records[0], visited, depth + 1)
                            count += child["count"]
                            breakdown.extend([f"  {x}" for x in child["breakdown"]])
                            notes.extend(child["notes"])
                        elif len(child_records) == 0:
                            notes.append(f"include target {target} has no SPF record")
                        else:
                            notes.append(f"include target {target} has multiple SPF records")
                    elif target and "%" in target:
                        notes.append(f"cannot recursively evaluate macro-based include target: {target}")
                if count > 20:
                    notes.append("lookup expansion stopped after clearly exceeding the SPF limit")
                    break

        return {"count": count, "breakdown": breakdown, "notes": notes}

    @staticmethod
    def _parse_dmarc_record(record: str) -> dict[str, Any]:
        tags: dict[str, str] = {}
        errors: list[str] = []
        parts = [x.strip() for x in str(record).strip().split(";") if x.strip()]
        ordered_keys: list[str] = []
        for part in parts:
            if "=" not in part:
                errors.append(f"invalid tag: {part}")
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if not key or not value:
                errors.append(f"invalid tag: {part}")
                continue
            if key in tags:
                errors.append(f"duplicate tag: {key}")
            tags[key] = value
            ordered_keys.append(key)

        if not ordered_keys or ordered_keys[0] != "v" or tags.get("v", "").upper() != "DMARC1":
            errors.append("v=DMARC1 must be the first tag")
        if len(ordered_keys) < 2 or ordered_keys[1] != "p":
            errors.append("p must be the second tag after v")
        policy = tags.get("p", "").lower()
        if policy not in ("none", "quarantine", "reject"):
            errors.append("p must be none, quarantine, or reject")
        if "sp" in tags and tags["sp"].lower() not in ("none", "quarantine", "reject"):
            errors.append("sp must be none, quarantine, or reject")
        for align in ("adkim", "aspf"):
            if align in tags and tags[align].lower() not in ("r", "s"):
                errors.append(f"{align} must be r or s")
        pct = 100
        if "pct" in tags:
            try:
                pct = int(tags["pct"])
                if pct < 0 or pct > 100:
                    raise ValueError
            except ValueError:
                errors.append("pct must be an integer from 0 to 100")
                pct = None

        rua = [x.strip() for x in tags.get("rua", "").split(",") if x.strip()]
        ruf = [x.strip() for x in tags.get("ruf", "").split(",") if x.strip()]
        return {
            "valid": not errors,
            "errors": errors,
            "tags": tags,
            "policy": policy or None,
            "subdomain_policy": tags.get("sp", policy).lower() if policy else None,
            "pct": pct,
            "rua": rua,
            "ruf": ruf,
            "adkim": tags.get("adkim", "r").lower(),
            "aspf": tags.get("aspf", "r").lower(),
            "fo": tags.get("fo", "0"),
        }

    def collect_dns(self):
        # Registration/domain and mail checks always use the registered root domain.
        # Web checks continue to use the exact target host supplied by the user.
        root = {}
        for rt in COMMON_DNS_TYPES:
            root[rt] = self.dns_query(self.root_domain, rt)
        root["DS"] = self.dns_query(self.root_domain, "DS")
        self.dns_records[self.root_domain] = root

        if self.target_domain != self.root_domain:
            target = {}
            for rt in COMMON_DNS_TYPES:
                target[rt] = self.dns_query(self.target_domain, rt)
            self.dns_records[self.target_domain] = target

        ds = root["DS"]
        rdap_signed = self.rdap.get("dnssec_rdap")
        if ds or rdap_signed is True:
            self.add_check("Domain", "DNSSEC", "pass",
                           f"Wykryto delegację DNSSEC dla {self.root_domain}.", 7, 7)
        else:
            self.add_check("Domain", "DNSSEC", "warn",
                           f"Nie wykryto delegacji DNSSEC dla {self.root_domain}.", 7, 0)

        # CAA can exist at the exact host; if absent, CA processing walks upward.
        target_caa = self.dns_query(self.target_domain, "CAA") if self.target_domain != self.root_domain else []
        caa = target_caa or root.get("CAA", [])
        self.rdap["caa_source"] = self.target_domain if target_caa else self.root_domain
        if caa:
            self.add_check("Domain", "CAA", "pass",
                           f"Wykryto {len(caa)} rekord(y) CAA (źródło: {self.rdap['caa_source']}).", 3, 3)
        else:
            self.add_check("Domain", "CAA", "warn",
                           "Brak rekordu CAA na hoście docelowym i domenie bazowej.", 3, 0)

        # MAIL SECURITY: always root domain, even if the website is on a subdomain.
        self.mail["domain"] = self.root_domain
        mx = root.get("MX", [])
        self.mail["mx"] = mx
        if mx:
            self.add_check("Mail", "MX", "pass",
                           f"Wykryto {len(mx)} rekord(y) MX dla {self.root_domain}.", 2, 2)
        else:
            self.add_check("Mail", "MX", "info",
                           f"Brak rekordów MX dla {self.root_domain}. Jeśli domena nie obsługuje poczty, może to być zamierzone.",
                           2, 0, False)

        txt = [self._normalize_txt_record(x) for x in root.get("TXT", [])]
        spf = [x for x in txt if x.lower().startswith("v=spf1")]
        self.mail["spf"] = spf
        self.mail["spf_analysis"] = {"record_count": len(spf)}

        if not spf:
            self.add_check("Mail", "SPF", "fail",
                           f"Nie wykryto rekordu SPF dla {self.root_domain}.", 8, 0)
            self.add_check("Mail", "SPF syntax", "unknown",
                           "Nie można ocenić składni SPF bez rekordu SPF.", 0, 0, False)
            self.add_check("Mail", "SPF DNS lookup budget", "unknown",
                           "Nie można ocenić limitu zapytań DNS bez rekordu SPF.", 0, 0, False)
        elif len(spf) > 1:
            self.mail["spf_analysis"].update({"valid": False, "error": "multiple SPF records"})
            self.add_check("Mail", "SPF", "fail",
                           f"Dla {self.root_domain} opublikowano {len(spf)} rekordy SPF; SPF powinien mieć jeden rekord v=spf1.", 8, 0)
            self.add_check("Mail", "SPF duplicate records", "fail",
                           "Wykryto więcej niż jeden rekord v=spf1, co może powodować SPF PermError.", 2, 0)
            self.add_check("Mail", "SPF syntax", "unknown",
                           "Ocena składni jest niejednoznaczna przy wielu rekordach SPF.", 0, 0, False)
            self.add_check("Mail", "SPF DNS lookup budget", "unknown",
                           "Ocena limitu zapytań jest niejednoznaczna przy wielu rekordach SPF.", 0, 0, False)
        else:
            spf_record = spf[0]
            syntax = self._analyze_spf_syntax(spf_record)
            lookups = self._estimate_spf_dns_lookups(self.root_domain, spf_record)
            self.mail["spf_analysis"].update({"record": spf_record, "syntax": syntax, "dns_lookups": lookups})

            if syntax["valid"]:
                self.add_check("Mail", "SPF syntax", "pass", "Składnia rekordu SPF wygląda poprawnie.", 2, 2)
            else:
                self.add_check("Mail", "SPF syntax", "fail",
                               "Wykryto problemy składni SPF: " + "; ".join(syntax["errors"][:4]), 2, 0)

            lookup_count = lookups["count"]
            if lookup_count > 10:
                self.add_check("Mail", "SPF DNS lookup budget", "fail",
                               f"Szacowany najgorszy przypadek używa {lookup_count} mechanizmów wymagających DNS; limit SPF wynosi 10.", 3, 0)
            elif lookup_count == 10:
                self.add_check("Mail", "SPF DNS lookup budget", "warn",
                               "SPF wykorzystuje szacunkowo pełny limit 10 mechanizmów DNS; kolejna zmiana może spowodować PermError.", 3, 1.5)
            else:
                self.add_check("Mail", "SPF DNS lookup budget", "pass",
                               f"Szacowany budżet SPF: {lookup_count}/10 mechanizmów wymagających DNS.", 3, 3)

            spf_lower = spf_record.lower()
            if "+all" in spf_lower:
                self.add_check("Mail", "SPF", "fail",
                               f"SPF dla {self.root_domain} zawiera +all, co praktycznie zezwala każdemu nadawcy.", 8, 0)
            elif not syntax["valid"] or lookup_count > 10:
                self.add_check("Mail", "SPF", "fail",
                               f"SPF dla {self.root_domain} istnieje, ale ma błąd składni lub przekracza limit zapytań DNS.", 8, 0)
            elif re.search(r"(?:^|\s)-all(?:\s|$)", spf_lower):
                self.add_check("Mail", "SPF", "pass",
                               f"SPF dla {self.root_domain} obecny z restrykcyjnym mechanizmem -all.", 8, 8)
            elif re.search(r"(?:^|\s)~all(?:\s|$)", spf_lower):
                self.add_check("Mail", "SPF", "pass",
                               f"SPF dla {self.root_domain} obecny z softfail ~all.", 8, 6)
            elif re.search(r"(?:^|\s)\?all(?:\s|$)", spf_lower):
                self.add_check("Mail", "SPF", "warn",
                               f"SPF dla {self.root_domain} kończy się neutralnym ?all i zapewnia słabszą politykę nadawców.", 8, 3)
            else:
                self.add_check("Mail", "SPF", "warn",
                               f"SPF dla {self.root_domain} obecny, ale końcowa polityka wymaga ręcznej oceny.", 8, 4)

        dmarc_txt = [self._normalize_txt_record(x) for x in self.dns_query(f"_dmarc.{self.root_domain}", "TXT")]
        dmarc = [x for x in dmarc_txt if re.search(r"\bv\s*=\s*dmarc1\b", x, flags=re.I)]
        self.mail["dmarc"] = dmarc
        self.mail["dmarc_analysis"] = {"record_count": len(dmarc)}
        if not dmarc:
            self.add_check("Mail", "DMARC", "fail",
                           f"Nie wykryto rekordu DMARC dla {self.root_domain}.", 12, 0)
            self.add_check("Mail", "DMARC syntax", "unknown",
                           "Nie można ocenić składni DMARC bez rekordu DMARC.", 0, 0, False)
        elif len(dmarc) > 1:
            self.mail["dmarc_analysis"].update({"valid": False, "error": "multiple DMARC records"})
            self.add_check("Mail", "DMARC", "fail",
                           f"Wykryto {len(dmarc)} rekordy DMARC dla {self.root_domain}; powinien istnieć jeden rekord polityki.", 12, 0)
            self.add_check("Mail", "DMARC syntax", "fail",
                           "Wiele rekordów DMARC powoduje niejednoznaczną/nieprawidłową politykę.", 2, 0)
        else:
            analysis = self._parse_dmarc_record(dmarc[0])
            self.mail["dmarc_analysis"].update(analysis)
            self.mail["dmarc_policy"] = analysis.get("policy") or "unknown"
            if not analysis["valid"]:
                self.add_check("Mail", "DMARC syntax", "fail",
                               "Wykryto problemy składni DMARC: " + "; ".join(analysis["errors"][:4]), 2, 0)
                self.add_check("Mail", "DMARC", "fail",
                               f"DMARC dla {self.root_domain} istnieje, ale rekord jest nieprawidłowy.", 12, 0)
            else:
                self.add_check("Mail", "DMARC syntax", "pass", "Składnia DMARC wygląda poprawnie.", 2, 2)
                policy = analysis["policy"]
                pct = analysis.get("pct", 100)
                sp = analysis.get("subdomain_policy") or policy
                if policy == "reject" and pct == 100:
                    self.add_check("Mail", "DMARC", "pass",
                                   f"DMARC dla {self.root_domain}: p=reject, pct=100, polityka subdomen={sp}.", 12, 12)
                elif policy == "quarantine" and pct == 100:
                    self.add_check("Mail", "DMARC", "pass",
                                   f"DMARC dla {self.root_domain}: p=quarantine, pct=100, polityka subdomen={sp}.", 12, 10)
                elif policy in ("reject", "quarantine") and isinstance(pct, int) and pct < 100:
                    self.add_check("Mail", "DMARC", "warn",
                                   f"DMARC ma p={policy}, ale pct={pct}; egzekwowanie obejmuje tylko część wiadomości.", 12, 7)
                elif policy == "none":
                    self.add_check("Mail", "DMARC", "warn",
                                   f"DMARC dla {self.root_domain} jest w trybie monitoringu p=none.", 12, 5)
                else:
                    self.add_check("Mail", "DMARC", "warn",
                                   "DMARC obecny, ale polityka wymaga ręcznej oceny.", 12, 6)

                rua = analysis.get("rua", [])
                if rua:
                    self.add_check("Mail", "DMARC aggregate reporting", "pass",
                                   f"Skonfigurowano raporty zbiorcze DMARC (rua): {len(rua)} adres(y).", 0, 0, False)
                else:
                    self.add_check("Mail", "DMARC aggregate reporting", "info",
                                   "Brak rua; domena nie prosi odbiorców o zbiorcze raporty DMARC.", 0, 0, False)
                self.add_check("Mail", "DMARC alignment", "info",
                               f"Alignment: DKIM={analysis.get('adkim','r')} / SPF={analysis.get('aspf','r')} (r=relaxed, s=strict).",
                               0, 0, False)

        found_dkim = {}
        for selector in COMMON_DKIM_SELECTORS:
            rows = self.dns_query(f"{selector}._domainkey.{self.root_domain}", "TXT")
            rows = [x for x in rows if "v=dkim1" in x.lower() or "p=" in x.lower()]
            if rows:
                found_dkim[selector] = rows
        self.mail["dkim_common_selectors"] = found_dkim
        if found_dkim:
            self.add_check("Mail", "DKIM", "pass",
                           "Wykryto DKIM dla selektorów: " + ", ".join(sorted(found_dkim)), 5, 5)
        else:
            self.add_check(
                "Mail", "DKIM", "unknown",
                f"Nie znaleziono DKIM dla popularnych selektorów na {self.root_domain}. "
                "To NIE oznacza braku DKIM; selektor jest częścią konfiguracji nadawcy.",
                5, 0, False
            )

        mta_sts_dns = self.dns_query(f"_mta-sts.{self.root_domain}", "TXT")
        mta_policy = None
        try:
            r = self.session.get(
                f"https://mta-sts.{self.root_domain}/.well-known/mta-sts.txt", timeout=TIMEOUT
            )
            if r.status_code == 200 and "version: STSv1" in r.text:
                mta_policy = r.text[:3000]
        except Exception:
            pass
        self.mail["mta_sts_dns"] = mta_sts_dns
        self.mail["mta_sts_policy"] = mta_policy
        if mta_sts_dns and mta_policy:
            self.add_check("Mail", "MTA-STS", "pass",
                           "Wykryto rekord MTA-STS i dostępną politykę HTTPS.", 3, 3)
        elif mta_sts_dns or mta_policy:
            self.add_check("Mail", "MTA-STS", "warn",
                           "MTA-STS wygląda na częściowo skonfigurowane.", 3, 1)
        else:
            self.add_check("Mail", "MTA-STS", "info",
                           f"Nie wykryto MTA-STS dla {self.root_domain}.", 3, 0)

        tls_rpt = self.dns_query(f"_smtp._tls.{self.root_domain}", "TXT")
        tls_rpt = [x for x in tls_rpt if "v=tlsrptv1" in x.lower()]
        self.mail["tls_rpt"] = tls_rpt
        if tls_rpt:
            self.add_check("Mail", "TLS-RPT", "pass", "Wykryto rekord TLS-RPT.", 2, 2)
        else:
            self.add_check("Mail", "TLS-RPT", "info",
                           f"Nie wykryto TLS-RPT dla {self.root_domain}.", 2, 0)

    # ---------------- passive subdomain discovery / crawl ----------------

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

    # ---------------- web / TLS ----------------

    @staticmethod
    def _extract_mixed_content(html: str, base_url: str) -> list[str]:
        """Return insecure HTTP subresources or form actions from an HTTPS page.

        Normal hyperlinks (<a href=http://...>) are intentionally not treated as
        mixed content because they do not load content into the HTTPS document.
        """
        if not str(base_url).lower().startswith("https://"):
            return []
        found: set[str] = set()
        try:
            soup = BeautifulSoup(html or "", "html.parser")
            resource_attrs = {
                "script": ("src",), "img": ("src",), "iframe": ("src",),
                "audio": ("src",), "video": ("src", "poster"), "source": ("src",),
                "track": ("src",), "embed": ("src",), "object": ("data",),
                "link": ("href",), "form": ("action",), "input": ("src",),
            }
            for tag_name, attrs in resource_attrs.items():
                for tag in soup.find_all(tag_name):
                    for attr in attrs:
                        value = tag.get(attr)
                        if isinstance(value, str) and value.strip().lower().startswith("http://"):
                            found.add(value.strip())
                    if tag_name in ("img", "source"):
                        srcset = tag.get("srcset")
                        if isinstance(srcset, str):
                            for part in srcset.split(","):
                                candidate = part.strip().split()[0] if part.strip() else ""
                                if candidate.lower().startswith("http://"):
                                    found.add(candidate)
            for value in re.findall(r"url\(\s*['\"]?(http://[^)'\"\s]+)", html or "", flags=re.I):
                found.add(value)
        except Exception:
            pass
        return sorted(found)

    @staticmethod
    def _cookie_header_values(response) -> list[str]:
        try:
            raw_headers = getattr(getattr(response, "raw", None), "headers", None)
            if raw_headers is not None and hasattr(raw_headers, "getlist"):
                values = raw_headers.getlist("Set-Cookie")
                if values:
                    return list(values)
        except Exception:
            pass
        value = response.headers.get("Set-Cookie") if getattr(response, "headers", None) else None
        return [value] if value else []

    def _analyze_cookies(self, response) -> dict[str, Any]:
        responses = list(getattr(response, "history", []) or []) + [response]
        headers: list[str] = []
        for item in responses:
            headers.extend(self._cookie_header_values(item))
        cookies: list[dict[str, Any]] = []
        sensitive_re = re.compile(r"(session|sess|auth|token|jwt|sid$|phpsessid|jsessionid|asp\.net|wordpress_logged_in|security)", re.I)
        for header in headers:
            jar = SimpleCookie()
            try:
                jar.load(header)
            except Exception:
                continue
            for name, morsel in jar.items():
                same_site = (morsel["samesite"] or "").strip()
                item = {
                    "name": name,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": same_site or None,
                    "sensitive": bool(sensitive_re.search(name)),
                    "issues": [],
                }
                if item["sensitive"]:
                    if not item["secure"]:
                        item["issues"].append("missing Secure")
                    if not item["httponly"]:
                        item["issues"].append("missing HttpOnly")
                    if not same_site:
                        item["issues"].append("missing SameSite")
                if same_site.lower() == "none" and not item["secure"]:
                    item["issues"].append("SameSite=None without Secure")
                cookies.append(item)
        sensitive = [x for x in cookies if x["sensitive"]]
        issues = [x for x in cookies if x["issues"]]
        warning_items = [x for x in cookies if (x["sensitive"] and x["issues"]) or "SameSite=None without Secure" in x["issues"]]
        return {
            "set_cookie_headers": len(headers),
            "cookies": cookies,
            "sensitive_count": len(sensitive),
            "issue_count": len(issues),
            "warning_count": len(warning_items),
        }

    @staticmethod
    def _server_disclosure(headers: dict[str, str]) -> dict[str, Any]:
        interesting = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
        disclosed: dict[str, str] = {}
        exact_version = False
        for key in interesting:
            value = headers.get(key)
            if value:
                disclosed[key] = value
                if re.search(r"(?:^|[/\s])v?\d+(?:\.\d+){1,3}(?:[-+._A-Za-z0-9]*)?", value):
                    exact_version = True
        return {"headers": disclosed, "exact_version": exact_version}

    def _probe_tls_version(self, version) -> dict[str, Any]:
        label = getattr(version, "name", str(version))
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                try:
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((self.target_domain, 443), timeout=TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                        return {"status": "supported", "protocol": ssock.version(), "cipher": ssock.cipher()[0] if ssock.cipher() else None}
        except ssl.SSLError as e:
            message = str(e).lower()
            if "no ciphers available" in message or "no protocols available" in message:
                return {"status": "unknown", "error": str(e), "label": label}
            return {"status": "not_supported", "error": str(e)}
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            return {"status": "not_supported", "error": str(e)}
        except (OSError, ValueError) as e:
            return {"status": "unknown", "error": str(e), "label": label}

    def check_tls(self):
        host = self.target_domain
        result = {"host": host}
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    cert = s.getpeercert()
                    result["protocol"] = s.version()
                    result["cipher"] = s.cipher()[0] if s.cipher() else None
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["san"] = [x[1] for x in cert.get("subjectAltName", []) if len(x) == 2]
                    result["notAfter"] = cert.get("notAfter")
                    if cert.get("notAfter"):
                        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (expires - datetime.now(timezone.utc)).days
                        result["expiry_days"] = days
                        if days >= 30:
                            self.add_check("Web", "TLS certificate", "pass",
                                           f"Certyfikat poprawny, ważny jeszcze ok. {days} dni.", 6, 6)
                        elif days >= 7:
                            self.add_check("Web", "TLS certificate", "warn",
                                           f"Certyfikat wygasa za ok. {days} dni.", 6, 3)
                        else:
                            self.add_check("Web", "TLS certificate", "fail",
                                           f"Certyfikat wygasa za ok. {days} dni.", 6, 0)
                    else:
                        self.add_check("Web", "TLS certificate", "pass",
                                       "Połączenie TLS zweryfikowane.", 6, 6)
            self.add_check("Web", "HTTPS", "pass",
                           f"HTTPS działa; negocjowany protokół: {result.get('protocol')}.", 8, 8)
        except Exception as e:
            result["error"] = str(e)
            self.add_check("Web", "HTTPS", "fail",
                           f"Nie udało się zweryfikować HTTPS/TLS: {e}", 8, 0)
            self.add_check("Web", "TLS certificate", "fail",
                           "Nie udało się zweryfikować certyfikatu.", 6, 0)

        # Explicit protocol support probes. These are a handful of TLS handshakes,
        # not cipher-suite enumeration.
        support: dict[str, Any] = {}
        versions = []
        for label, attr in (("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"), ("TLS 1.2", "TLSv1_2"), ("TLS 1.3", "TLSv1_3")):
            version = getattr(ssl.TLSVersion, attr, None)
            if version is not None:
                support[label] = self._probe_tls_version(version)
        result["protocol_support"] = support

        legacy_states = [support.get("TLS 1.0", {}).get("status"), support.get("TLS 1.1", {}).get("status")]
        enabled = [label for label in ("TLS 1.0", "TLS 1.1") if support.get(label, {}).get("status") == "supported"]
        unknown = [label for label in ("TLS 1.0", "TLS 1.1") if support.get(label, {}).get("status") == "unknown"]
        if enabled:
            self.add_check("Web", "Legacy TLS", "warn",
                           "Serwer akceptuje starsze protokoły: " + ", ".join(enabled) + ".", 4, 0)
        elif unknown:
            self.add_check("Web", "Legacy TLS", "unknown",
                           "Nie udało się jednoznacznie sprawdzić: " + ", ".join(unknown) + ".", 4, 0, False)
        else:
            self.add_check("Web", "Legacy TLS", "pass",
                           "TLS 1.0 i TLS 1.1 nie są akceptowane przez serwer.", 4, 4)

        self.tls = result

    def check_http(self):
        result: dict[str, Any] = {}

        # Does HTTP redirect to HTTPS?
        try:
            r = self.session.get(f"http://{self.target_domain}", timeout=TIMEOUT, allow_redirects=False)
            loc = r.headers.get("location", "")
            result["http_status"] = r.status_code
            result["http_location"] = loc
            if r.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://"):
                self.add_check("Web", "HTTP -> HTTPS redirect", "pass",
                               "HTTP przekierowuje do HTTPS.", 4, 4)
            else:
                self.add_check("Web", "HTTP -> HTTPS redirect", "warn",
                               f"Brak jednoznacznego przekierowania HTTP→HTTPS (status {r.status_code}).",
                               4, 0)
        except Exception as e:
            result["http_error"] = str(e)
            self.add_check("Web", "HTTP -> HTTPS redirect", "unknown",
                           f"Nie udało się sprawdzić HTTP: {e}", 4, 0, False)

        try:
            r = self.session.get(f"https://{self.target_domain}", timeout=TIMEOUT, allow_redirects=True)
            result["https_status"] = r.status_code
            result["final_url"] = r.url
            result["headers"] = dict(r.headers)
            html = r.text[:2_000_000] if r.text else ""
            result["cms"] = self.detect_cms(r, html)

            headers_l = {k.lower(): v for k, v in r.headers.items()}

            # Cookie flags. Only sensitive/session-like cookies generate WARN findings;
            # analytics/preferences are inventoried without overstating risk.
            cookie_analysis = self._analyze_cookies(r)
            result["cookies"] = cookie_analysis
            sensitive_issues = [x for x in cookie_analysis["cookies"] if x["sensitive"] and x["issues"]]
            if sensitive_issues:
                short = "; ".join(f"{x['name']}: {', '.join(x['issues'])}" for x in sensitive_issues[:4])
                self.add_check("Web", "Cookie security flags", "warn",
                               f"Wykryto problemy z flagami wrażliwych cookies: {short}.", 3, 0)
            elif cookie_analysis["sensitive_count"]:
                self.add_check("Web", "Cookie security flags", "pass",
                               f"Wrażliwe/session cookies ({cookie_analysis['sensitive_count']}) mają podstawowe flagi Secure/HttpOnly/SameSite.", 3, 3)
            else:
                self.add_check("Web", "Cookie security flags", "info",
                               "Nie wykryto jednoznacznie wrażliwych/session cookies w odpowiedzi strony głównej.", 0, 0, False)

            # Mixed HTTP resources across pages seen by the crawler plus this response.
            mixed = set(self.crawl_mixed_content)
            mixed.update(self._extract_mixed_content(html, r.url))
            result["mixed_content"] = sorted(mixed)
            if mixed:
                self.add_check("Web", "Mixed content", "warn",
                               f"Strona HTTPS odwołuje się do {len(mixed)} zasobu/zasobów przez nieszyfrowane HTTP; np. {next(iter(sorted(mixed)))}.", 3, 0)
            else:
                self.add_check("Web", "Mixed content", "pass",
                               "Nie wykryto jawnych odwołań http:// na analizowanych stronach HTTPS.", 3, 3)

            disclosure = self._server_disclosure(headers_l)
            result["server_disclosure"] = disclosure
            if disclosure["exact_version"]:
                shown = ", ".join(f"{k}: {v}" for k, v in disclosure["headers"].items())
                self.add_check("Web", "Server version disclosure", "warn",
                               f"Nagłówki HTTP ujawniają szczegółowe wersje technologii: {shown}.", 1, 0)
            elif disclosure["headers"]:
                shown = ", ".join(f"{k}: {v}" for k, v in disclosure["headers"].items())
                self.add_check("Web", "Server disclosure", "info",
                               f"Nagłówki ujawniają technologię serwera bez jednoznacznej wersji: {shown}.", 0, 0, False)
            found = {friendly: headers_l.get(key) for key, friendly in SECURITY_HEADERS.items()}
            result["security_headers"] = found

            # HSTS
            hsts = headers_l.get("strict-transport-security")
            if hsts:
                self.add_check("Web", "HSTS", "pass", "HSTS jest ustawione.", 4, 4)
            else:
                self.add_check("Web", "HSTS", "warn", "Brak nagłówka HSTS.", 4, 0)

            csp = headers_l.get("content-security-policy")
            if csp:
                self.add_check("Web", "CSP", "pass", "Content-Security-Policy jest ustawiona.", 3, 3)
            else:
                self.add_check("Web", "CSP", "warn", "Brak Content-Security-Policy.", 3, 0)

            xcto = headers_l.get("x-content-type-options", "").lower()
            if "nosniff" in xcto:
                self.add_check("Web", "X-Content-Type-Options", "pass",
                               "X-Content-Type-Options: nosniff.", 2, 2)
            else:
                self.add_check("Web", "X-Content-Type-Options", "warn",
                               "Brak X-Content-Type-Options: nosniff.", 2, 0)

            if headers_l.get("referrer-policy"):
                self.add_check("Web", "Referrer-Policy", "pass",
                               "Referrer-Policy jest ustawiona.", 1, 1)
            else:
                self.add_check("Web", "Referrer-Policy", "info",
                               "Brak jawnej Referrer-Policy.", 1, 0)

            if headers_l.get("permissions-policy"):
                self.add_check("Web", "Permissions-Policy", "pass",
                               "Permissions-Policy jest ustawiona.", 1, 1)
            else:
                self.add_check("Web", "Permissions-Policy", "info",
                               "Brak Permissions-Policy.", 1, 0)

            frame_protection = bool(headers_l.get("x-frame-options")) or (
                csp and "frame-ancestors" in csp.lower()
            )
            if frame_protection:
                self.add_check("Web", "Frame protection", "pass",
                               "Wykryto ochronę przed osadzaniem strony w ramce.", 1, 1)
            else:
                self.add_check("Web", "Frame protection", "warn",
                               "Nie wykryto X-Frame-Options ani CSP frame-ancestors.", 1, 0)

        except Exception as e:
            result["https_error"] = str(e)
            result["cms"] = {
                "detected": False,
                "name": None,
                "version": None,
                "confidence": "none",
                "signals": [],
                "technology_headers": {},
            }
            result["cookies"] = {"set_cookie_headers": 0, "cookies": [], "sensitive_count": 0, "issue_count": 0, "warning_count": 0}
            result["mixed_content"] = sorted(self.crawl_mixed_content)
            result["server_disclosure"] = {"headers": {}, "exact_version": False}

        # security.txt - informational only
        try:
            r = self.session.get(
                f"https://{self.target_domain}/.well-known/security.txt",
                timeout=TIMEOUT,
                allow_redirects=True,
            )
            result["security_txt"] = r.status_code == 200 and "contact:" in r.text.lower()
            self.add_check(
                "Web", "security.txt",
                "pass" if result["security_txt"] else "info",
                "Wykryto security.txt." if result["security_txt"] else "Nie wykryto security.txt.",
                0, 0, False
            )
        except Exception:
            result["security_txt"] = False

        self.http = result


    def detect_cms(self, response, html: str) -> dict[str, Any]:
        """Passively fingerprint common CMS / hosted site platforms.

        Uses only the HTTPS response already fetched by check_http().
        No CMS-specific paths are probed and no brute-force enumeration is done.
        A version is reported only when explicitly disclosed by high-confidence
        metadata or response headers.
        """
        headers_l = {k.lower(): v for k, v in response.headers.items()}
        html_l = (html or "").lower()
        signals: list[str] = []
        candidates: dict[str, int] = {}
        versions: dict[str, str] = {}

        def hit(name: str, points: int, signal: str):
            candidates[name] = candidates.get(name, 0) + points
            if signal not in signals:
                signals.append(signal)

        generator = None
        try:
            soup = BeautifulSoup(html or "", "html.parser")
            gen = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
            if gen and gen.get("content"):
                generator = str(gen.get("content")).strip()
        except Exception:
            generator = None

        if generator:
            gl = generator.lower()
            known = [
                ("WordPress", r"wordpress(?:\s+|/)?([0-9][0-9A-Za-z.\-_]*)?"),
                ("Drupal", r"drupal(?:\s+|/)?([0-9][0-9A-Za-z.\-_]*)?"),
                ("Joomla", r"joomla!?(?:\s+|/)?([0-9][0-9A-Za-z.\-_]*)?"),
                ("Ghost", r"ghost(?:\s+|/)?([0-9][0-9A-Za-z.\-_]*)?"),
                ("TYPO3", r"typo3(?:\s+|/)?([0-9][0-9A-Za-z.\-_]*)?"),
            ]
            for name, pattern in known:
                m = re.search(pattern, generator, re.I)
                if m:
                    hit(name, 8, f'meta generator="{generator}"')
                    if m.group(1):
                        versions[name] = m.group(1)
                    break

            for name, needle in [
                ("Wix", "wix"),
                ("Squarespace", "squarespace"),
                ("Webflow", "webflow"),
                ("Shopify", "shopify"),
            ]:
                if needle in gl:
                    hit(name, 8, f'meta generator="{generator}"')

        if "/wp-content/" in html_l:
            hit("WordPress", 4, "HTML references /wp-content/")
        if "/wp-includes/" in html_l:
            hit("WordPress", 4, "HTML references /wp-includes/")
        link_header = headers_l.get("link", "").lower()
        if "wp-json" in link_header or "/wp-json/" in html_l:
            hit("WordPress", 3, "WordPress REST API reference")

        if "drupal-settings-json" in html_l:
            hit("Drupal", 5, "Drupal settings marker")
        if "/sites/default/files/" in html_l:
            hit("Drupal", 3, "HTML references /sites/default/files/")
        x_generator = headers_l.get("x-generator", "")
        if x_generator.lower().startswith("drupal"):
            hit("Drupal", 8, f"X-Generator: {x_generator}")
            m = re.search(r"drupal\s+([0-9][0-9A-Za-z.\-_]*)", x_generator, re.I)
            if m:
                versions["Drupal"] = m.group(1)

        if "/media/system/js/" in html_l or "/media/system/css/" in html_l:
            hit("Joomla", 3, "Joomla media/system asset paths")
        if "joomla" in html_l and "com_content" in html_l:
            hit("Joomla", 3, "Joomla component markers")

        if "ghost-url" in html_l or "/ghost/api/" in html_l:
            hit("Ghost", 4, "Ghost API/content marker")

        if "cdn.shopify.com" in html_l:
            hit("Shopify", 5, "Shopify CDN assets")
        if "shopify.theme" in html_l or "shopify-section" in html_l:
            hit("Shopify", 4, "Shopify theme markers")

        if "static.parastorage.com" in html_l or "wixstatic.com" in html_l:
            hit("Wix", 5, "Wix static asset host")

        if "static1.squarespace.com" in html_l or "squarespace-cdn.com" in html_l:
            hit("Squarespace", 5, "Squarespace assets")

        if "data-wf-page=" in html_l or "data-wf-site=" in html_l:
            hit("Webflow", 5, "Webflow data attributes")
        if "webflow.css" in html_l or "webflow.js" in html_l:
            hit("Webflow", 3, "Webflow assets")

        powered_by = headers_l.get("x-powered-by")
        server = headers_l.get("server")
        tech_headers = {}
        if powered_by:
            tech_headers["X-Powered-By"] = powered_by
        if server:
            tech_headers["Server"] = server

        if not candidates:
            result = {
                "detected": False,
                "name": None,
                "version": None,
                "confidence": "none",
                "generator": generator,
                "signals": signals,
                "technology_headers": tech_headers,
            }
            self.add_check(
                "Web", "CMS / platform", "info",
                "Nie wykryto jednoznacznie CMS/platformy na podstawie pasywnych sygnałów.",
                0, 0, False
            )
            return result

        ranked = sorted(candidates.items(), key=lambda kv: (-kv[1], kv[0]))
        name, points = ranked[0]
        confidence = "high" if points >= 7 else "medium" if points >= 4 else "low"
        version = versions.get(name)

        msg = f"Wykryto {name} (pewność: {confidence})."
        if version:
            msg += f" Publicznie ujawniona wersja: {version}."
        else:
            msg += " Wersja nie jest wiarygodnie ujawniona."

        self.add_check("Web", "CMS / platform", "info", msg, 0, 0, False)

        if version:
            self.add_check(
                "Web", "CMS version disclosure", "info",
                f"Strona publicznie ujawnia wersję {name}: {version}. "
                "Samo ujawnienie wersji nie oznacza podatności; aktualność należy zweryfikować osobno.",
                0, 0, False
            )

        return {
            "detected": True,
            "name": name,
            "version": version,
            "confidence": confidence,
            "generator": generator,
            "signals": signals,
            "candidate_scores": dict(ranked),
            "technology_headers": tech_headers,
        }


    @staticmethod
    def _stable_numeric_version(value: str) -> Optional[tuple[int, ...]]:
        """Return a comparable numeric tuple for a stable dotted version.

        Examples: 7.1 -> (7, 1), 11.4.1 -> (11, 4, 1).
        Pre-release strings such as 12.0.0-beta1 return None.
        """
        if not value:
            return None
        value = str(value).strip().lstrip("vV")
        if re.search(r"(?:alpha|beta|rc|dev|snapshot|nightly)", value, re.I):
            return None
        m = re.fullmatch(r"(\d+(?:\.\d+){1,3})(?:[-+].*)?", value)
        if not m:
            return None
        return tuple(int(x) for x in m.group(1).split("."))

    @staticmethod
    def _version_gt(a: str, b: str) -> bool:
        """True when stable version a is newer than stable version b."""
        ta = Scanner._stable_numeric_version(a)
        tb = Scanner._stable_numeric_version(b)
        if ta is None or tb is None:
            return False
        width = max(len(ta), len(tb))
        ta += (0,) * (width - len(ta))
        tb += (0,) * (width - len(tb))
        return ta > tb

    @staticmethod
    def _max_version(values: list[str]) -> Optional[str]:
        stable = []
        for v in values:
            t = Scanner._stable_numeric_version(v)
            if t is not None:
                stable.append((t, v.lstrip("vV")))
        if not stable:
            return None
        width = max(len(t) for t, _ in stable)
        stable.sort(key=lambda item: item[0] + (0,) * (width - len(item[0])))
        return stable[-1][1]

    def _fetch_cms_releases(self, cms_name: str) -> dict[str, Any]:
        """Fetch stable release information from an official project source.

        This request goes to the CMS vendor/project infrastructure, not to the
        assessed website. Failure is non-fatal and is reported as unverifiable.
        """
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}

        if cms_name == "WordPress":
            url = "https://api.wordpress.org/core/version-check/1.7/?locale=en_US"
            r = self.session.get(url, timeout=TIMEOUT, headers=headers)
            r.raise_for_status()
            data = r.json()
            versions = []
            for offer in data.get("offers", []):
                version = str(offer.get("current") or offer.get("version") or "").strip()
                if version and self._stable_numeric_version(version):
                    versions.append(version)
            return {"versions": sorted(set(versions)), "source": url, "branch_aware": False}

        if cms_name == "Joomla":
            url = "https://api.github.com/repos/joomla/joomla-cms/releases?per_page=50"
            r = self.session.get(url, timeout=TIMEOUT, headers=headers)
            r.raise_for_status()
            versions = []
            for rel in r.json():
                if rel.get("draft") or rel.get("prerelease"):
                    continue
                tag = str(rel.get("tag_name") or "").strip().lstrip("vV")
                if self._stable_numeric_version(tag):
                    versions.append(tag)
            return {"versions": sorted(set(versions)), "source": url, "branch_aware": True}

        if cms_name == "Ghost":
            url = "https://api.github.com/repos/TryGhost/Ghost/releases?per_page=50"
            r = self.session.get(url, timeout=TIMEOUT, headers=headers)
            r.raise_for_status()
            versions = []
            for rel in r.json():
                if rel.get("draft") or rel.get("prerelease"):
                    continue
                tag = str(rel.get("tag_name") or "").strip().lstrip("vV")
                if self._stable_numeric_version(tag):
                    versions.append(tag)
            return {"versions": sorted(set(versions)), "source": url, "branch_aware": False}

        if cms_name == "Drupal":
            # Drupal's official release-history API. 'all' is used because the
            # core 'current' endpoint has historically had intermittent issues.
            url = "https://updates.drupal.org/release-history/drupal/all"
            r = self.session.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            root = ET.fromstring(r.content)
            versions = []
            for node in root.findall(".//release/version"):
                version = (node.text or "").strip().lstrip("vV")
                if self._stable_numeric_version(version):
                    versions.append(version)
            return {"versions": sorted(set(versions)), "source": url, "branch_aware": True}

        return {"versions": [], "source": None, "branch_aware": False}

    def check_cms_currency(self):
        """Compare a confidently disclosed CMS version with current releases.

        The check is informational/passive relative to the assessed site. It
        never probes CMS-specific paths. UPDATE AVAILABLE is WARN/yellow but has
        zero score weight because 'not latest' is not equivalent to vulnerable.
        """
        cms = (self.http.get("cms") or {})
        name = cms.get("name")
        detected = cms.get("version")
        confidence = cms.get("confidence")

        currency = {
            "checked": False,
            "cms": name,
            "detected_version": detected,
            "latest_version": None,
            "latest_same_major": None,
            "status": "not_checked",
            "source": None,
        }

        supported = {"WordPress", "Joomla", "Drupal", "Ghost"}
        if not name or name not in supported:
            cms["currency"] = currency
            return
        if not detected or confidence != "high" or self._stable_numeric_version(detected) is None:
            currency["status"] = "version_not_reliably_disclosed"
            cms["currency"] = currency
            self.add_check(
                "Web", "CMS update status", "unknown",
                f"Wykryto {name}, ale wersja nie jest wystarczająco wiarygodna do porównania z aktualnym wydaniem.",
                0, 0, False
            )
            return

        try:
            release_data = self._fetch_cms_releases(name)
            versions = release_data.get("versions", [])
            latest = self._max_version(versions)
            source = release_data.get("source")
            branch_aware = bool(release_data.get("branch_aware"))
            currency.update({"checked": True, "latest_version": latest, "source": source})

            det_tuple = self._stable_numeric_version(detected)
            detected_major = det_tuple[0] if det_tuple else None
            same_major = []
            for v in versions:
                vt = self._stable_numeric_version(v)
                if vt and detected_major is not None and vt[0] == detected_major:
                    same_major.append(v)
            latest_same_major = self._max_version(same_major)
            currency["latest_same_major"] = latest_same_major

            if not latest:
                raise RuntimeError("official release source returned no stable versions")

            # Joomla/Drupal can have multiple maintained majors. Prefer a same-major
            # patch/minor comparison, while still noting a newer major separately.
            if branch_aware and latest_same_major:
                if self._version_gt(latest_same_major, detected):
                    currency["status"] = "update_available"
                    self.add_check(
                        "Web", "CMS update available", "warn",
                        f"{name} {detected} wykryty; nowsza stabilna wersja w tej samej gałęzi to {latest_same_major}. "
                        f"Zalecana weryfikacja kompatybilności i aktualizacja.",
                        0, 0, False
                    )
                else:
                    currency["status"] = "current_branch"
                    msg = f"{name} {detected} jest aktualny w wykrytej głównej gałęzi ({latest_same_major})."
                    if latest and self._version_gt(latest, detected):
                        msg += f" Dostępna jest również nowsza główna wersja {latest}; migrację należy ocenić osobno."
                    self.add_check("Web", "CMS update status", "pass", msg, 0, 0, False)
            else:
                if self._version_gt(latest, detected):
                    currency["status"] = "update_available"
                    self.add_check(
                        "Web", "CMS update available", "warn",
                        f"{name} {detected} wykryty; najnowsza stabilna wersja to {latest}. "
                        f"Zalecana weryfikacja kompatybilności i aktualizacja.",
                        0, 0, False
                    )
                else:
                    currency["status"] = "current"
                    self.add_check(
                        "Web", "CMS update status", "pass",
                        f"{name} {detected} odpowiada najnowszej stabilnej wersji {latest}.",
                        0, 0, False
                    )

        except Exception as e:
            currency["status"] = "lookup_failed"
            currency["error"] = str(e)
            self.add_check(
                "Web", "CMS update status", "unknown",
                f"Nie udało się sprawdzić aktualnej wersji {name} w oficjalnym źródle: {e}",
                0, 0, False
            )

        cms["currency"] = currency
        self.http["cms"] = cms

    # ---------------- orchestration / scoring ----------------

    def run(self):
        self.rdap_lookup()
        self.collect_dns()
        self.discover_ct_subdomains()
        self.crawl()
        self.collect_subdomain_dns()
        self.check_tls()
        self.check_http()
        self.check_cms_currency()

    def score(self):
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
        return {
            "score": value,
            "label": label,
            "earned_points": round(earned, 1),
            "possible_points": round(possible, 1),
        }

    def to_dict(self):
        return {
            "domain": self.target_domain,
            "target_domain": self.target_domain,
            "root_domain": self.root_domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner_version": __version__,
            "score": self.score(),
            "checks": [asdict(c) for c in self.checks],
            "rdap": self.rdap,
            "mail": self.mail,
            "tls": self.tls,
            "http": self.http,
            "subdomains": sorted(self.subdomains),
            "emails": sorted(self.emails),
            "dns_records": self.dns_records,
            "limitations": [
                "To jest zewnętrzny, niskoinwazyjny health check, a nie pełny pentest.",
                "Brak wyniku DKIM dla popularnych selektorów nie oznacza braku DKIM.",
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


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.split("/")[0].strip(".")
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,63}", value):
        raise ValueError(f"Nieprawidłowa domena: {value}")
    return value



# Fallback only. RDAP walking above is the preferred way to identify the
# registered domain because "last two labels" is wrong for suffixes such as
# co.uk or com.pl. This list covers common multi-label public suffixes when
# RDAP is temporarily unavailable.
COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
    "com.pl", "net.pl", "org.pl", "biz.pl", "info.pl",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr",
}

def fallback_root_domain(host: str) -> str:
    host = normalize_domain(host)
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in COMMON_MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def is_in_scope_host(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def days_until(value: str) -> Optional[int]:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None


# ---------------- PDF ----------------


def register_pdf_fonts() -> tuple[str, str]:
    """Register a Unicode TTF font so Polish characters render correctly.

    Uses fonts already installed on the host OS; no font files are distributed.
    Windows normally resolves to Arial, Linux to DejaVu Sans.
    """
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        (windir / "Fonts" / "arial.ttf", windir / "Fonts" / "arialbd.ttf"),
        (windir / "Fonts" / "calibri.ttf", windir / "Fonts" / "calibrib.ttf"),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
         Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
        (Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
         Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf")),
        (Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
         Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf")),
        (Path("/Library/Fonts/Arial.ttf"), Path("/Library/Fonts/Arial Bold.ttf")),
    ]
    for regular, bold in candidates:
        if regular.exists():
            pdfmetrics.registerFont(TTFont("LocalUnicode", str(regular)))
            if bold.exists():
                pdfmetrics.registerFont(TTFont("LocalUnicode-Bold", str(bold)))
            else:
                pdfmetrics.registerFont(TTFont("LocalUnicode-Bold", str(regular)))
            return "LocalUnicode", "LocalUnicode-Bold"
    # Last-resort fallback. PDF still builds, but non-Latin glyph coverage depends
    # on the base font. A warning is emitted for diagnostics.
    print("[!] Unicode TTF font not found; PDF may not render Polish characters correctly.", file=sys.stderr)
    return "Helvetica", "Helvetica-Bold"

def p(text: Any) -> str:
    text = str(text if text is not None else "")
    text = text.replace("—", "-").replace("–", "-").replace("→", "->")
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )


def _status_palette(status: str):
    palettes = {
        "fail": (colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B"), colors.HexColor("#DC2626")),
        "warn": (colors.HexColor("#FEF3C7"), colors.HexColor("#92400E"), colors.HexColor("#D97706")),
        "pass": (colors.HexColor("#DCFCE7"), colors.HexColor("#166534"), colors.HexColor("#16A34A")),
        "info": (colors.HexColor("#DBEAFE"), colors.HexColor("#1E40AF"), colors.HexColor("#2563EB")),
        "unknown": (colors.HexColor("#F3F4F6"), colors.HexColor("#4B5563"), colors.HexColor("#6B7280")),
    }
    return palettes.get(status, palettes["unknown"])


def _score_palette(score: int):
    if score >= 90:
        return colors.HexColor("#DCFCE7"), colors.HexColor("#166534"), "Strong"
    if score >= 75:
        return colors.HexColor("#ECFDF5"), colors.HexColor("#047857"), "Good"
    if score >= 60:
        return colors.HexColor("#FEF3C7"), colors.HexColor("#92400E"), "Needs improvement"
    return colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B"), "Priority remediation"


def _recommendation(check: dict[str, Any]) -> str:
    name = str(check.get("name", "")).lower()
    status = str(check.get("status", "unknown"))
    if status == "pass":
        return "No action required."
    mapping = [
        ("spf duplicate", "Publish exactly one SPF record for the domain."),
        ("spf dns lookup", "Reduce nested include/a/mx/exists/redirect lookups so worst-case SPF evaluation stays below the 10-query limit."),
        ("spf syntax", "Correct the SPF syntax, then re-test the record."),
        ("dmarc syntax", "Correct the DMARC record syntax and keep a single valid policy record."),
        ("dmarc", "Publish/strengthen DMARC and move toward quarantine/reject after validation."),
        ("spf", "Review authorized mail senders and publish a valid SPF policy."),
        ("dkim", "Confirm the mail provider's DKIM selector and enable DKIM signing if needed."),
        ("dnssec", "Enable DNSSEC at the DNS provider/registrar and verify the DS delegation."),
        ("transfer lock", "Enable registrar/registry transfer protection where available."),
        ("domain expiry", "Renew the domain and consider auto-renewal with a monitored payment method."),
        ("caa", "Publish CAA records for the certificate authorities you actually use."),
        ("mta-sts", "Consider MTA-STS after confirming the mail flow and MX configuration."),
        ("tls-rpt", "Add TLS-RPT reporting if mail transport monitoring is desired."),
        ("hsts", "Enable HSTS after confirming HTTPS works correctly across the site."),
        ("csp", "Deploy a tested Content-Security-Policy appropriate for the application."),
        ("x-content-type", "Send X-Content-Type-Options: nosniff."),
        ("frame protection", "Add CSP frame-ancestors or X-Frame-Options where appropriate."),
        ("referrer", "Set a suitable Referrer-Policy."),
        ("permissions", "Set a Permissions-Policy that disables browser capabilities not required by the site."),
        ("http -> https", "Redirect all HTTP traffic to HTTPS."),
        ("https", "Repair HTTPS/TLS configuration and certificate validation."),
        ("tls certificate", "Renew/replace the TLS certificate and verify the full chain."),
        ("rdap", "Verify registrar and registration details manually if automated RDAP lookup is unavailable."),
        ("cookie security", "Set Secure and HttpOnly on session/authentication cookies and choose an appropriate SameSite policy."),
        ("mixed content", "Replace http:// asset/form references with HTTPS or remove them."),
        ("legacy tls", "Disable TLS 1.0/1.1 and retain modern TLS versions supported by your clients."),
        ("server version disclosure", "Remove unnecessary detailed software versions from Server/X-Powered-By style response headers."),
        ("name server", "Use redundant authoritative DNS servers/providers as appropriate."),
    ]
    for needle, action in mapping:
        if needle in name:
            return action
    if status == "fail":
        return "Review and remediate this finding as a priority."
    if status == "warn":
        return "Review the configuration and apply the recommended hardening where appropriate."
    return "Verify manually; the external scan could not determine this reliably."



def _impact(check: dict[str, Any]) -> str:
    """Short, customer-facing explanation of why a WARN/FAIL matters.

    The wording intentionally describes exposure/risk without claiming that
    exploitation or compromise has occurred.
    """
    name = str(check.get("name", "")).lower()
    message = str(check.get("message", "")).lower()

    mapping = [
        ("spf duplicate", "Multiple SPF records can cause SPF PermError, reducing the reliability of anti-spoofing checks."),
        ("spf dns lookup", "SPF evaluation is limited to 10 DNS-querying terms; exceeding it can produce PermError and weaken mail authentication."),
        ("spf syntax", "Invalid SPF syntax can cause receivers to treat the policy as an error instead of authenticating expected senders."),
        ("dmarc syntax", "An invalid or ambiguous DMARC record can prevent receivers from applying your intended anti-spoofing policy."),
        ("dmarc", "Weak or missing DMARC can make it easier for attackers to impersonate your domain in phishing emails."),
        ("spf", "A missing or overly permissive SPF policy can make forged email claiming to come from your domain harder for receivers to reject."),
        ("dkim", "Without confirmed DKIM signing, recipients have less cryptographic assurance that a message genuinely came from your mail system and was not altered in transit."),
        ("dnssec", "Without DNSSEC, DNS answers are not cryptographically validated, reducing protection against forged or tampered DNS responses."),
        ("transfer lock", "Without strong transfer protection, a compromised registrar account may have fewer barriers against unauthorized domain transfer."),
        ("domain expiry", "An expired domain can interrupt the website and email and, if lost, may allow another party to register it."),
        ("caa", "CAA limits which certificate authorities may issue certificates for your domain. Without it, you have less control over certificate issuance policy."),
        ("mta-sts", "Without MTA-STS, mail servers have less protection against downgrade or interception of SMTP transport where both sides support the mechanism."),
        ("tls-rpt", "Without TLS-RPT, failures in secure mail transport are harder to observe and investigate."),
        ("hsts", "Without HSTS, a user's first connection can be more exposed to HTTPS downgrade or SSL-stripping scenarios on hostile networks."),
        ("csp", "A strong Content-Security-Policy can reduce the impact of cross-site scripting and injected third-party content. Without it, the browser has fewer restrictions on what may execute."),
        ("x-content-type", "Without nosniff, some browsers may try to interpret a resource as a different content type, increasing exposure to content-type confusion attacks."),
        ("frame protection", "Without frame restrictions, the site may be embedded in another page and can be more exposed to clickjacking-style attacks."),
        ("referrer", "Without an explicit Referrer-Policy, URLs or path information may be shared with third-party sites more broadly than intended."),
        ("permissions", "Without Permissions-Policy, browser capabilities such as camera, microphone, geolocation or other features are not explicitly restricted by this header."),
        ("http -> https", "If HTTP is not consistently redirected to HTTPS, users can reach an unencrypted entry point and become more exposed to interception or downgrade."),
        ("https", "Broken HTTPS can prevent users from establishing an authenticated, encrypted connection to the site."),
        ("tls certificate", "An invalid or expiring certificate can cause browser warnings or outages and undermine trust in the encrypted connection."),
        ("name server", "Insufficient DNS redundancy can make the domain more dependent on a single DNS failure."),
        ("cms update", "Running an older CMS release may leave known bug fixes and security hardening unapplied. An update should be reviewed and tested before deployment."),
        ("cookie security", "Missing cookie protections can make session or authentication cookies easier to expose through insecure transport or client-side script compromise."),
        ("mixed content", "HTTP resources inside an HTTPS page can be blocked, observed, or modified in transit and weaken the page's transport-security posture."),
        ("legacy tls", "TLS 1.0/1.1 are obsolete protocols with weaker security properties and broader compatibility with legacy cryptography."),
        ("server version disclosure", "Exact software versions give attackers additional fingerprinting information that can help prioritize version-specific attacks."),
        ("application response", "A server-side error can make the website unavailable and may indicate a failed upstream service, reverse proxy, or application dependency."),
    ]

    for key, value in mapping:
        if key in name:
            return value

    # Message-aware fallback for CMS currency checks.
    if "update available" in message or "latest" in message and "detected" in message:
        return "An older CMS release may be missing bug fixes and security hardening available in the current maintained release."

    status = str(check.get("status", "")).lower()
    if status == "fail":
        return "This finding can materially affect availability, confidentiality, integrity, or trust and should be reviewed promptly."
    if status == "warn":
        return "This is a hardening gap or configuration weakness that can increase exposure in some attack scenarios."
    return ""


def _technical_status(label: str, value: Any, report: dict[str, Any]) -> str:
    """Map Web/TLS detail rows to a display status."""
    key = label.lower()
    http = report.get("http", {}) or {}
    tls = report.get("tls", {}) or {}
    cms = http.get("cms", {}) or {}
    currency = cms.get("currency", {}) or {}

    if key == "cms / platform":
        return "info" if cms.get("detected") else "unknown"

    if key in ("cms latest stable", "cms update status"):
        state = str(currency.get("status") or "").lower()
        if state in ("current", "current_branch"):
            return "pass"
        if state in ("update_available", "update available"):
            return "warn"
        return "unknown"

    if key == "tls protocol":
        proto = str(tls.get("protocol") or "").upper()
        if proto in ("TLSV1.3", "TLSV1.2", "TLS1.3", "TLS1.2"):
            return "pass"
        if proto:
            return "warn"
        return "unknown"

    if key == "tls cipher":
        return "pass" if tls.get("cipher") else "unknown"

    if key == "certificate expires in":
        days = tls.get("expiry_days")
        if isinstance(days, int):
            if days < 7:
                return "fail"
            if days < 30:
                return "warn"
            return "pass"
        return "unknown"

    if key == "https final url":
        return "info"

    if key == "https status":
        status = http.get("https_status")
        try:
            status = int(status)
        except (TypeError, ValueError):
            return "unknown"
        if 200 <= status < 400:
            return "pass"
        if 400 <= status < 500:
            return "warn"
        if status >= 500:
            return "fail"
        return "unknown"

    if key == "security.txt":
        return "pass" if http.get("security_txt") else "info"

    if key == "cms evidence":
        return "info" if cms.get("signals") else "unknown"

    if key in ("tls 1.0", "tls 1.1"):
        # Exact dictionary keys are title case (TLS 1.0 / TLS 1.1).
        lookup_label = "TLS 1.0" if key == "tls 1.0" else "TLS 1.1"
        state = (tls.get("protocol_support", {}).get(lookup_label, {}) or {}).get("status")
        if state == "supported":
            return "warn"
        if state == "not_supported":
            return "pass"
        return "unknown"

    if key == "mixed content":
        return "warn" if http.get("mixed_content") else "pass"

    if key == "cookie security flags":
        cookies = http.get("cookies", {}) or {}
        if cookies.get("warning_count", 0):
            return "warn"
        if cookies.get("sensitive_count", 0):
            return "pass"
        return "info"

    if key == "server/version disclosure":
        disclosure = http.get("server_disclosure", {}) or {}
        if disclosure.get("exact_version"):
            return "warn"
        return "info" if disclosure.get("headers") else "pass"

    return "info"


def generate_pdf(report: dict[str, Any], output: Path):
    regular_font, bold_font = register_pdf_fonts()
    styles = getSampleStyleSheet()
    for style_name in ("Title", "Heading1", "Heading2", "Heading3", "BodyText", "Normal"):
        if style_name in styles:
            styles[style_name].fontName = regular_font
    styles["Title"].fontName = bold_font
    styles["Heading1"].fontName = bold_font
    styles["Heading2"].fontName = bold_font
    styles["Heading3"].fontName = bold_font
    styles.add(ParagraphStyle(
        name="CenterTitle",
        parent=styles["Title"],
        fontName=bold_font,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155"),
    ))
    styles.add(ParagraphStyle(
        name="Tiny",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#475569"),
    ))
    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        fontName=bold_font,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6,
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.setLineWidth(0.4)
        canvas.line(14*mm, 10*mm, A4[0]-14*mm, 10*mm)
        canvas.setFont(regular_font, 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(14*mm, 6.5*mm, "© 2026 Jarosław Zadorożny | External Security Hygiene Report")
        canvas.drawRightString(A4[0]-14*mm, 6.5*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=14*mm, leftMargin=14*mm,
        topMargin=14*mm, bottomMargin=16*mm,
        title=f"External Security Hygiene - {report['target_domain']}",
        author="Jarosław Zadorożny",
        subject="External Security Hygiene Report",
    )
    story = []

    score = report["score"]
    score_value = int(score["score"])
    score_bg, score_fg, score_label = _score_palette(score_value)
    checks = report.get("checks", [])
    counts = {s: sum(1 for c in checks if c.get("status") == s) for s in ("fail", "warn", "pass", "info", "unknown")}

    story.append(Paragraph("External Security Hygiene Report", styles["CenterTitle"]))
    story.append(Paragraph(f"<b>{p(report['target_domain'])}</b>", ParagraphStyle(
        "Target", parent=styles["Heading2"], fontName=bold_font, alignment=TA_CENTER,
        textColor=colors.HexColor("#1E293B"), spaceAfter=8
    )))

    # Score banner + customer-friendly status counters.
    score_box = Table([
        [Paragraph(f"<b>{score_value}/100</b><br/><font size='9'>{p(score_label)}</font>", ParagraphStyle(
            "Score", parent=styles["BodyText"], fontName=bold_font, alignment=TA_CENTER,
            textColor=score_fg, fontSize=22, leading=24
        ))]
    ], colWidths=[58*mm], rowHeights=[28*mm])
    score_box.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), score_bg),
        ("BOX", (0,0), (-1,-1), 1.2, score_fg),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]))

    counter_cells = []
    for status, label in (("fail", "ACTION"), ("warn", "REVIEW"), ("pass", "OK"), ("unknown", "VERIFY")):
        bg, fg, border = _status_palette(status)
        cell = Table([[Paragraph(
            f"<b>{counts[status]}</b><br/><font size='7'>{label}</font>",
            ParagraphStyle(f"Counter-{status}", parent=styles["Small"], fontName=bold_font,
                           alignment=TA_CENTER, textColor=fg, fontSize=14, leading=15)
        )]], colWidths=[27*mm], rowHeights=[13*mm])
        cell.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), bg),
            ("BOX", (0,0), (-1,-1), 0.8, border),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        counter_cells.append(cell)

    counters = Table([counter_cells[:2], counter_cells[2:]], colWidths=[29*mm,29*mm], rowHeights=[14*mm,14*mm])
    counters.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "MIDDLE")]))

    overview = Table([[score_box, counters]], colWidths=[64*mm, 62*mm], hAlign="CENTER")
    overview.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 2),
        ("RIGHTPADDING", (0,0), (-1,-1), 2),
    ]))
    story.append(overview)
    story.append(Spacer(1, 8))

    meta = Table([
        ["Web host", report.get("target_domain", "n/a"), "Root / mail domain", report.get("root_domain", "n/a")],
        ["Generated", report.get("generated_at", "n/a"), "Assessment type", "External / low-impact"],
    ], colWidths=[25*mm, 62*mm, 30*mm, 61*mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (2,0), (2,-1), colors.HexColor("#F1F5F9")),
        ("FONTNAME", (0,0), (-1,-1), regular_font),
        ("FONTNAME", (0,0), (0,-1), bold_font),
        ("FONTNAME", (2,0), (2,-1), bold_font),
        ("FONTSIZE", (0,0), (-1,-1), 7.5),
        ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor("#334155")),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(meta)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>How to read this report:</b> red findings should be reviewed first, amber findings are recommended improvements, "
        "green findings passed the external check, and grey findings require manual verification. "
        "This is a security-hygiene snapshot, not a penetration test or guarantee of security.",
        styles["Small"]
    ))

    # Customer-focused priority summary.
    priorities = [c for c in checks if c.get("status") in ("fail", "warn")]
    order = {"fail": 0, "warn": 1}
    priorities = sorted(priorities, key=lambda x: (order.get(x.get("status"), 9), x.get("category", ""), x.get("name", "")))[:6]
    story.append(Paragraph("Top priorities", styles["Section"]))
    if priorities:
        pr_rows = [["Status", "Issue", "Finding / why it matters", "Recommended action"]]
        for c in priorities:
            pr_rows.append([
                c["status"].upper(),
                Paragraph(f"<b>{p(c['name'])}</b><br/><font size='7'>{p(c.get('category',''))}</font>", styles["Small"]),
                Paragraph(
                    f"<b>Finding:</b> {p(c['message'])}<br/><b>Why it matters:</b> {p(_impact(c))}",
                    styles["Small"]
                ),
                Paragraph(p(_recommendation(c)), styles["Small"]),
            ])
        pr_table = Table(pr_rows, colWidths=[18*mm, 34*mm, 64*mm, 62*mm], repeatRows=1)
        pr_style = [
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), bold_font),
            ("FONTNAME", (0,1), (-1,-1), regular_font),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]
        for idx, c in enumerate(priorities, start=1):
            bg, fg, border = _status_palette(c["status"])
            pr_style += [
                ("BACKGROUND", (0,idx), (0,idx), bg),
                ("TEXTCOLOR", (0,idx), (0,idx), fg),
                ("FONTNAME", (0,idx), (0,idx), bold_font),
                ("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFFBEB") if c["status"] == "warn" else colors.HexColor("#FFF7F7")),
            ]
        pr_table.setStyle(TableStyle(pr_style))
        story.append(pr_table)
    else:
        story.append(Paragraph("No red or amber findings were detected in the external checks.", styles["Small"]))

    # Full findings table with colored status and subtle row background.
    story.append(Paragraph("All findings", styles["Section"]))
    rows = [["Status", "Area", "Check", "Result"]]
    sort_order = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "pass": 4}
    sorted_checks = sorted(checks, key=lambda x: (sort_order.get(x["status"], 9), x["category"], x["name"]))
    for c in sorted_checks:
        result_text = p(c["message"])
        if c.get("status") in ("fail", "warn"):
            impact = _impact(c)
            if impact:
                result_text += f"<br/><font size='7'><b>Why it matters:</b> {p(impact)}</font>"
        rows.append([
            c["status"].upper(), c["category"], c["name"], Paragraph(result_text, styles["Small"])
        ])
    table = Table(rows, colWidths=[20*mm, 24*mm, 38*mm, 94*mm], repeatRows=1)
    table_style = [
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), bold_font),
        ("FONTNAME", (0,1), (-1,-1), regular_font),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#CBD5E1")),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]
    for idx, c in enumerate(sorted_checks, start=1):
        bg, fg, border = _status_palette(c["status"])
        table_style += [
            ("BACKGROUND", (0,idx), (0,idx), bg),
            ("TEXTCOLOR", (0,idx), (0,idx), fg),
            ("FONTNAME", (0,idx), (0,idx), bold_font),
        ]
        if c["status"] == "pass":
            table_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#F8FFF9")))
        elif c["status"] == "fail":
            table_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFF9F9")))
        elif c["status"] == "warn":
            table_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFFCF5")))
    table.setStyle(TableStyle(table_style))
    story.append(table)

    # Technical detail sections.
    story.append(Paragraph("Domain / RDAP", styles["Section"]))
    rdap = report.get("rdap", {})
    domain_rows = [
        ["Web host", report.get("target_domain", report.get("domain"))],
        ["Registered/root domain", report.get("root_domain", "n/a")],
        ["RDAP source", rdap.get("url", "n/a")],
        ["Registrar", rdap.get("registrar", "n/a")],
        ["Nameservers", ", ".join(rdap.get("nameservers", [])) or "n/a"],
        ["Statuses", ", ".join(rdap.get("status", [])) or "n/a"],
        ["Transfer lock", rdap.get("transfer_lock", "unknown")],
        ["NASK state", rdap.get("nask0_state", "n/a")],
    ]
    t = Table([[Paragraph(f"<b>{p(a)}</b>", styles["Small"]), Paragraph(p(b), styles["Small"])] for a,b in domain_rows],
              colWidths=[40*mm, 138*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F8FAFC")),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTNAME",(0,0),(-1,-1),regular_font),
    ]))
    story.append(t)

    story.append(Paragraph(f"Mail security - {p(report.get('root_domain', ''))}", styles["Section"]))
    mail = report.get("mail", {})
    spf_analysis = mail.get("spf_analysis", {}) or {}
    spf_dns = spf_analysis.get("dns_lookups", {}) or {}
    dmarc_analysis = mail.get("dmarc_analysis", {}) or {}
    mail_rows = [
        ["MX", "<br/>".join(p(x) for x in mail.get("mx", [])) or "n/a"],
        ["SPF", "<br/>".join(p(x) for x in mail.get("spf", [])) or "not detected"],
        ["SPF record count", spf_analysis.get("record_count", "n/a")],
        ["SPF syntax", "valid" if (spf_analysis.get("syntax", {}) or {}).get("valid") else ("invalid" if spf_analysis.get("syntax") else "n/a")],
        ["SPF DNS lookup estimate", f"{spf_dns.get('count')}/10" if spf_dns.get("count") is not None else "n/a"],
        ["DMARC", "<br/>".join(p(x) for x in mail.get("dmarc", [])) or "not detected"],
        ["DMARC policy", p(mail.get("dmarc_policy", "n/a"))],
        ["DMARC subdomain policy", dmarc_analysis.get("subdomain_policy", "n/a")],
        ["DMARC pct", dmarc_analysis.get("pct", "n/a")],
        ["DMARC aggregate reports (rua)", ", ".join(dmarc_analysis.get("rua", [])) or "not configured"],
        ["DMARC alignment", f"DKIM={dmarc_analysis.get('adkim','n/a')} / SPF={dmarc_analysis.get('aspf','n/a')}"],
        ["DKIM selectors found", ", ".join(mail.get("dkim_common_selectors", {}).keys()) or "not confirmed"],
        ["MTA-STS", "detected" if mail.get("mta_sts_dns") or mail.get("mta_sts_policy") else "not detected"],
        ["TLS-RPT", "<br/>".join(p(x) for x in mail.get("tls_rpt", [])) or "not detected"],
    ]
    t = Table([[Paragraph(f"<b>{p(a)}</b>", styles["Small"]), Paragraph(str(b), styles["Small"])] for a,b in mail_rows],
              colWidths=[40*mm, 138*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F8FAFC")),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTNAME",(0,0),(-1,-1),regular_font),
    ]))
    story.append(t)

    story.append(Paragraph("Web / TLS", styles["Section"]))
    tls = report.get("tls", {})
    http = report.get("http", {})
    cms = http.get("cms", {}) or {}
    cms_name = cms.get("name") or "not reliably detected"
    cms_version = cms.get("version") or "not disclosed"
    cms_confidence = cms.get("confidence") or "none"
    cms_display = f"{cms_name} | version: {cms_version} | confidence: {cms_confidence}"
    currency = cms.get("currency", {}) or {}
    latest_display = currency.get("latest_same_major") or currency.get("latest_version") or "not checked"
    currency_status = str(currency.get("status") or "not checked").replace("_", " ")

    web_rows = [
        ["CMS / platform", cms_display],
        ["CMS latest stable", latest_display],
        ["CMS update status", currency_status],
        ["TLS protocol", tls.get("protocol", "n/a")],
        ["TLS cipher", tls.get("cipher", "n/a")],
        ["TLS 1.0", (tls.get("protocol_support", {}).get("TLS 1.0", {}) or {}).get("status", "not checked")],
        ["TLS 1.1", (tls.get("protocol_support", {}).get("TLS 1.1", {}) or {}).get("status", "not checked")],
        ["Certificate expires in", f"{tls.get('expiry_days')} days" if tls.get("expiry_days") is not None else "n/a"],
        ["HTTPS final URL", http.get("final_url", "n/a")],
        ["HTTPS status", http.get("https_status", "n/a")],
        ["Mixed content", f"{len(http.get('mixed_content', []))} insecure reference(s)" if http.get("mixed_content") else "none detected"],
        ["Cookie security flags", f"{(http.get('cookies', {}) or {}).get('sensitive_count', 0)} sensitive / {(http.get('cookies', {}) or {}).get('warning_count', 0)} warning(s)"],
        ["Server/version disclosure", ", ".join(f"{k}: {v}" for k, v in (http.get("server_disclosure", {}).get("headers", {}) or {}).items()) or "none detected"],
        ["security.txt", "yes" if http.get("security_txt") else "no / unknown"],
        ["CMS evidence", "; ".join(cms.get("signals", [])[:5]) or "n/a"],
    ]

    web_detail_rows = [["Status", "Item", "Value"]]
    web_detail_statuses = []
    for label, value in web_rows:
        display_status = _technical_status(label, value, report)
        web_detail_statuses.append(display_status)
        status_label = {
            "pass": "OK",
            "warn": "REVIEW",
            "fail": "ACTION",
            "info": "INFO",
            "unknown": "VERIFY",
        }.get(display_status, display_status.upper())
        web_detail_rows.append([
            status_label,
            Paragraph(f"<b>{p(label)}</b>", styles["Small"]),
            Paragraph(p(value), styles["Small"]),
        ])

    t = Table(web_detail_rows, colWidths=[22*mm, 44*mm, 112*mm], repeatRows=1)
    web_style = [
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0F172A")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),bold_font),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTNAME",(0,1),(-1,-1),regular_font),
        ("FONTSIZE",(0,0),(-1,-1),7),
        ("LEFTPADDING",(0,0),(-1,-1),4),
        ("RIGHTPADDING",(0,0),(-1,-1),4),
        ("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]
    for idx, display_status in enumerate(web_detail_statuses, start=1):
        bg, fg, border = _status_palette(display_status)
        web_style += [
            ("BACKGROUND", (0,idx), (0,idx), bg),
            ("TEXTCOLOR", (0,idx), (0,idx), fg),
            ("FONTNAME", (0,idx), (0,idx), bold_font),
            ("BACKGROUND", (1,idx), (1,idx), colors.HexColor("#F8FAFC")),
        ]
        # Give status-sensitive rows a subtle whole-row tint.
        if display_status == "pass":
            web_style.append(("BACKGROUND", (2,idx), (2,idx), colors.HexColor("#F0FDF4")))
        elif display_status == "warn":
            web_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FFFBEB")))
        elif display_status == "fail":
            web_style.append(("BACKGROUND", (1,idx), (-1,idx), colors.HexColor("#FEF2F2")))
        elif display_status == "unknown":
            web_style.append(("BACKGROUND", (2,idx), (2,idx), colors.HexColor("#F9FAFB")))
    t.setStyle(TableStyle(web_style))
    story.append(t)

    story.append(PageBreak())
    story.append(Paragraph("External inventory", styles["Section"]))
    story.append(Paragraph(
        f"<b>Subdomains / hosts discovered:</b> {len(report.get('subdomains', []))}",
        styles["BodyText"]
    ))
    host_rows = [["Host"]] + [[host] for host in report.get("subdomains", [])]
    ht = Table(host_rows, colWidths=[178*mm], repeatRows=1)
    ht.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0F172A")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),bold_font),
        ("FONTNAME",(0,1),(-1,-1),regular_font),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
        ("FONTSIZE",(0,0),(-1,-1),7)
    ]))
    story.append(ht)

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<b>Public email addresses discovered on crawled pages:</b> {len(report.get('emails', []))}",
        styles["BodyText"]
    ))
    if report.get("emails"):
        story.append(Paragraph("<br/>".join(p(x) for x in report["emails"]), styles["Small"]))
    else:
        story.append(Paragraph("None found.", styles["Small"]))

    story.append(Paragraph("DNS appendix", styles["Section"]))
    for host, records in report.get("dns_records", {}).items():
        block = [Paragraph(f"<b>{p(host)}</b>", styles["BodyText"])]
        dns_rows = [["Type", "Value"]]
        for rtype, values in records.items():
            if values:
                dns_rows.append([rtype, Paragraph("<br/>".join(p(v) for v in values), styles["Small"])])
        if len(dns_rows) == 1:
            dns_rows.append(["-", "No records collected"])
        dt = Table(dns_rows, colWidths=[22*mm, 156*mm], repeatRows=1)
        dt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E2E8F0")),
            ("FONTNAME",(0,0),(-1,0),bold_font),
            ("FONTNAME",(0,1),(-1,-1),regular_font),
            ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("FONTSIZE",(0,0),(-1,-1),7)
        ]))
        block += [dt, Spacer(1, 6)]
        story.append(KeepTogether(block))

    story.append(Paragraph("Limitations", styles["Section"]))
    for item in report.get("limitations", []):
        story.append(Paragraph("- " + p(item), styles["Small"]))

    story.append(Spacer(1, 10))
    legal = Table([[Paragraph(
        "<b>Report ownership:</b> © 2026 Jarosław Zadorożny. "
        "The scanner software is licensed for non-commercial use only; see the accompanying LICENSE file. "
        "This report may be shared with the assessed organization for remediation purposes.", styles["Tiny"]
    )]], colWidths=[178*mm])
    legal.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(legal)

    doc.build(story, onFirstPage=footer, onLaterPages=footer)

def main():
    parser = argparse.ArgumentParser(
        description="Low-impact external domain security hygiene scanner."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Domain Security Scanner {__version__}",
    )
    parser.add_argument("domain", help="Domena, np. example.pl")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Potwierdzam, że mam zgodę na ocenę tej domeny."
    )
    parser.add_argument("--max-pages", type=int, default=20, choices=range(1, 101))
    parser.add_argument("--max-hosts", type=int, default=25, choices=range(1, 101))
    parser.add_argument("--out", default=None, help="Prefiks plików wyjściowych")
    args = parser.parse_args()

    if not args.authorized:
        print(
            "Refusing to scan without --authorized. "
            "Run only against domains you own or have explicit permission to assess.",
            file=sys.stderr,
        )
        return 2

    try:
        scanner = Scanner(args.domain, max_pages=args.max_pages, max_hosts=args.max_hosts)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    print(f"[+] Web target: {scanner.target_domain}")
    scanner.run()
    print(f"[+] Root/mail domain: {scanner.root_domain}")
    report = scanner.to_dict()

    prefix = args.out or f"security-report-{scanner.target_domain}"
    json_path = Path(prefix + ".json")
    pdf_path = Path(prefix + ".pdf")

    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    generate_pdf(report, pdf_path)

    print(f"[+] Score: {report['score']['score']}/100 ({report['score']['label']})")
    print(f"[+] JSON: {json_path}")
    print(f"[+] PDF:  {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
