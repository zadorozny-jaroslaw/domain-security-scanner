from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

import dns.exception
import dns.resolver

from .constants import COMMON_DKIM_SELECTORS, COMMON_DNS_TYPES, TIMEOUT
from .models import DnsQueryResult, DnsQueryState


class DnsMailMixin:
    """DNS inventory and mail-security checks."""

    def dns_query_result(self, host: str, rtype: str) -> DnsQueryResult:
        """Return cached DNS evidence while preserving absence vs resolver failure."""
        host_key = host.lower().rstrip(".")
        rtype_key = rtype.upper()
        cache_key = (host_key, rtype_key)
        cached = self.dns_query_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            ans = self.resolver.resolve(host_key, rtype_key, raise_on_no_answer=False)
            if ans.rrset is None:
                result = DnsQueryResult(host_key, rtype_key, DnsQueryState.NO_ANSWER)
            else:
                result = DnsQueryResult(
                    host_key,
                    rtype_key,
                    DnsQueryState.ANSWER,
                    tuple(r.to_text() for r in ans),
                )
        except dns.resolver.NXDOMAIN:
            result = DnsQueryResult(host_key, rtype_key, DnsQueryState.NXDOMAIN)
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            result = DnsQueryResult(host_key, rtype_key, DnsQueryState.TIMEOUT, error=str(exc))
        except dns.resolver.NoNameservers as exc:
            state = DnsQueryState.SERVFAIL if "SERVFAIL" in str(exc).upper() else DnsQueryState.ERROR
            result = DnsQueryResult(host_key, rtype_key, state, error=str(exc))
        except Exception as exc:
            result = DnsQueryResult(host_key, rtype_key, DnsQueryState.ERROR, error=str(exc))

        self.dns_query_cache[cache_key] = result
        return result

    def dns_query(self, host: str, rtype: str) -> list[str]:
        """Compatibility wrapper returning only records for inventory/report output."""
        return list(self.dns_query_result(host, rtype).records)

    @staticmethod
    def _dns_unavailable_message(result: DnsQueryResult) -> str:
        labels = {
            DnsQueryState.TIMEOUT: "timeout",
            DnsQueryState.SERVFAIL: "SERVFAIL",
            DnsQueryState.ERROR: "resolver error",
        }
        return labels.get(result.state, result.state.value)

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

    def _estimate_spf_dns_lookups(
        self,
        domain: str,
        record: str,
        visited: Optional[set[str]] = None,
        depth: int = 0,
    ) -> dict[str, Any]:
        """Estimate worst-case SPF DNS terms and track incomplete DNS evidence.

        RFC 7208 limits include/a/mx/ptr/exists plus redirect to 10 terms during
        evaluation, including nested include/redirect processing. Resolver failures
        must not be interpreted as an absent child SPF record or a complete budget.
        """
        if visited is None:
            visited = set()
        key = domain.lower().rstrip(".")
        if key in visited:
            return {
                "count": 0,
                "breakdown": [],
                "notes": [f"cycle detected at {domain}"],
                "complete": True,
            }
        if depth > 12:
            return {
                "count": 0,
                "breakdown": [],
                "notes": ["SPF recursion depth limit reached"],
                "complete": False,
            }
        visited = set(visited)
        visited.add(key)

        count = 0
        breakdown: list[str] = []
        notes: list[str] = []
        complete = True
        terms = self._spf_terms(record)[1:]

        def bare_token(raw: str) -> str:
            return raw[1:] if raw and raw[0] in "+-~?" else raw

        def child_spf(target: str, kind: str) -> None:
            nonlocal count, complete
            result = self.dns_query_result(target, "TXT")
            if result.failed:
                complete = False
                notes.append(
                    f"{kind} target {target} could not be resolved "
                    f"({self._dns_unavailable_message(result)})"
                )
                return

            child_records = [
                self._normalize_txt_record(x)
                for x in result.records
                if self._normalize_txt_record(x).lower().startswith("v=spf1")
            ]
            if len(child_records) == 1:
                child = self._estimate_spf_dns_lookups(
                    target, child_records[0], visited, depth + 1
                )
                count += child["count"]
                breakdown.extend([f"  {x}" for x in child["breakdown"]])
                notes.extend(child["notes"])
                complete = complete and child.get("complete", True)
            elif len(child_records) == 0:
                notes.append(f"{kind} target {target} has no SPF record")
            else:
                notes.append(f"{kind} target {target} has multiple SPF records")

        has_all = any(
            re.split(r"[:/]", bare_token(x).lower(), maxsplit=1)[0] == "all"
            for x in terms
            if "=" not in bare_token(x)
        )

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
                    child_spf(target, "redirect")
                elif target and "%" in target:
                    notes.append(
                        f"cannot recursively evaluate macro-based redirect target: {target}"
                    )
                if count > 20:
                    notes.append(
                        "lookup expansion stopped after clearly exceeding the SPF limit"
                    )
                    break
                continue

            if "=" in token:
                continue

            mechanism = re.split(r"[:/]", low, maxsplit=1)[0]
            if mechanism == "all":
                break

            if mechanism in ("include", "a", "mx", "ptr", "exists"):
                count += 1
                breakdown.append(token)
                if mechanism == "include":
                    target = (
                        token.split(":", 1)[1].strip().rstrip(".")
                        if ":" in token
                        else ""
                    )
                    if target and "%" not in target and count <= 20:
                        child_spf(target, "include")
                    elif target and "%" in target:
                        notes.append(
                            f"cannot recursively evaluate macro-based include target: {target}"
                        )
                if count > 20:
                    notes.append(
                        "lookup expansion stopped after clearly exceeding the SPF limit"
                    )
                    break

        return {
            "count": count,
            "breakdown": breakdown,
            "notes": notes,
            "complete": complete,
        }

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
        root_results: dict[str, DnsQueryResult] = {}
        for rt in COMMON_DNS_TYPES:
            result = self.dns_query_result(self.root_domain, rt)
            root_results[rt] = result
            root[rt] = list(result.records)
        ds_result = self.dns_query_result(self.root_domain, "DS")
        root_results["DS"] = ds_result
        root["DS"] = list(ds_result.records)
        self.dns_records[self.root_domain] = root

        target_results: dict[str, DnsQueryResult] = {}
        if self.target_domain != self.root_domain:
            target = {}
            for rt in COMMON_DNS_TYPES:
                result = self.dns_query_result(self.target_domain, rt)
                target_results[rt] = result
                target[rt] = list(result.records)
            self.dns_records[self.target_domain] = target

        ds = root["DS"]
        rdap_signed = self.rdap.get("dnssec_rdap")
        if ds or rdap_signed is True:
            self.add_check("Domain", "DNSSEC", "pass",
                           f"Wykryto delegację DNSSEC dla {self.root_domain}.", 7, 7)
        elif ds_result.failed:
            self.add_check(
                "Domain", "DNSSEC", "unknown",
                f"Nie można wiarygodnie ocenić DNSSEC: zapytanie DS zakończyło się "
                f"błędem ({self._dns_unavailable_message(ds_result)}).",
                7, 0, False
            )
        else:
            self.add_check("Domain", "DNSSEC", "warn",
                           f"Nie wykryto delegacji DNSSEC dla {self.root_domain}.", 7, 0)

        # CAA can exist at the exact host; if absent, CA processing walks upward.
        root_caa_result = root_results["CAA"]
        target_caa_result = (
            target_results.get("CAA")
            if self.target_domain != self.root_domain
            else None
        )
        target_caa = list(target_caa_result.records) if target_caa_result else []
        caa = target_caa or root.get("CAA", [])
        self.rdap["caa_source"] = self.target_domain if target_caa else self.root_domain
        if caa:
            self.add_check("Domain", "CAA", "pass",
                           f"Wykryto {len(caa)} rekord(y) CAA (źródło: {self.rdap['caa_source']}).", 3, 3)
        elif root_caa_result.failed or (target_caa_result and target_caa_result.failed):
            failed = target_caa_result if target_caa_result and target_caa_result.failed else root_caa_result
            self.add_check(
                "Domain", "CAA", "unknown",
                f"Nie można wiarygodnie potwierdzić braku CAA: zapytanie DNS zakończyło się "
                f"błędem ({self._dns_unavailable_message(failed)}).",
                3, 0, False
            )
        else:
            self.add_check("Domain", "CAA", "warn",
                           "Brak rekordu CAA na hoście docelowym i domenie bazowej.", 3, 0)

        # MAIL SECURITY: always root domain, even if the website is on a subdomain.
        self.mail["domain"] = self.root_domain
        mx_result = root_results["MX"]
        mx = root.get("MX", [])
        self.mail["mx"] = mx
        if mx:
            self.add_check("Mail", "MX", "pass",
                           f"Wykryto {len(mx)} rekord(y) MX dla {self.root_domain}.", 2, 2)
        elif mx_result.failed:
            self.add_check(
                "Mail", "MX", "unknown",
                f"Nie można ocenić rekordów MX z powodu błędu DNS "
                f"({self._dns_unavailable_message(mx_result)}).",
                2, 0, False
            )
        else:
            self.add_check("Mail", "MX", "info",
                           f"Brak rekordów MX dla {self.root_domain}. Jeśli domena nie obsługuje poczty, może to być zamierzone.",
                           2, 0, False)

        txt_result = root_results["TXT"]
        txt = [self._normalize_txt_record(x) for x in root.get("TXT", [])]
        spf = [x for x in txt if x.lower().startswith("v=spf1")]
        self.mail["spf"] = spf
        self.mail["spf_analysis"] = {"record_count": len(spf)}

        if txt_result.failed:
            self.mail["spf_analysis"]["dns_evidence"] = txt_result.state.value
            self.add_check(
                "Mail", "SPF", "unknown",
                f"Nie można wiarygodnie ocenić SPF: zapytanie TXT zakończyło się "
                f"błędem ({self._dns_unavailable_message(txt_result)}).",
                8, 0, False
            )
            self.add_check("Mail", "SPF syntax", "unknown",
                           "Nie można ocenić składni SPF bez wiarygodnego wyniku DNS.", 0, 0, False)
            self.add_check("Mail", "SPF DNS lookup budget", "unknown",
                           "Nie można ocenić limitu zapytań SPF bez wiarygodnego wyniku DNS.", 0, 0, False)
        elif not spf:
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
            lookup_complete = lookups.get("complete", True)
            if not lookup_complete:
                self.add_check(
                    "Mail", "SPF DNS lookup budget", "unknown",
                    "Nie można wiarygodnie ocenić pełnego budżetu SPF, ponieważ co najmniej jedno "
                    "zagnieżdżone zapytanie DNS nie zakończyło się wiarygodnym wynikiem.",
                    3, 0, False
                )
            elif lookup_count > 10:
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
            elif not syntax["valid"] or (lookup_complete and lookup_count > 10):
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

        dmarc_result = self.dns_query_result(f"_dmarc.{self.root_domain}", "TXT")
        dmarc_txt = [self._normalize_txt_record(x) for x in dmarc_result.records]
        dmarc = [x for x in dmarc_txt if re.search(r"\bv\s*=\s*dmarc1\b", x, flags=re.I)]
        self.mail["dmarc"] = dmarc
        self.mail["dmarc_analysis"] = {"record_count": len(dmarc)}
        if dmarc_result.failed:
            self.mail["dmarc_analysis"]["dns_evidence"] = dmarc_result.state.value
            self.add_check(
                "Mail", "DMARC", "unknown",
                f"Nie można wiarygodnie ocenić DMARC: zapytanie DNS zakończyło się "
                f"błędem ({self._dns_unavailable_message(dmarc_result)}).",
                12, 0, False
            )
            self.add_check("Mail", "DMARC syntax", "unknown",
                           "Nie można ocenić składni DMARC bez wiarygodnego wyniku DNS.", 0, 0, False)
        elif not dmarc:
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
        dkim_failures: list[DnsQueryResult] = []
        for selector in COMMON_DKIM_SELECTORS:
            result = self.dns_query_result(f"{selector}._domainkey.{self.root_domain}", "TXT")
            if result.failed:
                dkim_failures.append(result)
            rows = [x for x in result.records if "v=dkim1" in x.lower() or "p=" in x.lower()]
            if rows:
                found_dkim[selector] = rows
        self.mail["dkim_common_selectors"] = found_dkim
        if found_dkim:
            self.add_check("Mail", "DKIM", "pass",
                           "Wykryto DKIM dla selektorów: " + ", ".join(sorted(found_dkim)), 5, 5)
        elif dkim_failures:
            self.add_check(
                "Mail", "DKIM", "unknown",
                "Nie można zakończyć konserwatywnej próby popularnych selektorów DKIM, "
                "ponieważ część zapytań DNS zakończyła się błędem. "
                "Brak wyniku nadal nie oznacza braku DKIM.",
                5, 0, False
            )
        else:
            self.add_check(
                "Mail", "DKIM", "unknown",
                f"Nie znaleziono DKIM dla popularnych selektorów na {self.root_domain}. "
                "To NIE oznacza braku DKIM; selektor jest częścią konfiguracji nadawcy.",
                5, 0, False
            )

        mta_sts_result = self.dns_query_result(f"_mta-sts.{self.root_domain}", "TXT")
        mta_sts_dns = list(mta_sts_result.records)
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
        elif mta_sts_result.failed:
            self.add_check(
                "Mail", "MTA-STS", "unknown",
                f"Nie można wiarygodnie ocenić MTA-STS z powodu błędu DNS "
                f"({self._dns_unavailable_message(mta_sts_result)}).",
                3, 0, False
            )
        elif mta_sts_dns or mta_policy:
            self.add_check("Mail", "MTA-STS", "warn",
                           "MTA-STS wygląda na częściowo skonfigurowane.", 3, 1)
        else:
            self.add_check("Mail", "MTA-STS", "info",
                           f"Nie wykryto MTA-STS dla {self.root_domain}.", 3, 0)

        tls_rpt_result = self.dns_query_result(f"_smtp._tls.{self.root_domain}", "TXT")
        tls_rpt = [x for x in tls_rpt_result.records if "v=tlsrptv1" in x.lower()]
        self.mail["tls_rpt"] = tls_rpt
        if tls_rpt:
            self.add_check("Mail", "TLS-RPT", "pass", "Wykryto rekord TLS-RPT.", 2, 2)
        elif tls_rpt_result.failed:
            self.add_check(
                "Mail", "TLS-RPT", "unknown",
                f"Nie można wiarygodnie ocenić TLS-RPT z powodu błędu DNS "
                f"({self._dns_unavailable_message(tls_rpt_result)}).",
                2, 0, False
            )
        else:
            self.add_check("Mail", "TLS-RPT", "info",
                           f"Nie wykryto TLS-RPT dla {self.root_domain}.", 2, 0)
