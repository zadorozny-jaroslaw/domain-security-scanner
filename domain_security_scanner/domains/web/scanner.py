from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from ...constants import SECURITY_HEADERS, TIMEOUT
from ...standards import (
    RFC_6797,
    RFC_9110,
    RFC_9111,
    RFC_9116,
    RFC_10025,
    analyze_hsts,
    analyze_http_cache_policy,
    analyze_redirect,
    analyze_security_txt,
    analyze_set_cookie_header,
)


class WebScanMixin:
    """HTTP, cookie, and mixed-content checks."""

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
    def _header_values(response, name: str) -> list[str]:
        """Return repeated response header field values without comma folding when possible."""
        try:
            raw_headers = getattr(getattr(response, "raw", None), "headers", None)
            if raw_headers is not None and hasattr(raw_headers, "getlist"):
                values = raw_headers.getlist(name)
                if values:
                    return [str(value) for value in values]
        except Exception:
            pass
        headers = getattr(response, "headers", None)
        value = headers.get(name) if headers else None
        return [str(value)] if value else []

    @classmethod
    def _cookie_header_values(cls, response) -> list[str]:
        return cls._header_values(response, "Set-Cookie")

    def _analyze_cookies(self, response) -> dict[str, Any]:
        responses = list(getattr(response, "history", []) or []) + [response]
        headers: list[str] = []
        cookies: list[dict[str, Any]] = []
        for item_response in responses:
            response_headers = self._cookie_header_values(item_response)
            headers.extend(response_headers)
            for header in response_headers:
                item = analyze_set_cookie_header(header)
                name = str(item.get("name") or "")
                sensitive = bool(re.search(
                    r"(session|sess|auth|token|jwt|sid$|phpsessid|jsessionid|asp\.net|wordpress_logged_in|security)",
                    name,
                    re.I,
                ))
                issues = list(item.get("rfc_errors", []))
                hardening_issues: list[str] = []
                if sensitive:
                    if not item.get("secure"):
                        hardening_issues.append("missing Secure")
                    if not item.get("httponly"):
                        hardening_issues.append("missing HttpOnly")
                    if not item.get("samesite"):
                        hardening_issues.append("missing SameSite")
                issues.extend(hardening_issues)
                item["sensitive"] = sensitive
                item["hardening_issues"] = hardening_issues
                item["issues"] = issues
                cookies.append(item)

        sensitive = [x for x in cookies if x["sensitive"]]
        issues = [x for x in cookies if x["issues"]]
        rfc_errors = [
            f"{x.get('name') or '(unnamed)'}: {error}"
            for x in cookies
            for error in x.get("rfc_errors", [])
        ]
        warning_items = [
            x for x in cookies
            if x.get("rfc_errors") or (x["sensitive"] and x.get("hardening_issues"))
        ]
        return {
            "set_cookie_headers": len(headers),
            "cookies": cookies,
            "sensitive_count": len(sensitive),
            "issue_count": len(issues),
            "warning_count": len(warning_items),
            "rfc_error_count": len(rfc_errors),
            "rfc_errors": rfc_errors,
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

    def check_http(self, run_web_checks: bool = True):
        result: dict[str, Any] = {}

        # Does HTTP redirect to HTTPS? CMS-only scans skip this Web request.
        if run_web_checks:
            source_url = f"http://{self.target_domain}"
            try:
                r = self.session.get(source_url, timeout=TIMEOUT, allow_redirects=False)
                loc = r.headers.get("location", "")
                redirect = analyze_redirect(r.status_code, loc, source_url)
                result["http_status"] = r.status_code
                result["http_location"] = loc
                result["http_redirect"] = redirect
                if redirect["secure_target"]:
                    self.add_check(
                        "Web", "HTTP -> HTTPS redirect", "pass",
                        f"HTTP przekierowuje do HTTPS zgodnie z semantyką {RFC_9110.label}.",
                        4, 4,
                    )
                else:
                    detail = ""
                    if redirect["redirect_status"] and not redirect["valid_location"]:
                        detail = " Nieprawidłowa wartość Location."
                    elif redirect["redirect_status"] and redirect["resolved_location"]:
                        detail = f" Cel: {redirect['resolved_location']}."
                    self.add_check(
                        "Web", "HTTP -> HTTPS redirect", "warn",
                        f"Brak jednoznacznego przekierowania HTTP→HTTPS (status {r.status_code}).{detail}",
                        4, 0,
                    )
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
            cms_selected = getattr(
                self, "scan_group_selected", lambda group: True
            )("cms")
            if cms_selected:
                run_group_step = getattr(self, "_run_group_step", None)
                if run_group_step is not None:
                    result["cms"] = run_group_step(
                        "cms", self.detect_cms, r, html
                    )
                else:
                    result["cms"] = self.detect_cms(r, html)
            else:
                result["cms"] = {
                    "detected": False,
                    "name": None,
                    "version": None,
                    "confidence": "none",
                    "signals": [],
                    "technology_headers": {},
                }

            if not run_web_checks:
                self.http = result
                return

            capture_response_metadata = getattr(
                self, "_capture_web_response_metadata", None
            )
            if callable(capture_response_metadata):
                capture_response_metadata(r, result)

            headers_l = {k.lower(): v for k, v in r.headers.items()}

            # RFC 9111 cache metadata. This is advisory/non-scoring: the scanner
            # validates syntax and ambiguity without assuming every page should
            # be cacheable or non-cacheable.
            cache_analysis = analyze_http_cache_policy(
                self._header_values(r, "Cache-Control"),
                expires_values=self._header_values(r, "Expires"),
                age_values=self._header_values(r, "Age"),
                pragma_values=self._header_values(r, "Pragma"),
                warning_values=self._header_values(r, "Warning"),
            )
            result["cache"] = cache_analysis
            cache_review = cache_analysis["errors"] + cache_analysis["warnings"]
            if cache_review:
                self.add_check(
                    "Web", "HTTP cache policy", "warn",
                    f"Metadane cache wymagają przeglądu wg {RFC_9111.label}: "
                    + "; ".join(cache_review[:3]) + ".",
                    0, 0, False,
                )
            elif cache_analysis["present"]:
                details = []
                if cache_analysis["no_store"]:
                    details.append("no-store")
                if cache_analysis["private"]:
                    details.append("private")
                if cache_analysis["no_cache"]:
                    details.append("no-cache")
                if cache_analysis["s_maxage"] is not None:
                    details.append(f"s-maxage={cache_analysis['s_maxage']}")
                elif cache_analysis["max_age"] is not None:
                    details.append(f"max-age={cache_analysis['max_age']}")
                summary = ", ".join(details) or cache_analysis["freshness_source"]
                self.add_check(
                    "Web", "HTTP cache policy", "info",
                    f"Metadane cache są syntaktycznie spójne wg {RFC_9111.label} ({summary}).",
                    0, 0, False,
                )
            else:
                self.add_check(
                    "Web", "HTTP cache policy", "info",
                    f"Brak jawnych nagłówków polityki cache; {RFC_9111.label} dopuszcza heurystyczne cache'owanie części odpowiedzi.",
                    0, 0, False,
                )

            # Cookie flags. RFC 10025 violations and sensitive/session hardening
            # gaps generate WARN findings; non-sensitive cookies remain inventory.
            cookie_analysis = self._analyze_cookies(r)
            result["cookies"] = cookie_analysis
            warning_cookies = [x for x in cookie_analysis["cookies"] if x["issues"]]
            if warning_cookies:
                short = "; ".join(
                    f"{x.get('name') or '(unnamed)'}: {', '.join(x['issues'])}"
                    for x in warning_cookies[:4]
                )
                self.add_check(
                    "Web", "Cookie security flags", "warn",
                    f"Wykryto problemy z cookies ({RFC_10025.label} / hardening): {short}.",
                    3, 0,
                )
            elif cookie_analysis["sensitive_count"]:
                self.add_check(
                    "Web", "Cookie security flags", "pass",
                    f"Wrażliwe/session cookies ({cookie_analysis['sensitive_count']}) mają podstawowe flagi Secure/HttpOnly/SameSite i nie wykryto naruszeń {RFC_10025.label}.",
                    3, 3,
                )
            else:
                self.add_check(
                    "Web", "Cookie security flags", "info",
                    f"Nie wykryto jednoznacznie wrażliwych/session cookies; sprawdzono składnię i wymagania {RFC_10025.label} dla widocznych Set-Cookie.",
                    0, 0, False,
                )

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

            # HSTS: validate the RFC 6797 field rather than treating mere presence as pass.
            hsts_analysis = analyze_hsts(self._header_values(r, "Strict-Transport-Security"))
            result["hsts"] = hsts_analysis
            if not hsts_analysis["present"]:
                self.add_check("Web", "HSTS", "warn", "Brak nagłówka HSTS.", 4, 0)
            elif not hsts_analysis["valid"]:
                self.add_check(
                    "Web", "HSTS", "warn",
                    f"HSTS jest ustawione, ale nie spełnia składni {RFC_6797.label}: "
                    + "; ".join(hsts_analysis["errors"][:3]) + ".",
                    4, 0,
                )
            elif not hsts_analysis["active"]:
                self.add_check(
                    "Web", "HSTS", "warn",
                    f"HSTS jest poprawne składniowo, ale max-age=0 wyłącza politykę ({RFC_6797.label}).",
                    4, 0,
                )
            else:
                suffix = "; includeSubDomains" if hsts_analysis["include_subdomains"] else ""
                self.add_check(
                    "Web", "HSTS", "pass",
                    f"HSTS jest poprawne wg {RFC_6797.label} (max-age={hsts_analysis['max_age']}{suffix}).",
                    4, 4,
                )

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
            result["cookies"] = {
                "set_cookie_headers": 0,
                "cookies": [],
                "sensitive_count": 0,
                "issue_count": 0,
                "warning_count": 0,
                "rfc_error_count": 0,
                "rfc_errors": [],
            }
            result["mixed_content"] = sorted(self.crawl_mixed_content)
            result["server_disclosure"] = {"headers": {}, "exact_version": False}
            result["cache"] = {
                "present": False,
                "cache_control_present": False,
                "valid": False,
                "review": False,
                "errors": [],
                "warnings": [],
            }

        # security.txt - informational/advisory only, but validate RFC 9116 when present.
        if run_web_checks:
            security_txt_url = f"https://{self.target_domain}/.well-known/security.txt"
            try:
                r = self.session.get(
                    security_txt_url,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                )
                security_txt = analyze_security_txt(
                    status_code=r.status_code,
                    text=r.text or "",
                    content_type=r.headers.get("Content-Type", ""),
                    requested_url=security_txt_url,
                    final_url=getattr(r, "url", security_txt_url) or security_txt_url,
                )
                result["security_txt"] = security_txt["valid"]
                result["security_txt_analysis"] = security_txt
                if security_txt["valid"]:
                    self.add_check(
                        "Web", "security.txt", "pass",
                        f"Wykryto poprawny security.txt zgodny z {RFC_9116.label}.",
                        0, 0, False,
                    )
                elif security_txt["present"]:
                    self.add_check(
                        "Web", "security.txt", "warn",
                        f"security.txt jest obecny, ale wymaga korekty wg {RFC_9116.label}: "
                        + "; ".join(security_txt["errors"][:3]) + ".",
                        0, 0, False,
                    )
                else:
                    self.add_check(
                        "Web", "security.txt", "info",
                        "Nie wykryto security.txt w /.well-known/security.txt.",
                        0, 0, False,
                    )
            except Exception as e:
                result["security_txt"] = False
                result["security_txt_analysis"] = {
                    "present": False,
                    "valid": False,
                    "errors": [str(e)],
                    "warnings": [],
                }

        self.http = result
