from __future__ import annotations

import re
from http.cookies import SimpleCookie
from typing import Any

from bs4 import BeautifulSoup

from .constants import SECURITY_HEADERS, TIMEOUT
from .domains.tls import TlsScanMixin


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


class WebTlsMixin(TlsScanMixin, WebScanMixin):
    """Backward-compatible combined web and TLS mixin."""


__all__ = ["WebScanMixin", "WebTlsMixin"]
