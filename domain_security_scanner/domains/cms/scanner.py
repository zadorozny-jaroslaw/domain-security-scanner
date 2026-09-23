from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Optional

from bs4 import BeautifulSoup

from ...constants import TIMEOUT, USER_AGENT


class CmsScanMixin:
    """Passive CMS/platform detection and release-currency checks."""

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
        ta = CmsScanMixin._stable_numeric_version(a)
        tb = CmsScanMixin._stable_numeric_version(b)
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
            t = CmsScanMixin._stable_numeric_version(v)
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
