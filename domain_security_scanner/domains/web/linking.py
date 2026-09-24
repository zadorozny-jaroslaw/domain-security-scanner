from __future__ import annotations

from ...standards import RFC_8288, analyze_link_headers


class LinkHeaderScanMixin:
    """Add passive RFC 8288 Link-header analysis to the Web scan group."""

    def check_http(self, run_web_checks: bool = True):
        result = super().check_http(run_web_checks=run_web_checks)
        if not run_web_checks:
            return result

        http = getattr(self, "http", {}) or {}
        response_headers = http.get("headers", {}) or {}
        link_values = [
            str(value)
            for name, value in response_headers.items()
            if str(name).lower() == "link" and str(value).strip()
        ]
        context_url = http.get("final_url") or f"https://{self.target_domain}"
        analysis = analyze_link_headers(link_values, context_url=context_url)
        http["links"] = analysis
        self.http = http

        review_items = analysis["errors"] + analysis["warnings"]
        if review_items:
            self.add_check(
                "Web",
                "HTTP Link header",
                "warn",
                f"Nagłówek Link wymaga przeglądu wg {RFC_8288.label}: "
                + "; ".join(review_items[:3])
                + ".",
                0,
                0,
                False,
            )
        elif analysis["present"]:
            relations = ", ".join(analysis["relation_types"][:6]) or "brak relacji"
            self.add_check(
                "Web",
                "HTTP Link header",
                "info",
                f"Nagłówek Link jest poprawny wg {RFC_8288.label}; "
                f"wykryto {analysis['link_count']} link(ów), relacje: {relations}. "
                "Cele nie są automatycznie otwierane.",
                0,
                0,
                False,
            )
        else:
            self.add_check(
                "Web",
                "HTTP Link header",
                "info",
                f"Brak nagłówka Link; {RFC_8288.label} nie wymaga go dla każdej odpowiedzi HTTP.",
                0,
                0,
                False,
            )

        return result


__all__ = ["LinkHeaderScanMixin"]
