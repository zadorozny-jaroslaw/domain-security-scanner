from __future__ import annotations

from ...standards import RFC_7838, analyze_alt_svc_headers


class AltSvcScanMixin:
    """Add passive RFC 7838 Alt-Svc analysis to the Web scan group."""

    def check_http(self, run_web_checks: bool = True):
        result = super().check_http(run_web_checks=run_web_checks)
        if not run_web_checks:
            return result

        http = getattr(self, "http", {}) or {}
        response_headers = http.get("headers", {}) or {}
        alt_svc_values = [
            str(value)
            for name, value in response_headers.items()
            if str(name).lower() == "alt-svc" and str(value).strip()
        ]
        origin_url = http.get("final_url") or f"https://{self.target_domain}"
        response_age = (http.get("cache") or {}).get("age")

        analysis = analyze_alt_svc_headers(
            alt_svc_values,
            origin_url=origin_url,
            response_age=response_age,
        )
        http["alt_svc"] = analysis
        self.http = http

        review_items = analysis["errors"] + analysis["warnings"]
        if review_items:
            self.add_check(
                "Web",
                "HTTP Alt-Svc",
                "warn",
                f"Nagłówek Alt-Svc wymaga przeglądu wg {RFC_7838.label}: "
                + "; ".join(review_items[:3])
                + ".",
                0,
                0,
                False,
            )
        elif analysis["clear"]:
            self.add_check(
                "Web",
                "HTTP Alt-Svc",
                "info",
                f"Alt-Svc poprawnie używa wartości clear wg {RFC_7838.label}; "
                "klient powinien unieważnić zapamiętane usługi alternatywne.",
                0,
                0,
                False,
            )
        elif analysis["present"]:
            protocols = ", ".join(analysis["protocol_ids"][:6]) or "brak"
            changed = len(analysis["changed_hosts"])
            host_note = (
                f" {changed} reklama(y) wskazuje(-ą) inny host."
                if changed
                else ""
            )
            self.add_check(
                "Web",
                "HTTP Alt-Svc",
                "info",
                f"Alt-Svc jest poprawny wg {RFC_7838.label}; "
                f"wykryto {analysis['alternative_count']} usług alternatywnych "
                f"(protokoły: {protocols}).{host_note} "
                "Reklamowane usługi nie są automatycznie testowane ani otwierane.",
                0,
                0,
                False,
            )
        else:
            self.add_check(
                "Web",
                "HTTP Alt-Svc",
                "info",
                f"Brak nagłówka Alt-Svc; {RFC_7838.label} nie wymaga "
                "usług alternatywnych dla każdej odpowiedzi HTTP.",
                0,
                0,
                False,
            )

        return result


__all__ = ["AltSvcScanMixin"]
